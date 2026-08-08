package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/selfupdate"
)

// UpdateChecker is what the panel asks about releases.
//
// An interface rather than a direct call so the handler can be tested without the network,
// and so nothing in the web package decides what a release is.
type UpdateChecker interface {
	Latest() (selfupdate.Release, error)
	Apply(rel selfupdate.Release) (previousPath string, err error)
	RunningVersion() string
}

// DiskVersionReporter is implemented by a checker that can say what is on disk.
//
// Optional so a checker that cannot answer simply does not implement it, and the panel
// falls back to the running version rather than inventing one.
type DiskVersionReporter interface {
	OnDiskVersion() string
}

// updateCache holds the last answer.
//
// The panel asks on every page view, and the release API rate-limits by IP — an account
// whose panel is open in a tab would exhaust that and start reporting "no update" for the
// wrong reason. A stale answer for an hour is fine; a wrong one is not.
type updateCache struct {
	at   time.Time
	rel  selfupdate.Release
	err  error
	have bool
}

const updateCacheFor = time.Hour

// handleUpdateStatus reports whether a newer release exists. It changes nothing.
//
// Failure is reported, never rendered as "you are current". A panel that says nothing when
// it could not reach the release API is telling the user their tool is up to date when it
// does not know — which is the same shape as reporting zero findings without scanning.
func (s *Server) handleUpdateStatus(w http.ResponseWriter, req *http.Request) {
	if s.updates == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"supported": false,
			"reason": "this build cannot check for updates. It was built without a release " +
				"key, so it has no way to tell a real release from anything else",
			"current": s.runningVersion(),
		})
		return
	}

	// ?force=1 asks GitHub again instead of reusing the cached answer.
	//
	// The cache exists because the panel checks on every page view and the release API
	// rate-limits by IP. But a person who clicks "Check for updates" is asking precisely
	// because they want a fresh answer — handing them an hour-old one, with no way to tell,
	// would make the button a decoration.
	if req.URL.Query().Get("force") == "1" {
		s.updateMu.Lock()
		s.updateCached = updateCache{}
		s.updateMu.Unlock()
	}

	rel, err := s.cachedLatest()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"supported":  true,
			"current":    s.updates.RunningVersion(),
			"checked_at": s.lastCheckedAt(),
			"error":      err.Error(),
		})
		return
	}

	// What is ON DISK decides whether there is anything left to install.
	//
	// The running process reports the version it was compiled with, which after an update
	// is the old one — the file changed, the program in memory did not. Comparing against
	// that made the panel keep offering an update it had already installed, so a user who
	// installed and reloaded was told to install again. That is indistinguishable from the
	// update having silently failed, on the one screen that must never be ambiguous.
	running := s.updates.RunningVersion()
	onDisk := running
	if d, ok := s.updates.(DiskVersionReporter); ok {
		if v := d.OnDiskVersion(); v != "" {
			onDisk = v
		}
	}

	newer, cmpErr := selfupdate.IsNewer(onDisk, rel.Version)
	// Installed, but not yet running it. A restart is what is left, not another download.
	pendingRestart := false
	if staged, err := selfupdate.IsNewer(running, onDisk); err == nil && staged {
		pendingRestart = true
	}

	body := map[string]any{
		"supported":       true,
		"current":         running,
		"on_disk":         onDisk,
		"pending_restart": pendingRestart,
		"latest":          rel.Version,
		"newer":           newer,
		// When the answer was actually obtained, so "no update" can be read together with
		// how old that statement is.
		"checked_at": s.lastCheckedAt(),
		// What the user is being asked to install. Sent even when it is not newer, so the
		// panel can show what the current version was released with.
		"notes":     rel.Notes,
		"notes_url": rel.NotesURL,
	}
	if cmpErr != nil {
		// A development build, or a version that cannot be read. Say which rather than
		// showing a button that would discard what the person is running.
		body["newer"] = false
		body["error"] = cmpErr.Error()
	}
	writeJSON(w, http.StatusOK, body)
}

// handleUpdateApply installs the newer release.
//
// Reached only through protect(), so it needs a valid session AND a same-origin signal —
// this replaces the binary that guards the account, and it is the single most valuable
// thing an attacker could reach in this panel.
func (s *Server) handleUpdateApply(w http.ResponseWriter, req *http.Request) {
	if s.updates == nil {
		writeErr(w, http.StatusNotImplemented,
			"this build was made without a release key, so it cannot verify an update")
		return
	}

	rel, err := s.cachedLatest()
	if err != nil {
		writeErr(w, http.StatusBadGateway, "could not reach the release listing: %v", err)
		return
	}
	// Compared against DISK, not against the running process.
	//
	// Installing a version that is already on disk overwrites the binary with itself and
	// moves the old one to .prev — which means the rollback target becomes the version you
	// are already on. Two clicks of Install destroyed the only way back, silently, and the
	// second click looked exactly like the first.
	//
	// It happened: an account ended up with sentinelhost and sentinelhost.prev both
	// reporting v0.1.3, and the v0.1.2 it could have returned to was gone.
	installed := s.updates.RunningVersion()
	if d, ok := s.updates.(DiskVersionReporter); ok {
		if v := d.OnDiskVersion(); v != "" {
			installed = v
		}
	}

	newer, err := selfupdate.IsNewer(installed, rel.Version)
	if err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	if !newer {
		// Refused rather than performed. The panel must not be able to install a release
		// that is not an upgrade, whatever it was showing when the button was clicked.
		if installed != s.updates.RunningVersion() {
			// Already installed, waiting for a restart. Saying "not newer" here would be
			// technically true and completely unhelpful.
			writeErr(w, http.StatusConflict,
				"%s is already installed — the panel is still running %s until it restarts. "+
					"Installing again would overwrite the binary with itself and leave the "+
					"rollback pointing at %s instead of %s",
				rel.Version, s.updates.RunningVersion(), rel.Version, s.updates.RunningVersion())
			return
		}
		writeErr(w, http.StatusConflict,
			"%s is not newer than the installed %s", rel.Version, installed)
		return
	}

	prev, err := s.updates.Apply(rel)
	if err != nil {
		if errors.Is(err, selfupdate.ErrBadSignature) || errors.Is(err, selfupdate.ErrUnsigned) {
			// Worth its own status and its own log line: this is the case where somebody
			// served something the key did not sign.
			s.logAction(req, "an update was refused: the signature did not verify",
				map[string]any{"version": rel.Version, "error": err.Error()})
			writeErr(w, http.StatusForbidden, "%v", err)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}

	s.logAction(req, "the binary was updated from the panel", map[string]any{
		"from": s.updates.RunningVersion(), "to": rel.Version, "previous": prev,
	})
	// The cache is now describing a version we are no longer running.
	s.updateMu.Lock()
	s.updateCached = updateCache{}
	s.updateMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"installed": rel.Version,
		"previous":  prev,
		// The old wording described the problem and left the user to solve it, which on an
		// account with no shell is not something they can do. POST /api/restart is the
		// answer, and it is named here so an API caller finds it too.
		"note": "installed on disk. This process is still the previous version until it " +
			"restarts — POST /api/restart, or the button in the panel. The next scheduled " +
			"cycle uses the new binary either way.",
	})
}

func (s *Server) cachedLatest() (selfupdate.Release, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	if s.updateCached.have && time.Since(s.updateCached.at) < updateCacheFor {
		return s.updateCached.rel, s.updateCached.err
	}
	rel, err := s.updates.Latest()
	s.updateCached = updateCache{at: time.Now(), rel: rel, err: err, have: true}
	return rel, err
}

// lastCheckedAt reports when the release listing was last reached, in RFC 3339.
func (s *Server) lastCheckedAt() string {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if !s.updateCached.have {
		return ""
	}
	return s.updateCached.at.UTC().Format(time.RFC3339)
}

func (s *Server) runningVersion() string {
	if s.updates != nil {
		return s.updates.RunningVersion()
	}
	return ""
}
