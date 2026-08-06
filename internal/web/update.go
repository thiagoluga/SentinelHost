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

	rel, err := s.cachedLatest()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"supported": true,
			"current":   s.updates.RunningVersion(),
			"error":     err.Error(),
		})
		return
	}

	newer, cmpErr := selfupdate.IsNewer(s.updates.RunningVersion(), rel.Version)
	body := map[string]any{
		"supported": true,
		"current":   s.updates.RunningVersion(),
		"latest":    rel.Version,
		"newer":     newer,
	}
	if cmpErr != nil {
		// A development build, or a version that cannot be read. Say which rather than
		// showing a button that would discard what the person is running.
		body["newer"] = false
		body["error"] = cmpErr.Error()
	}
	writeJSON(w, http.StatusOK, body)
	_ = req
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
	newer, err := selfupdate.IsNewer(s.updates.RunningVersion(), rel.Version)
	if err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	if !newer {
		// Refused rather than performed. The panel must not be able to install a release
		// that is not an upgrade, whatever it was showing when the button was clicked.
		writeErr(w, http.StatusConflict,
			"%s is not newer than the running %s", rel.Version, s.updates.RunningVersion())
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
		"note": "the running process is still the old binary until it restarts. The next " +
			"cycle, and the next time the panel starts, use the new one",
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

func (s *Server) runningVersion() string {
	if s.updates != nil {
		return s.updates.RunningVersion()
	}
	return ""
}
