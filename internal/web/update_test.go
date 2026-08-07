package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/selfupdate"
)

type fakeUpdates struct {
	running  string
	rel      selfupdate.Release
	latestEr error
	applyEr  error
	applied  int
}

func (f *fakeUpdates) RunningVersion() string              { return f.running }
func (f *fakeUpdates) Latest() (selfupdate.Release, error) { return f.rel, f.latestEr }
func (f *fakeUpdates) Apply(selfupdate.Release) (string, error) {
	f.applied++
	return "/path/sentinelhost.prev", f.applyEr
}

// The panel must never install a release that is not an upgrade, whatever it was showing
// when the button was clicked. Serving an old release with a known hole is the cheapest
// attack on an updater, and the check has to live on the server: the button is markup.
func TestThePanelRefusesToInstallSomethingThatIsNotNewer(t *testing.T) {
	for _, latest := range []string{"v1.0.0", "v0.9.0"} {
		f := &fakeUpdates{running: "v1.0.0", rel: selfupdate.Release{Version: latest}}
		s := &Server{updates: f}

		w := httptest.NewRecorder()
		s.handleUpdateApply(w, httptest.NewRequest("POST", "/api/update", nil))

		if f.applied != 0 {
			t.Errorf("running v1.0.0, offered %s: it installed anyway", latest)
		}
		if w.Code != 409 {
			t.Errorf("running v1.0.0, offered %s: status %d", latest, w.Code)
		}
	}
}

// A refused signature is not a network problem, and the user needs to know which it was —
// one means "try later", the other means somebody served something the key did not sign.
func TestARefusedSignatureIsReportedAsItsOwnThing(t *testing.T) {
	f := &fakeUpdates{
		running: "v1.0.0",
		rel:     selfupdate.Release{Version: "v1.1.0"},
		applyEr: selfupdate.ErrBadSignature,
	}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateApply(w, httptest.NewRequest("POST", "/api/update", nil))

	if w.Code != 403 {
		t.Errorf("a bad signature answered %d, not 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "signature") {
		t.Errorf("the response does not say what went wrong: %s", w.Body.String())
	}
}

// "I could not check" and "you are up to date" are different sentences, and only one of
// them is safe to guess. A panel that goes quiet when the release listing is unreachable
// tells the user their tool is current when it does not know.
func TestAFailedCheckIsNotReportedAsBeingUpToDate(t *testing.T) {
	f := &fakeUpdates{running: "v1.0.0", latestEr: errors.New("dial tcp: timeout")}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateStatus(w, httptest.NewRequest("GET", "/api/update", nil))

	body := w.Body.String()
	if !strings.Contains(body, "error") {
		t.Errorf("the failure was not reported: %s", body)
	}
	if strings.Contains(body, `"newer":true`) {
		t.Errorf("a failed check offered an update: %s", body)
	}
}

// A build with no release key says so rather than showing a button backed by nothing.
func TestABuildThatCannotVerifySaysSoInsteadOfOfferingAButton(t *testing.T) {
	s := &Server{}

	w := httptest.NewRecorder()
	s.handleUpdateStatus(w, httptest.NewRequest("GET", "/api/update", nil))
	if !strings.Contains(w.Body.String(), `"supported":false`) {
		t.Errorf("a keyless build did not report that it cannot check: %s", w.Body.String())
	}

	w2 := httptest.NewRecorder()
	s.handleUpdateApply(w2, httptest.NewRequest("POST", "/api/update", nil))
	if w2.Code != 501 {
		t.Errorf("a keyless build answered %d to an install request", w2.Code)
	}
}

// The release notes are carried through, and the running version is always reported.
//
// Somebody reporting a problem needs to be able to say which version they are on without a
// shell, and until now the panel never said. The notes answer the question the banner
// otherwise begs: what am I about to install.
func TestTheStatusCarriesTheVersionAndTheNotes(t *testing.T) {
	f := &fakeUpdates{
		running: "v0.1.1",
		rel: selfupdate.Release{
			Version:  "v0.1.2",
			Notes:    "### Fixed\n- something small",
			NotesURL: "https://github.com/thiagoluga/SentinelHost/releases/tag/v0.1.2",
		},
	}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateStatus(w, httptest.NewRequest("GET", "/api/update", nil))

	body := w.Body.String()
	for _, want := range []string{`"current":"v0.1.1"`, `"latest":"v0.1.2"`, `"newer":true`, "something small", "releases/tag/v0.1.2"} {
		if !strings.Contains(body, want) {
			t.Errorf("the status does not carry %q: %s", want, body)
		}
	}
}

// Release notes are written by whoever cut the release. The panel displays them; it must
// never let them become markup — encoding/json escapes HTML by default, and the client
// assigns them with textContent.
func TestNotesThatLookLikeMarkupStayText(t *testing.T) {
	f := &fakeUpdates{
		running: "v0.1.1",
		rel: selfupdate.Release{
			Version: "v0.1.2",
			Notes:   `<img src=x onerror="alert(1)">`,
		},
	}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateStatus(w, httptest.NewRequest("GET", "/api/update", nil))

	body := w.Body.String()
	if strings.Contains(body, "<img") {
		t.Errorf("a raw tag survived into the response: %s", body)
	}
	// encoding/json escapes < > & as \u003c \u003e \u0026 by default, so the tag cannot
	// close a script block if this JSON is ever embedded in one.
	if !strings.Contains(body, `\u003cimg`) {
		t.Errorf("the tag was not escaped as expected: %s", body)
	}
}

// Stopping is the whole restart, and the answer has to reach the browser before it happens.
//
// An update replaces the file; the running process is still the old program. Behind the
// bridge the next visit starts the new binary, so the panel stopping IS the fix — but only
// if the client learns the request succeeded. Shutting down first would drop the connection
// and show a network error for an action that worked.
func TestTheRestartAnswersBeforeItStops(t *testing.T) {
	stopped := make(chan struct{})
	s := &Server{stop: func() { close(stopped) }}

	w := httptest.NewRecorder()
	s.handleRestart(w, httptest.NewRequest("POST", "/api/restart", nil))

	if w.Code != 200 {
		t.Fatalf("the restart answered %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "stopping") {
		t.Errorf("the response does not say what is happening: %s", w.Body.String())
	}

	// The response is written first; the stop follows shortly after.
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Error("the panel answered but never stopped")
	}
}

// A panel that cannot stop itself says so rather than reporting a restart that will not
// happen — leaving the user reloading a page that never changes version.
func TestAPanelThatCannotStopItselfSaysSo(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.handleRestart(w, httptest.NewRequest("POST", "/api/restart", nil))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("answered %d; expected 501", w.Code)
	}
}

type fakeWithDisk struct {
	*fakeUpdates
	disk string
}

func (f *fakeWithDisk) OnDiskVersion() string { return f.disk }

// Installed but not yet running is a DIFFERENT state from "an update exists".
//
// The running process reports the version it was compiled with; after an update that is
// the old one, because the file changed and the program in memory did not. Comparing
// against it made the panel keep offering an update it had already installed — so a user
// who installed and reloaded was told to install again, which is indistinguishable from
// the update having silently failed.
func TestAnInstalledUpdateIsReportedAsWaitingNotAsAvailable(t *testing.T) {
	f := &fakeWithDisk{
		fakeUpdates: &fakeUpdates{running: "v0.1.2", rel: selfupdate.Release{Version: "v0.1.3"}},
		disk:        "v0.1.3", // already installed
	}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateStatus(w, httptest.NewRequest("GET", "/api/update", nil))
	body := w.Body.String()

	if !strings.Contains(body, `"pending_restart":true`) {
		t.Errorf("an installed update was not reported as waiting: %s", body)
	}
	if !strings.Contains(body, `"newer":false`) {
		t.Errorf("it still offers an update that is already on disk: %s", body)
	}
	if !strings.Contains(body, `"on_disk":"v0.1.3"`) || !strings.Contains(body, `"current":"v0.1.2"`) {
		t.Errorf("the two versions are not both reported: %s", body)
	}
}

// And before installing, nothing is waiting.
func TestNothingIsWaitingWhenDiskAndProcessAgree(t *testing.T) {
	f := &fakeWithDisk{
		fakeUpdates: &fakeUpdates{running: "v0.1.2", rel: selfupdate.Release{Version: "v0.1.3"}},
		disk:        "v0.1.2",
	}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateStatus(w, httptest.NewRequest("GET", "/api/update", nil))
	body := w.Body.String()

	if !strings.Contains(body, `"pending_restart":false`) {
		t.Errorf("something was reported as waiting with nothing installed: %s", body)
	}
	if !strings.Contains(body, `"newer":true`) {
		t.Errorf("a real update was not offered: %s", body)
	}
}

// A checker that cannot report the disk must not break the panel: it falls back to the
// running version rather than inventing one.
func TestACheckerThatCannotSeeTheDiskStillWorks(t *testing.T) {
	f := &fakeUpdates{running: "v0.1.2", rel: selfupdate.Release{Version: "v0.1.3"}}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateStatus(w, httptest.NewRequest("GET", "/api/update", nil))
	body := w.Body.String()
	if !strings.Contains(body, `"newer":true`) || !strings.Contains(body, `"pending_restart":false`) {
		t.Errorf("the fallback path is wrong: %s", body)
	}
}

// Installing the same version twice destroys the way back.
//
// The second install overwrites the binary with itself and moves the old one to .prev, so
// the rollback target becomes the version you are already on. It happened on a real
// account: sentinelhost and sentinelhost.prev both reported v0.1.3, and the v0.1.2 it
// could have returned to was gone. Two clicks, no warning, and the second looked exactly
// like the first.
func TestInstallingWhatIsAlreadyOnDiskIsRefused(t *testing.T) {
	f := &fakeWithDisk{
		fakeUpdates: &fakeUpdates{running: "v0.1.2", rel: selfupdate.Release{Version: "v0.1.3"}},
		disk:        "v0.1.3", // installed by the first click
	}
	s := &Server{updates: f}

	w := httptest.NewRecorder()
	s.handleUpdateApply(w, httptest.NewRequest("POST", "/api/update", nil))

	if f.applied != 0 {
		t.Error("it installed again over itself, destroying the rollback")
	}
	if w.Code != 409 {
		t.Errorf("answered %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "already installed") || !strings.Contains(body, "rollback") {
		t.Errorf("the refusal does not explain what a second install would cost: %s", body)
	}
}
