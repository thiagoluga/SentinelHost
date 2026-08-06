package web

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

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
