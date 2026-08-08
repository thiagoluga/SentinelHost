package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The liveness endpoint must answer when nothing else in the panel can.
//
// A zero Server is the test: no store, no configuration, no vault, no session. If this
// handler ever grows a dependency, this panics rather than passing quietly — which is the
// point, because the PHP bridge kills what does not answer here. A /healthz that waits on
// the database would make a panel busy with a scan indistinguishable from a wedged one, and
// the cost of that mistake is a killed scan.
func TestHealthAnswersWithNothingBehindIt(t *testing.T) {
	s := &Server{}

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("a panel that is serving answered %d", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "ok" {
		t.Errorf("the body is %q, wanted %q", got, "ok")
	}
}

// Reached without a session, because the caller has none.
//
// The bridge is a PHP process asking whether the panel it just started is serving. Putting
// this behind protect() would make every probe answer 401 — still an HTTP response, so the
// bridge would read it as "answering", but it would be answering the wrong question and any
// future caller reading the status code would be misled.
func TestHealthNeedsNoSession(t *testing.T) {
	s := &Server{}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("an unauthenticated probe got %d; the bridge has no session to offer", rec.Code)
	}
}

// It says "ok" and nothing more.
//
// The panel is installed on a public URL, so this endpoint is reachable by anyone who finds
// it. A version string here would tell an unauthenticated visitor which release guards the
// account, which is a shopping list.
func TestHealthDoesNotDiscloseTheVersion(t *testing.T) {
	s := &Server{}

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	body := rec.Body.String()
	for _, leak := range []string{"v0.", "sentinelhost", "SentinelHost", "commit"} {
		if strings.Contains(body, leak) {
			t.Errorf("the health response contains %q: %q", leak, body)
		}
	}
}
