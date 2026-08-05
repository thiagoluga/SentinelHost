package web

import (
	"net/http/httptest"
	"testing"
)

// The session cookie says WHO is asking. It does not say WHAT PAGE asked, and on this
// deployment those are different questions: the panel is installed inside the document
// root of the site it protects, so every subdomain of the account is same-site and keeps
// a SameSite=Strict cookie.
//
// The premise for running a malware scanner is that something on this account is already
// compromised. A page on a compromised addon domain could POST
// /api/quarantine/{ref}/purge with the owner logged in — the only irreversible operation
// in the project, and the one that destroys the evidence.
func TestAStateChangingRequestFromAnotherPageIsRefused(t *testing.T) {
	s := &Server{}

	cases := []struct {
		what    string
		method  string
		headers map[string]string
		allowed bool
	}{
		// The panel's own fetch().
		{"the panel itself", "POST", map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
		// A user typing the URL or following a bookmark cannot carry a JSON body from
		// another page.
		{"a typed URL", "POST", map[string]string{"Sec-Fetch-Site": "none"}, true},

		// The attack.
		{"a compromised subdomain", "POST",
			map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"an unrelated site", "POST",
			map[string]string{"Sec-Fetch-Site": "cross-site"}, false},

		// Older browsers: Origin decides.
		{"Origin matching the host", "POST",
			map[string]string{"Origin": "https://example.com"}, true},
		{"Origin from a subdomain", "POST",
			map[string]string{"Origin": "https://blog.example.com"}, false},
		{"Origin from elsewhere", "POST",
			map[string]string{"Origin": "https://evil.test"}, false},

		// Reading is gated by the session, not by this.
		{"a GET from anywhere", "GET",
			map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
	}

	for _, c := range cases {
		req := httptest.NewRequest(c.method, "https://example.com/api/scan", nil)
		req.Host = "example.com"
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		err := s.requireSameOrigin(req)
		if c.allowed && err != nil {
			t.Errorf("%s was refused: %v", c.what, err)
		}
		if !c.allowed && err == nil {
			t.Errorf("%s was allowed to change state", c.what)
		}
	}
}

// A non-browser client sends neither header. Those are allowed, because the mechanism this
// defends against is a browser attaching somebody else's cookie automatically — which a
// curl invocation does not do, and a browser cannot do without sending one of the headers.
func TestANonBrowserClientIsNotBlocked(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("POST", "https://example.com/api/scan", nil)
	req.Host = "example.com"
	if err := s.requireSameOrigin(req); err != nil {
		t.Errorf("a client sending neither header was refused: %v", err)
	}
}

// The bridge forwards the client's own headers and THEN appends its computed ones, so both
// arrive — and http.Header.Get returns the first, which is the client's.
//
// That let a caller decide whether their own session cookie got the Secure flag: sending
// `X-Forwarded-Proto: http` to an HTTPS deployment produced a cookie the browser will
// later send in cleartext.
func TestTheProxysForwardedValueWinsOverTheClients(t *testing.T) {
	req := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/login", nil)
	// Exactly what reaches the panel: the client's value first, the bridge's second.
	req.Header.Add("X-Forwarded-Proto", "http")
	req.Header.Add("X-Forwarded-Proto", "https")

	if got := lastHeaderValue(req, "X-Forwarded-Proto"); got != "https" {
		t.Errorf("read %q; the value the proxy added is the last one, and it is the only "+
			"one the client did not choose", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatal("Header.Get no longer returns the first value; the reasoning behind " +
			"lastHeaderValue needs revisiting")
	}
}

// A single value still works, or every ordinary deployment breaks.
func TestASingleForwardedValueIsRead(t *testing.T) {
	req := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := lastHeaderValue(req, "X-Forwarded-Proto"); got != "https" {
		t.Errorf("read %q from a single value", got)
	}
	empty := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/login", nil)
	if got := lastHeaderValue(empty, "X-Forwarded-Proto"); got != "" {
		t.Errorf("read %q when the header is absent", got)
	}
}
