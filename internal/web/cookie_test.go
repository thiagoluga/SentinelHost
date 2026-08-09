package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Setting and clearing must describe the same cookie.
//
// A browser deletes a cookie only when the deletion matches it on name, domain and path.
// clearCookie was written separately from setCookie and had already drifted — it omitted
// Secure. That instance was harmless: the value being cleared is empty, so nothing secret
// travels in the clear, and Secure is not part of what a deletion matches on.
//
// The shape is not harmless. The day somebody adds a Domain, or changes the Path in one of
// two places, logout stops clearing anything and the browser keeps a cookie the panel
// believes it took back — with nothing failing anywhere to say so.
//
// So this asserts the attributes agree, rather than asserting the one that had drifted.
func TestClearingASessionDescribesTheSameCookieAsSettingIt(t *testing.T) {
	s := &Server{}

	for _, secure := range []bool{true, false} {
		set := httptest.NewRecorder()
		s.setCookie(set, "a-token", time.Now().Add(time.Hour), secure)

		cleared := httptest.NewRecorder()
		s.clearCookie(cleared, secure)

		got := readCookie(t, set, "set")
		gone := readCookie(t, cleared, "cleared")

		if got.Name != gone.Name {
			t.Errorf("secure=%v: names differ (%q vs %q); a deletion that does not match "+
				"the cookie by name deletes nothing", secure, got.Name, gone.Name)
		}
		if got.Path != gone.Path {
			t.Errorf("secure=%v: paths differ (%q vs %q); path is part of what a browser "+
				"matches a deletion on", secure, got.Path, gone.Path)
		}
		if got.Domain != gone.Domain {
			t.Errorf("secure=%v: domains differ (%q vs %q)", secure, got.Domain, gone.Domain)
		}
		if got.Secure != gone.Secure {
			t.Errorf("secure=%v: Secure differs (set=%v cleared=%v)",
				secure, got.Secure, gone.Secure)
		}
		if got.HttpOnly != gone.HttpOnly {
			t.Errorf("secure=%v: HttpOnly differs (set=%v cleared=%v)",
				secure, got.HttpOnly, gone.HttpOnly)
		}
		if got.SameSite != gone.SameSite {
			t.Errorf("secure=%v: SameSite differs (set=%v cleared=%v)",
				secure, got.SameSite, gone.SameSite)
		}

		// And the clearing actually clears.
		if gone.Value != "" {
			t.Errorf("secure=%v: the cleared cookie still carries %q", secure, gone.Value)
		}
		if gone.MaxAge >= 0 {
			t.Errorf("secure=%v: MaxAge is %d; a deletion needs a negative one",
				secure, gone.MaxAge)
		}
	}
}

// The session cookie keeps the two attributes that are not negotiable.
//
// HttpOnly stops a cross-site script reading the credential; SameSite=Strict stops a page
// in another tab carrying it into an action that moves the user's files. Secure is the one
// that depends on the request, because marking it on a panel reached over
// http://127.0.0.1 makes the browser drop the cookie and the login never completes.
func TestTheSessionCookieIsHttpOnlyAndStrictWhateverTheScheme(t *testing.T) {
	s := &Server{}

	for _, secure := range []bool{true, false} {
		rec := httptest.NewRecorder()
		s.setCookie(rec, "a-token", time.Now().Add(time.Hour), secure)
		c := readCookie(t, rec, "set")

		if !c.HttpOnly {
			t.Errorf("secure=%v: HttpOnly is off", secure)
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Errorf("secure=%v: SameSite is %v, wanted Strict", secure, c.SameSite)
		}
		if c.Secure != secure {
			t.Errorf("secure=%v: Secure is %v; it has to follow whether there is real TLS",
				secure, c.Secure)
		}
	}
}

func readCookie(t *testing.T, rec *httptest.ResponseRecorder, what string) *http.Cookie {
	t.Helper()
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("the %s response carries %d cookies, wanted 1", what, len(cookies))
	}
	return cookies[0]
}
