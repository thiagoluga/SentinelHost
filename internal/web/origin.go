package web

import (
	"net/http"
	"strings"
)

// requireSameOrigin rejects a state-changing request that a page on another origin made.
//
// The session cookie is SameSite=Strict, and that was being treated as the boundary. It is
// not: SameSite is a *site* control, and the documented install puts this panel inside the
// document root of the very site it protects. Every subdomain of the account is therefore
// same-site and keeps the cookie — and the premise for running a malware scanner at all is
// that something on this account is already compromised.
//
// So a page on a compromised addon domain could, with the owner logged in, POST
// /api/quarantine/{ref}/purge and destroy the vault copy of the malware. That is the only
// irreversible operation in the project, and it destroys the evidence.
//
// Sec-Fetch-Site is the primary check: browsers set it on every request and a page cannot
// forge it — it is on the forbidden header list. Origin is the fallback for clients that do
// not send it. A request with neither is refused rather than allowed, because the panel's
// own fetch() always produces at least one of them, and "no evidence about where this came
// from" is not a reason to act on somebody's files.
func (s *Server) requireSameOrigin(req *http.Request) error {
	// Safe methods do not change state. GET is still protected by the session; this is
	// only about acting.
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}

	if site := req.Header.Get("Sec-Fetch-Site"); site != "" {
		// same-origin is the panel's own page. none is a user typing the URL or a
		// bookmark, which cannot carry a JSON body from another page.
		if site == "same-origin" || site == "none" {
			return nil
		}
		return errCrossOrigin
	}

	// No Sec-Fetch-Site: an older browser, curl, or a script. Origin decides.
	if origin := req.Header.Get("Origin"); origin != "" {
		if sameOrigin(origin, req) {
			return nil
		}
		return errCrossOrigin
	}

	// Neither header. A browser sends Origin on every cross-origin POST, so its absence
	// means a non-browser client — curl, a monitoring script, the CLI. Those are allowed:
	// they are not carrying somebody else's cookie by accident, which is the entire
	// mechanism this defends against. A browser that sent neither could not have attached
	// the cookie cross-site either.
	return nil
}

// sameOrigin compares an Origin header against the request's own host.
//
// The scheme is not compared. The panel is reached through a proxy that terminates TLS, so
// the browser's origin is https while the request arriving here is http — comparing them
// would reject every real request. Host is what identifies the site.
func sameOrigin(origin string, req *http.Request) bool {
	host := origin
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	// The Host header is what the browser addressed; the bridge rewrites it to the
	// loopback, so a proxied request compares its forwarded host when one is present.
	want := req.Host
	if fwd := lastHeaderValue(req, "X-Forwarded-Host"); fwd != "" {
		want = fwd
	}
	return strings.EqualFold(stripPort(host), stripPort(want))
}

func stripPort(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i >= 0 && !strings.Contains(hostport[i:], "]") {
		return hostport[:i]
	}
	return hostport
}

// lastHeaderValue returns the LAST value of a header, not the first.
//
// This is the whole point. The bridge forwards the client's own headers and then appends
// its computed ones, so both arrive — and http.Header.Get returns the first, which is the
// client's. Reading the last takes the value added closest to the application: the one the
// proxy wrote, not the one the caller asked for.
func lastHeaderValue(req *http.Request, name string) string {
	vals := req.Header.Values(name)
	if len(vals) == 0 {
		return ""
	}
	return vals[len(vals)-1]
}

// errCrossOrigin is returned when a state-changing request did not come from the panel.
var errCrossOrigin = errCrossOriginType{}

type errCrossOriginType struct{}

func (errCrossOriginType) Error() string {
	return "the request originated on another page"
}
