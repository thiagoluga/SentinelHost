package web

import "net/http"

// handleHealth answers "this process is still serving HTTP", and nothing else.
//
// The PHP bridge used to decide the panel was up by opening a TCP connection to its port.
// That answers a different question. A process that is wedged still holds its listening
// socket, so the kernel completes the handshake and the probe passes — the bridge then
// proxied the visitor's request to it and waited until the web server killed the request.
// Sixty seconds with no response at all, not even the bridge's own 503.
//
// That is worse than the panel being down. A down panel is answered in two seconds with a
// page that retries itself, and the next visit starts a new one. A wedged panel holds a PHP
// worker on an account with a small ceiling on them, and reports nothing to the person
// looking at the screen.
//
// It is the same mistake this project exists to avoid, wearing different clothes: taking
// "I could not actually check" for "everything is fine". A socket that accepts is not a
// service that answers, exactly as an engine that could not run has not found zero threats.
//
// Deliberately touching nothing — no database, no configuration lock, no session. The
// question is whether the HTTP server is answering, and anything this handler waited on
// would make a BUSY panel indistinguishable from a wedged one. The bridge acts on the
// answer by killing the process, so a false negative here costs a scan.
//
// Unauthenticated, because the caller is a bridge with no session. It says only "ok": a
// version string here would tell any unauthenticated visitor which release guards the
// account.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte("ok\n"))
}
