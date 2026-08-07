// Package web serves the panel embedded in the binary.
//
// No JS framework and no build step: the assets are vanilla HTML/CSS/JS embedded
// with go:embed (Principle VII). The panel is a direct evolution of
// docs/panel-mockup.html consuming the real JSON API.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

//go:embed assets
var assets embed.FS

// Server serves the panel and the API.
type Server struct {
	// cfgMu protects cfg. The panel EDITS the configuration while a cycle
	// triggered by /api/scan READS it — without the lock that is a genuine data
	// race over the same maps and slices.
	cfgMu sync.RWMutex
	cfg   *config.Config

	store    *store.Store
	registry *adapter.Registry
	vault    *quarantine.Vault
	alerts   *alert.Dispatcher
	runner   *cycle.Runner

	limiter *rateLimiter
	now     func() time.Time

	// updates is nil when this build cannot verify a release. The panel then says so
	// rather than offering a button that could install anything.
	updates      UpdateChecker
	updateMu     sync.Mutex
	updateCached updateCache

	// stop ends the process so the next visit starts the binary now on disk. Nil when
	// the panel was not started in a way that lets it stop itself, and the endpoint says
	// so rather than pretending.
	stop func()
}

// config returns the configuration for reading.
//
// It returns the current pointer under the lock: writers SWAP the pointed-to
// content for a clone (see mutateConfig), so a reader that already took the
// pointer never sees the structure being changed underneath it.
func (s *Server) config() *config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// ErrBusy means a cycle is in progress holding the configuration.
var ErrBusy = errors.New("a scan is in progress; try again once it finishes")

// mutateConfig applies a change to a CLONE and only then publishes it.
//
// The clone exists so an invalid change does not leave the configuration
// half-applied: if fn returns an error, nothing was touched.
//
// The write uses TryLock rather than Lock because a cycle may hold the read for
// minutes, and a panel hanging with no explanation is worse than a clear refusal.
// Writers swap the pointed-to CONTENT, not the pointer, so the cycle runner and
// the vault — which share the same pointer — start seeing the new configuration.
func (s *Server) mutateConfig(fn func(*config.Config) error) error {
	if !s.cfgMu.TryLock() {
		return ErrBusy
	}
	defer s.cfgMu.Unlock()

	updated := s.cfg.Clone()
	if err := fn(updated); err != nil {
		return err
	}
	*s.cfg = *updated
	return nil
}

// withConfigRead holds the configuration during a long operation that reads it
// from beginning to end — in practice, a scan cycle.
func (s *Server) withConfigRead(fn func(*config.Config) error) error {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return fn(s.cfg)
}

// New assembles the server.
func New(cfg *config.Config, st *store.Store, reg *adapter.Registry, v *quarantine.Vault, d *alert.Dispatcher, r *cycle.Runner) *Server {
	return &Server{
		cfg: cfg, store: st, registry: reg, vault: v, alerts: d, runner: r,
		limiter: newRateLimiter(st, cfg.Web.LoginRateLimit),
		now:     time.Now,
	}
}

// WithUpdates gives the panel a way to check for and install releases.
//
// Separate from New so a build with no release key simply never calls it, and the panel
// reports that it cannot check rather than showing a button backed by nothing.
func (s *Server) WithUpdates(u UpdateChecker) *Server {
	s.updates = u
	return s
}

// Handler assembles the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Authentication.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("GET /api/session", s.handleSession)

	// Protected API.
	mux.Handle("GET /api/status", s.protect(s.handleStatus))
	mux.Handle("GET /api/verdicts", s.protect(s.handleVerdicts))
	mux.Handle("GET /api/verdicts/{id}", s.protect(s.handleVerdictDetail))
	mux.Handle("POST /api/verdicts/{id}/decide", s.protect(s.handleDecide))
	mux.Handle("GET /api/quarantine", s.protect(s.handleQuarantineList))
	mux.Handle("POST /api/quarantine/{ref}/restore", s.protect(s.handleRestore))
	mux.Handle("POST /api/quarantine/{ref}/purge", s.protect(s.handlePurge))
	mux.Handle("GET /api/engines", s.protect(s.handleEngines))
	mux.Handle("POST /api/engines/{slug}/install", s.protect(s.handleEngineInstall))
	mux.Handle("GET /api/config", s.protect(s.handleConfigGet))
	mux.Handle("PUT /api/config", s.protect(s.handleConfigPut))
	mux.Handle("POST /api/alert/test", s.protect(s.handleAlertTest))
	mux.Handle("POST /api/scan", s.protect(s.handleScanNow))
	mux.Handle("GET /api/events", s.protect(s.handleEvents))
	mux.Handle("GET /api/cron-line", s.protect(s.handleCronLine))
	mux.Handle("GET /api/update", s.protect(s.handleUpdateStatus))
	// Protected like every other state-changing route: a session AND a same-origin
	// signal. This one replaces the binary that guards the account.
	mux.Handle("POST /api/update", s.protect(s.handleUpdateApply))
	mux.Handle("POST /api/restart", s.protect(s.handleRestart))

	// Panel assets.
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(fmt.Sprintf("the panel assets are missing from the binary: %v", err))
	}
	mux.Handle("GET /", s.securityHeaders(http.FileServer(http.FS(sub))))

	return mux
}

// ListenAndServe starts the panel.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Read once, before any request exists: there is no concurrency at this point,
	// and the listen address does not change at runtime.
	srv := &http.Server{
		Addr:    s.config().Web.Listen,
		Handler: s.Handler(),
		// Explicit timeouts: a slow client must not be able to hold a connection
		// indefinitely in a process that also has to run scans.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(discard{}, "", 0),
	}

	// How the panel stops itself after an update. Graceful: in-flight requests finish, so
	// a scan triggered a second earlier is not cut in half.
	stopped := make(chan struct{})
	var stopOnce sync.Once
	s.stop = func() {
		stopOnce.Do(func() { close(stopped) })
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
		}
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// protect requires a valid session.
func (s *Server) protect(h http.HandlerFunc) http.Handler {
	return s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !s.authenticated(req) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "authentication required",
			})
			return
		}
		// A valid cookie says WHO is asking. It does not say what page asked, and on this
		// deployment those are different questions: the panel lives inside the document
		// root of the site it protects, so a compromised subdomain is same-site and keeps
		// the cookie.
		if err := s.requireSameOrigin(req); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "this request came from another page. State-changing requests to " +
					"the panel have to originate from the panel itself",
			})
			return
		}
		h(w, req)
	}))
}

// securityHeaders applies the defensive headers.
func (s *Server) securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// A CSP with no 'unsafe-inline' for script: the panel displays file paths
		// chosen by the ATTACKER. If one of them contains HTML, the CSP is the last
		// barrier before the panel executes the intruder's code.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// The panel must never be indexed nor show up in a proxy cache.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		h.ServeHTTP(w, req)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		// The response has already started; all that is left is recording it in the
		// body itself.
		_, _ = w.Write([]byte(`{"error":"failed to serialize the response"}`))
	}
}

func writeErr(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]any{"error": fmt.Sprintf(format, args...)})
}

func decodeBody(req *http.Request, v any) error {
	// Body limit: the panel only receives small JSON, and without a limit a huge
	// POST would consume the orchestrator's memory.
	dec := json.NewDecoder(http.MaxBytesReader(nil, req.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

// isSecureRequest answers whether the connection arrived over TLS.
func isSecureRequest(req *http.Request) bool {
	if req.TLS != nil {
		return true
	}
	// The hosting's proxy terminating TLS. We only trust this when the panel is not
	// on localhost, because on localhost there is no proxy at all.
	// The LAST value, not the first. The bridge forwards the client's own headers and
	// then appends its computed ones, so a caller who sends X-Forwarded-Proto: http has
	// their value arrive first — and Header.Get returns the first. That let the caller
	// decide whether their own session cookie got the Secure flag.
	return strings.EqualFold(lastHeaderValue(req, "X-Forwarded-Proto"), "https")
}
