// Package web serve o painel embutido no binario.
//
// Sem framework JS e sem build step: os assets sao HTML/CSS/JS vanilla
// embutidos por go:embed (Principio VII). O painel e uma evolucao direta de
// docs/painel-mockup.html consumindo a API JSON real.
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

// Server serve o painel e a API.
type Server struct {
	// cfgMu protege cfg. O painel EDITA a configuracao enquanto um ciclo
	// disparado por /api/scan a LE — sem o lock, isso e uma corrida de dados
	// de verdade sobre os mesmos mapas e fatias.
	cfgMu sync.RWMutex
	cfg   *config.Config

	store    *store.Store
	registry *adapter.Registry
	vault    *quarantine.Vault
	alerts   *alert.Dispatcher
	runner   *cycle.Runner

	limiter *rateLimiter
	now     func() time.Time
}

// config devolve a configuracao para leitura.
//
// Devolve o ponteiro atual sob lock: quem escreve TROCA o conteudo apontado
// por um clone (ver replaceConfig), entao um leitor que ja pegou o ponteiro
// nunca ve a estrutura sendo alterada por baixo.
func (s *Server) config() *config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// ErrBusy indica que ha um ciclo em andamento segurando a configuracao.
var ErrBusy = errors.New("ha um scan em andamento; tente de novo quando ele terminar")

// mutateConfig aplica uma alteracao sobre um CLONE e so entao publica.
//
// O clone existe para que uma alteracao invalida nao deixe a configuracao pela
// metade: se fn devolver erro, nada foi tocado.
//
// A escrita usa TryLock em vez de Lock porque um ciclo pode segurar a leitura
// por minutos, e o painel pendurado sem explicacao e pior que uma recusa
// clara. Quem escreve trocam o CONTEUDO apontado, e nao o ponteiro, para que o
// executor de ciclos e o cofre — que compartilham o mesmo ponteiro — passem a
// enxergar a configuracao nova.
func (s *Server) mutateConfig(fn func(*config.Config) error) error {
	if !s.cfgMu.TryLock() {
		return ErrBusy
	}
	defer s.cfgMu.Unlock()

	novo := s.cfg.Clone()
	if err := fn(novo); err != nil {
		return err
	}
	*s.cfg = *novo
	return nil
}

// withConfigRead segura a configuracao durante uma operacao longa que a le do
// comeco ao fim — na pratica, um ciclo de scan.
func (s *Server) withConfigRead(fn func(*config.Config) error) error {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return fn(s.cfg)
}

// New monta o servidor.
func New(cfg *config.Config, st *store.Store, reg *adapter.Registry, v *quarantine.Vault, d *alert.Dispatcher, r *cycle.Runner) *Server {
	return &Server{
		cfg: cfg, store: st, registry: reg, vault: v, alerts: d, runner: r,
		limiter: newRateLimiter(cfg.Web.LoginRateLimit),
		now:     time.Now,
	}
}

// Handler monta as rotas.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Autenticacao.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("GET /api/session", s.handleSession)

	// API protegida.
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

	// Assets do painel.
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(fmt.Sprintf("assets do painel ausentes do binario: %v", err))
	}
	mux.Handle("GET /", s.securityHeaders(http.FileServer(http.FS(sub))))

	return mux
}

// ListenAndServe sobe o painel.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Lido uma vez, antes de qualquer requisicao existir: nao ha concorrencia
	// neste ponto, e o endereco de escuta nao muda em tempo de execucao.
	srv := &http.Server{
		Addr:    s.config().Web.Listen,
		Handler: s.Handler(),
		// Timeouts explicitos: um cliente lento nao pode segurar uma conexao
		// indefinidamente num processo que tambem precisa rodar scans.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(discard{}, "", 0),
	}

	go func() {
		<-ctx.Done()
		desligar, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(desligar)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// protect exige sessao valida.
func (s *Server) protect(h http.HandlerFunc) http.Handler {
	return s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !s.authenticated(req) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "autenticacao necessaria",
			})
			return
		}
		h(w, req)
	}))
}

// securityHeaders aplica cabecalhos de defesa.
func (s *Server) securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// CSP sem 'unsafe-inline' para script: o painel exibe caminhos de
		// arquivos escolhidos pelo ATACANTE. Se um deles contiver HTML, a CSP
		// e a ultima barreira antes de o painel executar codigo do invasor.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// O painel nunca deve ser indexado nem aparecer em cache de proxy.
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
		// A resposta ja comecou; so resta registrar no proprio corpo.
		_, _ = w.Write([]byte(`{"error":"falha ao serializar resposta"}`))
	}
}

func writeErr(w http.ResponseWriter, status int, formato string, args ...any) {
	writeJSON(w, status, map[string]any{"error": fmt.Sprintf(formato, args...)})
}

func decodeBody(req *http.Request, v any) error {
	// Limite de corpo: o painel so recebe JSON pequeno, e sem limite um POST
	// gigante consumiria a memoria do orquestrador.
	dec := json.NewDecoder(http.MaxBytesReader(nil, req.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("corpo da requisicao invalido: %w", err)
	}
	return nil
}

// isSecureRequest responde se a conexao chegou por TLS.
func isSecureRequest(req *http.Request) bool {
	if req.TLS != nil {
		return true
	}
	// Proxy da hospedagem terminando TLS. So confiamos nisto quando o painel
	// nao esta em localhost, porque em localhost nao ha proxy nenhum.
	return strings.EqualFold(req.Header.Get("X-Forwarded-Proto"), "https")
}
