package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
	"github.com/thiagoluga/SentinelHost/internal/web"
)

// Este arquivo cobre o SC-004 pela API HTTP, sem navegador (DECISIONS.md
// D-017): primeiro acesso -> definir senha -> ver achado -> decidir ->
// configurar e-mail -> disparar teste de webhook.
//
// O que ele NAO cobre, e esta declarado: renderizacao, layout e a parte do
// SC-004 que e usabilidade real. Isso continua sendo validacao manual.

type painel struct {
	srv    *httptest.Server
	http   *http.Client
	cfg    *config.Config
	store  *store.Store
	site   string
	cfgDir string
}

func montarPainel(t *testing.T) *painel {
	t.Helper()
	ctx := context.Background()
	base := t.TempDir()
	site := filepath.Join(base, "public_html")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := config.Default()
	cfg.General.Roots = []string{site}
	cfg.General.DataDir = filepath.Join(base, "dados")
	cfg.SetPath(filepath.Join(base, "config.toml"))
	if err := cfg.EnsureDataDirs(); err != nil {
		t.Fatalf("EnsureDataDirs: %v", err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	st, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	reg := adapter.NewRegistry()
	vault := quarantine.New(cfg.QuarantineDir(), cfg.Quarantine, st)
	disp := alert.NewDispatcher(ctx, cfg, st)
	runner := cycle.New(cfg, st, reg, vault)

	srv := httptest.NewServer(web.New(cfg, st, reg, vault, disp, runner).Handler())
	t.Cleanup(srv.Close)

	// Cliente com jar de cookies: o painel autentica por cookie de sessao.
	jar := &jarSimples{cookies: map[string]*http.Cookie{}}
	return &painel{
		srv: srv, http: &http.Client{Jar: jar, Timeout: 30 * time.Second},
		cfg: cfg, store: st, site: site, cfgDir: base,
	}
}

// jarSimples e um cookie jar minimo (o net/http/cookiejar exige uma lista de
// sufixos publicos que nao faz sentido para 127.0.0.1).
type jarSimples struct{ cookies map[string]*http.Cookie }

func (j *jarSimples) SetCookies(_ *urlURL, cookies []*http.Cookie) {
	for _, c := range cookies {
		if c.MaxAge < 0 {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *jarSimples) Cookies(_ *urlURL) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}

func (p *painel) req(t *testing.T, metodo, caminho string, corpo any) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	var err error
	if corpo != nil {
		b, _ := json.Marshal(corpo)
		r, err = http.NewRequest(metodo, p.srv.URL+caminho, bytes.NewReader(b))
		if r != nil {
			r.Header.Set("Content-Type", "application/json")
		}
	} else {
		r, err = http.NewRequest(metodo, p.srv.URL+caminho, nil)
	}
	if err != nil {
		t.Fatalf("montando requisicao: %v", err)
	}

	resp, err := p.http.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", metodo, caminho, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestSC004FluxoCompletoDoPainel percorre o caminho do usuario leigo.
func TestSC004FluxoCompletoDoPainel(t *testing.T) {
	p := montarPainel(t)
	ctx := context.Background()

	// 1. Antes de qualquer coisa, o painel esta fechado.
	st, _ := p.req(t, "GET", "/api/session", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/session: %d", st)
	}
	st, _ = p.req(t, "GET", "/api/status", nil)
	if st != http.StatusUnauthorized {
		t.Fatalf("a API deveria exigir autenticacao, veio %d", st)
	}

	// 2. Primeiro acesso: definir a senha.
	st, body := p.req(t, "POST", "/api/setup", map[string]any{"password": "curta"})
	if st != http.StatusBadRequest {
		t.Fatalf("senha curta deveria ser recusada, veio %d", st)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "10 caracteres") {
		t.Errorf("a mensagem deveria explicar o minimo, veio %q", msg)
	}

	st, _ = p.req(t, "POST", "/api/setup", map[string]any{"password": "senha-forte-de-teste"})
	if st != http.StatusOK {
		t.Fatalf("setup: %d", st)
	}

	// 3. Definir a senha ja autentica; a API abre.
	st, status := p.req(t, "GET", "/api/status", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/status apos setup: %d", st)
	}
	// A cobertura vem junto do resumo, sempre.
	if _, ok := status["engines"]; !ok {
		t.Error("o status deveria trazer a cobertura de engines")
	}
	if _, ok := status["automatic_action"]; !ok {
		t.Error("o status deveria dizer se a acao automatica esta liberada")
	}

	// 4. Segundo setup e recusado: senao qualquer um que alcancasse a porta
	//    poderia redefinir a senha.
	st, _ = p.req(t, "POST", "/api/setup", map[string]any{"password": "outra-senha-qualquer"})
	if st != http.StatusConflict {
		t.Fatalf("redefinir a senha por /api/setup deveria ser recusado, veio %d", st)
	}

	// 5. Um achado pendente aparece na lista.
	arquivo := filepath.Join(p.site, "backdoor.php")
	if err := os.WriteFile(arquivo, []byte("<?php // amostra de teste\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	v := criarVeredito(t, ctx, p.store, arquivo)

	st, lista := p.req(t, "GET", "/api/verdicts?pending=1", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/verdicts: %d", st)
	}
	vs, _ := lista["verdicts"].([]any)
	if len(vs) != 1 {
		t.Fatalf("esperava 1 achado pendente, veio %d", len(vs))
	}

	// 6. O detalhe traz os votos: e o que responde "por que este arquivo?".
	st, detalhe := p.req(t, "GET", "/api/verdicts/"+v.VerdictID, nil)
	if st != http.StatusOK {
		t.Fatalf("GET detalhe: %d", st)
	}
	dv, _ := detalhe["verdict"].(map[string]any)
	votos, _ := dv["votes"].([]any)
	if len(votos) == 0 {
		t.Error("o detalhe do veredito veio sem votos")
	}

	// 7. Decidir: quarentenar.
	st, dec := p.req(t, "POST", "/api/verdicts/"+v.VerdictID+"/decide",
		map[string]any{"action": "quarantine"})
	if st != http.StatusOK {
		t.Fatalf("decidir quarentenar: %d (%v)", st, dec)
	}
	ref, _ := dec["quarantine_ref"].(string)
	if ref == "" {
		t.Fatal("a quarentena nao devolveu a referencia")
	}
	if _, err := os.Stat(arquivo); !os.IsNotExist(err) {
		t.Error("o arquivo deveria ter saido do lugar")
	}

	// 8. O item aparece na quarentena e volta byte a byte.
	st, cofre := p.req(t, "GET", "/api/quarantine", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/quarantine: %d", st)
	}
	itens, _ := cofre["items"].([]any)
	if len(itens) != 1 {
		t.Fatalf("esperava 1 item no cofre, veio %d", len(itens))
	}

	st, rest := p.req(t, "POST", "/api/quarantine/"+ref+"/restore", nil)
	if st != http.StatusOK {
		t.Fatalf("restaurar: %d (%v)", st, rest)
	}
	conteudo, err := os.ReadFile(arquivo)
	if err != nil {
		t.Fatalf("o arquivo nao voltou: %v", err)
	}
	if string(conteudo) != "<?php // amostra de teste\n" {
		t.Error("o arquivo nao voltou byte a byte")
	}

	// 9. Configurar e-mail pelo painel — e o TOML tem que refletir (FR-014).
	st, _ = p.req(t, "PUT", "/api/config", map[string]any{
		"email": map[string]any{
			"enabled": true,
			"host":    "smtp.exemplo.test",
			"port":    587,
			"from":    "sentinel@exemplo.test",
			"to":      []string{"dono@exemplo.test"},
			"levels":  []string{"confirmed"},
		},
	})
	if st != http.StatusOK {
		t.Fatalf("PUT /api/config: %d", st)
	}

	doDisco, err := config.Load(p.cfg.Path())
	if err != nil {
		t.Fatalf("relendo o TOML: %v", err)
	}
	if !doDisco.Alerts.Email.Enabled || doDisco.Alerts.Email.Host != "smtp.exemplo.test" {
		t.Errorf("a alteracao do painel nao chegou ao TOML: %+v", doDisco.Alerts.Email)
	}

	// 10. Segredos nunca saem pela API.
	st, cfgResp := p.req(t, "GET", "/api/config", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/config: %d", st)
	}
	if strings.Contains(mustJSON(t, cfgResp), "senha-forte-de-teste") {
		t.Error("a senha do painel vazou pela API de configuracao")
	}

	// 11. Teste de webhook: o resultado REAL vai para a tela.
	rec := &receptor{status: http.StatusTeapot}
	hookSrv := httptest.NewServer(rec.handler())
	defer hookSrv.Close()

	st, _ = p.req(t, "PUT", "/api/config", map[string]any{
		"webhooks": []map[string]any{{
			"id": "meu-hook", "enabled": true, "url": hookSrv.URL,
			"secret": "s3gr3d0", "events": []string{"verdict.confirmed"},
		}},
	})
	if st != http.StatusOK {
		t.Fatalf("salvando webhook: %d", st)
	}

	st, teste := p.req(t, "POST", "/api/alert/test",
		map[string]any{"channel": "webhook", "id": "meu-hook"})
	if st != http.StatusOK {
		t.Fatalf("teste de webhook: %d", st)
	}
	if ok, _ := teste["ok"].(bool); ok {
		t.Error("o teste deveria ter falhado com HTTP 418")
	}
	if hs, _ := teste["http_status"].(float64); int(hs) != http.StatusTeapot {
		t.Errorf("o status real do endpoint deveria aparecer, veio %v", teste["http_status"])
	}

	// 12. Logout fecha o painel.
	st, _ = p.req(t, "POST", "/api/logout", nil)
	if st != http.StatusOK {
		t.Fatalf("logout: %d", st)
	}
	st, _ = p.req(t, "GET", "/api/status", nil)
	if st != http.StatusUnauthorized {
		t.Fatalf("apos o logout a API deveria fechar, veio %d", st)
	}
}

func TestPainelExigeConfirmacaoTextualParaPurgar(t *testing.T) {
	p := montarPainel(t)
	ctx := context.Background()
	autenticar(t, p)

	arquivo := filepath.Join(p.site, "x.php")
	if err := os.WriteFile(arquivo, []byte("<?php\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	v := criarVeredito(t, ctx, p.store, arquivo)
	_, dec := p.req(t, "POST", "/api/verdicts/"+v.VerdictID+"/decide",
		map[string]any{"action": "quarantine"})
	ref, _ := dec["quarantine_ref"].(string)

	// Um clique acidental nao pode bastar para a unica operacao irreversivel.
	st, _ := p.req(t, "POST", "/api/quarantine/"+ref+"/purge", map[string]any{"confirm": "sim"})
	if st != http.StatusBadRequest {
		t.Fatalf("purga sem a palavra exata deveria ser recusada, veio %d", st)
	}
	item, err := p.store.GetQuarantineItem(ctx, ref)
	if err != nil || item.Status != store.QuarantineActive {
		t.Fatalf("o item deveria continuar no cofre: %+v (%v)", item, err)
	}

	st, _ = p.req(t, "POST", "/api/quarantine/"+ref+"/purge", map[string]any{"confirm": "purgar"})
	if st != http.StatusOK {
		t.Fatalf("purga confirmada: %d", st)
	}
}

func TestPainelLimitaTentativasDeLogin(t *testing.T) {
	// Sem limite, um painel exposto por engano vira alvo de forca bruta.
	p := montarPainel(t)
	st, _ := p.req(t, "POST", "/api/setup", map[string]any{"password": "senha-forte-de-teste"})
	if st != http.StatusOK {
		t.Fatalf("setup: %d", st)
	}
	_, _ = p.req(t, "POST", "/api/logout", nil)

	limite := p.cfg.Web.LoginRateLimit
	bloqueou := false
	for i := 0; i < limite+3; i++ {
		st, _ := p.req(t, "POST", "/api/login", map[string]any{"password": "errada"})
		if st == http.StatusTooManyRequests {
			bloqueou = true
			break
		}
	}
	if !bloqueou {
		t.Errorf("o painel aceitou mais de %d tentativas seguidas sem bloquear", limite)
	}
}

func TestPainelAplicaCabecalhosDeSeguranca(t *testing.T) {
	p := montarPainel(t)
	resp, err := p.http.Get(p.srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// A CSP e a ultima barreira: o painel exibe caminhos escolhidos pelo
	// atacante.
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP sem script-src restrito: %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("a CSP permite script inline")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("o painel pode ser embutido em iframe")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("falta nosniff")
	}
	if !strings.Contains(resp.Header.Get("X-Robots-Tag"), "noindex") {
		t.Error("o painel poderia ser indexado")
	}
}

// TestPainelSuportaConfigESacanConcorrentes existe para o `-race` do CI.
//
// O painel EDITA a configuracao enquanto um ciclo disparado por /api/scan a
// LE — mapas e fatias compartilhados, sem sincronizacao nenhuma na primeira
// versao. O detector de corrida so acusa se os dois acontecerem de fato ao
// mesmo tempo, e nenhum outro teste faz isso.
func TestPainelSuportaConfigEScanConcorrentes(t *testing.T) {
	p := montarPainel(t)
	autenticar(t, p)

	const rodadas = 12
	pronto := make(chan struct{})
	var wg sync.WaitGroup

	// Escritores de configuracao.
	for i := 0; i < rodadas; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-pronto
			// Cada escrita mexe em fatias e mapas — exatamente o que uma copia
			// rasa compartilharia com quem esta lendo.
			st, _ := p.req(t, "PUT", "/api/config", map[string]any{
				"whitelist": []string{fmt.Sprintf("**/plugin-%d/**", n)},
				"exclude":   []string{fmt.Sprintf("**/cache-%d/**", n)},
				"engines": map[string]any{
					"amwscan": map[string]any{"weight": 0.5 + float64(n)/100},
				},
			})
			// 409 e resposta legitima: ha um scan segurando a configuracao.
			if st != http.StatusOK && st != http.StatusConflict {
				t.Errorf("PUT /api/config devolveu %d", st)
			}
		}(i)
	}

	// Leitores e scans concorrentes.
	for i := 0; i < rodadas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-pronto
			if st, _ := p.req(t, "GET", "/api/status", nil); st != http.StatusOK {
				t.Errorf("GET /api/status devolveu %d", st)
			}
			if st, _ := p.req(t, "POST", "/api/scan", map[string]any{"full": false}); st != http.StatusOK && st != http.StatusConflict {
				t.Errorf("POST /api/scan devolveu %d", st)
			}
		}()
	}

	close(pronto)
	wg.Wait()

	// A configuracao no disco tem que continuar valida e legivel: uma escrita
	// concorrente nao pode deixar o TOML pela metade.
	doDisco, err := config.Load(p.cfg.Path())
	if err != nil {
		t.Fatalf("a configuracao ficou ilegivel apos escritas concorrentes: %v", err)
	}
	if res := doDisco.Validate(); res.HasErrors() {
		t.Errorf("a configuracao ficou invalida apos escritas concorrentes: %v", res.Errors())
	}
}

func TestPainelRecusaConfiguracaoInvalida(t *testing.T) {
	// Configuracao invalida nao pode chegar a tocar o arquivo: senao a
	// ferramenta nao sobe depois.
	p := montarPainel(t)
	autenticar(t, p)

	antes, err := os.ReadFile(p.cfg.Path())
	if err != nil {
		t.Fatalf("lendo config: %v", err)
	}

	st, _ := p.req(t, "PUT", "/api/config", map[string]any{
		"confirmed_at": 0.3, "likely_at": 0.6, // fora de ordem
	})
	if st != http.StatusBadRequest {
		t.Fatalf("limiares fora de ordem deveriam ser recusados, veio %d", st)
	}

	depois, _ := os.ReadFile(p.cfg.Path())
	if !bytes.Equal(antes, depois) {
		t.Error("o arquivo de configuracao foi alterado apesar da recusa")
	}
}

// Helpers ---------------------------------------------------------------------------

func autenticar(t *testing.T, p *painel) {
	t.Helper()
	st, _ := p.req(t, "POST", "/api/setup", map[string]any{"password": "senha-forte-de-teste"})
	if st != http.StatusOK {
		t.Fatalf("setup: %d", st)
	}
}

func criarVeredito(t *testing.T, ctx context.Context, st *store.Store, arquivo string) schema.Verdict {
	t.Helper()
	sha, err := hashDe(arquivo)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     verdict.FindingID("s_painel", "teste", "regra", sha),
		FileSHA256:    sha,
		FilePath:      arquivo,
		FileSize:      64,
		Level:         schema.LevelConfirmed,
		Score:         0.95,
		Votes: []schema.Vote{
			{Engine: "maldet", Weight: 1.0, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 1.0, Rule: "php.teste", Category: schema.CategoryBackdoor},
			{Engine: "amwscan", Weight: 0.8, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 0.8, Rule: "KNOWN_MALWARE", Category: schema.CategoryBackdoor},
		},
		ActionTaken: schema.ActionNone,
		ScanID:      "s_painel",
		CreatedAt:   time.Now(),
	}
	if err := st.SaveVerdict(ctx, v); err != nil {
		t.Fatalf("SaveVerdict: %v", err)
	}
	return v
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
