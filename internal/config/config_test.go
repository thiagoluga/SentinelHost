package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("escrevendo config de teste: %v", err)
	}
	return path
}

func TestDefaultEValido(t *testing.T) {
	cfg := config.Default()
	cfg.General.Roots = []string{"/home/user/public_html"}

	res := cfg.Validate()
	if res.HasErrors() {
		t.Fatalf("a configuracao padrao tem que ser valida, veio: %v", res.Errors())
	}
}

func TestDefaultESeguroDeSaida(t *testing.T) {
	// A primeira experiencia do usuario tem que ser "nao quebrou nada".
	cfg := config.Default()

	if !cfg.General.ObservationMode {
		t.Error("modo observacao deveria vir ligado")
	}
	if cfg.General.GracePeriodDays != 7 {
		t.Errorf("periodo de graca deveria ser 7 dias, veio %d", cfg.General.GracePeriodDays)
	}
	if cfg.Limits.Nice != 19 {
		t.Errorf("nice deveria ser 19 (Principio IV), veio %d", cfg.Limits.Nice)
	}
	if cfg.Quarantine.AutoPurge {
		t.Error("purga automatica nao pode vir ligada: apagar arquivo e decisao do usuario")
	}
	if !strings.HasPrefix(cfg.Web.Listen, "127.0.0.1") {
		t.Errorf("o painel deveria escutar em localhost por padrao, veio %q", cfg.Web.Listen)
	}
	if cfg.Limits.EngineTimeout.Duration <= 0 {
		t.Error("timeout de engine tem que vir ativo por padrao")
	}
}

func TestPesosPadraoSeguemODocumentoDeEsquema(t *testing.T) {
	// docs/esquema-e-adaptadores.md secao 2.1 fixa estes pesos.
	cfg := config.Default()
	esperado := map[string]float64{
		"wp-checksums":       1.5,
		"maldet":             1.0,
		"amwscan":            0.8,
		"php-malware-finder": 0.8,
	}
	for slug, peso := range esperado {
		if got := cfg.WeightFor(slug); got != peso {
			t.Errorf("peso de %s: esperado %v, veio %v", slug, peso, got)
		}
	}
}

func TestLoadPreservaPadroesNaoDeclarados(t *testing.T) {
	// O usuario escreve so o que quer mudar; o resto continua no padrao seguro.
	path := writeTOML(t, `
[general]
roots = ["/home/user/public_html"]

[limits]
nice = 15
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Limits.Nice != 15 {
		t.Errorf("nice declarado nao foi lido: %d", cfg.Limits.Nice)
	}
	if cfg.Limits.MaxFileSizeMB != config.Default().Limits.MaxFileSizeMB {
		t.Error("limite nao declarado deveria manter o padrao")
	}
	if !cfg.General.ObservationMode {
		t.Error("modo observacao nao declarado deveria manter o padrao (ligado)")
	}
}

func TestLoadReclamaDeChaveDesconhecida(t *testing.T) {
	// O pior cenario numa ferramenta de seguranca: o usuario acredita ter
	// desligado a acao automatica e nao desligou porque errou o nome da chave.
	path := writeTOML(t, `
[general]
roots = ["/tmp/x"]
observation_moed = false
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("chave com erro de digitacao deveria ser reportada")
	}
	if !strings.Contains(err.Error(), "observation_moed") {
		t.Errorf("o erro deveria citar a chave errada, veio: %v", err)
	}
}

func TestLoadNaoEncontrado(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nao-existe.toml"))
	if err == nil {
		t.Fatal("esperava erro")
	}
	if !strings.Contains(err.Error(), "nao encontrado") {
		t.Errorf("erro deveria indicar arquivo ausente, veio: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	// FR-014: o painel grava o TOML e o TOML alimenta o painel. Se o
	// round-trip perder um campo, os dois lados divergem em silencio.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	orig := config.Default()
	orig.General.Roots = []string{"/home/user/public_html", "/home/user/loja"}
	orig.General.ObservationMode = false
	orig.General.FirstRunAt = time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)
	orig.Verdict.Whitelist = []string{"**/wp-content/plugins/meu-plugin/**"}
	orig.Alerts.Email.Enabled = true
	orig.Alerts.Email.Host = "smtp.exemplo.com"
	orig.Alerts.Email.From = "sentinel@exemplo.com"
	orig.Alerts.Email.To = []string{"dono@exemplo.com"}
	orig.Alerts.Webhooks = []config.Webhook{{
		ID: "slack", Enabled: true, URL: "https://hooks.exemplo.com/x",
		Secret: "s3cr3t", Events: []string{"verdict.confirmed", "scan.completed"},
	}}
	orig.Engines["amwscan"] = config.Engine{Enabled: true, Weight: 0.9, Path: "/usr/bin/php"}

	if err := orig.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	back, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load apos Save: %v", err)
	}

	if len(back.General.Roots) != 2 || back.General.Roots[1] != "/home/user/loja" {
		t.Errorf("roots perdidas: %v", back.General.Roots)
	}
	if back.General.ObservationMode {
		t.Error("observation_mode=false nao sobreviveu ao round-trip")
	}
	if !back.General.FirstRunAt.Equal(orig.General.FirstRunAt) {
		t.Errorf("first_run_at: esperado %v, veio %v", orig.General.FirstRunAt, back.General.FirstRunAt)
	}
	if len(back.Verdict.Whitelist) != 1 {
		t.Errorf("whitelist perdida: %v", back.Verdict.Whitelist)
	}
	if len(back.Alerts.Webhooks) != 1 || back.Alerts.Webhooks[0].Secret != "s3cr3t" {
		t.Errorf("webhook perdido: %+v", back.Alerts.Webhooks)
	}
	if back.Engines["amwscan"].Weight != 0.9 || back.Engines["amwscan"].Path != "/usr/bin/php" {
		t.Errorf("config de engine perdida: %+v", back.Engines["amwscan"])
	}
	if back.Limits.EngineTimeout.Duration != orig.Limits.EngineTimeout.Duration {
		t.Errorf("duracao perdida: %v vs %v", back.Limits.EngineTimeout, orig.Limits.EngineTimeout)
	}
}

func TestSaveUsaPermissaoRestrita(t *testing.T) {
	if runtime.GOOS == "windows" {
		// DECISIONS.md D-002: o alvo e Linux userland; o Windows e so a
		// estacao de trabalho. O skip e explicito para a suite nao mentir
		// sobre cobertura.
		t.Skip("permissoes POSIX nao se aplicam no Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := config.Default()
	cfg.General.Roots = []string{"/tmp/x"}
	if err := cfg.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// O arquivo guarda senha de SMTP e segredos de webhook.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("configuracao legivel por outros: %v", perm)
	}
}

func TestDuracaoVaiEVoltaComoTextoLegivel(t *testing.T) {
	path := writeTOML(t, `
[general]
roots = ["/tmp/x"]

[limits]
engine_timeout = "90s"
batch_pause = "250ms"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Limits.EngineTimeout.Duration != 90*time.Second {
		t.Errorf("engine_timeout: %v", cfg.Limits.EngineTimeout)
	}
	if cfg.Limits.BatchPause.Duration != 250*time.Millisecond {
		t.Errorf("batch_pause: %v", cfg.Limits.BatchPause)
	}
}

func TestDuracaoInvalidaEReportada(t *testing.T) {
	path := writeTOML(t, `
[general]
roots = ["/tmp/x"]

[limits]
engine_timeout = "cinco minutos"
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("duracao invalida deveria ser recusada")
	}
	if !strings.Contains(err.Error(), "30s") {
		t.Errorf("a mensagem deveria ensinar o formato, veio: %v", err)
	}
}

// Validacao -----------------------------------------------------------------

func baseValida() *config.Config {
	c := config.Default()
	c.General.Roots = []string{"/home/user/public_html"}
	return c
}

func TestValidateRecusaLimiaresForaDeOrdem(t *testing.T) {
	// confirmed abaixo de likely tornaria o nivel confirmed inalcancavel.
	c := baseValida()
	c.Verdict.ConfirmedAt = 0.5
	c.Verdict.LikelyAt = 0.7

	res := c.Validate()
	if !res.HasErrors() {
		t.Fatal("limiares fora de ordem deveriam ser erro fatal")
	}
}

func TestValidateRecusaPurgaImediata(t *testing.T) {
	// Purga automatica com retencao 0 apagaria o arquivo no mesmo instante
	// da quarentena: acao irreversivel, viola o Principio I.
	c := baseValida()
	c.Quarantine.AutoPurge = true
	c.Quarantine.RetentionDays = 0

	res := c.Validate()
	if !res.HasErrors() {
		t.Fatal("purga imediata deveria ser erro fatal")
	}
}

func TestValidateRecusaRaizBarra(t *testing.T) {
	c := baseValida()
	c.General.Roots = []string{"/"}
	if !c.Validate().HasErrors() {
		t.Fatal("varrer / deveria ser recusado")
	}
}

func TestValidateRecusaSemEngine(t *testing.T) {
	c := baseValida()
	for slug, e := range c.Engines {
		e.Enabled = false
		c.Engines[slug] = e
	}
	if !c.Validate().HasErrors() {
		t.Fatal("nenhum engine habilitado deveria ser erro")
	}
}

func TestValidateAvisaSobreEngineUnico(t *testing.T) {
	// Nao existe consenso com um voto so — mas isso e um aviso, nao um erro:
	// a ferramenta que se recusa a rodar protege menos que a que roda avisando.
	c := baseValida()
	for slug, e := range c.Engines {
		if slug != "amwscan" {
			e.Enabled = false
			c.Engines[slug] = e
		}
	}
	res := c.Validate()
	if res.HasErrors() {
		t.Fatalf("engine unico nao deveria impedir a execucao: %v", res.Errors())
	}
	if len(res.Warnings()) == 0 {
		t.Error("engine unico deveria gerar aviso")
	}
}

func TestValidateAvisaSobrePainelExposto(t *testing.T) {
	c := baseValida()
	c.Web.Listen = "0.0.0.0:8787"
	res := c.Validate()
	if res.HasErrors() {
		t.Fatalf("expor o painel e escolha do usuario, nao erro: %v", res.Errors())
	}
	if len(res.Warnings()) == 0 {
		t.Error("painel exposto deveria gerar aviso")
	}
}

func TestValidateRecusaEventoDeWebhookDesconhecido(t *testing.T) {
	c := baseValida()
	c.Alerts.Webhooks = []config.Webhook{{
		ID: "w1", Enabled: true, URL: "https://x.exemplo.com",
		Secret: "s", Events: []string{"verdict.inventado"},
	}}
	if !c.Validate().HasErrors() {
		t.Fatal("evento desconhecido deveria ser erro")
	}
}

func TestValidateRecusaWebhooksComIDDuplicado(t *testing.T) {
	c := baseValida()
	w := config.Webhook{ID: "dup", Enabled: true, URL: "https://x.exemplo.com", Secret: "s", Events: []string{"scan.completed"}}
	c.Alerts.Webhooks = []config.Webhook{w, w}
	if !c.Validate().HasErrors() {
		t.Fatal("ids duplicados deveriam ser erro")
	}
}

func TestValidateEmailHabilitadoExigeDestinatario(t *testing.T) {
	c := baseValida()
	c.Alerts.Email.Enabled = true
	c.Alerts.Email.Host = "smtp.exemplo.com"
	c.Alerts.Email.From = "a@exemplo.com"
	c.Alerts.Email.To = nil
	if !c.Validate().HasErrors() {
		t.Fatal("e-mail habilitado sem destinatario deveria ser erro")
	}
}

// Periodo de graca ----------------------------------------------------------

func TestPeriodoDeGracaBloqueiaAcaoAutomatica(t *testing.T) {
	c := baseValida()
	c.General.ObservationMode = false
	c.General.GracePeriodDays = 7
	c.General.FirstRunAt = time.Now().Add(-2 * 24 * time.Hour)

	ok, motivo := c.AutomaticActionAllowed(time.Now())
	if ok {
		t.Fatal("acao automatica nao pode ser liberada dentro do periodo de graca")
	}
	if !strings.Contains(motivo, "graca") {
		t.Errorf("motivo deveria citar o periodo de graca, veio %q", motivo)
	}
}

func TestPrimeiroCicloEstaNoPeriodoDeGraca(t *testing.T) {
	// "Nunca rodou" tem que significar inicio do periodo, nao fim dele.
	c := baseValida()
	c.General.ObservationMode = false
	c.General.FirstRunAt = time.Time{}

	if !c.InGracePeriod(time.Now()) {
		t.Fatal("instalacao que nunca rodou deveria estar no periodo de graca")
	}
	if ok, _ := c.AutomaticActionAllowed(time.Now()); ok {
		t.Fatal("primeiro ciclo nao pode ja quarentenar")
	}
}

func TestAposGracaEObservacaoDesligadaAcaoELiberada(t *testing.T) {
	c := baseValida()
	c.General.ObservationMode = false
	c.General.GracePeriodDays = 7
	c.General.FirstRunAt = time.Now().Add(-30 * 24 * time.Hour)

	ok, motivo := c.AutomaticActionAllowed(time.Now())
	if !ok {
		t.Fatalf("acao deveria estar liberada, motivo: %q", motivo)
	}
}

func TestObservacaoVenceMesmoForaDaGraca(t *testing.T) {
	c := baseValida()
	c.General.ObservationMode = true
	c.General.FirstRunAt = time.Now().Add(-365 * 24 * time.Hour)

	if ok, _ := c.AutomaticActionAllowed(time.Now()); ok {
		t.Fatal("modo observacao tem que bloquear acao automatica sempre")
	}
}

func TestGracaZeroDesligaOPeriodo(t *testing.T) {
	c := baseValida()
	c.General.ObservationMode = false
	c.General.GracePeriodDays = 0
	c.General.FirstRunAt = time.Time{}

	if c.InGracePeriod(time.Now()) {
		t.Fatal("grace_period_days=0 deveria desligar o periodo de graca")
	}
}
