package adapter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// fake e um adaptador controlavel para exercitar a blindagem.
type fake struct {
	slug        string
	panicOn     string
	scanErr     error
	scanStatus  schema.ScanStatus
	parseErr    error
	report      schema.ScanReport
	probeResult adapter.ProbeResult
}

func (f *fake) Info() adapter.Info {
	if f.panicOn == "info" {
		panic("boom no Info")
	}
	return adapter.Info{Slug: f.slug, Kind: schema.KindMalware, DefaultWeight: 0.8}
}

func (f *fake) Probe(context.Context, adapter.Environment) adapter.ProbeResult {
	if f.panicOn == "probe" {
		panic("boom no Probe")
	}
	return f.probeResult
}

func (f *fake) Install(context.Context, adapter.Environment) error {
	if f.panicOn == "install" {
		panic("boom no Install")
	}
	return adapter.ErrNotInstallable
}

func (f *fake) UpdateSignatures(context.Context, adapter.Environment) (time.Time, error) {
	if f.panicOn == "update" {
		panic("boom no UpdateSignatures")
	}
	return time.Now(), nil
}

func (f *fake) Scan(context.Context, adapter.Environment, adapter.ScanRequest) (adapter.RawOutput, error) {
	if f.panicOn == "scan" {
		panic("boom no Scan")
	}
	return adapter.RawOutput{Engine: f.slug, Status: f.scanStatus}, f.scanErr
}

func (f *fake) Parse(adapter.RawOutput) (schema.ScanReport, error) {
	if f.panicOn == "parse" {
		panic("boom no Parse")
	}
	return f.report, f.parseErr
}

func req() adapter.ScanRequest {
	return adapter.ScanRequest{
		ScanID: "s_1", Root: "/home/user/public_html",
		Mode: schema.ModeIncremental, Paths: []string{"/home/user/public_html/x.php"},
	}
}

func TestPanicoNoScanViraAbstencao(t *testing.T) {
	// Um adaptador de terceiro com um bug de indice nao pode derrubar a
	// protecao do site inteiro (obrigacao 5 do contrato).
	a := &fake{slug: "quebrado", panicOn: "scan"}

	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())

	if !rep.Abstains() {
		t.Fatalf("panico deveria virar abstencao, veio status %q", rep.Status)
	}
	if rep.Engine != "quebrado" {
		t.Errorf("o engine culpado deveria estar no relatorio, veio %q", rep.Engine)
	}
	if !strings.Contains(rep.Error, "panico") {
		t.Errorf("o relatorio deveria dizer que houve panico, veio: %q", rep.Error)
	}
	if len(rep.Findings) != 0 {
		t.Error("relatorio de falha nao pode carregar achados")
	}
}

func TestPanicoNoParseViraAbstencao(t *testing.T) {
	a := &fake{slug: "quebrado", panicOn: "parse", scanStatus: schema.StatusCompleted}
	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())
	if !rep.Abstains() {
		t.Fatalf("panico no Parse deveria virar abstencao, veio %q", rep.Status)
	}
}

func TestErroDeScanViraAbstencao(t *testing.T) {
	a := &fake{slug: "eng", scanErr: errors.New("engine morreu")}
	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())
	if !rep.Abstains() {
		t.Fatalf("erro de scan deveria virar abstencao, veio %q", rep.Status)
	}
	if !strings.Contains(rep.Error, "engine morreu") {
		t.Errorf("motivo real perdido: %q", rep.Error)
	}
}

func TestStatusDeFalhaDoExecutorViraAbstencao(t *testing.T) {
	// O executor ja traduziu timeout/kill para o vocabulario do esquema; um
	// Scan que devolve erro nil mas status de timeout continua sendo falha.
	a := &fake{slug: "eng", scanStatus: schema.StatusTimeout}
	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())
	if !rep.Abstains() {
		t.Fatalf("status de timeout deveria virar abstencao, veio %q", rep.Status)
	}
	if rep.Status != schema.StatusTimeout {
		t.Errorf("o status original deveria ser preservado, veio %q", rep.Status)
	}
}

func TestRelatorioInvalidoViraAbstencao(t *testing.T) {
	// Um relatorio invalido e pior que nenhum: entraria no consenso com dados
	// que o resto do sistema nao sabe interpretar.
	a := &fake{
		slug:       "eng",
		scanStatus: schema.StatusCompleted,
		report: schema.ScanReport{
			Status: schema.StatusCompleted,
			Findings: []schema.Finding{{
				Engine: "eng", Rule: "regra",
				File:       schema.FileRef{Path: "/x.php", SHA256: "hash-invalido"},
				Category:   schema.CategoryWebshell,
				Severity:   schema.SeverityHigh,
				Confidence: schema.ConfidenceSignature,
				DetectedAt: time.Now(),
			}},
		},
	}

	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())

	if !rep.Abstains() {
		t.Fatalf("relatorio invalido deveria virar abstencao, veio %q", rep.Status)
	}
	if !strings.Contains(rep.Error, "esquema") {
		t.Errorf("o motivo deveria citar o esquema, veio: %q", rep.Error)
	}
}

func TestRelatorioValidoPassaEGanhaCamposFaltantes(t *testing.T) {
	a := &fake{
		slug:       "eng",
		scanStatus: schema.StatusCompleted,
		report: schema.ScanReport{
			Status: schema.StatusCompleted,
			Findings: []schema.Finding{{
				Engine: "eng", Rule: "webshell_generico",
				File:       schema.FileRef{Path: "/x.php", SHA256: sha},
				Category:   schema.CategoryWebshell,
				Severity:   schema.SeverityCritical,
				Confidence: schema.ConfidenceSignature,
				DetectedAt: time.Now(),
			}},
		},
	}

	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())

	if rep.Abstains() {
		t.Fatalf("relatorio valido nao deveria abster-se: %q / %q", rep.Status, rep.Error)
	}
	// O orquestrador completa o que o adaptador esqueceu, para que um
	// adaptador simples nao precise repetir metadados que ele ja recebeu.
	if rep.ScanID != "s_1" {
		t.Errorf("scan_id nao foi preenchido: %q", rep.ScanID)
	}
	if rep.SchemaVersion != schema.Version {
		t.Errorf("schema_version nao foi preenchida: %q", rep.SchemaVersion)
	}
	if rep.Scope.Root != "/home/user/public_html" {
		t.Errorf("root nao foi preenchida: %q", rep.Scope.Root)
	}
	if rep.Scope.Mode != schema.ModeIncremental {
		t.Errorf("mode nao foi preenchido: %q", rep.Scope.Mode)
	}
	if len(rep.Findings) != 1 {
		t.Errorf("achado perdido: %d", len(rep.Findings))
	}
}

func TestSafeProbeSobreviveAPanico(t *testing.T) {
	a := &fake{slug: "quebrado", panicOn: "probe"}
	res := adapter.SafeProbe(context.Background(), a, adapter.Environment{})
	if res.Available {
		t.Fatal("adaptador que entra em panico nao pode ser reportado como disponivel")
	}
	if !strings.Contains(res.Reason, "panico") {
		t.Errorf("motivo deveria citar o panico, veio: %q", res.Reason)
	}
}

func TestProbeIndisponivelSemMotivoGanhaMotivo(t *testing.T) {
	// FR-001: o usuario tem que ver POR QUE o engine nao esta disponivel.
	a := &fake{slug: "mudo", probeResult: adapter.ProbeResult{Available: false}}
	res := adapter.SafeProbe(context.Background(), a, adapter.Environment{})
	if res.Reason == "" {
		t.Fatal("indisponibilidade sem motivo deveria ganhar um motivo generico")
	}
}

func TestSafeInstallESafeUpdateSobrevivemAPanico(t *testing.T) {
	a := &fake{slug: "quebrado", panicOn: "install"}
	if err := adapter.SafeInstall(context.Background(), a, adapter.Environment{}); err == nil {
		t.Error("panico no Install deveria virar erro")
	}

	b := &fake{slug: "quebrado", panicOn: "update"}
	if _, err := adapter.SafeUpdateSignatures(context.Background(), b, adapter.Environment{}); err == nil {
		t.Error("panico no UpdateSignatures deveria virar erro")
	}
}

// Registro -------------------------------------------------------------------

func TestRegistroRecusaSlugDuplicado(t *testing.T) {
	// Dois adaptadores com o mesmo slug votariam duas vezes no mesmo veredito.
	r := adapter.NewRegistry()
	if err := r.Register(&fake{slug: "amwscan"}); err != nil {
		t.Fatalf("primeiro registro: %v", err)
	}
	if err := r.Register(&fake{slug: "amwscan"}); err == nil {
		t.Fatal("slug duplicado deveria ser recusado")
	}
}

func TestRegistroRecusaSlugVazio(t *testing.T) {
	r := adapter.NewRegistry()
	if err := r.Register(&fake{slug: ""}); err == nil {
		t.Fatal("slug vazio deveria ser recusado")
	}
}

func TestRegistroTemOrdemEstavel(t *testing.T) {
	// Comparar dois relatorios de ciclos diferentes nao pode virar exercicio
	// de paciencia por causa de ordem aleatoria de mapa.
	r := adapter.NewRegistry()
	for _, s := range []string{"maldet", "amwscan", "wp-checksums", "php-malware-finder"} {
		if err := r.Register(&fake{slug: s}); err != nil {
			t.Fatalf("Register(%s): %v", s, err)
		}
	}

	primeira := r.Slugs()
	for i := 0; i < 20; i++ {
		if got := r.Slugs(); !equal(got, primeira) {
			t.Fatalf("ordem instavel: %v vs %v", got, primeira)
		}
	}
	esperado := []string{"amwscan", "maldet", "php-malware-finder", "wp-checksums"}
	if !equal(primeira, esperado) {
		t.Errorf("esperava ordem alfabetica %v, veio %v", esperado, primeira)
	}
}

func TestRegistroGet(t *testing.T) {
	r := adapter.NewRegistry()
	_ = r.Register(&fake{slug: "amwscan"})

	if _, ok := r.Get("amwscan"); !ok {
		t.Error("adaptador registrado nao foi encontrado")
	}
	if _, ok := r.Get("inexistente"); ok {
		t.Error("adaptador inexistente foi encontrado")
	}
	if r.Len() != 1 {
		t.Errorf("Len: %d", r.Len())
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
