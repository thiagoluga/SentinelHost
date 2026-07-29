package schema_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

const validSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func validFinding() schema.Finding {
	return schema.Finding{
		SchemaVersion: schema.Version,
		ID:            "f_9f8a7b6c",
		Engine:        "php-malware-finder",
		EngineVersion: "0.9.2",
		Rule:          "ObfuscatedPhp",
		File: schema.FileRef{
			Path:      "/home/user/public_html/wp-content/uploads/cache.php",
			SizeBytes: 14382,
			SHA256:    validSHA,
			MTime:     time.Now(),
			Perms:     "0644",
		},
		Category:   schema.CategoryObfuscation,
		Severity:   schema.SeverityHigh,
		Confidence: schema.ConfidenceHeuristic,
		ScanID:     "s_20260723_0300",
		DetectedAt: time.Now(),
	}
}

func TestFindingValidateAceitaAchadoCompleto(t *testing.T) {
	if err := validFinding().Validate(); err != nil {
		t.Fatalf("achado valido foi recusado: %v", err)
	}
}

func TestFindingValidateExigeSHA256(t *testing.T) {
	// O sha256 e a chave de deduplicacao entre engines. Sem ele, dois engines
	// apontando o mesmo arquivo virariam dois vereditos com um voto cada em
	// vez de um veredito com dois votos — exatamente o oposto do consenso.
	cases := map[string]string{
		"vazio":       "",
		"curto":       "e3b0c44298fc",
		"maiusculo":   strings.ToUpper(validSHA),
		"nao-hex":     strings.Repeat("z", 64),
		"com espacos": strings.Repeat("a", 63) + " ",
	}
	for name, sha := range cases {
		t.Run(name, func(t *testing.T) {
			f := validFinding()
			f.File.SHA256 = sha
			if err := f.Validate(); err == nil {
				t.Fatalf("sha256 %q deveria ser recusado", sha)
			}
		})
	}
}

func TestFindingValidateRecusaEnumDesconhecido(t *testing.T) {
	f := validFinding()
	f.Category = "categoria-inventada"
	err := f.Validate()
	if err == nil {
		t.Fatal("category desconhecida deveria ser recusada")
	}
	if !strings.Contains(err.Error(), "other") {
		t.Errorf("a mensagem deveria orientar o autor do adaptador a usar other, veio: %v", err)
	}
}

func TestFindingValidateAcumulaTodosOsProblemas(t *testing.T) {
	// Um adaptador quebrado precisa ver a lista inteira de uma vez.
	f := schema.Finding{SchemaVersion: schema.Version}
	err := f.Validate()
	if err == nil {
		t.Fatal("finding vazio deveria ser recusado")
	}
	var ve *schema.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("erro deveria ser *ValidationError, veio %T", err)
	}
	if len(ve.Problems) < 5 {
		t.Errorf("esperava varios problemas acumulados, veio %d: %v", len(ve.Problems), ve.Problems)
	}
}

func TestFindingVulnerabilidadeNaoExigeSHA256(t *testing.T) {
	// Vereditos de vulnerabilidade sao consolidados por componente, nao por
	// arquivo (esquema secao 3). Exigir sha256 inviabilizaria a feature 002.
	f := validFinding()
	f.Kind = schema.KindVulnerability
	f.File = schema.FileRef{}
	f.Category = schema.CategoryVulnerableComponent
	f.Component = &schema.Component{
		Type:             "wordpress-plugin",
		Slug:             "contact-form-7",
		InstalledVersion: "5.7.1",
		FixedIn:          "5.7.2",
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("achado de vulnerabilidade valido foi recusado: %v", err)
	}

	f.Component = nil
	if err := f.Validate(); err == nil {
		t.Fatal("kind=vulnerability sem component deveria ser recusado")
	}
}

func TestKindVazioEMalware(t *testing.T) {
	f := validFinding()
	f.Kind = ""
	if got := f.EffectiveKind(); got != schema.KindMalware {
		t.Errorf("kind vazio deveria ser malware, veio %q", got)
	}
}

func TestStatusNaoCompletadoNuncaContaComoVoto(t *testing.T) {
	// Principio VI: falha de engine e abstencao, nunca "voto limpo".
	for _, s := range []schema.ScanStatus{
		schema.StatusPartial, schema.StatusFailed,
		schema.StatusTimeout, schema.StatusKilled,
	} {
		if s.CountsAsVote() {
			t.Errorf("status %q nao pode contar como voto", s)
		}
		r := schema.ScanReport{Status: s}
		if !r.Abstains() {
			t.Errorf("relatorio com status %q deveria abster-se", s)
		}
	}
	if !schema.StatusCompleted.CountsAsVote() {
		t.Error("completed deveria contar como voto")
	}
}

func TestFailedReportNuncaProduzStatusDeVoto(t *testing.T) {
	// Defesa contra chamada errada: mesmo pedindo "completed", o construtor
	// de falha tem que devolver abstencao.
	r := schema.FailedReport("s_1", "amwscan", schema.StatusCompleted, errTest{}, time.Now())
	if r.Status.CountsAsVote() {
		t.Fatalf("FailedReport devolveu status que conta como voto: %q", r.Status)
	}
	if r.Error == "" {
		t.Error("FailedReport deveria preencher Error")
	}
	if err := r.Validate(); err != nil {
		t.Errorf("relatorio de falha deveria ser valido: %v", err)
	}
}

func TestScanReportExigeMotivoQuandoFalha(t *testing.T) {
	r := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        "s_1",
		Engine:        "maldet",
		Status:        schema.StatusTimeout,
	}
	err := r.Validate()
	if err == nil {
		t.Fatal("status de falha sem error deveria ser recusado")
	}
	r.Error = "timeout apos 300s"
	if err := r.Validate(); err != nil {
		t.Fatalf("relatorio com motivo deveria ser valido: %v", err)
	}
}

func TestScanReportRecusaFindingDeOutroEngine(t *testing.T) {
	f := validFinding()
	r := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        "s_1",
		Engine:        "amwscan",
		Status:        schema.StatusCompleted,
		Findings:      []schema.Finding{f}, // engine = php-malware-finder
	}
	if err := r.Validate(); err == nil {
		t.Fatal("finding de engine diferente do relatorio deveria ser recusado")
	}
}

func TestLevelRankEAtLeast(t *testing.T) {
	if !schema.LevelConfirmed.AtLeast(schema.LevelLikely) {
		t.Error("confirmed deveria ser >= likely")
	}
	if schema.LevelSuspicious.AtLeast(schema.LevelConfirmed) {
		t.Error("suspicious nao deveria ser >= confirmed")
	}
	if !schema.LevelClean.AtLeast(schema.LevelClean) {
		t.Error("clean deveria ser >= clean")
	}
}

func TestVerdictActionableSoConfirmed(t *testing.T) {
	// Vereditos automaticos so no nivel confirmed (Principio V).
	for _, l := range []schema.Level{schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		v := schema.Verdict{Level: l}
		if v.Actionable() {
			t.Errorf("nivel %q nao pode autorizar acao automatica", l)
		}
	}
	if !(schema.Verdict{Level: schema.LevelConfirmed}).Actionable() {
		t.Error("confirmed deveria ser acionavel")
	}
	// Protecao por checksum oficial vence qualquer nivel.
	v := schema.Verdict{Level: schema.LevelConfirmed, CleanReason: "official_checksum_match"}
	if v.Actionable() {
		t.Error("veredito com clean_reason nunca pode ser acionavel")
	}
}

func TestVerdictQuarentenaExigeReferencia(t *testing.T) {
	// Sem quarantine_ref o arquivo nao e restauravel — viola o Principio I.
	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     "v_1",
		FileSHA256:    validSHA,
		Level:         schema.LevelConfirmed,
		Score:         0.95,
		ActionTaken:   schema.ActionQuarantined,
	}
	if err := v.Validate(); err == nil {
		t.Fatal("quarantined sem quarantine_ref deveria ser recusado")
	}
	v.QuarantineRef = "q_20260723_000132"
	if err := v.Validate(); err != nil {
		t.Fatalf("veredito completo deveria ser valido: %v", err)
	}
}

func TestVerdictRecusaScoreForaDoIntervalo(t *testing.T) {
	for _, score := range []float64{-0.1, 1.5} {
		v := schema.Verdict{
			SchemaVersion: schema.Version,
			VerdictID:     "v_1",
			FileSHA256:    validSHA,
			Level:         schema.LevelLikely,
			Score:         score,
		}
		if err := v.Validate(); err == nil {
			t.Errorf("score %v deveria ser recusado", score)
		}
	}
}

func TestCompatibleVersion(t *testing.T) {
	ok := []string{"", "1.0", "1.4"}
	for _, v := range ok {
		if err := schema.CompatibleVersion(v); err != nil {
			t.Errorf("versao %q deveria ser aceita: %v", v, err)
		}
	}
	bad := []string{"2.0", "0.9", "abc"}
	for _, v := range bad {
		if err := schema.CompatibleVersion(v); err == nil {
			t.Errorf("versao %q deveria ser recusada", v)
		}
	}
}

func TestSanitizeSnippetTruncaESanitiza(t *testing.T) {
	// A constituicao proibe re-servir conteudo malicioso: o trecho e truncado
	// e limpo de bytes de controle antes de sair do adaptador.
	long := strings.Repeat("A", schema.MaxMatchedContentBytes*2)
	got := schema.SanitizeSnippet(long)
	if len(got) > schema.MaxMatchedContentBytes {
		t.Errorf("trecho nao foi truncado: %d bytes", len(got))
	}

	got = schema.SanitizeSnippet("linha1\nlinha2\x00\x07fim")
	if strings.ContainsAny(got, "\x00\x07\n") {
		t.Errorf("bytes de controle sobreviveram: %q", got)
	}
	if !strings.Contains(got, "linha1") || !strings.Contains(got, "fim") {
		t.Errorf("conteudo legivel foi perdido: %q", got)
	}
}

func TestSanitizeSnippetNaoQuebraRuna(t *testing.T) {
	// Truncar no meio de um caractere multibyte produziria lixo invalido no
	// JSON do relatorio.
	s := strings.Repeat("ç", schema.MaxMatchedContentBytes)
	got := schema.SanitizeSnippet(s)
	if !isValidUTF8(got) {
		t.Errorf("resultado nao e UTF-8 valido: %q", got)
	}
}

func TestRoundTripJSONPreservaCampos(t *testing.T) {
	// O esquema e o contrato entre adaptador e motor de veredito; ele viaja
	// como JSON (saida do scan, API do painel, payload de webhook).
	orig := validFinding()
	orig.MatchedContent = "trecho sanitizado"
	orig.MatchedOffset = 1024

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back schema.Finding
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.File.SHA256 != orig.File.SHA256 || back.Rule != orig.Rule ||
		back.Category != orig.Category || back.MatchedOffset != orig.MatchedOffset {
		t.Errorf("round-trip perdeu campos:\nantes: %+v\ndepois: %+v", orig, back)
	}
}

// Helpers -------------------------------------------------------------------

type errTest struct{}

func (errTest) Error() string { return "engine morreu" }

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}
