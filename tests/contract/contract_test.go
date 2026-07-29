// Package contract_test verifica que cada adaptador entende o que o seu
// engine fala.
//
// O que esta sob teste aqui e o PARSER, nunca a deteccao. As fixtures em
// tests/testdata/raw/ sao saida bruta no formato exato de cada engine; o teste
// alimenta Parse() com elas e confere o ScanReport normalizado.
//
// A distincao que mais importa nestes testes: "nao achou nada" e "nao
// conseguiu procurar" sao coisas diferentes (Principio VI). Um parser que
// confunde as duas transforma engine morto em atestado de saude.
package contract_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/amwscan"
	"github.com/thiagoluga/SentinelHost/internal/adapter/pmf"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

const shaFalso = "1111111111111111111111111111111111111111111111111111111111111111"

func fixture(t *testing.T, engine, nome string) []byte {
	t.Helper()
	path := filepath.Join("..", "testdata", "raw", engine, nome)
	b, err := os.ReadFile(path) //nolint:gosec // caminho fixo de fixture
	if err != nil {
		t.Fatalf("lendo fixture %s: %v", path, err)
	}
	return b
}

// statFalso responde por qualquer caminho, para que o teste exercite o parser
// sem precisar materializar a arvore de um servidor real no disco (D-009).
func statFalso(path string) (amwscan.FileStat, bool) {
	return amwscan.FileStat{
		SHA256: shaFalso, Size: 1024, Perms: "0644", MTime: time.Unix(1785000000, 0),
	}, true
}

func statFalsoPMF(path string) (pmf.FileStat, bool) {
	return pmf.FileStat{
		SHA256: shaFalso, Size: 1024, Perms: "0644", MTime: time.Unix(1785000000, 0),
	}, true
}

func raw(engine string, stdout []byte, status schema.ScanStatus) adapter.RawOutput {
	return adapter.RawOutput{
		Engine: engine, ScanID: "s_teste", Root: "/home/user/public_html",
		Mode: schema.ModeIncremental, Stdout: stdout, Status: status,
		StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(),
		PathsRequested: 412,
	}
}

// AMWScan ---------------------------------------------------------------------

func TestAMWScanParseAchados(t *testing.T) {
	a := amwscan.New().WithStat(statFalso)

	rep, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "sucesso-com-achados.json"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("relatorio nao cumpre o esquema: %v", err)
	}
	if rep.Status != schema.StatusCompleted || rep.Abstains() {
		t.Fatalf("relatorio de sucesso nao deveria abster-se: %q", rep.Status)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("esperava 3 achados, veio %d", len(rep.Findings))
	}
	if rep.EngineVersion != "0.10.4" {
		t.Errorf("versao do engine perdida: %q", rep.EngineVersion)
	}
	if rep.Scope.FilesScanned != 412 {
		t.Errorf("files_scanned: %d", rep.Scope.FilesScanned)
	}

	// A tabela regra->categoria e o contrato do adaptador.
	esperado := map[string]struct {
		cat  schema.Category
		conf schema.Confidence
	}{
		"SIGNATURE_KNOWN_MARKER": {schema.CategoryKnownMalware, schema.ConfidenceSignature},
		"EVAL_POST":              {schema.CategoryBackdoor, schema.ConfidenceHeuristic},
		"OBFUSCATED_BLOB":        {schema.CategoryObfuscation, schema.ConfidenceHeuristic},
	}
	for _, f := range rep.Findings {
		e, ok := esperado[f.Rule]
		if !ok {
			t.Errorf("regra inesperada no relatorio: %q", f.Rule)
			continue
		}
		if f.Category != e.cat {
			t.Errorf("%s: categoria %q, esperada %q", f.Rule, f.Category, e.cat)
		}
		if f.Confidence != e.conf {
			t.Errorf("%s: confianca %q, esperada %q", f.Rule, f.Confidence, e.conf)
		}
		if f.File.SHA256 != shaFalso {
			t.Errorf("%s: o orquestrador deveria ter calculado o sha256", f.Rule)
		}
		if f.Engine != amwscan.Slug {
			t.Errorf("%s: engine %q", f.Rule, f.Engine)
		}
	}
}

func TestAMWScanSemAchadosNaoEAbstencao(t *testing.T) {
	// Zero achados com engine que rodou e um site limpo, nao uma falha.
	a := amwscan.New().WithStat(statFalso)

	rep, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "sucesso-sem-achados.json"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Abstains() {
		t.Fatal("zero achados nao pode virar abstencao")
	}
	if len(rep.Findings) != 0 {
		t.Errorf("esperava lista vazia, veio %d", len(rep.Findings))
	}
}

func TestAMWScanSaidaVaziaViraAbstencao(t *testing.T) {
	// O AMWScan sempre emite o JSON do relatorio. Vazio significa que ele
	// morreu antes de escrever — abstencao, nunca "nao achou nada".
	a := amwscan.New().WithStat(statFalso)

	_, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "saida-vazia.json"), schema.StatusCompleted))
	if err == nil {
		t.Fatal("saida vazia deveria ser recusada pelo parser")
	}
}

func TestAMWScanSaidaCorrompidaViraAbstencao(t *testing.T) {
	a := amwscan.New().WithStat(statFalso)

	_, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "saida-corrompida.json"), schema.StatusCompleted))
	if err == nil {
		t.Fatal("JSON truncado deveria ser recusado")
	}
}

func TestAMWScanDetectaRelatorioTruncado(t *testing.T) {
	// O engine declara N deteccoes mas lista menos: relatorio incompleto.
	// Aceita-lo como bom esconderia achados reais.
	a := amwscan.New().WithStat(statFalso)
	truncado := []byte(`{"version":"0.10.4","scanned":10,"detected":5,"logs":[
		{"file":"/x.php","exploit":"EVAL_POST","line":1}]}`)

	_, err := a.Parse(raw(amwscan.Slug, truncado, schema.StatusCompleted))
	if err == nil {
		t.Fatal("divergencia entre contador e lista deveria ser recusada")
	}
}

func TestAMWScanRegraDesconhecidaNaoEDescartada(t *testing.T) {
	// Obrigacao 4 do contrato: regra desconhecida vira other/medium/heuristic.
	// Descartar faria um achado real sumir quando o engine ganhasse uma
	// assinatura nova entre duas versoes do SentinelHost.
	a := amwscan.New().WithStat(statFalso)
	entrada := []byte(`{"version":"0.10.4","scanned":1,"detected":1,"logs":[
		{"file":"/x.php","exploit":"REGRA_QUE_NAO_EXISTE_NA_TABELA","line":7,"details":"x"}]}`)

	rep, err := a.Parse(raw(amwscan.Slug, entrada, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("o achado foi descartado: %d", len(rep.Findings))
	}
	f := rep.Findings[0]
	if f.Category != schema.CategoryOther {
		t.Errorf("categoria: %q, esperada other", f.Category)
	}
	if f.Rule != "REGRA_QUE_NAO_EXISTE_NA_TABELA" {
		t.Errorf("o nome original da regra deveria ser preservado: %q", f.Rule)
	}
	// E o relatorio registra que houve regra desconhecida, para que a tabela
	// receba manutencao em vez de envelhecer em silencio.
	if rep.Scope.SkippedReasonCounts["regra_desconhecida"] != 1 {
		t.Errorf("a regra desconhecida deveria ser contabilizada: %v", rep.Scope.SkippedReasonCounts)
	}
}

func TestAMWScanArquivoQueSumiuNaoViraAchadoSemHash(t *testing.T) {
	// Sem hash nao ha como deduplicar entre engines; inventar uma chave seria
	// pior que pular.
	a := amwscan.New().WithStat(func(string) (amwscan.FileStat, bool) {
		return amwscan.FileStat{}, false
	})
	entrada := []byte(`{"version":"0.10.4","scanned":1,"detected":1,"logs":[
		{"file":"/sumiu.php","exploit":"EVAL_POST","line":1}]}`)

	rep, err := a.Parse(raw(amwscan.Slug, entrada, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("achado sem hash nao deveria entrar: %+v", rep.Findings)
	}
	if rep.Scope.SkippedReasonCounts["sumiu_antes_do_hash"] != 1 {
		t.Errorf("o arquivo sumido deveria ser contabilizado: %v", rep.Scope.SkippedReasonCounts)
	}
}

func TestAMWScanMatchedContentESanitizadoETruncado(t *testing.T) {
	a := amwscan.New().WithStat(statFalso)
	longo := make([]byte, 0, 4096)
	for i := 0; i < 2000; i++ {
		longo = append(longo, 'A')
	}
	entrada := []byte(`{"version":"0.10.4","scanned":1,"detected":1,"logs":[
		{"file":"/x.php","exploit":"EVAL_POST","line":1,"match":"` + string(longo) + `"}]}`)

	rep, err := a.Parse(raw(amwscan.Slug, entrada, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings[0].MatchedContent) > schema.MaxMatchedContentBytes {
		t.Errorf("trecho nao foi truncado: %d bytes", len(rep.Findings[0].MatchedContent))
	}
}

// php-malware-finder ------------------------------------------------------------

func TestPMFParseHierarquiaDeRegraEStrings(t *testing.T) {
	// O formato do yara tem hierarquia: "REGRA CAMINHO" e, abaixo, as strings
	// que casaram. Tratar cada linha isoladamente produziria achados sem
	// arquivo.
	a := pmf.New().WithStat(statFalsoPMF)

	rep, err := a.Parse(raw(pmf.Slug, fixture(t, "php-malware-finder", "sucesso-com-achados.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("relatorio nao cumpre o esquema: %v", err)
	}
	if len(rep.Findings) != 5 {
		t.Fatalf("esperava 5 achados, veio %d", len(rep.Findings))
	}

	porRegra := map[string]schema.Finding{}
	for _, f := range rep.Findings {
		porRegra[f.Rule] = f
		if f.File.Path == "" {
			t.Errorf("achado da regra %q ficou sem arquivo", f.Rule)
		}
	}

	// As strings casadas viram matched_content do achado a que pertencem.
	if got := porRegra["ObfuscatedPhp"]; got.MatchedContent == "" {
		t.Error("as strings casadas nao viraram matched_content")
	}
	if got := porRegra["ObfuscatedPhp"]; got.Category != schema.CategoryObfuscation {
		t.Errorf("ObfuscatedPhp: categoria %q", got.Category)
	}
	if got := porRegra["SuspiciousEncoding"]; got.Confidence != schema.ConfidenceSignature {
		t.Errorf("SuspiciousEncoding deveria ser assinatura, veio %q", got.Confidence)
	}
	// Regra sem strings (linha solta) tambem vira achado.
	if _, ok := porRegra["PhpInUploads"]; !ok {
		t.Error("regra sem strings casadas deveria virar achado mesmo assim")
	}
	if got := porRegra["PhpInUploads"]; got.Confidence != schema.ConfidenceAnomaly {
		t.Errorf("PhpInUploads deveria ser anomalia, veio %q", got.Confidence)
	}
	// Regra fora da tabela nao e descartada.
	if got, ok := porRegra["RegraDesconhecidaQueNaoEstaNaTabela"]; !ok {
		t.Error("regra desconhecida foi descartada")
	} else if got.Category != schema.CategoryOther {
		t.Errorf("regra desconhecida: categoria %q, esperada other", got.Category)
	}
}

func TestPMFOffsetEExtraidoDaPrimeiraString(t *testing.T) {
	a := pmf.New().WithStat(statFalsoPMF)
	entrada := []byte("ObfuscatedPhp /site/x.php\n0x1f2:$blob: AAAA\n0x300:$outra: BBBB\n")

	rep, err := a.Parse(raw(pmf.Slug, entrada, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Findings[0].MatchedOffset != 0x1f2 {
		t.Errorf("offset: %#x, esperado 0x1f2", rep.Findings[0].MatchedOffset)
	}
}

// TestPMFVazioSignificaCoisasOpostas e o teste central deste pacote.
func TestPMFVazioSignificaCoisasOpostas(t *testing.T) {
	// Quando o yara roda e nao acha nada, stdout e vazio.
	// Quando o yara morre antes de escrever, stdout tambem e vazio.
	// A saida bruta e a MESMA; o significado e oposto. A diferenca vem do
	// status do processo, e um parser que olha so o conteudo nao tem como
	// acertar os dois.
	a := pmf.New().WithStat(statFalsoPMF)
	vazio := fixture(t, "php-malware-finder", "saida-vazia.txt")

	// Caso 1: engine completou. Site limpo.
	rep, err := a.Parse(raw(pmf.Slug, vazio, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse (completed): %v", err)
	}
	if rep.Abstains() {
		t.Fatal("yara que rodou e nao achou nada NAO pode virar abstencao")
	}
	if len(rep.Findings) != 0 {
		t.Errorf("esperava zero achados, veio %d", len(rep.Findings))
	}

	// Caso 2: engine morreu. O SafeScanAndParse do orquestrador e quem
	// converte isso em abstencao, antes de o Parse ser chamado.
	morto := raw(pmf.Slug, vazio, schema.StatusFailed)
	morto.Err = errTeste{}
	sr := adapter.SafeScanAndParse(t.Context(), adaptadorMorto{raw: morto}, adapter.Environment{},
		adapter.ScanRequest{ScanID: "s_teste", Root: "/site", Mode: schema.ModeIncremental})
	if !sr.Abstains() {
		t.Fatal("yara que morreu TEM que virar abstencao")
	}
}

func TestPMFIgnoraLinhaDeStringSemRegraAnterior(t *testing.T) {
	// Saida truncada pode comecar no meio. Criar um achado sem arquivo seria
	// pior que ignorar.
	a := pmf.New().WithStat(statFalsoPMF)
	entrada := []byte("0x1f2:$blob: AAAA\nObfuscatedPhp /site/x.php\n")

	rep, err := a.Parse(raw(pmf.Slug, entrada, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("esperava 1 achado, veio %d", len(rep.Findings))
	}
	if rep.Findings[0].File.Path != "/site/x.php" {
		t.Errorf("caminho: %q", rep.Findings[0].File.Path)
	}
}

func TestPMFCaminhoComEspacoNaoQuebra(t *testing.T) {
	// yara nao escapa nada. O nome da regra nunca tem espaco, entao o corte e
	// no primeiro espaco e o resto da linha e o caminho inteiro.
	a := pmf.New().WithStat(statFalsoPMF)
	entrada := []byte("ObfuscatedPhp /site/pasta com espaco/arquivo estranho.php\n")

	rep, err := a.Parse(raw(pmf.Slug, entrada, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("esperava 1 achado, veio %d", len(rep.Findings))
	}
	if rep.Findings[0].File.Path != "/site/pasta com espaco/arquivo estranho.php" {
		t.Errorf("caminho truncado no espaco: %q", rep.Findings[0].File.Path)
	}
}

// Helpers ------------------------------------------------------------------------

type errTeste struct{}

func (errTeste) Error() string { return "o engine morreu" }

// adaptadorMorto devolve uma saida bruta com status de falha.
type adaptadorMorto struct{ raw adapter.RawOutput }

func (a adaptadorMorto) Info() adapter.Info {
	return adapter.Info{Slug: pmf.Slug, Kind: schema.KindMalware}
}
func (a adaptadorMorto) Probe(_ context.Context, _ adapter.Environment) adapter.ProbeResult {
	return adapter.ProbeResult{Available: true}
}
func (a adaptadorMorto) Install(_ context.Context, _ adapter.Environment) error { return nil }
func (a adaptadorMorto) UpdateSignatures(_ context.Context, _ adapter.Environment) (time.Time, error) {
	return time.Time{}, nil
}
func (a adaptadorMorto) Scan(_ context.Context, _ adapter.Environment, _ adapter.ScanRequest) (adapter.RawOutput, error) {
	return a.raw, nil
}
func (a adaptadorMorto) Parse(adapter.RawOutput) (schema.ScanReport, error) {
	return schema.ScanReport{}, nil
}
