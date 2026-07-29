package verdict_test

import (
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func motor() *verdict.Engine {
	cfg := config.Default()
	return verdict.New(cfg.Verdict, cfg.Engines)
}

func achado(engine, rule, sha, path string, conf schema.Confidence) schema.Finding {
	return schema.Finding{
		SchemaVersion: schema.Version,
		ID:            verdict.FindingID("s_1", engine, rule, sha),
		Engine:        engine,
		Rule:          rule,
		File:          schema.FileRef{Path: path, SHA256: sha, SizeBytes: 1024},
		Category:      schema.CategoryBackdoor,
		Severity:      schema.SeverityHigh,
		Confidence:    conf,
		ScanID:        "s_1",
		DetectedAt:    time.Now(),
	}
}

func relatorio(engine string, findings ...schema.Finding) schema.ScanReport {
	return schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        "s_1",
		Engine:        engine,
		Status:        schema.StatusCompleted,
		Findings:      findings,
	}
}

func umVerdict(t *testing.T, r verdict.Result) schema.Verdict {
	t.Helper()
	if len(r.Verdicts) != 1 {
		t.Fatalf("esperava 1 veredito, veio %d", len(r.Verdicts))
	}
	return r.Verdicts[0]
}

// Cenarios da spec ------------------------------------------------------------

func TestDoisEnginesComAssinaturaDaoConfirmed(t *testing.T) {
	// Cenario 2 da US1: dois engines com confidence=signature -> confirmed.
	// Com os pesos do documento de esquema: maldet 1.0 + amwscan 0.8 = 1.8,
	// sobre o teto 2.0 = 0.90, exatamente o limiar de confirmed.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("maldet", achado("maldet", "php.corpus.marker.v1", shaA, "/site/x.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "SIGNATURE_KNOWN_MARKER", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := umVerdict(t, r)
	if v.Level != schema.LevelConfirmed {
		t.Fatalf("esperava confirmed, veio %s (score %.4f)", v.Level, v.Score)
	}
	if len(v.Votes) != 2 {
		t.Errorf("esperava 2 votos, veio %d", len(v.Votes))
	}
	if !v.Actionable() {
		t.Error("confirmed sem veto deveria ser acionavel")
	}
}

func TestUmEngineHeuristicoDaSuspicious(t *testing.T) {
	// Cenario 3 da US1: um engine heuristico sozinho -> suspicious, sem acao.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan", achado("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	})

	v := umVerdict(t, r)
	// 0.8 * 0.8 = 0.64, sobre 2.0 = 0.32 -> suspicious.
	if v.Level != schema.LevelSuspicious {
		t.Fatalf("esperava suspicious, veio %s (score %.4f)", v.Level, v.Score)
	}
	if v.Actionable() {
		t.Error("suspicious nunca pode autorizar acao automatica")
	}
}

func TestDoisEnginesHeuristicosDaoLikely(t *testing.T) {
	// O documento de esquema descreve exatamente este caso como likely.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan", achado("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
			relatorio("php-malware-finder", achado("php-malware-finder", "DangerousPhp", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	})

	v := umVerdict(t, r)
	// (0.8*0.8) * 2 = 1.28, sobre 2.0 = 0.64 -> likely.
	if v.Level != schema.LevelLikely {
		t.Fatalf("esperava likely, veio %s (score %.4f)", v.Level, v.Score)
	}
	if v.Actionable() {
		t.Error("likely aguarda decisao humana")
	}
}

func TestChecksumDivergenteMaisUmEngineDaConfirmed(t *testing.T) {
	// O documento de esquema cita "checksum oficial divergente + 1 engine"
	// como exemplo de confirmed. wp-checksums pesa 1.5.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("wp-checksums", achado("wp-checksums", "core_file_modified", shaA, "/site/wp-includes/pluggable.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "EVAL_BASE64", shaA, "/site/wp-includes/pluggable.php", schema.ConfidenceHeuristic)),
		},
	})

	v := umVerdict(t, r)
	if v.Level != schema.LevelConfirmed {
		t.Fatalf("esperava confirmed, veio %s (score %.4f)", v.Level, v.Score)
	}
}

func TestChecksumOficialVetaMesmoComVotosDeConfirmed(t *testing.T) {
	// Cenario 5 da US1 e a regra fixa do esquema: arquivo identico ao checksum
	// oficial NUNCA e quarentenado, independente de votos. Engines dao falso
	// positivo em arquivo legitimo minificado, e um falso positivo no core
	// derruba o site inteiro.
	limpo := relatorio("wp-checksums")
	limpo.CleanFiles = []string{shaA}

	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			limpo,
			relatorio("maldet", achado("maldet", "php.x", shaA, "/site/wp-includes/version.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "KNOWN_MALWARE", shaA, "/site/wp-includes/version.php", schema.ConfidenceSignature)),
		},
	})

	v := umVerdict(t, r)
	if v.Level != schema.LevelClean {
		t.Fatalf("checksum oficial deveria vetar: veio %s (score %.4f)", v.Level, v.Score)
	}
	if v.Score != 0 {
		t.Errorf("score deveria ser zerado pelo veto, veio %.4f", v.Score)
	}
	if v.CleanReason != verdict.CleanReasonOfficialChecksum {
		t.Errorf("o motivo tem que ficar registrado, veio %q", v.CleanReason)
	}
	if v.Actionable() {
		t.Error("veredito vetado nunca pode ser acionavel")
	}
	// Os votos continuam visiveis: o usuario precisa ver que os engines
	// apontaram e por que foram vencidos (Principio V).
	if len(v.Votes) != 2 {
		t.Errorf("os votos vencidos deveriam continuar registrados, veio %d", len(v.Votes))
	}
	if v.ActionTaken != schema.ActionSkippedOfficial {
		t.Errorf("action_taken deveria explicar o veto, veio %q", v.ActionTaken)
	}
}

func TestEngineQueFalhaViraAbstencaoEOCicloCompleta(t *testing.T) {
	// Cenario 4 da US1.
	falha := schema.FailedReport("s_1", "maldet", schema.StatusTimeout,
		errTimeout{}, time.Now())

	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			falha,
			relatorio("amwscan", achado("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	})

	v := umVerdict(t, r)
	if len(v.Abstentions) != 1 || v.Abstentions[0] != "maldet" {
		t.Fatalf("maldet deveria constar como abstencao, veio %v", v.Abstentions)
	}
	if motivo := r.Abstentions["maldet"]; motivo == "" {
		t.Error("a abstencao precisa carregar o motivo real")
	}
	// E, principalmente: o veredito saiu. O ciclo completou com os demais.
	if v.Level != schema.LevelSuspicious {
		t.Errorf("o veredito deveria ter saido normalmente, veio %s", v.Level)
	}
}

// Regras estruturais ----------------------------------------------------------

func TestAbstencaoNaoDiluiOScore(t *testing.T) {
	// Se a abstencao entrasse no denominador, um engine que estourou timeout
	// rebaixaria um confirmed para likely — transformando falha tecnica em
	// decisao de seguranca (DECISIONS.md D-004).
	comAbstencao := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("maldet", achado("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			schema.FailedReport("s_1", "php-malware-finder", schema.StatusFailed, errTimeout{}, time.Now()),
		},
		ExpectedEngines: []string{"maldet", "amwscan", "php-malware-finder", "wp-checksums"},
	})

	semAbstencao := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("maldet", achado("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	a := umVerdict(t, comAbstencao)
	b := umVerdict(t, semAbstencao)
	if a.Score != b.Score {
		t.Fatalf("a abstencao mudou o score: %.4f com, %.4f sem", a.Score, b.Score)
	}
	if a.Level != schema.LevelConfirmed {
		t.Errorf("o nivel foi rebaixado por causa de uma falha tecnica: %s", a.Level)
	}
	// Mas a abstencao TEM que aparecer: 2 falharam/sumiram.
	if len(a.Abstentions) != 2 {
		t.Errorf("esperava 2 abstencoes registradas, veio %v", a.Abstentions)
	}
}

func TestEngineHabilitadoQueSumiuTambemAbstem(t *testing.T) {
	// Sumir em silencio nao pode parecer "rodou e nao achou nada".
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan", achado("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
		ExpectedEngines: []string{"amwscan", "maldet", "wp-checksums"},
	})

	if _, ok := r.Abstentions["maldet"]; !ok {
		t.Error("engine habilitado sem relatorio deveria constar como abstencao")
	}
	if _, ok := r.Abstentions["wp-checksums"]; !ok {
		t.Error("engine habilitado sem relatorio deveria constar como abstencao")
	}
	if _, ok := r.Abstentions["amwscan"]; ok {
		t.Error("engine que rodou nao pode constar como abstencao")
	}
}

func TestUmEngineComVariasRegrasContinuaUmVotoSo(t *testing.T) {
	// Contar cinco regras como cinco votos deixaria um unico scanner decidir
	// qualquer veredito sozinho — o oposto de consenso.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan",
				achado("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceSignature),
				achado("amwscan", "SHELL_EXEC", shaA, "/site/x.php", schema.ConfidenceSignature),
				achado("amwscan", "OBFUSCATED_BLOB", shaA, "/site/x.php", schema.ConfidenceSignature),
				achado("amwscan", "SEO_SPAM", shaA, "/site/x.php", schema.ConfidenceSignature),
			),
		},
	})

	v := umVerdict(t, r)
	if len(v.Votes) != 1 {
		t.Fatalf("quatro regras do mesmo engine deveriam dar 1 voto, veio %d", len(v.Votes))
	}
	if v.Level == schema.LevelConfirmed {
		t.Error("um engine sozinho nao pode chegar a confirmed so repetindo regras")
	}
}

func TestVotoUsaARegraMaisForteDoEngine(t *testing.T) {
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan",
				achado("amwscan", "SUSPICIOUS_TITLE", shaA, "/site/x.php", schema.ConfidenceAnomaly),
				achado("amwscan", "KNOWN_MALWARE", shaA, "/site/x.php", schema.ConfidenceSignature),
			),
		},
	})

	v := umVerdict(t, r)
	if v.Votes[0].Confidence != schema.ConfidenceSignature {
		t.Errorf("o voto deveria usar a regra mais forte, veio %q", v.Votes[0].Confidence)
	}
	if v.Votes[0].Rule != "KNOWN_MALWARE" {
		t.Errorf("a regra registrada deveria ser a mais forte, veio %q", v.Votes[0].Rule)
	}
}

func TestDeduplicacaoPorHashUneEnginesEmUmVeredito(t *testing.T) {
	// O mesmo arquivo visto por caminhos diferentes (link, copia) continua
	// sendo um alvo so: a chave e o hash.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan", achado("amwscan", "EVAL_POST", shaA, "/site/a.php", schema.ConfidenceHeuristic)),
			relatorio("maldet", achado("maldet", "php.x", shaA, "/site/b.php", schema.ConfidenceHeuristic)),
			relatorio("php-malware-finder", achado("php-malware-finder", "DangerousPhp", shaB, "/site/c.php", schema.ConfidenceHeuristic)),
		},
	})

	if len(r.Verdicts) != 2 {
		t.Fatalf("esperava 2 vereditos (2 hashes), veio %d", len(r.Verdicts))
	}
	for _, v := range r.Verdicts {
		if v.FileSHA256 == shaA && len(v.Votes) != 2 {
			t.Errorf("os dois engines deveriam votar no mesmo alvo, veio %d votos", len(v.Votes))
		}
	}
}

func TestWhitelistBloqueiaAcaoMasMantemOVeredito(t *testing.T) {
	// D-006: o arquivo continua visivel no relatorio com o nivel real.
	// Rebaixar para clean esconderia que os engines continuam apontando.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("maldet", achado("maldet", "r", shaA, "/site/wp-content/plugins/meu/x.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "r", shaA, "/site/wp-content/plugins/meu/x.php", schema.ConfidenceSignature)),
		},
		Whitelist: []string{"**/wp-content/plugins/meu/**"},
	})

	v := umVerdict(t, r)
	if v.Level != schema.LevelConfirmed {
		t.Fatalf("a whitelist nao pode mudar o nivel, veio %s", v.Level)
	}
	if v.ActionTaken != schema.ActionSkippedWhitelist {
		t.Fatalf("a acao deveria ser bloqueada pela whitelist, veio %q", v.ActionTaken)
	}
	// O usuario precisa saber QUAL regra protegeu o arquivo.
	if !strings.Contains(v.ActionError, "meu") {
		t.Errorf("a regra que protegeu deveria estar registrada, veio %q", v.ActionError)
	}
}

func TestRelatorioQueSeAbstemNaoContribuiComAchados(t *testing.T) {
	// Um engine que nao terminou de olhar pode ter achados parciais; aceita-los
	// como voto daria peso a uma leitura incompleta.
	parcial := relatorio("maldet", achado("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature))
	parcial.Status = schema.StatusPartial
	parcial.Error = "erro de leitura em 12 arquivos"

	r := motor().Consolidate(verdict.Input{
		ScanID:  "s_1",
		Reports: []schema.ScanReport{parcial},
	})

	if len(r.Verdicts) != 0 {
		t.Fatalf("achado de relatorio parcial nao deveria virar veredito, veio %d", len(r.Verdicts))
	}
	if r.Abstentions["maldet"] == "" {
		t.Error("o engine parcial deveria constar como abstencao com motivo")
	}
}

func TestCleanFilesDeRelatorioQueFalhouNaoValem(t *testing.T) {
	// Um wp-checksums que morreu no meio so conferiu parte dos arquivos.
	// Aceitar essa lista daria imunidade a arquivos que ninguem conferiu.
	falho := schema.FailedReport("s_1", "wp-checksums", schema.StatusTimeout, errTimeout{}, time.Now())
	falho.CleanFiles = []string{shaA}

	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			falho,
			relatorio("maldet", achado("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := umVerdict(t, r)
	if v.CleanReason != "" {
		t.Fatal("lista de limpos de um relatorio que falhou nao pode vetar")
	}
	if v.Level != schema.LevelConfirmed {
		t.Errorf("o veredito deveria seguir os votos, veio %s", v.Level)
	}
}

func TestEngineComPesoZeroNaoInfluencia(t *testing.T) {
	cfg := config.Default()
	cfg.Engines["amwscan"] = config.Engine{Enabled: true, Weight: 0}
	e := verdict.New(cfg.Verdict, cfg.Engines)

	r := e.Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan", achado("amwscan", "KNOWN_MALWARE", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := umVerdict(t, r)
	if len(v.Votes) != 0 {
		t.Errorf("engine com peso 0 nao deveria votar, veio %d votos", len(v.Votes))
	}
	if v.Level != schema.LevelClean {
		t.Errorf("sem votos o nivel deveria ser clean, veio %s", v.Level)
	}
}

func TestEngineDesconhecidoNaoVota(t *testing.T) {
	// Um adaptador nao registrado na configuracao nao pode influenciar
	// veredito so por aparecer num relatorio.
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("engine-nao-configurado", achado("engine-nao-configurado", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := umVerdict(t, r)
	if len(v.Votes) != 0 {
		t.Errorf("engine desconhecido nao deveria votar, veio %d", len(v.Votes))
	}
}

func TestScoreSatura(t *testing.T) {
	// Cinco engines fortes nao podem estourar o intervalo [0,1].
	cfg := config.Default()
	cfg.Engines["e1"] = config.Engine{Enabled: true, Weight: 1.5}
	cfg.Engines["e2"] = config.Engine{Enabled: true, Weight: 1.5}
	cfg.Engines["e3"] = config.Engine{Enabled: true, Weight: 1.5}
	e := verdict.New(cfg.Verdict, cfg.Engines)

	r := e.Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("e1", achado("e1", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			relatorio("e2", achado("e2", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			relatorio("e3", achado("e3", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := umVerdict(t, r)
	if v.Score > 1.0 {
		t.Fatalf("score estourou o intervalo: %.4f", v.Score)
	}
	if err := v.Validate(); err != nil {
		t.Errorf("veredito saturado deveria ser valido: %v", err)
	}
}

func TestAchadoDeVulnerabilidadeNaoEntraNoScoreDeMalware(t *testing.T) {
	// Malware e vulnerabilidade sao pipelines paralelos que nunca se misturam
	// no mesmo score (esquema secao 3).
	vuln := achado("amwscan", "componente-vulneravel", shaA, "/site/x.php", schema.ConfidenceSignature)
	vuln.Kind = schema.KindVulnerability
	vuln.Category = schema.CategoryVulnerableComponent
	vuln.Component = &schema.Component{Type: "wordpress-plugin", Slug: "cf7", InstalledVersion: "5.7.1"}

	r := motor().Consolidate(verdict.Input{
		ScanID:  "s_1",
		Reports: []schema.ScanReport{relatorio("amwscan", vuln)},
	})

	if len(r.Verdicts) != 0 {
		t.Fatalf("achado de vulnerabilidade nao pode virar veredito de malware, veio %d", len(r.Verdicts))
	}
}

func TestVerdictIDEDeterministico(t *testing.T) {
	// Reexecutar o mesmo ciclo tem que ATUALIZAR o veredito, nao duplicar.
	in := verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan", achado("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	}
	a := umVerdict(t, motor().Consolidate(in))
	b := umVerdict(t, motor().Consolidate(in))
	if a.VerdictID != b.VerdictID {
		t.Errorf("ids diferentes para o mesmo ciclo e arquivo: %s vs %s", a.VerdictID, b.VerdictID)
	}
}

func TestOrdemDosVereditosEEstavel(t *testing.T) {
	in := verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("amwscan",
				achado("amwscan", "r", shaB, "/site/b.php", schema.ConfidenceHeuristic),
				achado("amwscan", "r", shaA, "/site/a.php", schema.ConfidenceHeuristic),
			),
		},
	}
	primeira := motor().Consolidate(in)
	for i := 0; i < 10; i++ {
		outra := motor().Consolidate(in)
		for j := range primeira.Verdicts {
			if primeira.Verdicts[j].FileSHA256 != outra.Verdicts[j].FileSHA256 {
				t.Fatal("a ordem dos vereditos variou entre execucoes")
			}
		}
	}
}

func TestTodoVerdictProduzidoEValido(t *testing.T) {
	r := motor().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			relatorio("maldet", achado("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			relatorio("amwscan", achado("amwscan", "r", shaB, "/site/y.php", schema.ConfidenceHeuristic)),
		},
	})
	for _, v := range r.Verdicts {
		if err := v.Validate(); err != nil {
			t.Errorf("veredito invalido saiu do motor: %v", err)
		}
	}
}

type errTimeout struct{}

func (errTimeout) Error() string { return "timeout apos 300s" }
