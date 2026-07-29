// Package integration_test exercita o consenso de ponta a ponta sobre o corpus
// sintetico.
//
// Os engines reais nao sao executados (DECISIONS.md D-011): os adaptadores de
// teste emitem os ScanReport que o manifesto declara. O que esta sob teste e a
// CONSOLIDACAO — se dois engines heuristicos concordando dao `likely`, se um
// arquivo com checksum oficial sobrevive a dois votos de assinatura, se uma
// abstencao dilui o score. Nada disso depende da qualidade da assinatura de
// terceiros, e tudo isso e o que o SentinelHost realmente implementa.
package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

// Manifesto e a expectativa declarada em tests/testdata/corpus/manifesto.json.
type Manifesto struct {
	Amostras []Amostra `json:"amostras"`
	Limpos   []Limpo   `json:"limpos"`
}

type Amostra struct {
	Arquivo         string   `json:"arquivo"`
	CaminhoSimulado string   `json:"caminho_simulado"`
	Simula          string   `json:"simula"`
	Category        string   `json:"category"`
	Severity        string   `json:"severity"`
	Confidence      string   `json:"confidence"`
	NivelMinimo     string   `json:"nivel_minimo_esperado"`
	Engines         []string `json:"engines_que_devem_apontar"`
}

type Limpo struct {
	Arquivo         string `json:"arquivo"`
	CaminhoSimulado string `json:"caminho_simulado"`
	NivelMaximo     string `json:"nivel_maximo_aceitavel"`
	ChecksumOficial bool   `json:"checksum_oficial"`
	Observacao      string `json:"observacao"`
}

const corpusDir = "../testdata/corpus"

func carregarManifesto(t *testing.T) Manifesto {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpusDir, "manifesto.json"))
	if err != nil {
		t.Fatalf("lendo manifesto: %v", err)
	}
	var m Manifesto
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifesto invalido: %v", err)
	}
	return m
}

// TestTodoArquivoDoCorpusEstaNoManifesto impede que alguem adicione uma amostra
// sem declarar o que espera dela.
func TestTodoArquivoDoCorpusEstaNoManifesto(t *testing.T) {
	m := carregarManifesto(t)

	declarado := map[string]bool{}
	for _, a := range m.Amostras {
		declarado[filepath.ToSlash(a.Arquivo)] = true
	}
	for _, l := range m.Limpos {
		declarado[filepath.ToSlash(l.Arquivo)] = true
	}

	var faltando []string
	err := filepath.Walk(corpusDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(corpusDir, p)
		rel = filepath.ToSlash(rel)
		// Documentacao e manifesto nao sao amostras.
		if strings.HasSuffix(rel, ".md") || rel == "manifesto.json" {
			return nil
		}
		if !declarado[rel] {
			faltando = append(faltando, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("percorrendo corpus: %v", err)
	}
	if len(faltando) > 0 {
		t.Errorf("arquivos do corpus fora do manifesto: %v\n"+
			"Toda amostra precisa declarar a expectativa (AMOSTRAS.md e manifesto.json).", faltando)
	}
}

// TestAmostrasSaoInertes confere as garantias que tornam o corpus seguro.
func TestAmostrasSaoInertes(t *testing.T) {
	m := carregarManifesto(t)

	for _, a := range m.Amostras {
		t.Run(a.Arquivo, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(corpusDir, a.Arquivo))
			if err != nil {
				t.Fatalf("lendo amostra: %v", err)
			}
			conteudo := string(b)

			if !strings.Contains(conteudo, "SENTINELHOST-SYNTHETIC-CORPUS") {
				t.Error("faltou o marcador que identifica a amostra como sintetica")
			}
			// A primeira instrucao executavel tem que ser um exit().
			idx := strings.Index(conteudo, "exit(")
			if idx < 0 {
				t.Fatal("a amostra nao tem exit() e portanto nao e inerte")
			}
			antesDoExit := conteudo[:idx]
			for _, perigoso := range []string{
				"eval(", "system(", "shell_exec(", "passthru(", "proc_open(",
				"fsockopen(", "file_put_contents(", "move_uploaded_file(",
				"base64_decode(", "assert(", "include ", "require ",
			} {
				if strings.Contains(antesDoExit, perigoso) {
					t.Errorf("chamada perigosa %q aparece ANTES do exit()", perigoso)
				}
			}
		})
	}
}

// SC-001 -----------------------------------------------------------------------

// TestSC001Deteccao mede o consenso sobre o corpus.
//
// A spec exige >= 95% das amostras em `confirmed`/`likely` e ZERO falso
// positivo `confirmed` em arquivo oficial do core.
//
// O denominador sao as amostras de CONTEUDO malicioso. As duas amostras cujo
// unico sinal e anomalia (arquivo no lugar errado, permissao frouxa) sao
// medidas a parte, com o piso `suspicious` que o manifesto declara — ver
// DECISIONS.md D-016.
func TestSC001Deteccao(t *testing.T) {
	m := carregarManifesto(t)
	cfg := config.Default()
	motor := verdict.New(cfg.Verdict, cfg.Engines)

	relatorios, hashes, limpos := montarCiclo(t, m)

	res := motor.Consolidate(verdict.Input{
		ScanID:          "s_sc001",
		Reports:         relatorios,
		ExpectedEngines: []string{"wp-checksums", "amwscan", "php-malware-finder", "maldet"},
		Now:             time.Now(),
	})

	porHash := map[string]schema.Verdict{}
	for _, v := range res.Verdicts {
		porHash[v.FileSHA256] = v
	}

	var conteudoMalicioso, detectados int
	var falhas []string

	for _, a := range m.Amostras {
		v, ok := porHash[hashes[a.Arquivo]]
		if !ok {
			falhas = append(falhas, a.Arquivo+": nenhum veredito produzido")
			continue
		}
		piso := schema.Level(a.NivelMinimo)
		if !v.Level.AtLeast(piso) {
			falhas = append(falhas, // nolint:gocritic
				a.Arquivo+": nivel "+string(v.Level)+", esperado ao menos "+string(piso))
		}

		// Amostras de conteudo malicioso sao as que o manifesto espera em
		// likely ou confirmed.
		if piso.AtLeast(schema.LevelLikely) {
			conteudoMalicioso++
			if v.Level.AtLeast(schema.LevelLikely) {
				detectados++
			}
		}
	}

	for _, f := range falhas {
		t.Errorf("SC-001: %s", f)
	}

	if conteudoMalicioso == 0 {
		t.Fatal("o corpus nao tem amostras de conteudo malicioso declaradas")
	}
	taxa := float64(detectados) / float64(conteudoMalicioso)
	t.Logf("SC-001: %d/%d amostras de conteudo malicioso em confirmed/likely (%.1f%%)",
		detectados, conteudoMalicioso, taxa*100)
	if taxa < 0.95 {
		t.Errorf("SC-001 reprovado: taxa de deteccao %.1f%%, minimo 95%%", taxa*100)
	}

	// Zero falso positivo `confirmed` em arquivo oficial do core.
	for _, l := range limpos {
		v, ok := porHash[l.hash]
		if !ok {
			continue
		}
		maximo := schema.Level(l.nivelMaximo)
		if v.Level.Rank() > maximo.Rank() {
			t.Errorf("SC-001: falso positivo em %s — nivel %s, maximo aceitavel %s",
				l.arquivo, v.Level, maximo)
		}
		if l.checksumOficial {
			if v.Level != schema.LevelClean {
				t.Errorf("SC-001: arquivo com checksum oficial saiu como %s (%s)", v.Level, l.arquivo)
			}
			if v.CleanReason != verdict.CleanReasonOfficialChecksum {
				t.Errorf("SC-001: o veto por checksum nao foi registrado em %s (clean_reason=%q)",
					l.arquivo, v.CleanReason)
			}
			// E o mais importante: os votos que o veto venceu continuam
			// visiveis, para o usuario entender o que aconteceu.
			if len(v.Votes) == 0 {
				t.Errorf("SC-001: os votos vencidos pelo veto sumiram em %s", l.arquivo)
			}
		}
	}
}

type limpoResolvido struct {
	arquivo         string
	hash            string
	nivelMaximo     string
	checksumOficial bool
}

// montarCiclo transforma o manifesto em relatorios de engine.
//
// Cada "engine" emite exatamente o que o manifesto declara. Os hashes sao os
// reais dos arquivos do corpus, calculados aqui — e o mesmo caminho que o
// orquestrador usa em producao.
func montarCiclo(t *testing.T, m Manifesto) ([]schema.ScanReport, map[string]string, []limpoResolvido) {
	t.Helper()

	porEngine := map[string][]schema.Finding{}
	hashes := map[string]string{}
	agora := time.Now()

	for _, a := range m.Amostras {
		h, err := baseline.HashFile(filepath.Join(corpusDir, a.Arquivo))
		if err != nil {
			t.Fatalf("hash de %s: %v", a.Arquivo, err)
		}
		hashes[a.Arquivo] = h

		for _, eng := range a.Engines {
			conf := schema.Confidence(a.Confidence)
			// O wp-checksums so fala de integridade de core e sempre com
			// confianca de assinatura.
			if eng == "wp-checksums" {
				conf = schema.ConfidenceSignature
			}
			porEngine[eng] = append(porEngine[eng], schema.Finding{
				SchemaVersion: schema.Version,
				ID:            verdict.FindingID("s_sc001", eng, a.Category, h),
				Engine:        eng,
				Rule:          regraDe(eng, a),
				File: schema.FileRef{
					Path: "/home/user/public_html/" + a.CaminhoSimulado, SHA256: h, SizeBytes: 1024,
				},
				Category:   schema.Category(a.Category),
				Severity:   schema.Severity(a.Severity),
				Confidence: conf,
				ScanID:     "s_sc001",
				DetectedAt: agora,
			})
		}
	}

	var limpos []limpoResolvido
	var cleanFiles []string

	for _, l := range m.Limpos {
		h, err := baseline.HashFile(filepath.Join(corpusDir, l.Arquivo))
		if err != nil {
			t.Fatalf("hash de %s: %v", l.Arquivo, err)
		}
		limpos = append(limpos, limpoResolvido{
			arquivo: l.Arquivo, hash: h,
			nivelMaximo: l.NivelMaximo, checksumOficial: l.ChecksumOficial,
		})

		if !l.ChecksumOficial {
			continue
		}
		cleanFiles = append(cleanFiles, h)

		// O cenario que o SC-001 realmente testa: DOIS engines apontam o
		// arquivo oficial com confianca de assinatura (o que daria
		// `confirmed`), e o veto por checksum tem que vencer mesmo assim.
		for _, eng := range []string{"maldet", "amwscan"} {
			porEngine[eng] = append(porEngine[eng], schema.Finding{
				SchemaVersion: schema.Version,
				ID:            verdict.FindingID("s_sc001", eng, "falso_positivo", h),
				Engine:        eng,
				Rule:          "FALSO_POSITIVO_EM_ARQUIVO_OFICIAL",
				File: schema.FileRef{
					Path: "/home/user/public_html/" + l.CaminhoSimulado, SHA256: h, SizeBytes: 2048,
				},
				Category:   schema.CategoryKnownMalware,
				Severity:   schema.SeverityCritical,
				Confidence: schema.ConfidenceSignature,
				ScanID:     "s_sc001",
				DetectedAt: agora,
			})
		}
	}

	var relatorios []schema.ScanReport
	for _, eng := range []string{"wp-checksums", "amwscan", "php-malware-finder", "maldet"} {
		r := schema.ScanReport{
			SchemaVersion: schema.Version,
			ScanID:        "s_sc001",
			Engine:        eng,
			Status:        schema.StatusCompleted,
			StartedAt:     agora.Add(-time.Minute),
			FinishedAt:    agora,
			Scope:         schema.Scope{Root: "/home/user/public_html", Mode: schema.ModeFull},
			Findings:      porEngine[eng],
		}
		if eng == "wp-checksums" {
			r.CleanFiles = cleanFiles
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("relatorio de teste do engine %s e invalido: %v", eng, err)
		}
		relatorios = append(relatorios, r)
	}
	return relatorios, hashes, limpos
}

func regraDe(engine string, a Amostra) string {
	switch engine {
	case "wp-checksums":
		return "core_file_modified"
	case "php-malware-finder":
		return "RegraYara_" + a.Category
	default:
		return strings.ToUpper(a.Category)
	}
}

// TestAnomaliaSozinhaNaoChegaALikely documenta e trava o comportamento que
// justifica o denominador do SC-001 (D-016).
func TestAnomaliaSozinhaNaoChegaALikely(t *testing.T) {
	cfg := config.Default()
	motor := verdict.New(cfg.Verdict, cfg.Engines)

	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	res := motor.Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{{
			SchemaVersion: schema.Version, ScanID: "s_1", Engine: "php-malware-finder",
			Status: schema.StatusCompleted,
			Findings: []schema.Finding{{
				SchemaVersion: schema.Version, Engine: "php-malware-finder", Rule: "PhpInUploads",
				File:       schema.FileRef{Path: "/site/uploads/x.php", SHA256: sha},
				Category:   schema.CategorySuspiciousLocation,
				Severity:   schema.SeverityMedium,
				Confidence: schema.ConfidenceAnomaly,
				DetectedAt: time.Now(),
			}},
		}},
	})

	if len(res.Verdicts) != 1 {
		t.Fatalf("esperava 1 veredito, veio %d", len(res.Verdicts))
	}
	v := res.Verdicts[0]
	if v.Level.AtLeast(schema.LevelLikely) {
		t.Fatalf("um sinal de anomalia sozinho nao pode chegar a %s: "+
			"isso faria um unico engine disparar alerta de acao recomendada", v.Level)
	}
	if v.Actionable() {
		t.Error("anomalia sozinha nunca pode autorizar acao automatica")
	}
}
