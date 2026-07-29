// Package verdict consolida os achados de varios engines num veredito por
// arquivo.
//
// Este pacote NAO conhece nenhum engine: ele so entende o esquema normalizado
// (Principio VI). Trocar o AMWScan por outro scanner nao muda uma linha aqui.
//
// A formula e as regras estao documentadas em DECISIONS.md D-003 a D-006.
package verdict

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// CleanReasonOfficialChecksum e o unico motivo de veto hoje.
const CleanReasonOfficialChecksum = "official_checksum_match"

// Engine e o motor de consenso.
type Engine struct {
	cfg     config.VerdictConfig
	weights map[string]float64
}

// New cria o motor a partir da configuracao.
func New(cfg config.VerdictConfig, engines map[string]config.Engine) *Engine {
	w := make(map[string]float64, len(engines))
	for slug, e := range engines {
		w[slug] = e.Weight
	}
	return &Engine{cfg: cfg, weights: w}
}

// Input e tudo que o motor precisa para decidir.
type Input struct {
	ScanID string
	// Reports sao os relatorios de todos os engines que rodaram, incluindo os
	// que falharam — a falha e informacao, nao ausencia de informacao.
	Reports []schema.ScanReport
	// ExpectedEngines sao os engines habilitados na configuracao. Um engine
	// habilitado que nao produziu relatorio nenhum tambem e abstencao: sumir
	// em silencio nao pode parecer "rodou e nao achou nada".
	ExpectedEngines []string
	// Whitelist de globs do usuario.
	Whitelist []string
	Now       time.Time
}

// Result e a saida da consolidacao.
type Result struct {
	Verdicts []schema.Verdict
	// Abstentions lista os engines que nao votaram, com o motivo.
	Abstentions map[string]string
	// CleanFileCount e quantos hashes foram declarados legitimos por checksum
	// oficial.
	CleanFileCount int
}

// Consolidate transforma os relatorios em vereditos, um por arquivo.
func (e *Engine) Consolidate(in Input) Result {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	abstentions := e.collectAbstentions(in)
	official := collectOfficialCleanHashes(in.Reports)

	// Agrupa achados por sha256: e a chave de deduplicacao entre engines.
	// Mesmo arquivo apontado por N engines = N votos no MESMO alvo.
	grupos := groupBySHA(in.Reports)

	abstentionList := make([]string, 0, len(abstentions))
	for slug := range abstentions {
		abstentionList = append(abstentionList, slug)
	}
	sort.Strings(abstentionList)

	verdicts := make([]schema.Verdict, 0, len(grupos))
	for _, sha := range sortedKeys(grupos) {
		verdicts = append(verdicts, e.consolidateFile(in, sha, grupos[sha], official, abstentionList, now))
	}

	return Result{
		Verdicts:       verdicts,
		Abstentions:    abstentions,
		CleanFileCount: len(official),
	}
}

// consolidateFile decide sobre UM arquivo.
func (e *Engine) consolidateFile(
	in Input,
	sha string,
	findings []schema.Finding,
	official map[string]bool,
	abstentions []string,
	now time.Time,
) schema.Verdict {
	votes := e.buildVotes(findings)

	soma := 0.0
	for _, v := range votes {
		soma += v.EffectiveWeight
	}
	score := e.score(soma)
	level := e.level(score)

	// O caminho e o do achado mais recente: se um arquivo foi movido entre
	// engines, o ultimo caminho visto e o que o usuario vai encontrar.
	path, size := representative(findings)

	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     verdictID(in.ScanID, sha),
		FileSHA256:    sha,
		FilePath:      path,
		FileSize:      size,
		Level:         level,
		Score:         score,
		Votes:         votes,
		Abstentions:   abstentions,
		ActionTaken:   schema.ActionNone,
		ScanID:        in.ScanID,
		CreatedAt:     now,
	}

	// Veto por checksum oficial (D-005). Aplicado DEPOIS do calculo, e nao
	// como voto negativo: um voto poderia ser superado por votos suficientes,
	// e a regra e "nunca, independente de votos". Os votos ficam registrados
	// para o usuario ver que os engines apontaram e por que foram vencidos.
	if official[sha] {
		v.Level = schema.LevelClean
		v.Score = 0
		v.CleanReason = CleanReasonOfficialChecksum
		v.ActionTaken = schema.ActionSkippedOfficial
		return v
	}

	// Whitelist bloqueia a ACAO, nao o veredito (D-006). O arquivo continua
	// visivel no relatorio com o nivel real: rebaixa-lo para clean esconderia
	// do usuario que os engines continuam apontando aquele arquivo.
	if regra := pathmatch.WhichMatches(in.Whitelist, path); regra != "" && v.Level != schema.LevelClean {
		v.ActionTaken = schema.ActionSkippedWhitelist
		v.ActionError = "protegido pela regra de whitelist: " + regra
	}

	return v
}

// buildVotes monta um voto por ENGINE, nao por achado.
//
// Um engine que aponta o mesmo arquivo por cinco regras diferentes continua
// sendo um engine so. Contar cinco votos deixaria um unico scanner decidir
// qualquer veredito sozinho — o oposto de consenso.
func (e *Engine) buildVotes(findings []schema.Finding) []schema.Vote {
	melhor := map[string]schema.Vote{}

	for _, f := range findings {
		peso := e.weights[f.Engine]
		if peso <= 0 {
			// Engine desconhecido ou com peso zero nao influencia veredito.
			// Mesmo assim seu achado ja esta arquivado e visivel no painel.
			continue
		}
		efetivo := peso * e.confidenceMultiplier(f.Confidence)

		atual, existe := melhor[f.Engine]
		if !existe || efetivo > atual.EffectiveWeight {
			melhor[f.Engine] = schema.Vote{
				Engine:          f.Engine,
				FindingID:       f.ID,
				Weight:          peso,
				Confidence:      f.Confidence,
				EffectiveWeight: efetivo,
				Rule:            f.Rule,
				Category:        f.Category,
			}
		}
	}

	out := make([]schema.Vote, 0, len(melhor))
	for _, v := range melhor {
		out = append(out, v)
	}
	// Ordem estavel, do voto mais forte para o mais fraco: e a ordem em que o
	// usuario quer ler "por que este arquivo foi apontado".
	sort.Slice(out, func(i, j int) bool {
		if out[i].EffectiveWeight != out[j].EffectiveWeight {
			return out[i].EffectiveWeight > out[j].EffectiveWeight
		}
		return out[i].Engine < out[j].Engine
	})
	return out
}

func (e *Engine) confidenceMultiplier(c schema.Confidence) float64 {
	switch c {
	case schema.ConfidenceSignature:
		return e.cfg.SignatureMultiplier
	case schema.ConfidenceHeuristic:
		return e.cfg.HeuristicMultiplier
	case schema.ConfidenceAnomaly:
		return e.cfg.AnomalyMultiplier
	default:
		// Confianca desconhecida pesa como a mais fraca. Um adaptador que
		// inventa um valor novo nao pode ganhar peso por isso.
		return e.cfg.AnomalyMultiplier
	}
}

// score normaliza a soma de pesos por um teto de saturacao.
//
// Soma dividida por teto, e nao media: com media, cada engine que se abstem
// diluiria o score, transformando falha tecnica em voto de inocencia — o que
// o Principio VI proibe explicitamente (DECISIONS.md D-003 e D-004).
func (e *Engine) score(soma float64) float64 {
	sat := e.cfg.Saturation
	if sat <= 0 {
		sat = 2.0
	}
	s := soma / sat
	if s > 1 {
		return 1
	}
	if s < 0 {
		return 0
	}
	return s
}

func (e *Engine) level(score float64) schema.Level {
	switch {
	case score >= e.cfg.ConfirmedAt:
		return schema.LevelConfirmed
	case score >= e.cfg.LikelyAt:
		return schema.LevelLikely
	case score >= e.cfg.SuspiciousAt:
		return schema.LevelSuspicious
	default:
		return schema.LevelClean
	}
}

// collectAbstentions reune quem nao votou e por que.
func (e *Engine) collectAbstentions(in Input) map[string]string {
	out := map[string]string{}

	viu := map[string]bool{}
	for _, r := range in.Reports {
		viu[r.Engine] = true
		if r.Abstains() {
			motivo := r.Error
			if motivo == "" {
				motivo = fmt.Sprintf("relatorio com status %q", r.Status)
			}
			out[r.Engine] = motivo
		}
	}

	// Engine habilitado que nao produziu relatorio nenhum. Sumir em silencio
	// nao pode parecer "rodou e nao achou nada".
	for _, slug := range in.ExpectedEngines {
		if !viu[slug] {
			out[slug] = "o engine estava habilitado mas nao produziu relatorio neste ciclo"
		}
	}
	return out
}

// collectOfficialCleanHashes reune os hashes declarados legitimos.
//
// So relatorios COMPLETOS contam. Um wp-checksums que falhou no meio pode ter
// listado como limpos apenas os arquivos que chegou a verificar; aceitar essa
// lista parcial daria imunidade a arquivos que ninguem conferiu.
func collectOfficialCleanHashes(reports []schema.ScanReport) map[string]bool {
	out := map[string]bool{}
	for _, r := range reports {
		if r.Abstains() {
			continue
		}
		for _, h := range r.CleanFiles {
			out[h] = true
		}
	}
	return out
}

// groupBySHA agrupa achados de malware por hash do arquivo.
func groupBySHA(reports []schema.ScanReport) map[string][]schema.Finding {
	out := map[string][]schema.Finding{}
	for _, r := range reports {
		// Relatorio que se abstem nao contribui com achados: o engine nao
		// terminou de olhar, e um achado parcial dele nao pode virar voto.
		if r.Abstains() {
			continue
		}
		for _, f := range r.Findings {
			if f.EffectiveKind() != schema.KindMalware {
				// Vulnerabilidade e hardening sao consolidados por componente,
				// em pipeline separado (spec 002). Nunca se misturam ao score
				// de malware.
				continue
			}
			if f.File.SHA256 == "" {
				continue
			}
			out[f.File.SHA256] = append(out[f.File.SHA256], f)
		}
	}
	return out
}

// representative escolhe caminho e tamanho para o veredito.
func representative(findings []schema.Finding) (string, int64) {
	var path string
	var size int64
	var maisRecente time.Time
	for _, f := range findings {
		if f.File.Path == "" {
			continue
		}
		if path == "" || f.DetectedAt.After(maisRecente) {
			path = f.File.Path
			size = f.File.SizeBytes
			maisRecente = f.DetectedAt
		}
	}
	return path, size
}

// verdictID e deterministico a partir do ciclo e do arquivo.
//
// Determinismo importa: reexecutar o mesmo ciclo tem que ATUALIZAR o veredito,
// nao criar um segundo. Sem isso, o painel encheria de duplicatas a cada
// reprocessamento.
func verdictID(scanID, sha string) string {
	sum := sha256.Sum256([]byte(scanID + ":" + sha))
	return "v_" + hex.EncodeToString(sum[:])[:12]
}

// FindingID gera o id de um achado, tambem deterministico.
//
// O orquestrador gera os ids, nunca o adaptador (esquema secao 1.1).
func FindingID(scanID, engine, rule, sha string) string {
	sum := sha256.Sum256([]byte(scanID + ":" + engine + ":" + rule + ":" + sha))
	return "f_" + hex.EncodeToString(sum[:])[:12]
}

func sortedKeys(m map[string][]schema.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
