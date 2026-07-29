package cycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

// mergeReports junta os relatorios parciais de um engine num relatorio unico.
//
// Um engine que roda em 10 lotes produz 10 relatorios; o consenso trabalha com
// um por engine. A regra de fusao importa: se QUALQUER lote falhou, o
// relatorio inteiro fica com status de falha. Aceitar "9 de 10 lotes deram
// certo" como sucesso declararia limpos os arquivos do lote que ninguem
// conseguiu olhar.
func mergeReports(scanID, slug, engineVersion string, parciais []schema.ScanReport, root string, mode schema.ScanMode) schema.ScanReport {
	out := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        scanID,
		Engine:        slug,
		EngineVersion: engineVersion,
		Status:        schema.StatusCompleted,
		Scope:         schema.Scope{Root: root, Mode: mode},
		Findings:      []schema.Finding{},
	}
	if len(parciais) == 0 {
		out.Status = schema.StatusFailed
		out.Error = "o engine nao produziu nenhum relatorio"
		return out
	}

	var erros []string
	for i, p := range parciais {
		if i == 0 || p.StartedAt.Before(out.StartedAt) {
			out.StartedAt = p.StartedAt
		}
		if p.FinishedAt.After(out.FinishedAt) {
			out.FinishedAt = p.FinishedAt
		}
		out.Findings = append(out.Findings, p.Findings...)
		out.CleanFiles = append(out.CleanFiles, p.CleanFiles...)
		out.Scope.FilesConsidered += p.Scope.FilesConsidered
		out.Scope.FilesScanned += p.Scope.FilesScanned
		out.ResourceUsage.WallSeconds += p.ResourceUsage.WallSeconds
		if p.ResourceUsage.MaxRSSMB > out.ResourceUsage.MaxRSSMB {
			out.ResourceUsage.MaxRSSMB = p.ResourceUsage.MaxRSSMB
		}
		if out.RawRef == "" {
			out.RawRef = p.RawRef
		}
		if p.EngineVersion != "" && out.EngineVersion == "" {
			out.EngineVersion = p.EngineVersion
		}
		for k, v := range p.Scope.SkippedReasonCounts {
			if out.Scope.SkippedReasonCounts == nil {
				out.Scope.SkippedReasonCounts = map[string]int{}
			}
			out.Scope.SkippedReasonCounts[k] += v
		}

		if p.Abstains() {
			out.Status = piorStatus(out.Status, p.Status)
			if p.Error != "" {
				erros = append(erros, p.Error)
			}
		}
	}

	if out.Abstains() {
		out.Error = fmt.Sprintf("%d de %d lotes falharam: %v", len(erros), len(parciais), erros)
		// Um relatorio de falha nao carrega achados: o engine nao terminou de
		// olhar, e um achado parcial dele nao pode virar voto.
		out.Findings = []schema.Finding{}
		out.CleanFiles = nil
	}
	return out
}

// piorStatus escolhe o status mais grave entre dois.
func piorStatus(a, b schema.ScanStatus) schema.ScanStatus {
	gravidade := map[schema.ScanStatus]int{
		schema.StatusCompleted: 0,
		schema.StatusPartial:   1,
		schema.StatusTimeout:   2,
		schema.StatusKilled:    3,
		schema.StatusFailed:    4,
	}
	if gravidade[b] > gravidade[a] {
		return b
	}
	return a
}

// persist grava achados e vereditos.
func (r *Runner) persist(ctx context.Context, reports []schema.ScanReport, verdicts []schema.Verdict) error {
	var erros []error

	for _, rep := range reports {
		for _, f := range rep.Findings {
			if f.ID == "" {
				// O orquestrador gera os ids, nunca o adaptador (esquema 1.1).
				f.ID = verdict.FindingID(rep.ScanID, f.Engine, f.Rule, f.File.SHA256)
			}
			if err := r.store.SaveFinding(ctx, f); err != nil {
				erros = append(erros, err)
			}
		}
	}
	for _, v := range verdicts {
		if err := r.store.SaveVerdict(ctx, v); err != nil {
			erros = append(erros, err)
		}
	}
	return errors.Join(erros...)
}

// act aplica a acao automatica aos vereditos confirmados.
//
// Toda a decisao de "pode agir?" esta concentrada em config.AutomaticActionAllowed
// e em Verdict.Actionable(). Este metodo nao adiciona nenhuma condicao propria:
// se adicionasse, existiriam duas fontes de verdade sobre quando a ferramenta
// mexe nos arquivos do usuario.
func (r *Runner) act(ctx context.Context, opts Options, sum *Summary) {
	permitido, motivo := r.cfg.AutomaticActionAllowed(r.now())
	if opts.DryRun {
		permitido, motivo = false, "execucao em modo simulacao (--dry-run)"
	}
	sum.ObservationReason = motivo

	for i := range sum.Verdicts {
		v := &sum.Verdicts[i]

		// Whitelist e checksum oficial ja definiram a acao no motor de
		// veredito; nao se mexe nelas aqui.
		if v.ActionTaken != schema.ActionNone {
			r.emitVerdict(ctx, *v)
			continue
		}
		if !v.Actionable() {
			r.emitVerdict(ctx, *v)
			continue
		}

		if !permitido {
			v.ActionTaken = schema.ActionRecommended
			v.ActionAt = r.now()
			v.ActionError = motivo
			_ = r.store.UpdateVerdictAction(ctx, v.VerdictID, v.ActionTaken, "", motivo)
			r.log(ctx, "warn", store.CatVerdict,
				fmt.Sprintf("veredito confirmado em %s, acao recomendada: %s", v.FilePath, motivo),
				sum.ScanID, map[string]any{"verdict_id": v.VerdictID, "score": v.Score})
			r.emitVerdict(ctx, *v)
			continue
		}

		r.quarantineOne(ctx, v, sum)
		r.emitVerdict(ctx, *v)
	}
}

func (r *Runner) quarantineOne(ctx context.Context, v *schema.Verdict, sum *Summary) {
	item, err := r.vault.Quarantine(ctx, v.VerdictID, v.FilePath, v.FileSHA256)
	switch {
	case err == nil:
		v.ActionTaken = schema.ActionQuarantined
		v.ActionAt = r.now()
		v.QuarantineRef = item.Ref
		_ = r.store.UpdateVerdictAction(ctx, v.VerdictID, v.ActionTaken, item.Ref, "")
		r.log(ctx, "warn", store.CatQuarantine,
			fmt.Sprintf("arquivo quarentenado: %s", v.FilePath), sum.ScanID,
			map[string]any{"ref": item.Ref, "verdict_id": v.VerdictID, "score": v.Score})
		r.emit(ctx, "quarantine.action", quarantineEvent(item, "quarantined"))

	case errors.Is(err, quarantine.ErrHashMismatch):
		// O arquivo mudou entre o scan e a acao. Reescaneia em vez de
		// quarentenar as cegas (edge case explicito da spec).
		v.ActionTaken = schema.ActionRescanNeeded
		v.ActionAt = r.now()
		v.ActionError = err.Error()
		_ = r.store.UpdateVerdictAction(ctx, v.VerdictID, v.ActionTaken, "", err.Error())
		r.log(ctx, "info", store.CatQuarantine,
			fmt.Sprintf("%s mudou desde o scan; sera reescaneado em vez de quarentenado", v.FilePath),
			sum.ScanID, map[string]any{"verdict_id": v.VerdictID})

	default:
		// Disco cheio ou sem permissao no cofre: alerta critico "nao foi
		// possivel neutralizar", nunca falha silenciosa.
		v.ActionTaken = schema.ActionFailed
		v.ActionAt = r.now()
		v.ActionError = err.Error()
		_ = r.store.UpdateVerdictAction(ctx, v.VerdictID, v.ActionTaken, "", err.Error())
		r.log(ctx, "error", store.CatQuarantine,
			fmt.Sprintf("NAO foi possivel neutralizar %s: %v", v.FilePath, err), sum.ScanID,
			map[string]any{"verdict_id": v.VerdictID})
		r.emit(ctx, "quarantine.action", map[string]any{
			"action": "failed", "verdict_id": v.VerdictID,
			"original_path": v.FilePath, "error": err.Error(), "reversible": true,
		})
	}
}

func quarantineEvent(item store.QuarantineItem, action string) map[string]any {
	return map[string]any{
		"action":          action,
		"quarantine_ref":  item.Ref,
		"verdict_id":      item.VerdictID,
		"original_path":   item.OriginalPath,
		"file_sha256":     item.SHA256,
		"size_bytes":      item.SizeBytes,
		"reversible":      true,
		"retention_until": item.RetentionUntil,
	}
}

// emitVerdict manda o evento do nivel correspondente.
func (r *Runner) emitVerdict(ctx context.Context, v schema.Verdict) {
	switch v.Level {
	case schema.LevelConfirmed:
		r.emit(ctx, "verdict.confirmed", v)
	case schema.LevelLikely:
		r.emit(ctx, "verdict.likely", v)
	case schema.LevelSuspicious:
		r.emit(ctx, "verdict.suspicious", v)
	}
}

// emit entrega um evento sem deixar o alerta derrubar o ciclo.
func (r *Runner) emit(ctx context.Context, event string, data any) {
	if r.dispatch == nil {
		return
	}
	if err := r.dispatch.Dispatch(ctx, event, data); err != nil {
		// Falha de alerta e registrada, nunca propagada: um webhook fora do
		// ar nao pode impedir uma quarentena de acontecer.
		r.log(ctx, "warn", store.CatAlert,
			fmt.Sprintf("nao foi possivel despachar %s: %v", event, err), "", nil)
	}
}

func (r *Runner) log(ctx context.Context, level, cat, msg, scanID string, fields map[string]any) {
	_ = r.store.Log(ctx, store.Event{
		TS: r.now(), Level: level, Category: cat, Message: msg,
		ScanID: scanID, Fields: fields,
	})
}

func (r *Runner) finish(ctx context.Context, sum *Summary, status schema.ScanStatus) {
	sum.FinishedAt = r.now()
	sum.Status = status
	_ = r.store.FinishScan(ctx, store.ScanRecord{
		ScanID: sum.ScanID, FinishedAt: sum.FinishedAt, Status: status,
		FilesConsidered: sum.FilesConsidered, FilesScanned: sum.FilesScanned,
		Summary: sum.Event(),
	})
	r.log(ctx, "info", store.CatScan,
		fmt.Sprintf("ciclo terminado com status %s", status), sum.ScanID,
		map[string]any{
			"arquivos_considerados": sum.FilesConsidered,
			"arquivos_escaneados":   sum.FilesScanned,
			"duracao_s":             sum.FinishedAt.Sub(sum.StartedAt).Seconds(),
		})
}

// Event monta o payload de scan.completed do contrato de webhooks.
//
// E o mesmo objeto usado pelo `--json` da CLI e pelo resumo gravado no banco:
// tres consumidores, uma unica definicao de "o que aconteceu neste ciclo".
func (s Summary) Event() map[string]any {
	var ran []string
	abstained := make([]map[string]string, 0)
	for _, e := range s.Engines {
		if e.Available && e.Status == schema.StatusCompleted {
			ran = append(ran, e.Slug)
			continue
		}
		// Engine indisponivel ou que falhou SEMPRE acompanha o resumo: um
		// ciclo em que metade dos engines falhou nao pode parecer limpo.
		motivo := e.Reason
		if motivo == "" {
			motivo = string(e.Status)
		}
		abstained = append(abstained, map[string]string{"engine": e.Slug, "reason": motivo})
	}

	verdicts := map[string]int{}
	for lvl, n := range s.LevelCounts {
		verdicts[string(lvl)] = n
	}
	actions := map[string]int{}
	for a, n := range s.ActionCts {
		actions[string(a)] = n
	}

	return map[string]any{
		"scan_id":           s.ScanID,
		"mode":              string(s.Mode),
		"started_at":        s.StartedAt.Format(time.RFC3339),
		"finished_at":       s.FinishedAt.Format(time.RFC3339),
		"status":            string(s.Status),
		"files_considered":  s.FilesConsidered,
		"files_scanned":     s.FilesScanned,
		"skipped":           s.SkippedCounts,
		"engines_ran":       ran,
		"engines_abstained": abstained,
		"verdicts":          verdicts,
		"actions":           actions,
	}
}
