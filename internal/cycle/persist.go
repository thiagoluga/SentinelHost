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

// mergeReports joins an engine's partial reports into a single report.
//
// An engine that runs in 10 batches produces 10 reports; the consensus works with
// one per engine. The merge rule matters: if ANY batch failed, the whole report
// carries a failure status. Accepting "9 out of 10 batches worked" as success
// would declare clean the files of the batch nobody managed to look at.
func mergeReports(scanID, slug, engineVersion string, partials []schema.ScanReport, root string, mode schema.ScanMode) schema.ScanReport {
	out := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        scanID,
		Engine:        slug,
		EngineVersion: engineVersion,
		Status:        schema.StatusCompleted,
		Scope:         schema.Scope{Root: root, Mode: mode},
		Findings:      []schema.Finding{},
	}
	if len(partials) == 0 {
		out.Status = schema.StatusFailed
		out.Error = "the engine produced no report at all"
		return out
	}

	var failures []string
	for i, p := range partials {
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
			out.Status = worstStatus(out.Status, p.Status)
			if p.Error != "" {
				failures = append(failures, p.Error)
			}
		}
	}

	if out.Abstains() {
		out.Error = fmt.Sprintf("%d of %d batches failed: %v", len(failures), len(partials), failures)
		// A failure report carries no findings: the engine did not finish looking,
		// and a partial finding of its own cannot become a vote.
		out.Findings = []schema.Finding{}
		out.CleanFiles = nil
	}
	return out
}

// worstStatus picks the more severe of two statuses.
func worstStatus(a, b schema.ScanStatus) schema.ScanStatus {
	severity := map[schema.ScanStatus]int{
		schema.StatusCompleted: 0,
		schema.StatusPartial:   1,
		schema.StatusTimeout:   2,
		schema.StatusKilled:    3,
		schema.StatusFailed:    4,
	}
	if severity[b] > severity[a] {
		return b
	}
	return a
}

// persist writes findings and verdicts.
func (r *Runner) persist(ctx context.Context, reports []schema.ScanReport, verdicts []schema.Verdict) error {
	var failures []error

	for _, rep := range reports {
		for _, f := range rep.Findings {
			if f.ID == "" {
				// The orchestrator generates the ids, never the adapter (schema 1.1).
				f.ID = verdict.FindingID(rep.ScanID, f.Engine, f.Rule, f.File.SHA256)
			}
			if err := r.store.SaveFinding(ctx, f); err != nil {
				failures = append(failures, err)
			}
		}
	}
	for _, v := range verdicts {
		if err := r.store.SaveVerdict(ctx, v); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// act applies the automatic action to the confirmed verdicts.
//
// The whole "may we act?" decision is concentrated in
// config.AutomaticActionAllowed and in Verdict.Actionable(). This method adds no
// condition of its own: if it did, there would be two sources of truth about when
// the tool touches the user's files.
func (r *Runner) act(ctx context.Context, opts Options, sum *Summary) {
	allowed, reason := r.cfg.AutomaticActionAllowed(r.now())
	if opts.DryRun {
		allowed, reason = false, "running in simulation mode (--dry-run)"
	}
	sum.ObservationReason = reason

	for i := range sum.Verdicts {
		v := &sum.Verdicts[i]

		// The whitelist and the official checksum already set the action in the
		// verdict engine; they are not touched here.
		if v.ActionTaken != schema.ActionNone {
			r.emitVerdict(ctx, *v)
			continue
		}
		if !v.Actionable() {
			r.emitVerdict(ctx, *v)
			continue
		}

		if !allowed {
			v.ActionTaken = schema.ActionRecommended
			v.ActionAt = r.now()
			v.ActionError = reason
			_ = r.store.UpdateVerdictAction(ctx, v.VerdictID, v.ActionTaken, "", reason)
			r.log(ctx, "warn", store.CatVerdict,
				fmt.Sprintf("verdict confirmed on %s, action recommended: %s", v.FilePath, reason),
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
			fmt.Sprintf("file quarantined: %s", v.FilePath), sum.ScanID,
			map[string]any{"ref": item.Ref, "verdict_id": v.VerdictID, "score": v.Score})
		r.emit(ctx, "quarantine.action", quarantineEvent(item, "quarantined"))

	case errors.Is(err, quarantine.ErrHashMismatch):
		// The file changed between the scan and the action. Re-scan instead of
		// quarantining blindly (an explicit edge case in the spec).
		v.ActionTaken = schema.ActionRescanNeeded
		v.ActionAt = r.now()
		v.ActionError = err.Error()
		_ = r.store.UpdateVerdictAction(ctx, v.VerdictID, v.ActionTaken, "", err.Error())
		r.log(ctx, "info", store.CatQuarantine,
			fmt.Sprintf("%s changed since the scan; it will be re-scanned instead of quarantined", v.FilePath),
			sum.ScanID, map[string]any{"verdict_id": v.VerdictID})

	default:
		// A full disk or no permission in the vault: a critical "could not
		// neutralize" alert, never a silent failure.
		v.ActionTaken = schema.ActionFailed
		v.ActionAt = r.now()
		v.ActionError = err.Error()
		_ = r.store.UpdateVerdictAction(ctx, v.VerdictID, v.ActionTaken, "", err.Error())
		r.log(ctx, "error", store.CatQuarantine,
			fmt.Sprintf("could NOT neutralize %s: %v", v.FilePath, err), sum.ScanID,
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

// emitVerdict sends the event matching the level.
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

// emit delivers an event without letting the alert take the cycle down.
func (r *Runner) emit(ctx context.Context, event string, data any) {
	if r.dispatch == nil {
		return
	}
	if err := r.dispatch.Dispatch(ctx, event, data); err != nil {
		// An alert failure is recorded, never propagated: a webhook that is down
		// must not keep a quarantine from happening.
		r.log(ctx, "warn", store.CatAlert,
			fmt.Sprintf("could not dispatch %s: %v", event, err), "", nil)
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
		fmt.Sprintf("cycle finished with status %s", status), sum.ScanID,
		map[string]any{
			"files_considered": sum.FilesConsidered,
			"files_scanned":    sum.FilesScanned,
			"duration_s":       sum.FinishedAt.Sub(sum.StartedAt).Seconds(),
		})
}

// Event assembles the scan.completed payload of the webhooks contract.
//
// It is the same object the CLI's `--json` uses and the summary written to the
// database: three consumers, one single definition of "what happened in this
// cycle".
func (s Summary) Event() map[string]any {
	var ran []string
	abstained := make([]map[string]string, 0)
	for _, e := range s.Engines {
		if e.Available && e.Status == schema.StatusCompleted {
			ran = append(ran, e.Slug)
			continue
		}
		// An unavailable or failed engine ALWAYS travels with the summary: a cycle
		// in which half the engines failed must not look clean.
		reason := e.Reason
		if reason == "" {
			reason = string(e.Status)
		}
		abstained = append(abstained, map[string]string{"engine": e.Slug, "reason": reason})
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
