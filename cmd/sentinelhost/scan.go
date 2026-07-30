package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/housekeeping"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

func cmdScan(ctx context.Context, args []string) int {
	fs, cfgPath := flagSet("scan")
	full := fs.Bool("full", false, "scan everything instead of only what changed since the last cycle")
	dryRun := fs.Bool("dry-run", false, "compute the verdicts without taking any action")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	quiet := fs.Bool("quiet", false, "print only when there are findings")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost scan — run a cycle now.

It probes the available engines, runs the ones that are ready, normalizes their
output and consolidates one verdict per file.

It exits with code 1 when it finds findings. That is NOT an error: it is the
normal behaviour of a scanner that found something. Use it in the cron to tell
"found malware" from "the tool broke".

OPTIONS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer a.Close()

	mode := schema.ModeIncremental
	if *full {
		mode = schema.ModeFull
	}

	dispatcher := alert.NewDispatcher(ctx, a.cfg, a.store)
	runner := cycle.New(a.cfg, a.store, a.registry, a.vault).WithDispatcher(dispatcher)

	// The periodic maintenance runs BEFORE the cycle, in cron mode as much as in
	// the daemon. It is what makes the webhook backoff, the periodic summary and the
	// disk retention actually exist in the project's DEFAULT mode — without it, all
	// of that only happened for whoever keeps a daemon alive, which is precisely
	// what Principle III says we cannot presuppose.
	maint, err := housekeeping.Run(ctx, housekeeping.Deps{
		Cfg: a.cfg, Store: a.store, Vault: a.vault, Alerts: dispatcher,
	})
	if err != nil {
		// Maintenance that fails never blocks the scan: the scan is the protection,
		// the maintenance is the tidying up.
		fmt.Fprintf(os.Stderr, "warning: periodic maintenance: %v\n", err)
	}

	sum, err := runner.Run(ctx, cycle.Options{Mode: mode, DryRun: *dryRun})
	if err != nil {
		if errors.Is(err, errLocked) {
			fmt.Fprintln(os.Stderr, err)
			return exitLocked
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	// Mark the first cycle, which starts the grace period's count.
	if a.cfg.General.FirstRunAt.IsZero() {
		a.cfg.General.FirstRunAt = sum.StartedAt
		if err := a.cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not record the date of the first cycle: %v\n", err)
		}
	}

	findings := countActionable(sum)

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(jsonReport(sum)); err != nil {
			fmt.Fprintf(os.Stderr, "error serializing the report: %v\n", err)
			return exitError
		}
	case *quiet && findings == 0:
		// deliberate silence
	default:
		printReport(os.Stdout, sum, &maint)
	}

	if findings > 0 {
		return exitFindings
	}
	// Exit 0 means "the cycle ran and found nothing". A cycle where no engine voted did
	// not run in any sense that matters, and exiting 0 tells every cron job and
	// monitoring check watching this command that the site is fine.
	//
	// exitError rather than a new code: this IS a failure — the tool was asked to scan
	// and did not — and inventing a fourth code would leave every existing integration
	// treating the new value as success by default.
	if !sum.AnyEngineVoted() {
		fmt.Fprintln(os.Stderr,
			"error: no engine could run, so nothing was scanned. Exiting non-zero so this "+
				"is not mistaken for a clean result.")
		return exitError
	}
	return exitOK
}

func countActionable(sum cycle.Summary) int {
	return sum.LevelCounts[schema.LevelConfirmed] +
		sum.LevelCounts[schema.LevelLikely] +
		sum.LevelCounts[schema.LevelSuspicious]
}

func jsonReport(sum cycle.Summary) map[string]any {
	out := sum.Event()
	out["verdicts_detail"] = sum.Verdicts
	return out
}

// printReport writes the report as text.
//
// The order is not decorative: first what demands action, then what the user needs
// to know about the scan's COVERAGE. A report that says "0 findings" without saying
// that 3 of the 4 engines failed is a lie by omission.
func printReport(w *os.File, sum cycle.Summary, maint *housekeeping.Result) {
	fmt.Fprintf(w, "\nSentinelHost — cycle %s (%s)\n", sum.ScanID, sum.Mode)
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 64))
	fmt.Fprintf(w, "Duration: %s | Considered: %d | Scanned: %d\n",
		sum.FinishedAt.Sub(sum.StartedAt).Round(time.Millisecond),
		sum.FilesConsidered, sum.FilesScanned)

	// Engines: this cycle's real coverage.
	fmt.Fprintf(w, "\nENGINES\n")
	for _, e := range sum.Engines {
		switch {
		case !e.Available:
			fmt.Fprintf(w, "  ✗ %-20s unavailable — %s\n", e.Slug, e.Reason)
		case e.Status != schema.StatusCompleted:
			fmt.Fprintf(w, "  ! %-20s %s (abstention) — %s\n", e.Slug, e.Status, e.Reason)
		default:
			fmt.Fprintf(w, "  ✓ %-20s %d finding(s) in %s\n", e.Slug, e.Findings, e.Duration.Round(time.Millisecond))
		}
		// What the engine could NOT look at travels with what it did look at.
		// wp-checksums records how many plugins were left unverified (commercial,
		// in-house, or with no version in the header); that number living only in
		// the database would make "not verified" look like "clean".
		if len(e.Skipped) > 0 {
			fmt.Fprintf(w, "      skipped: %s\n", formatSkipped(e.Skipped))
		}
	}
	// An abstention from an engine that was never even probed (enabled in the
	// configuration but with no adapter in this binary) also enters the list: the
	// number of abstentions has to match the reasons shown, otherwise the user sees
	// "4 abstained" and only 3 explanations.
	listed := map[string]bool{}
	for _, e := range sum.Engines {
		listed[e.Slug] = true
	}
	for _, slug := range sortedKeys(sum.Abstentions) {
		if !listed[slug] {
			fmt.Fprintf(w, "  ✗ %-20s %s\n", slug, sum.Abstentions[slug])
		}
	}
	// "Reduced coverage" and "no coverage" are not the same sentence.
	//
	// The message used to be identical whether one engine abstained or all of them did.
	// A cycle where nothing voted did not scan the site, and the empty verdict list below
	// it means nothing whatsoever — so it says that, in the place where someone reading
	// the output would otherwise be relieved.
	if !sum.AnyEngineVoted() {
		fmt.Fprintf(w, "\n  NOTHING WAS SCANNED: all %d engine(s) abstained.\n", len(sum.Abstentions))
		fmt.Fprintf(w, "  An empty result below says nothing about this site. Fix a reason above first.\n")
	} else if len(sum.Abstentions) > 0 {
		fmt.Fprintf(w, "\n  %d engine(s) abstained: this cycle's coverage is reduced.\n", len(sum.Abstentions))
	}

	// Verdicts.
	actionable := sortBySeverity(sum.Verdicts)
	fmt.Fprintf(w, "\nVERDICTS\n")
	if len(actionable) == 0 {
		fmt.Fprintf(w, "  Nothing to report.\n")
	}
	for _, v := range actionable {
		fmt.Fprintf(w, "\n  [%s] score %.2f — %s\n", strings.ToUpper(string(v.Level)), v.Score, v.FilePath)
		for _, vote := range v.Votes {
			fmt.Fprintf(w, "      vote: %-20s weight %.2f x %-9s = %.2f  (rule %s)\n",
				vote.Engine, vote.Weight, vote.Confidence, vote.EffectiveWeight, vote.Rule)
		}
		if len(v.Abstentions) > 0 {
			fmt.Fprintf(w, "      abstentions: %s\n", strings.Join(v.Abstentions, ", "))
		}
		if v.CleanReason != "" {
			fmt.Fprintf(w, "      veto: %s\n", v.CleanReason)
		}
		fmt.Fprintf(w, "      action: %s", v.ActionTaken)
		if v.ActionError != "" {
			fmt.Fprintf(w, " (%s)", v.ActionError)
		}
		fmt.Fprintln(w)
	}

	// Summary per level.
	fmt.Fprintf(w, "\nSUMMARY  ")
	for _, l := range []schema.Level{schema.LevelConfirmed, schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		fmt.Fprintf(w, "%s=%d  ", l, sum.LevelCounts[l])
	}
	fmt.Fprintln(w)

	if sum.ObservationReason != "" {
		fmt.Fprintf(w, "\nNo automatic action was taken: %s\n", sum.ObservationReason)
	}
	if maint != nil && !maint.Empty() {
		fmt.Fprintf(w, "\nMaintenance: %s\n", maintenanceSummary(*maint))
	}
	if n := sum.SkippedCounts["truncated"]; n > 0 {
		fmt.Fprintf(w, "\nWARNING: the per-cycle file limit was reached. Part of the site was not looked at.\n")
	}
	if len(sum.SkippedCounts) > 0 {
		fmt.Fprintf(w, "\nSkipped: %s\n", formatSkipped(sum.SkippedCounts))
	}
	fmt.Fprintln(w)
}

// sortBySeverity puts what demands action on top and hides the clean ones.
func sortBySeverity(vs []schema.Verdict) []schema.Verdict {
	var out []schema.Verdict
	for _, v := range vs {
		if v.Level != schema.LevelClean {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Level.Rank() != out[j].Level.Rank() {
			return out[i].Level.Rank() > out[j].Level.Rank()
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func formatSkipped(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// maintenanceSummary describes in one line what the maintenance routine did.
func maintenanceSummary(r housekeeping.Result) string {
	var parts []string
	if r.RetriedDeliveries > 0 {
		parts = append(parts, fmt.Sprintf("%d delivery/ies retried", r.RetriedDeliveries))
	}
	if r.DigestSent {
		parts = append(parts, "periodic summary sent")
	}
	if r.PurgedQuarantine > 0 {
		parts = append(parts, fmt.Sprintf("%d item(s) purged by retention", r.PurgedQuarantine))
	}
	if r.PrunedEvents > 0 {
		parts = append(parts, fmt.Sprintf("%d log event(s) pruned", r.PrunedEvents))
	}
	if r.PrunedRawDirs > 0 {
		parts = append(parts, fmt.Sprintf("%d raw-output directory/ies removed", r.PrunedRawDirs))
	}
	if r.RecoveredScans > 0 {
		parts = append(parts, fmt.Sprintf("%d interrupted cycle(s) recorded as killed", r.RecoveredScans))
	}
	return strings.Join(parts, ", ")
}
