// Package housekeeping gathers SentinelHost's periodic maintenance.
//
// It exists because those routines used to live only in the daemon, and the
// project's DEFAULT mode is `cron` (Principle III: everything essential has to work
// with the cPanel cron alone). The practical effect was that, on the path the
// documentation recommends:
//
//   - a webhook that failed was never retried — the 5-attempt backoff existed in
//     the code and never happened;
//   - the periodic summary never went out;
//   - cycles killed by the hosting stayed `running` forever;
//   - the configured retention for the log and the raw output was never applied,
//     and both grew until they blew the account's disk quota — the exact opposite
//     of Principle IV, caused by the tool itself.
//
// Now `scan` and `daemon` call the same routines.
package housekeeping

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Alerter is what the maintenance needs from the alerts. A local interface so this
// package does not depend on the alerts package — a stuck delivery must have no way
// of holding the disk cleanup up.
type Alerter interface {
	RetryPending(ctx context.Context) (int, error)
	SendDigestIfDue(ctx context.Context) (bool, error)
}

// Result describes what the maintenance did, for the log and for the CLI.
type Result struct {
	RetriedDeliveries int
	DigestSent        bool
	PurgedQuarantine  int
	PrunedEvents      int64
	PrunedRawDirs     int
	RecoveredScans    int
}

// Empty answers whether there was nothing to do.
func (r Result) Empty() bool {
	return r.RetriedDeliveries == 0 && !r.DigestSent && r.PurgedQuarantine == 0 &&
		r.PrunedEvents == 0 && r.PrunedRawDirs == 0 && r.RecoveredScans == 0
}

// Deps are the pieces the maintenance uses. Vault and Alerts may be nil.
type Deps struct {
	Cfg    *config.Config
	Store  *store.Store
	Vault  *quarantine.Vault
	Alerts Alerter
	Now    func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Run runs every routine.
//
// No failure interrupts the others: if the webhook is down, the disk pruning still
// has to happen. The errors are aggregated and returned for the record, never
// propagated as a cycle failure.
func Run(ctx context.Context, d Deps) (Result, error) {
	var res Result
	var failures []error

	res.RecoveredScans = recoverCycles(ctx, d, &failures)

	if d.Alerts != nil {
		if n, err := d.Alerts.RetryPending(ctx); err != nil {
			failures = append(failures, fmt.Errorf("delivery retries: %w", err))
		} else {
			res.RetriedDeliveries = n
		}

		if sent, err := d.Alerts.SendDigestIfDue(ctx); err != nil {
			failures = append(failures, fmt.Errorf("periodic summary: %w", err))
		} else {
			res.DigestSent = sent
		}
	}

	// The automatic purge only acts if the user turned it on, and the vault still
	// refuses any item inside its retention — the maintenance has no way of getting
	// around that barrier, not even by accident.
	if d.Vault != nil && d.Cfg.Quarantine.AutoPurge {
		if n, err := d.Vault.PurgeExpired(ctx); err != nil {
			failures = append(failures, fmt.Errorf("quarantine purge: %w", err))
		} else if n > 0 {
			res.PurgedQuarantine = n
			// Permanently removing a user's file always gets recorded, even when it
			// was authorized in advance by the configuration.
			log(ctx, d, "warn", store.CatQuarantine,
				fmt.Sprintf("%d expired item(s) permanently purged by the automatic routine", n))
		}
	}

	res.PrunedEvents = pruneLog(ctx, d, &failures)
	res.PrunedRawDirs = pruneRawOutput(ctx, d, &failures)

	if _, err := d.Store.PurgeExpiredSessions(ctx); err != nil {
		failures = append(failures, fmt.Errorf("expired sessions: %w", err))
	}

	return res, errors.Join(failures...)
}

// recoverCycles closes cycles that started and never finished.
//
// The hosting kills long processes. An interrupted cycle stays `running` with no
// `finished_at`; leaving it that way forever would make the history lie by
// omission — and recording it as `killed` is what makes the loss of coverage in
// that period visible.
func recoverCycles(ctx context.Context, d Deps, failures *[]error) int {
	ids, err := d.Store.InterruptedScans(ctx)
	if err != nil {
		*failures = append(*failures, fmt.Errorf("looking for interrupted cycles: %w", err))
		return 0
	}

	n := 0
	for _, id := range ids {
		if err := d.Store.FinishScan(ctx, store.ScanRecord{
			ScanID: id, FinishedAt: d.now(), Status: schema.StatusKilled,
		}); err != nil {
			*failures = append(*failures, err)
			continue
		}
		n++
		log(ctx, d, "warn", store.CatScan,
			fmt.Sprintf("cycle %s was interrupted before finishing (process killed?); recorded as killed", id))
	}
	return n
}

// pruneLog applies the structured log's retention.
func pruneLog(ctx context.Context, d Deps, failures *[]error) int64 {
	days := d.Cfg.Logging.RetentionDays
	if days <= 0 {
		return 0
	}
	cutoff := d.now().AddDate(0, 0, -days)
	n, err := d.Store.PruneEvents(ctx, cutoff)
	if err != nil {
		*failures = append(*failures, fmt.Errorf("pruning the log: %w", err))
		return 0
	}
	return n
}

// pruneRawOutput deletes engine raw output beyond the retention.
//
// The raw output is archived for auditing and reprocessing, but it is what grows
// fastest: every cycle writes each engine's complete stdout. On an account with a
// quota, without pruning that fills the disk within weeks.
//
// Only whole cycle directories are removed, and only by modification date — never
// by name, which would be a guess about the format of an id.
func pruneRawOutput(ctx context.Context, d Deps, failures *[]error) int {
	days := d.Cfg.Logging.RawOutputRetentionDays
	if days <= 0 {
		return 0
	}
	root := d.Cfg.RawOutputDir()
	cutoff := d.now().AddDate(0, 0, -days)

	entries, err := os.ReadDir(root)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			*failures = append(*failures, fmt.Errorf("reading %s: %w", root, err))
		}
		return 0
	}

	n := 0
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		target := filepath.Join(root, e.Name())
		// Check that the target is still inside the data area before removing it
		// recursively. An unexpected name must never turn into a RemoveAll outside
		// where the tool is meant to act.
		if !inside(root, target) {
			continue
		}
		if err := os.RemoveAll(target); err != nil {
			*failures = append(*failures, fmt.Errorf("removing %s: %w", target, err))
			continue
		}
		n++
	}
	if n > 0 {
		log(ctx, d, "info", store.CatSystem,
			fmt.Sprintf("%d raw-output directory/ies removed by retention (%d days)", n, days))
	}
	return n
}

func inside(root, target string) bool {
	r, err1 := filepath.Abs(root)
	a, err2 := filepath.Abs(target)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(r, a)
	if err != nil {
		return false
	}
	return rel != ".." && !filepath.IsAbs(rel) &&
		!(len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator))
}

func log(ctx context.Context, d Deps, level, cat, msg string) {
	_ = d.Store.Log(ctx, store.Event{TS: d.now(), Level: level, Category: cat, Message: msg})
}
