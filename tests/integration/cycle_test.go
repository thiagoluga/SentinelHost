package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/lock"
)

// SC-002 -----------------------------------------------------------------------

// TestSC002LargeIncrementalCycle measures the incremental cycle on a 20,000-file
// site with 1% of changes.
//
// The spec demands under 5 minutes within the default limits. What dominates that
// time is the walk plus the hashing of the files that changed; running the external
// engines is out of scope (D-011), which is why the test measures the cost
// SentinelHost has control over.
func TestSC002LargeIncrementalCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("SC-002 builds 20,000 files; skipped under -short")
	}

	root := t.TempDir()
	const total = 20000
	const changed = total / 100 // 1%

	buildSite(t, root, total)

	cfg := config.Default()
	cfg.General.Roots = []string{root}
	cfg.General.DataDir = filepath.Join(t.TempDir(), "data")

	baselinePath := filepath.Join(cfg.General.DataDir, "baseline.json")
	if err := os.MkdirAll(cfg.General.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Cycle 1: the full baseline. It does not count towards SC-002's measurement —
	// the criterion is about the INCREMENTAL cycle.
	bl := baseline.New(cfg.General.Roots)
	res, err := baseline.Walk(context.Background(), walkOptions(cfg, root))
	if err != nil {
		t.Fatalf("initial walk: %v", err)
	}
	if len(res.Entries) < total {
		t.Fatalf("expected at least %d files, got %d", total, len(res.Entries))
	}
	baselineStart := time.Now()
	entries := baseline.HashEntries(context.Background(), res.Entries, res.SkippedCounts)
	bl.Update(entries, nil)
	if err := bl.Save(baselinePath); err != nil {
		t.Fatalf("saving the baseline: %v", err)
	}
	t.Logf("full baseline of %d files: %s", len(entries), time.Since(baselineStart).Round(time.Millisecond))

	// Modify 1% of the files.
	for i := 0; i < changed; i++ {
		p := filepath.Join(root, fmt.Sprintf("dir%02d", i%50), fmt.Sprintf("file%05d.php", i))
		if err := os.WriteFile(p, []byte(fmt.Sprintf("<?php // changed %d\n", i)), 0o644); err != nil {
			t.Fatalf("modifying %s: %v", p, err)
		}
	}

	// Cycle 2: incremental. This is the one SC-002 measures.
	start := time.Now()

	bl2, err := baseline.Load(baselinePath, cfg.General.Roots)
	if err != nil {
		t.Fatalf("loading the baseline: %v", err)
	}
	res2, err := baseline.Walk(context.Background(), walkOptions(cfg, root))
	if err != nil {
		t.Fatalf("incremental walk: %v", err)
	}
	// Only what changed in the size+mtime pair is read from disk. It is the step
	// that makes the incremental cycle cheap enough to run hourly.
	needsHash := bl2.NeedsHash(res2.Entries)
	hashed := baseline.HashEntries(context.Background(), needsHash, res2.SkippedCounts)

	fresh := map[string]baseline.Entry{}
	for _, e := range hashed {
		fresh[e.Path] = e
	}
	current := make([]baseline.Entry, 0, len(res2.Entries))
	for _, e := range res2.Entries {
		if h, ok := fresh[e.Path]; ok {
			current = append(current, h)
			continue
		}
		if previous, ok := bl2.Get(e.Path); ok {
			e.SHA256 = previous.SHA256
		}
		current = append(current, e)
	}
	d := bl2.Compare(current)
	targets := d.Targets()

	elapsed := time.Since(start)

	t.Logf("SC-002: incremental cycle of %d files (%d modified) in %s",
		len(res2.Entries), len(targets), elapsed.Round(time.Millisecond))
	t.Logf("        files re-read from disk: %d (%.2f%% of the total)",
		len(needsHash), float64(len(needsHash))/float64(len(res2.Entries))*100)

	if len(targets) != changed {
		t.Errorf("the incremental cycle should scan exactly the %d modified files, got %d", changed, len(targets))
	}
	if d.Unchanged != len(res2.Entries)-changed {
		t.Errorf("unchanged: %d, expected %d", d.Unchanged, len(res2.Entries)-changed)
	}
	// The incremental cycle's gain is right here: re-reading 1% of the site instead
	// of 100%.
	if len(needsHash) > changed*2 {
		t.Errorf("the incremental cycle re-read %d files for %d modified: the cheap filter is not working",
			len(needsHash), changed)
	}
	if elapsed > 5*time.Minute {
		t.Errorf("SC-002 failed: the incremental cycle took %s, limit 5 minutes", elapsed)
	}
}

func walkOptions(cfg *config.Config, root string) baseline.WalkOptions {
	return baseline.WalkOptions{
		Root:             root,
		Exclude:          cfg.Limits.Exclude,
		MaxDepth:         cfg.Limits.MaxDepth,
		MaxFileSizeBytes: int64(cfg.Limits.MaxFileSizeMB) << 20,
		MaxFiles:         cfg.Limits.MaxFilesPerCycle,
	}
}

func buildSite(t *testing.T, root string, n int) {
	t.Helper()
	for d := 0; d < 50; d++ {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("dir%02d", d)), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	content := []byte("<?php\n// SentinelHost test file\nfunction x() { return 1; }\n")
	for i := 0; i < n; i++ {
		p := filepath.Join(root, fmt.Sprintf("dir%02d", i%50), fmt.Sprintf("file%05d.php", i))
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

// Single-instance lock ---------------------------------------------------------

// TestTheLockPreventsConcurrentCycles covers the spec's edge case: the cron and the
// panel triggering a scan at the same time.
func TestTheLockPreventsConcurrentCycles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	first, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer func() { _ = first.Release() }()

	const attempts = 20
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			l, err := lock.Acquire(path)
			if err == nil {
				_ = l.Release()
			}
			results <- err
		}()
	}

	successes := 0
	for i := 0; i < attempts; i++ {
		if err := <-results; err == nil {
			successes++
		}
	}
	// Two concurrent cycles would write to the same baseline and could try to
	// quarantine the same file twice.
	if successes != 0 {
		t.Errorf("%d process(es) got the lock while it was taken", successes)
	}
}
