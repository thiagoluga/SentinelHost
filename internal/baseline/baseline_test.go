package baseline_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
)

func buildTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"index.php":                          "<?php echo 'hi';",
		"wp-content/themes/theme/footer.php": "<?php // footer",
		"wp-content/cache/x.php":             "<?php // cache",
		"wp-content/uploads/2026/photo.jpg":  "fake-binary",
		"wp-content/uploads/2026/script.php": "<?php // suspicious",
		"a/b/c/d/e/f/deep.php":               "<?php // deep",
	}
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

func paths(entries []baseline.Entry) map[string]bool {
	out := map[string]bool{}
	for _, e := range entries {
		out[filepath.ToSlash(e.Path)] = true
	}
	return out
}

func TestWalkAppliesExclusions(t *testing.T) {
	root := buildTree(t)

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root:     root,
		Exclude:  []string{"**/wp-content/cache/**", "**/*.jpg"},
		MaxDepth: 20,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	got := paths(res.Entries)
	for p := range got {
		if filepath.Ext(p) == ".jpg" {
			t.Errorf("a file excluded by extension showed up: %s", p)
		}
		if contains(p, "/cache/") {
			t.Errorf("an excluded directory showed up: %s", p)
		}
	}
	if res.SkippedCounts["excluded"] == 0 {
		t.Error("the exclusions should be counted, not silent")
	}
}

func TestWalkCountsALargeFileInsteadOfIgnoringIt(t *testing.T) {
	// Skipping silently would make the coverage look complete.
	root := t.TempDir()
	large := filepath.Join(root, "large.php")
	if err := os.WriteFile(large, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	small := filepath.Join(root, "small.php")
	if err := os.WriteFile(small, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 10, MaxFileSizeBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(res.Entries))
	}
	if res.SkippedCounts["too_large"] != 1 {
		t.Errorf("the large file should be counted: %v", res.SkippedCounts)
	}
}

func TestWalkHonoursTheMaximumDepth(t *testing.T) {
	root := buildTree(t)

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 2,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, e := range res.Entries {
		if contains(filepath.ToSlash(e.Path), "/a/b/c/") {
			t.Errorf("a file beyond the depth showed up: %s", e.Path)
		}
	}
	if res.SkippedCounts["too_deep"] == 0 {
		t.Error("the exceeded depth should be counted")
	}
}

func TestWalkNeverFollowsASymlink(t *testing.T) {
	// A link pointing outside the root would take the scanner into someone else's
	// account on a shared server.
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs a privilege; the real target is Linux (D-002)")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{Root: root, MaxDepth: 10})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, e := range res.Entries {
		if contains(e.Path, "secret.php") {
			t.Fatalf("the walker followed the symlink and left the root: %s", e.Path)
		}
	}
	if res.SkippedCounts["symlink"] == 0 {
		t.Error("the symlink should be counted")
	}
}

func TestWalkTruncatesAtMaxFiles(t *testing.T) {
	root := buildTree(t)
	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 20, MaxFiles: 2,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(res.Entries))
	}
	if !res.Truncated {
		t.Error("the truncation should be signalled so the cycle becomes partial")
	}
}

func TestWalkRefusesANonExistentRoot(t *testing.T) {
	_, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: filepath.Join(t.TempDir(), "does-not-exist"), MaxDepth: 5,
	})
	if err == nil {
		t.Fatal("a non-existent root should be an error")
	}
}

// Baseline --------------------------------------------------------------------

func TestBaselineRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{
		{Path: "/site/a.php", Size: 10, MTime: 100, SHA256: "aa", Perms: "0644"},
		{Path: "/site/b.php", Size: 20, MTime: 200, SHA256: "bb", Perms: "0644"},
	}, nil)

	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	back, err := baseline.Load(path, []string{"/site"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if back.Len() != 2 {
		t.Fatalf("expected 2 files, got %d", back.Len())
	}
	e, ok := back.Get("/site/a.php")
	if !ok || e.SHA256 != "aa" {
		t.Errorf("entry lost: %+v", e)
	}
}

func TestAnAbsentBaselineIsNotAnError(t *testing.T) {
	// The first run has no baseline, and that is normal.
	b, err := baseline.Load(filepath.Join(t.TempDir(), "does-not-exist.json"), []string{"/site"})
	if err != nil {
		t.Fatalf("an absent baseline should not be an error: %v", err)
	}
	if b.Len() != 0 {
		t.Errorf("expected an empty baseline, got %d", b.Len())
	}
}

func TestACorruptedBaselineStartsOverInsteadOfBlocking(t *testing.T) {
	// Starting over costs one full scan; blocking costs all of the protection.
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("{this is not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, err := baseline.Load(path, []string{"/site"})
	if err == nil {
		t.Error("the problem should be reported to the caller")
	}
	if b == nil || b.Len() != 0 {
		t.Fatal("it should return a usable empty baseline")
	}
}

func TestCompareDetectsNewModifiedAndRemoved(t *testing.T) {
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{
		{Path: "/site/same.php", Size: 10, MTime: 100, SHA256: "aa"},
		{Path: "/site/changed.php", Size: 20, MTime: 200, SHA256: "bb"},
		{Path: "/site/vanished.php", Size: 30, MTime: 300, SHA256: "cc"},
	}, nil)

	d := b.Compare([]baseline.Entry{
		{Path: "/site/same.php", Size: 10, MTime: 100, SHA256: "aa"},
		{Path: "/site/changed.php", Size: 25, MTime: 250, SHA256: "bb-new"},
		{Path: "/site/new.php", Size: 5, MTime: 400, SHA256: "dd"},
	})

	if d.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", d.Unchanged)
	}
	if len(d.Modified) != 1 || d.Modified[0].Path != "/site/changed.php" {
		t.Errorf("wrong modified set: %+v", d.Modified)
	}
	if len(d.New) != 1 || d.New[0].Path != "/site/new.php" {
		t.Errorf("wrong new set: %+v", d.New)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "/site/vanished.php" {
		t.Errorf("wrong removed set: %+v", d.Removed)
	}
	if len(d.Targets()) != 2 {
		t.Errorf("the cycle should scan 2 files, got %d", len(d.Targets()))
	}
}

func TestAFileWithTheSameSizeAndMtimeButADifferentHashIsModified(t *testing.T) {
	// `touch` to restore the mtime is the first thing an attacker does. Once the
	// hash has been computed, it beats the size+mtime pair.
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{{Path: "/site/x.php", Size: 100, MTime: 500, SHA256: "original"}}, nil)

	d := b.Compare([]baseline.Entry{{Path: "/site/x.php", Size: 100, MTime: 500, SHA256: "tampered"}})

	if len(d.Modified) != 1 {
		t.Fatalf("a different hash should mark it as modified, got %+v", d)
	}
}

func TestNeedsHashOnlyTakesWhatChangedInTheCheapPair(t *testing.T) {
	// It is the step that makes the incremental cycle cheap.
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{
		{Path: "/site/a.php", Size: 10, MTime: 100, SHA256: "aa"},
		{Path: "/site/b.php", Size: 20, MTime: 200, SHA256: "bb"},
	}, nil)

	needed := b.NeedsHash([]baseline.Entry{
		{Path: "/site/a.php", Size: 10, MTime: 100},
		{Path: "/site/b.php", Size: 21, MTime: 200},
		{Path: "/site/c.php", Size: 5, MTime: 300},
	})

	if len(needed) != 2 {
		t.Fatalf("expected 2 files to hash, got %d: %+v", len(needed), needed)
	}
}

func TestUpdateDoesNotStoreAnEntryWithNoHash(t *testing.T) {
	// Storing it without a hash would make the next cycle believe it already knows
	// the file.
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{{Path: "/site/new.php", Size: 10, MTime: 100}}, nil)

	if b.Len() != 0 {
		t.Errorf("an entry with no hash should not enter the baseline: %d", b.Len())
	}
}

func TestUpdatePreservesAKnownHashWhenItWasNotRecomputed(t *testing.T) {
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{{Path: "/site/x.php", Size: 10, MTime: 100, SHA256: "aa"}}, nil)
	// A new cycle: the same file, with no hash recomputed because nothing changed.
	b.Update([]baseline.Entry{{Path: "/site/x.php", Size: 10, MTime: 100}}, nil)

	e, ok := b.Get("/site/x.php")
	if !ok || e.SHA256 != "aa" {
		t.Errorf("the known hash was lost: %+v", e)
	}
}

func TestHashEntriesDiscardsTheUnreadable(t *testing.T) {
	// An empty hash would become an invalid deduplication key in the consensus.
	root := t.TempDir()
	good := filepath.Join(root, "good.php")
	if err := os.WriteFile(good, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	skipped := map[string]int{}
	out := baseline.HashEntries(context.Background(), []baseline.Entry{
		{Path: good},
		{Path: filepath.Join(root, "does-not-exist.php")},
	}, skipped)

	if len(out) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(out))
	}
	if out[0].SHA256 == "" {
		t.Error("the hash was not computed")
	}
	if skipped["unreadable"] != 1 {
		t.Errorf("the unreadable one should be counted: %v", skipped)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
