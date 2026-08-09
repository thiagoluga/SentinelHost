package baseline_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
)

// symlinkOrSkip creates a symlink, or skips with a reason.
//
// Windows refuses symlink creation to an unprivileged process. Skipping is honest here —
// production is Linux — but it is stated rather than silent, because a skipped test and a
// passing one are the same line without -v, and this repository has been caught twice by
// a green Windows suite saying nothing about POSIX behaviour.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating a symlink needs a privilege this process lacks on Windows: %v", err)
		}
		t.Fatalf("creating the symlink: %v", err)
	}
}

// A symlinked directory and a symlinked file cost wildly different things, and used to be
// counted as the same thing.
//
// Both landed in `skipped: symlink`. A link to a file costs one file — and if its target
// is inside a root, the walk reaches that target under its real name anyway. A link to a
// DIRECTORY costs everything underneath it, and if the target lies outside the configured
// roots, nothing in the cycle ever opens it while the web server may serve every file in
// there.
//
// So `symlink=1` meant either "one stray link" or "an entire web-reachable tree nobody
// looked at". Counted, and therefore not silent — but understating the second case by
// four orders of magnitude, which is the failure the count exists to prevent.
func TestASymlinkedDirectoryIsNotCountedAsOneSkippedFile(t *testing.T) {
	root := t.TempDir()

	// A real file, so the walk has something to succeed at.
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A directory outside the root holding several files, linked from inside it. This is
	// the shape that matters: the content is reachable through the site and its real path
	// is not in any configured root.
	outside := t.TempDir()
	for _, n := range []string{"a.php", "b.php", "c.php"} {
		if err := os.WriteFile(filepath.Join(outside, n), []byte("<?php\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	symlinkOrSkip(t, outside, filepath.Join(root, "uploads"))

	// And a plain symlinked file, which must stay in its own bucket.
	symlinkOrSkip(t, filepath.Join(root, "index.php"), filepath.Join(root, "alias.php"))

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 10,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if n := res.SkippedCounts["symlinked_directory"]; n != 1 {
		t.Errorf("symlinked_directory=%d, wanted 1 (all counts: %v). A subtree that was "+
			"never opened has to be distinguishable from a stray link",
			n, res.SkippedCounts)
	}
	if n := res.SkippedCounts["symlink"]; n != 1 {
		t.Errorf("symlink=%d, wanted 1 for the linked FILE (all counts: %v)",
			n, res.SkippedCounts)
	}

	// The path, not just the count. "symlinked_directory=1" says something was skipped;
	// the path is what lets the owner do anything about it.
	if len(res.SymlinkedDirs) != 1 {
		t.Fatalf("SymlinkedDirs=%v, wanted the one path", res.SymlinkedDirs)
	}
	if filepath.Base(res.SymlinkedDirs[0]) != "uploads" {
		t.Errorf("reported %q, wanted the link at uploads", res.SymlinkedDirs[0])
	}

	// The security decision is unchanged and must stay unchanged: nothing behind the link
	// was walked. This test would otherwise be a comfortable way to introduce the exact
	// traversal the walk refuses.
	for _, e := range res.Entries {
		if filepath.Dir(e.Path) == outside {
			t.Fatalf("the walk followed the symlink and read %s, outside the root", e.Path)
		}
	}
	if len(res.Entries) != 1 {
		t.Errorf("walked %d file(s), wanted only the real index.php: %v",
			len(res.Entries), res.Entries)
	}
}

// A symlink pointing at a directory INSIDE the root is still not followed, and still
// counted — but its target is reached under its real name, so nothing is lost.
//
// This test was written one commit before the distinction existed, and its own comment
// already said what was wrong: "the case where the count looks alarming and is not". It
// then asserted the alarming bucket. The reader can now tell the two apart because the
// counter does, so the assertion moved to the bucket that says "covered".
func TestASymlinkToADirectoryInsideTheRootLosesNoCoverage(t *testing.T) {
	root := t.TempDir()

	real := filepath.Join(root, "site")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "x.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, real, filepath.Join(root, "www"))

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 10,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if n := res.SkippedCounts["symlinked_directory_already_covered"]; n != 1 {
		t.Errorf("symlinked_directory_already_covered=%d, wanted 1 (all counts: %v)",
			n, res.SkippedCounts)
	}
	if n := res.SkippedCounts["symlinked_directory"]; n != 0 {
		t.Errorf("symlinked_directory=%d; this link hides nothing, and counting it as a "+
			"gap is a warning that would fire on every cPanel account", n)
	}
	// The file is still covered, once, through the real path.
	var found int
	for _, e := range res.Entries {
		if filepath.Base(e.Path) == "x.php" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("x.php was walked %d time(s), wanted exactly 1 — through its real path "+
			"and not through the link", found)
	}
}

// A link into ground the walk already covers is not a gap.
//
// On cPanel every account has `www` linked to `public_html`, which is inside the root and
// is walked under its real name — so nothing behind that link goes unseen. The first
// version of this reporting called it an unopened door, which would have put a line nobody
// can act on into every report on every account. The real one said so on day one:
//
//	2 directories reached through a symlink were not entered
//	(/home1/motel510/access-logs, /home1/motel510/www)
//
// One of those is a genuine gap and the other is the standard layout, and the message
// could not tell them apart. A warning that fires on every install is a warning that
// teaches its reader to skip the section it lives in.
func TestALinkIntoAlreadyCoveredGroundIsNotReportedAsAGap(t *testing.T) {
	root := t.TempDir()

	real := filepath.Join(root, "public_html")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "index.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, real, filepath.Join(root, "www"))

	// And one that genuinely leaves the root.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "hidden.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, outside, filepath.Join(root, "elsewhere"))

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 10,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if n := res.SkippedCounts["symlinked_directory"]; n != 1 {
		t.Errorf("symlinked_directory=%d, wanted 1 — only the link that leaves the root "+
			"hides anything (all counts: %v)", n, res.SkippedCounts)
	}
	if n := res.SkippedCounts["symlinked_directory_already_covered"]; n != 1 {
		t.Errorf("symlinked_directory_already_covered=%d, wanted 1. The link is still "+
			"counted — it was skipped, and nothing skipped goes unrecorded — but not as a "+
			"gap (all counts: %v)", n, res.SkippedCounts)
	}
	if len(res.SymlinkedDirs) != 1 || filepath.Base(res.SymlinkedDirs[0]) != "elsewhere" {
		t.Errorf("SymlinkedDirs=%v, wanted only the one that leaves the root",
			res.SymlinkedDirs)
	}

	// The covered content is still walked, once, under its real name.
	var seen int
	for _, e := range res.Entries {
		if filepath.Base(e.Path) == "index.php" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("index.php was walked %d time(s), wanted exactly 1", seen)
	}
}
