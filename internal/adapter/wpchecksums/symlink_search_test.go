package wpchecksums

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating a symlink needs a privilege this process lacks on Windows: %v", err)
		}
		t.Fatalf("creating the symlink: %v", err)
	}
}

// A WordPress behind a symlinked directory is unexamined, not absent.
//
// os.ReadDir returns entries describing the LINK, so DirEntry.IsDir() answers false for a
// symlinked directory and the search skipped it with no trace at all. That is this
// adapter's original defect wearing a second disguise: an account whose site sits behind
// a linked directory would be told "this does not look like a WordPress installation".
//
// The search still does not follow it — the walker refuses for a reason that holds here
// too, and this must not become the soft way around it. What changed is that the door is
// reported as closed rather than treated as empty.
func TestASymlinkedDirectoryIsReportedRatherThanIgnored(t *testing.T) {
	home := t.TempDir()

	elsewhere := t.TempDir()
	inc := filepath.Join(elsewhere, "wp-includes")
	if err := os.MkdirAll(inc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inc, "version.php"),
		[]byte("<?php\n$wp_version = '6.5.2';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "public_html")
	symlinkOrSkip(t, elsewhere, link)

	res := DetectAll(context.Background(), []string{home}, 0, 0, 0)

	if len(res.Installs) != 0 {
		t.Fatalf("the search entered the symlink and found %d installation(s); it must "+
			"not follow one", len(res.Installs))
	}
	if len(res.SymlinkedDirs) != 1 {
		t.Fatalf("SymlinkedDirs=%v, wanted the one link. Without it the abstention reads "+
			"as 'this account has no WordPress', which is a different statement from "+
			"'there is a door here that was not opened'", res.SymlinkedDirs)
	}
	if filepath.Base(res.SymlinkedDirs[0]) != "public_html" {
		t.Errorf("reported %q, wanted the link at public_html", res.SymlinkedDirs[0])
	}
}

// A symlinked FILE is not a skipped directory, and must not be reported as one.
//
// The check asks what the link points at rather than assuming; a file called
// `public_html` linked to another file would otherwise inflate the count and send the
// reader looking for a site that was never there.
func TestASymlinkedFileIsNotReportedAsASkippedDirectory(t *testing.T) {
	home := t.TempDir()

	target := filepath.Join(home, "readme.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, target, filepath.Join(home, "alias.txt"))

	res := DetectAll(context.Background(), []string{home}, 0, 0, 0)

	if len(res.SymlinkedDirs) != 0 {
		t.Errorf("SymlinkedDirs=%v; a link to a file hides no directory", res.SymlinkedDirs)
	}
}

// A root that IS a symlink still works.
//
// Detect() opens <root>/wp-includes/version.php, and os.Open follows links, so a
// configured root that happens to be a symlink resolves normally. Worth pinning: the
// change above is about links found DURING the search, and it would be easy to break
// this case while fixing that one.
func TestARootThatIsItselfASymlinkStillResolves(t *testing.T) {
	parent := t.TempDir()

	real := filepath.Join(parent, "www")
	if err := os.MkdirAll(filepath.Join(real, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "wp-includes", "version.php"),
		[]byte("<?php\n$wp_version = '6.5.2';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "public_html")
	symlinkOrSkip(t, real, link)

	res := DetectAll(context.Background(), []string{link}, 0, 0, 0)

	if len(res.Installs) != 1 {
		t.Fatalf("found %d installation(s) with the root itself a symlink, wanted 1",
			len(res.Installs))
	}
}

// The same distinction in the WordPress search.
//
// `www` -> `public_html` is universal on cPanel, and public_html is inside the root the
// search already walks. Naming it as an unopened door would appear in every account's
// abstention, which is how a message stops being read.
func TestALinkIntoTheSearchedTreeIsNotReportedAsADoorLeftClosed(t *testing.T) {
	home := t.TempDir()

	real := filepath.Join(home, "public_html")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, real, filepath.Join(home, "www"))

	elsewhere := t.TempDir()
	symlinkOrSkip(t, elsewhere, filepath.Join(home, "outside"))

	res := DetectAll(context.Background(), []string{home}, 0, 0, 0)

	if len(res.SymlinkedDirs) != 1 {
		t.Fatalf("SymlinkedDirs=%v, wanted only the link that leaves the searched tree",
			res.SymlinkedDirs)
	}
	if filepath.Base(res.SymlinkedDirs[0]) != "outside" {
		t.Errorf("reported %q; www points at public_html, which this search already walks",
			res.SymlinkedDirs[0])
	}
}
