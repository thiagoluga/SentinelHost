package wpchecksums

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// plantWordPress writes the minimum that makes a directory a WordPress: the version file
// the adapter reads.
func plantWordPress(t *testing.T, dir, version string) string {
	t.Helper()
	inc := filepath.Join(dir, "wp-includes")
	if err := os.MkdirAll(inc, 0o755); err != nil {
		t.Fatalf("creating %s: %v", inc, err)
	}
	body := "<?php\n$wp_version = '" + version + "';\n"
	if err := os.WriteFile(filepath.Join(inc, "version.php"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing version.php: %v", err)
	}
	return dir
}

func rootsOf(res SearchResult) []string {
	out := make([]string, 0, len(res.Installs))
	for _, i := range res.Installs {
		out = append(out, i.Root)
	}
	sort.Strings(out)
	return out
}

// The one that started this: WordPress in a subdirectory of the configured root.
//
// The adapter only ever asked whether the root ITSELF was a WordPress, so on a hosting
// account — where the root is the home and the site is at public_html/<domain>/ — it
// reported "this does not look like a WordPress installation" for an account running one.
// That is not a missing feature; it is the engine that vetoes quarantine for legitimate
// core files (D-005) staying silent while the heuristics judge those files alone.
func TestWordPressInASubdirectoryIsFound(t *testing.T) {
	home := t.TempDir()
	want := plantWordPress(t, filepath.Join(home, "public_html", "example.com"), "6.5.2")

	res := DetectAll([]string{home}, 0, 0, 0)

	if len(res.Installs) != 1 {
		t.Fatalf("found %d installations, wanted 1: %v", len(res.Installs), rootsOf(res))
	}
	if res.Installs[0].Root != want {
		t.Errorf("found %q, wanted %q", res.Installs[0].Root, want)
	}
	if res.Installs[0].Version != "6.5.2" {
		t.Errorf("version %q, wanted 6.5.2", res.Installs[0].Version)
	}
	if res.DirsWalked == 0 {
		t.Error("DirsWalked is 0, so nothing records that the search happened at all")
	}
}

// An account with several sites gets all of them.
//
// This is the normal shape of shared hosting, not an edge case: one account, one addon
// domain per site. Finding the first and stopping would report on one site while looking
// like it had covered the account.
func TestEveryInstallationOnTheAccountIsFound(t *testing.T) {
	home := t.TempDir()
	a := plantWordPress(t, filepath.Join(home, "public_html"), "6.5.2")
	b := plantWordPress(t, filepath.Join(home, "public_html", "blog.example.com"), "6.4.1")
	c := plantWordPress(t, filepath.Join(home, "outra", "loja"), "6.6")

	res := DetectAll([]string{home}, 0, 0, 0)

	got := rootsOf(res)
	want := []string{a, b, c}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("found %v, wanted %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("found %v, wanted %v", got, want)
		}
	}
}

// A WordPress inside another one's wp-content is not a second site.
//
// Backups and staging copies live there. Treating one as its own installation would
// report every finding twice and inflate the account's file counts.
func TestABackupInsideWPContentIsNotASecondSite(t *testing.T) {
	home := t.TempDir()
	site := plantWordPress(t, filepath.Join(home, "public_html"), "6.5.2")
	plantWordPress(t, filepath.Join(site, "wp-content", "backups", "old-site"), "5.9")

	res := DetectAll([]string{home}, 0, 0, 0)

	if len(res.Installs) != 1 {
		t.Fatalf("found %d installations, wanted 1: %v", len(res.Installs), rootsOf(res))
	}
	if res.Installs[0].Root != site {
		t.Errorf("found %q, wanted the real site at %q", res.Installs[0].Root, site)
	}
}

// Every root is searched, not only the first.
//
// The cycle passed firstRoot() to this adapter, so a second configured root was never
// looked at — the same "we checked one place and reported as if we had checked" in the
// layer above.
func TestEveryConfiguredRootIsSearched(t *testing.T) {
	home := t.TempDir()
	one := plantWordPress(t, filepath.Join(home, "a", "site"), "6.5.2")
	two := plantWordPress(t, filepath.Join(home, "b", "site"), "6.4.1")

	res := DetectAll([]string{filepath.Join(home, "a"), filepath.Join(home, "b")}, 0, 0, 0)

	got := rootsOf(res)
	want := []string{one, two}
	sort.Strings(want)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("found %v, wanted %v", got, want)
	}
}

// A search that hit a bound says so.
//
// The whole point of this adapter is that "found nothing" must never be the same
// statement as "stopped looking". A truncated search that reports like a complete one
// reproduces the defect it was written to fix, one level along.
func TestATruncatedSearchSaysWhatStoppedIt(t *testing.T) {
	home := t.TempDir()
	for _, n := range []string{"one", "two", "three"} {
		plantWordPress(t, filepath.Join(home, "public_html", n), "6.5.2")
	}

	res := DetectAll([]string{home}, 0, 2, 0)

	if len(res.Installs) != 2 {
		t.Fatalf("found %d, wanted the ceiling of 2", len(res.Installs))
	}
	if res.StoppedAt == "" {
		t.Fatal("the search hit its ceiling and reported nothing about it, which reads " +
			"exactly like an account that has two WordPress installations")
	}
}

// The depth the search reached is part of its answer.
//
// Beyond the limit we genuinely do not know, and cannot claim to. What we can do is state
// how far we looked, so "no WordPress" carries the qualifier that makes it checkable —
// which is why the adapter's reason names the depth.
func TestTheDepthLimitIsRealAndTheDefaultIsGenerousEnough(t *testing.T) {
	home := t.TempDir()
	deep := plantWordPress(t, filepath.Join(home, "a", "b", "c", "d"), "6.5.2")

	shallow := DetectAll([]string{home}, 2, 0, 0)
	if len(shallow.Installs) != 0 {
		t.Fatalf("depth 2 reached %v, which the test needs to be out of range", rootsOf(shallow))
	}
	if shallow.Depth != 2 {
		t.Errorf("Depth is %d; the answer has to carry how far it looked", shallow.Depth)
	}

	// public_html/<domain>/<subdir> is three, and this is four. The default has to clear
	// the layouts a hosting account actually uses.
	deepEnough := DetectAll([]string{home}, 0, 0, 0)
	if len(deepEnough.Installs) != 1 || deepEnough.Installs[0].Root != deep {
		t.Errorf("the default depth of %d found %v, wanted %q",
			DefaultSearchDepth, rootsOf(deepEnough), deep)
	}
}

// A subdomain inside the main site's directory is a separate site, not a copy.
//
// This is the normal cPanel layout: public_html/ is the main WordPress and every addon
// domain is public_html/<domain>/. The first draft of the search stopped descending as
// soon as it found an installation, which lost exactly this — and it is the common case,
// not an edge one.
func TestAnAddonDomainInsideTheMainSiteIsItsOwnInstallation(t *testing.T) {
	home := t.TempDir()
	main := plantWordPress(t, filepath.Join(home, "public_html"), "6.5.2")
	addon := plantWordPress(t, filepath.Join(home, "public_html", "loja.example.com"), "6.4.1")

	res := DetectAll([]string{home}, 0, 0, 0)

	got := rootsOf(res)
	want := []string{main, addon}
	sort.Strings(want)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("found %v, wanted both %v", got, want)
	}
}

// An unreadable root is a gap in coverage, not an absence of WordPress.
func TestAMissingRootIsReportedAsUnreadable(t *testing.T) {
	home := t.TempDir()
	plantWordPress(t, filepath.Join(home, "site"), "6.5.2")

	res := DetectAll([]string{home, filepath.Join(home, "does-not-exist")}, 0, 0, 0)

	if len(res.Installs) != 1 {
		t.Errorf("the readable root should still be searched: %v", rootsOf(res))
	}
	if len(res.Unreadable) != 1 {
		t.Errorf("Unreadable is %v; a root that cannot be opened has to be distinguishable "+
			"from one that simply has no WordPress in it", res.Unreadable)
	}
}

// The old question still gets the old answer: a root that IS a WordPress.
func TestARootThatIsItselfAWordPressStillWorks(t *testing.T) {
	home := plantWordPress(t, t.TempDir(), "6.5.2")

	res := DetectAll([]string{home}, 0, 0, 0)

	if len(res.Installs) != 1 || res.Installs[0].Root != home {
		t.Fatalf("found %v, wanted the root itself at %q", rootsOf(res), home)
	}
}

// Nothing anywhere is a legitimate answer, and it must be distinguishable from a failure.
func TestASiteThatIsNotWordPressFindsNothingAndSaysItLooked(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html", "laravel", "app"), 0o755); err != nil {
		t.Fatal(err)
	}

	res := DetectAll([]string{home}, 0, 0, 0)

	if len(res.Installs) != 0 {
		t.Fatalf("found %v in a site that is not WordPress", rootsOf(res))
	}
	if res.DirsWalked < 3 {
		t.Errorf("DirsWalked is %d; without evidence that directories were examined, "+
			"'no WordPress' cannot be told apart from 'the search never ran'", res.DirsWalked)
	}
	if res.StoppedAt != "" {
		t.Errorf("StoppedAt is %q, but nothing should have stopped this search", res.StoppedAt)
	}
}
