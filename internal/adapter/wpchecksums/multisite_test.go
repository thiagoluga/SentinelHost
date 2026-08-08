package wpchecksums_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/wpchecksums"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// siteAt builds a WordPress at an exact path, rather than at a fresh temp directory, so
// several of them can share one account's home the way a real account's do.
func siteAt(t *testing.T, api *fakeAPI, dir string) string {
	t.Helper()
	versionFile := filepath.Join(dir, "wp-includes", "version.php")
	write(t, versionFile, "<?php\n$wp_version = '6.5.2';\n")
	api.coreSums["wp-includes/version.php"] = md5Of(t, versionFile)
	return dir
}

// tamper rewrites a core file so it no longer matches the published checksum.
func tamper(t *testing.T, dir string) {
	t.Helper()
	write(t, filepath.Join(dir, "wp-includes", "version.php"),
		"<?php\n$wp_version = '6.5.2';\n/* eval($_POST[0]); */\n")
}

func scanRoots(t *testing.T, a *wpchecksums.Adapter, roots []string) (schema.ScanReport, error) {
	t.Helper()
	req := adapter.ScanRequest{ScanID: "s_1", Root: roots[0], Mode: schema.ModeFull}
	raw, err := a.Scan(context.Background(), adapter.Environment{Roots: roots}, req)
	if err != nil {
		return schema.ScanReport{}, err
	}
	return a.Parse(raw)
}

// The report covers every site on the account, not the first one found.
//
// One WordPress per addon domain is the ordinary shape of shared hosting. Reporting on one
// of them while looking like the account had been covered is the exact failure this
// project is built around, and it is what the adapter did: it asked whether the configured
// root ITSELF was a WordPress and abstained for everything else.
func TestEverySiteOnTheAccountIsScanned(t *testing.T) {
	api := newAPI(t)
	home := t.TempDir()
	main := siteAt(t, api, filepath.Join(home, "public_html"))
	addon := siteAt(t, api, filepath.Join(home, "public_html", "loja.example.com"))
	tamper(t, main)
	tamper(t, addon)

	rep, err := scanRoots(t, api.adapter(), []string{home})
	if err != nil {
		t.Fatalf("scanning: %v", err)
	}

	seen := map[string]bool{}
	for _, f := range rep.Findings {
		seen[filepath.Dir(filepath.Dir(f.File.Path))] = true
	}
	if !seen[main] {
		t.Errorf("nothing was reported for the main site at %s", main)
	}
	if !seen[addon] {
		t.Errorf("nothing was reported for the addon domain at %s — an account with two "+
			"sites got a report about one, and nothing said so", addon)
	}
}

// A site that cannot be verified is counted, and does not silence the others.
//
// Here the second site is missing a core file the API publishes, which trips the guard
// against comparing against an incomplete core. That is one site's problem. Before this
// change the guard returned an error from Parse and discarded the whole report — so one
// broken directory could take an entire account's coverage with it, silently.
func TestASiteThatCannotBeVerifiedIsCountedAndTheOthersSurvive(t *testing.T) {
	api := newAPI(t)
	home := t.TempDir()
	good := siteAt(t, api, filepath.Join(home, "public_html"))
	broken := siteAt(t, api, filepath.Join(home, "public_html", "quebrado"))

	// A second published core file, present only in the good site. The broken one is
	// then missing half its core, well past the 10% ceiling.
	extra := filepath.Join(good, "wp-admin", "index.php")
	write(t, extra, "<?php\n// wp-admin\n")
	api.coreSums["wp-admin/index.php"] = md5Of(t, extra)
	tamper(t, good)

	rep, err := scanRoots(t, api.adapter(), []string{home})
	if err != nil {
		t.Fatalf("one unverifiable site took the whole report down: %v", err)
	}

	if len(rep.Findings) == 0 {
		t.Error("the site that COULD be verified produced no findings")
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.File.Path, broken) {
			t.Errorf("a finding was reported for the site that could not be verified: %s",
				f.File.Path)
		}
	}
	if n := rep.Scope.SkippedReasonCounts["wordpress_not_verified"]; n != 1 {
		t.Errorf("skipped wordpress_not_verified is %d (all skips: %v), wanted 1. A site "+
			"nobody checked has to appear in the accounting, or the report reads as full "+
			"coverage", n, rep.Scope.SkippedReasonCounts)
	}
}

// When nothing could be verified, the engine abstains rather than reporting a clean run.
//
// This is the line the whole project is drawn on: an engine that could not run has not
// found zero threats. A report of `completed` with no findings, after failing to compare
// anything, is the single worst output this adapter could produce.
func TestWhenNoSiteCanBeVerifiedTheEngineAbstains(t *testing.T) {
	api := newAPI(t)
	home := t.TempDir()
	siteAt(t, api, filepath.Join(home, "public_html"))

	// Publish core files that exist nowhere, so the one site is almost entirely absent.
	for _, rel := range []string{"wp-admin/a.php", "wp-admin/b.php", "wp-admin/c.php"} {
		api.coreSums[rel] = "00000000000000000000000000000000"
	}

	rep, err := scanRoots(t, api.adapter(), []string{home})
	if err == nil {
		t.Fatalf("the engine reported %s with %d finding(s) after verifying nothing",
			rep.Status, len(rep.Findings))
	}
	if !strings.Contains(err.Error(), "could be verified") {
		t.Errorf("the refusal reads %q; it has to say that nothing was verified", err)
	}
}

// The probe finds a site below the root, and says where it looked when it does not.
func TestTheProbeSearchesBelowTheRoot(t *testing.T) {
	api := newAPI(t)
	home := t.TempDir()
	siteAt(t, api, filepath.Join(home, "public_html", "example.com"))

	res := api.adapter().Probe(context.Background(), adapter.Environment{Roots: []string{home}})
	if !res.Available {
		t.Fatalf("the engine abstained for an account that has a WordPress: %s", res.Reason)
	}

	// And an account with none gets an answer that can be checked.
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}
	none := api.adapter().Probe(context.Background(), adapter.Environment{Roots: []string{empty}})
	if none.Available {
		t.Fatal("a directory with no WordPress was reported as available")
	}
	for _, want := range []string{empty, "depth", "directories examined"} {
		if !strings.Contains(none.Reason, want) {
			t.Errorf("the reason %q does not mention %q — without where and how far it "+
				"looked, 'not WordPress' cannot be told from 'never looked'", none.Reason, want)
		}
	}
}

// An explicit path in the configuration still wins over the search.
func TestAConfiguredPathOverridesTheSearch(t *testing.T) {
	api := newAPI(t)
	home := t.TempDir()
	wanted := siteAt(t, api, filepath.Join(home, "public_html", "a"))
	siteAt(t, api, filepath.Join(home, "public_html", "b"))

	res := api.adapter().Probe(context.Background(), adapter.Environment{
		BinaryPath: wanted,
		Roots:      []string{home},
	})
	if !res.Available {
		t.Fatalf("abstained: %s", res.Reason)
	}
	if res.BinaryPath != wanted {
		t.Errorf("resolved to %q; a path the user configured has to beat anything a "+
			"search finds", res.BinaryPath)
	}
}
