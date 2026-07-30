package wpchecksums_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/wpchecksums"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// No test here touches the network: `fakeAPI` serves both the core checksums and
// the plugin ones. A test that hit the public WordPress.org API would fail in CI
// for reasons unrelated to the code — and would spend, for free, the
// infrastructure of a project that already serves us for free.

type fakeAPI struct {
	srv *httptest.Server
	// coreSums is the core's path->md5 map.
	coreSums map[string]string
	// pluginSums is slug/version -> path -> hashes.
	pluginSums map[string]map[string]map[string][]string
	// seen records which plugin URLs were requested.
	seen []string
}

func newAPI(t *testing.T) *fakeAPI {
	t.Helper()
	a := &fakeAPI{
		coreSums:   map[string]string{},
		pluginSums: map[string]map[string]map[string][]string{},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/core/checksums/1.0/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"checksums": a.coreSums})
	})

	mux.HandleFunc("/plugin-checksums/", func(w http.ResponseWriter, r *http.Request) {
		a.seen = append(a.seen, r.URL.Path)
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/plugin-checksums/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		slug := parts[0]
		version := strings.TrimSuffix(parts[1], ".json")

		files, ok := a.pluginSums[slug][version]
		if !ok {
			// 404 is the real answer for a plugin outside the official directory.
			http.NotFound(w, r)
			return
		}
		payload := map[string]any{}
		for path, hashes := range files {
			payload[path] = map[string]any{"sha256": hashes}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"plugin": slug, "version": version, "files": payload,
		})
	})

	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAPI) adapter() *wpchecksums.Adapter {
	return wpchecksums.NewWithBases(
		a.srv.URL+"/core/checksums/1.0/",
		a.srv.URL+"/plugin-checksums/",
	)
}

// site builds a minimal WordPress installation and registers the core in the fake
// API.
//
// Registering the core is mandatory: with an empty list the adapter treats the
// version as unknown and abstains — correct product behaviour, which would mask
// what these tests want to exercise (the plugins).
func site(t *testing.T, api *fakeAPI) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	versionFile := filepath.Join(root, "wp-includes", "version.php")
	write(t, versionFile, "<?php\n$wp_version = '6.5.2';\n")
	api.coreSums["wp-includes/version.php"] = md5Of(t, versionFile)
	return root
}

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return sha256Of(t, path)
}

func sha256Of(t *testing.T, path string) string {
	t.Helper()
	h, err := wpchecksums.HashFileSHA256(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return h
}

// plugin creates a plugin on disk and returns its directory.
func plugin(t *testing.T, root, slug, version string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, "wp-content", "plugins", slug)
	header := fmt.Sprintf("<?php\n/**\n * Plugin Name: Plugin %s\n * Version: %s\n */\n", slug, version)
	write(t, filepath.Join(dir, slug+".php"), header)
	for rel, content := range files {
		write(t, filepath.Join(dir, filepath.FromSlash(rel)), content)
	}
	return dir
}

func run(t *testing.T, a *wpchecksums.Adapter, root string) schema.ScanReport {
	t.Helper()
	req := adapter.ScanRequest{ScanID: "s_1", Root: root, Mode: schema.ModeFull}
	raw, err := a.Scan(context.Background(), adapter.Environment{}, req)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	rep, err := a.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("report violates the schema: %v", err)
	}
	return rep
}

func findRule(rep schema.ScanReport, rule string) []schema.Finding {
	var out []schema.Finding
	for _, f := range rep.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// Plugin detection -------------------------------------------------------------

func TestDetectPluginsReadsTheSlugFromTheDirectoryNotTheHeader(t *testing.T) {
	// The API indexes by DIRECTORY name. Using the "Plugin Name" would make every
	// query 404 and the plugin verifier would never find anything — failing
	// silently, which is the failure mode this project fears most.
	root := site(t, newAPI(t))
	plugin(t, root, "contact-form-7", "5.9.3", nil)

	ps, err := wpchecksums.DetectPlugins(root)
	if err != nil {
		t.Fatalf("DetectPlugins: %v", err)
	}
	if len(ps) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(ps))
	}
	if ps[0].Slug != "contact-form-7" {
		t.Errorf("slug: %q (should be the directory name)", ps[0].Slug)
	}
	if ps[0].Version != "5.9.3" {
		t.Errorf("version: %q", ps[0].Version)
	}
	if ps[0].Name != "Plugin contact-form-7" {
		t.Errorf("name: %q", ps[0].Name)
	}
}

func TestDetectPluginsIgnoresALooseFileAndDoesNotFollowSymlinks(t *testing.T) {
	root := site(t, newAPI(t))
	plugin(t, root, "good", "1.0", nil)
	// hello.php: a single-file plugin, with no published checksum.
	write(t, filepath.Join(root, "wp-content", "plugins", "hello.php"), "<?php\n")

	ps, err := wpchecksums.DetectPlugins(root)
	if err != nil {
		t.Fatalf("DetectPlugins: %v", err)
	}
	for _, p := range ps {
		if p.Slug == "hello.php" {
			t.Error("a single-file plugin should not enter the list")
		}
	}
}

func TestNoPluginsDirectoryIsNotAnError(t *testing.T) {
	// An installation with a custom content directory is a legitimate case.
	root := site(t, newAPI(t))
	ps, err := wpchecksums.DetectPlugins(root)
	if err != nil {
		t.Fatalf("the absence of wp-content/plugins should not be an error: %v", err)
	}
	if len(ps) != 0 {
		t.Errorf("expected an empty list, got %d", len(ps))
	}
}

// Verification -----------------------------------------------------------------

func TestAnIntactPluginBecomesACleanFileAndNotAFinding(t *testing.T) {
	// A legitimate plugin carries minified JS and base64 — exactly what produces
	// heuristic false positives. Without entering clean_files it does not get the
	// veto's protection and another engine could take the user's site down.
	api := newAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "my-plugin", "2.0", map[string]string{
		"inc/util.php": "<?php // legitimate\n",
	})

	api.pluginSums["my-plugin"] = map[string]map[string][]string{
		"2.0": {
			"my-plugin.php": {sha256Of(t, filepath.Join(dir, "my-plugin.php"))},
			"inc/util.php":  {sha256Of(t, filepath.Join(dir, "inc/util.php"))},
		},
	}

	rep := run(t, api.adapter(), root)

	if n := len(findRule(rep, "plugin_file_modified")); n != 0 {
		t.Errorf("an intact plugin produced %d alteration finding(s)", n)
	}
	expected := sha256Of(t, filepath.Join(dir, "inc/util.php"))
	found := false
	for _, h := range rep.CleanFiles {
		if h == expected {
			found = true
		}
	}
	if !found {
		t.Error("an intact plugin file should enter clean_files (the anti-false-positive veto)")
	}
}

func TestAnAlteredPluginFileIsASignatureFinding(t *testing.T) {
	api := newAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "my-plugin", "2.0", map[string]string{
		"inc/util.php": "<?php // TAMPERED WITH\n",
	})

	api.pluginSums["my-plugin"] = map[string]map[string][]string{
		"2.0": {
			"my-plugin.php": {sha256Of(t, filepath.Join(dir, "my-plugin.php"))},
			// the hash of content different from what is on disk
			"inc/util.php": {strings.Repeat("a", 64)},
		},
	}

	rep := run(t, api.adapter(), root)

	findings := findRule(rep, "plugin_file_modified")
	if len(findings) != 1 {
		t.Fatalf("expected 1 alteration finding, got %d", len(findings))
	}
	f := findings[0]
	// Divergence from the official checksum is PROOF, not suspicion: it is what
	// justifies this engine's weight of 1.5 in the consensus.
	if f.Confidence != schema.ConfidenceSignature {
		t.Errorf("confidence: %q, expected signature", f.Confidence)
	}
	if f.Severity != schema.SeverityCritical {
		t.Errorf("severity: %q", f.Severity)
	}
	if !strings.Contains(f.File.Path, "inc") {
		t.Errorf("finding path: %q", f.File.Path)
	}
}

func TestAnExtraFileInAPluginIsAFinding(t *testing.T) {
	// This verifier's most valuable finding: a backdoor inside a legitimate plugin
	// does not show up in the core check, and the user never suspects the plugin
	// they installed themselves.
	api := newAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "my-plugin", "2.0", map[string]string{
		"inc/backdoor.php": "<?php // does not belong to the plugin\n",
	})

	api.pluginSums["my-plugin"] = map[string]map[string][]string{
		"2.0": {"my-plugin.php": {sha256Of(t, filepath.Join(dir, "my-plugin.php"))}},
	}

	rep := run(t, api.adapter(), root)

	findings := findRule(rep, "plugin_file_unexpected")
	if len(findings) != 1 {
		t.Fatalf("expected 1 extra-file finding, got %d", len(findings))
	}
	if findings[0].Confidence != schema.ConfidenceSignature {
		t.Errorf("confidence: %q — an official plugin does not grow a .php on its own", findings[0].Confidence)
	}
}

func TestAMissingPluginFileIsAnAnomalyNotASignature(t *testing.T) {
	// Same reason as the core's: absence holds no malicious code and cannot be
	// quarantined. As `signature`, weight 1.5 would push the finding on its own
	// close to `confirmed`, authorizing action on a file that does not even exist.
	api := newAPI(t)
	root := site(t, api)
	// A plugin with several files present: 1 missing out of 5 stays under the 34%
	// ceiling that triggers the abstention. A two-file plugin would give 50% and the
	// adapter would abstain — correctly, but masking what is under test here.
	dir := plugin(t, root, "my-plugin", "2.0", map[string]string{
		"inc/a.php": "<?php // a\n",
		"inc/b.php": "<?php // b\n",
		"inc/c.php": "<?php // c\n",
	})

	api.pluginSums["my-plugin"] = map[string]map[string][]string{
		"2.0": {
			"my-plugin.php":    {sha256Of(t, filepath.Join(dir, "my-plugin.php"))},
			"inc/a.php":        {sha256Of(t, filepath.Join(dir, "inc/a.php"))},
			"inc/b.php":        {sha256Of(t, filepath.Join(dir, "inc/b.php"))},
			"inc/c.php":        {sha256Of(t, filepath.Join(dir, "inc/c.php"))},
			"inc/vanished.php": {strings.Repeat("b", 64)},
		},
	}

	rep := run(t, api.adapter(), root)

	findings := findRule(rep, "plugin_file_missing")
	if len(findings) != 1 {
		t.Fatalf("expected 1 missing-file finding, got %d", len(findings))
	}
	if findings[0].Confidence != schema.ConfidenceAnomaly {
		t.Errorf("confidence: %q, expected anomaly", findings[0].Confidence)
	}
	if findings[0].Severity == schema.SeverityCritical {
		t.Error("absence cannot be critical: you cannot hide a backdoor in a file that does not exist")
	}
}

// Abstentions ------------------------------------------------------------------

func TestAPluginWithNoPublishedChecksumAbstainsWithAReason(t *testing.T) {
	// A commercial or in-house plugin has no checksum. Treating absence of DATA as
	// absence of a PROBLEM would declare clean what nobody checked.
	api := newAPI(t)
	root := site(t, api)
	plugin(t, root, "commercial-plugin", "3.1", map[string]string{
		"inc/x.php": "<?php\n",
	})

	rep := run(t, api.adapter(), root)

	if len(rep.Findings) != 0 {
		t.Errorf("a plugin with no checksum should not produce findings: %d", len(rep.Findings))
	}
	// And most importantly: the report records that it was NOT verified.
	if rep.Scope.SkippedReasonCounts["plugin_without_checksum"] == 0 {
		t.Error("an unverified plugin has to appear in the report's accounting")
	}
}

func TestAPluginWithNoVersionInItsHeaderAbstains(t *testing.T) {
	api := newAPI(t)
	root := site(t, api)
	dir := filepath.Join(root, "wp-content", "plugins", "no-version")
	write(t, filepath.Join(dir, "no-version.php"), "<?php\n/**\n * Plugin Name: No Version\n */\n")

	rep := run(t, api.adapter(), root)

	if len(rep.Findings) != 0 {
		t.Errorf("a plugin with no version should not produce findings: %d", len(rep.Findings))
	}
	if rep.Scope.SkippedReasonCounts["plugin_without_checksum"] == 0 {
		t.Error("a plugin with no version has to show up as unverified")
	}
}

func TestTooManyMissingFilesAbstainsInsteadOfDrowningTheReport(t *testing.T) {
	// The same lesson as the core's 2998 findings, applied to a plugin: if most of
	// the files are missing, the directory is not the version the header declares,
	// and emitting one finding per file would bury what matters.
	api := newAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "my-plugin", "2.0", nil)

	files := map[string][]string{
		"my-plugin.php": {sha256Of(t, filepath.Join(dir, "my-plugin.php"))},
	}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("inc/f%02d.php", i)] = []string{strings.Repeat("c", 64)}
	}
	api.pluginSums["my-plugin"] = map[string]map[string][]string{"2.0": files}

	rep := run(t, api.adapter(), root)

	if n := len(findRule(rep, "plugin_file_missing")); n > 0 {
		t.Errorf("expected an abstention about the plugin, got %d missing-file finding(s)", n)
	}
	if rep.Scope.SkippedReasonCounts["plugin_without_checksum"] == 0 {
		t.Error("the abstention has to show up in the report with a reason")
	}
}

func TestAPluginFailureDoesNotTakeDownTheCoreVerification(t *testing.T) {
	// The core is the project's highest-weight signal. It must not be left
	// unverified because a third-party plugin has no published checksum.
	api := newAPI(t)
	root := site(t, api)
	plugin(t, root, "plugin-without-checksum", "1.0", nil)

	// Core with one tampered file.
	write(t, filepath.Join(root, "wp-includes", "pluggable.php"), "<?php // TAMPERED WITH\n")
	api.coreSums["wp-includes/pluggable.php"] = "md5-that-does-not-match"

	rep := run(t, api.adapter(), root)

	if n := len(findRule(rep, "core_file_modified")); n != 1 {
		t.Fatalf("the core should have been verified: %d finding(s)", n)
	}
	if rep.Abstains() {
		t.Error("a plugin failure must not make the whole engine abstain")
	}
}

func TestASlugWithPathTraversalDoesNotEscapeTheAPI(t *testing.T) {
	// The slug comes from a directory name on the user's disk. A directory called
	// `../something` must not be able to build a URL to somewhere else in the API.
	api := newAPI(t)
	root := site(t, api)
	dir := filepath.Join(root, "wp-content", "plugins", "..strange")
	write(t, filepath.Join(dir, "x.php"), "<?php\n/**\n * Plugin Name: X\n * Version: 1.0\n */\n")

	_ = run(t, api.adapter(), root)

	for _, u := range api.seen {
		if strings.Contains(u, "/../") {
			t.Errorf("the URL escaped the API prefix: %q", u)
		}
		if !strings.HasPrefix(u, "/plugin-checksums/") {
			t.Errorf("URL outside the expected prefix: %q", u)
		}
	}
}

func TestThePerCyclePluginLimitIsRecorded(t *testing.T) {
	// Truncating silently would make the report look complete. The user needs to
	// know that some of their plugins were not looked at in this cycle.
	api := newAPI(t)
	root := site(t, api)
	for i := 0; i < 45; i++ {
		plugin(t, root, fmt.Sprintf("plugin-%02d", i), "1.0", nil)
	}

	rep := run(t, api.adapter(), root)

	if rep.Scope.SkippedReasonCounts["plugin_without_checksum"] < 5 {
		t.Errorf("the plugins beyond the limit have to show up as unverified: %v",
			rep.Scope.SkippedReasonCounts)
	}
}

func TestHashVariantsAreAccepted(t *testing.T) {
	// The API publishes ARRAYS of hashes per file, because one path may have
	// accepted variants (CRLF and LF, for instance). Matching one is enough;
	// requiring the first would produce false positives on a legitimate site.
	api := newAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "my-plugin", "2.0", map[string]string{
		"inc/util.php": "<?php // legitimate\n",
	})

	real := sha256Of(t, filepath.Join(dir, "inc/util.php"))
	api.pluginSums["my-plugin"] = map[string]map[string][]string{
		"2.0": {
			"my-plugin.php": {sha256Of(t, filepath.Join(dir, "my-plugin.php"))},
			// the correct variant is the SECOND in the list
			"inc/util.php": {strings.Repeat("d", 64), real},
		},
	}

	rep := run(t, api.adapter(), root)

	if n := len(findRule(rep, "plugin_file_modified")); n != 0 {
		t.Errorf("the second hash variant should have been accepted: %d finding(s)", n)
	}
}

func TestOfflineModeQueriesNothingAboutPlugins(t *testing.T) {
	api := newAPI(t)
	root := site(t, api)
	plugin(t, root, "my-plugin", "2.0", nil)

	a := api.adapter()
	_, err := a.Scan(context.Background(),
		adapter.Environment{Offline: true},
		adapter.ScanRequest{ScanID: "s_1", Root: root, Mode: schema.ModeFull})
	if err == nil {
		t.Fatal("offline mode should have prevented the scan")
	}
	if len(api.seen) != 0 {
		t.Errorf("offline mode queried the API: %v", api.seen)
	}
}

func TestCancellationInterruptsThePluginVerification(t *testing.T) {
	api := newAPI(t)
	root := site(t, api)
	for i := 0; i < 5; i++ {
		plugin(t, root, fmt.Sprintf("p%02d", i), "1.0", nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := api.adapter()
	raw, err := a.Scan(ctx, adapter.Environment{},
		adapter.ScanRequest{ScanID: "s_1", Root: root, Mode: schema.ModeFull})
	// The core fails first (cancelled context), which is already the right
	// outcome: an abstention with a reason.
	if err == nil && raw.Status == schema.StatusCompleted {
		t.Error("a cancelled context should have interrupted the scan")
	}
}

func md5Of(t *testing.T, path string) string {
	t.Helper()
	h, err := wpchecksums.HashFileMD5(path)
	if err != nil {
		t.Fatalf("md5 %s: %v", path, err)
	}
	return h
}

// A plugin that WAS verified must not be reported as skipped.
//
// `SkippedReasonCounts` answers one question, and it is the question this whole project
// is organised around: what did the scan NOT look at? Putting a success into it inverts
// the meaning — a user reading `skipped: plugin_verified=1` concludes coverage was lost
// and goes hunting for a problem that does not exist.
//
// The damage runs the other way too, and that half is worse. `plugin_without_checksum`
// is a real gap: a plugin nobody verified, sitting in the same list, indistinguishable
// at a glance from a success. Diluting the skip list is how a genuine gap stops being
// noticed.
//
// Found on a real account, where every single cycle printed `skipped: plugin_verified=1`
// against a WordPress whose one plugin had just been checked against the official API
// and found intact.
func TestAVerifiedPluginIsNotCountedAsSkipped(t *testing.T) {
	api := newAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "akismet", "5.0", map[string]string{
		"inc/util.php": "<?php // legitimate\n",
	})
	api.pluginSums["akismet"] = map[string]map[string][]string{
		"5.0": {
			"akismet.php":  {sha256Of(t, filepath.Join(dir, "akismet.php"))},
			"inc/util.php": {sha256Of(t, filepath.Join(dir, "inc/util.php"))},
		},
	}

	rep := run(t, api.adapter(), root)

	if n, ok := rep.Scope.SkippedReasonCounts["plugin_verified"]; ok {
		t.Errorf("a verified plugin was reported as skipped (%d): the counter answers "+
			"\"what did the scan NOT look at?\", and this plugin was looked at", n)
	}
	// The coverage itself is not lost by dropping the counter — the plugin's files are
	// already in FilesScanned, which is where "what was examined" belongs.
	if rep.Scope.FilesScanned < 2 {
		t.Errorf("the plugin's files are missing from FilesScanned (%d): dropping the "+
			"counter must not drop the coverage with it", rep.Scope.FilesScanned)
	}
}

// The counter that must keep working, since it is the one that means something is
// genuinely uncovered.
func TestAnUnverifiedPluginIsStillCountedAsSkipped(t *testing.T) {
	api := newAPI(t)
	root := site(t, api)
	plugin(t, root, "no-checksums-published", "1.0", nil)
	// No entry in api.pluginSums: the API publishes nothing for this plugin.

	rep := run(t, api.adapter(), root)

	if rep.Scope.SkippedReasonCounts["plugin_without_checksum"] == 0 {
		t.Error("a plugin nobody could verify must be counted as skipped, loudly: " +
			"an unverified plugin that looks verified is the failure this project exists to prevent")
	}
}
