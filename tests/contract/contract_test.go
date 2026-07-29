// Package contract_test verifies that each adapter understands what its engine
// says.
//
// What is under test here is the PARSER, never the detection. The fixtures under
// tests/testdata/raw/ are raw output in each engine's exact format; the test feeds
// Parse() with them and checks the normalized ScanReport.
//
// The distinction that matters most in these tests: "found nothing" and "could not
// look" are different things (Principle VI). A parser that confuses the two turns
// a dead engine into a certificate of health.
package contract_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/amwscan"
	"github.com/thiagoluga/SentinelHost/internal/adapter/pmf"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

const fakeSHA = "1111111111111111111111111111111111111111111111111111111111111111"

func fixture(t *testing.T, engine, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "testdata", "raw", engine, name)
	b, err := os.ReadFile(path) // fixed fixture path
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return b
}

// fakeStat answers for any path, so the test exercises the parser without having
// to materialize a real server's tree on disk (D-009).
func fakeStat(path string) (amwscan.FileStat, bool) {
	return amwscan.FileStat{
		SHA256: fakeSHA, Size: 1024, Perms: "0644", MTime: time.Unix(1785000000, 0),
	}, true
}

func fakeStatPMF(path string) (pmf.FileStat, bool) {
	return pmf.FileStat{
		SHA256: fakeSHA, Size: 1024, Perms: "0644", MTime: time.Unix(1785000000, 0),
	}, true
}

func raw(engine string, stdout []byte, status schema.ScanStatus) adapter.RawOutput {
	return adapter.RawOutput{
		Engine: engine, ScanID: "s_test", Root: "/home/user/public_html",
		Mode: schema.ModeIncremental, Stdout: stdout, Status: status,
		StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(),
		PathsRequested: 412,
	}
}

// AMWScan ---------------------------------------------------------------------

func TestAMWScanParsesFindings(t *testing.T) {
	a := amwscan.New().WithStat(fakeStat)

	rep, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("the report does not satisfy the schema: %v", err)
	}
	if rep.Abstains() {
		t.Fatalf("a success report should not abstain: %q", rep.Status)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(rep.Findings))
	}

	// The report's hierarchy: each finding has to end up with the file of the
	// `File:` block it belongs to. Treating the lines in isolation would produce
	// findings with no file, or all of them on the wrong file.
	expected := map[string]string{
		"Signature":            "/home/user/public_html/wp-content/uploads/2026/07/x.php",
		"Eval":                 "/home/user/public_html/wp-content/plugins/cache-helper/init.php",
		"RuleThatIsNotInTable": "/home/user/public_html/wp-content/themes/theme/inc/loader.php",
	}
	for _, f := range rep.Findings {
		path, ok := expected[f.Rule]
		if !ok {
			t.Errorf("unexpected rule: %q", f.Rule)
			continue
		}
		if f.File.Path != path {
			t.Errorf("%s: file %q, expected %q", f.Rule, f.File.Path, path)
		}
		if f.File.SHA256 != fakeSHA {
			t.Errorf("%s: the orchestrator should have computed the sha256", f.Rule)
		}
	}
}

func TestAMWScanTheTagBeatsTheRuleName(t *testing.T) {
	// The line "      => backdoor" is more specific than the rule name:
	// "Signature" alone does not say which family the finding belongs to.
	a := amwscan.New().WithStat(fakeStat)
	rep, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, f := range rep.Findings {
		if f.Rule == "Signature" && f.Category != schema.CategoryBackdoor {
			t.Errorf("the `backdoor` tag should have set the category, got %q", f.Category)
		}
	}
}

func TestAMWScanTheFindingsLineIsPreserved(t *testing.T) {
	a := amwscan.New().WithStat(fakeStat)
	rep, _ := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "success-with-findings.txt"), schema.StatusCompleted))
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "Signature" {
			found = true
			if f.MatchedOffset != 4 {
				t.Errorf("finding line: %d, expected 4", f.MatchedOffset)
			}
		}
	}
	if !found {
		t.Error("the Signature finding did not show up")
	}
}

func TestAMWScanNoFindingsIsNotAnAbstention(t *testing.T) {
	// AMWScan always writes at least the `Scan date:` line. A report with only the
	// header means a clean site, not a failure.
	a := amwscan.New().WithStat(fakeStat)

	rep, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "success-no-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Abstains() {
		t.Fatal("zero findings must not become an abstention")
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected an empty list, got %d", len(rep.Findings))
	}
}

func TestAMWScanAnEmptyReportBecomesAnAbstention(t *testing.T) {
	// Empty means the engine never got to writing the header — an abstention,
	// never "found nothing".
	a := amwscan.New().WithStat(fakeStat)

	_, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "empty-output.txt"), schema.StatusCompleted))
	if err == nil {
		t.Fatal("an empty report should have been refused by the parser")
	}
}

func TestAMWScanAnOffFormatReportBecomesAnAbstention(t *testing.T) {
	a := amwscan.New().WithStat(fakeStat)

	_, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "corrupted-output.txt"), schema.StatusCompleted))
	if err == nil {
		t.Fatal("an off-format report should have been refused")
	}
}

func TestAMWScanAnUnknownRuleIsNotDiscarded(t *testing.T) {
	// Obligation 4 of the contract. The table covers only the rules seen in a real
	// run; discarding the rest would make findings vanish with every new engine
	// version.
	a := amwscan.New().WithStat(fakeStat)

	rep, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Rule == "RuleThatIsNotInTable" {
			found = true
			if f.Category != schema.CategoryOther {
				t.Errorf("category: %q, expected other", f.Category)
			}
		}
	}
	if !found {
		t.Fatal("the unknown-rule finding was discarded")
	}
	if rep.Scope.SkippedReasonCounts["unknown_rule"] == 0 {
		t.Errorf("the unknown rule should be counted: %v", rep.Scope.SkippedReasonCounts)
	}
}

func TestAMWScanAVanishedFileDoesNotBecomeAFindingWithNoHash(t *testing.T) {
	a := amwscan.New().WithStat(func(string) (amwscan.FileStat, bool) {
		return amwscan.FileStat{}, false
	})

	rep, err := a.Parse(raw(amwscan.Slug, fixture(t, "amwscan", "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("a finding with no hash should not enter: %+v", rep.Findings)
	}
	if rep.Scope.SkippedReasonCounts["vanished_before_hashing"] != 3 {
		t.Errorf("the vanished files should be counted: %v", rep.Scope.SkippedReasonCounts)
	}
}

// php-malware-finder -----------------------------------------------------------

func TestPMFParsesTheRuleAndStringHierarchy(t *testing.T) {
	// yara's format is hierarchical: "RULE PATH" and, below it, the strings that
	// matched. Treating each line in isolation would produce findings with no file.
	a := pmf.New().WithStat(fakeStatPMF)

	rep, err := a.Parse(raw(pmf.Slug, fixture(t, "php-malware-finder", "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("the report does not satisfy the schema: %v", err)
	}
	if len(rep.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(rep.Findings))
	}

	byRule := map[string]schema.Finding{}
	for _, f := range rep.Findings {
		byRule[f.Rule] = f
		if f.File.Path == "" {
			t.Errorf("the finding for rule %q ended up with no file", f.Rule)
		}
	}

	// The matched strings become the matched_content of the finding they belong to.
	if got := byRule["ObfuscatedPhp"]; got.MatchedContent == "" {
		t.Error("the matched strings did not become matched_content")
	}
	if got := byRule["ObfuscatedPhp"]; got.Category != schema.CategoryObfuscation {
		t.Errorf("ObfuscatedPhp: category %q", got.Category)
	}
	if got := byRule["SuspiciousEncoding"]; got.Confidence != schema.ConfidenceSignature {
		t.Errorf("SuspiciousEncoding should be a signature, got %q", got.Confidence)
	}
	// A rule with no strings (a lone line) also becomes a finding.
	if _, ok := byRule["PhpInUploads"]; !ok {
		t.Error("a rule with no matched strings should become a finding all the same")
	}
	if got := byRule["PhpInUploads"]; got.Confidence != schema.ConfidenceAnomaly {
		t.Errorf("PhpInUploads should be an anomaly, got %q", got.Confidence)
	}
	// A rule outside the table is not discarded.
	if got, ok := byRule["UnknownRuleThatIsNotInTable"]; !ok {
		t.Error("the unknown rule was discarded")
	} else if got.Category != schema.CategoryOther {
		t.Errorf("unknown rule: category %q, expected other", got.Category)
	}
}

func TestPMFTheOffsetComesFromTheFirstString(t *testing.T) {
	a := pmf.New().WithStat(fakeStatPMF)
	input := []byte("ObfuscatedPhp /site/x.php\n0x1f2:$blob: AAAA\n0x300:$other: BBBB\n")

	rep, err := a.Parse(raw(pmf.Slug, input, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Findings[0].MatchedOffset != 0x1f2 {
		t.Errorf("offset: %#x, expected 0x1f2", rep.Findings[0].MatchedOffset)
	}
}

// TestPMFEmptyMeansOppositeThings is this package's central test.
func TestPMFEmptyMeansOppositeThings(t *testing.T) {
	// When yara runs and finds nothing, stdout is empty.
	// When yara dies before writing, stdout is empty too.
	// The raw output is the SAME; the meaning is the opposite. The difference comes
	// from the process's status, and a parser that only looks at the content has no
	// way of getting both right.
	a := pmf.New().WithStat(fakeStatPMF)
	empty := fixture(t, "php-malware-finder", "empty-output.txt")

	// Case 1: the engine completed. The site is clean.
	rep, err := a.Parse(raw(pmf.Slug, empty, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse (completed): %v", err)
	}
	if rep.Abstains() {
		t.Fatal("a yara that ran and found nothing must NOT become an abstention")
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(rep.Findings))
	}

	// Case 2: the engine died. The orchestrator's SafeScanAndParse is what turns
	// that into an abstention, before Parse is ever called.
	dead := raw(pmf.Slug, empty, schema.StatusFailed)
	dead.Err = testErr{}
	sr := adapter.SafeScanAndParse(t.Context(), deadAdapter{raw: dead}, adapter.Environment{},
		adapter.ScanRequest{ScanID: "s_test", Root: "/site", Mode: schema.ModeIncremental})
	if !sr.Abstains() {
		t.Fatal("a yara that died MUST become an abstention")
	}
}

func TestPMFIgnoresAStringLineWithNoPrecedingRule(t *testing.T) {
	// Truncated output may start mid-way. Creating a finding with no file would be
	// worse than ignoring it.
	a := pmf.New().WithStat(fakeStatPMF)
	input := []byte("0x1f2:$blob: AAAA\nObfuscatedPhp /site/x.php\n")

	rep, err := a.Parse(raw(pmf.Slug, input, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
	if rep.Findings[0].File.Path != "/site/x.php" {
		t.Errorf("path: %q", rep.Findings[0].File.Path)
	}
}

func TestPMFAPathWithASpaceDoesNotBreak(t *testing.T) {
	// yara escapes nothing. A rule name never contains a space, so the cut is at
	// the first space and the rest of the line is the whole path.
	a := pmf.New().WithStat(fakeStatPMF)
	input := []byte("ObfuscatedPhp /site/folder with space/strange file.php\n")

	rep, err := a.Parse(raw(pmf.Slug, input, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
	if rep.Findings[0].File.Path != "/site/folder with space/strange file.php" {
		t.Errorf("the path was truncated at the space: %q", rep.Findings[0].File.Path)
	}
}

// Helpers ----------------------------------------------------------------------

type testErr struct{}

func (testErr) Error() string { return "the engine died" }

// deadAdapter returns raw output with a failure status.
type deadAdapter struct{ raw adapter.RawOutput }

func (a deadAdapter) Info() adapter.Info {
	return adapter.Info{Slug: pmf.Slug, Kind: schema.KindMalware}
}
func (a deadAdapter) Probe(_ context.Context, _ adapter.Environment) adapter.ProbeResult {
	return adapter.ProbeResult{Available: true}
}
func (a deadAdapter) Install(_ context.Context, _ adapter.Environment) error { return nil }
func (a deadAdapter) UpdateSignatures(_ context.Context, _ adapter.Environment) (time.Time, error) {
	return time.Time{}, nil
}
func (a deadAdapter) Scan(_ context.Context, _ adapter.Environment, _ adapter.ScanRequest) (adapter.RawOutput, error) {
	return a.raw, nil
}
func (a deadAdapter) Parse(adapter.RawOutput) (schema.ScanReport, error) {
	return schema.ScanReport{}, nil
}
