package adapter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// fake is a controllable adapter used to exercise the shielding.
type fake struct {
	slug        string
	panicOn     string
	scanErr     error
	scanStatus  schema.ScanStatus
	parseErr    error
	report      schema.ScanReport
	probeResult adapter.ProbeResult
}

func (f *fake) Info() adapter.Info {
	if f.panicOn == "info" {
		panic("boom in Info")
	}
	return adapter.Info{Slug: f.slug, Kind: schema.KindMalware, DefaultWeight: 0.8, ScopeAware: true}
}

func (f *fake) Probe(context.Context, adapter.Environment) adapter.ProbeResult {
	if f.panicOn == "probe" {
		panic("boom in Probe")
	}
	return f.probeResult
}

func (f *fake) Install(context.Context, adapter.Environment) error {
	if f.panicOn == "install" {
		panic("boom in Install")
	}
	return adapter.ErrNotInstallable
}

func (f *fake) UpdateSignatures(context.Context, adapter.Environment) (time.Time, error) {
	if f.panicOn == "update" {
		panic("boom in UpdateSignatures")
	}
	return time.Now(), nil
}

func (f *fake) Scan(context.Context, adapter.Environment, adapter.ScanRequest) (adapter.RawOutput, error) {
	if f.panicOn == "scan" {
		panic("boom in Scan")
	}
	return adapter.RawOutput{Engine: f.slug, Status: f.scanStatus}, f.scanErr
}

func (f *fake) Parse(adapter.RawOutput) (schema.ScanReport, error) {
	if f.panicOn == "parse" {
		panic("boom in Parse")
	}
	return f.report, f.parseErr
}

func req() adapter.ScanRequest {
	return adapter.ScanRequest{
		ScanID: "s_1", Root: "/home/user/public_html",
		Mode: schema.ModeIncremental, Paths: []string{"/home/user/public_html/x.php"},
	}
}

func TestPanicInScanBecomesAnAbstention(t *testing.T) {
	// A third-party adapter with an off-by-one bug must not take down protection
	// for the whole site (obligation 5 of the contract).
	a := &fake{slug: "broken", panicOn: "scan"}

	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())

	if !rep.Abstains() {
		t.Fatalf("a panic should become an abstention, got status %q", rep.Status)
	}
	if rep.Engine != "broken" {
		t.Errorf("the guilty engine should be named in the report, got %q", rep.Engine)
	}
	if !strings.Contains(rep.Error, "panic") {
		t.Errorf("the report should say a panic happened, got: %q", rep.Error)
	}
	if len(rep.Findings) != 0 {
		t.Error("a failure report must not carry findings")
	}
}

func TestPanicInParseBecomesAnAbstention(t *testing.T) {
	a := &fake{slug: "broken", panicOn: "parse", scanStatus: schema.StatusCompleted}
	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())
	if !rep.Abstains() {
		t.Fatalf("a panic in Parse should become an abstention, got %q", rep.Status)
	}
}

func TestScanErrorBecomesAnAbstention(t *testing.T) {
	a := &fake{slug: "eng", scanErr: errors.New("engine died")}
	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())
	if !rep.Abstains() {
		t.Fatalf("a scan error should become an abstention, got %q", rep.Status)
	}
	if !strings.Contains(rep.Error, "engine died") {
		t.Errorf("the real reason was lost: %q", rep.Error)
	}
}

func TestAFailureStatusFromTheExecutorBecomesAnAbstention(t *testing.T) {
	// The executor has already translated timeout/kill into the schema's
	// vocabulary; a Scan returning a nil error but a timeout status is still a
	// failure.
	a := &fake{slug: "eng", scanStatus: schema.StatusTimeout}
	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())
	if !rep.Abstains() {
		t.Fatalf("a timeout status should become an abstention, got %q", rep.Status)
	}
	if rep.Status != schema.StatusTimeout {
		t.Errorf("the original status should be preserved, got %q", rep.Status)
	}
}

func TestAnInvalidReportBecomesAnAbstention(t *testing.T) {
	// An invalid report is worse than none: it would enter the consensus with
	// data the rest of the system cannot interpret.
	a := &fake{
		slug:       "eng",
		scanStatus: schema.StatusCompleted,
		report: schema.ScanReport{
			Status: schema.StatusCompleted,
			Findings: []schema.Finding{{
				Engine: "eng", Rule: "rule",
				File:       schema.FileRef{Path: "/x.php", SHA256: "invalid-hash"},
				Category:   schema.CategoryWebshell,
				Severity:   schema.SeverityHigh,
				Confidence: schema.ConfidenceSignature,
				DetectedAt: time.Now(),
			}},
		},
	}

	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())

	if !rep.Abstains() {
		t.Fatalf("an invalid report should become an abstention, got %q", rep.Status)
	}
	if !strings.Contains(rep.Error, "schema") {
		t.Errorf("the reason should mention the schema, got: %q", rep.Error)
	}
}

func TestAValidReportPassesAndGetsMissingFieldsFilledIn(t *testing.T) {
	a := &fake{
		slug:       "eng",
		scanStatus: schema.StatusCompleted,
		report: schema.ScanReport{
			Status: schema.StatusCompleted,
			Findings: []schema.Finding{{
				Engine: "eng", Rule: "generic_webshell",
				File:       schema.FileRef{Path: "/x.php", SHA256: sha},
				Category:   schema.CategoryWebshell,
				Severity:   schema.SeverityCritical,
				Confidence: schema.ConfidenceSignature,
				DetectedAt: time.Now(),
			}},
		},
	}

	rep := adapter.SafeScanAndParse(context.Background(), a, adapter.Environment{}, req())

	if rep.Abstains() {
		t.Fatalf("a valid report should not abstain: %q / %q", rep.Status, rep.Error)
	}
	// The orchestrator fills in what the adapter forgot, so a simple adapter does
	// not have to repeat metadata it was already handed.
	if rep.ScanID != "s_1" {
		t.Errorf("scan_id was not filled in: %q", rep.ScanID)
	}
	if rep.SchemaVersion != schema.Version {
		t.Errorf("schema_version was not filled in: %q", rep.SchemaVersion)
	}
	if rep.Scope.Root != "/home/user/public_html" {
		t.Errorf("root was not filled in: %q", rep.Scope.Root)
	}
	if rep.Scope.Mode != schema.ModeIncremental {
		t.Errorf("mode was not filled in: %q", rep.Scope.Mode)
	}
	if len(rep.Findings) != 1 {
		t.Errorf("finding lost: %d", len(rep.Findings))
	}
}

func TestSafeProbeSurvivesAPanic(t *testing.T) {
	a := &fake{slug: "broken", panicOn: "probe"}
	res := adapter.SafeProbe(context.Background(), a, adapter.Environment{})
	if res.Available {
		t.Fatal("an adapter that panics must not be reported as available")
	}
	if !strings.Contains(res.Reason, "panic") {
		t.Errorf("the reason should mention the panic, got: %q", res.Reason)
	}
}

func TestAnUnavailableProbeWithNoReasonGetsOne(t *testing.T) {
	// FR-001: the user has to see WHY the engine is unavailable.
	a := &fake{slug: "silent", probeResult: adapter.ProbeResult{Available: false}}
	res := adapter.SafeProbe(context.Background(), a, adapter.Environment{})
	if res.Reason == "" {
		t.Fatal("an unavailability with no reason should have been given a generic one")
	}
}

func TestSafeInstallAndSafeUpdateSurviveAPanic(t *testing.T) {
	a := &fake{slug: "broken", panicOn: "install"}
	if err := adapter.SafeInstall(context.Background(), a, adapter.Environment{}); err == nil {
		t.Error("a panic in Install should become an error")
	}

	b := &fake{slug: "broken", panicOn: "update"}
	if _, err := adapter.SafeUpdateSignatures(context.Background(), b, adapter.Environment{}); err == nil {
		t.Error("a panic in UpdateSignatures should become an error")
	}
}

// Registry -------------------------------------------------------------------

func TestRegistryRejectsADuplicateSlug(t *testing.T) {
	// Two adapters with the same slug would vote twice on the same verdict.
	r := adapter.NewRegistry()
	if err := r.Register(&fake{slug: "amwscan"}); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if err := r.Register(&fake{slug: "amwscan"}); err == nil {
		t.Fatal("a duplicate slug should have been rejected")
	}
}

func TestRegistryRejectsAnEmptySlug(t *testing.T) {
	r := adapter.NewRegistry()
	if err := r.Register(&fake{slug: ""}); err == nil {
		t.Fatal("an empty slug should have been rejected")
	}
}

func TestRegistryHasAStableOrder(t *testing.T) {
	// Comparing two cycles' reports must not become an exercise in patience
	// because of random map ordering.
	r := adapter.NewRegistry()
	for _, s := range []string{"maldet", "amwscan", "wp-checksums", "php-malware-finder"} {
		if err := r.Register(&fake{slug: s}); err != nil {
			t.Fatalf("Register(%s): %v", s, err)
		}
	}

	first := r.Slugs()
	for i := 0; i < 20; i++ {
		if got := r.Slugs(); !equal(got, first) {
			t.Fatalf("unstable order: %v vs %v", got, first)
		}
	}
	expected := []string{"amwscan", "maldet", "php-malware-finder", "wp-checksums"}
	if !equal(first, expected) {
		t.Errorf("expected alphabetical order %v, got %v", expected, first)
	}
}

func TestRegistryGet(t *testing.T) {
	r := adapter.NewRegistry()
	_ = r.Register(&fake{slug: "amwscan"})

	if _, ok := r.Get("amwscan"); !ok {
		t.Error("a registered adapter was not found")
	}
	if _, ok := r.Get("nonexistent"); ok {
		t.Error("a non-existent adapter was found")
	}
	if r.Len() != 1 {
		t.Errorf("Len: %d", r.Len())
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
