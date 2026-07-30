package schema_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

const validSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func validFinding() schema.Finding {
	return schema.Finding{
		SchemaVersion: schema.Version,
		ID:            "f_9f8a7b6c",
		Engine:        "php-malware-finder",
		EngineVersion: "0.9.2",
		Rule:          "ObfuscatedPhp",
		File: schema.FileRef{
			Path:      "/home/user/public_html/wp-content/uploads/cache.php",
			SizeBytes: 14382,
			SHA256:    validSHA,
			MTime:     time.Now(),
			Perms:     "0644",
		},
		Category:   schema.CategoryObfuscation,
		Severity:   schema.SeverityHigh,
		Confidence: schema.ConfidenceHeuristic,
		ScanID:     "s_20260723_0300",
		DetectedAt: time.Now(),
	}
}

func TestFindingValidateAcceptsCompleteFinding(t *testing.T) {
	if err := validFinding().Validate(); err != nil {
		t.Fatalf("a valid finding was rejected: %v", err)
	}
}

func TestFindingValidateRequiresSHA256(t *testing.T) {
	// sha256 is the deduplication key across engines. Without it, two engines
	// flagging the same file would become two verdicts with one vote each —
	// exactly the opposite of consensus.
	cases := map[string]string{
		"empty":       "",
		"short":       "e3b0c44298fc",
		"uppercase":   strings.ToUpper(validSHA),
		"non-hex":     strings.Repeat("z", 64),
		"with spaces": strings.Repeat("a", 63) + " ",
	}
	for name, sha := range cases {
		t.Run(name, func(t *testing.T) {
			f := validFinding()
			f.File.SHA256 = sha
			if err := f.Validate(); err == nil {
				t.Fatalf("sha256 %q should have been rejected", sha)
			}
		})
	}
}

func TestFindingValidateRejectsUnknownEnum(t *testing.T) {
	f := validFinding()
	f.Category = "made-up-category"
	err := f.Validate()
	if err == nil {
		t.Fatal("an unknown category should have been rejected")
	}
	if !strings.Contains(err.Error(), "other") {
		t.Errorf("the message should point the adapter author at other, got: %v", err)
	}
}

func TestFindingValidateCollectsEveryProblem(t *testing.T) {
	// A broken adapter needs to see the whole list at once.
	f := schema.Finding{SchemaVersion: schema.Version}
	err := f.Validate()
	if err == nil {
		t.Fatal("an empty finding should have been rejected")
	}
	var ve *schema.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error should be *ValidationError, got %T", err)
	}
	if len(ve.Problems) < 5 {
		t.Errorf("expected several collected problems, got %d: %v", len(ve.Problems), ve.Problems)
	}
}

func TestVulnerabilityFindingDoesNotRequireSHA256(t *testing.T) {
	// Vulnerability verdicts are consolidated per component, not per file
	// (schema section 3). Requiring sha256 would make feature 002 impossible.
	f := validFinding()
	f.Kind = schema.KindVulnerability
	f.File = schema.FileRef{}
	f.Category = schema.CategoryVulnerableComponent
	f.Component = &schema.Component{
		Type:             "wordpress-plugin",
		Slug:             "contact-form-7",
		InstalledVersion: "5.7.1",
		FixedIn:          "5.7.2",
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("a valid vulnerability finding was rejected: %v", err)
	}

	f.Component = nil
	if err := f.Validate(); err == nil {
		t.Fatal("kind=vulnerability without component should have been rejected")
	}
}

func TestEmptyKindMeansMalware(t *testing.T) {
	f := validFinding()
	f.Kind = ""
	if got := f.EffectiveKind(); got != schema.KindMalware {
		t.Errorf("empty kind should be malware, got %q", got)
	}
}

func TestNonCompletedStatusNeverCountsAsVote(t *testing.T) {
	// Principle VI: an engine failure is an abstention, never a "clean vote".
	for _, s := range []schema.ScanStatus{
		schema.StatusPartial, schema.StatusFailed,
		schema.StatusTimeout, schema.StatusKilled,
	} {
		if s.CountsAsVote() {
			t.Errorf("status %q must not count as a vote", s)
		}
		r := schema.ScanReport{Status: s}
		if !r.Abstains() {
			t.Errorf("a report with status %q should abstain", s)
		}
	}
	if !schema.StatusCompleted.CountsAsVote() {
		t.Error("completed should count as a vote")
	}
}

func TestFailedReportNeverProducesAVotingStatus(t *testing.T) {
	// Guard against a wrong call: even when asked for "completed", the failure
	// constructor has to return an abstention.
	r := schema.FailedReport("s_1", "amwscan", schema.StatusCompleted, errTest{}, time.Now())
	if r.Status.CountsAsVote() {
		t.Fatalf("FailedReport returned a status that counts as a vote: %q", r.Status)
	}
	if r.Error == "" {
		t.Error("FailedReport should fill in Error")
	}
	if err := r.Validate(); err != nil {
		t.Errorf("a failure report should be valid: %v", err)
	}
}

func TestScanReportRequiresAReasonOnFailure(t *testing.T) {
	r := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        "s_1",
		Engine:        "maldet",
		Status:        schema.StatusTimeout,
	}
	err := r.Validate()
	if err == nil {
		t.Fatal("a failure status with no error should have been rejected")
	}
	r.Error = "timed out after 300s"
	if err := r.Validate(); err != nil {
		t.Fatalf("a report with a reason should be valid: %v", err)
	}
}

func TestScanReportRejectsFindingFromAnotherEngine(t *testing.T) {
	f := validFinding()
	r := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        "s_1",
		Engine:        "amwscan",
		Status:        schema.StatusCompleted,
		Findings:      []schema.Finding{f}, // engine = php-malware-finder
	}
	if err := r.Validate(); err == nil {
		t.Fatal("a finding from a different engine than the report should have been rejected")
	}
}

func TestLevelRankAndAtLeast(t *testing.T) {
	if !schema.LevelConfirmed.AtLeast(schema.LevelLikely) {
		t.Error("confirmed should be >= likely")
	}
	if schema.LevelSuspicious.AtLeast(schema.LevelConfirmed) {
		t.Error("suspicious should not be >= confirmed")
	}
	if !schema.LevelClean.AtLeast(schema.LevelClean) {
		t.Error("clean should be >= clean")
	}
}

func TestVerdictActionableOnlyWhenConfirmed(t *testing.T) {
	// Automatic verdicts only at the confirmed level (Principle V).
	for _, l := range []schema.Level{schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		v := schema.Verdict{Level: l}
		if v.Actionable() {
			t.Errorf("level %q must not authorize automatic action", l)
		}
	}
	if !(schema.Verdict{Level: schema.LevelConfirmed}).Actionable() {
		t.Error("confirmed should be actionable")
	}
	// Official-checksum protection beats any level.
	v := schema.Verdict{Level: schema.LevelConfirmed, CleanReason: "official_checksum_match"}
	if v.Actionable() {
		t.Error("a verdict with clean_reason can never be actionable")
	}
}

func TestVerdictQuarantineRequiresAReference(t *testing.T) {
	// Without quarantine_ref the file is not restorable — that violates
	// Principle I.
	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     "v_1",
		FileSHA256:    validSHA,
		Level:         schema.LevelConfirmed,
		Score:         0.95,
		ActionTaken:   schema.ActionQuarantined,
	}
	if err := v.Validate(); err == nil {
		t.Fatal("quarantined without quarantine_ref should have been rejected")
	}
	v.QuarantineRef = "q_20260723_000132"
	if err := v.Validate(); err != nil {
		t.Fatalf("a complete verdict should be valid: %v", err)
	}
}

func TestVerdictRejectsScoreOutsideRange(t *testing.T) {
	for _, score := range []float64{-0.1, 1.5} {
		v := schema.Verdict{
			SchemaVersion: schema.Version,
			VerdictID:     "v_1",
			FileSHA256:    validSHA,
			Level:         schema.LevelLikely,
			Score:         score,
		}
		if err := v.Validate(); err == nil {
			t.Errorf("score %v should have been rejected", score)
		}
	}
}

func TestCompatibleVersion(t *testing.T) {
	ok := []string{"", "1.0", "1.4"}
	for _, v := range ok {
		if err := schema.CompatibleVersion(v); err != nil {
			t.Errorf("version %q should be accepted: %v", v, err)
		}
	}
	bad := []string{"2.0", "0.9", "abc"}
	for _, v := range bad {
		if err := schema.CompatibleVersion(v); err == nil {
			t.Errorf("version %q should be rejected", v)
		}
	}
}

func TestSanitizeSnippetTruncatesAndSanitizes(t *testing.T) {
	// The constitution forbids re-serving malicious content: the snippet is
	// truncated and stripped of control bytes before leaving the adapter.
	long := strings.Repeat("A", schema.MaxMatchedContentBytes*2)
	got := schema.SanitizeSnippet(long)
	if len(got) > schema.MaxMatchedContentBytes {
		t.Errorf("snippet was not truncated: %d bytes", len(got))
	}

	got = schema.SanitizeSnippet("line1\nline2\x00\x07end")
	if strings.ContainsAny(got, "\x00\x07\n") {
		t.Errorf("control bytes survived: %q", got)
	}
	if !strings.Contains(got, "line1") || !strings.Contains(got, "end") {
		t.Errorf("readable content was lost: %q", got)
	}
}

func TestSanitizeSnippetDoesNotBreakARune(t *testing.T) {
	// Truncating mid-multibyte-character would produce invalid garbage in the
	// report's JSON.
	// "ß" is two bytes in UTF-8, so the truncation lands mid-character.
	s := strings.Repeat("ß", schema.MaxMatchedContentBytes)
	got := schema.SanitizeSnippet(s)
	if !isValidUTF8(got) {
		t.Errorf("result is not valid UTF-8: %q", got)
	}
}

func TestJSONRoundTripPreservesFields(t *testing.T) {
	// The schema is the contract between adapter and verdict engine; it travels
	// as JSON (scan output, panel API, webhook payload).
	orig := validFinding()
	orig.MatchedContent = "sanitized snippet"
	orig.MatchedOffset = 1024

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back schema.Finding
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.File.SHA256 != orig.File.SHA256 || back.Rule != orig.Rule ||
		back.Category != orig.Category || back.MatchedOffset != orig.MatchedOffset {
		t.Errorf("round-trip lost fields:\nbefore: %+v\nafter: %+v", orig, back)
	}
}

// Helpers -------------------------------------------------------------------

type errTest struct{}

func (errTest) Error() string { return "engine died" }

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}
