package contract_test

import (
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/adapter/amwscan"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// The real engine names the rule generically and puts the discriminator in parentheses.
//
// This fixture is a sanitised capture from a live hosting account, not a hand-written
// sample. It matters that it is captured: the fixture the adapter was built against shows
//
//	=> [!] Signature (d30fc49e) [line 4]
//	   - Malware Signature (hash: d30fc49e)
//	     => backdoor
//
// where that last line looks like a category — and the parser was written to read it as
// one, with priority over everything else. Against the real engine the same position holds
// the source that matched:
//
//	=> [!] Function (exec) [line 147]
//	   - Potentially dangerous function `exec`
//	     => exec('kill -' . (int) $signal . ' ' . (int) $pid . ' 2>/dev/null', $out, $code)
//
// So "Function" — which is not in the rule table and never will be — decided the answer,
// and `exec`, which IS in the table, was captured into a field used only for display. On
// the account this was taken from, that is 199 eval and 29 exec findings reported as
// generic medium heuristics.
func TestTheParenthesisedTokenClassifiesTheFinding(t *testing.T) {
	a := amwscan.New().WithStat(fakeStat)

	rep, err := a.Parse(raw(amwscan.Slug,
		fixture(t, "amwscan", "real-0.15.1-function-and-exploit.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("the report does not validate: %v", err)
	}

	want := map[string]struct {
		category schema.Category
		severity schema.Severity
	}{
		"exec":       {schema.CategoryWebshell, schema.SeverityCritical},
		"eval":       {schema.CategoryBackdoor, schema.SeverityCritical},
		"assert":     {schema.CategoryBackdoor, schema.SeverityHigh},
		"shell_exec": {schema.CategoryWebshell, schema.SeverityCritical},
	}

	seen := map[string]bool{}
	for _, f := range rep.Findings {
		for token, exp := range want {
			// The rule stays as the engine wrote it; the snippet carries the token.
			if !strings.Contains(strings.ToLower(f.MatchedContent), "("+token+")") {
				continue
			}
			seen[token] = true
			if f.Category != exp.category {
				t.Errorf("%s: category %q, wanted %q — the token in the parentheses is the "+
					"only thing that says what this finding is", token, f.Category, exp.category)
			}
			if f.Severity != exp.severity {
				t.Errorf("%s: severity %q, wanted %q", token, f.Severity, exp.severity)
			}
		}
	}
	for token := range want {
		if !seen[token] {
			t.Errorf("no finding carried the token %q; the fixture or the parser changed", token)
		}
	}
}

// A hash in the parentheses falls through to the rule name, which is the right answer.
//
// Signature (11413268) has no entry — hashes never will — so classification has to reach
// "signature" and report known malware. Trying the token first must not cost this.
func TestASignatureHashFallsThroughToTheRuleName(t *testing.T) {
	a := amwscan.New().WithStat(fakeStat)

	rep, _ := a.Parse(raw(amwscan.Slug,
		fixture(t, "amwscan", "real-0.15.1-function-and-exploit.txt"), schema.StatusCompleted))

	found := false
	for _, f := range rep.Findings {
		if f.Rule != "Signature" {
			continue
		}
		found = true
		if f.Category != schema.CategoryKnownMalware {
			t.Errorf("a Signature hit came out as %q, wanted known_malware: %s", f.Category, f.MatchedContent)
		}
		if f.Confidence != schema.ConfidenceSignature {
			t.Errorf("confidence %q, wanted signature — this is the one case where the "+
				"engine claims to recognise the threat, not a pattern", f.Confidence)
		}
	}
	if !found {
		t.Fatal("the fixture carries no Signature finding")
	}
}

// The matched source must never decide what a finding is.
//
// The engine detects strrev-obfuscated calls, and then the matched source reads `Lave` or
// `tressa` — eval and assert spelled backwards. Under the old parser those strings WERE
// the category, so an obfuscated backdoor classified as unknown while the plain word
// `eval` sat in the parentheses. Worse in principle than in practice: the string comes out
// of the scanned file, so its author chooses it.
func TestTheMatchedSourceIsEvidenceNotACategory(t *testing.T) {
	a := amwscan.New().WithStat(fakeStat)

	rep, _ := a.Parse(raw(amwscan.Slug,
		fixture(t, "amwscan", "real-0.15.1-function-and-exploit.txt"), schema.StatusCompleted))

	checked := 0
	for _, f := range rep.Findings {
		low := strings.ToLower(f.MatchedContent)
		if !strings.Contains(low, "lave") && !strings.Contains(low, "tressa") {
			continue
		}
		checked++
		if f.Category == schema.CategoryOther {
			t.Errorf("an obfuscated call classified as other: %s", f.MatchedContent)
		}
	}
	if checked == 0 {
		t.Fatal("the fixture lost its strrev-obfuscated findings, which are the point here")
	}
}
