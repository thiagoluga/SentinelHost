package amwscan

import (
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Obfuscation is a reason to look, not a reason to act.
//
// Every entry in that family says the technique is USUALLY used for malicious code, and
// usually is the operative word — minified libraries, licence blobs and legitimate
// encoders trip the same patterns. They sit at medium, matching the existing `encoded`
// entry, because a heuristic that fires on ordinary vendor code at high severity is one
// whose severity stops meaning anything.
func TestTheObfuscationFamilyStaysAtMedium(t *testing.T) {
	for _, token := range []string{
		"base64_long", "hex_char", "double_var2",
		"concat_vars_array", "concat_vars_with_spaces",
	} {
		m, known := classify("Exploit", token)
		if !known {
			t.Errorf("%s is not in the table", token)
			continue
		}
		if m.category != schema.CategoryObfuscation {
			t.Errorf("%s: category %q, wanted obfuscation", token, m.category)
		}
		if m.severity != schema.SeverityMedium {
			t.Errorf("%s: severity %q, wanted medium — obfuscation alone is not a reason "+
				"to act, and inflating it costs the severity field its meaning", token, m.severity)
		}
	}
}

// The two deliberate omissions stay unknown, and unknown is not discarded.
//
// etc_passwd matches every config parser and tutorial that names the path; php_uname is
// one information-gathering call that installers make legitimately. The engine describes
// what they mean when an attacker wrote them, and the pattern cannot tell who did. They
// come out as other/medium and get counted, so they keep showing up as something to
// decide about rather than quietly becoming a verdict.
func TestTheAmbiguousPatternsAreLeftUnknownOnPurpose(t *testing.T) {
	for _, token := range []string{"etc_passwd", "php_uname"} {
		m, known := classify("Exploit", token)
		if known {
			t.Errorf("%s was mapped to %+v. If that is deliberate, the reasoning written "+
				"beside it in rules.go has to change too — it currently says the opposite", token, m)
		}
		if m.category != schema.CategoryOther || m.severity != schema.SeverityMedium {
			t.Errorf("%s fell back to %q/%q, wanted other/medium", token, m.category, m.severity)
		}
	}
}

// The token beats the rule name, and a hash falls through to it.
//
// The whole point of D-057: Function (eval) is a backdoor because of `eval`, not because
// of "Function"; Signature (11413268) is known malware because of "Signature", since no
// table will ever hold that hash.
func TestTheTokenIsTriedBeforeTheRuleName(t *testing.T) {
	cases := []struct {
		rule, token string
		category    schema.Category
		confidence  schema.Confidence
	}{
		{"Function", "eval", schema.CategoryBackdoor, schema.ConfidenceHeuristic},
		{"Function", "exec", schema.CategoryWebshell, schema.ConfidenceHeuristic},
		{"Exploit", "execution", schema.CategoryBackdoor, schema.ConfidenceHeuristic},
		{"Signature", "11413268", schema.CategoryKnownMalware, schema.ConfidenceSignature},
	}
	for _, tc := range cases {
		m, known := classify(tc.rule, tc.token)
		if !known {
			t.Errorf("%s (%s): not classified", tc.rule, tc.token)
			continue
		}
		if m.category != tc.category {
			t.Errorf("%s (%s): category %q, wanted %q", tc.rule, tc.token, m.category, tc.category)
		}
		if m.confidence != tc.confidence {
			t.Errorf("%s (%s): confidence %q, wanted %q", tc.rule, tc.token, m.confidence, tc.confidence)
		}
	}
}
