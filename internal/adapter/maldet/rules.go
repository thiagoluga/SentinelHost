package maldet

import (
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// maldet's signature-type -> confidence table, plus the rule-name -> category
// heuristics.
//
// Versioned next to the adapter, as obligation 4 of the contract requires.
//
// PROVENANCE: the format comes from Linux Malware Detect 1.6.5, recorded in
// tests/testdata/raw/maldet/PROVENANCE.md. The signature NAMES below are the
// families maldet's own rule set uses (`php.base64`, `php.cmdshell`, …); an unknown
// name is not discarded, it becomes other/medium and is counted.

// confidenceForType maps the prefix in braces to a confidence.
//
// This distinction is the one that must not be lost: `{HEX}` and `{MD5}` are an
// exact match against a known-bad blob — maldet is asserting it recognizes the
// THREAT. `{YARA}` and `{CAV}` are a pattern that resembles one. Collapsing them
// would give a heuristic the weight of proof, and with maldet's weight of 1.0 that
// is the difference between `suspicious` and one vote away from `confirmed`.
func confidenceForType(sigType string) schema.Confidence {
	switch strings.ToUpper(sigType) {
	case "HEX", "MD5":
		return schema.ConfidenceSignature
	case "YARA", "CAV", "CLAMAV":
		return schema.ConfidenceHeuristic
	default:
		// An unrecognized prefix weighs as the weakest thing it could be. A new
		// signature type must not gain the weight of proof just by being unknown.
		return schema.ConfidenceAnomaly
	}
}

type mapping struct {
	category schema.Category
	severity schema.Severity
}

// familyTable maps a fragment of maldet's signature name to a category.
//
// maldet's names are dotted families (`php.cmdshell.unclassed.359`), so the match is
// on a substring rather than on equality: the tail is a serial that changes with
// every rule update, and matching the whole name would make the table go stale on
// the first signature refresh.
var familyTable = []struct {
	fragment string
	mapping  mapping
}{
	{"cmdshell", mapping{schema.CategoryWebshell, schema.SeverityCritical}},
	{"shell", mapping{schema.CategoryWebshell, schema.SeverityCritical}},
	{"backdoor", mapping{schema.CategoryBackdoor, schema.SeverityCritical}},
	{"bkdr", mapping{schema.CategoryBackdoor, schema.SeverityCritical}},
	{"irc", mapping{schema.CategoryBackdoor, schema.SeverityCritical}},
	{"base64", mapping{schema.CategoryObfuscation, schema.SeverityHigh}},
	{"gzbase64", mapping{schema.CategoryObfuscation, schema.SeverityHigh}},
	{"obfus", mapping{schema.CategoryObfuscation, schema.SeverityHigh}},
	{"encode", mapping{schema.CategoryObfuscation, schema.SeverityMedium}},
	{"phishing", mapping{schema.CategoryPhishing, schema.SeverityCritical}},
	{"phish", mapping{schema.CategoryPhishing, schema.SeverityCritical}},
	{"mailer", mapping{schema.CategorySpamSEO, schema.SeverityHigh}},
	{"spam", mapping{schema.CategorySpamSEO, schema.SeverityMedium}},
	{"seo", mapping{schema.CategorySpamSEO, schema.SeverityMedium}},
	{"uploader", mapping{schema.CategoryDropper, schema.SeverityHigh}},
	{"dropper", mapping{schema.CategoryDropper, schema.SeverityHigh}},
	{"downloader", mapping{schema.CategoryDropper, schema.SeverityHigh}},
	{"inject", mapping{schema.CategoryInjection, schema.SeverityHigh}},
	{"iframe", mapping{schema.CategoryInjection, schema.SeverityHigh}},
	{"defac", mapping{schema.CategoryInjection, schema.SeverityHigh}},
	{"exploit", mapping{schema.CategoryOther, schema.SeverityHigh}},
	{"trojan", mapping{schema.CategoryKnownMalware, schema.SeverityCritical}},
	{"malware", mapping{schema.CategoryKnownMalware, schema.SeverityCritical}},
	{"virus", mapping{schema.CategoryKnownMalware, schema.SeverityCritical}},
	{"corpus", mapping{schema.CategoryKnownMalware, schema.SeverityCritical}},
}

// classify translates a maldet signature name into the normalized schema.
//
// The second return value says whether the family was recognized — the adapter uses
// it to count how many new families showed up, so the table gets maintained instead
// of quietly rotting.
func classify(signature string) (mapping, bool) {
	name := strings.ToLower(signature)
	for _, e := range familyTable {
		if strings.Contains(name, e.fragment) {
			return e.mapping, true
		}
	}
	// Unknown is not discarded. It enters as a medium-severity other, strong enough
	// to appear in the report and weak enough not to trigger a quarantine on its own.
	return mapping{schema.CategoryOther, schema.SeverityMedium}, false
}
