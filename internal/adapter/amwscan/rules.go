package amwscan

import (
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// AMWScan's rule->(category, severity, confidence) table.
//
// Versioned next to the adapter, as obligation 4 of the contract requires.
//
// PROVENANCE: the names below come from the real AMWScan 0.15.1 report captured
// in the validation container (docker/Dockerfile.validation). An earlier version
// of this table used INVENTED names (EVAL_POST, OBFUSCATED_BLOB...) that the
// engine never emits — the result was a parser that passed its own tests and
// would recognize nothing in production.
//
// The table is deliberately incomplete: AMWScan has hundreds of definitions and
// only the ones seen in a real run get in here. An unknown rule is NOT
// discarded — it becomes other/medium/heuristic, shows up in the report, and is
// counted under `unknown_rule` so the table gets maintained.

type mapping struct {
	category   schema.Category
	severity   schema.Severity
	confidence schema.Confidence
}

var ruleTable = map[string]mapping{
	// "Signature" is a match against AMWScan's own hash database: the only case
	// where it claims to recognize the THREAT, not a pattern.
	"signature":         {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},
	"malware signature": {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},

	// Categories AMWScan reports on the report's "=> <tag>" line.
	"backdoor":    {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"webshell":    {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"shell":       {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"obfuscator":  {schema.CategoryObfuscation, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"obfuscated":  {schema.CategoryObfuscation, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"encoded":     {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"eval":        {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"exec":        {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"system":      {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"shell_exec":  {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"passthru":    {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"assert":      {schema.CategoryBackdoor, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"phishing":    {schema.CategoryPhishing, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"spam":        {schema.CategorySpamSEO, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"seo":         {schema.CategorySpamSEO, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"mailer":      {schema.CategorySpamSEO, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"uploader":    {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"dropper":     {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"downloader":  {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"injection":   {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"iframe":      {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"include":     {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"irc":         {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"crypto":      {schema.CategoryOther, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"suspicious":  {schema.CategoryOther, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"unsafe":      {schema.CategoryOther, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"permissions": {schema.CategorySuspiciousPerms, schema.SeverityMedium, schema.ConfidenceAnomaly},
}

// classify translates the engine's rule name into the normalized schema.
//
// The second return value says whether the rule was known — the adapter uses it
// to count how many new rules showed up.
func classify(rule, tag string) (mapping, bool) {
	// The tag (the report's "=> backdoor" line) is more specific than the rule
	// name, so it wins: "Signature" with tag "backdoor" says more than
	// "Signature" alone.
	if tag != "" {
		if m, ok := ruleTable[strings.ToLower(strings.TrimSpace(tag))]; ok {
			return m, true
		}
	}
	if m, ok := ruleTable[strings.ToLower(strings.TrimSpace(rule))]; ok {
		return m, true
	}
	// Unknown is not discarded. It enters with medium heuristic weight: strong
	// enough to show up in the report, weak enough not to trigger automatic
	// quarantine on its own.
	return mapping{schema.CategoryOther, schema.SeverityMedium, schema.ConfidenceHeuristic}, false
}
