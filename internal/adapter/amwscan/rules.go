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

	// AMWScan's Exploit vocabulary, mapped from the descriptions the engine itself prints
	// on the "- " line under every finding. Those descriptions are quoted here so the next
	// person can check the mapping against the source rather than against my reading of it.
	// Captured from a live account (see tests/testdata/raw/amwscan/PROVENANCE.md), where
	// `execution` alone accounted for 732 findings.
	//
	// "RCE (Remote Code Execution) allow remote attackers to execute PHP code on the
	// target machine via HTTP" — the same thing `eval` means, which is why it lands in the
	// same place.
	"execution": {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	// "Nano is a family of PHP webshells which are code golfed to be extremely stealthy
	// and efficient" — a named webshell family, not a pattern that happens to look bad.
	"nano": {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	// "LFI (Local File Inclusion), through a image inclusion, allow remote attackers to
	// inject and execute arbitrary commands or code" — the same category and weight the
	// table already gives plain `include`.
	"clever_include": {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},

	// The obfuscation family. Every one of these says "usually used for the obfuscation of
	// malicious code", and USUALLY is the operative word: minified libraries, licence
	// blobs and legitimate encoders trip them too.
	//
	// Medium, matching the existing `encoded` entry rather than `obfuscated`. Obfuscation
	// on its own is a reason to look, not a reason to act, and a heuristic that fires on
	// ordinary vendor code at high severity is one whose severity stops meaning anything.
	"base64_long":             {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"hex_char":                {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"double_var2":             {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"concat_vars_array":       {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"concat_vars_with_spaces": {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},

	// "Comments composed by 5 random chars usually used to detect if a file is infected
	// yet" — a marker malware leaves behind to recognise its own work. Not a technique the
	// file performs, so it is not backdoor or webshell; it is a strong sign the file has
	// been touched by something that keeps bookkeeping.
	"infected_comment": {schema.CategoryOther, schema.SeverityHigh, schema.ConfidenceHeuristic},

	// Two are deliberately NOT here, and the reason belongs next to the ones that are.
	//
	//   etc_passwd — "the /etc/passwd file on Unix systems contains password information,
	//     an attacker who has accessed the etc/passwd file may attempt a brute force
	//     attack". True of an attacker; also true of every config parser, test fixture and
	//     tutorial that mentions the path. The engine is describing what the string means
	//     when an attacker wrote it, and the pattern cannot tell who did.
	//
	//   php_uname — the engine files it under RCE. It is one information-gathering call,
	//     which diagnostics and installers make legitimately. Calling that critical on its
	//     own would put ordinary code next to webshells in the same list.
	//
	// Both stay unknown, which means other/medium/heuristic and a line in the note counts
	// so they keep showing up as something to decide about. That is the honest state for a
	// pattern whose meaning depends on who wrote the file, and an unmapped rule is not a
	// discarded one.
}

// classify translates the engine's rule name into the normalized schema.
//
// The second return value says whether the rule was known — the adapter uses it
// to count how many new rules showed up.
func classify(rule, detail string) (mapping, bool) {
	// The parenthesised token is the discriminator, and it used to be thrown away.
	//
	// Real AMWScan output names the rule generically and puts the specific thing in
	// parentheses:
	//
	//     => [!] Function (eval)
	//     => [!] Function (exec) [line 147]
	//     => [!] Signature (11413268) [line 66]
	//
	// "Function" is not in this table and never will be, so every one of those landed on
	// other/medium/heuristic while the word that decides the answer sat one pair of
	// brackets away. On one real account that was 199 `eval` and 29 `exec` findings shown
	// as generic medium heuristics — eval being the single strongest backdoor indicator
	// PHP has.
	//
	// Tried before the rule name because it is strictly more specific. A hash from
	// Signature (11413268) matches nothing here and falls through to "signature", which is
	// the intended answer for it.
	if detail != "" {
		if m, ok := ruleTable[strings.ToLower(strings.TrimSpace(detail))]; ok {
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
