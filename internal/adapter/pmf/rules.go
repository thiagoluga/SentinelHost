package pmf

import (
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// php-malware-finder's rule->(category, severity, confidence) table.
//
// The names are those of the YARA rules published in `php.yar`. Versioned next
// to the adapter (obligation 4 of the contract). An unknown rule becomes
// other/medium/heuristic — it is never discarded.

type mapping struct {
	category   schema.Category
	severity   schema.Severity
	confidence schema.Confidence
}

var ruleTable = map[string]mapping{
	"ObfuscatedPhp":       {schema.CategoryObfuscation, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"DodgyPhp":            {schema.CategoryBackdoor, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"DangerousPhp":        {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"DodgyStrings":        {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"SuspiciousEncoding":  {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},
	"Websites":            {schema.CategorySpamSEO, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"IRCBot":              {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"HiddenInAFile":       {schema.CategoryObfuscation, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"Base64Encoded":       {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"CloudFlareBypass":    {schema.CategoryWebshell, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"PhpInUploads":        {schema.CategorySuspiciousLocation, schema.SeverityMedium, schema.ConfidenceAnomaly},
	"PhpMailer":           {schema.CategorySpamSEO, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"WorldWritableFile":   {schema.CategorySuspiciousPerms, schema.SeverityMedium, schema.ConfidenceAnomaly},
	"DodgyPhpFilename":    {schema.CategorySuspiciousLocation, schema.SeverityMedium, schema.ConfidenceAnomaly},
	"PasswordProtection":  {schema.CategoryWebshell, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"Shell":               {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"WebShell":            {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"Phishing":            {schema.CategoryPhishing, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"SeoSpam":             {schema.CategorySpamSEO, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"Injection":           {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"Dropper":             {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"HiddenIframe":        {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"UploaderNoValidate":  {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"NonPrintableChars":   {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceAnomaly},
	"DodgyPhpVariables":   {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"SuspiciousDirectory": {schema.CategorySuspiciousLocation, schema.SeverityMedium, schema.ConfidenceAnomaly},
}

func classify(rule string) (mapping, bool) {
	if m, ok := ruleTable[strings.TrimSpace(rule)]; ok {
		return m, true
	}
	return mapping{schema.CategoryOther, schema.SeverityMedium, schema.ConfidenceHeuristic}, false
}
