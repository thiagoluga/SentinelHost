package amwscan

import (
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Tabela regra->(categoria, severidade, confianca) do AMWScan.
//
// Versionada junto do adaptador, como manda a obrigacao 4 do contrato. Regra
// desconhecida NUNCA e descartada: vira other/medium/heuristic, para que um
// achado real nao suma so porque o engine ganhou uma assinatura nova entre
// duas versoes do SentinelHost.

type mapping struct {
	category   schema.Category
	severity   schema.Severity
	confidence schema.Confidence
}

var ruleTable = map[string]mapping{
	// Assinaturas exatas -----------------------------------------------------
	"SIGNATURE_KNOWN_MARKER": {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},
	"KNOWN_MALWARE":          {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},
	"BLACKLIST_HASH":         {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},

	// Execucao dinamica ------------------------------------------------------
	"EVAL_POST":         {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"EVAL_GET":          {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"EVAL_REQUEST":      {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"EVAL_BASE64":       {schema.CategoryObfuscation, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"ASSERT_DYNAMIC":    {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"PREG_REPLACE_EVAL": {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"CREATE_FUNCTION":   {schema.CategoryBackdoor, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"CALLBACK_DYNAMIC":  {schema.CategoryBackdoor, schema.SeverityHigh, schema.ConfidenceHeuristic},

	// Shell ------------------------------------------------------------------
	"SHELL_EXEC":    {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"SYSTEM_CALL":   {schema.CategoryWebshell, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"PROC_OPEN":     {schema.CategoryWebshell, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"REVERSE_SHELL": {schema.CategoryBackdoor, schema.SeverityCritical, schema.ConfidenceHeuristic},

	// Ofuscacao --------------------------------------------------------------
	"OBFUSCATED_BLOB":   {schema.CategoryObfuscation, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"OBFUSCATED_VARS":   {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"GZINFLATE_CHAIN":   {schema.CategoryObfuscation, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"STR_ROT13":         {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"HEX_STRING":        {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"NON_PRINTABLE_VAR": {schema.CategoryObfuscation, schema.SeverityMedium, schema.ConfidenceAnomaly},

	// Upload e persistencia ---------------------------------------------------
	"UPLOAD_NO_VALIDATION": {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"FILE_WRITE_WEBROOT":   {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"REMOTE_INCLUDE":       {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"REMOTE_DOWNLOAD":      {schema.CategoryDropper, schema.SeverityHigh, schema.ConfidenceHeuristic},

	// Conteudo ---------------------------------------------------------------
	"SEO_SPAM":         {schema.CategorySpamSEO, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"CLOAKING":         {schema.CategorySpamSEO, schema.SeverityMedium, schema.ConfidenceHeuristic},
	"PHISHING_FORM":    {schema.CategoryPhishing, schema.SeverityCritical, schema.ConfidenceHeuristic},
	"MAIL_INJECTION":   {schema.CategorySpamSEO, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"HIDDEN_IFRAME":    {schema.CategoryInjection, schema.SeverityHigh, schema.ConfidenceHeuristic},
	"SUSPICIOUS_TITLE": {schema.CategoryOther, schema.SeverityLow, schema.ConfidenceAnomaly},
}

// classify traduz o nome da regra do engine para o esquema normalizado.
//
// O segundo retorno diz se a regra era conhecida — o adaptador usa isso para
// registrar quantas regras novas apareceram, sinal de que a tabela precisa de
// manutencao.
func classify(rule string) (mapping, bool) {
	key := strings.ToUpper(strings.TrimSpace(rule))
	if m, ok := ruleTable[key]; ok {
		return m, true
	}
	// Desconhecida nao e descartada. Entra com peso de heuristica media, que e
	// forte o bastante para aparecer no relatorio e fraco o bastante para nao
	// disparar quarentena automatica sozinha.
	return mapping{schema.CategoryOther, schema.SeverityMedium, schema.ConfidenceHeuristic}, false
}
