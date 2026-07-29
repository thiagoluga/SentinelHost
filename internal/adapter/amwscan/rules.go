package amwscan

import (
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Tabela regra->(categoria, severidade, confianca) do AMWScan.
//
// Versionada junto do adaptador, como manda a obrigacao 4 do contrato.
//
// PROCEDENCIA: os nomes abaixo vem do relatorio real do AMWScan 0.15.1,
// capturado no container de validacao (docker/Dockerfile.validacao). Uma
// versao anterior desta tabela usava nomes INVENTADOS (EVAL_POST,
// OBFUSCATED_BLOB...) que o engine nunca emite — o resultado era um parser que
// passava nos proprios testes e nao reconheceria nada em producao.
//
// A tabela esta incompleta de proposito: o AMWScan tem centenas de definicoes
// e so as vistas em execucao real entram aqui. Regra desconhecida NAO e
// descartada — vira other/medium/heuristic, aparece no relatorio, e e
// contabilizada em `regra_desconhecida` para que a tabela receba manutencao.

type mapping struct {
	category   schema.Category
	severity   schema.Severity
	confidence schema.Confidence
}

var ruleTable = map[string]mapping{
	// "Signature" e o casamento com a base de hashes do proprio AMWScan: e o
	// unico caso em que ele afirma reconhecer a AMEACA, nao um padrao.
	"signature":         {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},
	"malware signature": {schema.CategoryKnownMalware, schema.SeverityCritical, schema.ConfidenceSignature},

	// Categorias que o AMWScan reporta na linha "=> <tag>" do relatorio.
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

// classify traduz o nome da regra do engine para o esquema normalizado.
//
// O segundo retorno diz se a regra era conhecida — o adaptador usa isso para
// contabilizar quantas regras novas apareceram.
func classify(rule, tag string) (mapping, bool) {
	// A tag (a linha "=> backdoor" do relatorio) e mais especifica que o nome
	// da regra, entao tem prioridade: "Signature" com tag "backdoor" diz mais
	// que "Signature" sozinho.
	if tag != "" {
		if m, ok := ruleTable[strings.ToLower(strings.TrimSpace(tag))]; ok {
			return m, true
		}
	}
	if m, ok := ruleTable[strings.ToLower(strings.TrimSpace(rule))]; ok {
		return m, true
	}
	// Desconhecida nao e descartada. Entra com peso de heuristica media, forte
	// o bastante para aparecer no relatorio e fraco o bastante para nao
	// disparar quarentena automatica sozinha.
	return mapping{schema.CategoryOther, schema.SeverityMedium, schema.ConfidenceHeuristic}, false
}
