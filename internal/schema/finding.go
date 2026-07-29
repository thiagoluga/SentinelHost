package schema

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// FileRef identifica o arquivo apontado por um achado.
//
// SHA256 e obrigatorio: e a chave de deduplicacao entre engines. Mesmo arquivo
// apontado por N engines = N votos no mesmo alvo.
type FileRef struct {
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	MD5       string    `json:"md5,omitempty"`
	MTime     time.Time `json:"mtime"`
	Owner     string    `json:"owner,omitempty"`
	// Perms e a permissao em octal como string ("0644"), preservada para que
	// o restore da quarentena devolva o arquivo exatamente como estava.
	Perms string `json:"perms,omitempty"`
}

// Component descreve o componente vulneravel de um achado kind=vulnerability.
//
// Definido em docs/esquema-e-adaptadores.md secao 3.1. O MVP nao produz estes
// achados — o tipo existe para que a feature 002 nao exija quebrar o esquema
// (DECISIONS.md D-013).
type Component struct {
	// Type: "wordpress-plugin", "wordpress-theme", "wordpress-core",
	// "composer-package", "npm-package".
	Type             string   `json:"type"`
	Slug             string   `json:"slug"`
	InstalledVersion string   `json:"installed_version"`
	FixedIn          string   `json:"fixed_in,omitempty"`
	VulnIDs          []string `json:"vuln_ids,omitempty"`
	CVSS             float64  `json:"cvss,omitempty"`
	ExploitedInWild  bool     `json:"exploited_in_wild,omitempty"`
}

// Finding e um achado individual reportado por um engine, ja normalizado.
//
// Um Finding e sempre a opiniao de UM engine sobre UM arquivo. A consolidacao
// entre engines acontece no Verdict, nunca aqui.
type Finding struct {
	SchemaVersion string `json:"schema_version"`
	// ID e gerado pelo orquestrador, nunca pelo adaptador.
	ID string `json:"id"`
	// Kind discrimina malware/vulnerability/hardening. Vazio e tratado como
	// KindMalware na normalizacao, para compatibilidade com adaptadores
	// escritos antes da secao 3 do esquema.
	Kind          Kind   `json:"kind,omitempty"`
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version,omitempty"`
	// Rule e o nome da assinatura/regra que bateu, como o engine reporta.
	Rule    string `json:"rule"`
	RuleRef string `json:"rule_ref,omitempty"`

	File FileRef `json:"file"`

	Category   Category   `json:"category"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`

	// MatchedContent e o trecho que disparou a regra: truncado a
	// MaxMatchedContentBytes e sanitizado. Nunca executavel.
	MatchedContent string `json:"matched_content,omitempty"`
	MatchedOffset  int64  `json:"matched_offset,omitempty"`

	// Component so e preenchido quando Kind == KindVulnerability.
	Component *Component `json:"component,omitempty"`

	ScanID     string    `json:"scan_id"`
	DetectedAt time.Time `json:"detected_at"`
}

// EffectiveKind devolve o Kind tratando vazio como malware.
func (f Finding) EffectiveKind() Kind {
	if f.Kind == "" {
		return KindMalware
	}
	return f.Kind
}

// SanitizeSnippet prepara um trecho de arquivo suspeito para ser transportado
// no esquema e exibido na UI.
//
// A constituicao proibe re-servir conteudo malicioso. Aqui isso significa:
// truncar em MaxMatchedContentBytes (respeitando fronteira de runa), remover
// bytes de controle que poderiam quebrar terminal ou log, e substituir
// sequencias nao-UTF8 por um marcador. A funcao NAO tenta desarmar o payload —
// isso e responsabilidade de quem renderiza (escapar HTML) e do fato de que o
// trecho nunca e passado a um interpretador.
func SanitizeSnippet(raw string) string {
	if len(raw) > MaxMatchedContentBytes {
		raw = raw[:MaxMatchedContentBytes]
		// Nao corta uma runa ao meio.
		for len(raw) > 0 && !utf8.ValidString(raw) {
			raw = raw[:len(raw)-1]
		}
	}

	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == utf8.RuneError:
			b.WriteByte('.')
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
