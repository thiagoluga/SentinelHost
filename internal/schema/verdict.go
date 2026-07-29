package schema

import "time"

// Vote e a participacao de um engine num veredito. E o que torna o consenso
// auditavel: o usuario sempre consegue responder "por que este arquivo foi
// quarentenado?" (Principio V).
type Vote struct {
	Engine    string `json:"engine"`
	FindingID string `json:"finding_id"`
	// Weight e o peso configurado do engine.
	Weight float64 `json:"weight"`
	// Confidence do achado; multiplica o peso no score.
	Confidence Confidence `json:"confidence"`
	// EffectiveWeight = Weight * multiplicador(Confidence). E o numero que
	// realmente entrou na soma.
	EffectiveWeight float64 `json:"effective_weight"`
	// Rule e Category sao repetidos aqui para que o veredito seja explicavel
	// sem precisar recarregar os Findings.
	Rule     string   `json:"rule"`
	Category Category `json:"category"`
}

// Verdict e a decisao consolidada sobre UM arquivo, produzida pelo motor de
// veredito. Adaptadores nunca produzem Verdict.
type Verdict struct {
	SchemaVersion string `json:"schema_version"`
	VerdictID     string `json:"verdict_id"`

	FileSHA256 string `json:"file_sha256"`
	FilePath   string `json:"file_path"`
	FileSize   int64  `json:"file_size,omitempty"`

	Level Level   `json:"level"`
	Score float64 `json:"score"`

	Votes []Vote `json:"votes"`
	// Abstentions lista os engines que nao puderam opinar. Registradas para
	// transparencia; NAO entram no calculo do score (DECISIONS.md D-004).
	Abstentions []string `json:"abstentions,omitempty"`

	// CleanReason explica um Level=clean que contraria os votos. Hoje so
	// "official_checksum_match".
	CleanReason string `json:"clean_reason,omitempty"`

	ActionTaken ActionTaken `json:"action_taken"`
	ActionAt    time.Time   `json:"action_at,omitempty"`
	// ActionError e o motivo real quando ActionTaken == failed.
	ActionError   string `json:"action_error,omitempty"`
	QuarantineRef string `json:"quarantine_ref,omitempty"`

	AcknowledgedByUser bool      `json:"acknowledged_by_user"`
	AcknowledgedAt     time.Time `json:"acknowledged_at,omitempty"`

	ScanID    string    `json:"scan_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Engines devolve os slugs que votaram, na ordem em que aparecem.
func (v Verdict) Engines() []string {
	out := make([]string, 0, len(v.Votes))
	for _, vote := range v.Votes {
		out = append(out, vote.Engine)
	}
	return out
}

// Actionable responde se este veredito, isolado, autoriza acao automatica.
//
// Somente confirmed. Niveis inferiores sempre aguardam decisao humana
// (Principio V). As demais condicoes (modo observacao, periodo de graca,
// whitelist, re-hash) sao checadas pelo orquestrador, nao aqui.
func (v Verdict) Actionable() bool {
	return v.Level == LevelConfirmed && v.CleanReason == ""
}
