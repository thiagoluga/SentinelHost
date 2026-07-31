package schema

import "time"

// Vote is one engine's participation in a verdict. It is what makes the
// consensus auditable: the user can always answer "why was this file
// quarantined?" (Principle V).
type Vote struct {
	Engine    string `json:"engine"`
	FindingID string `json:"finding_id"`
	// Weight is the engine's configured weight.
	Weight float64 `json:"weight"`
	// Confidence of the finding; multiplies the weight in the score.
	Confidence Confidence `json:"confidence"`
	// EffectiveWeight = Weight * multiplier(Confidence). It is the number that
	// actually entered the sum.
	EffectiveWeight float64 `json:"effective_weight"`
	// Rule and Category are repeated here so a verdict is explainable without
	// reloading the Findings.
	Rule     string   `json:"rule"`
	Category Category `json:"category"`
}

// Verdict is the consolidated decision about ONE file, produced by the verdict
// engine. Adapters never produce a Verdict.
type Verdict struct {
	SchemaVersion string `json:"schema_version"`
	VerdictID     string `json:"verdict_id"`

	FileSHA256 string `json:"file_sha256"`
	FilePath   string `json:"file_path"`
	// FileLocation mirrors FileRef.Location: whether the web serves this path.
	FileLocation string `json:"file_location,omitempty"`
	FileSize     int64  `json:"file_size,omitempty"`

	Level Level   `json:"level"`
	Score float64 `json:"score"`

	Votes []Vote `json:"votes"`
	// Abstentions lists the engines that could not weigh in. Recorded for
	// transparency; they do NOT enter the score calculation (DECISIONS.md D-004).
	Abstentions []string `json:"abstentions,omitempty"`

	// CleanReason explains a Level=clean that contradicts the votes. Today only
	// "official_checksum_match".
	CleanReason string `json:"clean_reason,omitempty"`

	ActionTaken ActionTaken `json:"action_taken"`
	ActionAt    time.Time   `json:"action_at,omitempty"`
	// ActionError is the real reason when ActionTaken == failed.
	ActionError   string `json:"action_error,omitempty"`
	QuarantineRef string `json:"quarantine_ref,omitempty"`

	AcknowledgedByUser bool      `json:"acknowledged_by_user"`
	AcknowledgedAt     time.Time `json:"acknowledged_at,omitempty"`

	ScanID    string    `json:"scan_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Engines returns the slugs that voted, in the order they appear.
func (v Verdict) Engines() []string {
	out := make([]string, 0, len(v.Votes))
	for _, vote := range v.Votes {
		out = append(out, vote.Engine)
	}
	return out
}

// Actionable answers whether this verdict, on its own, authorizes automatic
// action.
//
// Only confirmed. Lower levels always wait for a human decision (Principle V).
// The remaining conditions (observation mode, grace period, whitelist, re-hash)
// are checked by the orchestrator, not here.
func (v Verdict) Actionable() bool {
	return v.Level == LevelConfirmed && v.CleanReason == ""
}
