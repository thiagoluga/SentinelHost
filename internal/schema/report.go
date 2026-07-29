package schema

import "time"

// Scope descreve o que o engine recebeu para escanear neste ciclo.
//
// Quem decide a lista e o ORQUESTRADOR (incremental por mtime/baseline); o
// adaptador nunca escolhe escopo.
type Scope struct {
	Root            string   `json:"root"`
	Mode            ScanMode `json:"mode"`
	FilesConsidered int      `json:"files_considered"`
	FilesScanned    int      `json:"files_scanned"`
	// SkippedReasonCounts mapeia motivo->quantidade ("unchanged", "too_large",
	// "unreadable", "excluded", "symlink").
	SkippedReasonCounts map[string]int `json:"skipped_reason_counts,omitempty"`
}

// ResourceUsage e o custo real da execucao do engine. Alimenta o painel e o
// agendador (Principio IV: cidadao educado da hospedagem).
type ResourceUsage struct {
	WallSeconds float64 `json:"wall_seconds"`
	MaxRSSMB    int     `json:"max_rss_mb,omitempty"`
}

// ScanReport e o resultado de UMA execucao de UM engine num ciclo.
type ScanReport struct {
	SchemaVersion string `json:"schema_version"`
	ScanID        string `json:"scan_id"`
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version,omitempty"`
	// SignaturesUpdatedAt e a data das assinaturas/regras no momento do scan.
	// Zero quando o engine nao separa assinaturas da instalacao.
	SignaturesUpdatedAt time.Time `json:"signatures_updated_at,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Scope Scope `json:"scope"`

	Status ScanStatus `json:"status"`
	// Error e a mensagem real do erro quando Status != completed. Nunca fica
	// vazio num status de falha: o usuario tem que conseguir saber o motivo.
	Error string `json:"error,omitempty"`

	ResourceUsage ResourceUsage `json:"resource_usage"`
	Findings      []Finding     `json:"findings"`

	// CleanFiles lista os sha256 que este engine afirma positivamente serem
	// legitimos. So o wp-checksums preenche isso (arquivos identicos ao
	// checksum oficial do WordPress.org). E a base da protecao anti-falso-
	// positivo do motor de veredito.
	CleanFiles []string `json:"clean_files,omitempty"`

	// RawRef aponta para a saida bruta arquivada deste scan, para auditoria e
	// reprocessamento por Parse().
	RawRef string `json:"raw_ref,omitempty"`
}

// Abstains responde se este relatorio deve virar abstencao no consenso.
//
// Um ScanReport com status != completed NUNCA conta como "engine nao achou
// nada": conta como abstencao (Principio VI).
func (r ScanReport) Abstains() bool {
	return !r.Status.CountsAsVote()
}

// Duration e o tempo de parede da execucao.
func (r ScanReport) Duration() time.Duration {
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		return 0
	}
	return r.FinishedAt.Sub(r.StartedAt)
}

// FailedReport monta o relatorio de abstencao de um engine que falhou. E o
// caminho unico pelo qual uma falha de adaptador entra no consenso: nunca
// derruba o ciclo, sempre vira abstencao registrada.
func FailedReport(scanID, engine string, status ScanStatus, err error, started time.Time) ScanReport {
	msg := "erro desconhecido"
	if err != nil {
		msg = err.Error()
	}
	if status.CountsAsVote() {
		// Defesa contra chamada errada: um relatorio de falha jamais pode
		// sair daqui com status que conta como voto.
		status = StatusFailed
	}
	return ScanReport{
		SchemaVersion: Version,
		ScanID:        scanID,
		Engine:        engine,
		StartedAt:     started,
		FinishedAt:    time.Now(),
		Status:        status,
		Error:         msg,
		Findings:      []Finding{},
	}
}
