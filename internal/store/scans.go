package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// ScanRecord e o registro de um ciclo completo.
type ScanRecord struct {
	ScanID          string
	Mode            schema.ScanMode
	Roots           []string
	StartedAt       time.Time
	FinishedAt      time.Time
	Status          schema.ScanStatus
	FilesConsidered int
	FilesScanned    int
	Summary         map[string]any
}

// ScanRunning e o status de um ciclo que comecou e ainda nao terminou.
//
// Nao e um schema.ScanStatus de proposito: aquele enum descreve o desfecho da
// execucao de um ENGINE, e "em andamento" nao e desfecho. Um ciclo que a
// hospedagem matou no meio fica com este status e sem finished_at — que e
// exatamente o sinal que o watchdog procura para saber que precisa retomar.
const ScanRunning = "running"

// StartScan registra o inicio de um ciclo.
func (s *Store) StartScan(ctx context.Context, rec ScanRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scans (scan_id, mode, roots, started_at, status, files_considered, files_scanned)
		VALUES (?,?,?,?,?,?,?)`,
		rec.ScanID, string(rec.Mode), strings.Join(rec.Roots, "\n"),
		formatTime(orNow(rec.StartedAt)), ScanRunning, 0, 0)
	if err != nil {
		return fmt.Errorf("registrando inicio do ciclo %s: %w", rec.ScanID, err)
	}
	return nil
}

// InterruptedScans devolve ciclos que comecaram e nunca terminaram. O watchdog
// usa isto para retomar do ultimo estado sem corromper baseline nem quarentena.
func (s *Store) InterruptedScans(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT scan_id FROM scans WHERE status = ? AND finished_at IS NULL ORDER BY started_at`,
		ScanRunning)
	if err != nil {
		return nil, fmt.Errorf("buscando ciclos interrompidos: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// FinishScan fecha o ciclo com o desfecho real.
func (s *Store) FinishScan(ctx context.Context, rec ScanRecord) error {
	summary := "{}"
	if rec.Summary != nil {
		b, err := json.Marshal(rec.Summary)
		if err != nil {
			return fmt.Errorf("serializando resumo do ciclo: %w", err)
		}
		summary = string(b)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE scans SET finished_at = ?, status = ?, files_considered = ?,
		       files_scanned = ?, summary_json = ?
		WHERE scan_id = ?`,
		formatTime(orNow(rec.FinishedAt)), string(rec.Status),
		rec.FilesConsidered, rec.FilesScanned, summary, rec.ScanID)
	if err != nil {
		return fmt.Errorf("fechando ciclo %s: %w", rec.ScanID, err)
	}
	return checkAffected(res, rec.ScanID)
}

// SaveScanReport arquiva o relatorio de um engine.
//
// Relatorios de falha sao gravados com o mesmo cuidado que os de sucesso: o
// painel precisa mostrar POR QUE um engine nao contribuiu num ciclo, senao a
// degradacao de cobertura fica invisivel.
func (s *Store) SaveScanReport(ctx context.Context, r schema.ScanReport) error {
	blob, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("serializando relatorio de %s: %w", r.Engine, err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO scan_reports (
			scan_id, engine, engine_version, status, error, started_at, finished_at,
			wall_seconds, max_rss_mb, findings_count, raw_ref, report_json
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ScanID, r.Engine, nullString(r.EngineVersion), string(r.Status), nullString(r.Error),
		nullTime(r.StartedAt), nullTime(r.FinishedAt), r.ResourceUsage.WallSeconds,
		r.ResourceUsage.MaxRSSMB, len(r.Findings), nullString(r.RawRef), string(blob))
	if err != nil {
		return fmt.Errorf("gravando relatorio de %s: %w", r.Engine, err)
	}
	return nil
}

// ListScanReports devolve os relatorios de um ciclo.
func (s *Store) ListScanReports(ctx context.Context, scanID string) ([]schema.ScanReport, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT report_json FROM scan_reports WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("listando relatorios do ciclo %s: %w", scanID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []schema.ScanReport
	for rows.Next() {
		var blob string
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		var r schema.ScanReport
		if err := json.Unmarshal([]byte(blob), &r); err != nil {
			return nil, fmt.Errorf("relatorio do ciclo %s corrompido: %w", scanID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveFinding arquiva um achado individual.
func (s *Store) SaveFinding(ctx context.Context, f schema.Finding) error {
	blob, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("serializando achado: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO findings (
			id, scan_id, engine, kind, rule, file_sha256, file_path, category,
			severity, confidence, matched_content, matched_offset, detected_at, finding_json
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO NOTHING`,
		f.ID, f.ScanID, f.Engine, string(f.EffectiveKind()), f.Rule, f.File.SHA256, f.File.Path,
		string(f.Category), string(f.Severity), string(f.Confidence),
		nullString(f.MatchedContent), f.MatchedOffset, formatTime(f.DetectedAt), string(blob))
	if err != nil {
		return fmt.Errorf("gravando achado %s: %w", f.ID, err)
	}
	return nil
}

// FindingsForHash devolve os achados de todos os engines sobre um arquivo.
// E o que o painel usa para responder "por que este arquivo foi apontado?".
func (s *Store) FindingsForHash(ctx context.Context, sha string) ([]schema.Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT finding_json FROM findings WHERE file_sha256 = ? ORDER BY detected_at DESC`, sha)
	if err != nil {
		return nil, fmt.Errorf("buscando achados de %s: %w", sha, err)
	}
	defer func() { _ = rows.Close() }()

	var out []schema.Finding
	for rows.Next() {
		var blob string
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		var f schema.Finding
		if err := json.Unmarshal([]byte(blob), &f); err != nil {
			return nil, fmt.Errorf("achado corrompido: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LastScan devolve o ciclo mais recente.
func (s *Store) LastScan(ctx context.Context) (ScanRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT scan_id, mode, roots, started_at, finished_at, status,
		       files_considered, files_scanned, summary_json
		FROM scans ORDER BY started_at DESC LIMIT 1`)

	var (
		rec         ScanRecord
		mode, roots string
		started     string
		finished    sql.NullString
		status      string
		summary     sql.NullString
	)
	err := row.Scan(&rec.ScanID, &mode, &roots, &started, &finished, &status,
		&rec.FilesConsidered, &rec.FilesScanned, &summary)
	if err != nil {
		return rec, err
	}
	rec.Mode = schema.ScanMode(mode)
	if roots != "" {
		rec.Roots = strings.Split(roots, "\n")
	}
	rec.StartedAt = parseTime(started)
	rec.FinishedAt = timeFromNull(finished)
	rec.Status = schema.ScanStatus(status)
	if summary.Valid && summary.String != "" {
		_ = json.Unmarshal([]byte(summary.String), &rec.Summary)
	}
	return rec, nil
}
