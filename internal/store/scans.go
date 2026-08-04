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

// ScanRecord is the record of a complete cycle.
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

// ScanRunning is the status of a cycle that started and has not finished.
//
// Deliberately not a schema.ScanStatus: that enum describes the outcome of an
// ENGINE execution, and "in progress" is not an outcome. A cycle the host killed
// mid-run keeps this status with no finished_at — which is exactly the signal the
// watchdog looks for to know it has to recover.
const ScanRunning = "running"

// StartScan records the beginning of a cycle.
func (s *Store) StartScan(ctx context.Context, rec ScanRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scans (scan_id, mode, roots, started_at, status, files_considered, files_scanned)
		VALUES (?,?,?,?,?,?,?)`,
		rec.ScanID, string(rec.Mode), strings.Join(rec.Roots, "\n"),
		formatTime(orNow(rec.StartedAt)), ScanRunning, 0, 0)
	if err != nil {
		return fmt.Errorf("recording the start of cycle %s: %w", rec.ScanID, err)
	}
	return nil
}

// InterruptedScans returns cycles that started and never finished. The watchdog
// uses this to resume from the last state without corrupting the baseline or the
// quarantine.
func (s *Store) InterruptedScans(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT scan_id FROM scans WHERE status = ? AND finished_at IS NULL ORDER BY started_at`,
		ScanRunning)
	if err != nil {
		return nil, fmt.Errorf("looking for interrupted cycles: %w", err)
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

// FinishScan closes the cycle with its real outcome.
func (s *Store) FinishScan(ctx context.Context, rec ScanRecord) error {
	summary := "{}"
	if rec.Summary != nil {
		b, err := json.Marshal(rec.Summary)
		if err != nil {
			return fmt.Errorf("serializing the cycle summary: %w", err)
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
		return fmt.Errorf("closing cycle %s: %w", rec.ScanID, err)
	}
	return checkAffected(res, rec.ScanID)
}

// SaveScanReport archives one engine's report.
//
// Failure reports are stored with the same care as successful ones: the panel
// needs to show WHY an engine did not contribute to a cycle, otherwise the
// coverage degradation stays invisible.
func (s *Store) SaveScanReport(ctx context.Context, r schema.ScanReport) error {
	blob, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("serializing the report of %s: %w", r.Engine, err)
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
		return fmt.Errorf("writing the report of %s: %w", r.Engine, err)
	}
	return nil
}

// ListScanReports returns a cycle's reports.
func (s *Store) ListScanReports(ctx context.Context, scanID string) ([]schema.ScanReport, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT report_json FROM scan_reports WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("listing the reports of cycle %s: %w", scanID, err)
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
			return nil, fmt.Errorf("the report of cycle %s is corrupt: %w", scanID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveFinding archives one individual finding.
func (s *Store) SaveFinding(ctx context.Context, f schema.Finding) error {
	blob, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("serializing the finding: %w", err)
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
		return fmt.Errorf("writing finding %s: %w", f.ID, err)
	}
	return nil
}

// FindingsForHash returns every engine's findings about one file. It is what the
// panel uses to answer "why was this file flagged?".
func (s *Store) FindingsForHash(ctx context.Context, sha string) ([]schema.Finding, error) {
	return s.findings(ctx, sha, "")
}

// FindingsForVerdict returns the evidence one verdict was actually built from.
//
// FindingsForHash returns every finding for that content across every cycle, and a cron
// running every fifteen minutes re-detects the same file all day. The panel showed one
// wp-checksums vote above three identical wp-checksums evidence blocks — which is not
// only noise, it contradicts the votes printed directly above it.
//
// The verdict's votes come from one cycle's findings. Showing another cycle's evidence
// under them answers "why was this file flagged, at some point, by anyone" when the
// question on screen is "why does THIS verdict say what it says".
func (s *Store) FindingsForVerdict(ctx context.Context, sha, scanID string) ([]schema.Finding, error) {
	return s.findings(ctx, sha, scanID)
}

func (s *Store) findings(ctx context.Context, sha, scanID string) ([]schema.Finding, error) {
	q := `SELECT finding_json FROM findings WHERE file_sha256 = ?`
	args := []any{sha}
	if scanID != "" {
		q += ` AND scan_id = ?`
		args = append(args, scanID)
	}
	q += ` ORDER BY detected_at DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("looking for findings of %s: %w", sha, err)
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
			return nil, fmt.Errorf("corrupt finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LastScan returns the most recent cycle.
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
