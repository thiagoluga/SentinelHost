package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Structured log categories (FR-015). Fixed, so the panel's filter has a known
// set instead of free text.
const (
	CatScan       = "scan"
	CatVerdict    = "verdict"
	CatQuarantine = "quarantine"
	CatAlert      = "alert"
	CatConfig     = "config"
	CatEngine     = "engine"
	CatAuth       = "auth"
	CatSystem     = "system"
)

// Event is one line of the structured log.
type Event struct {
	ID        int64
	TS        time.Time
	Level     string // debug, info, warn, error
	Category  string
	Message   string
	Fields    map[string]any
	ScanID    string
	VerdictID string
}

// Log writes an event.
//
// Every relevant action goes through here: scans, verdicts, quarantines,
// restores, alerts and configuration changes. It is the record that lets the user
// reconstruct what the tool did to their site.
func (s *Store) Log(ctx context.Context, e Event) error {
	fields := "{}"
	if len(e.Fields) > 0 {
		b, err := json.Marshal(e.Fields)
		if err != nil {
			return fmt.Errorf("serializing the event fields: %w", err)
		}
		fields = string(b)
	}
	if e.Level == "" {
		e.Level = "info"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events (ts, level, category, message, fields_json, scan_id, verdict_id)
		VALUES (?,?,?,?,?,?,?)`,
		formatTime(orNow(e.TS)), e.Level, e.Category, e.Message, fields,
		nullString(e.ScanID), nullString(e.VerdictID))
	if err != nil {
		return fmt.Errorf("writing a log event: %w", err)
	}
	return nil
}

// EventFilter parameterizes the panel's query.
type EventFilter struct {
	Category string
	Level    string
	ScanID   string
	Since    time.Time
	Limit    int
	Offset   int
}

// ListEvents queries the log, most recent first.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	q := `SELECT id, ts, level, category, message, fields_json, scan_id, verdict_id
	      FROM events WHERE 1=1`
	var args []any
	if f.Category != "" {
		q += ` AND category = ?`
		args = append(args, f.Category)
	}
	if f.Level != "" {
		q += ` AND level = ?`
		args = append(args, f.Level)
	}
	if f.ScanID != "" {
		q += ` AND scan_id = ?`
		args = append(args, f.ScanID)
	}
	if !f.Since.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, formatTime(f.Since))
	}
	q += ` ORDER BY ts DESC, id DESC`
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q += fmt.Sprintf(` LIMIT %d OFFSET %d`, limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("querying the log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Event
	for rows.Next() {
		var (
			e                 Event
			ts, fields        string
			scanID, verdictID sql.NullString
		)
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Category, &e.Message, &fields, &scanID, &verdictID); err != nil {
			return nil, err
		}
		e.TS = parseTime(ts)
		e.ScanID = strFromNull(scanID)
		e.VerdictID = strFromNull(verdictID)
		if fields != "" {
			_ = json.Unmarshal([]byte(fields), &e.Fields)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneEvents deletes events older than the configured retention.
//
// Deleting log entries is not a destructive action in the sense of Principle I:
// it is not the user's file, and without pruning the database grows without limit
// on an account with a disk quota.
func (s *Store) PruneEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, formatTime(olderThan))
	if err != nil {
		return 0, fmt.Errorf("pruning the log: %w", err)
	}
	return res.RowsAffected()
}
