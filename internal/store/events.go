package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Categorias do log estruturado (FR-015). Fixas para que o filtro do painel
// tenha um conjunto conhecido em vez de texto livre.
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

// Event e uma linha do log estruturado.
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

// Log grava um evento.
//
// Toda acao relevante passa por aqui: scans, vereditos, quarentenas,
// restauracoes, alertas e mudancas de configuracao. E o registro que permite
// ao usuario reconstruir o que a ferramenta fez com o site dele.
func (s *Store) Log(ctx context.Context, e Event) error {
	fields := "{}"
	if len(e.Fields) > 0 {
		b, err := json.Marshal(e.Fields)
		if err != nil {
			return fmt.Errorf("serializando campos do evento: %w", err)
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
		return fmt.Errorf("gravando evento de log: %w", err)
	}
	return nil
}

// EventFilter parametriza a consulta do painel.
type EventFilter struct {
	Category string
	Level    string
	ScanID   string
	Since    time.Time
	Limit    int
	Offset   int
}

// ListEvents consulta o log, mais recentes primeiro.
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
		return nil, fmt.Errorf("consultando log: %w", err)
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

// PruneEvents apaga eventos mais antigos que a retencao configurada.
//
// Apagar log nao e acao destrutiva no sentido do Principio I: nao e arquivo do
// usuario, e sem poda o banco cresce sem limite numa conta com cota de disco.
func (s *Store) PruneEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, formatTime(olderThan))
	if err != nil {
		return 0, fmt.Errorf("podando log: %w", err)
	}
	return res.RowsAffected()
}
