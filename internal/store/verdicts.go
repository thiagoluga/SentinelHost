package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// ErrNotFound signals a record that does not exist.
var ErrNotFound = errors.New("record not found")

// SaveVerdict inserts or updates a verdict.
//
// The key is verdict_id, not the hash: the same file can receive different
// verdicts in different cycles, and deleting the previous one would destroy the
// history the user relies on to understand what happened to their site.
func (s *Store) SaveVerdict(ctx context.Context, v schema.Verdict) error {
	if err := v.Validate(); err != nil {
		return fmt.Errorf("an invalid verdict cannot be persisted: %w", err)
	}

	votes, err := json.Marshal(v.Votes)
	if err != nil {
		return fmt.Errorf("serializing votes: %w", err)
	}
	abst, err := json.Marshal(v.Abstentions)
	if err != nil {
		return fmt.Errorf("serializing abstentions: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO verdicts (
			verdict_id, file_sha256, file_path, file_location, file_size, level, score,
			votes_json, abstentions_json, clean_reason, action_taken, action_at,
			action_error, quarantine_ref, acknowledged_by_user, acknowledged_at,
			scan_id, created_at, updated_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(verdict_id) DO UPDATE SET
			level = excluded.level,
			score = excluded.score,
			votes_json = excluded.votes_json,
			abstentions_json = excluded.abstentions_json,
			clean_reason = excluded.clean_reason,
			action_taken = excluded.action_taken,
			action_at = excluded.action_at,
			action_error = excluded.action_error,
			quarantine_ref = excluded.quarantine_ref,
			acknowledged_by_user = excluded.acknowledged_by_user,
			acknowledged_at = excluded.acknowledged_at,
			file_location = excluded.file_location,
			updated_at = excluded.updated_at
	`,
		v.VerdictID, v.FileSHA256, v.FilePath, v.FileLocation, v.FileSize, string(v.Level), v.Score,
		string(votes), string(abst), nullString(v.CleanReason), string(v.ActionTaken),
		nullTime(v.ActionAt), nullString(v.ActionError), nullString(v.QuarantineRef),
		boolToInt(v.AcknowledgedByUser), nullTime(v.AcknowledgedAt),
		v.ScanID, formatTime(orNow(v.CreatedAt)), nowUTC(),
	)
	if err != nil {
		return fmt.Errorf("writing verdict %s: %w", v.VerdictID, err)
	}
	return nil
}

// GetVerdict looks a verdict up by id.
func (s *Store) GetVerdict(ctx context.Context, id string) (schema.Verdict, error) {
	row := s.db.QueryRowContext(ctx, verdictSelect+` WHERE verdict_id = ?`, id)
	v, err := scanVerdict(row)
	if errors.Is(err, sql.ErrNoRows) {
		return v, fmt.Errorf("%w: verdict %s", ErrNotFound, id)
	}
	return v, err
}

// VerdictFilter parameterizes the panel's listing.
type VerdictFilter struct {
	// Levels empty = all.
	Levels []schema.Level
	// ScanID empty = every cycle.
	ScanID string
	// PendingOnly narrows to what still awaits a human decision.
	PendingOnly bool
	// AllCycles keeps every cycle's verdict for a file instead of only the most recent.
	//
	// The listing collapses to one row per file by default, because a cron every fifteen
	// minutes re-decides the same file ninety-six times a day and a panel that lists all
	// of them is a panel nobody can read. Set this when the history is the point.
	AllCycles bool

	// IncludeClean: by default the clean level is left out of listings,
	// otherwise the panel would show thousands of clean files and hide the 3
	// that matter.
	IncludeClean bool
	Limit        int
	Offset       int
}

// ListVerdicts lists verdicts, most recent first.
func (s *Store) ListVerdicts(ctx context.Context, f VerdictFilter) ([]schema.Verdict, error) {
	q := verdictSelect + ` WHERE 1=1`
	var args []any

	if len(f.Levels) > 0 {
		q += ` AND level IN (` + placeholders(len(f.Levels)) + `)`
		for _, l := range f.Levels {
			args = append(args, string(l))
		}
	} else if !f.IncludeClean {
		q += ` AND level != ?`
		args = append(args, string(schema.LevelClean))
	}
	if f.ScanID != "" {
		q += ` AND scan_id = ?`
		args = append(args, f.ScanID)
	}
	if f.PendingOnly {
		// "Pending" means nobody has decided and the tool did not resolve it on
		// its own.
		q += ` AND acknowledged_by_user = 0 AND action_taken IN ('none','recommended','rescan_needed','failed')`
	}

	// One row per file, not one per cycle.
	//
	// A verdict's identity includes the scan that produced it, deliberately: the history
	// of what was decided when is worth keeping. But a cron running every fifteen minutes
	// re-decides the same file ninety-six times a day, and the panel was listing every one
	// of them. Measured on a real account: 1050 rows for 213 distinct files, growing by
	// ~208 every cycle, the same path repeating down the page.
	//
	// The newest row per (path, content) wins. Keyed on both because the same path with
	// new content is a different thing to decide about — a file that was replaced is not
	// the same finding — while the same content at two paths stays two findings, which is
	// what verdictID was fixed to preserve.
	//
	// Filtering happens before the collapse, so `pending only` picks the newest row that
	// is *pending*, rather than picking the newest row and then discovering it was
	// acknowledged.
	if !f.AllCycles && f.ScanID == "" {
		// ROW_NUMBER rather than GROUP BY. A bare `GROUP BY file_path` with no aggregate
		// leaves SQLite free to return any row from each group — the ORDER BY of an inner
		// query does not bind it — so the obvious spelling would show an arbitrary cycle's
		// verdict and look right most of the time.
		//
		// verdict_id breaks ties: rows written by one cycle share a created_at to the
		// nanosecond, and without a second key the choice among them is undefined again.
		q = `SELECT ` + verdictCols + ` FROM (SELECT ` + verdictCols + `,
		       ROW_NUMBER() OVER (PARTITION BY file_path, file_sha256
		                          ORDER BY created_at DESC, verdict_id DESC) AS rn
		     FROM (` + q + `)) WHERE rn = 1`
	}

	q += ` ORDER BY created_at DESC`
	if f.Limit > 0 {
		q += fmt.Sprintf(` LIMIT %d OFFSET %d`, f.Limit, f.Offset)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing verdicts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []schema.Verdict
	for rows.Next() {
		v, err := scanVerdict(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LatestVerdictForHash returns a file's most recent verdict.
func (s *Store) LatestVerdictForHash(ctx context.Context, sha string) (schema.Verdict, error) {
	row := s.db.QueryRowContext(ctx,
		verdictSelect+` WHERE file_sha256 = ? ORDER BY created_at DESC LIMIT 1`, sha)
	v, err := scanVerdict(row)
	if errors.Is(err, sql.ErrNoRows) {
		return v, fmt.Errorf("%w: no verdict for %s", ErrNotFound, sha)
	}
	return v, err
}

// UpdateVerdictAction records the outcome of the action on the file.
func (s *Store) UpdateVerdictAction(ctx context.Context, id string, action schema.ActionTaken, quarantineRef, actionErr string) error {
	if !action.Valid() {
		return fmt.Errorf("unknown action_taken %q", action)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE verdicts
		SET action_taken = ?, action_at = ?, quarantine_ref = ?, action_error = ?, updated_at = ?
		WHERE verdict_id = ?`,
		string(action), nowUTC(), nullString(quarantineRef), nullString(actionErr), nowUTC(), id)
	if err != nil {
		return fmt.Errorf("updating the action of verdict %s: %w", id, err)
	}
	return checkAffected(res, id)
}

// AcknowledgeVerdict marks that the user decided about this finding.
func (s *Store) AcknowledgeVerdict(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE verdicts SET acknowledged_by_user = 1, acknowledged_at = ?, updated_at = ?
		WHERE verdict_id = ?`, nowUTC(), nowUTC(), id)
	if err != nil {
		return fmt.Errorf("marking verdict %s as decided: %w", id, err)
	}
	return checkAffected(res, id)
}

// CountByLevel summarizes a cycle's verdicts per level (the panel overview and
// the scan.completed payload).
func (s *Store) CountByLevel(ctx context.Context, scanID string) (map[schema.Level]int, error) {
	q := `SELECT level, COUNT(*) FROM verdicts`
	var args []any
	if scanID != "" {
		q += ` WHERE scan_id = ?`
		args = append(args, scanID)
	}
	q += ` GROUP BY level`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("counting verdicts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[schema.Level]int{}
	for rows.Next() {
		var lvl string
		var n int
		if err := rows.Scan(&lvl, &n); err != nil {
			return nil, err
		}
		out[schema.Level(lvl)] = n
	}
	return out, rows.Err()
}

// SQL and scanning -----------------------------------------------------------

// verdictCols is the column list, in the order scanVerdict reads them. Kept apart from
// the FROM so a query can wrap this SELECT in another one and still name the columns.
const verdictCols = `verdict_id, file_sha256, file_path, file_location, file_size, level, score,
	       votes_json, abstentions_json, clean_reason, action_taken, action_at,
	       action_error, quarantine_ref, acknowledged_by_user, acknowledged_at,
	       scan_id, created_at`

const verdictSelect = `SELECT ` + verdictCols + ` FROM verdicts`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanVerdict(r rowScanner) (schema.Verdict, error) {
	var (
		v                      schema.Verdict
		votesJSON, abstJSON    string
		cleanReason, actionErr sql.NullString
		actionAt, ackAt        sql.NullString
		qRef                   sql.NullString
		ack                    int
		createdAt, level       string
		action                 string
	)
	err := r.Scan(&v.VerdictID, &v.FileSHA256, &v.FilePath, &v.FileLocation, &v.FileSize, &level, &v.Score,
		&votesJSON, &abstJSON, &cleanReason, &action, &actionAt,
		&actionErr, &qRef, &ack, &ackAt, &v.ScanID, &createdAt)
	if err != nil {
		return v, err
	}

	v.SchemaVersion = schema.Version
	v.Level = schema.Level(level)
	v.ActionTaken = schema.ActionTaken(action)
	v.CleanReason = strFromNull(cleanReason)
	v.ActionError = strFromNull(actionErr)
	v.QuarantineRef = strFromNull(qRef)
	v.ActionAt = timeFromNull(actionAt)
	v.AcknowledgedByUser = ack != 0
	v.AcknowledgedAt = timeFromNull(ackAt)
	v.CreatedAt = parseTime(createdAt)

	if err := json.Unmarshal([]byte(votesJSON), &v.Votes); err != nil {
		return v, fmt.Errorf("votes of verdict %s are corrupt: %w", v.VerdictID, err)
	}
	if abstJSON != "" && abstJSON != "null" {
		if err := json.Unmarshal([]byte(abstJSON), &v.Abstentions); err != nil {
			return v, fmt.Errorf("abstentions of verdict %s are corrupt: %w", v.VerdictID, err)
		}
	}
	return v, nil
}
