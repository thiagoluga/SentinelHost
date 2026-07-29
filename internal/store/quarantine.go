package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// QuarantineStatus is the state of an item in the vault.
type QuarantineStatus string

const (
	QuarantineActive   QuarantineStatus = "quarantined"
	QuarantineRestored QuarantineStatus = "restored"
	QuarantinePurged   QuarantineStatus = "purged"
)

// QuarantineItem is the record that makes quarantine reversible.
//
// Without this metadata the file in the vault is undecipherable garbage: there
// is no way to know where it came from, what permissions to restore, or whether
// it is still the same file.
type QuarantineItem struct {
	Ref           string
	VerdictID     string
	OriginalPath  string
	VaultPath     string
	SHA256        string
	SizeBytes     int64
	Perms         string
	Owner         string
	OriginalMTime time.Time

	QuarantinedAt  time.Time
	RetentionUntil time.Time
	Status         QuarantineStatus
	RestoredAt     time.Time
	RestoredTo     string
	PurgedAt       time.Time
	Note           string
}

// Expired answers whether the item has passed its configured retention.
func (q QuarantineItem) Expired(now time.Time) bool {
	if q.Status != QuarantineActive || q.RetentionUntil.IsZero() {
		return false
	}
	return now.After(q.RetentionUntil)
}

// InsertQuarantineItem records an item just moved into the vault.
func (s *Store) InsertQuarantineItem(ctx context.Context, it QuarantineItem) error {
	if it.Ref == "" || it.VaultPath == "" || it.OriginalPath == "" || it.SHA256 == "" {
		return errors.New("a quarantine item with no ref, paths or hash is not restorable")
	}
	if it.Status == "" {
		it.Status = QuarantineActive
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO quarantine_items (
			ref, verdict_id, original_path, vault_path, sha256, size_bytes,
			perms, owner, original_mtime, quarantined_at, retention_until,
			status, note
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		it.Ref, nullString(it.VerdictID), it.OriginalPath, it.VaultPath, it.SHA256,
		it.SizeBytes, it.Perms, nullString(it.Owner), nullTime(it.OriginalMTime),
		formatTime(orNow(it.QuarantinedAt)), nullTime(it.RetentionUntil),
		string(it.Status), nullString(it.Note))
	if err != nil {
		return fmt.Errorf("recording quarantine item %s: %w", it.Ref, err)
	}
	return nil
}

// GetQuarantineItem looks an item up by reference.
func (s *Store) GetQuarantineItem(ctx context.Context, ref string) (QuarantineItem, error) {
	row := s.db.QueryRowContext(ctx, quarantineSelect+` WHERE ref = ?`, ref)
	it, err := scanQuarantineItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return it, fmt.Errorf("%w: quarantine item %s", ErrNotFound, ref)
	}
	return it, err
}

// ListQuarantineItems lists the vault. An empty status means all of them.
func (s *Store) ListQuarantineItems(ctx context.Context, status QuarantineStatus, limit int) ([]QuarantineItem, error) {
	q := quarantineSelect
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, string(status))
	}
	q += ` ORDER BY quarantined_at DESC`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing the quarantine: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []QuarantineItem
	for rows.Next() {
		it, err := scanQuarantineItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ExpiredItems returns the active items whose retention has already elapsed.
//
// Note the query filters on the active status: an item already restored or
// purged never reappears as a purge candidate.
func (s *Store) ExpiredItems(ctx context.Context, now time.Time) ([]QuarantineItem, error) {
	rows, err := s.db.QueryContext(ctx,
		quarantineSelect+` WHERE status = ? AND retention_until IS NOT NULL AND retention_until < ?
		ORDER BY retention_until`,
		string(QuarantineActive), formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("looking for expired items: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []QuarantineItem
	for rows.Next() {
		it, err := scanQuarantineItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkRestored records the file's return to its original location.
func (s *Store) MarkRestored(ctx context.Context, ref, restoredTo string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE quarantine_items SET status = ?, restored_at = ?, restored_to = ?
		WHERE ref = ? AND status = ?`,
		string(QuarantineRestored), nowUTC(), restoredTo, ref, string(QuarantineActive))
	if err != nil {
		return fmt.Errorf("marking %s as restored: %w", ref, err)
	}
	return checkAffected(res, ref)
}

// MarkPurged records the permanent removal.
//
// It only accepts active and expired items: this is Principle I's last barrier
// at the database level, so that a wrong call from another package cannot delete
// the record of an item still inside its retention window.
func (s *Store) MarkPurged(ctx context.Context, ref string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE quarantine_items SET status = ?, purged_at = ?
		WHERE ref = ? AND status = ? AND retention_until IS NOT NULL AND retention_until < ?`,
		string(QuarantinePurged), nowUTC(), ref, string(QuarantineActive), formatTime(now))
	if err != nil {
		return fmt.Errorf("marking %s as purged: %w", ref, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s is not active or is still inside its retention period", ErrNotFound, ref)
	}
	return nil
}

// ForcePurge records a permanent removal explicitly requested by the user,
// without waiting for the retention period. It is the only path that ignores the
// deadline, and it exists because the constitution allows "permanent purge by
// manual user action".
func (s *Store) ForcePurge(ctx context.Context, ref string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE quarantine_items SET status = ?, purged_at = ?
		WHERE ref = ? AND status = ?`,
		string(QuarantinePurged), nowUTC(), ref, string(QuarantineActive))
	if err != nil {
		return fmt.Errorf("purging %s: %w", ref, err)
	}
	return checkAffected(res, ref)
}

// CountQuarantine counts items per status.
func (s *Store) CountQuarantine(ctx context.Context) (map[QuarantineStatus]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM quarantine_items GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("counting the quarantine: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[QuarantineStatus]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[QuarantineStatus(st)] = n
	}
	return out, rows.Err()
}

const quarantineSelect = `
	SELECT ref, verdict_id, original_path, vault_path, sha256, size_bytes,
	       perms, owner, original_mtime, quarantined_at, retention_until,
	       status, restored_at, restored_to, purged_at, note
	FROM quarantine_items`

func scanQuarantineItem(r rowScanner) (QuarantineItem, error) {
	var (
		it                             QuarantineItem
		verdictID, owner, note         sql.NullString
		mtime, retention               sql.NullString
		restoredAt, restoredTo, purged sql.NullString
		quarantinedAt, status          string
	)
	err := r.Scan(&it.Ref, &verdictID, &it.OriginalPath, &it.VaultPath, &it.SHA256,
		&it.SizeBytes, &it.Perms, &owner, &mtime, &quarantinedAt, &retention,
		&status, &restoredAt, &restoredTo, &purged, &note)
	if err != nil {
		return it, err
	}
	it.VerdictID = strFromNull(verdictID)
	it.Owner = strFromNull(owner)
	it.Note = strFromNull(note)
	it.OriginalMTime = timeFromNull(mtime)
	it.QuarantinedAt = parseTime(quarantinedAt)
	it.RetentionUntil = timeFromNull(retention)
	it.Status = QuarantineStatus(status)
	it.RestoredAt = timeFromNull(restoredAt)
	it.RestoredTo = strFromNull(restoredTo)
	it.PurgedAt = timeFromNull(purged)
	return it, nil
}
