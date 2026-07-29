package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Settings keys. They live in the database rather than the TOML because they are
// derived secrets the user does not edit by hand — and a TOML the panel rewrites
// is no place for a password hash.
const (
	KeyPanelPasswordHash = "panel.password_hash"
	KeyInstanceID        = "instance.id"
	KeyFirstRunAt        = "instance.first_run_at"
	KeyLastDigestAt      = "alert.last_digest_at"
	KeyGraceNotifiedAt   = "instance.grace_notified_at"
)

// GetSetting reads a value. A missing key returns ("", nil): most callers want
// "not configured yet", not an error.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading internal setting %s: %w", key, err)
	}
	return v, nil
}

// SetSetting writes a value.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, nowUTC())
	if err != nil {
		return fmt.Errorf("writing internal setting %s: %w", key, err)
	}
	return nil
}

// DeleteSetting removes a value.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}

// Panel sessions --------------------------------------------------------------

// CreateSession records an authenticated session.
func (s *Store) CreateSession(ctx context.Context, token string, expiresAt time.Time, userAgent, ip string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (token, created_at, expires_at, user_agent, remote_ip)
		VALUES (?,?,?,?,?)`,
		token, nowUTC(), formatTime(expiresAt), nullString(userAgent), nullString(ip))
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	return nil
}

// SessionValid answers whether the token exists and has not expired.
//
// Expiry is checked in SQL rather than in Go so that an expired session is never
// accepted because of clock drift between the read and the comparison.
func (s *Store) SessionValid(ctx context.Context, token string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE token = ? AND expires_at > ?`,
		token, nowUTC()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("validating session: %w", err)
	}
	return n > 0, nil
}

// DeleteSession ends a session (logout).
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// PurgeExpiredSessions clears expired sessions.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, nowUTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Engine state ----------------------------------------------------------------

// EngineState is what the panel shows in the "engines" area.
type EngineState struct {
	Slug                string
	Available           bool
	UnavailableReason   string
	Version             string
	BinaryPath          string
	SignaturesUpdatedAt time.Time
	LastProbeAt         time.Time
	LastRunAt           time.Time
	LastRunStatus       string
}

// SaveEngineState records the result of probing an engine.
func (s *Store) SaveEngineState(ctx context.Context, st EngineState) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO engine_state (
			slug, available, unavailable_reason, version, binary_path,
			signatures_updated_at, last_probe_at, last_run_at, last_run_status
		) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(slug) DO UPDATE SET
			available = excluded.available,
			unavailable_reason = excluded.unavailable_reason,
			version = excluded.version,
			binary_path = excluded.binary_path,
			signatures_updated_at = COALESCE(excluded.signatures_updated_at, engine_state.signatures_updated_at),
			last_probe_at = excluded.last_probe_at,
			last_run_at = COALESCE(excluded.last_run_at, engine_state.last_run_at),
			last_run_status = COALESCE(excluded.last_run_status, engine_state.last_run_status)`,
		st.Slug, boolToInt(st.Available), nullString(st.UnavailableReason),
		nullString(st.Version), nullString(st.BinaryPath),
		nullTime(st.SignaturesUpdatedAt), formatTime(orNow(st.LastProbeAt)),
		nullTime(st.LastRunAt), nullString(st.LastRunStatus))
	if err != nil {
		return fmt.Errorf("writing the state of engine %s: %w", st.Slug, err)
	}
	return nil
}

// ListEngineStates returns the state of every known engine.
func (s *Store) ListEngineStates(ctx context.Context) ([]EngineState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT slug, available, unavailable_reason, version, binary_path,
		       signatures_updated_at, last_probe_at, last_run_at, last_run_status
		FROM engine_state ORDER BY slug`)
	if err != nil {
		return nil, fmt.Errorf("listing engines: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []EngineState
	for rows.Next() {
		var (
			st                               EngineState
			available                        int
			reason, version, path, runStatus sql.NullString
			sigUpdated, lastProbe, lastRun   sql.NullString
		)
		if err := rows.Scan(&st.Slug, &available, &reason, &version, &path,
			&sigUpdated, &lastProbe, &lastRun, &runStatus); err != nil {
			return nil, err
		}
		st.Available = available != 0
		st.UnavailableReason = strFromNull(reason)
		st.Version = strFromNull(version)
		st.BinaryPath = strFromNull(path)
		st.SignaturesUpdatedAt = timeFromNull(sigUpdated)
		st.LastProbeAt = timeFromNull(lastProbe)
		st.LastRunAt = timeFromNull(lastRun)
		st.LastRunStatus = strFromNull(runStatus)
		out = append(out, st)
	}
	return out, rows.Err()
}
