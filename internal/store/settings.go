package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	Slug              string
	Available         bool
	UnavailableReason string
	// Installable reports whether Install() could resolve the unavailability.
	//
	// Stored rather than recomputed because the panel lists engines without probing
	// them, and a button offered on the strength of a guess is a button that returns 400.
	Installable         bool
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
			slug, available, unavailable_reason, installable, version, binary_path,
			signatures_updated_at, last_probe_at, last_run_at, last_run_status
		) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(slug) DO UPDATE SET
			available = excluded.available,
			unavailable_reason = excluded.unavailable_reason,
			installable = excluded.installable,
			version = excluded.version,
			binary_path = excluded.binary_path,
			signatures_updated_at = COALESCE(excluded.signatures_updated_at, engine_state.signatures_updated_at),
			last_probe_at = excluded.last_probe_at,
			last_run_at = COALESCE(excluded.last_run_at, engine_state.last_run_at),
			last_run_status = COALESCE(excluded.last_run_status, engine_state.last_run_status)`,
		st.Slug, boolToInt(st.Available), nullString(st.UnavailableReason),
		boolToInt(st.Installable), nullString(st.Version), nullString(st.BinaryPath),
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
		SELECT slug, available, unavailable_reason, installable, version, binary_path,
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
			available, installable           int
			reason, version, path, runStatus sql.NullString
			sigUpdated, lastProbe, lastRun   sql.NullString
		)
		if err := rows.Scan(&st.Slug, &available, &reason, &installable, &version, &path,
			&sigUpdated, &lastProbe, &lastRun, &runStatus); err != nil {
			return nil, err
		}
		st.Available = available != 0
		st.UnavailableReason = strFromNull(reason)
		st.Installable = installable != 0
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

// Login attempt counting ------------------------------------------------------
//
// The brute-force counter lives here, in SQLite, rather than in a map in process
// memory.
//
// Under `serve` a single process holds every request, so a map would work — and it did.
// It stops working the moment the panel is served any other way: CGI, FastCGI, one
// process per request. There the map is fresh and empty on every attempt, so the
// lock-out silently does not exist while every page behaves exactly as before. Nothing
// in the logs would say the protection had been switched off.
//
// Keeping the count where the sessions already are costs one small query per login and
// removes that whole class of surprise.

const loginAttemptPrefix = "login_attempts:"

// RecentLoginAttempts returns the attempt timestamps for an IP inside the window,
// discarding anything older.
func (s *Store) RecentLoginAttempts(ctx context.Context, ip string, since time.Time) ([]time.Time, error) {
	raw, err := s.GetSetting(ctx, loginAttemptPrefix+ip)
	if err != nil || raw == "" {
		return nil, err
	}
	var out []time.Time
	for _, field := range strings.Split(raw, ",") {
		n, convErr := strconv.ParseInt(field, 10, 64)
		if convErr != nil {
			// A corrupt entry is dropped rather than failing the login path. Losing a
			// count is bad; refusing every login because one row is malformed is worse.
			continue
		}
		if t := time.Unix(n, 0); t.After(since) {
			out = append(out, t)
		}
	}
	return out, nil
}

// RecordLoginAttempt stores the window's attempts for an IP.
//
// An empty list deletes the key instead of writing one. Without that, every IP that ever
// tried once would leave a row behind forever, and the settings table would grow with
// the internet rather than with the account.
func (s *Store) RecordLoginAttempt(ctx context.Context, ip string, attempts []time.Time) error {
	if len(attempts) == 0 {
		return s.DeleteSetting(ctx, loginAttemptPrefix+ip)
	}
	parts := make([]string, 0, len(attempts))
	for _, t := range attempts {
		parts = append(parts, strconv.FormatInt(t.Unix(), 10))
	}
	return s.SetSetting(ctx, loginAttemptPrefix+ip, strings.Join(parts, ","))
}

// ClearLoginAttempts forgets an IP, called after a successful login.
func (s *Store) ClearLoginAttempts(ctx context.Context, ip string) error {
	return s.DeleteSetting(ctx, loginAttemptPrefix+ip)
}

// PruneLoginAttempts removes counters whose last write is older than the cutoff.
//
// The delete-when-empty rule above covers an IP that comes back; this covers the one
// that never does.
func (s *Store) PruneLoginAttempts(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM settings WHERE key LIKE ? AND updated_at < ?`,
		loginAttemptPrefix+"%", olderThan.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("pruning login attempts: %w", err)
	}
	return res.RowsAffected()
}
