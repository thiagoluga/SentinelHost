package store

import (
	"context"
	"database/sql"
	"fmt"
)

// migration is one versioned step of the database schema.
//
// Migrations are applied in order and never edited once published: a user who
// upgrades the binary has to end up with exactly the same schema as someone
// installing from scratch.
type migration struct {
	version int
	name    string
	stmts   []string
}

var migrations = []migration{
	{
		version: 1,
		name:    "initial schema",
		stmts: []string{
			// Scan cycles ----------------------------------------------------
			`CREATE TABLE scans (
				scan_id           TEXT PRIMARY KEY,
				mode              TEXT NOT NULL,
				roots             TEXT NOT NULL,
				started_at        TEXT NOT NULL,
				finished_at       TEXT,
				status            TEXT NOT NULL,
				files_considered  INTEGER NOT NULL DEFAULT 0,
				files_scanned     INTEGER NOT NULL DEFAULT 0,
				summary_json      TEXT
			)`,
			`CREATE INDEX idx_scans_started ON scans(started_at DESC)`,

			// One report per engine. Stored whole so the panel can show WHY an
			// engine did not contribute to a cycle.
			`CREATE TABLE scan_reports (
				id            INTEGER PRIMARY KEY AUTOINCREMENT,
				scan_id       TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
				engine        TEXT NOT NULL,
				engine_version TEXT,
				status        TEXT NOT NULL,
				error         TEXT,
				started_at    TEXT,
				finished_at   TEXT,
				wall_seconds  REAL NOT NULL DEFAULT 0,
				max_rss_mb    INTEGER NOT NULL DEFAULT 0,
				findings_count INTEGER NOT NULL DEFAULT 0,
				raw_ref       TEXT,
				report_json   TEXT NOT NULL
			)`,
			`CREATE INDEX idx_reports_scan ON scan_reports(scan_id)`,
			`CREATE INDEX idx_reports_engine_status ON scan_reports(engine, status)`,

			// Individual findings ---------------------------------------------
			`CREATE TABLE findings (
				id             TEXT PRIMARY KEY,
				scan_id        TEXT NOT NULL,
				engine         TEXT NOT NULL,
				kind           TEXT NOT NULL DEFAULT 'malware',
				rule           TEXT NOT NULL,
				file_sha256    TEXT NOT NULL,
				file_path      TEXT NOT NULL,
				category       TEXT NOT NULL,
				severity       TEXT NOT NULL,
				confidence     TEXT NOT NULL,
				matched_content TEXT,
				matched_offset INTEGER,
				detected_at    TEXT NOT NULL,
				finding_json   TEXT NOT NULL
			)`,
			// The sha256 index is what makes cross-engine deduplication cheap —
			// the central operation of the consensus.
			`CREATE INDEX idx_findings_sha ON findings(file_sha256)`,
			`CREATE INDEX idx_findings_scan ON findings(scan_id)`,

			// Consolidated verdicts --------------------------------------------
			`CREATE TABLE verdicts (
				verdict_id      TEXT PRIMARY KEY,
				file_sha256     TEXT NOT NULL,
				file_path       TEXT NOT NULL,
				file_size       INTEGER NOT NULL DEFAULT 0,
				level           TEXT NOT NULL,
				score           REAL NOT NULL,
				votes_json      TEXT NOT NULL,
				abstentions_json TEXT,
				clean_reason    TEXT,
				action_taken    TEXT NOT NULL DEFAULT 'none',
				action_at       TEXT,
				action_error    TEXT,
				quarantine_ref  TEXT,
				acknowledged_by_user INTEGER NOT NULL DEFAULT 0,
				acknowledged_at TEXT,
				scan_id         TEXT NOT NULL,
				created_at      TEXT NOT NULL,
				updated_at      TEXT NOT NULL
			)`,
			`CREATE INDEX idx_verdicts_level ON verdicts(level, created_at DESC)`,
			`CREATE INDEX idx_verdicts_sha ON verdicts(file_sha256)`,
			`CREATE INDEX idx_verdicts_scan ON verdicts(scan_id)`,
			`CREATE INDEX idx_verdicts_pending ON verdicts(acknowledged_by_user, level)`,

			// Quarantine vault ---------------------------------------------------
			// This is the table that makes the action reversible. Without it the
			// file in the vault is undecipherable garbage: there is no way to
			// know where it came from or what permissions to restore.
			`CREATE TABLE quarantine_items (
				ref             TEXT PRIMARY KEY,
				verdict_id      TEXT,
				original_path   TEXT NOT NULL,
				vault_path      TEXT NOT NULL,
				sha256          TEXT NOT NULL,
				size_bytes      INTEGER NOT NULL,
				perms           TEXT NOT NULL,
				owner           TEXT,
				original_mtime  TEXT,
				quarantined_at  TEXT NOT NULL,
				retention_until TEXT,
				status          TEXT NOT NULL DEFAULT 'quarantined',
				restored_at     TEXT,
				restored_to     TEXT,
				purged_at       TEXT,
				note            TEXT
			)`,
			`CREATE INDEX idx_quarantine_status ON quarantine_items(status, quarantined_at DESC)`,
			`CREATE INDEX idx_quarantine_retention ON quarantine_items(status, retention_until)`,

			// Alert deliveries ----------------------------------------------------
			`CREATE TABLE deliveries (
				delivery_id   TEXT PRIMARY KEY,
				channel       TEXT NOT NULL,
				target        TEXT NOT NULL,
				event         TEXT NOT NULL,
				payload_json  TEXT NOT NULL,
				status        TEXT NOT NULL,
				attempts      INTEGER NOT NULL DEFAULT 0,
				http_status   INTEGER,
				error         TEXT,
				created_at    TEXT NOT NULL,
				last_attempt_at TEXT,
				next_attempt_at TEXT,
				delivered_at  TEXT
			)`,
			`CREATE INDEX idx_deliveries_pending ON deliveries(status, next_attempt_at)`,
			`CREATE INDEX idx_deliveries_target ON deliveries(channel, target, created_at DESC)`,

			// Structured log (FR-015) ----------------------------------------------
			`CREATE TABLE events (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				ts          TEXT NOT NULL,
				level       TEXT NOT NULL,
				category    TEXT NOT NULL,
				message     TEXT NOT NULL,
				fields_json TEXT,
				scan_id     TEXT,
				verdict_id  TEXT
			)`,
			`CREATE INDEX idx_events_ts ON events(ts DESC)`,
			`CREATE INDEX idx_events_category ON events(category, ts DESC)`,

			// Internal configuration that does NOT belong in the TOML: the
			// panel's password hash, the instance id, the session secret. A
			// derived secret does not go into a readable file the user edits.
			`CREATE TABLE settings (
				key        TEXT PRIMARY KEY,
				value      TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,

			`CREATE TABLE sessions (
				token      TEXT PRIMARY KEY,
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				user_agent TEXT,
				remote_ip  TEXT
			)`,
			`CREATE INDEX idx_sessions_expiry ON sessions(expires_at)`,

			// Engine state: last version seen, signature date, reason for being
			// unavailable.
			`CREATE TABLE engine_state (
				slug                  TEXT PRIMARY KEY,
				available             INTEGER NOT NULL DEFAULT 0,
				unavailable_reason    TEXT,
				version               TEXT,
				binary_path           TEXT,
				signatures_updated_at TEXT,
				last_probe_at         TEXT,
				last_run_at           TEXT,
				last_run_status       TEXT
			)`,
		},
	},
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating the migrations table: %w", err)
	}

	var current int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("reading the schema version: %w", err)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration applies a whole step inside a transaction: either the schema
// moves forward completely, or it stays exactly where it was. A half-migrated
// database would be worse than an old one.
func (s *Store) applyMigration(ctx context.Context, m migration) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		for i, stmt := range m.stmts {
			if _, err := t.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migration %d (%s), statement %d: %w", m.version, m.name, i+1, err)
			}
		}
		_, err := t.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
			m.version, m.name, nowUTC())
		if err != nil {
			return fmt.Errorf("recording migration %d: %w", m.version, err)
		}
		return nil
	})
}

// SchemaVersion returns the applied database schema version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}
