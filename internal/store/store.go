// Package store keeps SentinelHost's state in SQLite.
//
// Driver: modernc.org/sqlite (pure Go). The binary has to be static and free of
// CGO to run on any shared hosting account (Principle VII), which rules out
// mattn/go-sqlite3.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // the "sqlite" driver
)

// Store is the connection to the state database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the database at the given path and applies any
// pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	// _busy_timeout: the panel and the scan cycle write to the same database.
	// Without a timeout a concurrent write would return SQLITE_BUSY immediately
	// instead of waiting — and losing the record of a quarantine to a lock is
	// unacceptable.
	// WAL: a read from the panel does not block the cycle's write.
	dsn := path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// SQLite gains nothing from many write connections and loses on lock
	// contention.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connecting to the database: %w", err)
	}

	s := &Store{db: db, path: path}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrating the database: %w", err)
	}

	// The database holds the panel's password hash and session secrets.
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		return s, fmt.Errorf("adjusting database permissions: %w", err)
	}
	return s, nil
}

// Close closes the connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB exposes the connection for cases that need raw SQL (panel reports). Writes
// should go through the DAOs.
func (s *Store) DB() *sql.DB { return s.db }

// Path returns the database file's path.
func (s *Store) Path() string { return s.path }

// tx runs fn inside a transaction, rolling back on error or panic.
//
// Consolidating it here guarantees no quarantine write is left half done: moving
// the file and recording the item have to be all or nothing, otherwise there is
// a file in the vault with no record of how to restore it.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = t.Rollback()
			panic(p)
		}
	}()
	if err := fn(t); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Commit()
}
