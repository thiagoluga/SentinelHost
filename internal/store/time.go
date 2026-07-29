package store

import (
	"database/sql"
	"time"
)

// The database stores time as RFC3339 in UTC. Text because the panel, the JSON
// reports and SQLite itself stay readable; UTC because the host can change time
// zone without warning, and an incident history with ambiguous timestamps is
// useless for investigating anything.

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// nullTime turns a zero time into NULL, so that "never happened" and "happened
// in year zero" do not become the same thing in the database.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return formatTime(t)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func timeFromNull(ns sql.NullString) time.Time {
	if !ns.Valid {
		return time.Time{}
	}
	return parseTime(ns.String)
}

func strFromNull(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
