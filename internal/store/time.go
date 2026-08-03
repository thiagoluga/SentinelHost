package store

import (
	"database/sql"
	"time"
)

// The database stores time as RFC3339 in UTC. Text because the panel, the JSON
// reports and SQLite itself stay readable; UTC because the host can change time
// zone without warning, and an incident history with ambiguous timestamps is
// useless for investigating anything.

// timeLayout is RFC3339 with the fraction pinned to nine digits.
//
// NOT time.RFC3339Nano, which "removes trailing zeros from the seconds field" — its own
// documentation says so. SQLite compares TEXT byte by byte, so a variable-width fraction
// makes the sort disagree with the clock:
//
//	2026-08-03T17:01:23.9Z            is 23.900000000
//	2026-08-03T17:01:23.905504385Z    is 23.905504385, which is LATER
//
// Byte four of the fraction is 'Z' (0x5A) against '0' (0x30), so the earlier instant
// sorts last. A whole second is worse: 23Z has no fraction at all and sorts after every
// fraction in its own second.
//
// Everything resting on "most recent" was therefore wrong for roughly one write in ten,
// silently and unrepeatably: the panel's ordering, LatestVerdictForHash, the collapse
// that picks one row per file (D-046), session expiry, quarantine retention.
//
// Nine digits, always, so lexicographic order is chronological order. Reading still
// accepts the old shape — RFC3339Nano parses any fraction width.
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func nowUTC() string {
	return time.Now().UTC().Format(timeLayout)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
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
