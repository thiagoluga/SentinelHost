package store

import (
	"testing"
	"time"
)

// SQLite compares TEXT byte by byte, so the stored form has to sort the way the clock
// does. time.RFC3339Nano does not: its documentation says it "removes trailing zeros from
// the seconds field", which makes the fraction variable-width.
//
//	2026-08-03T17:01:23.9Z          is .900000000
//	2026-08-03T17:01:23.905504385Z  is .905504385, and LATER
//
// Compared as text, byte four of the fraction is 'Z' (0x5A) against '0' (0x30), so the
// earlier instant sorts last. Everything resting on "most recent" was wrong for roughly
// one write in ten — the panel's ordering, LatestVerdictForHash, the one-row-per-file
// collapse — silently, and never the same way twice.
func TestStoredTimestampsSortChronologically(t *testing.T) {
	base := time.Date(2026, 8, 3, 17, 1, 23, 0, time.UTC)

	instants := []time.Time{
		base,                                  // .000000000 — no fraction under RFC3339Nano
		base.Add(500 * time.Millisecond),      // .500000000 — trimmed to .5
		base.Add(900 * time.Millisecond),      // .900000000 — trimmed to .9
		base.Add(905504385 * time.Nanosecond), // .905504385 — full width
		base.Add(999999999 * time.Nanosecond), // .999999999
		base.Add(time.Second),                 // the next second
	}

	for i := 0; i < len(instants)-1; i++ {
		earlier, later := instants[i], instants[i+1]
		a, b := formatTime(earlier), formatTime(later)
		if !(a < b) {
			t.Errorf("%v is before %v, but the stored forms sort the other way:\n  %q\n  %q",
				earlier.Format(time.RFC3339Nano), later.Format(time.RFC3339Nano), a, b)
		}
	}
}

// Every stored timestamp is the same width, which is what makes the comparison above
// hold for any pair rather than only the ones this test happens to list.
func TestEveryStoredTimestampIsTheSameWidth(t *testing.T) {
	base := time.Date(2026, 8, 3, 17, 1, 23, 0, time.UTC)
	want := len(formatTime(base))

	for _, ns := range []int{0, 1, 9, 90, 900, 500000000, 905504385, 999999999} {
		got := formatTime(base.Add(time.Duration(ns)))
		if len(got) != want {
			t.Errorf("%q is %d bytes, others are %d — a mixed width sorts wrongly at the "+
				"boundary between the two", got, len(got), want)
		}
	}
}

// Reading has to keep accepting what earlier versions wrote, or every timestamp already
// on disk becomes the zero time — which reads as "never happened".
func TestParsingStillAcceptsTheOldTrimmedForm(t *testing.T) {
	for _, s := range []string{
		"2026-08-03T17:01:23Z",
		"2026-08-03T17:01:23.9Z",
		"2026-08-03T17:01:23.905504385Z",
		"2026-08-03T17:01:23.000000000Z",
	} {
		if got := parseTime(s); got.IsZero() {
			t.Errorf("%q parsed as the zero time, which the panel shows as never", s)
		}
	}
}

// An empty string is "never happened" and must stay that way, rather than becoming a
// real-looking instant in year zero.
func TestTheZeroTimeStaysEmpty(t *testing.T) {
	if got := formatTime(time.Time{}); got != "" {
		t.Errorf("the zero time formatted as %q", got)
	}
	if !parseTime("").IsZero() {
		t.Error("an empty string parsed as a real instant")
	}
}
