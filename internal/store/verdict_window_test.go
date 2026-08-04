package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

func windowStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func at(t *testing.T, st *store.Store, id string, when time.Time) {
	t.Helper()
	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     id,
		FileSHA256:    fmt.Sprintf("%064x", len(id)),
		FilePath:      "/home/u/" + id + ".php",
		Level:         schema.LevelSuspicious,
		Score:         0.5,
		Votes:         []schema.Vote{{Engine: "amwscan", Rule: "r", Weight: 0.8}},
		ActionTaken:   schema.ActionNone,
		ScanID:        "s_" + id,
		CreatedAt:     when,
	}
	if err := st.SaveVerdict(context.Background(), v); err != nil {
		t.Fatalf("saving %s: %v", id, err)
	}
}

// The digest asks for a window. It used to take the most recent N verdicts and compare
// dates afterwards, which fails in the direction that matters: verdicts NEWER than the
// window consume the budget first, so a summary of yesterday sent today could report
// nothing at all for a day that had hundreds.
//
// An empty digest and a digest that never looked read identically to whoever opens it.
func TestTheWindowIsAppliedBeforeTheLimit(t *testing.T) {
	ctx := context.Background()
	st := windowStore(t)

	yesterday := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	today := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	// Three in the window we will ask about...
	for i := 0; i < 3; i++ {
		at(t, st, fmt.Sprintf("old%d", i), yesterday.Add(time.Duration(i)*time.Minute))
	}
	// ...and more, newer, which under the old code would have filled the budget.
	for i := 0; i < 10; i++ {
		at(t, st, fmt.Sprintf("new%d", i), today.Add(time.Duration(i)*time.Minute))
	}

	got, err := st.ListVerdicts(ctx, store.VerdictFilter{
		IncludeClean: true,
		Since:        yesterday.Add(-time.Hour),
		Until:        yesterday.Add(time.Hour),
		Limit:        5,
	})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("the window holds 3 verdicts, the listing returned %d — a summary of that "+
			"period would have reported the wrong number", len(got))
	}
	for _, v := range got {
		if v.CreatedAt.After(yesterday.Add(time.Hour)) {
			t.Errorf("a verdict from outside the window came back: %s at %s",
				v.VerdictID, v.CreatedAt)
		}
	}
}

// An open-ended side means unbounded, so callers that do not care about time keep working.
func TestAnAbsentBoundMeansUnbounded(t *testing.T) {
	ctx := context.Background()
	st := windowStore(t)
	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		at(t, st, fmt.Sprintf("v%d", i), base.Add(time.Duration(i)*time.Hour))
	}

	all, err := st.ListVerdicts(ctx, store.VerdictFilter{IncludeClean: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Errorf("no bounds returned %d of 4", len(all))
	}

	from, err := st.ListVerdicts(ctx, store.VerdictFilter{
		IncludeClean: true, Since: base.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(from) != 2 {
		t.Errorf("an open upper bound returned %d, wanted the 2 at or after the lower one", len(from))
	}
}

// The bound has to compare as an instant, not as whatever the string happens to sort as.
// Timestamps are stored as text and were fixed to nine fractional digits for exactly this
// reason (D-047); a window query is where a variable width would silently drop rows.
func TestTheBoundIsAnInstantNotAStringAccident(t *testing.T) {
	ctx := context.Background()
	st := windowStore(t)
	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	// .900000000 formats shorter than .905504385 under RFC3339Nano, and sorts after it.
	at(t, st, "ninehundred", base.Add(900000000*time.Nanosecond))
	at(t, st, "ninefivefive", base.Add(905504385*time.Nanosecond))

	got, err := st.ListVerdicts(ctx, store.VerdictFilter{
		IncludeClean: true,
		Since:        base.Add(902000000 * time.Nanosecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VerdictID != "ninefivefive" {
		t.Errorf("the window returned %d rows %v; only the later instant is at or after the bound",
			len(got), got)
	}
}
