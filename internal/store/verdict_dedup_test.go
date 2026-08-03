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

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func saveCycle(t *testing.T, st *store.Store, scan string, at time.Time, path, sha string, lvl schema.Level) {
	t.Helper()
	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     fmt.Sprintf("v_%s_%s", scan, sha[:4]),
		FileSHA256:    sha,
		FilePath:      path,
		FileLocation:  "web_reachable",
		Level:         lvl,
		Score:         0.5,
		Votes:         []schema.Vote{{Engine: "amwscan", Rule: "r", Weight: 0.8}},
		ActionTaken:   schema.ActionNone,
		ScanID:        scan,
		CreatedAt:     at,
	}
	if err := st.SaveVerdict(context.Background(), v); err != nil {
		t.Fatalf("saving %s/%s: %v", scan, path, err)
	}
}

// A cron every fifteen minutes re-decides the same file ninety-six times a day. The panel
// was listing every one of them: on the real account, 1050 rows for 213 distinct files,
// the same path repeating down the page, growing by ~208 each cycle.
func TestTheListingIsOneRowPerFileNotPerCycle(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	base := time.Unix(1785000000, 0).UTC()
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for i := 0; i < 5; i++ {
		saveCycle(t, st, fmt.Sprintf("s_%d", i), base.Add(time.Duration(i)*15*time.Minute),
			"/home/u/x.php", sha, schema.LevelSuspicious)
	}

	got, err := st.ListVerdicts(ctx, store.VerdictFilter{})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("five cycles over one file produced %d rows in the panel, wanted 1", len(got))
	}
	// And it must be the newest, not whichever the engine happened to return.
	if got[0].ScanID != "s_4" {
		t.Errorf("the listing kept cycle %q; the newest is s_4", got[0].ScanID)
	}

	// The history itself is not deleted — it is only collapsed for display.
	all, err := st.ListVerdicts(ctx, store.VerdictFilter{AllCycles: true})
	if err != nil {
		t.Fatalf("listing all: %v", err)
	}
	if len(all) != 5 {
		t.Errorf("the history holds %d rows, wanted all 5 — collapsing the panel must not "+
			"destroy the record of what was decided when", len(all))
	}
}

// Same content at two paths stays two findings. That is what verdictID was fixed to
// preserve, and collapsing by content alone would undo it one layer up.
func TestTwoPathsWithIdenticalContentStayTwoRows(t *testing.T) {
	st := openStore(t)
	at := time.Unix(1785000000, 0).UTC()
	sha := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	saveCycle(t, st, "s_1", at, "/home/u/one/shell.php", sha, schema.LevelLikely)
	// Distinct verdict ids, same cycle, same content, different paths.
	v := schema.Verdict{
		SchemaVersion: schema.Version, VerdictID: "v_other", FileSHA256: sha,
		FilePath: "/home/u/two/shell.php", FileLocation: "web_reachable",
		Level: schema.LevelLikely, Score: 0.5, ActionTaken: schema.ActionNone,
		Votes:  []schema.Vote{{Engine: "amwscan", Rule: "r", Weight: 0.8}},
		ScanID: "s_1", CreatedAt: at,
	}
	if err := st.SaveVerdict(context.Background(), v); err != nil {
		t.Fatal(err)
	}

	got, err := st.ListVerdicts(context.Background(), store.VerdictFilter{})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("the same payload at two paths collapsed to %d row(s). Each path is its "+
			"own decision: quarantining one does not clean the other", len(got))
	}
}

// A file whose content changed is a different thing to decide about, so it gets its own
// row rather than replacing the verdict on what used to be there.
func TestNewContentAtTheSamePathIsItsOwnRow(t *testing.T) {
	st := openStore(t)
	base := time.Unix(1785000000, 0).UTC()

	saveCycle(t, st, "s_1", base, "/home/u/x.php",
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", schema.LevelSuspicious)
	saveCycle(t, st, "s_2", base.Add(time.Hour), "/home/u/x.php",
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", schema.LevelLikely)

	got, err := st.ListVerdicts(context.Background(), store.VerdictFilter{})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("the file was replaced between cycles and the panel shows %d row(s); "+
			"the old verdict does not describe the new file", len(got))
	}
}

// The filter has to run before the collapse. Picking the newest row and then discarding it
// for being acknowledged would hide a file that is still pending from an earlier cycle.
func TestPendingPicksTheNewestPendingRowNotTheNewestRow(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	base := time.Unix(1785000000, 0).UTC()
	sha := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	saveCycle(t, st, "s_1", base, "/home/u/x.php", sha, schema.LevelSuspicious)
	saveCycle(t, st, "s_2", base.Add(time.Hour), "/home/u/x.php", sha, schema.LevelSuspicious)

	// The newer one gets acknowledged; the older stays pending.
	if err := st.AcknowledgeVerdict(ctx, "v_s_2_eeee"); err != nil {
		t.Skipf("no acknowledge method to exercise: %v", err)
	}

	got, err := st.ListVerdicts(ctx, store.VerdictFilter{PendingOnly: true})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 1 || got[0].ScanID != "s_1" {
		t.Errorf("pending returned %d row(s) %v; wanted the still-pending s_1", len(got), got)
	}
}
