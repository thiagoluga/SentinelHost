package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// The location has to survive the database.
//
// It was computed on every cycle and printed by the CLI — and the verdicts table had no
// column for it, so it was dropped on the way to disk. The panel reads from the store,
// so every finding arrived unclassified however carefully the scan had worked it out, and
// the whole reachability feature was invisible to the person it was built for.
//
// Nothing failed. The CLI was right, the panel was empty, and the two never compared
// notes — which is why this test writes and reads back rather than checking either side
// on its own.
func TestTheLocationSurvivesTheDatabase(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	for _, loc := range []string{"web_reachable", "trash", "outside_docroot", "unknown"} {
		v := schema.Verdict{
			SchemaVersion: schema.Version,
			VerdictID:     "v_" + loc,
			FileSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			FilePath:      "/home/u/x.php",
			FileLocation:  loc,
			Level:         schema.LevelSuspicious,
			Score:         0.32,
			Votes:         []schema.Vote{{Engine: "amwscan", Rule: "r", Weight: 0.8}},
			ScanID:        "s_1",
			CreatedAt:     time.Unix(1785000000, 0),
		}
		if err := st.SaveVerdict(ctx, v); err != nil {
			t.Fatalf("saving %s: %v", loc, err)
		}

		got, err := st.GetVerdict(ctx, v.VerdictID)
		if err != nil {
			t.Fatalf("reading %s back: %v", loc, err)
		}
		if got.FileLocation != loc {
			t.Errorf("wrote %q and read back %q — the classification never reaches the panel",
				loc, got.FileLocation)
		}
	}
}

// A verdict decided before the classification existed keeps no location, and must not be
// given one. Inventing it would assert something nobody measured; the panel has a group
// that says exactly that instead.
func TestAVerdictWithoutALocationStaysWithoutOne(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     "v_old",
		FileSHA256:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		FilePath:      "/home/u/y.php",
		Level:         schema.LevelLikely,
		Score:         0.75,
		Votes:         []schema.Vote{{Engine: "wp-checksums", Rule: "r", Weight: 1.5}},
		ScanID:        "s_1",
		CreatedAt:     time.Unix(1785000000, 0),
	}
	if err := st.SaveVerdict(ctx, v); err != nil {
		t.Fatalf("saving: %v", err)
	}
	got, err := st.GetVerdict(ctx, "v_old")
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if got.FileLocation != "" {
		t.Errorf("an unclassified verdict came back as %q", got.FileLocation)
	}
}
