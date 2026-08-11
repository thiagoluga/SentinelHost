package cycle

import (
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// A note is not a gap, and the summary has to keep them apart.
//
// Found by reading a real account's cycle rather than a fixture. It reported
//
//	skipped: outside_requested_scope=853, unknown_rule=260
//
// which announces 1113 unexamined files. Not one of them was unexamined: the 260 are
// findings sitting in the report under a generic category, and the 853 are paths the
// orchestrator never asked about. Both counts belong somewhere — nothing an engine reports
// gets discarded — but not in the field whose entire job is answering "what did the scan
// NOT look at".
//
// wpchecksums had already learned this and had "plugin_verified" taken out of that map for
// the same reason. Two other adapters were still doing it.
func TestNotesTravelSeparatelyFromGaps(t *testing.T) {
	sum := Summary{
		ScanID: "s_1",
		Status: schema.StatusCompleted,
		Engines: []EngineOutcome{
			{
				Slug: "amwscan", Available: true, Status: schema.StatusCompleted,
				Skipped: map[string]int{"vanished_before_hashing": 2},
				Notes:   map[string]int{"unknown_rule": 260, "outside_requested_scope": 853},
			},
		},
	}

	ev := sum.Event()

	skipped, _ := ev["engines_skipped"].(map[string]map[string]int)
	if skipped["amwscan"]["vanished_before_hashing"] != 2 {
		t.Errorf("a real gap went missing: %v", skipped)
	}
	for _, note := range []string{"unknown_rule", "outside_requested_scope"} {
		if n, ok := skipped["amwscan"][note]; ok {
			t.Errorf("%s = %d is in engines_skipped; a reader of that field concludes "+
				"coverage was lost and goes looking for files that were never missing",
				note, n)
		}
	}

	notes, ok := ev["engines_notes"].(map[string]map[string]int)
	if !ok {
		t.Fatalf("engines_notes is %T; bookkeeping that reaches nobody gets maintained "+
			"by nobody", ev["engines_notes"])
	}
	if notes["amwscan"]["unknown_rule"] != 260 {
		t.Errorf("the unmapped-rule count did not survive: %v", notes)
	}
	if notes["amwscan"]["outside_requested_scope"] != 853 {
		t.Errorf("the out-of-scope count did not survive: %v", notes)
	}
}

// An engine with notes but no gaps must not appear in engines_skipped at all.
//
// Otherwise a monitor keying off "is engines_skipped non-empty" fires on a cycle that
// missed nothing — and an alert that cries wolf is one its reader turns off.
func TestNotesAloneDoNotCreateAGap(t *testing.T) {
	sum := Summary{
		ScanID: "s_1",
		Status: schema.StatusCompleted,
		Engines: []EngineOutcome{
			{
				Slug: "php-malware-finder", Available: true, Status: schema.StatusCompleted,
				Notes: map[string]int{"unknown_rule": 12},
			},
		},
	}

	ev := sum.Event()

	skipped, _ := ev["engines_skipped"].(map[string]map[string]int)
	if len(skipped) != 0 {
		t.Errorf("engines_skipped = %v, wanted empty: this cycle missed nothing", skipped)
	}
	notes, _ := ev["engines_notes"].(map[string]map[string]int)
	if notes["php-malware-finder"]["unknown_rule"] != 12 {
		t.Errorf("the note was dropped instead: %v", notes)
	}
}

// The merge across an engine's partial reports must carry notes too.
//
// An engine that runs once per file produces one report per file, and mergeReports folds
// them into one. Notes not folded there would vanish before anything downstream could
// separate them from gaps — the silent discard, applied to the half of the accounting
// nobody thinks about.
func TestTheMergeCarriesNotesAcrossPartialReports(t *testing.T) {
	partials := []schema.ScanReport{
		{Scope: schema.Scope{
			NoteCounts:          map[string]int{"unknown_rule": 3},
			SkippedReasonCounts: map[string]int{"vanished_before_hashing": 1},
		}},
		{Scope: schema.Scope{
			NoteCounts: map[string]int{"unknown_rule": 4, "outside_requested_scope": 10},
		}},
	}

	out := mergeReports("s_1", "amwscan", "1.0", partials, "/root", schema.ModeFull)

	if got := out.Scope.NoteCounts["unknown_rule"]; got != 7 {
		t.Errorf("unknown_rule = %d across two reports, wanted 7: %v", got, out.Scope.NoteCounts)
	}
	if got := out.Scope.NoteCounts["outside_requested_scope"]; got != 10 {
		t.Errorf("outside_requested_scope = %d, wanted 10: %v", got, out.Scope.NoteCounts)
	}
	if got := out.Scope.SkippedReasonCounts["vanished_before_hashing"]; got != 1 {
		t.Errorf("the real gap did not survive the merge: %v", out.Scope.SkippedReasonCounts)
	}
	if _, ok := out.Scope.SkippedReasonCounts["unknown_rule"]; ok {
		t.Errorf("the merge put a note into the gap map: %v", out.Scope.SkippedReasonCounts)
	}
}
