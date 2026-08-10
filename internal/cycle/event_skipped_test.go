package cycle_test

import (
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// The machine interface has to say what the terminal says.
//
// Found by running the real binary against a payload whose filename contains a newline —
// the evasion this project already closed once. The terminal printed
//
//	skipped: unscannable_path_name=1
//
// and the JSON from the same scan said `"skipped": {}`, `"status": "completed"`,
// `"files_scanned": 2`. That object is not a display detail: it is what `scan --json`
// prints, what the scan.completed webhook carries, and what gets written to the database.
// Three machine consumers were told a file nobody could open had been looked at.
//
// D-031 recorded this same divergence in this same summary, found the same way: "by looking at
// the JSON at all. The text output had been correct this whole session and I had read it a
// dozen times; the machine interface next to it was saying the opposite thing, and nothing
// checked that the two agreed." Nothing checked this time either — so this test exists to
// be the thing that checks.
func TestTheEventCarriesWhatTheEnginesCouldNotLookAt(t *testing.T) {
	sum := cycle.Summary{
		ScanID: "s_1",
		Mode:   schema.ModeFull,
		Status: schema.StatusCompleted,
		Engines: []cycle.EngineOutcome{
			{
				Slug:      "maldet",
				Available: true,
				Status:    schema.StatusCompleted,
				Skipped:   map[string]int{"unscannable_path_name": 1},
			},
		},
	}

	ev := sum.Event()

	skipped, ok := ev["engines_skipped"].(map[string]map[string]int)
	if !ok {
		t.Fatalf("engines_skipped is %T, wanted a map of engine to reason counts", ev["engines_skipped"])
	}
	if n := skipped["maldet"]["unscannable_path_name"]; n != 1 {
		t.Errorf("engines_skipped = %v; a file no engine could be asked about has to reach "+
			"the machine interface, or a monitor reads `completed` and stops looking", skipped)
	}

	// The engine still counts as having run — it did, over everything it could be given.
	// Losing that would swap one wrong answer for another.
	ran, _ := ev["engines_ran"].([]string)
	if len(ran) != 1 || ran[0] != "maldet" {
		t.Errorf("engines_ran = %v, wanted [maldet]", ran)
	}
}

// A file refused by three engines is one file the cycle did not look at, not three.
//
// Which is why these are not summed into the walker's `skipped`: that number would grow
// with however many engines happen to be installed, and a count that moves for reasons
// unrelated to the site is a count nobody can act on.
func TestEngineSkipsAreAttributedRatherThanSummed(t *testing.T) {
	sum := cycle.Summary{
		ScanID:        "s_1",
		Status:        schema.StatusCompleted,
		SkippedCounts: map[string]int{"too_large": 4},
		Engines: []cycle.EngineOutcome{
			{Slug: "maldet", Available: true, Status: schema.StatusCompleted,
				Skipped: map[string]int{"unscannable_path_name": 1}},
			{Slug: "php-malware-finder", Available: true, Status: schema.StatusCompleted,
				Skipped: map[string]int{"unscannable_path_name": 1}},
			{Slug: "amwscan", Available: true, Status: schema.StatusCompleted,
				Skipped: map[string]int{"unscannable_path_name": 1}},
		},
	}

	ev := sum.Event()

	walker, _ := ev["skipped"].(map[string]int)
	if walker["unscannable_path_name"] != 0 {
		t.Errorf("the walker's skipped picked up an engine's reason: %v", walker)
	}
	if walker["too_large"] != 4 {
		t.Errorf("the walker's own counts were disturbed: %v", walker)
	}

	skipped, _ := ev["engines_skipped"].(map[string]map[string]int)
	if len(skipped) != 3 {
		t.Fatalf("engines_skipped has %d engine(s), wanted 3: %v", len(skipped), skipped)
	}
	for _, slug := range []string{"maldet", "php-malware-finder", "amwscan"} {
		if skipped[slug]["unscannable_path_name"] != 1 {
			t.Errorf("%s reports %v; each engine states its own refusal", slug, skipped[slug])
		}
	}
}

// An engine with nothing to report does not appear, so the field stays readable.
func TestAnEngineThatSkippedNothingIsAbsent(t *testing.T) {
	sum := cycle.Summary{
		ScanID: "s_1",
		Status: schema.StatusCompleted,
		Engines: []cycle.EngineOutcome{
			{Slug: "maldet", Available: true, Status: schema.StatusCompleted},
		},
	}

	skipped, _ := sum.Event()["engines_skipped"].(map[string]map[string]int)
	if len(skipped) != 0 {
		t.Errorf("engines_skipped = %v, wanted empty; a cycle that missed nothing should "+
			"not have to be read to discover that", skipped)
	}
}
