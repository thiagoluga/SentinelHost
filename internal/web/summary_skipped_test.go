package web

import "testing"

// A record that cannot say what it missed must not answer "nothing".
//
// The dashboard forwards two coverage maps out of the stored scan summary. Both can be
// legitimately empty — a cycle really did miss nothing — and both can be absent, because
// the record was written before the field existed. Rendered the same, the second becomes a
// reassuring zero produced by a row that was never able to make the claim.
//
// This is the same distinction the scanner draws between an engine that abstained and an
// engine that found nothing, applied to the panel: unexamined and absent must never read
// the same.
func TestAnAbsentKeyIsNotAnEmptyResult(t *testing.T) {
	cases := []struct {
		name    string
		summary map[string]any
		key     string
		wantNil bool
	}{
		{
			name:    "a cycle that really missed nothing",
			summary: map[string]any{"engines_skipped": map[string]any{}},
			key:     "engines_skipped",
			wantNil: false,
		},
		{
			name:    "a record written before the field existed",
			summary: map[string]any{"files_scanned": float64(3)},
			key:     "engines_skipped",
			wantNil: true,
		},
		{
			name:    "no summary at all",
			summary: nil,
			key:     "engines_skipped",
			wantNil: true,
		},
		{
			name:    "the key is there but holds something unreadable",
			summary: map[string]any{"engines_skipped": "not an object"},
			key:     "engines_skipped",
			wantNil: true,
		},
		{
			name:    "the key is there and explicitly null",
			summary: map[string]any{"engines_skipped": nil},
			key:     "engines_skipped",
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := summaryMap(tc.summary, tc.key)
			if tc.wantNil && got != nil {
				t.Errorf("got %v, wanted nil — the panel would render this as "+
					"'nothing was missed' on the authority of a record that cannot say so", got)
			}
			if !tc.wantNil && got == nil {
				t.Errorf("got nil, wanted an empty object — the cycle DID report, and " +
					"'not recorded' understates what is known")
			}
		})
	}
}

// The real shape survives the round trip through SQLite's JSON.
//
// Nothing typed comes back out: engines_skipped goes in as map[string]map[string]int and
// returns as map[string]any of map[string]any of float64. A helper that type-asserted the
// original shape would answer nil for every stored cycle and the panel would report
// "not recorded" forever — passing its own test while telling every user nothing is known.
func TestTheShapeThatComesBackFromTheDatabase(t *testing.T) {
	summary := map[string]any{
		"engines_skipped": map[string]any{
			"maldet": map[string]any{"unscannable_path_name": float64(1)},
		},
	}

	got := summaryMap(summary, "engines_skipped")
	if got == nil {
		t.Fatal("nil for a summary that plainly carries the field")
	}

	maldet, ok := got["maldet"].(map[string]any)
	if !ok {
		t.Fatalf("maldet came back as %T", got["maldet"])
	}
	if n, _ := maldet["unscannable_path_name"].(float64); n != 1 {
		t.Errorf("the count is %v, wanted 1", maldet["unscannable_path_name"])
	}
}
