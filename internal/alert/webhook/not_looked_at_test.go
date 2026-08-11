package webhook

import (
	"strings"
	"testing"
)

// The alert is the surface that wakes somebody up, and it was reporting the two numbers
// that look reassuring together.
//
// "2 scanned of 2 considered" says every file considered was scanned. With a filename no
// engine can be passed as an argument, that file is considered, counted as scanned, and
// handed to nobody — so the line is true about the walk and false about the coverage.
// D-054 put this in the JSON and D-055 on the panel; an operator reading Slack at 3 a.m.
// was still being told the cycle looked at everything.
func TestTheAlertSaysWhatWasNotLookedAt(t *testing.T) {
	env := sampleEnvelope()
	env.Event = "scan.completed"
	env.Data = map[string]any{
		"status": "completed", "mode": "full",
		"files_scanned": 2, "files_considered": 2,
		"engines_skipped": map[string]any{
			"maldet": map[string]any{"unscannable_path_name": 1},
		},
	}

	b, err := Body("slack", env)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	text := decode(t, b)["text"].(string)

	if !strings.Contains(text, "not looked at") {
		t.Fatalf("the alert never mentions what went unexamined:\n%s", text)
	}
	if !strings.Contains(text, "maldet") {
		t.Errorf("the engine that could not be asked is not named:\n%s", text)
	}
	// The reason is the actionable half: "1 skipped" says something is wrong, "unscannable
	// path name" says what to go and look at.
	if !strings.Contains(text, "unscannable path name") {
		t.Errorf("the reason is missing, so the reader has a number and nowhere to go:\n%s", text)
	}
}

// A cycle that missed nothing says nothing, so the line keeps its meaning.
//
// "not looked at: nothing" on every alert trains the reader to skip the line on the one
// occasion it is not empty.
func TestNoLineWhenNothingWasMissed(t *testing.T) {
	env := sampleEnvelope()
	env.Event = "scan.completed"
	env.Data = map[string]any{
		"status": "completed", "mode": "incremental",
		"files_scanned": 412, "files_considered": 18234,
		"skipped":         map[string]any{},
		"engines_skipped": map[string]any{},
	}

	b, _ := Body("slack", env)
	text := decode(t, b)["text"].(string)

	if strings.Contains(text, "not looked at") {
		t.Errorf("a clean cycle should not carry the line at all:\n%s", text)
	}
}

// Both kinds are reported, side by side, never summed.
//
// A file the walk never handed on is unexamined; a file one engine could not be asked
// about may still have been examined by another. One total would be true of neither.
func TestWalkSkipsAndEngineSkipsAreBothNamed(t *testing.T) {
	env := sampleEnvelope()
	env.Event = "scan.completed"
	env.Data = map[string]any{
		"status": "completed", "mode": "full",
		"files_scanned": 100, "files_considered": 106,
		"skipped": map[string]any{"too_large": 4},
		"engines_skipped": map[string]any{
			"maldet":             map[string]any{"unscannable_path_name": 1},
			"php-malware-finder": map[string]any{"unscannable_path_name": 1},
		},
	}

	b, _ := Body("slack", env)
	text := decode(t, b)["text"].(string)

	for _, want := range []string{
		"4 skipped by the walk (too large)",
		"1 maldet could not be asked about",
		"1 php-malware-finder could not be asked about",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "6 skipped") || strings.Contains(text, "2 could not") {
		t.Errorf("the counts were summed; two engines refusing one path is not two "+
			"files:\n%s", text)
	}
}

// The engines are listed in a stable order.
//
// A message whose lines reorder between cycles cannot be diffed against the last one,
// which is how an operator notices that something changed.
func TestTheEngineOrderIsStable(t *testing.T) {
	data := map[string]any{
		"status": "completed", "mode": "full",
		"files_scanned": 1, "files_considered": 1,
		"engines_skipped": map[string]any{
			"zzz-engine": map[string]any{"unscannable_path_name": 1},
			"amwscan":    map[string]any{"unscannable_path_name": 1},
			"maldet":     map[string]any{"unscannable_path_name": 1},
		},
	}

	first := notLookedAt(data)
	for i := 0; i < 20; i++ {
		if got := notLookedAt(data); got != first {
			t.Fatalf("the order changed between renders:\n  %s\n  %s", first, got)
		}
	}
	if !strings.HasPrefix(first, "1 amwscan") {
		t.Errorf("engines are not sorted by slug: %s", first)
	}
}
