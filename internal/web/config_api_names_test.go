package web

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// The names the API sends have to be the names the panel reads.
//
// They were not. The config structs carried only `toml:` tags, so Go serialized them
// with its own field names — `{"alerts":{"Email":{"Enabled":false,…}}}` — while the panel
// reads `CFG.alerts.email.enabled`. The whole Settings tab was populated from undefined,
// and it did so SILENTLY: assigning undefined to an input's .value just leaves the field
// empty. Only one line threw, because it read a property OF the undefined object, and
// that single toast was the only outward sign that a whole screen was wrong.
//
// A test that asserted the Go structs, or one that asserted the JS, would have passed.
// This one reads both and compares them, which is the only version that could have
// caught it.

// panelReads extracts every `CFG.<section>.<field>` the panel asks for.
var panelReads = regexp.MustCompile(`CFG\.([a-z_]+)\.([a-z_]+)`)

func TestTheAPISendsTheNamesThePanelReads(t *testing.T) {
	js, err := os.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading app.js: %v", err)
	}

	// What the API actually emits, through the same marshalling the handler uses.
	cfg := config.Default()
	sections := map[string]any{
		"general": cfg.General, "limits": cfg.Limits, "schedule": cfg.Schedule,
		"verdict": cfg.Verdict, "quarantine": cfg.Quarantine,
		"alerts": cfg.Alerts, "web": cfg.Web, "logging": cfg.Logging,
	}
	emitted := map[string]map[string]bool{}
	for name, section := range sections {
		raw, err := json.Marshal(section)
		if err != nil {
			t.Fatalf("marshalling %s: %v", name, err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("re-reading %s: %v", name, err)
		}
		emitted[name] = map[string]bool{}
		for k := range fields {
			emitted[name][k] = true
		}
	}

	var missing []string
	for _, m := range panelReads.FindAllStringSubmatch(string(js), -1) {
		section, field := m[1], m[2]
		if _, known := emitted[section]; !known {
			continue // a section the API does not expose; not this test's business
		}
		if !emitted[section][field] {
			missing = append(missing, "CFG."+section+"."+field)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("the panel reads %d field(s) the API does not send:\n  %s\n\n"+
			"These come back undefined. Assigning undefined to an input's .value throws "+
			"nothing and leaves it blank, so the screen is wrong in silence.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// The specific shape that broke, kept as its own case because it is the one that threw
// and the one a person actually saw.
func TestTheAlertsSectionIsAddressableInLowerCase(t *testing.T) {
	raw, err := json.Marshal(config.Default().Alerts)
	if err != nil {
		t.Fatalf("marshalling alerts: %v", err)
	}
	var alerts struct {
		Email *struct {
			Enabled bool `json:"enabled"`
		} `json:"email"`
		Webhooks []any `json:"webhooks"`
	}
	if err := json.Unmarshal(raw, &alerts); err != nil {
		t.Fatalf("re-reading alerts: %v", err)
	}
	if alerts.Email == nil {
		t.Fatalf("alerts.email is absent, so the panel's `CFG.alerts.email.enabled` throws. "+
			"What the API sends is: %s", raw)
	}
}

// Every toml tag should have a json twin. The panel and the file the user edits by hand
// name the same setting, and two names for one thing is how they drift apart.
func TestEveryTOMLNameHasAJSONTwin(t *testing.T) {
	src, err := os.ReadFile("../config/config.go")
	if err != nil {
		t.Fatalf("reading config.go: %v", err)
	}

	tagged := regexp.MustCompile("`toml:\"([^\"]+)\"([^`]*)`")
	var bare []string
	for _, m := range tagged.FindAllStringSubmatch(string(src), -1) {
		if !strings.Contains(m[2], `json:"`) {
			bare = append(bare, m[1])
		}
	}
	if len(bare) > 0 {
		t.Errorf("%d field(s) have a toml name and no json name, so the API will send Go's "+
			"identifier instead: %s", len(bare), strings.Join(bare, ", "))
	}
}
