package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

func TestDefaultIsValid(t *testing.T) {
	cfg := config.Default()
	cfg.General.Roots = []string{"/home/user/public_html"}

	res := cfg.Validate()
	if res.HasErrors() {
		t.Fatalf("the default configuration must be valid, got: %v", res.Errors())
	}
}

func TestDefaultIsSafeOutOfTheBox(t *testing.T) {
	// The user's first experience has to be "it broke nothing".
	cfg := config.Default()

	if !cfg.General.ObservationMode {
		t.Error("observation mode should ship enabled")
	}
	if cfg.General.GracePeriodDays != 7 {
		t.Errorf("grace period should be 7 days, got %d", cfg.General.GracePeriodDays)
	}
	if cfg.Limits.Nice != 19 {
		t.Errorf("nice should be 19 (Principle IV), got %d", cfg.Limits.Nice)
	}
	if cfg.Quarantine.AutoPurge {
		t.Error("automatic purge must not ship enabled: deleting a file is the user's decision")
	}
	if !strings.HasPrefix(cfg.Web.Listen, "127.0.0.1") {
		t.Errorf("the panel should listen on localhost by default, got %q", cfg.Web.Listen)
	}
	if cfg.Limits.EngineTimeout.Duration <= 0 {
		t.Error("the engine timeout has to be active by default")
	}
}

func TestDefaultWeightsFollowTheSchemaDocument(t *testing.T) {
	// docs/schema-and-adapters.md section 2.1 fixes these weights.
	cfg := config.Default()
	expected := map[string]float64{
		"wp-checksums":       1.5,
		"maldet":             1.0,
		"amwscan":            0.8,
		"php-malware-finder": 0.8,
	}
	for slug, weight := range expected {
		if got := cfg.WeightFor(slug); got != weight {
			t.Errorf("weight of %s: expected %v, got %v", slug, weight, got)
		}
	}
}

func TestLoadKeepsUndeclaredDefaults(t *testing.T) {
	// The user writes only what they want to change; the rest keeps its safe
	// default.
	path := writeTOML(t, `
[general]
roots = ["/home/user/public_html"]

[limits]
nice = 15
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Limits.Nice != 15 {
		t.Errorf("the declared nice was not read: %d", cfg.Limits.Nice)
	}
	if cfg.Limits.MaxFileSizeMB != config.Default().Limits.MaxFileSizeMB {
		t.Error("an undeclared limit should keep its default")
	}
	if !cfg.General.ObservationMode {
		t.Error("an undeclared observation mode should keep its default (enabled)")
	}
}

func TestLoadComplainsAboutUnknownKey(t *testing.T) {
	// The worst scenario in a security tool: the user believes they turned off
	// automatic action and did not, because they mistyped the key name.
	path := writeTOML(t, `
[general]
roots = ["/tmp/x"]
observation_moed = false
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("a mistyped key should have been reported")
	}
	if !strings.Contains(err.Error(), "observation_moed") {
		t.Errorf("the error should name the wrong key, got: %v", err)
	}
}

func TestLoadNotFound(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("the error should indicate a missing file, got: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	// FR-014: the panel writes the TOML and the TOML feeds the panel. If the
	// round-trip loses a field, the two sides diverge silently.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	orig := config.Default()
	orig.General.Roots = []string{"/home/user/public_html", "/home/user/shop"}
	orig.General.ObservationMode = false
	orig.General.FirstRunAt = time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)
	orig.Verdict.Whitelist = []string{"**/wp-content/plugins/my-plugin/**"}
	orig.Alerts.Email.Enabled = true
	orig.Alerts.Email.Host = "smtp.example.com"
	orig.Alerts.Email.From = "sentinel@example.com"
	orig.Alerts.Email.To = []string{"owner@example.com"}
	orig.Alerts.Webhooks = []config.Webhook{{
		ID: "slack", Enabled: true, URL: "https://hooks.example.com/x",
		Secret: "s3cr3t", Events: []string{"verdict.confirmed", "scan.completed"},
	}}
	orig.Engines["amwscan"] = config.Engine{Enabled: true, Weight: 0.9, Path: "/usr/bin/php"}

	if err := orig.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	back, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}

	if len(back.General.Roots) != 2 || back.General.Roots[1] != "/home/user/shop" {
		t.Errorf("roots lost: %v", back.General.Roots)
	}
	if back.General.ObservationMode {
		t.Error("observation_mode=false did not survive the round-trip")
	}
	if !back.General.FirstRunAt.Equal(orig.General.FirstRunAt) {
		t.Errorf("first_run_at: expected %v, got %v", orig.General.FirstRunAt, back.General.FirstRunAt)
	}
	if len(back.Verdict.Whitelist) != 1 {
		t.Errorf("whitelist lost: %v", back.Verdict.Whitelist)
	}
	if len(back.Alerts.Webhooks) != 1 || back.Alerts.Webhooks[0].Secret != "s3cr3t" {
		t.Errorf("webhook lost: %+v", back.Alerts.Webhooks)
	}
	if back.Engines["amwscan"].Weight != 0.9 || back.Engines["amwscan"].Path != "/usr/bin/php" {
		t.Errorf("engine config lost: %+v", back.Engines["amwscan"])
	}
	if back.Limits.EngineTimeout.Duration != orig.Limits.EngineTimeout.Duration {
		t.Errorf("duration lost: %v vs %v", back.Limits.EngineTimeout, orig.Limits.EngineTimeout)
	}
}

func TestSaveUsesRestrictedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		// DECISIONS.md D-002: the target is Linux user space; Windows is only
		// the workstation. The skip is explicit so the suite does not lie about
		// coverage.
		t.Skip("POSIX permissions do not apply on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := config.Default()
	cfg.General.Roots = []string{"/tmp/x"}
	if err := cfg.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// The file holds the SMTP password and webhook secrets.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("configuration is readable by others: %v", perm)
	}
}

func TestDurationRoundTripsAsReadableText(t *testing.T) {
	path := writeTOML(t, `
[general]
roots = ["/tmp/x"]

[limits]
engine_timeout = "90s"
batch_pause = "250ms"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Limits.EngineTimeout.Duration != 90*time.Second {
		t.Errorf("engine_timeout: %v", cfg.Limits.EngineTimeout)
	}
	if cfg.Limits.BatchPause.Duration != 250*time.Millisecond {
		t.Errorf("batch_pause: %v", cfg.Limits.BatchPause)
	}
}

func TestInvalidDurationIsReported(t *testing.T) {
	path := writeTOML(t, `
[general]
roots = ["/tmp/x"]

[limits]
engine_timeout = "five minutes"
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("an invalid duration should have been rejected")
	}
	if !strings.Contains(err.Error(), "30s") {
		t.Errorf("the message should teach the format, got: %v", err)
	}
}

// Validation ----------------------------------------------------------------

func validBase() *config.Config {
	c := config.Default()
	c.General.Roots = []string{"/home/user/public_html"}
	return c
}

func TestValidateRejectsThresholdsOutOfOrder(t *testing.T) {
	// A confirmed below likely would make the confirmed level unreachable.
	c := validBase()
	c.Verdict.ConfirmedAt = 0.5
	c.Verdict.LikelyAt = 0.7

	res := c.Validate()
	if !res.HasErrors() {
		t.Fatal("thresholds out of order should be a fatal error")
	}
}

func TestValidateRejectsImmediatePurge(t *testing.T) {
	// Automatic purge with zero retention would delete the file at the very
	// instant it was quarantined: an irreversible action, violating Principle I.
	c := validBase()
	c.Quarantine.AutoPurge = true
	c.Quarantine.RetentionDays = 0

	res := c.Validate()
	if !res.HasErrors() {
		t.Fatal("immediate purge should be a fatal error")
	}
}

func TestValidateRejectsRootSlash(t *testing.T) {
	c := validBase()
	c.General.Roots = []string{"/"}
	if !c.Validate().HasErrors() {
		t.Fatal("walking / should have been rejected")
	}
}

func TestValidateRejectsNoEngine(t *testing.T) {
	c := validBase()
	for slug, e := range c.Engines {
		e.Enabled = false
		c.Engines[slug] = e
	}
	if !c.Validate().HasErrors() {
		t.Fatal("no engine enabled should be an error")
	}
}

func TestValidateWarnsAboutASingleEngine(t *testing.T) {
	// There is no consensus with a single vote — but that is a warning, not an
	// error: a tool that refuses to run protects less than one that runs and
	// warns.
	c := validBase()
	for slug, e := range c.Engines {
		if slug != "amwscan" {
			e.Enabled = false
			c.Engines[slug] = e
		}
	}
	res := c.Validate()
	if res.HasErrors() {
		t.Fatalf("a single engine should not prevent execution: %v", res.Errors())
	}
	if len(res.Warnings()) == 0 {
		t.Error("a single engine should produce a warning")
	}
}

func TestValidateWarnsAboutAnExposedPanel(t *testing.T) {
	c := validBase()
	c.Web.Listen = "0.0.0.0:8787"
	res := c.Validate()
	if res.HasErrors() {
		t.Fatalf("exposing the panel is a user choice, not an error: %v", res.Errors())
	}
	if len(res.Warnings()) == 0 {
		t.Error("an exposed panel should produce a warning")
	}
}

func TestValidateRejectsUnknownWebhookEvent(t *testing.T) {
	c := validBase()
	c.Alerts.Webhooks = []config.Webhook{{
		ID: "w1", Enabled: true, URL: "https://x.example.com",
		Secret: "s", Events: []string{"verdict.made-up"},
	}}
	if !c.Validate().HasErrors() {
		t.Fatal("an unknown event should be an error")
	}
}

func TestValidateRejectsDuplicateWebhookIDs(t *testing.T) {
	c := validBase()
	w := config.Webhook{ID: "dup", Enabled: true, URL: "https://x.example.com", Secret: "s", Events: []string{"scan.completed"}}
	c.Alerts.Webhooks = []config.Webhook{w, w}
	if !c.Validate().HasErrors() {
		t.Fatal("duplicate ids should be an error")
	}
}

func TestValidateEnabledEmailRequiresRecipient(t *testing.T) {
	c := validBase()
	c.Alerts.Email.Enabled = true
	c.Alerts.Email.Host = "smtp.example.com"
	c.Alerts.Email.From = "a@example.com"
	c.Alerts.Email.To = nil
	if !c.Validate().HasErrors() {
		t.Fatal("email enabled with no recipient should be an error")
	}
}

// Grace period --------------------------------------------------------------

func TestGracePeriodBlocksAutomaticAction(t *testing.T) {
	c := validBase()
	c.General.ObservationMode = false
	c.General.GracePeriodDays = 7
	c.General.FirstRunAt = time.Now().Add(-2 * 24 * time.Hour)

	ok, reason := c.AutomaticActionAllowed(time.Now())
	if ok {
		t.Fatal("automatic action must not be allowed inside the grace period")
	}
	if !strings.Contains(reason, "grace") {
		t.Errorf("the reason should mention the grace period, got %q", reason)
	}
}

func TestFirstCycleIsInsideTheGracePeriod(t *testing.T) {
	// "Never ran" has to mean the start of the window, not the end of it.
	c := validBase()
	c.General.ObservationMode = false
	c.General.FirstRunAt = time.Time{}

	if !c.InGracePeriod(time.Now()) {
		t.Fatal("an installation that never ran should be inside the grace period")
	}
	if ok, _ := c.AutomaticActionAllowed(time.Now()); ok {
		t.Fatal("the first cycle must not be able to quarantine already")
	}
}

func TestAfterGraceWithObservationOffActionIsAllowed(t *testing.T) {
	c := validBase()
	c.General.ObservationMode = false
	c.General.GracePeriodDays = 7
	c.General.FirstRunAt = time.Now().Add(-30 * 24 * time.Hour)

	ok, reason := c.AutomaticActionAllowed(time.Now())
	if !ok {
		t.Fatalf("action should be allowed, reason given: %q", reason)
	}
}

func TestObservationWinsEvenOutsideGrace(t *testing.T) {
	c := validBase()
	c.General.ObservationMode = true
	c.General.FirstRunAt = time.Now().Add(-365 * 24 * time.Hour)

	if ok, _ := c.AutomaticActionAllowed(time.Now()); ok {
		t.Fatal("observation mode has to block automatic action always")
	}
}

func TestZeroGraceDisablesTheWindow(t *testing.T) {
	c := validBase()
	c.General.ObservationMode = false
	c.General.GracePeriodDays = 0
	c.General.FirstRunAt = time.Time{}

	if c.InGracePeriod(time.Now()) {
		t.Fatal("grace_period_days=0 should disable the grace period")
	}
}

// Clone ---------------------------------------------------------------------

func TestCloneIsIndependent(t *testing.T) {
	// The panel edits the configuration while a cycle may be reading it. A
	// shallow copy would leave both mutating the same map — a real data race.
	orig := validBase()
	orig.Verdict.Whitelist = []string{"**/a/**"}
	orig.Engines["amwscan"] = config.Engine{Enabled: true, Weight: 0.8, ExtraArgs: []string{"-x"}}
	orig.Alerts.Webhooks = []config.Webhook{{ID: "w", Events: []string{"scan.completed"}}}

	clone := orig.Clone()

	clone.Verdict.Whitelist[0] = "**/changed/**"
	clone.Engines["amwscan"] = config.Engine{Enabled: false}
	clone.Alerts.Webhooks[0].Events[0] = "verdict.confirmed"
	clone.General.Roots = append(clone.General.Roots, "/another")

	if orig.Verdict.Whitelist[0] != "**/a/**" {
		t.Error("mutating the clone changed the original's whitelist")
	}
	if !orig.Engines["amwscan"].Enabled {
		t.Error("mutating the clone changed the original's engine map")
	}
	if orig.Alerts.Webhooks[0].Events[0] != "scan.completed" {
		t.Error("mutating the clone changed the original's webhook events")
	}
	if len(orig.General.Roots) != 1 {
		t.Error("appending to the clone changed the original's roots")
	}
}

func TestCloneOfNilIsNil(t *testing.T) {
	var c *config.Config
	if c.Clone() != nil {
		t.Error("cloning nil should return nil")
	}
}
