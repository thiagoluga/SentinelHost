package config

import (
	"os"
	"path/filepath"
	"time"
)

// Default per-engine weights, from docs/schema-and-adapters.md section 2.1.
const (
	WeightWPChecksums = 1.5 // tampered core = near certainty
	WeightMaldet      = 1.0
	WeightAMWScan     = 0.8
	WeightPMF         = 0.8
	WeightWordfence   = 1.0 // post-MVP
	WeightClamAV      = 0.6 // post-MVP
)

// DefaultDataDir is ~/.sentinelhost. It lives in user space because there is no
// root (Principle III).
func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// With no HOME (the minimal cron of some hosts), fall back to the
		// current directory instead of failing: running in a predictable place
		// beats not running at all.
		return ".sentinelhost"
	}
	return filepath.Join(home, ".sentinelhost")
}

// DefaultConfigPath is <data_dir>/config.toml.
func DefaultConfigPath() string {
	return filepath.Join(DefaultDataDir(), "config.toml")
}

// Default returns the initial configuration.
//
// The defaults are deliberately conservative: observation on, nice 19,
// incremental every hour, no automatic purge, panel on localhost only. The
// user's first experience has to be "it broke nothing", not "good thing I had a
// backup".
func Default() *Config {
	data := DefaultDataDir()
	return &Config{
		General: General{
			Roots:   nil, // with no root configured, the scan refuses to run
			DataDir: data,
			// Observation on out of the box. Together with the 7-day grace
			// period, it guarantees the tool only starts touching files after
			// the user has seen what it thinks.
			ObservationMode: true,
			GracePeriodDays: 7,
			Locale:          "en",
		},
		Limits: Limits{
			Nice:             19,
			IoniceClass:      3, // idle
			MaxFileSizeMB:    16,
			EngineTimeout:    D(5 * time.Minute),
			CycleTimeout:     D(30 * time.Minute),
			BatchSize:        200,
			BatchPause:       D(500 * time.Millisecond),
			MaxDepth:         20,
			MaxFilesPerCycle: 200000,
			MemoryLimitMB:    128,
			Exclude: []string{
				// Cache and binary uploads: huge volume, low risk.
				"**/wp-content/cache/**",
				"**/wp-content/uploads/**/*.jpg",
				"**/wp-content/uploads/**/*.jpeg",
				"**/wp-content/uploads/**/*.png",
				"**/wp-content/uploads/**/*.gif",
				"**/wp-content/uploads/**/*.webp",
				"**/wp-content/uploads/**/*.svg",
				"**/wp-content/uploads/**/*.mp4",
				"**/wp-content/uploads/**/*.pdf",
				"**/node_modules/**",
				"**/vendor/**/tests/**",
				"**/.git/**",
				"**/.svn/**",
				// Our own data directory: scanning the quarantine vault would
				// re-detect what has already been neutralized, in a loop.
				"**/.sentinelhost/**",
			},
		},
		Schedule: Schedule{
			Mode:           "cron", // shared hosting rarely keeps a daemon alive
			Incremental:    D(time.Hour),
			FullCron:       "0 3 * * 0", // Sunday 03:00
			SignaturesCron: "0 2 * * *", // daily 02:00
		},
		Verdict: VerdictConfig{
			// See DECISIONS.md D-003 for why the ceiling is 2.0.
			Saturation:          2.0,
			ConfirmedAt:         0.9,
			LikelyAt:            0.6,
			SuspiciousAt:        0.3,
			SignatureMultiplier: 1.0,
			HeuristicMultiplier: 0.8,
			AnomalyMultiplier:   0.55,
			Whitelist:           []string{},
		},
		Quarantine: QuarantineConfig{
			Dir:           "", // <data_dir>/quarantine
			RetentionDays: 30,
			// Off: deleting the user's file is always their decision.
			AutoPurge:            false,
			NeutralizedExtension: ".quarantined",
		},
		Engines: map[string]Engine{
			"wp-checksums":       {Enabled: true, Weight: WeightWPChecksums},
			"amwscan":            {Enabled: true, Weight: WeightAMWScan},
			"php-malware-finder": {Enabled: true, Weight: WeightPMF},
			// maldet ships DISABLED because this binary does not carry its
			// adapter yet. Enabling an engine with no adapter would make it
			// appear as an abstention in every cycle — a permanent alarm about
			// something the user has no way to fix. The weight stays recorded
			// for when the adapter arrives.
			"maldet": {Enabled: false, Weight: WeightMaldet},
		},
		Alerts: Alerts{
			Email: EmailConfig{
				Enabled: false,
				Port:    587,
				TLS:     "starttls",
				// Only confirmed and likely by default: alerting on suspicious
				// out of the box trains the user to ignore the emails.
				Levels:        []string{"confirmed", "likely"},
				DigestEnabled: false,
				DigestAt:      "08:00",
			},
			Webhooks: []Webhook{},
		},
		Web: Web{
			Enabled: true,
			// 127.0.0.1 by default. Access through an SSH tunnel or a
			// deliberately opened port (an explicit constitution constraint).
			Listen:         "127.0.0.1:8787",
			SessionTTL:     D(12 * time.Hour),
			LoginRateLimit: 10,
		},
		Logging: Logging{
			Level:                  "info",
			RetentionDays:          90,
			RawOutputRetentionDays: 14,
		},
	}
}

// QuarantineDir resolves the vault's effective directory.
func (c *Config) QuarantineDir() string {
	if c.Quarantine.Dir != "" {
		return c.Quarantine.Dir
	}
	return filepath.Join(c.General.DataDir, "quarantine")
}

// DatabasePath is the state SQLite file.
func (c *Config) DatabasePath() string {
	return filepath.Join(c.General.DataDir, "sentinelhost.db")
}

// RawOutputDir holds the archived raw engine output.
func (c *Config) RawOutputDir() string {
	return filepath.Join(c.General.DataDir, "raw")
}

// BaselinePath is the hash baseline file.
func (c *Config) BaselinePath() string {
	return filepath.Join(c.General.DataDir, "baseline.json")
}

// LockPath is the single-instance lock.
func (c *Config) LockPath() string {
	return filepath.Join(c.General.DataDir, "sentinelhost.lock")
}

// EngineTimeoutFor returns an engine's effective timeout.
func (c *Config) EngineTimeoutFor(slug string) time.Duration {
	if e, ok := c.Engines[slug]; ok && e.Timeout.Duration > 0 {
		return e.Timeout.Duration
	}
	return c.Limits.EngineTimeout.Duration
}

// WeightFor returns an engine's configured weight. An unknown engine weighs
// zero: an unregistered adapter cannot influence a verdict.
func (c *Config) WeightFor(slug string) float64 {
	if e, ok := c.Engines[slug]; ok {
		return e.Weight
	}
	return 0
}

// EngineEnabled answers whether the engine is switched on in the configuration.
func (c *Config) EngineEnabled(slug string) bool {
	e, ok := c.Engines[slug]
	return ok && e.Enabled
}

// InGracePeriod answers whether the installation is still in the window where
// no automatic action happens (DECISIONS.md D-007).
func (c *Config) InGracePeriod(now time.Time) bool {
	if c.General.GracePeriodDays <= 0 {
		return false
	}
	if c.General.FirstRunAt.IsZero() {
		// No first cycle yet: we are at the start of the window, not past it.
		// Treating "never ran" as "grace expired" would let the very first run
		// quarantine already.
		return true
	}
	return now.Before(c.General.FirstRunAt.AddDate(0, 0, c.General.GracePeriodDays))
}

// GracePeriodEndsAt returns when the grace period expires. Zero if there is no
// grace period or the tool has not run yet.
func (c *Config) GracePeriodEndsAt() time.Time {
	if c.General.GracePeriodDays <= 0 || c.General.FirstRunAt.IsZero() {
		return time.Time{}
	}
	return c.General.FirstRunAt.AddDate(0, 0, c.General.GracePeriodDays)
}

// AutomaticActionAllowed is the single gate automatic quarantine has to pass.
// Concentrated here so that no code path can act automatically by accident
// (DECISIONS.md D-008).
func (c *Config) AutomaticActionAllowed(now time.Time) (bool, string) {
	if c.General.ObservationMode {
		return false, "observation mode is on"
	}
	if c.InGracePeriod(now) {
		end := c.GracePeriodEndsAt()
		if end.IsZero() {
			return false, "grace period active (the first cycle has not been recorded yet)"
		}
		return false, "grace period active until " + end.Format("2006-01-02")
	}
	return true, ""
}
