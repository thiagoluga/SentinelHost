// Package config loads, validates and writes SentinelHost's single TOML file.
//
// The TOML is the shared source of truth between the CLI and the panel
// (FR-014): everything the panel edits lives here, and anything edited by hand
// shows up in the panel. There is no second configuration file (Principle VII).
package config

import (
	"time"
)

// Config is the whole file.
type Config struct {
	General    General           `toml:"general"`
	Limits     Limits            `toml:"limits"`
	Schedule   Schedule          `toml:"schedule"`
	Verdict    VerdictConfig     `toml:"verdict"`
	Quarantine QuarantineConfig  `toml:"quarantine"`
	Engines    map[string]Engine `toml:"engines"`
	Alerts     Alerts            `toml:"alerts"`
	Web        Web               `toml:"web"`
	Logging    Logging           `toml:"logging"`

	// path records where this Config was read from, so Save() can return to the
	// same place without the caller having to remember.
	path string `toml:"-"`
}

// General gathers what defines the installation.
type General struct {
	// Roots are the watched root directories. Nothing outside them is ever
	// scanned — not even through a symlink.
	Roots []string `toml:"roots"`
	// DataDir holds the baseline, the quarantine vault, raw output and SQLite.
	DataDir string `toml:"data_dir"`
	// ObservationMode disables every automatic action: verdicts keep coming out
	// and alerts become "action recommended".
	ObservationMode bool `toml:"observation_mode"`
	// GracePeriodDays is the window after the first run during which no
	// automatic quarantine happens, even with observation_mode=false. It exists
	// so the user can calibrate weights and the whitelist before the tool
	// touches their files (DECISIONS.md D-007).
	GracePeriodDays int `toml:"grace_period_days"`
	// FirstRunAt is written by the first cycle. Zero means "has not run yet".
	FirstRunAt time.Time `toml:"first_run_at"`
	// Locale of the panel and the emails.
	Locale string `toml:"locale"`
}

// Limits is Principle IV in struct form: the scanner must never get the user's
// account suspended for resource abuse. Every one of these limits is mandatory
// and active by default.
type Limits struct {
	// Nice from 0 to 19. The default is 19 (the lowest possible priority).
	Nice int `toml:"nice"`
	// IoniceClass 3 = idle. Applied when ionice exists.
	IoniceClass int `toml:"ionice_class"`
	// MaxFileSizeMB: larger files are skipped and counted as "too_large" in the
	// report, never silently ignored.
	MaxFileSizeMB int `toml:"max_file_size_mb"`
	// EngineTimeout: the maximum time for ONE engine execution.
	EngineTimeout Duration `toml:"engine_timeout"`
	// CycleTimeout: the maximum time for the whole cycle.
	CycleTimeout Duration `toml:"cycle_timeout"`
	// BatchSize and BatchPause implement the pause between batches.
	BatchSize  int      `toml:"batch_size"`
	BatchPause Duration `toml:"batch_pause"`
	// MaxDepth caps the walker's depth (sites with runaway cache directories).
	MaxDepth int `toml:"max_depth"`
	// MaxFilesPerCycle cuts the cycle short with a partial status instead of
	// walking millions of inodes at once.
	MaxFilesPerCycle int `toml:"max_files_per_cycle"`
	// Exclude are globs relative to each root.
	Exclude []string `toml:"exclude"`
	// MemoryLimitMB of the orchestrator itself (engines have their own).
	MemoryLimitMB int `toml:"memory_limit_mb"`
}

// Schedule defines the rhythm of the cycles.
type Schedule struct {
	// Mode: "daemon" or "cron". In "cron" the binary runs one cycle and exits.
	Mode string `toml:"mode"`
	// Incremental is the interval between incremental cycles.
	Incremental Duration `toml:"incremental"`
	// FullCron is the full-scan schedule (5-field cron format).
	FullCron string `toml:"full_cron"`
	// SignaturesCron is the schedule for updating engine signatures.
	SignaturesCron string `toml:"signatures_cron"`
	// QuietHours suspends scans during a window of the day ("02:00-06:00";
	// empty means no restriction). Useful for known traffic peaks.
	QuietHours string `toml:"quiet_hours"`
}

// VerdictConfig parameterizes the consensus engine. Thresholds and weights are
// configurable (FR-017); the safety rules (whitelist and official checksum) are
// not.
type VerdictConfig struct {
	// Saturation is the ceiling of the weight sum: score = min(1, sum/saturation).
	// See DECISIONS.md D-003.
	Saturation float64 `toml:"saturation"`
	// Thresholds: the minimum score for each level.
	ConfirmedAt  float64 `toml:"confirmed_at"`
	LikelyAt     float64 `toml:"likely_at"`
	SuspiciousAt float64 `toml:"suspicious_at"`
	// Multipliers by finding confidence.
	SignatureMultiplier float64 `toml:"signature_multiplier"`
	HeuristicMultiplier float64 `toml:"heuristic_multiplier"`
	AnomalyMultiplier   float64 `toml:"anomaly_multiplier"`
	// Whitelist of paths (globs) that are never quarantined. They stay visible
	// in the report (DECISIONS.md D-006).
	Whitelist []string `toml:"whitelist"`
}

// QuarantineConfig governs the vault.
type QuarantineConfig struct {
	// Dir empty = <data_dir>/quarantine.
	Dir string `toml:"dir"`
	// RetentionDays before an item becomes eligible for purging. Purging is
	// never automatic before an item passes this deadline (Principle I).
	RetentionDays int `toml:"retention_days"`
	// AutoPurge enables the periodic purge of expired items. Off by default:
	// deleting the user's file is always the user's decision.
	AutoPurge bool `toml:"auto_purge"`
	// NeutralizedExtension is the suffix applied inside the vault.
	NeutralizedExtension string `toml:"neutralized_extension"`
}

// Engine is one adapter's configuration.
type Engine struct {
	Enabled bool `toml:"enabled"`
	// Weight is this engine's vote weight in the consensus.
	Weight float64 `toml:"weight"`
	// Path forces the binary/phar path when the automatic probe cannot find the
	// engine (hosting with PHP in an exotic location).
	Path string `toml:"path"`
	// ExtraArgs are passed through to the subprocess.
	ExtraArgs []string `toml:"extra_args"`
	// Timeout overrides limits.engine_timeout for this engine only.
	Timeout Duration `toml:"timeout"`
}

// Alerts gathers the notification channels.
type Alerts struct {
	Email    EmailConfig `toml:"email"`
	Webhooks []Webhook   `toml:"webhooks"`
}

// EmailConfig is the SMTP setup.
type EmailConfig struct {
	Enabled  bool   `toml:"enabled"`
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
	// TLS: "starttls", "tls" or "none".
	TLS  string   `toml:"tls"`
	From string   `toml:"from"`
	To   []string `toml:"to"`
	// Levels that trigger an immediate alert.
	Levels []string `toml:"levels"`
	// Daily digest.
	DigestEnabled bool   `toml:"digest_enabled"`
	DigestAt      string `toml:"digest_at"`
	// PanelURL goes into the email body so the user can reach the finding.
	PanelURL string `toml:"panel_url"`
}

// Webhook is a signed endpoint.
type Webhook struct {
	ID      string `toml:"id"`
	Enabled bool   `toml:"enabled"`
	URL     string `toml:"url"`
	// Secret is the HMAC-SHA256 key.
	Secret string `toml:"secret"`
	// Events subscribed to. No subscription, no delivery.
	Events []string `toml:"events"`
	// Format shapes the body for the destination: "raw" (the project's own
	// envelope, the default), "slack" or "discord".
	//
	// It exists because Slack's and Discord's incoming webhooks do not accept an
	// arbitrary payload: Slack wants {"text": ...} or blocks, Discord wants
	// {"content": ...} or embeds. Posting our envelope to either one is rejected
	// or arrives as an empty message — so "integrates with Slack" was a promise
	// the generic webhook could not keep (US4).
	Format string `toml:"format"`
}

// WebhookFormat values.
const (
	// FormatRaw sends the project's envelope. It is the only format whose HMAC
	// signature means anything, because it is the only one a receiver of ours
	// reads.
	FormatRaw = "raw"
	// FormatSlack shapes the body for a Slack incoming webhook.
	FormatSlack = "slack"
	// FormatDiscord shapes the body for a Discord webhook.
	FormatDiscord = "discord"
)

// KnownWebhookFormats are the destinations a webhook body can be shaped for.
var KnownWebhookFormats = []string{FormatRaw, FormatSlack, FormatDiscord}

// FormatOrDefault resolves an empty format to "raw".
//
// Empty has to keep meaning "raw": every webhook configured before the field
// existed has no format, and silently changing their body shape would break
// deliveries that work today.
func (w Webhook) FormatOrDefault() string {
	if w.Format == "" {
		return FormatRaw
	}
	return w.Format
}

// Web is the embedded panel.
type Web struct {
	Enabled bool `toml:"enabled"`
	// Listen defaults to 127.0.0.1. Exposing it on 0.0.0.0 requires a
	// deliberate choice by the user and triggers a validation warning.
	Listen string `toml:"listen"`
	// SessionTTL of the authenticated session.
	SessionTTL Duration `toml:"session_ttl"`
	// LoginRateLimit: attempts per minute per IP.
	LoginRateLimit int `toml:"login_rate_limit"`
}

// Logging configures the structured log.
type Logging struct {
	// Level: debug, info, warn, error.
	Level string `toml:"level"`
	// RetentionDays of the structured log.
	RetentionDays int `toml:"retention_days"`
	// RawOutputRetentionDays of the archived raw engine output (auditing and
	// reprocessing through Parse).
	RawOutputRetentionDays int `toml:"raw_output_retention_days"`
}

// Path returns the file this Config was read from.
func (c *Config) Path() string { return c.path }

// SetPath sets Save()'s destination.
func (c *Config) SetPath(p string) { c.path = p }
