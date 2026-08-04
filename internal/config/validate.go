package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Problem is one finding from configuration validation.
type Problem struct {
	Field   string
	Message string
	// Fatal separates "this stops the program from running" from "this deserves
	// a warning on screen". A warning must never prevent the scan from
	// happening: a tool that refuses to run protects less than one that runs
	// and warns.
	Fatal bool
}

func (p Problem) String() string {
	prefix := "warning"
	if p.Fatal {
		prefix = "error"
	}
	return fmt.Sprintf("%s: %s: %s", prefix, p.Field, p.Message)
}

// ValidationResult collects errors and warnings.
type ValidationResult struct {
	Problems []Problem
}

// HasErrors answers whether anything prevents execution.
func (r ValidationResult) HasErrors() bool {
	for _, p := range r.Problems {
		if p.Fatal {
			return true
		}
	}
	return false
}

// Errors returns only the fatal problems.
func (r ValidationResult) Errors() []Problem {
	var out []Problem
	for _, p := range r.Problems {
		if p.Fatal {
			out = append(out, p)
		}
	}
	return out
}

// Warnings returns only the warnings.
func (r ValidationResult) Warnings() []Problem {
	var out []Problem
	for _, p := range r.Problems {
		if !p.Fatal {
			out = append(out, p)
		}
	}
	return out
}

// Err turns the fatal problems into a single error, or nil.
func (r ValidationResult) Err() error {
	errs := r.Errors()
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(errs))
	for _, p := range errs {
		msgs = append(msgs, p.Field+": "+p.Message)
	}
	return fmt.Errorf("invalid configuration: %s", strings.Join(msgs, "; "))
}

func (r *ValidationResult) fatal(field, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{field, fmt.Sprintf(format, args...), true})
}

func (r *ValidationResult) warn(field, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{field, fmt.Sprintf(format, args...), false})
}

// Validate checks the whole configuration.
func (c *Config) Validate() ValidationResult {
	var r ValidationResult

	c.validateGeneral(&r)
	c.validateLimits(&r)
	c.validateVerdict(&r)
	c.validateQuarantine(&r)
	c.validateEngines(&r)
	c.validateAlerts(&r)
	c.validateWeb(&r)

	return r
}

func (c *Config) validateGeneral(r *ValidationResult) {
	if len(c.General.Roots) == 0 {
		r.fatal("general.roots", "no root configured: the scan has nothing to walk")
	}
	for i, root := range c.General.Roots {
		if root == "" {
			r.fatal(fmt.Sprintf("general.roots[%d]", i), "empty root")
			continue
		}
		if root == "/" {
			r.fatal(fmt.Sprintf("general.roots[%d]", i),
				"walking / is not what this tool is for and would get the account suspended for resource abuse")
		}
	}
	if c.General.DataDir == "" {
		r.fatal("general.data_dir", "empty")
	}
	if c.General.GracePeriodDays < 0 {
		r.fatal("general.grace_period_days", "cannot be negative")
	}
	if !c.General.ObservationMode && c.General.GracePeriodDays == 0 {
		r.warn("general.observation_mode",
			"automatic action is on with no grace period: the tool may quarantine on the very first cycle, before you have calibrated the whitelist")
	}
}

func (c *Config) validateLimits(r *ValidationResult) {
	if c.Limits.Nice < 0 || c.Limits.Nice > 19 {
		r.fatal("limits.nice", "must be between 0 and 19, got %d", c.Limits.Nice)
	}
	if c.Limits.Nice < 10 {
		// Without root you cannot LOWER nice afterwards; raising priority is
		// exactly what gets a hosting account suspended.
		r.warn("limits.nice", "a value of %d gives the scanner high priority and may get the account suspended (recommended: 19)", c.Limits.Nice)
	}
	if c.Limits.MaxFileSizeMB <= 0 {
		r.fatal("limits.max_file_size_mb", "must be positive")
	}
	if c.Limits.EngineTimeout.Duration <= 0 {
		r.fatal("limits.engine_timeout", "must be positive: with no timeout, a stuck engine freezes the cycle forever")
	}
	if c.Limits.CycleTimeout.Duration > 0 && c.Limits.CycleTimeout.Duration < c.Limits.EngineTimeout.Duration {
		r.warn("limits.cycle_timeout", "is smaller than engine_timeout: no engine will ever be able to finish")
	}
	if c.Limits.BatchSize <= 0 {
		r.fatal("limits.batch_size", "must be positive")
	}
	if c.Limits.MaxDepth <= 0 {
		r.fatal("limits.max_depth", "must be positive")
	}
	if c.Limits.MemoryLimitMB > 0 && c.Limits.MemoryLimitMB < 32 {
		r.warn("limits.memory_limit_mb", "below 32 MB the orchestrator itself may not fit")
	}
}

func (c *Config) validateVerdict(r *ValidationResult) {
	v := c.Verdict
	if v.Saturation <= 0 {
		r.fatal("verdict.saturation", "must be positive (it is the score divisor)")
	}
	for name, val := range map[string]float64{
		"verdict.confirmed_at":  v.ConfirmedAt,
		"verdict.likely_at":     v.LikelyAt,
		"verdict.suspicious_at": v.SuspiciousAt,
	} {
		if val < 0 || val > 1 {
			r.fatal(name, "must be between 0 and 1, got %v", val)
		}
	}
	// Thresholds out of order would produce unreachable levels — a confirmed
	// below likely would turn every serious finding into likely.
	if !(v.ConfirmedAt > v.LikelyAt && v.LikelyAt > v.SuspiciousAt) {
		r.fatal("verdict",
			"thresholds out of order: confirmed_at (%v) > likely_at (%v) > suspicious_at (%v) is required",
			v.ConfirmedAt, v.LikelyAt, v.SuspiciousAt)
	}
	for name, val := range map[string]float64{
		"verdict.signature_multiplier": v.SignatureMultiplier,
		"verdict.heuristic_multiplier": v.HeuristicMultiplier,
		"verdict.anomaly_multiplier":   v.AnomalyMultiplier,
	} {
		if val < 0 || val > 1 {
			r.fatal(name, "must be between 0 and 1, got %v", val)
		}
	}
	if v.SignatureMultiplier < v.HeuristicMultiplier || v.HeuristicMultiplier < v.AnomalyMultiplier {
		r.warn("verdict",
			"multipliers are inverted: an anomaly would end up weighing more than an exact signature")
	}
	if v.ConfirmedAt < 0.5 {
		r.warn("verdict.confirmed_at",
			"low threshold (%v) for the level that authorizes automatic quarantine", v.ConfirmedAt)
	}
}

func (c *Config) validateQuarantine(r *ValidationResult) {
	if c.Quarantine.RetentionDays < 0 {
		r.fatal("quarantine.retention_days", "cannot be negative")
	}
	if c.Quarantine.AutoPurge && c.Quarantine.RetentionDays == 0 {
		r.fatal("quarantine.auto_purge",
			"automatic purge with zero retention would delete the file the instant it was quarantined, making the action irreversible")
	}
	if c.Quarantine.AutoPurge && c.Quarantine.RetentionDays < 7 {
		r.warn("quarantine.retention_days",
			"%d days is not long enough to notice a false positive before the purge", c.Quarantine.RetentionDays)
	}
	if c.Quarantine.NeutralizedExtension == "" {
		r.fatal("quarantine.neutralized_extension",
			"empty: the file would sit in the vault with its original extension, still executable if the vault is ever served over the web")
	}
}

func (c *Config) validateEngines(r *ValidationResult) {
	enabled := 0
	for slug, e := range c.Engines {
		if e.Weight < 0 {
			r.fatal("engines."+slug+".weight", "cannot be negative")
		}
		if e.Weight > 3 {
			r.warn("engines."+slug+".weight",
				"a weight of %v lets this engine decide any verdict on its own", e.Weight)
		}
		if e.Enabled {
			enabled++
			if e.Weight == 0 {
				r.warn("engines."+slug,
					"enabled with weight 0: it will burn CPU and never influence a verdict")
			}
		}
	}
	if enabled == 0 {
		r.fatal("engines", "no engine enabled")
	}
	if enabled == 1 {
		r.warn("engines",
			"only 1 engine enabled: there is no consensus with a single vote, and coverage is reduced")
	}
}

func (c *Config) validateAlerts(r *ValidationResult) {
	e := c.Alerts.Email
	if e.Enabled {
		if e.Host == "" {
			r.fatal("alerts.email.host", "empty with email enabled")
		}
		if e.Port <= 0 || e.Port > 65535 {
			r.fatal("alerts.email.port", "invalid port: %d", e.Port)
		}
		switch strings.ToLower(e.Transport) {
		case "", "auto", "smtp", "sendmail":
		default:
			r.fatal("alerts.email.transport",
				"unknown value %q (use auto, smtp or sendmail)", e.Transport)
		}
		// A host is required only when SMTP is actually going to be used. Demanding one
		// under `sendmail` would force a user with no mailbox to invent a server they
		// will never contact.
		if strings.EqualFold(e.Transport, "smtp") && e.Host == "" {
			r.fatal("alerts.email.host", "empty with transport set to smtp")
		}
		if e.From == "" {
			r.fatal("alerts.email.from", "empty with email enabled")
		}
		if len(e.To) == 0 {
			r.fatal("alerts.email.to", "no recipient with email enabled")
		}
		switch e.TLS {
		case "starttls", "tls", "none":
		default:
			r.fatal("alerts.email.tls", "invalid value %q (use starttls, tls or none)", e.TLS)
		}
		if e.TLS == "none" && e.Password != "" {
			r.warn("alerts.email.tls",
				"the SMTP password would be sent over the network in clear text")
		}
		for _, lv := range e.Levels {
			switch lv {
			case "confirmed", "likely", "suspicious":
			default:
				r.fatal("alerts.email.levels", "unknown level %q", lv)
			}
		}
		if len(e.Levels) == 0 {
			r.warn("alerts.email.levels",
				"no level selected: email is enabled but will never fire")
		}
	}

	seen := map[string]bool{}
	for i, w := range c.Alerts.Webhooks {
		field := fmt.Sprintf("alerts.webhooks[%d]", i)
		if w.ID == "" {
			r.fatal(field+".id", "empty")
		} else if seen[w.ID] {
			r.fatal(field+".id", "duplicate id %q", w.ID)
		} else {
			seen[w.ID] = true
		}

		u, err := url.Parse(w.URL)
		switch {
		case w.URL == "":
			r.fatal(field+".url", "empty")
		case err != nil:
			r.fatal(field+".url", "invalid: %v", err)
		case u.Scheme != "http" && u.Scheme != "https":
			r.fatal(field+".url", "unsupported scheme %q (use http or https)", u.Scheme)
		case u.Scheme == "http" && w.Enabled:
			r.warn(field+".url",
				"http without TLS: the payload carrying your file paths travels in clear text")
		}

		if !validWebhookFormat(w.FormatOrDefault()) {
			r.fatal(field+".format", "unknown format %q (use raw, slack or discord)", w.Format)
		}

		switch {
		case w.Enabled && w.Secret == "" && w.FormatOrDefault() == FormatRaw:
			r.warn(field+".secret",
				"without a secret the destination cannot verify the delivery came from here")
		case w.Enabled && w.Secret != "" && w.FormatOrDefault() != FormatRaw:
			// Saying nothing here would let the user believe the signature protects
			// a delivery that nobody checks.
			r.warn(field+".secret",
				"format %q does not verify signatures: the delivery is still signed, but only the raw format has a receiver that reads it",
				w.FormatOrDefault())
		}
		if w.Enabled && len(w.Events) == 0 {
			r.warn(field+".events", "no events subscribed: there will never be a delivery")
		}
		for _, ev := range w.Events {
			if !validEvent(ev) {
				r.fatal(field+".events", "unknown event %q", ev)
			}
		}
	}
}

// KnownEvents are the webhook events from the contract
// (specs/001-orquestrador-mvp/contracts/webhooks.md).
var KnownEvents = []string{
	"verdict.confirmed",
	"verdict.likely",
	"verdict.suspicious",
	"quarantine.action",
	"scan.completed",
	"engine.failed",
}

func validWebhookFormat(f string) bool {
	for _, k := range KnownWebhookFormats {
		if k == f {
			return true
		}
	}
	return false
}

func validEvent(e string) bool {
	for _, k := range KnownEvents {
		if k == e {
			return true
		}
	}
	return false
}

func (c *Config) validateWeb(r *ValidationResult) {
	if !c.Web.Enabled {
		return
	}
	if c.Web.Listen == "" {
		r.fatal("web.listen", "empty with the panel enabled")
	}
	host, _, found := strings.Cut(c.Web.Listen, ":")
	if !found {
		r.fatal("web.listen", "invalid format: use host:port")
		return
	}
	// The constitution requires listening on localhost by default. Exposing it
	// is a legitimate user choice — but it has to be a deliberate one, with a
	// warning.
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		r.warn("web.listen",
			"the panel will accept connections from outside %q; prefer an SSH tunnel or make sure the port is protected", host)
	}
	if c.Web.SessionTTL.Duration <= 0 {
		r.fatal("web.session_ttl", "must be positive")
	}
	if c.Web.LoginRateLimit <= 0 {
		r.fatal("web.login_rate_limit", "must be positive: with no limit the panel is open to brute force")
	}
}
