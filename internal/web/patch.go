package web

import (
	"github.com/thiagoluga/SentinelHost/internal/config"
)

// configPatch is the partial change coming from the panel.
//
// Every field is a pointer on purpose: that is what tells "the user did not touch
// this field" apart from "the user cleared this field". Without that distinction,
// saving the alerts tab would wipe the whitelist configured in the settings tab.
type configPatch struct {
	ObservationMode *bool     `json:"observation_mode,omitempty"`
	GracePeriodDays *int      `json:"grace_period_days,omitempty"`
	Roots           *[]string `json:"roots,omitempty"`

	Nice          *int      `json:"nice,omitempty"`
	MaxFileSizeMB *int      `json:"max_file_size_mb,omitempty"`
	EngineTimeout *string   `json:"engine_timeout,omitempty"`
	BatchSize     *int      `json:"batch_size,omitempty"`
	BatchPause    *string   `json:"batch_pause,omitempty"`
	Exclude       *[]string `json:"exclude,omitempty"`

	ScheduleMode   *string `json:"schedule_mode,omitempty"`
	Incremental    *string `json:"incremental,omitempty"`
	FullCron       *string `json:"full_cron,omitempty"`
	SignaturesCron *string `json:"signatures_cron,omitempty"`

	ConfirmedAt  *float64  `json:"confirmed_at,omitempty"`
	LikelyAt     *float64  `json:"likely_at,omitempty"`
	SuspiciousAt *float64  `json:"suspicious_at,omitempty"`
	Saturation   *float64  `json:"saturation,omitempty"`
	Whitelist    *[]string `json:"whitelist,omitempty"`

	RetentionDays *int  `json:"retention_days,omitempty"`
	AutoPurge     *bool `json:"auto_purge,omitempty"`

	Engines map[string]enginePatch `json:"engines,omitempty"`

	Email    *emailPatch     `json:"email,omitempty"`
	Webhooks *[]webhookPatch `json:"webhooks,omitempty"`
}

type enginePatch struct {
	Enabled *bool    `json:"enabled,omitempty"`
	Weight  *float64 `json:"weight,omitempty"`
	Path    *string  `json:"path,omitempty"`
}

type emailPatch struct {
	Enabled       *bool     `json:"enabled,omitempty"`
	Host          *string   `json:"host,omitempty"`
	Port          *int      `json:"port,omitempty"`
	Username      *string   `json:"username,omitempty"`
	Password      *string   `json:"password,omitempty"`
	TLS           *string   `json:"tls,omitempty"`
	From          *string   `json:"from,omitempty"`
	To            *[]string `json:"to,omitempty"`
	Levels        *[]string `json:"levels,omitempty"`
	DigestEnabled *bool     `json:"digest_enabled,omitempty"`
	DigestAt      *string   `json:"digest_at,omitempty"`
	PanelURL      *string   `json:"panel_url,omitempty"`
}

type webhookPatch struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	URL     string   `json:"url"`
	Secret  string   `json:"secret"`
	Events  []string `json:"events"`
	Format  string   `json:"format"`
}

// apply applies the patch to a copy of the configuration.
func (p configPatch) apply(c *config.Config) {
	setBool(&c.General.ObservationMode, p.ObservationMode)
	setInt(&c.General.GracePeriodDays, p.GracePeriodDays)
	setStrings(&c.General.Roots, p.Roots)

	setInt(&c.Limits.Nice, p.Nice)
	setInt(&c.Limits.MaxFileSizeMB, p.MaxFileSizeMB)
	setDuration(&c.Limits.EngineTimeout, p.EngineTimeout)
	setInt(&c.Limits.BatchSize, p.BatchSize)
	setDuration(&c.Limits.BatchPause, p.BatchPause)
	setStrings(&c.Limits.Exclude, p.Exclude)

	setString(&c.Schedule.Mode, p.ScheduleMode)
	setDuration(&c.Schedule.Incremental, p.Incremental)
	setString(&c.Schedule.FullCron, p.FullCron)
	setString(&c.Schedule.SignaturesCron, p.SignaturesCron)

	setFloat(&c.Verdict.ConfirmedAt, p.ConfirmedAt)
	setFloat(&c.Verdict.LikelyAt, p.LikelyAt)
	setFloat(&c.Verdict.SuspiciousAt, p.SuspiciousAt)
	setFloat(&c.Verdict.Saturation, p.Saturation)
	setStrings(&c.Verdict.Whitelist, p.Whitelist)

	setInt(&c.Quarantine.RetentionDays, p.RetentionDays)
	setBool(&c.Quarantine.AutoPurge, p.AutoPurge)

	for slug, ep := range p.Engines {
		e := c.Engines[slug]
		setBool(&e.Enabled, ep.Enabled)
		setFloat(&e.Weight, ep.Weight)
		setString(&e.Path, ep.Path)
		c.Engines[slug] = e
	}

	if p.Email != nil {
		e := &c.Alerts.Email
		setBool(&e.Enabled, p.Email.Enabled)
		setString(&e.Host, p.Email.Host)
		setInt(&e.Port, p.Email.Port)
		setString(&e.Username, p.Email.Username)
		// A masked password does not overwrite the real one: the panel returns
		// "********" on GET, and sending that back on PUT would wipe the real
		// password.
		if p.Email.Password != nil && *p.Email.Password != "********" {
			e.Password = *p.Email.Password
		}
		setString(&e.TLS, p.Email.TLS)
		setString(&e.From, p.Email.From)
		setStrings(&e.To, p.Email.To)
		setStrings(&e.Levels, p.Email.Levels)
		setBool(&e.DigestEnabled, p.Email.DigestEnabled)
		setString(&e.DigestAt, p.Email.DigestAt)
		setString(&e.PanelURL, p.Email.PanelURL)
	}

	if p.Webhooks != nil {
		previous := map[string]string{}
		for _, w := range c.Alerts.Webhooks {
			previous[w.ID] = w.Secret
		}
		updated := make([]config.Webhook, 0, len(*p.Webhooks))
		for _, wp := range *p.Webhooks {
			secret := wp.Secret
			if secret == "********" {
				// Same reasoning as the password: preserve the existing secret.
				secret = previous[wp.ID]
			}
			updated = append(updated, config.Webhook{
				ID: wp.ID, Enabled: wp.Enabled, URL: wp.URL,
				Secret: secret, Events: wp.Events, Format: wp.Format,
			})
		}
		c.Alerts.Webhooks = updated
	}
}

// fields lists the fields that were touched, for the audit log.
func (p configPatch) fields() []string {
	var out []string
	add := func(name string, touched bool) {
		if touched {
			out = append(out, name)
		}
	}
	add("observation_mode", p.ObservationMode != nil)
	add("grace_period_days", p.GracePeriodDays != nil)
	add("roots", p.Roots != nil)
	add("limits", p.Nice != nil || p.MaxFileSizeMB != nil || p.EngineTimeout != nil ||
		p.BatchSize != nil || p.BatchPause != nil || p.Exclude != nil)
	add("schedule", p.ScheduleMode != nil || p.Incremental != nil || p.FullCron != nil || p.SignaturesCron != nil)
	add("verdict", p.ConfirmedAt != nil || p.LikelyAt != nil || p.SuspiciousAt != nil || p.Saturation != nil)
	add("whitelist", p.Whitelist != nil)
	add("quarantine", p.RetentionDays != nil || p.AutoPurge != nil)
	add("engines", len(p.Engines) > 0)
	add("email", p.Email != nil)
	add("webhooks", p.Webhooks != nil)
	return out
}

func setBool(dst *bool, v *bool) {
	if v != nil {
		*dst = *v
	}
}

func setInt(dst *int, v *int) {
	if v != nil {
		*dst = *v
	}
}

func setFloat(dst *float64, v *float64) {
	if v != nil {
		*dst = *v
	}
}

func setString(dst *string, v *string) {
	if v != nil {
		*dst = *v
	}
}

func setStrings(dst *[]string, v *[]string) {
	if v != nil {
		*dst = *v
	}
}

// setDuration ignores invalid values instead of zeroing the field.
//
// Zeroing a timeout because of a user's typo would remove a mandatory resource
// limit — and the validation that follows would complain about a value the user
// never typed.
func setDuration(dst *config.Duration, v *string) {
	if v == nil {
		return
	}
	var d config.Duration
	if err := d.UnmarshalText([]byte(*v)); err != nil {
		return
	}
	*dst = d
}
