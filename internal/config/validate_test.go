package config_test

import (
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// A local-MTA configuration has no host, no port and no credentials. That is the point of
// it: the account is trusted by the machine it runs on, and there is no mailbox to name.
//
// The first deployment of that transport was rejected by this validator for an empty
// host, because the new conditional rule was added beside the old unconditional one
// instead of replacing it. The sender would have delivered the mail happily; the config
// check refused to let it try.
func TestSendmailNeedsNoHostAndNoPort(t *testing.T) {
	c := validBase()
	c.Alerts.Email = config.EmailConfig{
		Enabled:   true,
		Transport: "sendmail",
		From:      "sentinelhost@example.com",
		To:        []string{"admin@example.com"},
		TLS:       "starttls",
		Levels:    []string{"confirmed"},
	}

	r := c.Validate()
	for _, p := range r.Errors() {
		t.Errorf("a valid sendmail configuration was rejected: %s", p)
	}
}

// Under "auto" with no host, the same applies: that is exactly how the transport is
// selected at send time, and the two have to agree. A configuration the validator accepts
// and the sender then refuses — or the reverse — is worse than either check alone.
func TestAutoWithNoHostIsALocalMTAConfiguration(t *testing.T) {
	c := validBase()
	c.Alerts.Email = config.EmailConfig{
		Enabled: true, Transport: "auto",
		From: "sentinelhost@example.com", To: []string{"admin@example.com"},
		TLS: "starttls", Levels: []string{"confirmed"},
	}
	for _, p := range c.Validate().Errors() {
		t.Errorf("auto with no host was rejected: %s", p)
	}
}

// But asking for SMTP and giving nothing to dial is still an error, and it has to say so
// rather than silently falling back to a transport the user did not choose.
func TestSMTPStillRequiresAHost(t *testing.T) {
	c := validBase()
	c.Alerts.Email = config.EmailConfig{
		Enabled: true, Transport: "smtp", Port: 587,
		From: "sentinelhost@example.com", To: []string{"admin@example.com"},
		TLS: "starttls", Levels: []string{"confirmed"},
	}
	errs := c.Validate().Errors()
	found := false
	for _, p := range errs {
		if p.Field == "alerts.email.host" {
			found = true
		}
	}
	if !found {
		t.Errorf("transport=smtp with no host was accepted; errors were %v", errs)
	}
}

// A host that IS configured still has its port checked, because something is going to
// dial it.
func TestAConfiguredHostStillNeedsAValidPort(t *testing.T) {
	c := validBase()
	c.Alerts.Email = config.EmailConfig{
		Enabled: true, Transport: "auto", Host: "smtp.example.com", Port: 0,
		From: "sentinelhost@example.com", To: []string{"admin@example.com"},
		TLS: "starttls", Levels: []string{"confirmed"},
	}
	found := false
	for _, p := range c.Validate().Errors() {
		if p.Field == "alerts.email.port" {
			found = true
		}
	}
	if !found {
		t.Error("a host was configured with port 0 and the port went unchecked")
	}
}
