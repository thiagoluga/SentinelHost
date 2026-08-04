package email

import (
	"context"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// Shared hosting comes in two shapes: an account with mailbox credentials, and an account
// with no credentials at all but a working sendmail binary — which is most of them.
// Supporting only one of those is not a general answer, and the failure has to name what
// was tried rather than report an absence.
func TestSendSaysWhichTransportItLookedFor(t *testing.T) {
	cases := []struct {
		what      string
		cfg       config.EmailConfig
		wantInErr []string
	}{
		{
			"transport smtp with no host",
			config.EmailConfig{Transport: "smtp", From: "s@example.com", To: []string{"u@example.com"}},
			[]string{"no SMTP host", "transport is set to smtp"},
		},
		{
			"an unknown transport",
			config.EmailConfig{Transport: "carrier-pigeon", From: "s@example.com", To: []string{"u@example.com"}},
			[]string{"carrier-pigeon", "auto, smtp or sendmail"},
		},
		{
			"sendmail, pointed at something that is not there",
			config.EmailConfig{
				Transport: "sendmail", SendmailPath: "/nonexistent/sendmail",
				From: "s@example.com", To: []string{"u@example.com"},
			},
			[]string{"/nonexistent/sendmail"},
		},
		{
			"no recipient at all",
			config.EmailConfig{Transport: "auto", From: "s@example.com"},
			[]string{"no recipient"},
		},
	}

	for _, c := range cases {
		err := New(c.cfg).Send(context.Background(), Message{Subject: "t", Text: "t"})
		if err == nil {
			t.Errorf("%s: sent successfully, which cannot be true here", c.what)
			continue
		}
		for _, want := range c.wantInErr {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error does not mention %q.\n  got: %v", c.what, want, err)
			}
		}
	}
}

// A configured host wins under "auto": somebody who filled it in meant it, and silently
// preferring the local MTA would send mail from an address they did not choose.
func TestAConfiguredHostIsNotOverriddenByAutoDetection(t *testing.T) {
	cfg := config.EmailConfig{
		Transport: "auto", Host: "smtp.example.com", Port: 587,
		From: "s@example.com", To: []string{"u@example.com"},
	}
	err := New(cfg).Send(context.Background(), Message{Subject: "t", Text: "t"})
	if err == nil {
		t.Fatal("expected a connection failure against a host that does not exist")
	}
	// It has to have tried to dial rather than reaching for sendmail.
	if !strings.Contains(err.Error(), "smtp.example.com") {
		t.Errorf("auto did not use the configured host: %v", err)
	}
}
