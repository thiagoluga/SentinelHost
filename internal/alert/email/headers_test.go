package email

import (
	"strings"
	"testing"
)

// The subject of an alert carries the path of the offending file, and the person who put
// the malware there chose that name. A file called
//
//	evil\r\nBcc: somewhere@else.example.php
//
// is legal on every filesystem this runs on, and a header ends at CRLF — so the text
// after it stops being a subject and becomes a header of its own.
//
// It matters most with sendmail's `-t`, which reads the recipient list out of the
// headers, but an injected Bcc is delivered by an SMTP server just as willingly.
func TestAHostileFilenameCannotForgeAHeader(t *testing.T) {
	hostile := []struct {
		what    string
		subject string
	}{
		{"CRLF, the classic", "SentinelHost: evil\r\nBcc: attacker@evil.example.php"},
		{"a bare LF", "SentinelHost: evil\nBcc: attacker@evil.example.php"},
		{"a bare CR", "SentinelHost: evil\rBcc: attacker@evil.example.php"},
		{"a NUL, which truncates the field in a C parser", "SentinelHost: evil\x00.php"},
		{"a full body injection", "x\r\n\r\nFrom: bank@example.com\r\n\r\nSend money"},
	}

	for _, h := range hostile {
		out, err := buildSafe("s@example.com", []string{"u@example.com"},
			Message{Subject: h.subject, Text: "body"})
		if err == nil {
			t.Errorf("%s: accepted. The assembled message was:\n%s", h.what, out)
			continue
		}
		if !strings.Contains(err.Error(), "forge") {
			t.Errorf("%s: refused, but the reason does not say why: %v", h.what, err)
		}
		if out != nil {
			t.Errorf("%s: refused AND returned a message", h.what)
		}
	}
}

// The addresses come from a configuration file a person edits, which is exactly where a
// stray paste of a multi-line value ends up.
func TestAnAddressCannotForgeAHeaderEither(t *testing.T) {
	if _, err := buildSafe("s@example.com\r\nBcc: attacker@evil.example", []string{"u@example.com"},
		Message{Subject: "ok"}); err == nil {
		t.Error("a sender address carrying a header was accepted")
	}
	if _, err := buildSafe("s@example.com", []string{"u@example.com\r\nBcc: attacker@evil.example"},
		Message{Subject: "ok"}); err == nil {
		t.Error("a recipient address carrying a header was accepted")
	}
}

// Refusing must not become refusing everything: accented subjects are the ordinary case
// this project ships for, and a check that broke them would be reverted within a day.
func TestOrdinarySubjectsStillGoThrough(t *testing.T) {
	fine := []string{
		"SentinelHost: 3 findings on motelgrandplace.com.br",
		"SentinelHost: arquivo suspeito encontrado — ação recomendada",
		"SentinelHost: /home/u/public_html/wp-includes/pluggable.php",
		"SentinelHost: file with 'quotes' and (parens) and a: colon",
		"",
	}
	for _, subject := range fine {
		out, err := buildSafe("s@example.com", []string{"u@example.com"},
			Message{Subject: subject, Text: "body"})
		if err != nil {
			t.Errorf("refused an ordinary subject %q: %v", subject, err)
			continue
		}
		if len(out) == 0 {
			t.Errorf("subject %q produced an empty message", subject)
		}
	}
}
