// Package email sends alerts over SMTP.
//
// It uses the stdlib (net/smtp) rather than an external library: the alert bodies
// are plain text and basic HTML, and one more dependency in a binary that promises
// "no mandatory dependencies" needs a better justification than that
// (Principle VII).
package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// DialTimeout of the SMTP connection.
const DialTimeout = 20 * time.Second

// Message is an e-mail ready to send.
type Message struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

// Sender sends e-mails.
type Sender struct {
	cfg config.EmailConfig
	// dial is injectable in tests, so no real server is needed.
	dial func(addr string) (net.Conn, error)
}

// New creates the sender.
func New(cfg config.EmailConfig) *Sender {
	return &Sender{
		cfg: cfg,
		dial: func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, DialTimeout)
		},
	}
}

// WithDialer swaps the dialer. Tests only.
func (s *Sender) WithDialer(fn func(string) (net.Conn, error)) *Sender {
	s.dial = fn
	return s
}

// Send delivers the message.
//
// It returns the server's REAL error. The spec requires the "send test" button to
// show the actual error: "failed to send" helps nobody find out that the hosting
// blocks port 587.
func (s *Sender) Send(ctx context.Context, msg Message) error {
	if s.cfg.Host == "" {
		return errors.New("no SMTP host configured")
	}
	recipients := msg.To
	if len(recipients) == 0 {
		recipients = s.cfg.To
	}
	if len(recipients) == 0 {
		return errors.New("no recipient configured")
	}

	addr := net.JoinHostPort(s.cfg.Host, fmt.Sprint(s.cfg.Port))

	conn, err := s.dial(addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}

	// Implicit TLS (port 465) wraps the connection before the SMTP handshake.
	if s.cfg.TLS == "tls" {
		conn = tls.Client(conn, &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12})
	}

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("starting the SMTP session: %w", err)
	}
	defer func() { _ = c.Close() }()

	// Honour cancellation: a hung SMTP must not hold the cycle up.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if s.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("the server %s does not offer STARTTLS; adjust alerts.email.tls", s.cfg.Host)
		}
		if err := c.StartTLS(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("negotiating STARTTLS: %w", err)
		}
	}

	if s.cfg.Username != "" {
		// Which mechanism, decided from what the server advertises rather than assumed.
		// Outlook refuses PLAIN and answers 504 "Unrecognized authentication type", which
		// looks like a rejected account and is the server declining the method — the
		// password never leaves the client.
		auth := chooseAuth(c, s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("authenticating with %s: %w", s.cfg.Host, err)
		}
	}

	if err := c.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("the sender %q was refused: %w", s.cfg.From, err)
	}
	for _, to := range recipients {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("the recipient %q was refused: %w", to, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("starting the message body: %w", err)
	}
	if _, err := w.Write(build(s.cfg.From, recipients, msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("writing the message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finalizing the message: %w", err)
	}
	return c.Quit()
}

// build assembles the MIME message.
func build(from string, to []string, msg Message) []byte {
	var b strings.Builder
	boundary := "sentinelhost-" + fmt.Sprint(time.Now().UnixNano())

	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeSubject(msg.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	// Mark the origin so filters and the user themselves recognize it.
	b.WriteString("X-Mailer: SentinelHost\r\n")

	if msg.HTML == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(msg.Text)
		return []byte(b.String())
	}

	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", boundary, msg.Text)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n", boundary, msg.HTML)
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}

// encodeSubject applies RFC 2047 when there is a non-ASCII character.
//
// Without it, a subject carrying accented text arrives unreadable in a good share
// of clients — and the subject is the first thing the user sees in a security
// alert.
func encodeSubject(s string) string {
	ascii := true
	for _, r := range s {
		if r > 127 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	return mimeEncode(s)
}
