package email

import (
	"errors"
	"fmt"
	"net/smtp"
	"strings"
)

// loginAuth implements the LOGIN mechanism, which the standard library does not.
//
// Outlook, Office 365 and several cPanel mail servers advertise LOGIN and refuse PLAIN.
// Against smtp-mail.outlook.com, PLAIN comes back as:
//
//	504 5.7.4 Unrecognized authentication type
//
// which reads like a broken account and is nothing of the kind — the password was never
// sent. It is the server declining the mechanism, and 504 is easy to mistake for 535
// (bad credentials) when the only visible symptom is "it will not send".
//
// LOGIN is PLAIN with extra steps: the server prompts for the username, then for the
// password, each base64-encoded. net/smtp handles the encoding; this only answers.
type loginAuth struct {
	username, password string
	host               string
}

// Start refuses to proceed unless the connection is already encrypted.
//
// This mirrors what smtp.PlainAuth does, and it is the reason to copy that behaviour
// rather than simply answering the prompts: LOGIN sends the password in base64, which is
// not encryption. Without the check, misconfiguring `tls` would put the password on the
// wire in a form anyone watching can read, and nothing would appear to be wrong.
//
// TLS is trusted only for the host we meant to reach: a server that redirected us
// elsewhere must not be handed the credentials.
func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("refusing to send the password over an unencrypted " +
			"connection: set alerts.email.tls to starttls or tls")
	}
	if server.Name != a.host {
		return "", nil, fmt.Errorf("connected to %q while expecting %q; not sending the password",
			server.Name, a.host)
	}
	return "LOGIN", nil, nil
}

// Next answers the server's prompts.
//
// The prompt text is not standardised — "Username:", "User Name", "Nome de utilizador"
// on a localised server — so it is matched loosely and by order, rather than by an exact
// string that would work on one provider and fail on the next.
func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch prompt := strings.ToLower(strings.TrimSpace(string(fromServer))); {
	case strings.Contains(prompt, "user"):
		return []byte(a.username), nil
	case strings.Contains(prompt, "pass"):
		return []byte(a.password), nil
	default:
		// An unrecognised prompt is answered with nothing rather than with the password.
		// Guessing here is how a credential ends up somewhere it was not meant to go.
		return nil, fmt.Errorf("unexpected prompt from %s during LOGIN: %q", a.host, fromServer)
	}
}

// chooseAuth picks a mechanism the server actually advertises.
//
// Order matters, and it is deliberately PLAIN first: it is one round trip instead of
// three and every server that offers both accepts it. LOGIN exists for the ones that
// refuse PLAIN, which is where this started.
//
// When the server advertises neither — or says nothing at all, which some do — PLAIN is
// still attempted rather than failing early. A server that omits the AUTH line and then
// accepts credentials is rarer than a working setup, but refusing to try would turn a
// send that used to work into a failure on an upgrade.
func chooseAuth(c interface {
	Extension(string) (bool, string)
}, username, password, host string) smtp.Auth {
	_, mechanisms := c.Extension("AUTH")
	m := strings.ToUpper(mechanisms)

	if strings.Contains(m, "PLAIN") || m == "" {
		return smtp.PlainAuth("", username, password, host)
	}
	if strings.Contains(m, "LOGIN") {
		return &loginAuth{username: username, password: password, host: host}
	}
	// Something is offered, and it is neither. Say which, because the alternative is the
	// caller reading "authentication failed" and changing the password that was fine.
	return unsupportedAuth(mechanisms)
}

// unsupportedAuth carries the server's list into the error instead of discarding it.
type unsupportedAuth string

func (u unsupportedAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "", nil, fmt.Errorf("the server offers only %q, and this build supports PLAIN "+
		"and LOGIN. OAuth-only accounts need an app password instead", string(u))
}

func (u unsupportedAuth) Next([]byte, bool) ([]byte, error) { return nil, nil }
