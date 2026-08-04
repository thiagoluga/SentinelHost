package email

import (
	"net/smtp"
	"strings"
	"testing"
)

type fakeExt struct{ mechanisms string }

func (f fakeExt) Extension(name string) (bool, string) {
	if name != "AUTH" {
		return false, ""
	}
	return f.mechanisms != "", f.mechanisms
}

// Outlook advertises LOGIN and refuses PLAIN, answering
// `504 5.7.4 Unrecognized authentication type` — which reads like a rejected account and
// is the server declining the method. The password never left the client.
func TestTheMechanismComesFromWhatTheServerOffers(t *testing.T) {
	cases := []struct {
		what       string
		advertises string
		want       string
	}{
		{"Outlook", "LOGIN XOAUTH2", "*email.loginAuth"},
		{"a server offering both", "PLAIN LOGIN", "*smtp.plainAuth"},
		{"a server offering only PLAIN", "PLAIN", "*smtp.plainAuth"},
		{"lowercase, as some servers send it", "login", "*email.loginAuth"},
		// Silence is not evidence that authentication is unsupported, and refusing to try
		// would break a setup that works today.
		{"a server that advertises nothing", "", "*smtp.plainAuth"},
		{"OAuth only", "XOAUTH2", "email.unsupportedAuth"},
	}

	for _, c := range cases {
		got := chooseAuth(fakeExt{c.advertises}, "u@example.com", "pw", "smtp.example.com")
		if name := typeName(got); name != c.want {
			t.Errorf("%s advertises %q: chose %s, wanted %s", c.what, c.advertises, name, c.want)
		}
	}
}

func typeName(a smtp.Auth) string {
	switch a.(type) {
	case *loginAuth:
		return "*email.loginAuth"
	case unsupportedAuth:
		return "email.unsupportedAuth"
	default:
		return "*smtp.plainAuth"
	}
}

// LOGIN base64-encodes the password, which is not encryption. Sending it over a plain
// connection would put it on the wire readable by anyone in the path, and nothing would
// look wrong — so the refusal has to come from the mechanism itself, not from the caller
// remembering to configure TLS.
func TestLoginRefusesAnUnencryptedConnection(t *testing.T) {
	a := &loginAuth{username: "u@example.com", password: "pw", host: "smtp.example.com"}

	_, _, err := a.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: false})
	if err == nil {
		t.Fatal("the password would have been sent over an unencrypted connection")
	}
	if !strings.Contains(err.Error(), "unencrypted") {
		t.Errorf("the error does not say why: %v", err)
	}

	if _, _, err := a.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: true}); err != nil {
		t.Errorf("a TLS connection to the right host was refused: %v", err)
	}
}

// A server that is not the one we meant to reach does not get the credentials.
func TestLoginRefusesAnUnexpectedHost(t *testing.T) {
	a := &loginAuth{username: "u@example.com", password: "pw", host: "smtp.example.com"}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "evil.example.net", TLS: true}); err == nil {
		t.Fatal("the password would have gone to a host we did not ask for")
	}
}

// The prompt text is not standardised, so it is matched loosely — and anything
// unrecognised is answered with an error rather than with the password.
func TestLoginAnswersThePromptsAndNothingElse(t *testing.T) {
	a := &loginAuth{username: "u@example.com", password: "pw", host: "smtp.example.com"}

	for _, prompt := range []string{"Username:", "username", "User Name\x00", "USERNAME:"} {
		got, err := a.Next([]byte(prompt), true)
		if err != nil || string(got) != "u@example.com" {
			t.Errorf("prompt %q returned (%q, %v), wanted the username", prompt, got, err)
		}
	}
	for _, prompt := range []string{"Password:", "password", "PASSWORD"} {
		got, err := a.Next([]byte(prompt), true)
		if err != nil || string(got) != "pw" {
			t.Errorf("prompt %q returned (%q, %v), wanted the password", prompt, got, err)
		}
	}

	got, err := a.Next([]byte("Something else entirely"), true)
	if err == nil {
		t.Error("an unrecognised prompt was answered instead of refused")
	}
	if string(got) == "pw" {
		t.Error("an unrecognised prompt was answered WITH THE PASSWORD")
	}

	// more=false means the exchange is over; there is nothing left to say.
	if got, err := a.Next(nil, false); err != nil || got != nil {
		t.Errorf("the end of the exchange returned (%q, %v)", got, err)
	}
}
