package email

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// sendmailCandidates are the usual locations of a sendmail-compatible binary.
//
// Not a cPanel thing: accepting mail on stdin with this calling convention is a POSIX
// convention that exim, postfix, ssmtp, msmtp and the original sendmail all honour, which
// is what makes it worth supporting at all. A host that has any MTA almost certainly has
// one of these paths.
//
// Absolute paths, never a PATH lookup: this executes a program, and resolving it through
// an environment variable would let anything that can set PATH choose what runs.
var sendmailCandidates = []string{
	"/usr/sbin/sendmail",
	"/usr/lib/sendmail",
	"/usr/bin/sendmail",
	"/bin/sendmail",
}

// findSendmail returns the first candidate that exists and is executable.
func findSendmail() string {
	for _, p := range sendmailCandidates {
		if isExecutableFile(p) {
			return p
		}
	}
	return ""
}

// sendViaSendmail hands the message to the local MTA.
//
// The appeal is that there is nothing to configure and nothing to authenticate: the
// account is already trusted by the machine it runs on. And on a host whose SPF and DKIM
// name that machine — which is the normal arrangement when the domain is hosted there —
// a message sent this way is better authenticated in the eyes of a receiving spam filter
// than the same message relayed through an unrelated provider.
//
// `-t` reads the recipients from the To/Cc/Bcc headers, so no address is ever passed as
// an argument. `-i` stops a line consisting of a single dot from being read as
// end-of-input, which would silently truncate the body — a snippet of a malicious file
// is exactly the kind of content that can contain one.
func (s *Sender) sendViaSendmail(ctx context.Context, binary string, from string, to []string, msg Message) error {
	body, err := buildSafe(from, to, msg)
	if err != nil {
		return err
	}

	// exec.CommandContext takes an argv: there is no shell, so nothing in these strings
	// can be interpreted as a command. The binary itself comes from a fixed list, never
	// from the message.
	cmd := exec.CommandContext(ctx, binary, "-t", "-i")
	cmd.Stdin = bytes.NewReader(body)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		// The real error, as the SMTP path does: "failed to send" helps nobody discover
		// that the MTA is refusing the sender address.
		return fmt.Errorf("%s refused the message: %s", binary, detail)
	}
	return nil
}

// errNoTransport explains what was tried, rather than reporting an absence.
//
// "Could not send" leaves a user guessing between a missing MTA, a wrong port and a
// firewall. Each of those has a different fix, and the message has to say which one it is
// looking at.
func errNoTransport(triedSendmail bool) error {
	if triedSendmail {
		return fmt.Errorf("no way to send mail: alerts.email.host is empty and no local MTA "+
			"was found at %s. Either configure an SMTP server or install one",
			strings.Join(sendmailCandidates, ", "))
	}
	return errors.New("no SMTP host configured, and alerts.email.transport is set to smtp")
}
