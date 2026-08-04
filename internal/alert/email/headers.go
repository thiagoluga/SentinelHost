package email

import (
	"fmt"
	"strings"
)

// buildSafe assembles the message, refusing any header field that could forge another.
//
// A header ends at CRLF, so a value containing one does not stay a value: everything
// after it is read as a new header. This is not hypothetical here. The subject of an
// alert carries the path of the offending file, and a file called
//
//	evil\r\nBcc: somewhere@else.example.php
//
// is a legal name on every filesystem this runs on — created by whoever put the malware
// there. A tool that reads attacker-chosen filenames and puts them in mail headers has to
// assume exactly that.
//
// It refuses rather than strips. A silently altered subject would still describe the
// wrong file, and a stripped Bcc would still mean somebody managed to reach into the
// message; both deserve to surface as a failure with a name attached, not as mail that
// looks fine.
//
// Applies to both transports. It matters more with sendmail's `-t`, which takes its
// recipient list from the headers, but an injected Bcc is delivered by an SMTP server too.
func buildSafe(from string, to []string, msg Message) ([]byte, error) {
	if err := checkHeaderValue("the sender address", from); err != nil {
		return nil, err
	}
	for _, addr := range to {
		if err := checkHeaderValue("a recipient address", addr); err != nil {
			return nil, err
		}
	}
	// The subject is checked before encoding, not after: RFC 2047 encodes non-ASCII and
	// leaves a plain-ASCII CRLF exactly where it was.
	if err := checkHeaderValue("the subject", msg.Subject); err != nil {
		return nil, err
	}
	return build(from, to, msg), nil
}

// checkHeaderValue rejects the characters that end a header field.
//
// A lone CR and a lone LF are both refused, not only the CRLF pair: parsers disagree
// about the bare forms, and a value that some of them treat as a line ending is not one
// this has any business passing on. NUL goes too — it truncates the field in a C-based
// MTA, and every sendmail-compatible binary is one.
func checkHeaderValue(what, value string) error {
	if i := strings.IndexAny(value, "\r\n\x00"); i >= 0 {
		return fmt.Errorf("%s contains a line break or a null byte at position %d, which "+
			"would forge an e-mail header; refusing to send", what, i)
	}
	return nil
}
