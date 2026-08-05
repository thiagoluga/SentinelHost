package adapter_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
)

const (
	body = "rule Backdoor { strings: $a = \"eval(\" condition: $a }\n"
)

func pinFor(t *testing.T, content string) (adapter.Pinned, string) {
	t.Helper()
	h, sum := adapter.Hasher()
	if _, err := h.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	d := sum()
	return adapter.Pinned{Name: "the test rules", URL: "https://example.test/php.yar", SHA256: d}, d
}

// The download decides which of the user's files get quarantined, or what code runs on
// their account. A file that is not the one this release was built against is refused, not
// used — the whole point of pinning is that a later upstream change cannot reach an
// installed copy.
func TestATamperedDownloadIsRefused(t *testing.T) {
	pin, _ := pinFor(t, body)

	var out bytes.Buffer
	err := pin.VerifyReader(&out, strings.NewReader(body+"\nrule AlsoMatchWpConfig { condition: true }"))
	if err == nil {
		t.Fatal("a modified ruleset was accepted. A rule matching wp-config.php needs no code " +
			"execution to destroy a site: SentinelHost would quarantine it, on schedule, " +
			"believing it was working")
	}
	// The error has to be actionable, not "checksum mismatch".
	for _, want := range []string{"expected", "received", "https://example.test/php.yar"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// The unmodified file passes, or the check would simply break every install.
func TestTheExpectedDownloadIsAccepted(t *testing.T) {
	pin, _ := pinFor(t, body)
	var out bytes.Buffer
	if err := pin.VerifyReader(&out, strings.NewReader(body)); err != nil {
		t.Fatalf("the pinned file was refused: %v", err)
	}
	if out.String() != body {
		t.Error("the bytes written differ from the bytes verified")
	}
}

// An empty pin must fail closed. Treating "no digest configured" as "nothing to check" is
// how verification silently stops happening — and it would look exactly like success.
func TestAnEmptyPinIsAFailureNotASkip(t *testing.T) {
	pin := adapter.Pinned{Name: "the test rules", URL: "https://example.test/x"}
	var out bytes.Buffer
	err := pin.VerifyReader(&out, strings.NewReader(body))
	if err == nil {
		t.Fatal("a download with no pinned digest was accepted, so an override without a " +
			"digest is a way past the check")
	}
	if !strings.Contains(err.Error(), "no pinned digest") {
		t.Errorf("the error does not say the pin is missing: %v", err)
	}
}

// Case must not decide the outcome: a digest pasted in uppercase is the same digest.
func TestTheDigestComparisonIgnoresCase(t *testing.T) {
	pin, d := pinFor(t, body)
	pin.SHA256 = strings.ToUpper(d)
	var out bytes.Buffer
	if err := pin.VerifyReader(&out, strings.NewReader(body)); err != nil {
		t.Errorf("an uppercase digest was rejected: %v", err)
	}
}
