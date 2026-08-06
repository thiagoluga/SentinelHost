package selfupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withKey installs a signing key for the duration of a test and returns a signer.
func withKey(t *testing.T) func([]byte) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := PublicKey
	PublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { PublicKey = old })
	return func(payload []byte) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	}
}

// The thing being replaced is the binary that guards the account. A payload the key did
// not sign is refused, not installed.
func TestAPayloadTheKeyDidNotSignIsRefused(t *testing.T) {
	sign := withKey(t)
	genuine := []byte("the real release")
	sig := sign(genuine)

	if err := Verify(genuine, sig); err != nil {
		t.Fatalf("the genuine release was refused: %v", err)
	}

	// One byte changed is a different program.
	tampered := []byte("the real release.")
	if err := Verify(tampered, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a tampered payload was accepted or failed for the wrong reason: %v", err)
	}

	// A signature from a different key.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSig := base64.StdEncoding.EncodeToString(ed25519.Sign(other, genuine))
	if err := Verify(genuine, otherSig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a signature from another key was accepted: %v", err)
	}

	if err := Verify(genuine, "not base64!!"); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a malformed signature was accepted: %v", err)
	}
}

// A build with no key cannot tell a release from anything else, so it refuses rather than
// trusting what it is handed. "No key configured" must never degrade into "no check".
func TestABuildWithNoKeyRefusesToUpdate(t *testing.T) {
	old := PublicKey
	PublicKey = ""
	defer func() { PublicKey = old }()

	err := Verify([]byte("anything"), "anything")
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("a keyless build accepted a payload: %v", err)
	}

	// A malformed key is a build mistake and must fail the same way.
	PublicKey = "not-a-key"
	if err := Verify([]byte("x"), "y"); !errors.Is(err, ErrUnsigned) {
		t.Errorf("a malformed key did not fail closed: %v", err)
	}
}

// Serving an old release with a known hole is the cheapest attack on an updater that only
// asks whether the offered version is different.
func TestADowngradeIsRefused(t *testing.T) {
	cases := []struct {
		running, offered string
		newer            bool
	}{
		{"v1.2.3", "v1.2.4", true},
		{"v1.2.3", "v1.3.0", true},
		{"v1.2.3", "v2.0.0", true},
		{"v1.2.3", "v1.2.3", false}, // sideways
		{"v1.2.3", "v1.2.2", false}, // backwards
		{"v2.0.0", "v1.9.9", false},
		// The one a string comparison gets wrong, and gets wrong silently: "v0.10.0" sorts
		// before "v0.9.0" as text, so the newer release would be refused for as long as
		// the project kept shipping, looking exactly like "you are up to date".
		{"v0.9.0", "v0.10.0", true},
		{"v0.10.0", "v0.9.0", false},
		// Suffixes are dropped for comparison rather than making the version unreadable.
		{"v1.2.3", "v1.2.4-rc1", true},
	}

	for _, c := range cases {
		got, err := IsNewer(c.running, c.offered)
		if err != nil {
			t.Errorf("%s -> %s: %v", c.running, c.offered, err)
			continue
		}
		if got != c.newer {
			t.Errorf("%s -> %s: got newer=%v, wanted %v", c.running, c.offered, got, c.newer)
		}
	}
}

// A development build was made from a checkout. Replacing it with a release would discard
// whatever the person was testing, so it is not upgraded automatically.
func TestADevelopmentBuildIsNotUpgraded(t *testing.T) {
	if _, err := IsNewer("dev", "v1.0.0"); err == nil {
		t.Error("a dev build was offered an upgrade path")
	}
	if _, err := IsNewer("v1.0.0", "not-a-version"); err == nil {
		t.Error("an unreadable offered version was accepted")
	}
}

// The install must never leave the path holding a partial file: a half-written binary on a
// cron-driven install is a scanner that stops running and says nothing.
func TestTheOldBinaryIsKeptAndTheNewOneIsWholeOrAbsent(t *testing.T) {
	sign := withKey(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "sentinelhost")

	if err := os.WriteFile(target, []byte("the old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	payload := []byte("the new binary, longer than the old one")
	prev, err := Install(payload, sign(payload), target)
	if err != nil {
		t.Fatalf("installing: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("the target holds %q", got)
	}
	old, err := os.ReadFile(prev)
	if err != nil || string(old) != "the old binary" {
		t.Errorf("the previous binary was not kept: %q, %v", old, err)
	}
	if !strings.HasSuffix(prev, ".prev") {
		t.Errorf("the rollback copy is at %q", prev)
	}
}

// A refused payload must not touch the installed binary at all.
func TestARefusedPayloadLeavesTheBinaryAlone(t *testing.T) {
	sign := withKey(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "sentinelhost")
	if err := os.WriteFile(target, []byte("the old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Signed, then modified.
	payload := []byte("legitimate")
	sig := sign(payload)
	if _, err := Install([]byte("hostile"), sig, target); err == nil {
		t.Fatal("a payload that failed verification was installed")
	}

	got, _ := os.ReadFile(target)
	if string(got) != "the old binary" {
		t.Errorf("the installed binary changed: %q", got)
	}
	if _, err := os.Stat(target + ".prev"); err == nil {
		t.Error("a rollback copy was made for an install that never happened")
	}
	// And no debris beside it.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries after a refused install", len(entries))
	}
}

// The asset is chosen from the running process, never from the response: letting a server
// pick would let it hand an arm64 binary to an amd64 account, and the failure would look
// like a corrupt download.
func TestTheAssetIsNamedFromThisProcess(t *testing.T) {
	name := AssetName()
	if !strings.HasPrefix(name, "sentinelhost-") || strings.Count(name, "-") != 2 {
		t.Errorf("asset name %q is not sentinelhost-GOOS-GOARCH", name)
	}
}

// The ceiling exists so a hostile length cannot fill the account's disk.
func TestTheDownloadHasACeiling(t *testing.T) {
	if _, err := ReadAll(strings.NewReader("0123456789"), 5); err == nil {
		t.Error("a payload over the ceiling was accepted")
	}
	b, err := ReadAll(strings.NewReader("01234"), 5)
	if err != nil || len(b) != 5 {
		t.Errorf("a payload at the ceiling was refused: %v", err)
	}
}
