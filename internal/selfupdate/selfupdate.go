// Package selfupdate replaces the running binary with a newer, signed one.
//
// This is the most dangerous code in the project, and it is worth saying why before
// reading any of it. Every other defect here costs one account. A compromised update
// costs every account at once, silently, with the tool's own permissions — and the thing
// being replaced is a security tool the user installed precisely because they could not
// watch their own files.
//
// So the rules are stricter than anywhere else, and each one is here because its absence
// is exploitable rather than because it is good practice:
//
//   - A signature, verified against a key compiled INTO the running binary. The installer
//     checks a SHA256SUMS file fetched from the same place as the binary, which catches a
//     corrupted transfer and nothing else: whoever can serve the binary can serve the
//     checksum. A signature moves the trust to a key an attacker would have to steal
//     separately, and the verification happens offline, against bytes already downloaded.
//   - Never a downgrade. Serving an old release with a known hole is the cheapest attack
//     against an updater that only asks "is this different".
//   - Never automatic. A security tool that replaces itself unattended on shared hosting
//     is behaving the way the thing it hunts behaves, and the user has no way to tell the
//     difference.
//   - The previous binary is kept. An update that cannot be undone is a single point of
//     failure for whoever is on the other end of a bad release.
package selfupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// PublicKey is the release-signing key, set at build time with -ldflags.
//
// Empty on a development build, and that is not a gap to paper over: a binary built from
// a checkout has no idea what a legitimate release looks like, so it refuses to update
// itself rather than trusting whatever it is handed. See ErrUnsigned.
var PublicKey = ""

var (
	// ErrUnsigned means this build cannot verify a release, so it will not install one.
	ErrUnsigned = errors.New("this build has no release key compiled in")
	// ErrBadSignature means the download is not what the key says it should be.
	ErrBadSignature = errors.New("the signature does not match the release key")
	// ErrNotNewer means the offered version is not an upgrade.
	ErrNotNewer = errors.New("the offered version is not newer than the running one")
)

// Release is what a check found.
type Release struct {
	Version string
	// URL and Signature address the asset for THIS platform.
	URL       string
	Signature string
	SHA256    string
}

// Verify checks a downloaded release against the compiled-in key.
//
// It takes the bytes rather than a path: verifying a file and then installing it from disk
// leaves a window where something else can replace it, and on shared hosting the directory
// this runs in is not private.
func Verify(payload []byte, signature string) error {
	if PublicKey == "" {
		return fmt.Errorf("%w, so it cannot tell a real release from anything else. "+
			"Download the new version yourself and check its signature", ErrUnsigned)
	}
	key, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		// A malformed key is a build mistake, and it must not degrade into "no check".
		return fmt.Errorf("%w: the compiled-in key is not a valid ed25519 public key",
			ErrUnsigned)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return fmt.Errorf("%w: the signature is not valid base64", ErrBadSignature)
	}
	if !ed25519.Verify(key, payload, sig) {
		return fmt.Errorf("%w. The download is refused rather than installed: it would "+
			"replace the binary that guards this account", ErrBadSignature)
	}
	return nil
}

// IsNewer reports whether offered is a later version than running.
//
// Refusing to move sideways or backwards is the point. An updater that installs anything
// "different" can be handed last year's release with a known hole — a far cheaper attack
// than forging a signature, and one that needs no key at all if the check is only for
// inequality.
//
// A development build ("dev", or anything unparseable) is never upgraded automatically:
// it was built from a checkout, and quietly replacing it with a release would discard
// whatever the person was testing.
func IsNewer(running, offered string) (bool, error) {
	r, err := parseVersion(running)
	if err != nil {
		return false, fmt.Errorf("the running version %q is not a release version, so there "+
			"is nothing to compare against. Update by installing deliberately", running)
	}
	o, err := parseVersion(offered)
	if err != nil {
		return false, fmt.Errorf("the offered version %q cannot be read as a version", offered)
	}
	for i := range r {
		if o[i] != r[i] {
			return o[i] > r[i], nil
		}
	}
	return false, nil
}

// parseVersion reads vMAJOR.MINOR.PATCH into comparable numbers.
//
// Numeric, never lexicographic: "v0.10.0" sorts before "v0.9.0" as a string, so a string
// comparison would refuse the newer release for as long as the project keeps shipping —
// silently, and looking exactly like "you are up to date".
func parseVersion(v string) ([3]int, error) {
	var out [3]int
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	// A pre-release or build suffix is dropped for comparison; ordering within one patch
	// level is not something this needs to decide.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("not MAJOR.MINOR.PATCH: %q", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("not a number: %q", p)
		}
		out[i] = n
	}
	return out, nil
}

// AssetName is the release asset this build should be replaced by.
//
// Named from the running process rather than from anything the server says: letting a
// response choose which asset to install would let it hand an arm64 binary to an amd64
// account, or the reverse, and the failure would look like a corrupt download.
func AssetName() string {
	return fmt.Sprintf("sentinelhost-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// Install writes the verified payload over the running binary, keeping the old one.
//
// The order matters and mirrors the quarantine's: write the new file beside the target,
// verify it, move the current one aside, and only then move the new one into place. At no
// point is there a moment where the path holds a partial file — a half-written binary on a
// cron-driven install is a scanner that stops running and says nothing.
func Install(payload []byte, signature, targetPath string) (previous string, err error) {
	if err := Verify(payload, signature); err != nil {
		return "", err
	}

	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".sentinelhost-new-*")
	if err != nil {
		return "", fmt.Errorf("creating the replacement next to the current binary: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("writing the replacement: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("closing the replacement: %w", err)
	}
	if err = os.Chmod(tmpName, 0o755); err != nil {
		return "", fmt.Errorf("making the replacement executable: %w", err)
	}

	// Kept, not deleted. An update that cannot be undone is a single point of failure for
	// whoever is on the other end of a bad release, and the person who needs the rollback
	// is by definition someone whose tool just stopped working.
	previous = targetPath + ".prev"
	_ = os.Remove(previous)
	if err = os.Rename(targetPath, previous); err != nil {
		return "", fmt.Errorf("setting the current binary aside: %w", err)
	}
	if err = os.Rename(tmpName, targetPath); err != nil {
		// Put it back rather than leaving the account with no scanner at all.
		_ = os.Rename(previous, targetPath)
		return "", fmt.Errorf("installing the replacement: %w", err)
	}
	return previous, nil
}

// Digest returns the hex sha256 of payload, for reporting rather than for trust.
//
// The digest is what a user compares by hand against the release page. It is NOT what
// authorises the install: whoever can serve the binary can serve a matching digest, which
// is the whole reason the signature exists.
func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// ReadAll reads a payload with a ceiling, so a hostile length cannot fill the account.
func ReadAll(r io.Reader, maxBytes int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("the download exceeded %d bytes", maxBytes)
	}
	return b, nil
}
