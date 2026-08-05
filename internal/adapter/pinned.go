package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Pinned is a file this project downloads: where it comes from, and what it must be.
//
// Both fields matter and neither is sufficient alone.
//
// The URL was a moving branch — `.../master/dist/scanner`, `.../master/data/php.yar`.
// Whatever is at the end of a branch today is not what anyone reviewed, and these are not
// inert files: the AMWScan download is a PHP program this tool then executes, and the
// php-malware-finder download is a YARA ruleset that decides which of the user's files get
// quarantined. A ruleset matching `wp-config.php` does not need code execution to destroy
// a site — SentinelHost would do the destroying, on schedule, believing it was working.
//
// So a commit, which is immutable, plus the digest of the bytes at that commit. The commit
// says which review this is; the digest says nobody rewrote history or intercepted the
// transfer. Upstream cannot change what an installed copy of SentinelHost runs, and
// updating a pin is a commit in this repository — visible, reviewable, and tied to a
// release someone chose to install.
type Pinned struct {
	// Name is what appears in an error. "the AMWScan scanner", not a URL fragment.
	Name string
	// URL must address immutable content: a commit SHA or a release asset, never a branch
	// and never `latest`.
	URL string
	// SHA256 is the lowercase hex digest of the exact bytes expected at URL.
	SHA256 string
}

// Verify checks a downloaded file against its pin.
//
// It takes the digest rather than the path so the caller can compute it while streaming,
// and so nothing has to trust that the file on disk is still the file that was fetched.
func (p Pinned) Verify(got string) error {
	if p.SHA256 == "" {
		// An empty pin is a programming error, not a configuration one. Treating it as
		// "skip the check" is how verification quietly stops happening.
		return fmt.Errorf("%s has no pinned digest, so nothing can be verified", p.Name)
	}
	if !strings.EqualFold(got, p.SHA256) {
		return fmt.Errorf(
			"%s does not match what this version of SentinelHost pinned.\n"+
				"  expected %s\n"+
				"  received %s\n"+
				"  from     %s\n"+
				"This is refused rather than used. The file decides what runs on your account "+
				"or which of your files are quarantined, and a mismatch means it is not the "+
				"file this release was built against",
			p.Name, p.SHA256, strings.ToLower(got), p.URL)
	}
	return nil
}

// Hasher returns a hash to write the download through, and a function reading the result.
//
// Streaming rather than re-reading the file: a check that opens the path again can be
// beaten by anything that replaces the file in between, and on shared hosting the
// temporary directory is not private.
func Hasher() (hash.Hash, func() string) {
	h := sha256.New()
	return h, func() string { return hex.EncodeToString(h.Sum(nil)) }
}

// VerifyReader copies src to dst and fails if the bytes do not match the pin.
//
// Nothing is written to its final destination before the digest is known: the caller
// writes to a temporary file, and only renames it after this returns nil.
func (p Pinned) VerifyReader(dst io.Writer, src io.Reader) error {
	h, sum := Hasher()
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		return fmt.Errorf("downloading %s: %w", p.Name, err)
	}
	return p.Verify(sum())
}
