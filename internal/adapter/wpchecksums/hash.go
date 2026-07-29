package wpchecksums

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashFileSHA256 and HashFileMD5 expose a file's hashes.
//
// They exist so tests can build expectations from the real content they wrote
// themselves, instead of from copied constants — a literal hash in a test ages
// silently when the fixture changes.
func HashFileSHA256(path string) (string, error) {
	_, sha, err := hashFile(path)
	return sha, err
}

// HashFileMD5 returns the MD5, which is the format the core API publishes.
func HashFileMD5(path string) (string, error) {
	md5sum, _, err := hashFile(path)
	return md5sum, err
}

// pathHash returns the sha256 of the path.
//
// It serves MISSING files, which by definition have no content to hash. The
// schema requires a sha256 because it is the deduplication key across engines;
// using the hash of the path gives the finding a stable key across cycles
// without pretending a file is there. No other engine will produce that same
// hash, so the finding never merges by accident with one for a real file.
func pathHash(path string) string {
	sum := sha256.Sum256([]byte("sentinelhost:missing-core-file:" + path))
	return hex.EncodeToString(sum[:])
}
