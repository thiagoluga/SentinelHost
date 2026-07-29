package integration_test

import (
	"net/url"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
)

// urlURL exists only to keep the cookie jar's signatures readable.
type urlURL = url.URL

// hashOf computes a file's sha256 through the same path the orchestrator uses in
// production.
func hashOf(path string) (string, error) {
	return baseline.HashFile(path)
}
