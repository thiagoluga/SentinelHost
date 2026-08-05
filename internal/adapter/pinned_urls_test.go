package adapter_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/adapter/amwscan"
	"github.com/thiagoluga/SentinelHost/internal/adapter/pmf"
)

// A pin whose URL is a branch is not a pin.
//
// Both of these were `.../master/...` — whatever is at the end of a branch today is not
// what anyone reviewed, and one of them is a PHP program this tool executes. A commit SHA
// is immutable; `master`, `main` and `latest` are promises the upstream can revise without
// telling anybody.
func TestEveryPinnedURLAddressesImmutableContent(t *testing.T) {
	commit := regexp.MustCompile(`/[0-9a-f]{40}/`)

	for _, p := range []struct {
		what string
		url  string
		sha  string
	}{
		{"AMWScan", amwscan.Phar.URL, amwscan.Phar.SHA256},
		{"the YARA rules", pmf.Rules.URL, pmf.Rules.SHA256},
		{"the YARA whitelist", pmf.Whitelist.URL, pmf.Whitelist.SHA256},
	} {
		for _, moving := range []string{"/master/", "/main/", "/latest/", "/HEAD/"} {
			if strings.Contains(p.url, moving) {
				t.Errorf("%s is downloaded from %s, which upstream can change after review: %s",
					p.what, strings.Trim(moving, "/"), p.url)
			}
		}
		if !commit.MatchString(p.url) {
			t.Errorf("%s is not addressed by a commit SHA: %s", p.what, p.url)
		}
		if len(p.sha) != 64 {
			t.Errorf("%s has no usable digest (%q), so the URL being immutable buys nothing "+
				"against an intercepted transfer", p.what, p.sha)
		}
	}
}
