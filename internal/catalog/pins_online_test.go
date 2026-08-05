package catalog_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/catalog"
)

// The digest in a manifest is whatever the submitter typed.
//
// Everything else about this catalogue is checked offline, which means a reviewer merging
// a pull request is trusting one field they cannot see. This downloads each entry and
// compares — the only check that turns "the submission says so" into "we looked".
//
// Network-dependent, so it runs when SENTINELHOST_ONLINE=1 is set: in CI on pull requests
// touching the catalogue, and never in the offline suite. It skips with a reason rather
// than silently, because a check nobody notices is not running is not a check.
func TestEveryPinnedDigestMatchesWhatIsActuallyThere(t *testing.T) {
	if os.Getenv("SENTINELHOST_ONLINE") != "1" {
		t.Skip("needs the network: set SENTINELHOST_ONLINE=1 (CI does this for catalogue changes)")
	}

	all, err := catalog.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("no entries, so this would pass without verifying anything")
	}

	client := &http.Client{Timeout: 2 * time.Minute}
	for _, e := range all {
		t.Run(e.Slug, func(t *testing.T) {
			resp, err := client.Get(e.URL)
			if err != nil {
				t.Fatalf("downloading: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s answered %s. A pinned URL that stops resolving means the "+
					"install is broken for everyone who has not run it yet", e.URL, resp.Status)
			}

			h := sha256.New()
			n, err := io.Copy(h, io.LimitReader(resp.Body, 64<<20))
			if err != nil {
				t.Fatalf("reading: %v", err)
			}
			got := hex.EncodeToString(h.Sum(nil))
			if got != e.SHA256 {
				t.Errorf("the manifest claims a digest the URL does not produce.\n"+
					"  manifest %s\n  actual   %s\n  url      %s\n"+
					"Either the pin is wrong, or the content at an address that was supposed "+
					"to be immutable has changed — and the second is worth understanding "+
					"before this is merged", e.SHA256, got, e.URL)
			}
			t.Logf("%d bytes verified", n)
		})
	}
}
