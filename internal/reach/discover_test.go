package reach_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/reach"
)

// A hosting account is rarely one site. Addon domains, subdomains and parked domains each
// get their own directory, and a webshell in a secondary domain is exactly as executable
// as one in the primary.
//
// Asking the user to list the roots by hand means the list is right on the day they wrote
// it and wrong the first time they add a domain — and nothing would say so, because a
// MISSING root only makes findings look less urgent than they are. That is the direction
// this project cannot afford to be wrong in, so the roots come from the panel's own
// records.

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// A cPanel account with three domains, which is the case the manual list gets wrong.
func account(t *testing.T) string {
	t.Helper()
	home := t.TempDir()

	roots := map[string]string{
		"primary.com":     filepath.Join(home, "public_html"),
		"addon.com":       filepath.Join(home, "public_html", "addon"),
		"sub.primary.com": filepath.Join(home, "sub"),
	}
	for domain, root := range roots {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", root, err)
		}
		write(t, filepath.Join(home, ".cpanel", "userdata", domain),
			"main_domain: primary.com\ndocumentroot: "+root+"\nusergroup: u\n")
	}
	return home
}

func TestEveryDomainsRootIsFound(t *testing.T) {
	home := account(t)

	got := reach.DiscoverDocumentRoots(home)
	if len(got) != 3 {
		t.Fatalf("found %d root(s), want 3 — a domain left out makes its findings look "+
			"less urgent than they are:\n  %v", len(got), got)
	}
}

// A domain can be configured and never deployed. A root that is not there classifies
// nothing while looking like coverage.
func TestARootThatDoesNotExistIsNotReported(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".cpanel", "userdata", "ghost.com"),
		"documentroot: "+filepath.Join(home, "never-deployed")+"\n")

	if got := reach.DiscoverDocumentRoots(home); len(got) != 0 {
		t.Errorf("reported a root that does not exist: %v", got)
	}
}

// The .cache copies repeat the same domains and can lag behind a change. A stale root is
// worse than a missing one: it points confidently at the wrong directory.
func TestTheCacheFilesAreIgnored(t *testing.T) {
	home := t.TempDir()
	live := filepath.Join(home, "public_html")
	stale := filepath.Join(home, "old_root")
	for _, d := range []string{live, stale} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(home, ".cpanel", "userdata", "site.com"), "documentroot: "+live+"\n")
	write(t, filepath.Join(home, ".cpanel", "userdata", "site.com.cache"), "documentroot: "+stale+"\n")

	for _, r := range reach.DiscoverDocumentRoots(home) {
		if r == stale {
			t.Error("a .cache file's root was used: those lag behind a change, and a stale " +
				"root points confidently at the wrong directory")
		}
	}
}

// Without the panel's records, a directory that behaves like a site still counts.
func TestSitesAreFoundWithoutCPanelRecords(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, "public_html", "index.php"), "<?php\n")
	write(t, filepath.Join(home, "otherdomain.com", "index.html"), "<html>\n")

	got := reach.DiscoverDocumentRoots(home)
	if len(got) != 2 {
		t.Errorf("found %d, want both directories: %v", len(got), got)
	}
}

// The account's own furniture is not a site. The trash especially: it is full of index
// files from deleted installations, and calling it a document root would say the web
// serves things it does not.
func TestTheAccountsOwnDirectoriesAreNotSites(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, "public_html", "index.php"), "<?php\n")
	for _, d := range []string{".trash", "mail", "logs", ".softaculous", "tmp"} {
		write(t, filepath.Join(home, d, "site", "index.php"), "<?php\n")
	}

	for _, r := range reach.DiscoverDocumentRoots(home) {
		rel, _ := filepath.Rel(home, r)
		first, _, _ := cut(filepath.ToSlash(rel), "/")
		for _, bad := range []string{".trash", "mail", "logs", ".softaculous", "tmp"} {
			if first == bad {
				t.Errorf("%s was reported as a document root; the web does not serve it, and "+
					"saying it does claims coverage that is not there", r)
			}
		}
	}
}

// An account with nothing recognisable returns nothing, and the caller must read that as
// "unknown" rather than "nothing is served" — Location.Reachable() already does.
func TestAnEmptyAccountClaimsNothing(t *testing.T) {
	if got := reach.DiscoverDocumentRoots(t.TempDir()); len(got) != 0 {
		t.Errorf("invented %d root(s) on an empty account: %v", len(got), got)
	}
}

// And the discovered roots have to work with the classifier they feed.
func TestDiscoveredRootsClassifyTheSitesTheyDescribe(t *testing.T) {
	home := account(t)
	c := reach.New(reach.DiscoverDocumentRoots(home), nil)

	served := filepath.Join(home, "sub", "shell.php")
	if got := c.Of(served); got != reach.LocationWebReachable {
		t.Errorf("%s: %q — a file in a discovered subdomain root is served", served, got)
	}
	notServed := filepath.Join(home, "backups", "old.php")
	if got := c.Of(notServed); got != reach.LocationOutsideDocRoot {
		t.Errorf("%s: %q", notServed, got)
	}
}

func cut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
