package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The panel must work when it is not at the root of a domain.
//
// It used to address itself absolutely — `/api/status`, `/app.css`. That works only when
// the panel IS the site. Behind any reverse proxy on a sub-path — and that includes the
// PHP bridge that makes the panel usable on shared hosting at all — the browser asks the
// SITE for /api/status rather than the panel. Every request 404s while the page itself
// loads: unstyled, inert, and with nothing on screen saying why.
//
// Found by installing the bridge on a real account: the HTML arrived, `app.css` and
// `app.js` came back 404, and the panel rendered as bare markup.

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("assets/" + name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

func TestTheHTMLDoesNotLinkAssetsFromTheRoot(t *testing.T) {
	html := readAsset(t, "index.html")

	// href="/…" and src="/…" — but not "//" (protocol-relative) and not a bare "/".
	absolute := regexp.MustCompile(`(?:href|src)="/(?:[^/"]|$)`)
	if m := absolute.FindAllString(html, -1); len(m) > 0 {
		t.Errorf("index.html links assets from the domain root %v — the panel then only "+
			"works when it IS the site, and breaks behind any sub-path proxy", m)
	}
}

func TestEveryFetchGoesThroughTheURLHelper(t *testing.T) {
	js := readAsset(t, "app.js")

	// The helper is what turns a panel-relative path into a mounted one. A fetch that
	// bypasses it is a request that will miss the panel when it is not at the root.
	for _, line := range strings.Split(js, "\n") {
		if !strings.Contains(line, "fetch(") {
			continue
		}
		if !strings.Contains(line, "fetch(url(") {
			t.Errorf("a fetch bypasses the url() helper, so it will miss the panel under a "+
				"sub-path:\n  %s", strings.TrimSpace(line))
		}
	}
}

func TestTheBaseIsDerivedFromThePageRatherThanAssumed(t *testing.T) {
	js := readAsset(t, "app.js")
	if !strings.Contains(js, "document.baseURI") {
		t.Error("the mount point is not derived from the page's own URL; anything else is " +
			"an assumption about where the panel was installed")
	}
}
