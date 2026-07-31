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

// document.baseURI is not a constant: a `<base href>` element changes it. One injected
// into this page would silently redirect every API call — including the ones that
// quarantine and restore files — to somewhere else entirely.
//
// Nothing renders untrusted HTML in the panel today. The check costs one comparison,
// which is the right trade for a guarantee that would otherwise depend on that staying
// true forever.
func TestTheResolvedURLIsCheckedAgainstThePagesOrigin(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "window.location.origin") {
		t.Error("url() does not compare the resolved origin against the page's own; " +
			"a <base href> would then redirect every API call off-origin")
	}
	if !strings.Contains(js, "refusing to send a panel request off-origin") {
		t.Error("nothing refuses an off-origin request: the comparison has to act on its result")
	}
}

// The hidden attribute must not be out-specified by anything.
//
// `hidden` applies display:none through the browser's own stylesheet, which any author
// rule outranks. `.modal{display:grid}` beat it, so the purge confirmation — the dialog
// for the only irreversible operation in this project — sat on screen over everything,
// including the first-access password form. Someone opening the panel for the first time
// was asked to type "purge", and could not dismiss it: the Cancel and Confirm handlers
// are attached when the dialog is opened deliberately, and this one never was.
//
// A rule per component would fix that case and leave the next one to be found the same
// way, because every element toggled with `hidden` is exposed the moment it gains a
// display of its own.
func TestTheHiddenAttributeCannotBeOverridden(t *testing.T) {
	css := readAsset(t, "app.css")

	if !strings.Contains(css, "[hidden]") {
		t.Fatal("no [hidden] rule: any component with its own display will ignore the attribute")
	}
	if !strings.Contains(css, "[hidden] { display: none !important; }") {
		t.Error("the [hidden] rule is not !important, so a component rule can still out-specify " +
			"\"this element is not here\"")
	}
}

// Every element the code hides with the attribute is a candidate for the same bug, so
// the rule above has to come before the component styles that would otherwise win.
func TestTheHiddenRuleComesBeforeTheComponents(t *testing.T) {
	css := readAsset(t, "app.css")
	hidden := strings.Index(css, "[hidden] { display: none !important; }")
	// Line-anchored: the explanatory comment above the rule quotes `.modal{display:grid}`,
	// and a bare substring search finds that instead of the declaration.
	modal := strings.Index(css, "\n.modal{")
	if hidden == -1 || modal == -1 {
		t.Skip("one of the rules is absent; the test above reports that")
	}
	if hidden > modal {
		t.Error("the [hidden] rule appears after .modal; with equal specificity the later " +
			"rule wins, which is how this bug worked in the first place")
	}
}
