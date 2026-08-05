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

// Findings are grouped by where the file sits, and the groups that are not urgent start
// closed.
//
// On a real account this mattered immediately: 209 findings, nearly all of them framework
// code from Laravel and Symfony inside deleted WordPress installations, against a handful
// on the live site. An undifferentiated list buries the ones somebody can act on under
// the ones nobody can.
//
// Closed is not hidden. The count and the reason live in the summary, always on screen —
// the same rule the scan report follows for skipped files, and the reason this is a
// grouping rather than a filter.
func TestFindingsAreGroupedByLocation(t *testing.T) {
	js := readAsset(t, "app.js")

	for _, key := range []string{"web_reachable", "trash", "outside_docroot", "unknown"} {
		if !strings.Contains(js, "'"+key+"'") {
			t.Errorf("the panel does not group %q", key)
		}
	}

	// Reachable before trash: it is the only group where somebody can execute the file
	// right now, and reading order is the whole point of the change.
	reachable := strings.Index(js, "'web_reachable'")
	trash := strings.Index(js, "'trash',")
	if reachable == -1 || trash == -1 || reachable > trash {
		t.Error("the trash is listed before the served files; the urgent group has to come first")
	}
}

func TestTheGroupsThatAreNotUrgentStartClosed(t *testing.T) {
	js := readAsset(t, "app.js")

	// The declaration carries `open` per location. Reachable true, trash false.
	trashLine := ""
	for _, line := range strings.Split(js, "\n") {
		if strings.Contains(line, "key: 'trash'") {
			trashLine = line
		}
	}
	if trashLine == "" {
		t.Fatal("no trash group declared")
	}
	if !strings.Contains(trashLine, "open: false") {
		t.Errorf("the trash group starts open, so 209 findings nobody can act on still bury "+
			"the ones somebody can:\n  %s", strings.TrimSpace(trashLine))
	}
}

// Whatever is collapsed still says how much it is and why. A group that hid its count
// would be a filter pretending to be a grouping.
func TestACollapsedGroupStillShowsItsCountAndReason(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "verdicts.length") {
		t.Error("the summary does not carry the count")
	}
	if !strings.Contains(js, "loc.note") {
		t.Error("the summary does not carry the reason the group exists")
	}
	// And the worst level inside, so a confirmed finding in a closed group is visible
	// from the outside without opening it.
	if !strings.Contains(js, "worst") {
		t.Error("a closed group does not say the worst level it contains, so a confirmed " +
			"finding could sit inside one with nothing on screen suggesting it")
	}
}

// A verdict recorded before locations existed still has to appear somewhere.
func TestAVerdictWithNoLocationIsStillShown(t *testing.T) {
	js := readAsset(t, "app.js")
	if !strings.Contains(js, "key: ''") {
		t.Error("there is no group for verdicts with no location, so older ones vanish " +
			"from the list entirely")
	}
}

// The groups collapse because we say so, not because the browser is expected to.
//
// <details> hides its contents through the user agent stylesheet, the weakest link in the
// cascade. Measured in a real browser, the cards stayed laid out at full height with the
// element closed — and a bare <details> did too, so it was not our styling. Rather than
// keep bisecting somebody else's cascade, the rule is stated.
//
// Same lesson as the purge dialog that would not close (D-036): when something must not
// be on screen, say so, instead of relying on a default any other rule can outrank.
func TestTheGroupCollapsesByAnExplicitRule(t *testing.T) {
	css := readAsset(t, "app.css")

	if !strings.Contains(css, ".loc-group:not([open]) > *:not(summary)") {
		t.Error("nothing collapses a closed group explicitly; a closed group that still " +
			"renders its findings is not a grouping at all")
	}
	// The summary must survive it — that is where the count and the reason live.
	if strings.Contains(css, ".loc-group:not([open]) > * {") {
		t.Error("the rule hides the summary as well, taking the count and the reason off " +
			"screen with the findings")
	}
}

// The panel fetches the tab you are looking at, and not the other five.
//
// It used to run six loaders and eight API calls at startup, for one visible tab —
// including /api/engines twice, once for the dashboard summary and once for its own tab.
// On shared hosting every one of those is a PHP process holding a worker while it proxies
// to the panel, and the account has a hard ceiling on how many may run at once.
//
// Whether that ceiling is what produced the intermittent 503s on the validation account
// is NOT established. What is indefensible either way is loading five invisible tabs to
// show one: the tool is a guest on somebody's hosting, which is what Principle IV is about.
func TestThePanelDoesNotLoadEveryTabAtStartup(t *testing.T) {
	js := readAsset(t, "app.js")

	if strings.Contains(js, "loadEverything") {
		t.Error("loadEverything is still called: that fetches every tab's data on startup, " +
			"including tabs nobody is looking at")
	}
	if !strings.Contains(js, "TAB_LOADERS") {
		t.Error("there is no per-tab loader table, so nothing decides what a tab actually needs")
	}
}

// Opening a tab has to fetch it. A lazy panel that never loads is worse than an eager one.
func TestOpeningATabLoadsIt(t *testing.T) {
	js := readAsset(t, "app.js")
	// Every route into a tab goes through showTab, and showTab loads it. Asserting on the
	// pair rather than on one call site is the point: this test previously matched
	// `loadTab(b.dataset.tab)` and broke the moment the click handler stopped being the
	// only way to open a tab, while the behaviour it names was intact.
	//
	// It is still a string match, and a string match cannot tell that a pane filled. What
	// can is a browser: clicking through every tab, reloading on one, and reading back
	// which pane is active. That was done for the hash routing below.
	if !strings.Contains(js, "function showTab(") {
		t.Fatal("there is no single place that opens a tab, so the ways of opening one can " +
			"drift apart")
	}
	body := js[strings.Index(js, "function showTab("):]
	if end := strings.Index(body, "\n}"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "loadTab(") {
		t.Error("showTab does not load the tab, so every pane after the first is blank")
	}
}

// The open tab belongs in the URL: a reload has to land where the user was, and a tab
// should be linkable.
//
// This panel runs behind a bridge that restarts the backend, so reloading is routine
// rather than rare, and losing your place every time is a small cost paid constantly.
func TestTheOpenTabIsInTheURL(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "hashchange") {
		t.Error("nothing reacts to the URL changing, so back and forward do not move between tabs")
	}
	if !strings.Contains(js, "tabFromHash()") {
		t.Error("the URL is never read, so a reload cannot restore the tab that was open")
	}
}

// The hash comes from the address bar, which means whoever sends a link chooses it. It is
// concatenated into "#tab-" + name to find the pane, so an unvalidated value is a selector
// built from attacker text — a thrown exception that blanks the panel, at best.
func TestTheTabNameFromTheURLIsValidatedBeforeUse(t *testing.T) {
	js := readAsset(t, "app.js")
	i := strings.Index(js, "function tabFromHash(")
	if i < 0 {
		t.Fatal("no tabFromHash to validate anything")
	}
	body := js[i:]
	if end := strings.Index(body, "\n}"); end > 0 {
		body = body[:end]
	}
	// It must be checked against the known set, not merely trimmed or escaped.
	if !strings.Contains(body, "TAB_LOADERS") {
		t.Error("the tab name from the URL is not checked against the known tabs before it " +
			"is used to build a selector")
	}
	if !strings.Contains(body, "hasOwnProperty") && !strings.Contains(body, " in TAB_LOADERS") {
		t.Error("the check does not look like a membership test")
	}
}

// A failed load must not mark the tab as done, or it stays blank until a full reload.
func TestAFailedTabLoadCanBeRetried(t *testing.T) {
	js := readAsset(t, "app.js")
	if !strings.Contains(js, "loaded.delete(tab)") {
		t.Error("a tab that failed to load stays marked as loaded, so re-opening it shows a " +
			"blank pane forever instead of trying again")
	}
}

// And after something that changed state, everything is stale — but only what is on
// screen gets fetched.
func TestAnActionInvalidatesEveryTabAndReloadsOnlyTheVisibleOne(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "loaded.clear()") {
		t.Error("an action does not invalidate the other tabs; quarantining a file changes " +
			"the findings, the quarantine and the dashboard counts, and stale panes would " +
			"show the state from before it happened")
	}
	if !strings.Contains(js, "reloadCurrentTab()") {
		t.Error("nothing re-fetches the visible tab after an action")
	}
}

// Each finding can show what the engine actually saw.
//
// The votes say a file was flagged and by whom. They do not say WHY, and "why" is the
// difference between a user who can decide and one who has to trust us. The engines
// already record it — AMWScan keeps the offending line and its number, yara the strings
// that matched and their byte offset — and it was going into the database and no further.
func TestAFindingCanShowWhatTheEngineSaw(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "matched_content") {
		t.Error("the panel never reads matched_content, so the evidence the engines record " +
			"stays in the database where nobody sees it")
	}
	if !strings.Contains(js, "matched_offset") {
		t.Error("the panel never reads matched_offset, so a user is told a file is bad but " +
			"not where to look in it")
	}
}

// Attacker-chosen text. The file paths and snippets shown here were written by whoever
// wrote the malware; `<img src=x onerror=…>.php` is a legal filename.
func TestTheSnippetNeverBecomesMarkup(t *testing.T) {
	js := readAsset(t, "app.js")

	// Assignment, not the word. The file's own comments explain why innerHTML is
	// forbidden here, and a bare substring search finds those instead — the same way an
	// earlier test matched a CSS rule quoted inside its own explanation.
	assigns := regexp.MustCompile(`\.innerHTML\s*=`)
	if m := assigns.FindAllString(js, -1); len(m) > 0 {
		t.Errorf("the panel assigns innerHTML %d time(s): every string from the server has "+
			"to enter the DOM as textContent, or a filename turns this page into an attack "+
			"on the person reading it", len(m))
	}
}

// Fetched when opened, not with the list. Two hundred cards must not mean two hundred
// extra requests on an account with a ceiling on concurrent processes.
func TestTheEvidenceIsFetchedOnDemand(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "addEventListener('toggle'") {
		t.Error("the evidence is not loaded on opening, so either it is fetched for every " +
			"card up front or it is never fetched at all")
	}
	css := readAsset(t, "app.css")
	if !strings.Contains(css, ".evidence:not([open]) > *:not(summary)") {
		t.Error("nothing collapses the evidence explicitly — the same default that failed " +
			"for the purge dialog and the finding groups")
	}
}

// maldet records which signature matched and never the text. An empty box would read as
// a load that failed.
func TestAnEngineWithNoSnippetSaysSoRatherThanShowingNothing(t *testing.T) {
	js := readAsset(t, "app.js")
	if !strings.Contains(js, "not the text that matched it") {
		t.Error("an engine that records no snippet produces an empty panel with nothing " +
			"saying why")
	}
}
