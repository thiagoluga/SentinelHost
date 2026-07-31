package reach_test

import (
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/reach"
)

// The classification changes urgency, never truth. A finding stays a finding at its real
// level wherever it sits; what this decides is whether the tool acts on it by itself and
// how the report orders it.
//
// The cases that matter most are the ones where a wrong answer is silent: a file called
// unreachable when it is served, and a directory of the user's own downgraded because its
// name resembles a control panel's.

func TestAFileInTheDocumentRootIsReachable(t *testing.T) {
	c := reach.New([]string{"/home/u/public_html"}, nil)

	for _, p := range []string{
		"/home/u/public_html/index.php",
		"/home/u/public_html/wp-content/uploads/x.php",
		"/home/u/public_html",
	} {
		if got := c.Of(p); got != reach.LocationWebReachable {
			t.Errorf("%s: %q — a visitor can request this file", p, got)
		}
	}
}

func TestTheAccountsTrashIsRecognised(t *testing.T) {
	c := reach.New([]string{"/home/u/public_html"}, nil)

	for _, p := range []string{
		"/home/u/.trash/wordpress/wp-admin/includes/update-core-helper.php",
		"/home/u/.trash/blog/index.php",
	} {
		got := c.Of(p)
		if got != reach.LocationTrash {
			t.Errorf("%s: %q, want trash", p, got)
		}
		if got.Reachable() {
			t.Errorf("%s: reported as reachable", p)
		}
	}
}

// The failure that would be invisible: a directory of the user's own, downgraded because
// its name resembles a panel's. A site with public_html/trash/ full of drafts must not
// have its findings quietly demoted.
func TestAUserDirectoryNamedLikeTrashIsNotTrash(t *testing.T) {
	c := reach.New([]string{"/home/u/public_html"}, nil)

	for _, p := range []string{
		"/home/u/public_html/trash/old-draft.php", // their own folder, not a panel's
		"/home/u/public_html/contrash/x.php",      // contains "trash" as a substring
		"/home/u/public_html/mytrash/shell.php",   // ditto
		"/home/u/public_html/.trashcan/x.php",     // similar, not the same segment
	} {
		if got := c.Of(p); got != reach.LocationWebReachable {
			t.Errorf("%s: %q — this is the user's own directory, inside the served root, "+
				"and downgrading it hides a live finding", p, got)
		}
	}
}

// A sibling whose name merely starts the same way is a different site.
func TestASiblingDirectoryIsNotInsideTheRoot(t *testing.T) {
	c := reach.New([]string{"/home/u/public_html"}, nil)

	if got := c.Of("/home/u/public_html2/index.php"); got == reach.LocationWebReachable {
		t.Error("public_html2 was treated as being inside public_html: a prefix comparison " +
			"puts somebody else's site under this one's root")
	}
}

func TestOutsideEveryRootIsNotServed(t *testing.T) {
	c := reach.New([]string{"/home/u/public_html"}, nil)

	got := c.Of("/home/u/backups/site-2026.php")
	if got != reach.LocationOutsideDocRoot {
		t.Errorf("got %q, want outside_docroot", got)
	}
	if got.Reachable() {
		t.Error("a backup directory was reported as reachable")
	}
}

// With no document root configured, the question was never answerable — and the safe
// reading of "I do not know" is the urgent one. Answering "unreachable" would downgrade
// every finding on any installation that never configured its roots.
func TestWithoutADocumentRootNothingIsClaimed(t *testing.T) {
	c := reach.New(nil, nil)

	got := c.Of("/home/u/public_html/index.php")
	if got != reach.LocationUnknown {
		t.Errorf("got %q, want unknown", got)
	}
	if !got.Reachable() {
		t.Error("unknown was treated as unreachable: that downgrades every finding on an " +
			"installation whose roots were never configured")
	}
}

// Trash wins over the document root. A panel's trash can sit inside a served directory,
// and "the web serves this" is the wrong headline for a file the account already deleted.
func TestTrashInsideTheRootIsStillTrash(t *testing.T) {
	c := reach.New([]string{"/home/u/public_html"}, nil)

	if got := c.Of("/home/u/public_html/.trash/old.php"); got != reach.LocationTrash {
		t.Errorf("got %q, want trash", got)
	}
}

// An extra trash location can be configured, for panels this does not know by name.
func TestAConfiguredTrashDirectoryIsHonoured(t *testing.T) {
	c := reach.New([]string{"/home/u/httpdocs"}, []string{"/home/u/.plesk-recycle"})

	if got := c.Of("/home/u/.plesk-recycle/site/x.php"); got != reach.LocationTrash {
		t.Errorf("got %q, want trash", got)
	}
}

// Every location has to say what it means AND what it does not. "Unreachable" is the
// half of the message that invites the wrong conclusion, and the trash is restorable
// with one click.
func TestEveryLocationExplainsItselfWithoutReassuring(t *testing.T) {
	for _, l := range []reach.Location{
		reach.LocationWebReachable, reach.LocationTrash,
		reach.LocationOutsideDocRoot, reach.LocationUnknown,
	} {
		if l.Explain() == "" {
			t.Errorf("%q has no explanation", l)
		}
	}
	if got := reach.LocationTrash.Explain(); !contains(got, "restore") {
		t.Errorf("the trash explanation does not mention that restoring brings it back: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
