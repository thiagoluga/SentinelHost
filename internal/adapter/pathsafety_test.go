package adapter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
)

// A filename on Linux may hold any byte but `/` and NUL — including a newline.
//
// The scope goes to yara and maldet as one path per line, so `uploads/x<LF>.php` becomes
// TWO lines. Neither exists, so neither engine ever opens the payload — while it stays
// reachable and executable, because the web server keys on the trailing `.php`. All three
// malware engines then report zero findings on a live webshell, which is the failure this
// project exists to prevent, produced by one rename().
func TestAPathThatCannotBeExpressedIsRefusedAndCounted(t *testing.T) {
	// Built from bytes so no source-file escaping stands between the test and the attack.
	lf := string([]byte{0x0a})
	cr := string([]byte{0x0d})
	nul := string([]byte{0x00})

	hostile := []struct {
		what string
		path string
	}{
		{"a newline that hides the file from both engines",
			"/home/u/public_html/uploads/x" + lf + ".php"},
		{"a newline that injects a path outside every root",
			"/home/u/public_html/a" + lf + "/home/u/mail/secret"},
		{"a carriage return", "/home/u/public_html/x" + cr + ".php"},
		{"a NUL, which truncates the path in a C engine",
			"/home/u/public_html/x" + nul + ".php"},
	}

	var paths []string
	for _, h := range hostile {
		if adapter.PathIsExpressible(h.path) {
			t.Errorf("%s: accepted as expressible", h.what)
		}
		paths = append(paths, h.path)
	}
	ordinary := "/home/u/public_html/index.php"
	paths = append(paths, ordinary)

	usable, refused := adapter.FilterExpressiblePaths(paths)
	if len(usable) != 1 || usable[0] != ordinary {
		t.Errorf("usable was %v; only the ordinary path can go to an engine", usable)
	}
	if len(refused) != len(hostile) {
		t.Errorf("refused %d of %d hostile paths", len(refused), len(hostile))
	}
}

// Refused is not the same as dropped. The whole point is that these files were NOT
// scanned, so the count has to reach the report — a file nobody looked at must never be
// indistinguishable from one that was looked at and found clean.
func TestTheTargetListReportsWhatItCouldNotWrite(t *testing.T) {
	dir := t.TempDir()
	lf := string([]byte{0x0a})

	list, cleanup, refused, err := adapter.WriteTargetList(dir, "test-engine", []string{
		"/home/u/public_html/index.php",
		"/home/u/public_html/uploads/x" + lf + ".php",
	})
	if err != nil {
		t.Fatalf("writing: %v", err)
	}
	defer cleanup()

	if len(refused) != 1 {
		t.Fatalf("refused %d paths, wanted 1 — silently writing it would put two bogus "+
			"lines in the scope and scan neither", len(refused))
	}

	body, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("the list has %d lines %q; the hostile name would have added a second", len(lines), lines)
	}
	if lines[0] != "/home/u/public_html/index.php" {
		t.Errorf("the surviving line is %q", lines[0])
	}
}

// Engine output is text, and a path parsed out of it is acted on — it becomes a verdict,
// and a verdict can be quarantined. Containment is what stops a forged or mis-parsed path
// from naming any file on the account.
func TestContainmentDoesNotConfuseASiblingForAChild(t *testing.T) {
	root := filepath.FromSlash("/home/user/public_html")

	inside := []string{
		"/home/user/public_html/index.php",
		"/home/user/public_html/wp-content/uploads/x.php",
		"/home/user/public_html",
	}
	outside := []string{
		"/home/user/public_html-backup/x.php", // the prefix trap
		"/home/user/mail/secret",
		"/home/user2/public_html/x.php",
		"/etc/passwd",
		"/home/user/public_html/../mail/secret", // resolves out
	}

	for _, p := range inside {
		if !adapter.PathIsWithin(filepath.FromSlash(p), root) {
			t.Errorf("%s was treated as outside the root", p)
		}
	}
	for _, p := range outside {
		if adapter.PathIsWithin(filepath.FromSlash(p), root) {
			t.Errorf("%s was treated as inside the root; a path parsed out of engine text "+
				"reaches os.Remove", p)
		}
	}
	if adapter.PathIsWithin("/anything", "") {
		t.Error("an empty root contains everything")
	}
}
