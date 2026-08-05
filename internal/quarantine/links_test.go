package quarantine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/quarantine"
)

// payload stands in for a webshell without being one.
//
// The vault never looks at the content — it copies bytes and unlinks a name — so nothing
// here needs to be real malware. And a literal webshell in a source file gets this
// repository quarantined by the antivirus on a contributor's own workstation, which
// happened twice while writing this test: the file was deleted between being written and
// being compiled.
const payload = "<?php /* stands in for a webshell; see the comment above */ ?>"

// os.Remove unlinks a NAME, not content.
//
// An attacker who uploads a payload and gives it a second name has one flagged path and
// one that is not. Quarantining the flagged one copies the content to the vault, unlinks
// that name, and reports success — while the content stays exactly where it was, fully
// executable, under the other name. No race is required: it is one extra command at upload
// time, and the reward is a scanner that says the threat is handled.
func TestAHardLinkedFileIsNotQuarantinedSilently(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard-link counting is not implemented on Windows; production is Linux")
	}
	e := setup(t)

	flagged := filepath.Join(e.site, "flagged.php")
	if err := os.WriteFile(flagged, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(e.site, "innocent.php")
	if err := os.Link(flagged, second); err != nil {
		t.Skipf("this filesystem does not support hard links: %v", err)
	}

	_, err := e.vault.Quarantine(context.Background(), "v_1", flagged, "")
	if err == nil {
		t.Fatal("the file was reported as quarantined while identical content remained " +
			"reachable under another name")
	}
	if !errors.Is(err, quarantine.ErrOtherNames) {
		t.Errorf("refused, but not for having other names: %v", err)
	}
	// The error has to be actionable: the user now has to find the other names.
	if !strings.Contains(err.Error(), "-samefile") {
		t.Errorf("the error does not say how to find the other names: %v", err)
	}

	// Neither name may have been touched.
	for _, p := range []string{flagged, second} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed by a quarantine that failed: %v", p, err)
		}
	}
}

// A symbolic link whose target holds identical bytes survives the hash re-check, because
// the hash is of the target. The copy would be made from the target, the removal would
// take the link, and the content would be untouched.
//
// The scan skips symbolic links, so one appearing here means it was created between the
// scan and the action — a reason to look, not to proceed.
func TestASymlinkIsRefusedRatherThanUnlinked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks on Windows needs a privilege the suite should not require")
	}
	e := setup(t)

	target := filepath.Join(e.site, "the-real-file.php")
	if err := os.WriteFile(target, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(e.site, "flagged.php")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this environment cannot create symlinks: %v", err)
	}

	_, err := e.vault.Quarantine(context.Background(), "v_1", link, "")
	if err == nil {
		t.Fatal("the link was removed and reported as a quarantine, leaving the file it " +
			"pointed at in place")
	}
	if !errors.Is(err, quarantine.ErrNotAPlainFile) {
		t.Errorf("refused, but not for being a link: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the link was removed anyway: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the target was removed: %v", err)
	}
}

// The ordinary case must still work, or this check would simply switch quarantine off.
func TestAPlainFileIsStillQuarantined(t *testing.T) {
	e := setup(t)

	flagged := filepath.Join(e.site, "flagged.php")
	if err := os.WriteFile(flagged, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	item, err := e.vault.Quarantine(context.Background(), "v_1", flagged, "")
	if err != nil {
		t.Fatalf("a plain file was refused: %v", err)
	}
	if _, err := os.Stat(flagged); !os.IsNotExist(err) {
		t.Error("the original is still in place after a successful quarantine")
	}
	if _, err := os.Stat(item.VaultPath); err != nil {
		t.Errorf("the vault copy is missing: %v", err)
	}
}

// A path that did not come from the walk must not be acted on.
//
// Engine output is text. A forged `File:` header in an AMWScan report, or a mis-parse,
// produces a path that reaches the vault — and the vault deletes things. Nothing between
// the parser and os.Remove asserted the path was one this tool had walked.
func TestAPathOutsideTheRootsIsRefused(t *testing.T) {
	e := setup(t)
	v := e.vault.WithRoots([]string{e.site})

	outside := filepath.Join(t.TempDir(), "not-ours.php")
	if err := os.WriteFile(outside, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := v.Quarantine(context.Background(), "v_1", outside, "")
	if err == nil {
		t.Fatal("a file outside every configured root was quarantined")
	}
	if !errors.Is(err, quarantine.ErrOutsideRoots) {
		t.Errorf("refused, but not for being outside the roots: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("it was removed anyway: %v", err)
	}

	// Inside still works, or containment has switched quarantine off.
	inside := filepath.Join(e.site, "flagged.php")
	if err := os.WriteFile(inside, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Quarantine(context.Background(), "v_2", inside, ""); err != nil {
		t.Fatalf("a file inside the root was refused: %v", err)
	}
}
