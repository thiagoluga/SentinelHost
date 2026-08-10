package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

const brokenTOML = `[general]
roots = ["/home/u/public_html"]

[alerts]
  [alerts.email]
    enabled = true

  [[alerts.webhooks]]
    id = "DISC"

  [alerts.email]
    enabled = true
`

// The file that could not be read has to survive being repaired.
//
// This is the whole point. An account's config.toml became invalid TOML and every start
// died reading it; by the time anybody looked, it had been fixed and overwritten, and the
// only artifact that could have explained how it got that way was gone. The cause is still
// unknown — the current configuration, three archived ones, the encoder's field order and
// a round trip over hostile values were all checked and all clean.
//
// SaveTo cannot produce one since v0.1.7, which reads back what it wrote. That covers only
// what this program writes: a control panel's file manager, an editor over FTP or a second
// process are not prevented, and the failure looks identical from here.
func TestAConfigurationThatCannotBeReadIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(brokenTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	// It really is unparseable, so the test is about the case it claims to be about.
	if _, err := config.Load(path); err == nil {
		t.Fatal("the fixture parses; it is supposed to be the duplicated-table shape")
	}

	kept, err := config.PreserveUnreadable(path)
	if err != nil {
		t.Fatalf("preserving: %v", err)
	}

	got, err := os.ReadFile(kept)
	if err != nil {
		t.Fatalf("reading the copy: %v", err)
	}
	if string(got) != brokenTOML {
		t.Errorf("the copy is not what was on disk:\n%s", got)
	}
}

// The FIRST failure is the one worth keeping.
//
// Every visit to the panel starts the binary, so a config that cannot be read produces a
// start per visit — fifty-four of them, on the real occurrence. A copy per start would be
// fifty-four identical files on an account with a disk quota, and the later ones say
// nothing the first does not.
func TestAnExistingCopyIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(brokenTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := config.PreserveUnreadable(path)
	if err != nil {
		t.Fatal(err)
	}

	// Somebody edits the broken file, gets it wrong again, and the panel starts again.
	if err := os.WriteFile(path, []byte("this is a later, different mess\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := config.PreserveUnreadable(path)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("a second copy was made at %s; there should be one, from the first failure",
			second)
	}

	got, _ := os.ReadFile(first)
	if string(got) != brokenTOML {
		t.Errorf("the kept copy was replaced by a later one:\n%s", got)
	}
}

// The copy is no more readable than the original.
//
// It carries the SMTP password and the webhook secrets verbatim. A diagnostic that widens
// permissions on the file it copies would be its own defect, and a quiet one — nobody
// checks the mode of a file they did not know existed.
func TestTheKeptCopyIsNotWorldReadable(t *testing.T) {
	// runtime.GOOS, not os.Getenv("GOOS") — which is empty in a normal process and
	// would have made this skip nowhere and fail on Windows. It did, which is the right
	// direction to get it wrong: a guard that skips when it should run is the one this
	// repository has been bitten by twice.
	if runtime.GOOS == "windows" {
		t.Skip("Windows ignores POSIX permissions; production is Linux (D-002)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(brokenTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	kept, err := config.PreserveUnreadable(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(kept)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the copy is %04o; it holds the SMTP password and the webhook secrets",
			mode)
	}
}

// A file that cannot be read at all reports that, and does not invent a path.
func TestAFileThatCannotBeCopiedReportsIt(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "not-there.toml")

	kept, err := config.PreserveUnreadable(missing)
	if err == nil {
		t.Fatalf("preserving a file that does not exist reported success at %q", kept)
	}
	if kept != "" {
		t.Errorf("a path was returned alongside the error: %q", kept)
	}
}
