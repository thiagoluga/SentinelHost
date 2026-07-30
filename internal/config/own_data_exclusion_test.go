package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
)

// The guarantee under test: SentinelHost never walks its own data directory, no matter
// what the user named it or where they put it.
//
// The default exclusion list carries the literal `**/.sentinelhost/**`, which protects
// only the default NAME. A user who points `data_dir` at a folder of their own — an
// ordinary thing to do, and something we recommend so the vault stays out of backups —
// used to lose that protection silently whenever the folder sat under a watched root.
// The scan then reads the quarantine vault, re-detects the malware it already
// neutralized, quarantines the vault's copy, and does it again every cycle.
//
// Everything here goes through the real Load, because a struct assembled in a test is
// not the path a user's configuration actually takes.

func writeConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the TOML: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading the TOML: %v", err)
	}
	return cfg
}

// tomlPath quotes a path as a TOML value. Windows paths carry backslashes, which TOML
// reads as escapes, so the slash form is what goes into the file.
func tomlPath(p string) string { return fmt.Sprintf("%q", filepath.ToSlash(p)) }

func TestTheConfiguredDataDirIsExcludedWhateverItIsCalled(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "public_html")
	// A name with nothing "sentinelhost" about it, deliberately INSIDE the watched
	// root: the worst case, and exactly the one a name-based exclusion misses.
	data := filepath.Join(root, "my-scanner-files")

	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(root)+"]\ndata_dir = "+tomlPath(data)+"\n")

	vaultFile := filepath.Join(data, "quarantine", "q_0001", "payload.php")
	if !pathmatch.MatchAny(cfg.Limits.Exclude, vaultFile) {
		t.Fatalf("the quarantine vault would be scanned:\n  %s\nexclusions: %v",
			vaultFile, cfg.Limits.Exclude)
	}
	if !pathmatch.MatchAny(cfg.Limits.Exclude, filepath.Join(data, "sentinelhost.db")) {
		t.Error("the SQLite database would be scanned")
	}
	// The directory entry itself, so the walker returns SkipDir instead of descending.
	if !pathmatch.MatchAny(cfg.Limits.Exclude, data) {
		t.Error("the data directory itself would be descended into")
	}
}

// A separately configured quarantine dir has to be covered too. It is the one directory
// that holds live malicious content by design.
func TestASeparatelyConfiguredQuarantineDirIsAlsoExcluded(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "public_html")
	vault := filepath.Join(root, "vault")

	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(root)+"]\ndata_dir = "+
		tomlPath(filepath.Join(home, "data"))+"\n\n[quarantine]\ndir = "+tomlPath(vault)+"\n")

	if !pathmatch.MatchAny(cfg.Limits.Exclude, filepath.Join(vault, "q_0001", "shell.php")) {
		t.Fatalf("a quarantine dir set apart from data_dir would be scanned; exclusions: %v",
			cfg.Limits.Exclude)
	}
}

// The exclusion is absolute on purpose. A `**/vault/**` shape would also drop an
// unrelated `vault` directory belonging to the user's site — and silently excluding part
// of someone's site is the same class of failure as silently including our own.
func TestTheExclusionDoesNotSwallowASameNamedDirectoryElsewhere(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "public_html")

	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(root)+"]\ndata_dir = "+
		tomlPath(filepath.Join(home, "vault"))+"\n")

	theirs := filepath.Join(root, "wp-content", "vault", "index.php")
	if pathmatch.MatchAny(cfg.Limits.Exclude, theirs) {
		t.Errorf("a directory of the user's site was excluded because it shares our name:\n"+
			"  %s\nexclusions: %v", theirs, cfg.Limits.Exclude)
	}
}

// normalize runs on every Load, so a hand-edited TOML gets the same guarantee as a
// generated one. Someone who deletes the `.sentinelhost` line from `exclude`, or writes
// the file from scratch, must not be able to switch this off by accident.
func TestAHandEditedExcludeListStillGetsTheGuarantee(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, "sh-data")

	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(filepath.Join(home, "public_html"))+
		"]\ndata_dir = "+tomlPath(data)+"\n\n[limits]\nexclude = [\"**/node_modules/**\"]\n")

	if !pathmatch.MatchAny(cfg.Limits.Exclude, filepath.Join(data, "quarantine", "x.php")) {
		t.Fatalf("wiping the exclude list disabled the self-exclusion; got %v", cfg.Limits.Exclude)
	}
}

// Loading the same file repeatedly must not keep appending the same glob.
func TestTheExclusionIsNotDuplicatedOnRepeatedLoads(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, "sh")
	path := filepath.Join(home, "config.toml")
	body := "[general]\nroots = [" + tomlPath(filepath.Join(home, "public_html")) +
		"]\ndata_dir = " + tomlPath(data) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the TOML: %v", err)
	}

	for i := range 3 {
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		count := 0
		for _, e := range cfg.Limits.Exclude {
			if strings.Contains(e, filepath.ToSlash(data)) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("load %d: the data-dir glob appears %d times: %v", i, count, cfg.Limits.Exclude)
		}
	}
}
