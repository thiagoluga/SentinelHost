package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// Whatever Save writes, the file left on disk must parse.
//
// This is the invariant an account depends on: a config the tool cannot read stops it
// completely — every start dies reading it, and on an account with no shell the only
// evidence is a log the owner cannot open. It happened. An account was left with a
// duplicated table and restarted into the same failure on every visit until somebody
// noticed.
//
// SaveTo now loads the temporary file before the rename, so a configuration that cannot be
// read back never replaces one that can.
//
// Honest limitation: I could not construct an input that makes the encoder emit
// unparseable TOML — it escapes hostile table names and values correctly, including the
// shape that broke the real account. So this exercises the round trip across awkward values
// rather than the refusal path itself, and the refusal is verified by reading SaveTo. That
// the encoder resists these inputs is worth recording on its own: it means the corruption
// seen in production did not come from here, and the cause is still unknown.
func TestWhateverIsSavedCanBeReadBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	// Built with explicit escapes so the source file's own quoting cannot soften them.
	hostile := []string{
		"a\"]\n[alerts.email]\nx = \"", // the shape that broke the account
		"quote\" and \\ backslash",
		"newline\nin\nthe\nmiddle",
		"[brackets] = and = equals",
		"",
	}

	for _, id := range hostile {
		cfg := config.Default()
		cfg.General.Roots = []string{dir}
		cfg.General.DataDir = filepath.Join(dir, "data")
		cfg.Alerts.Webhooks = []config.Webhook{{
			ID: id, Enabled: true, URL: "https://example.test/hook",
		}}
		cfg.SetPath(path)

		if err := cfg.Save(); err != nil {
			// Refusing is a legitimate outcome. Leaving something unreadable is not, and
			// the file is checked below either way.
			t.Logf("saving a webhook id %q was refused: %v", id, err)
		}
		if _, err := config.Load(path); err != nil {
			t.Fatalf("after a save with webhook id %q, the file on disk does not load: %v",
				id, err)
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the configuration is gone: %v", err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("the final configuration does not load: %v", err)
	}
}
