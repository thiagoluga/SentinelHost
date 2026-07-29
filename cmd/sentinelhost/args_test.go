package main

import (
	"flag"
	"io"
	"testing"
)

// The standard library's flag stops parsing at the first argument that does not
// start with a dash. That made `quarantine restore <ref> --config /path` ignore
// the --config SILENTLY and fall back to the default path — and the form the
// quickstart documents is precisely that one.
//
// The symptom was a misleading error ("configuration not found") in a command that
// received the configuration correctly; the real risk was acting on the wrong
// instance on a machine with more than one site.

func newFS() (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "/default/config.toml", "")
	force := fs.Bool("force", false, "")
	return fs, cfg, force
}

func TestAFlagAfterThePositionalIsRead(t *testing.T) {
	fs, cfg, _ := newFS()

	pos, err := parseArgs(fs, []string{"q_123", "--config", "/mine/config.toml"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 1 || pos[0] != "q_123" {
		t.Fatalf("positionals: %v", pos)
	}
	if *cfg != "/mine/config.toml" {
		t.Errorf("--config after the positional was ignored: %q", *cfg)
	}
}

func TestAFlagBeforeThePositionalKeepsWorking(t *testing.T) {
	fs, cfg, _ := newFS()

	pos, err := parseArgs(fs, []string{"--config", "/mine/config.toml", "q_123"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 1 || pos[0] != "q_123" {
		t.Fatalf("positionals: %v", pos)
	}
	if *cfg != "/mine/config.toml" {
		t.Errorf("config: %q", *cfg)
	}
}

func TestFlagsInterleavedWithPositionals(t *testing.T) {
	fs, cfg, force := newFS()

	pos, err := parseArgs(fs, []string{"--force", "q_123", "--config", "/x.toml", "q_456"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 2 || pos[0] != "q_123" || pos[1] != "q_456" {
		t.Fatalf("positionals: %v", pos)
	}
	if !*force {
		t.Error("--force before the positional was lost")
	}
	if *cfg != "/x.toml" {
		t.Errorf("--config between positionals was lost: %q", *cfg)
	}
}

func TestWithNoPositionalTheDefaultIsUsed(t *testing.T) {
	fs, cfg, _ := newFS()

	pos, err := parseArgs(fs, []string{"--config", "/y.toml"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 0 {
		t.Errorf("there should be no positionals: %v", pos)
	}
	if *cfg != "/y.toml" {
		t.Errorf("config: %q", *cfg)
	}
}

func TestAnUnknownFlagIsAnError(t *testing.T) {
	// A mistyped flag must not silently become a positional argument: in a tool
	// that moves files, `--fofce` has to fail, not be treated as the name of a
	// quarantine reference.
	fs, _, _ := newFS()

	if _, err := parseArgs(fs, []string{"q_123", "--does-not-exist"}); err == nil {
		t.Fatal("an unknown flag should be an error")
	}
}

func TestAnEmptyListDoesNotBreak(t *testing.T) {
	fs, cfg, _ := newFS()

	pos, err := parseArgs(fs, nil)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 0 {
		t.Errorf("positionals: %v", pos)
	}
	if *cfg != "/default/config.toml" {
		t.Errorf("the default should have been preserved: %q", *cfg)
	}
}
