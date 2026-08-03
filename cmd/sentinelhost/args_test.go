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

// The help calls --config a GLOBAL OPTION. It has to behave like one.
//
// The parser read os.Args[1] and rejected anything starting with a dash, so the form the
// documentation implies — `sentinelhost --config X scan` — died with `unknown command:
// --config`. Two automated cycles against a real account were spent on it: the scan never
// ran, the report was zero bytes, and the check reading that report concluded "no
// findings", which is the precise failure this project exists to prevent.
func TestTheConfigFlagIsGlobalBecauseTheHelpSaysSo(t *testing.T) {
	cases := []struct {
		argv     []string
		wantCmd  string
		wantArgs []string
	}{
		// The form that used to fail.
		{[]string{"--config", "/etc/s.toml", "scan"}, "scan", []string{"--config", "/etc/s.toml"}},
		// The form that always worked, unchanged.
		{[]string{"scan", "--config", "/etc/s.toml"}, "scan", []string{"--config", "/etc/s.toml"}},
		// Leading flag plus the subcommand's own flags.
		{[]string{"--config", "/etc/s.toml", "scan", "--full", "--json"}, "scan",
			[]string{"--full", "--json", "--config", "/etc/s.toml"}},
		// The = form, where the value is not a separate argument.
		{[]string{"--config=/etc/s.toml", "serve"}, "serve", []string{"--config=/etc/s.toml"}},
		// A boolean before the subcommand must not swallow it.
		{[]string{"--json", "scan"}, "scan", []string{"--json"}},
		// Commands spelled like flags stay commands.
		{[]string{"--version"}, "--version", []string{}},
		{[]string{"-h"}, "-h", []string{}},
	}

	for _, c := range cases {
		gotCmd, gotArgs := splitCommand(c.argv)
		if gotCmd != c.wantCmd {
			t.Errorf("%v: command %q, wanted %q", c.argv, gotCmd, c.wantCmd)
			continue
		}
		if len(gotArgs) != len(c.wantArgs) {
			t.Errorf("%v: args %v, wanted %v", c.argv, gotArgs, c.wantArgs)
			continue
		}
		for i := range gotArgs {
			if gotArgs[i] != c.wantArgs[i] {
				t.Errorf("%v: args %v, wanted %v", c.argv, gotArgs, c.wantArgs)
				break
			}
		}
	}
}

// No subcommand at all is a usage error, not a panic.
func TestNoSubcommandIsNotACrash(t *testing.T) {
	if cmd, _ := splitCommand(nil); cmd != "" {
		t.Errorf("empty arguments produced the command %q", cmd)
	}
}
