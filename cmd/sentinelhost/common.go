package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/amwscan"
	"github.com/thiagoluga/SentinelHost/internal/adapter/maldet"
	"github.com/thiagoluga/SentinelHost/internal/adapter/pmf"
	"github.com/thiagoluga/SentinelHost/internal/adapter/wpchecksums"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/lock"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// errLocked carries concurrency's own exit code.
var errLocked = lock.ErrLocked

// app gathers everything the commands need.
type app struct {
	cfg      *config.Config
	store    *store.Store
	registry *adapter.Registry
	vault    *quarantine.Vault
}

func (a *app) Close() {
	if a != nil && a.store != nil {
		_ = a.store.Close()
	}
}

// newRegistry assembles the registry with the MVP's adapters.
//
// Registering here, rather than in each package's init(), keeps it explicit which
// engines this binary knows about — useful when the user asks why an engine "does
// not show up".
func newRegistry() *adapter.Registry {
	r := adapter.NewRegistry()
	r.MustRegister(wpchecksums.New())
	r.MustRegister(amwscan.New())
	r.MustRegister(pmf.New())
	r.MustRegister(maldet.New())
	return r
}

// openApp loads the config and opens the database.
func openApp(ctx context.Context, configPath string) (*app, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil, fmt.Errorf("%w\n\nRun this first:  sentinelhost config init --root <path to the site>", err)
		}
		return nil, err
	}

	res := cfg.Validate()
	if res.HasErrors() {
		return nil, res.Err()
	}
	// Warnings do not block execution: a tool that refuses to run protects less
	// than one that runs while warning.
	for _, p := range res.Warnings() {
		fmt.Fprintf(os.Stderr, "warning: %s: %s\n", p.Field, p.Message)
	}

	if err := cfg.EnsureDataDirs(); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		return nil, err
	}

	return &app{
		cfg:      cfg,
		store:    st,
		registry: newRegistry(),
		// Bounded to the configured roots: a path that arrived from engine output rather
		// than from the walk is a parser bug or a forged report, and either way it is not
		// something to delete.
		vault: quarantine.New(cfg.QuarantineDir(), cfg.Quarantine, st).
			WithRoots(cfg.General.Roots),
	}, nil
}

// flagSet creates a flag set with --config already included.
func flagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "path to the TOML configuration file")
	return fs, cfgPath
}

// parseArgs interprets flags that appear AFTER positional arguments.
//
// The standard library's flag stops parsing at the first argument that does not
// start with a dash. That makes
//
//	sentinelhost quarantine restore q_123 --config /path/config.toml
//
// ignore the --config silently and fall back to the default path — which is
// exactly the form the quickstart documents for anyone whose configuration lives
// outside the default place. The command then fails saying it could not find the
// configuration, or worse, acts on the wrong instance.
//
// The fix is the loop: parse, take the first positional out, and parse the rest.
// It returns the positionals in the order they appeared.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// splitCommand finds the subcommand in the arguments and moves anything that came before
// it to the back, so that `--config X scan` and `scan --config X` are the same command.
//
// The help calls --config a GLOBAL OPTION, which is a promise that it goes with the
// program rather than with one subcommand — and every convention that word carries says
// it may precede the subcommand. The parser read os.Args[1] and rejected anything
// starting with a dash: `unknown command: --config`.
//
// The cost was not theoretical. Two automated cycles against a real account produced an
// empty report and a usage error nobody read, and the run that consumed them concluded
// "no findings" from a zero-byte file. A flag documented as global has to be global, or
// the documentation has to stop saying so; of the two, this is the one that does not
// require every existing user to be wrong.
//
// Returns "" when the arguments hold no subcommand at all.
func splitCommand(argv []string) (string, []string) {
	var leading []string

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			// The subcommand. Whatever preceded it belongs to it.
			return a, append(append([]string{}, argv[i+1:]...), leading...)
		}
		leading = append(leading, a)
		// `--config <path>` puts the path in the next argument; `--config=<path>` does
		// not. Taking the value with the flag keeps the two forms equivalent, and stops
		// a path being mistaken for the subcommand.
		if !strings.Contains(a, "=") && i+1 < len(argv) && needsValue(a) {
			i++
			leading = append(leading, argv[i])
		}
	}

	// Only flags. `--version` and `--help` are commands spelled like flags, so they are
	// still worth returning; anything else falls through to the usage text.
	if len(argv) > 0 {
		return argv[0], argv[1:]
	}
	return "", nil
}

// needsValue reports whether a leading flag takes a separate argument.
//
// Deliberately a short list rather than a guess: treating every unrecognised flag as
// value-taking would swallow the subcommand after a boolean like `--json`.
func needsValue(flag string) bool {
	switch flag {
	case "--config", "-config", "--data-dir", "-data-dir":
		return true
	}
	return false
}
