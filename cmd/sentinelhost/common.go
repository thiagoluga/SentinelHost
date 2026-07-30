package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

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
		vault:    quarantine.New(cfg.QuarantineDir(), cfg.Quarantine, st),
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
