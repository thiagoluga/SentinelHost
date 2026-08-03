// Command sentinelhost: a malware-scanner orchestrator for shared hosting.
//
// A single, static binary with no mandatory dependencies (Principle VII).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Exit codes. Stable, because the user's cron and scripts depend on them.
const (
	exitOK = 0
	// exitFindings: the cycle ran and found something that deserves attention. It
	// is NOT an error: it is the normal behaviour of a scanner that found
	// something. Keeping it apart from the error codes lets the user's cron tell
	// "found malware" from "the tool broke".
	exitFindings = 1
	exitError    = 2
	// exitLocked: another instance is running. Its own code, so the cron does not
	// treat normal concurrency as a failure.
	exitLocked = 3
	exitUsage  = 64
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage()
		return exitUsage
	}

	// Ctrl-C and SIGTERM (the hosting killing the process) cancel the context
	// instead of killing right away: the cycle needs to close the report, release
	// the lock and not leave a file halfway between the disk and the vault.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, args := splitCommand(os.Args[1:])
	if cmd == "" {
		usage()
		return exitUsage
	}

	var err error
	switch cmd {
	case "scan":
		return cmdScan(ctx, args)
	case "serve":
		err = cmdServe(ctx, args)
	case "daemon":
		err = cmdDaemon(ctx, args)
	case "quarantine":
		err = cmdQuarantine(ctx, args)
	case "config":
		err = cmdConfig(ctx, args)
	case "engines":
		err = cmdEngines(ctx, args)
	case "alert":
		err = cmdAlert(ctx, args)
	case "cron-line":
		err = cmdCronLine(args)
	case "doctor":
		err = cmdDoctor(ctx, args)
	case "version", "--version", "-v":
		fmt.Printf("sentinelhost %s (commit %s, build %s)\n", version, commit, buildDate)
		return exitOK
	case "help", "--help", "-h":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		return exitUsage
	}

	if err != nil {
		if errors.Is(err, errLocked) {
			fmt.Fprintln(os.Stderr, err)
			return exitLocked
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	return exitOK
}

func usage() {
	fmt.Fprint(os.Stderr, `SentinelHost — a malware-scanner orchestrator for shared hosting.

It has no detection engine of its own: it runs the engines available in your
environment, normalizes their output and consolidates everything into one
consensus verdict.

USAGE
  sentinelhost <command> [options]

COMMANDS
  scan          Run a cycle now and show the report
  daemon        Keep running cycles at the configured interval
  serve         Start the web panel (127.0.0.1 by default)
  quarantine    List, restore and purge items in the vault
  engines       Show the engines, their availability and the reason
  config        Show, validate and initialize the configuration
  alert         Send a test delivery by e-mail or webhook
  cron-line     Print the cron line ready to paste into cPanel
  doctor        Diagnose the environment and what each engine is missing
  version       Show the version

GLOBAL OPTIONS
  --config <file>   Path to the TOML (default: ~/.sentinelhost/config.toml)

EXIT CODES
  0   nothing to report
  1   the cycle found findings (not an error)
  2   execution error
  3   another instance is already running
  64  incorrect usage

Start with:  sentinelhost config init --root ~/public_html
`)
}
