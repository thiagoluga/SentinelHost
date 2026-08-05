package main

import (
	"context"
	"fmt"
	"github.com/thiagoluga/SentinelHost/internal/store"
	"os"
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/web"
)

func cmdServe(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("serve")
	listen := fs.String("listen", "", "listen address (overrides the TOML)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost serve — starts the embedded web panel.

The panel listens on 127.0.0.1 by default. To reach it from another machine, use
an SSH tunnel instead of exposing the port:

  ssh -L 8787:127.0.0.1:8787 user@server

On first access the panel asks you to set the password.

OPTIONS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	if *listen != "" {
		a.cfg.Web.Listen = *listen
	}
	if !a.cfg.Web.Enabled {
		return fmt.Errorf("the panel is disabled in the configuration (web.enabled = false)")
	}

	dispatcher := alert.NewDispatcher(ctx, a.cfg, a.store)
	runner := cycle.New(a.cfg, a.store, a.registry, a.vault).WithDispatcher(dispatcher)
	srv := web.New(a.cfg, a.store, a.registry, a.vault, dispatcher, runner)

	url := "http://" + a.cfg.Web.Listen
	fmt.Printf("SentinelHost panel at %s\n", url)
	if !strings.HasPrefix(a.cfg.Web.Listen, "127.0.0.1") && !strings.HasPrefix(a.cfg.Web.Listen, "localhost") {
		// Exposing the panel is a legitimate choice of the user's, but it has to be
		// a conscious one: the single password is the only barrier left.
		fmt.Fprintf(os.Stderr,
			"\nWARNING: the panel is accepting connections from outside localhost.\n"+
				"Make sure the port is protected, or prefer an SSH tunnel:\n"+
				"  ssh -L 8787:127.0.0.1:8787 user@server\n\n")
	}
	// First access needs a token, and this is where the owner gets it.
	//
	// Being first to reach the URL is not a credential. The panel sits at a guessable
	// path and whoever claimed it was handed a session — and with it the ability to point
	// an engine's binary at an uploaded file and run it as this account. Reading this
	// token requires access to the account's own filesystem, which is what separates the
	// person installing the panel from a visitor.
	if !a.passwordAlreadySet(ctx) {
		token, err := web.SetupToken(a.cfg.General.DataDir)
		if err != nil {
			return fmt.Errorf("preparing first access: %w", err)
		}
		fmt.Printf("\nFirst access. Paste this on the setup screen:\n\n    %s\n\n"+
			"It is also in %s inside the data directory, readable only by this account.\n"+
			"It stops working the moment the password is set.\n\n",
			token, "setup-token")
	}

	fmt.Println("Ctrl-C to stop.")

	return srv.ListenAndServe(ctx)
}

// passwordAlreadySet reports whether the panel has an owner.
//
// Fails CLOSED: an unreadable store answers "yes", so a database problem prints no token
// rather than advertising a fresh one for a panel that already belongs to somebody.
func (a *app) passwordAlreadySet(ctx context.Context) bool {
	h, err := a.store.GetSetting(ctx, store.KeyPanelPasswordHash)
	if err != nil {
		return true
	}
	return h != ""
}
