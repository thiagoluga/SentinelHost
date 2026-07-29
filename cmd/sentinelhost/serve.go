package main

import (
	"context"
	"fmt"
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
	fmt.Println("Ctrl-C to stop.")

	return srv.ListenAndServe(ctx)
}
