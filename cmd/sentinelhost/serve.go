package main

import (
	"context"
	"fmt"
	"github.com/thiagoluga/SentinelHost/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/web"
)

func cmdServe(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("serve")
	listen := fs.String("listen", "", "listen address (overrides the TOML)")
	pidFile := fs.String("pidfile", "", "write this process's id here, and remove it on a clean exit")
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

	// Say which process this is, for whoever has to clear it later.
	//
	// A panel that wedges keeps its listening socket, so nothing can start a replacement on
	// the port and nothing can identify what to kill. On the account this was built for
	// there is no shell — no ps, no fuser — so the only party able to act is the PHP bridge,
	// and it needs a process id it can verify belongs to this binary before it signals it.
	//
	// Removed on a clean exit precisely so a file that SURVIVES means something: the process
	// did not get to shut down, which is the case the bridge is looking for.
	removePID, err := writePIDFile(*pidFile)
	if err != nil {
		return err
	}
	defer removePID()

	dispatcher := alert.NewDispatcher(ctx, a.cfg, a.store)
	runner := cycle.New(a.cfg, a.store, a.registry, a.vault).WithDispatcher(dispatcher)
	srv := web.New(a.cfg, a.store, a.registry, a.vault, dispatcher, runner)

	// The panel can report a newer release and install it when the user asks. It never
	// does so on its own: a security tool that replaces itself unattended on shared
	// hosting behaves the way the things it hunts behave.
	//
	// A build with no release key still gets the checker — it answers "cannot check" and
	// says why, which is more useful than a panel with no opinion at all.
	if updates, err := newPanelUpdates(ctx); err == nil {
		srv = srv.WithUpdates(updates)
	} else {
		fmt.Fprintf(os.Stderr, "the panel cannot offer updates: %v\n", err)
	}

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

// writePIDFile records this process's id, and returns the way to take it back.
//
// An empty path is not an error: a panel started by hand does not need one, and refusing to
// serve without it would break every existing install for the sake of a debugging aid.
//
// 0600 because the file names a process the bridge is allowed to kill. It is written whole
// rather than appended so a reader never sees two ids, and the caller removes it on a clean
// exit so a file left behind carries information: this process never shut down.
func writePIDFile(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("preparing the directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return func() { _ = os.Remove(path) }, nil
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
