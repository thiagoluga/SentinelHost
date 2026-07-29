package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"text/tabwriter"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	sexec "github.com/thiagoluga/SentinelHost/internal/exec"
)

// engines: lists the engines with their availability and reason (FR-001).
func cmdEngines(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("engines")
	install := fs.String("install", "", "install an engine in the user's space (slug)")
	update := fs.String("update", "", "update an engine's signatures (slug, or 'all')")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	if *install != "" {
		ad, ok := a.registry.Get(*install)
		if !ok {
			return fmt.Errorf("engine %q does not exist in this binary", *install)
		}
		fmt.Printf("Installing %s in the user's space...\n", *install)
		if err := adapter.SafeInstall(ctx, ad, envFor(a.cfg, *install)); err != nil {
			return err
		}
		fmt.Println("Done.")
		return nil
	}

	if *update != "" {
		targets := []string{*update}
		if *update == "all" {
			targets = a.registry.Slugs()
		}
		for _, slug := range targets {
			ad, ok := a.registry.Get(slug)
			if !ok {
				continue
			}
			t, err := adapter.SafeUpdateSignatures(ctx, ad, envFor(a.cfg, slug))
			if err != nil {
				fmt.Printf("  ✗ %-20s %v\n", slug, err)
				continue
			}
			when := "no separate signatures"
			if !t.IsZero() {
				when = t.Local().Format("2006-01-02 15:04")
			}
			fmt.Printf("  ✓ %-20s %s\n", slug, when)
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENGINE\tENABLED\tWEIGHT\tAVAILABLE\tREASON / VERSION")
	for _, slug := range a.registry.Slugs() {
		ad, _ := a.registry.Get(slug)
		probe := adapter.SafeProbe(ctx, ad, envFor(a.cfg, slug))

		enabled := "no"
		if a.cfg.EngineEnabled(slug) {
			enabled = "yes"
		}
		available, detail := "no", probe.Reason
		if probe.Available {
			available, detail = "yes", probe.Version
		} else if probe.Installable {
			detail += "  → sentinelhost engines --install " + slug
		}
		fmt.Fprintf(w, "%s\t%s\t%.2f\t%s\t%s\n", slug, enabled, a.cfg.WeightFor(slug), available, detail)
	}
	return w.Flush()
}

// envFor assembles the adapter's environment for use outside the cycle (a manual
// probe, an install, a signature update).
//
// The executor comes along even here: a probe that called os/exec directly would
// escape the resource limits, and `sentinelhost engines` runs on the same server
// under the same quota as the cycle.
func envFor(cfg *config.Config, slug string) adapter.Environment {
	e := cfg.Engines[slug]
	binPath := e.Path
	if slug == "wp-checksums" && binPath == "" && len(cfg.General.Roots) > 0 {
		// A native adapter: what it needs to know is where to look.
		binPath = cfg.General.Roots[0]
	}
	return adapter.Environment{
		DataDir: cfg.General.DataDir,
		Runner: sexec.New(sexec.Limits{
			Nice:        cfg.Limits.Nice,
			IoniceClass: cfg.Limits.IoniceClass,
			Timeout:     cfg.Limits.EngineTimeout.Duration,
		}, cfg.RawOutputDir()),
		BinaryPath: binPath,
		ExtraArgs:  e.ExtraArgs,
	}
}

// alert: test delivery (FR-012).
func cmdAlert(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("alert")
	testEmail := fs.Bool("test-email", false, "send a test e-mail")
	testWebhook := fs.String("test-webhook", "", "send a test delivery to the webhook (id)")
	digest := fs.Bool("digest", false, "send the period's summary now")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	d := alert.NewDispatcher(ctx, a.cfg, a.store)

	switch {
	case *testEmail:
		res := d.TestEmail(ctx)
		fmt.Println(res)
		if !res.OK {
			return fmt.Errorf("the test delivery failed")
		}
	case *testWebhook != "":
		res := d.TestWebhook(ctx, *testWebhook)
		fmt.Println(res)
		if res.Body != "" {
			fmt.Printf("response: %s\n", res.Body)
		}
		if !res.OK {
			return fmt.Errorf("the test delivery failed")
		}
	case *digest:
		if err := d.SendDigestNow(ctx, time.Now().AddDate(0, 0, -1)); err != nil {
			return err
		}
		fmt.Println("Summary sent (if there was anything to summarize).")
	default:
		return fmt.Errorf("usage: sentinelhost alert --test-email | --test-webhook <id> | --digest")
	}
	return nil
}

// cron-line: produces the line ready to paste into cPanel (FR-009).
func cmdCronLine(args []string) error {
	fs, cfgPath := flagSet("cron-line")
	if err := fs.Parse(args); err != nil {
		return err
	}

	bin, err := os.Executable()
	if err != nil {
		bin = "sentinelhost"
	}
	bin, _ = filepath.Abs(bin)

	cfg, _, err := config.LoadOrDefault(*cfgPath)
	if err != nil {
		return err
	}

	interval := cfg.Schedule.Incremental.Duration
	schedule := "0 * * * *"
	description := "hourly"
	switch {
	case interval <= 15*time.Minute:
		schedule, description = "*/15 * * * *", "every 15 minutes"
	case interval <= 30*time.Minute:
		schedule, description = "*/30 * * * *", "every 30 minutes"
	case interval >= 6*time.Hour:
		schedule, description = "0 */6 * * *", "every 6 hours"
	}

	fmt.Println("Paste these lines into the cPanel cron manager:")
	fmt.Println()
	fmt.Printf("# incremental scan (%s)\n", description)
	fmt.Printf("%s %s scan --config %s --quiet\n", schedule, bin, *cfgPath)
	fmt.Println()
	fmt.Printf("# full scan (%s)\n", cfg.Schedule.FullCron)
	fmt.Printf("%s %s scan --config %s --full --quiet\n", cfg.Schedule.FullCron, bin, *cfgPath)
	fmt.Println()
	fmt.Printf("# signature update (%s)\n", cfg.Schedule.SignaturesCron)
	fmt.Printf("%s %s engines --update all --config %s\n", cfg.Schedule.SignaturesCron, bin, *cfgPath)
	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  • --quiet makes the cron send e-mail only when there are findings.")
	fmt.Println("  • The single-instance lock keeps two cycles from running over each")
	fmt.Println("    other; the second exits with code 3 without doing anything.")
	fmt.Println("  • Exit code 1 means 'found something', not 'broke'.")
	return nil
}

// doctor: environment diagnosis (T039).
func cmdDoctor(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("doctor")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("SentinelHost %s (%s/%s, Go %s)\n\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())

	cfg, exists, err := config.LoadOrDefault(*cfgPath)
	if err != nil {
		fmt.Printf("  ✗ configuration: %v\n", err)
		return err
	}
	if !exists {
		fmt.Printf("  ! the configuration has not been created at %s yet\n", *cfgPath)
		fmt.Printf("    run: sentinelhost config init --root ~/public_html\n")
		return nil
	}
	fmt.Printf("  ✓ configuration: %s\n", *cfgPath)

	res := cfg.Validate()
	for _, p := range res.Warnings() {
		fmt.Printf("  ! %s: %s\n", p.Field, p.Message)
	}
	for _, p := range res.Errors() {
		fmt.Printf("  ✗ %s: %s\n", p.Field, p.Message)
	}

	fmt.Printf("\nROOTS\n")
	for _, r := range cfg.General.Roots {
		if info, err := os.Stat(r); err != nil {
			fmt.Printf("  ✗ %s — %v\n", r, err)
		} else if !info.IsDir() {
			fmt.Printf("  ✗ %s — not a directory\n", r)
		} else {
			fmt.Printf("  ✓ %s\n", r)
		}
	}

	fmt.Printf("\nDATA DIRECTORY\n")
	if err := cfg.EnsureDataDirs(); err != nil {
		fmt.Printf("  ✗ %s — %v\n", cfg.General.DataDir, err)
	} else {
		fmt.Printf("  ✓ %s\n", cfg.General.DataDir)
		fmt.Printf("    vault:    %s\n", cfg.QuarantineDir())
		fmt.Printf("    database: %s\n", cfg.DatabasePath())
	}

	fmt.Printf("\nENGINES\n")
	if err := cmdEngines(ctx, []string{"--config", *cfgPath}); err != nil {
		fmt.Printf("  ✗ %v\n", err)
	}

	fmt.Printf("\nAUTOMATIC ACTION\n")
	allowed, reason := cfg.AutomaticActionAllowed(time.Now())
	if allowed {
		fmt.Printf("  ✓ allowed: confirmed verdicts will be quarantined\n")
	} else {
		fmt.Printf("  ! blocked: %s\n", reason)
	}
	return nil
}
