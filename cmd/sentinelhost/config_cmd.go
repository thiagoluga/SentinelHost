package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

func cmdConfig(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sentinelhost config <init|show|validate|path>")
	}
	switch args[0] {
	case "init":
		return configInit(args[1:])
	case "show":
		return configShow(args[1:])
	case "validate":
		return configValidate(args[1:])
	case "path":
		fmt.Println(config.DefaultConfigPath())
		return nil
	default:
		return fmt.Errorf("unknown subcommand: %s (use init, show, validate or path)", args[0])
	}
}

func configInit(args []string) error {
	fs, cfgPath := flagSet("config init")
	var roots multiFlag
	fs.Var(&roots, "root", "root of the site to watch (may be repeated)")
	force := fs.Bool("force", false, "overwrite an existing configuration")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost config init — creates the initial configuration.

The defaults are deliberately conservative: observation mode on, a 7-day grace
period, nice 19, automatic purge off and the panel on localhost only. The first
experience has to be "it broke nothing".

EXAMPLE
  sentinelhost config init --root ~/public_html

OPTIONS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(roots) == 0 {
		return fmt.Errorf("give at least one root: --root ~/public_html")
	}

	if _, err := os.Stat(*cfgPath); err == nil && !*force {
		return fmt.Errorf("a configuration already exists at %s (use --force to overwrite)", *cfgPath)
	}

	cfg := config.Default()
	cfg.SetPath(*cfgPath)
	for _, r := range roots {
		abs, err := filepath.Abs(expandTilde(r))
		if err != nil {
			return fmt.Errorf("invalid root %q: %w", r, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("the root %s does not exist or is not accessible: %w", abs, err)
		}
		cfg.General.Roots = append(cfg.General.Roots, abs)
	}

	if res := cfg.Validate(); res.HasErrors() {
		return res.Err()
	}
	if err := cfg.EnsureDataDirs(); err != nil {
		return err
	}
	if err := cfg.Save(); err != nil {
		return err
	}

	fmt.Printf("Configuration created at %s\n\n", *cfgPath)
	fmt.Printf("  watched roots:    %s\n", strings.Join(cfg.General.Roots, ", "))
	fmt.Printf("  data directory:   %s\n", cfg.General.DataDir)
	fmt.Printf("  observation mode: on (nothing will be moved)\n")
	fmt.Printf("  grace period:     %d days\n", cfg.General.GracePeriodDays)
	fmt.Printf("\nNext step:\n  sentinelhost scan\n")
	fmt.Printf("\nAfter reviewing the results, turn observation mode off in the TOML\n")
	fmt.Printf("or in the panel so the automatic quarantine starts acting.\n")
	return nil
}

func configShow(args []string) error {
	fs, cfgPath := flagSet("config show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := os.ReadFile(*cfgPath) // path given by the user themselves
	if err != nil {
		return err
	}
	// The configuration holds the SMTP password and webhook secrets. Printing
	// everything on screen is the easiest way to leak a secret in a screenshot or
	// in a support log.
	fmt.Print(maskSecrets(string(data)))
	return nil
}

func configValidate(args []string) error {
	fs, cfgPath := flagSet("config validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	res := cfg.Validate()

	for _, p := range res.Warnings() {
		fmt.Printf("warning  %s: %s\n", p.Field, p.Message)
	}
	for _, p := range res.Errors() {
		fmt.Printf("ERROR    %s: %s\n", p.Field, p.Message)
	}
	if res.HasErrors() {
		return fmt.Errorf("the configuration has %d error(s)", len(res.Errors()))
	}
	if len(res.Warnings()) == 0 {
		fmt.Println("The configuration is valid, with no warnings.")
	} else {
		fmt.Printf("\nThe configuration is valid, with %d warning(s).\n", len(res.Warnings()))
	}
	return nil
}

// maskSecrets hides the values of sensitive fields.
func maskSecrets(toml string) string {
	sensitive := []string{"password", "secret"}
	lines := strings.Split(toml, "\n")
	for i, l := range lines {
		trim := strings.TrimSpace(l)
		for _, field := range sensitive {
			if strings.HasPrefix(trim, field+" ") || strings.HasPrefix(trim, field+"=") {
				key, _, ok := strings.Cut(l, "=")
				if ok && strings.TrimSpace(strings.Trim(strings.SplitN(l, "=", 2)[1], ` "`)) != "" {
					lines[i] = key + `= "***"`
				}
			}
		}
	}
	return strings.Join(lines, "\n")
}

func expandTilde(p string) string {
	if !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// multiFlag accepts a repeated flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
