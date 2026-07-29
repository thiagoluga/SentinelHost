package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/thiagoluga/SentinelHost/internal/store"
)

func cmdQuarantine(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sentinelhost quarantine <list|restore|purge|verify> [options]")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		return quarantineList(ctx, rest)
	case "restore":
		return quarantineRestore(ctx, rest)
	case "purge":
		return quarantinePurge(ctx, rest)
	case "verify":
		return quarantineVerify(ctx, rest)
	default:
		return fmt.Errorf("unknown subcommand: %s (use list, restore, purge or verify)", sub)
	}
}

func quarantineList(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("quarantine list")
	all := fs.Bool("all", false, "include items already restored and purged")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	filter := store.QuarantineActive
	if *all {
		filter = ""
	}
	items, err := a.store.ListQuarantineItems(ctx, filter, 0)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("The vault is empty.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "REF\tSTATUS\tQUARANTINED\tRETENTION UNTIL\tORIGINAL FILE")
	for _, it := range items {
		retention := "never expires"
		if !it.RetentionUntil.IsZero() {
			retention = it.RetentionUntil.Local().Format("2006-01-02")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			it.Ref, it.Status,
			it.QuarantinedAt.Local().Format("2006-01-02 15:04"),
			retention, it.OriginalPath)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Printf("\n%d item(s). All are restorable with:  sentinelhost quarantine restore <ref>\n", len(items))
	return nil
}

func quarantineRestore(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("quarantine restore")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return fmt.Errorf("usage: sentinelhost quarantine restore <ref>")
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	ref := positional[0]
	item, err := a.vault.Restore(ctx, ref)
	if err != nil {
		return err
	}
	_ = a.store.Log(ctx, store.Event{
		Level: "info", Category: store.CatQuarantine,
		Message: "file restored by the user through the CLI: " + item.OriginalPath,
		Fields:  map[string]any{"ref": ref},
	})

	fmt.Printf("Restored byte for byte at %s\n", item.OriginalPath)
	fmt.Printf("Hash checked: %s\n", item.SHA256)
	return nil
}

func quarantinePurge(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("quarantine purge")
	force := fs.Bool("force", false, "purge a specific item even inside its retention")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost quarantine purge [ref] — remove permanently.

With no argument, it purges only the items whose retention period has passed.
With a ref and --force, it purges that item even inside its retention.

This is SentinelHost's ONLY irreversible operation.

OPTIONS
`)
		fs.PrintDefaults()
	}
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	if len(positional) == 0 {
		n, err := a.vault.PurgeExpired(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%d expired item(s) purged.\n", n)
		return nil
	}

	ref := positional[0]
	item, err := a.store.GetQuarantineItem(ctx, ref)
	if err != nil {
		return err
	}

	// Explicit confirmation: this is the project's only irreversible operation.
	if !*yes {
		fmt.Printf("Purge %s permanently?\n", ref)
		fmt.Printf("  original file: %s\n", item.OriginalPath)
		fmt.Printf("  quarantined at: %s\n", item.QuarantinedAt.Local().Format("2006-01-02 15:04"))
		fmt.Print("\nThis CANNOT be undone. Type 'purge' to confirm: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if strings.TrimSpace(answer) != "purge" {
			fmt.Println("Cancelled. Nothing was removed.")
			return nil
		}
	}

	if err := a.vault.Purge(ctx, ref, *force); err != nil {
		return err
	}
	_ = a.store.Log(ctx, store.Event{
		Level: "warn", Category: store.CatQuarantine,
		Message: "item permanently purged by the user: " + item.OriginalPath,
		Fields:  map[string]any{"ref": ref, "force": *force},
	})
	fmt.Printf("%s purged permanently.\n", ref)
	return nil
}

func quarantineVerify(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("quarantine verify")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	problems, err := a.vault.Verify(ctx)
	if err != nil {
		return err
	}
	if len(problems) == 0 {
		fmt.Println("The vault is intact: every copy matches its recorded hash.")
		return nil
	}
	fmt.Printf("%d problem(s) in the vault:\n", len(problems))
	for _, p := range problems {
		fmt.Printf("  ! %s\n", p)
	}
	return fmt.Errorf("the vault has copies that do not match; restoring those items is not guaranteed")
}
