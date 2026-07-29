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
		return fmt.Errorf("uso: sentinelhost quarantine <list|restore|purge|verify> [opcoes]")
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
		return fmt.Errorf("subcomando desconhecido: %s (use list, restore, purge ou verify)", sub)
	}
}

func quarantineList(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("quarantine list")
	todos := fs.Bool("all", false, "inclui itens ja restaurados e purgados")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	filtro := store.QuarantineActive
	if *todos {
		filtro = ""
	}
	itens, err := a.store.ListQuarantineItems(ctx, filtro, 0)
	if err != nil {
		return err
	}
	if len(itens) == 0 {
		fmt.Println("O cofre esta vazio.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "REF\tSTATUS\tQUARENTENADO\tRETENCAO ATE\tARQUIVO ORIGINAL")
	for _, it := range itens {
		retencao := "nunca expira"
		if !it.RetentionUntil.IsZero() {
			retencao = it.RetentionUntil.Local().Format("2006-01-02")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			it.Ref, it.Status,
			it.QuarantinedAt.Local().Format("2006-01-02 15:04"),
			retencao, it.OriginalPath)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Printf("\n%d item(ns). Todos sao restauraveis com:  sentinelhost quarantine restore <ref>\n", len(itens))
	return nil
}

func quarantineRestore(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("quarantine restore")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("uso: sentinelhost quarantine restore <ref>")
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer a.Close()

	ref := fs.Arg(0)
	item, err := a.vault.Restore(ctx, ref)
	if err != nil {
		return err
	}
	_ = a.store.Log(ctx, store.Event{
		Level: "info", Category: store.CatQuarantine,
		Message: "arquivo restaurado pelo usuario via CLI: " + item.OriginalPath,
		Fields:  map[string]any{"ref": ref},
	})

	fmt.Printf("Restaurado byte a byte em %s\n", item.OriginalPath)
	fmt.Printf("Hash conferido: %s\n", item.SHA256)
	return nil
}

func quarantinePurge(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("quarantine purge")
	force := fs.Bool("force", false, "purga um item especifico mesmo dentro da retencao")
	sim := fs.Bool("yes", false, "nao pede confirmacao")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost quarantine purge [ref] — remove definitivamente.

Sem argumento, purga apenas os itens que ja passaram do periodo de retencao.
Com uma ref e --force, purga aquele item mesmo dentro da retencao.

Esta e a UNICA operacao irreversivel do SentinelHost.

OPCOES
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

	if fs.NArg() == 0 {
		n, err := a.vault.PurgeExpired(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%d item(ns) expirado(s) purgado(s).\n", n)
		return nil
	}

	ref := fs.Arg(0)
	item, err := a.store.GetQuarantineItem(ctx, ref)
	if err != nil {
		return err
	}

	// Confirmacao explicita: esta e a unica operacao irreversivel do projeto.
	if !*sim {
		fmt.Printf("Purgar definitivamente %s?\n", ref)
		fmt.Printf("  arquivo original: %s\n", item.OriginalPath)
		fmt.Printf("  quarentenado em:  %s\n", item.QuarantinedAt.Local().Format("2006-01-02 15:04"))
		fmt.Print("\nIsto NAO tem volta. Digite 'purgar' para confirmar: ")
		var resposta string
		_, _ = fmt.Scanln(&resposta)
		if strings.TrimSpace(resposta) != "purgar" {
			fmt.Println("Cancelado. Nada foi removido.")
			return nil
		}
	}

	if err := a.vault.Purge(ctx, ref, *force); err != nil {
		return err
	}
	_ = a.store.Log(ctx, store.Event{
		Level: "warn", Category: store.CatQuarantine,
		Message: "item purgado definitivamente pelo usuario: " + item.OriginalPath,
		Fields:  map[string]any{"ref": ref, "force": *force},
	})
	fmt.Printf("%s purgado definitivamente.\n", ref)
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

	problemas, err := a.vault.Verify(ctx)
	if err != nil {
		return err
	}
	if len(problemas) == 0 {
		fmt.Println("Cofre integro: todas as copias conferem com o hash registrado.")
		return nil
	}
	fmt.Printf("%d problema(s) no cofre:\n", len(problemas))
	for _, p := range problemas {
		fmt.Printf("  ! %s\n", p)
	}
	return fmt.Errorf("o cofre tem copias que nao conferem; a restauracao desses itens nao esta garantida")
}
