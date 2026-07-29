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

// engines: lista os engines com disponibilidade e motivo (FR-001).
func cmdEngines(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("engines")
	install := fs.String("install", "", "instala um engine no espaco do usuario (slug)")
	update := fs.String("update", "", "atualiza as assinaturas de um engine (slug, ou 'all')")
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
			return fmt.Errorf("engine %q nao existe neste binario", *install)
		}
		fmt.Printf("Instalando %s no espaco do usuario...\n", *install)
		if err := adapter.SafeInstall(ctx, ad, envFor(a.cfg, *install)); err != nil {
			return err
		}
		fmt.Println("Pronto.")
		return nil
	}

	if *update != "" {
		alvos := []string{*update}
		if *update == "all" {
			alvos = a.registry.Slugs()
		}
		for _, slug := range alvos {
			ad, ok := a.registry.Get(slug)
			if !ok {
				continue
			}
			t, err := adapter.SafeUpdateSignatures(ctx, ad, envFor(a.cfg, slug))
			if err != nil {
				fmt.Printf("  ✗ %-20s %v\n", slug, err)
				continue
			}
			quando := "sem assinaturas separadas"
			if !t.IsZero() {
				quando = t.Local().Format("2006-01-02 15:04")
			}
			fmt.Printf("  ✓ %-20s %s\n", slug, quando)
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENGINE\tHABILITADO\tPESO\tDISPONIVEL\tMOTIVO / VERSAO")
	for _, slug := range a.registry.Slugs() {
		ad, _ := a.registry.Get(slug)
		probe := adapter.SafeProbe(ctx, ad, envFor(a.cfg, slug))

		habilitado := "nao"
		if a.cfg.EngineEnabled(slug) {
			habilitado = "sim"
		}
		disp, detalhe := "nao", probe.Reason
		if probe.Available {
			disp, detalhe = "sim", probe.Version
		} else if probe.Installable {
			detalhe += "  → sentinelhost engines --install " + slug
		}
		fmt.Fprintf(w, "%s\t%s\t%.2f\t%s\t%s\n", slug, habilitado, a.cfg.WeightFor(slug), disp, detalhe)
	}
	return w.Flush()
}

// envFor monta o ambiente do adaptador para uso fora do ciclo (probe manual,
// instalacao, atualizacao de assinaturas).
//
// O executor vai junto mesmo aqui: um probe que chamasse os/exec direto
// escaparia dos limites de recursos, e `sentinelhost engines` roda no mesmo
// servidor com a mesma cota que o ciclo.
func envFor(cfg *config.Config, slug string) adapter.Environment {
	e := cfg.Engines[slug]
	binPath := e.Path
	if slug == "wp-checksums" && binPath == "" && len(cfg.General.Roots) > 0 {
		// Adaptador nativo: o que ele precisa saber e onde procurar.
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

// alert: entrega de teste (FR-012).
func cmdAlert(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("alert")
	testarEmail := fs.Bool("test-email", false, "envia um e-mail de teste")
	testarWebhook := fs.String("test-webhook", "", "envia uma entrega de teste ao webhook (id)")
	digest := fs.Bool("digest", false, "envia o resumo do periodo agora")
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
	case *testarEmail:
		res := d.TestEmail(ctx)
		fmt.Println(res)
		if !res.OK {
			return fmt.Errorf("a entrega de teste falhou")
		}
	case *testarWebhook != "":
		res := d.TestWebhook(ctx, *testarWebhook)
		fmt.Println(res)
		if res.Body != "" {
			fmt.Printf("resposta: %s\n", res.Body)
		}
		if !res.OK {
			return fmt.Errorf("a entrega de teste falhou")
		}
	case *digest:
		if err := d.SendDigestNow(ctx, time.Now().AddDate(0, 0, -1)); err != nil {
			return err
		}
		fmt.Println("Resumo enviado (se havia o que resumir).")
	default:
		return fmt.Errorf("uso: sentinelhost alert --test-email | --test-webhook <id> | --digest")
	}
	return nil
}

// cron-line: gera a linha pronta para colar no cPanel (FR-009).
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

	intervalo := cfg.Schedule.Incremental.Duration
	agenda := "0 * * * *"
	descricao := "de hora em hora"
	switch {
	case intervalo <= 15*time.Minute:
		agenda, descricao = "*/15 * * * *", "a cada 15 minutos"
	case intervalo <= 30*time.Minute:
		agenda, descricao = "*/30 * * * *", "a cada 30 minutos"
	case intervalo >= 6*time.Hour:
		agenda, descricao = "0 */6 * * *", "a cada 6 horas"
	}

	fmt.Println("Cole estas linhas no gerenciador de cron do cPanel:")
	fmt.Println()
	fmt.Printf("# scan incremental (%s)\n", descricao)
	fmt.Printf("%s %s scan --config %s --quiet\n", agenda, bin, *cfgPath)
	fmt.Println()
	fmt.Printf("# scan completo (%s)\n", cfg.Schedule.FullCron)
	fmt.Printf("%s %s scan --config %s --full --quiet\n", cfg.Schedule.FullCron, bin, *cfgPath)
	fmt.Println()
	fmt.Printf("# atualizacao de assinaturas (%s)\n", cfg.Schedule.SignaturesCron)
	fmt.Printf("%s %s engines --update all --config %s\n", cfg.Schedule.SignaturesCron, bin, *cfgPath)
	fmt.Println()
	fmt.Println("Observacoes:")
	fmt.Println("  • --quiet faz o cron so mandar e-mail quando houver achados.")
	fmt.Println("  • O lock de instancia unica impede que dois ciclos se atropelem;")
	fmt.Println("    o segundo sai com codigo 3 sem fazer nada.")
	fmt.Println("  • Codigo de saida 1 significa 'achou algo', nao 'quebrou'.")
	return nil
}

// doctor: diagnostico do ambiente (T039).
func cmdDoctor(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("doctor")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("SentinelHost %s (%s/%s, Go %s)\n\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())

	cfg, existe, err := config.LoadOrDefault(*cfgPath)
	if err != nil {
		fmt.Printf("  ✗ configuracao: %v\n", err)
		return err
	}
	if !existe {
		fmt.Printf("  ! configuracao ainda nao criada em %s\n", *cfgPath)
		fmt.Printf("    rode: sentinelhost config init --root ~/public_html\n")
		return nil
	}
	fmt.Printf("  ✓ configuracao: %s\n", *cfgPath)

	res := cfg.Validate()
	for _, p := range res.Warnings() {
		fmt.Printf("  ! %s: %s\n", p.Field, p.Message)
	}
	for _, p := range res.Errors() {
		fmt.Printf("  ✗ %s: %s\n", p.Field, p.Message)
	}

	fmt.Printf("\nRAIZES\n")
	for _, r := range cfg.General.Roots {
		if info, err := os.Stat(r); err != nil {
			fmt.Printf("  ✗ %s — %v\n", r, err)
		} else if !info.IsDir() {
			fmt.Printf("  ✗ %s — nao e diretorio\n", r)
		} else {
			fmt.Printf("  ✓ %s\n", r)
		}
	}

	fmt.Printf("\nDIRETORIO DE DADOS\n")
	if err := cfg.EnsureDataDirs(); err != nil {
		fmt.Printf("  ✗ %s — %v\n", cfg.General.DataDir, err)
	} else {
		fmt.Printf("  ✓ %s\n", cfg.General.DataDir)
		fmt.Printf("    cofre:  %s\n", cfg.QuarantineDir())
		fmt.Printf("    banco:  %s\n", cfg.DatabasePath())
	}

	fmt.Printf("\nENGINES\n")
	if err := cmdEngines(ctx, []string{"--config", *cfgPath}); err != nil {
		fmt.Printf("  ✗ %v\n", err)
	}

	fmt.Printf("\nACAO AUTOMATICA\n")
	permitido, motivo := cfg.AutomaticActionAllowed(time.Now())
	if permitido {
		fmt.Printf("  ✓ liberada: vereditos confirmados serao quarentenados\n")
	} else {
		fmt.Printf("  ! bloqueada: %s\n", motivo)
	}
	return nil
}
