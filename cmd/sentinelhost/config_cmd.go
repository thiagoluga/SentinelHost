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
		return fmt.Errorf("uso: sentinelhost config <init|show|validate|path>")
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
		return fmt.Errorf("subcomando desconhecido: %s (use init, show, validate ou path)", args[0])
	}
}

func configInit(args []string) error {
	fs, cfgPath := flagSet("config init")
	var roots multiFlag
	fs.Var(&roots, "root", "raiz do site a vigiar (pode repetir)")
	force := fs.Bool("force", false, "sobrescreve uma configuracao existente")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost config init — cria a configuracao inicial.

Os padroes sao deliberadamente conservadores: modo observacao ligado, periodo
de graca de 7 dias, nice 19, purga automatica desligada e painel so em
localhost. A primeira experiencia tem que ser "nao quebrou nada".

EXEMPLO
  sentinelhost config init --root ~/public_html

OPCOES
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(roots) == 0 {
		return fmt.Errorf("informe ao menos uma raiz: --root ~/public_html")
	}

	if _, err := os.Stat(*cfgPath); err == nil && !*force {
		return fmt.Errorf("ja existe configuracao em %s (use --force para sobrescrever)", *cfgPath)
	}

	cfg := config.Default()
	cfg.SetPath(*cfgPath)
	for _, r := range roots {
		abs, err := filepath.Abs(expandirTil(r))
		if err != nil {
			return fmt.Errorf("raiz %q invalida: %w", r, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("a raiz %s nao existe ou nao esta acessivel: %w", abs, err)
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

	fmt.Printf("Configuracao criada em %s\n\n", *cfgPath)
	fmt.Printf("  raizes vigiadas:   %s\n", strings.Join(cfg.General.Roots, ", "))
	fmt.Printf("  diretorio de dados: %s\n", cfg.General.DataDir)
	fmt.Printf("  modo observacao:    ligado (nada sera movido)\n")
	fmt.Printf("  periodo de graca:   %d dias\n", cfg.General.GracePeriodDays)
	fmt.Printf("\nProximo passo:\n  sentinelhost scan\n")
	fmt.Printf("\nDepois de conferir os resultados, desligue o modo observacao no TOML\n")
	fmt.Printf("ou no painel para que a quarentena automatica passe a agir.\n")
	return nil
}

func configShow(args []string) error {
	fs, cfgPath := flagSet("config show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := os.ReadFile(*cfgPath) //nolint:gosec // caminho informado pelo proprio usuario
	if err != nil {
		return err
	}
	// A configuracao guarda senha de SMTP e segredos de webhook. Imprimir
	// tudo na tela e o jeito mais facil de vazar um segredo num print de tela
	// ou num log de suporte.
	fmt.Print(mascararSegredos(string(data)))
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
		fmt.Printf("aviso  %s: %s\n", p.Field, p.Message)
	}
	for _, p := range res.Errors() {
		fmt.Printf("ERRO   %s: %s\n", p.Field, p.Message)
	}
	if res.HasErrors() {
		return fmt.Errorf("a configuracao tem %d erro(s)", len(res.Errors()))
	}
	if len(res.Warnings()) == 0 {
		fmt.Println("Configuracao valida, sem avisos.")
	} else {
		fmt.Printf("\nConfiguracao valida, com %d aviso(s).\n", len(res.Warnings()))
	}
	return nil
}

// mascararSegredos esconde valores de campos sensiveis.
func mascararSegredos(toml string) string {
	sensiveis := []string{"password", "secret"}
	linhas := strings.Split(toml, "\n")
	for i, l := range linhas {
		trim := strings.TrimSpace(l)
		for _, campo := range sensiveis {
			if strings.HasPrefix(trim, campo+" ") || strings.HasPrefix(trim, campo+"=") {
				chave, _, ok := strings.Cut(l, "=")
				if ok && strings.TrimSpace(strings.Trim(strings.SplitN(l, "=", 2)[1], ` "`)) != "" {
					linhas[i] = chave + `= "***"`
				}
			}
		}
	}
	return strings.Join(linhas, "\n")
}

func expandirTil(p string) string {
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

// multiFlag aceita uma flag repetida.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
