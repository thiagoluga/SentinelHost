package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/amwscan"
	"github.com/thiagoluga/SentinelHost/internal/adapter/pmf"
	"github.com/thiagoluga/SentinelHost/internal/adapter/wpchecksums"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/lock"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// errLocked propaga o codigo de saida proprio de concorrencia.
var errLocked = lock.ErrLocked

// app reune tudo que os comandos precisam.
type app struct {
	cfg      *config.Config
	store    *store.Store
	registry *adapter.Registry
	vault    *quarantine.Vault
}

func (a *app) Close() {
	if a != nil && a.store != nil {
		_ = a.store.Close()
	}
}

// registry monta o registro com os adaptadores do MVP.
//
// Registrar aqui, e nao num init() de cada pacote, mantem explicito quais
// engines este binario conhece — util quando o usuario pergunta por que um
// engine "nao aparece".
func newRegistry() *adapter.Registry {
	r := adapter.NewRegistry()
	r.MustRegister(wpchecksums.New())
	r.MustRegister(amwscan.New())
	r.MustRegister(pmf.New())
	return r
}

// openApp carrega config e abre o banco.
func openApp(ctx context.Context, configPath string) (*app, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil, fmt.Errorf("%w\n\nRode primeiro:  sentinelhost config init --root <caminho do site>", err)
		}
		return nil, err
	}

	res := cfg.Validate()
	if res.HasErrors() {
		return nil, res.Err()
	}
	// Avisos nao impedem a execucao: a ferramenta que se recusa a rodar
	// protege menos que a que roda avisando.
	for _, p := range res.Warnings() {
		fmt.Fprintf(os.Stderr, "aviso: %s: %s\n", p.Field, p.Message)
	}

	if err := cfg.EnsureDataDirs(); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		return nil, err
	}

	return &app{
		cfg:      cfg,
		store:    st,
		registry: newRegistry(),
		vault:    quarantine.New(cfg.QuarantineDir(), cfg.Quarantine, st),
	}, nil
}

// flagSet cria um conjunto de flags com --config ja incluida.
func flagSet(nome string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(nome, flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath(), "caminho do arquivo de configuracao TOML")
	return fs, cfgPath
}

// parseArgs interpreta flags que aparecem DEPOIS de argumentos posicionais.
//
// O flag da biblioteca padrao para de parsear no primeiro argumento que nao
// comeca com traco. Isso faz
//
//	sentinelhost quarantine restore q_123 --config /caminho/config.toml
//
// ignorar o --config em silencio e cair no caminho padrao — que e exatamente a
// forma documentada no quickstart para quem tem a configuracao fora do lugar
// padrao. O comando entao falha dizendo que nao achou a configuracao, ou pior,
// age sobre a instancia errada.
//
// A solucao e o laco: parseia, tira o primeiro posicional, e parseia o resto.
// Devolve os posicionais na ordem em que apareceram.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var posicionais []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		resto := fs.Args()
		if len(resto) == 0 {
			return posicionais, nil
		}
		posicionais = append(posicionais, resto[0])
		args = resto[1:]
	}
}
