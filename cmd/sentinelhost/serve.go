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
	listen := fs.String("listen", "", "endereco de escuta (sobrepoe o TOML)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost serve — sobe o painel web embutido.

O painel escuta em 127.0.0.1 por padrao. Para acessar de outra maquina, use um
tunel SSH em vez de expor a porta:

  ssh -L 8787:127.0.0.1:8787 usuario@servidor

No primeiro acesso o painel pede que voce defina a senha.

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

	if *listen != "" {
		a.cfg.Web.Listen = *listen
	}
	if !a.cfg.Web.Enabled {
		return fmt.Errorf("o painel esta desabilitado na configuracao (web.enabled = false)")
	}

	dispatcher := alert.NewDispatcher(ctx, a.cfg, a.store)
	runner := cycle.New(a.cfg, a.store, a.registry, a.vault).WithDispatcher(dispatcher)
	srv := web.New(a.cfg, a.store, a.registry, a.vault, dispatcher, runner)

	url := "http://" + a.cfg.Web.Listen
	fmt.Printf("Painel do SentinelHost em %s\n", url)
	if !strings.HasPrefix(a.cfg.Web.Listen, "127.0.0.1") && !strings.HasPrefix(a.cfg.Web.Listen, "localhost") {
		// Expor o painel e escolha legitima do usuario, mas ela precisa ser
		// consciente: a senha unica e a unica barreira que sobra.
		fmt.Fprintf(os.Stderr,
			"\nATENCAO: o painel esta aceitando conexoes de fora de localhost.\n"+
				"Garanta que a porta esta protegida, ou prefira um tunel SSH:\n"+
				"  ssh -L 8787:127.0.0.1:8787 usuario@servidor\n\n")
	}
	fmt.Println("Ctrl-C para encerrar.")

	return srv.ListenAndServe(ctx)
}
