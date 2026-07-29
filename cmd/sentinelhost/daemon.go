package main

import (
	"context"
	"fmt"
	"os"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/sched"
)

func cmdDaemon(ctx context.Context, args []string) error {
	fs, cfgPath := flagSet("daemon")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost daemon — fica rodando ciclos no intervalo configurado.

O daemon e OPCIONAL. Hospedagem compartilhada raramente mantem um processo
vivo por horas, e tudo que ele faz tambem funciona so com o cron do cPanel:

  sentinelhost cron-line

Use o daemon quando voce tem SSH e quer ciclos mais frequentes.

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

	dispatcher := alert.NewDispatcher(ctx, a.cfg, a.store)
	runner := cycle.New(a.cfg, a.store, a.registry, a.vault).WithDispatcher(dispatcher)

	d := sched.New(a.cfg, runner, a.store, dispatcher, a.vault)
	d.OnCycle = func(sum cycle.Summary) {
		fmt.Printf("[%s] ciclo %s: %d confirmado(s), %d provavel(is), %d suspeito(s)\n",
			sum.FinishedAt.Format("15:04:05"), sum.ScanID,
			sum.LevelCounts["confirmed"], sum.LevelCounts["likely"], sum.LevelCounts["suspicious"])
	}

	fmt.Printf("SentinelHost em modo daemon (intervalo: %s). Ctrl-C para sair.\n",
		a.cfg.Schedule.Incremental.Duration)
	return d.Run(ctx)
}
