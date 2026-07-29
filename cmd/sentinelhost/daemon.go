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
		fmt.Fprint(os.Stderr, `sentinelhost daemon — keeps running cycles at the configured interval.

The daemon is OPTIONAL. Shared hosting rarely keeps a process alive for hours,
and everything it does also works with the cPanel cron alone:

  sentinelhost cron-line

Use the daemon when you have SSH and want more frequent cycles.

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

	dispatcher := alert.NewDispatcher(ctx, a.cfg, a.store)
	runner := cycle.New(a.cfg, a.store, a.registry, a.vault).WithDispatcher(dispatcher)

	d := sched.New(a.cfg, runner, a.store, dispatcher, a.vault)
	d.OnCycle = func(sum cycle.Summary) {
		fmt.Printf("[%s] cycle %s: %d confirmed, %d likely, %d suspicious\n",
			sum.FinishedAt.Format("15:04:05"), sum.ScanID,
			sum.LevelCounts["confirmed"], sum.LevelCounts["likely"], sum.LevelCounts["suspicious"])
	}

	fmt.Printf("SentinelHost in daemon mode (interval: %s). Ctrl-C to exit.\n",
		a.cfg.Schedule.Incremental.Duration)
	return d.Run(ctx)
}
