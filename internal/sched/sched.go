// Package sched runs cycles continuously in daemon mode.
//
// Daemon mode is OPTIONAL by design: shared hosting rarely keeps a process alive
// for hours, and Principle III requires everything essential to work with the
// cPanel cron alone. The daemon is a comfort for those who have SSH, never a
// requirement.
package sched

import (
	"context"
	"errors"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/housekeeping"
	"github.com/thiagoluga/SentinelHost/internal/lock"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Daemon runs cycles at the configured interval.
type Daemon struct {
	cfg    *config.Config
	runner *cycle.Runner
	store  *store.Store
	alerts *alert.Dispatcher
	vault  *quarantine.Vault
	now    func() time.Time
	// OnCycle is called after each cycle (used by the CLI to print).
	OnCycle func(cycle.Summary)
}

// New assembles the daemon.
func New(cfg *config.Config, r *cycle.Runner, st *store.Store, d *alert.Dispatcher, v *quarantine.Vault) *Daemon {
	return &Daemon{cfg: cfg, runner: r, store: st, alerts: d, vault: v, now: time.Now}
}

// Run runs until the context is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	interval := d.cfg.Schedule.Incremental.Duration
	if interval <= 0 {
		interval = time.Hour
	}

	// Maintenance at start-up: closes cycles interrupted by an earlier kill,
	// resumes pending deliveries and applies the disk retention.
	d.maintenance(ctx)

	// The first cycle runs immediately: whoever starts the daemon wants to know
	// the state now, not an hour from now.
	d.runOnce(ctx)

	t := time.NewTicker(interval)
	defer t.Stop()

	// The full scan has its own, more spaced-out schedule; the daemon only checks
	// from time to time whether its hour has come.
	checkFull := time.NewTicker(15 * time.Minute)
	defer checkFull.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			d.runOnce(ctx)
		case <-checkFull.C:
			d.maybeFull(ctx)
			d.maintenance(ctx)
		}
	}
}

// runOnce runs one incremental cycle.
//
// No cycle error takes the daemon down: a scan that failed today must not keep
// tomorrow's scan from happening. The failure is recorded and life goes on.
func (d *Daemon) runOnce(ctx context.Context) {
	sum, err := d.runner.Run(ctx, cycle.Options{Mode: schema.ModeIncremental})
	switch {
	case errors.Is(err, lock.ErrLocked):
		// Another process (the cron, most likely) is running. Normal.
		d.log(ctx, "info", store.CatScan, "cycle skipped: "+err.Error())
		return
	case err != nil:
		d.log(ctx, "error", store.CatScan, "cycle failed: "+err.Error())
		return
	}
	if d.OnCycle != nil {
		d.OnCycle(sum)
	}
}

// maybeFull triggers the full scan when the schedule calls for it.
func (d *Daemon) maybeFull(ctx context.Context) {
	if d.cfg.Schedule.FullCron == "" {
		return
	}
	last, err := d.store.LastScan(ctx)
	if err == nil && last.Mode == schema.ModeFull && d.now().Sub(last.StartedAt) < 20*time.Hour {
		return
	}
	schedule, err := ParseCron(d.cfg.Schedule.FullCron)
	if err != nil {
		d.log(ctx, "warn", store.CatSystem, "invalid schedule.full_cron: "+err.Error())
		return
	}
	if !schedule.Matches(d.now()) {
		return
	}

	sum, err := d.runner.Run(ctx, cycle.Options{Mode: schema.ModeFull})
	if err != nil {
		if !errors.Is(err, lock.ErrLocked) {
			d.log(ctx, "error", store.CatScan, "the full scan failed: "+err.Error())
		}
		return
	}
	if d.OnCycle != nil {
		d.OnCycle(sum)
	}
}

// maintenance delegates to the housekeeping package, the SAME one the `scan`
// command uses.
//
// These routines used to live only here, and the project's default mode is `cron`
// — the result was that webhook retries, the periodic summary and the disk
// retention never happened for most users.
func (d *Daemon) maintenance(ctx context.Context) {
	res, err := housekeeping.Run(ctx, housekeeping.Deps{
		Cfg: d.cfg, Store: d.store, Vault: d.vault, Alerts: d.alerts, Now: d.now,
	})
	if err != nil {
		d.log(ctx, "warn", store.CatSystem, "periodic maintenance: "+err.Error())
	}
	if res.DigestSent {
		d.log(ctx, "info", store.CatAlert, "periodic summary sent")
	}
}

func (d *Daemon) log(ctx context.Context, level, cat, msg string) {
	_ = d.store.Log(ctx, store.Event{TS: d.now(), Level: level, Category: cat, Message: msg})
}
