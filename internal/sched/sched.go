// Package sched roda ciclos continuamente no modo daemon.
//
// O modo daemon e OPCIONAL por design: hospedagem compartilhada raramente
// mantem um processo vivo por horas, e o Principio III exige que tudo
// essencial funcione so com o cron do cPanel. O daemon e conforto para quem
// tem SSH, nunca requisito.
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

// Daemon executa ciclos no intervalo configurado.
type Daemon struct {
	cfg    *config.Config
	runner *cycle.Runner
	store  *store.Store
	alerts *alert.Dispatcher
	vault  *quarantine.Vault
	now    func() time.Time
	// OnCycle e chamado apos cada ciclo (usado pela CLI para imprimir).
	OnCycle func(cycle.Summary)
}

// New monta o daemon.
func New(cfg *config.Config, r *cycle.Runner, st *store.Store, d *alert.Dispatcher, v *quarantine.Vault) *Daemon {
	return &Daemon{cfg: cfg, runner: r, store: st, alerts: d, vault: v, now: time.Now}
}

// Run roda ate o contexto ser cancelado.
func (d *Daemon) Run(ctx context.Context) error {
	intervalo := d.cfg.Schedule.Incremental.Duration
	if intervalo <= 0 {
		intervalo = time.Hour
	}

	// Manutencao no arranque: fecha ciclos interrompidos por um kill anterior,
	// retoma entregas pendentes e aplica a retencao de disco.
	d.manutencao(ctx)

	// Primeiro ciclo imediato: quem sobe o daemon quer saber o estado agora,
	// nao daqui a uma hora.
	d.runOnce(ctx)

	t := time.NewTicker(intervalo)
	defer t.Stop()

	// O scan completo tem agenda propria e mais espacada; o daemon so checa
	// de tempos em tempos se ja passou da hora.
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
			d.manutencao(ctx)
		}
	}
}

// runOnce executa um ciclo incremental.
//
// Nenhum erro de ciclo derruba o daemon: um scan que falhou hoje nao pode
// impedir o scan de amanha. A falha e registrada e a vida continua.
func (d *Daemon) runOnce(ctx context.Context) {
	sum, err := d.runner.Run(ctx, cycle.Options{Mode: schema.ModeIncremental})
	switch {
	case errors.Is(err, lock.ErrLocked):
		// Outro processo (o cron, provavelmente) esta rodando. Normal.
		d.log(ctx, "info", store.CatScan, "ciclo pulado: "+err.Error())
		return
	case err != nil:
		d.log(ctx, "error", store.CatScan, "ciclo falhou: "+err.Error())
		return
	}
	if d.OnCycle != nil {
		d.OnCycle(sum)
	}
}

// maybeFull dispara o scan completo quando a agenda pede.
func (d *Daemon) maybeFull(ctx context.Context) {
	if d.cfg.Schedule.FullCron == "" {
		return
	}
	ultimo, err := d.store.LastScan(ctx)
	if err == nil && ultimo.Mode == schema.ModeFull && d.now().Sub(ultimo.StartedAt) < 20*time.Hour {
		return
	}
	agenda, err := ParseCron(d.cfg.Schedule.FullCron)
	if err != nil {
		d.log(ctx, "warn", store.CatSystem, "schedule.full_cron invalido: "+err.Error())
		return
	}
	if !agenda.Matches(d.now()) {
		return
	}

	sum, err := d.runner.Run(ctx, cycle.Options{Mode: schema.ModeFull})
	if err != nil {
		if !errors.Is(err, lock.ErrLocked) {
			d.log(ctx, "error", store.CatScan, "scan completo falhou: "+err.Error())
		}
		return
	}
	if d.OnCycle != nil {
		d.OnCycle(sum)
	}
}

// manutencao delega ao pacote housekeeping, o MESMO que o comando `scan` usa.
//
// Antes estas rotinas viviam so aqui, e o modo padrao do projeto e `cron` — o
// resultado era que retentativa de webhook, resumo periodico e retencao de
// disco nunca aconteciam para a maioria dos usuarios.
func (d *Daemon) manutencao(ctx context.Context) {
	res, err := housekeeping.Run(ctx, housekeeping.Deps{
		Cfg: d.cfg, Store: d.store, Vault: d.vault, Alerts: d.alerts, Now: d.now,
	})
	if err != nil {
		d.log(ctx, "warn", store.CatSystem, "manutencao periodica: "+err.Error())
	}
	if res.DigestSent {
		d.log(ctx, "info", store.CatAlert, "resumo periodico enviado")
	}
}

func (d *Daemon) log(ctx context.Context, level, cat, msg string) {
	_ = d.store.Log(ctx, store.Event{TS: d.now(), Level: level, Category: cat, Message: msg})
}
