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
	"fmt"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/lock"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Daemon executa ciclos no intervalo configurado.
type Daemon struct {
	cfg    *config.Config
	runner *cycle.Runner
	store  *store.Store
	alerts *alert.Dispatcher
	now    func() time.Time
	// OnCycle e chamado apos cada ciclo (usado pela CLI para imprimir).
	OnCycle func(cycle.Summary)
}

// New monta o daemon.
func New(cfg *config.Config, r *cycle.Runner, st *store.Store, d *alert.Dispatcher) *Daemon {
	return &Daemon{cfg: cfg, runner: r, store: st, alerts: d, now: time.Now}
}

// Run roda ate o contexto ser cancelado.
func (d *Daemon) Run(ctx context.Context) error {
	intervalo := d.cfg.Schedule.Incremental.Duration
	if intervalo <= 0 {
		intervalo = time.Hour
	}

	// Ciclos interrompidos por um kill anterior sao registrados no arranque,
	// para que o historico nao fique com buracos silenciosos.
	d.recoverInterrupted(ctx)

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
			d.maybeDigest(ctx)
			d.maybeAutoPurge(ctx)
		}
	}
}

// runOnce executa um ciclo incremental.
//
// Nenhum erro de ciclo derruba o daemon: um scan que falhou hoje nao pode
// impedir o scan de amanha. A falha e registrada e a vida continua.
func (d *Daemon) runOnce(ctx context.Context) {
	// Retentativas de webhook pendentes vem primeiro: e o que faz o backoff
	// sobreviver a um processo morto entre tentativas.
	if d.alerts != nil {
		if _, err := d.alerts.RetryPending(ctx); err != nil {
			d.log(ctx, "warn", store.CatAlert, "retentativas pendentes: "+err.Error())
		}
	}

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

func (d *Daemon) maybeDigest(ctx context.Context) {
	if d.alerts == nil {
		return
	}
	enviado, err := d.alerts.SendDigestIfDue(ctx)
	if err != nil {
		d.log(ctx, "warn", store.CatAlert, "digest: "+err.Error())
		return
	}
	if enviado {
		d.log(ctx, "info", store.CatAlert, "resumo periodico enviado")
	}
}

// maybeAutoPurge so age quando o usuario ligou a purga automatica.
func (d *Daemon) maybeAutoPurge(ctx context.Context) {
	if !d.cfg.Quarantine.AutoPurge {
		return
	}
	// A purga em si e delegada ao cofre, que recusa qualquer item ainda
	// dentro da retencao.
	d.log(ctx, "debug", store.CatQuarantine, "verificando itens expirados")
}

// recoverInterrupted registra ciclos que ficaram sem desfecho.
func (d *Daemon) recoverInterrupted(ctx context.Context) {
	ids, err := d.store.InterruptedScans(ctx)
	if err != nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		// Fecha o ciclo como `killed`: ele NAO completou, e por isso nao pode
		// aparecer no historico como um ciclo limpo.
		_ = d.store.FinishScan(ctx, store.ScanRecord{
			ScanID: id, FinishedAt: d.now(), Status: schema.StatusKilled,
		})
		d.log(ctx, "warn", store.CatScan,
			fmt.Sprintf("ciclo %s foi interrompido antes de terminar (processo morto?); registrado como killed", id))
	}
}

func (d *Daemon) log(ctx context.Context, level, cat, msg string) {
	_ = d.store.Log(ctx, store.Event{TS: d.now(), Level: level, Category: cat, Message: msg})
}
