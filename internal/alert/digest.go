package alert

import (
	"context"
	"fmt"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert/email"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// SendDigestIfDue envia o resumo periodico quando o horario configurado
// chegou e ainda nao houve envio no periodo.
//
// O estado do digest e lido do SQLite na hora, sem nada acumulado em memoria:
// perder o processo (a hospedagem mata processos longos) nao pode perder o
// resumo do dia. Devolve true se enviou.
func (d *Dispatcher) SendDigestIfDue(ctx context.Context) (bool, error) {
	e := d.cfg.Alerts.Email
	if !e.Enabled || !e.DigestEnabled {
		return false, nil
	}

	agora := d.now()
	horario, err := parseHoraDoDia(e.DigestAt)
	if err != nil {
		return false, fmt.Errorf("alerts.email.digest_at invalido: %w", err)
	}

	ultimo, err := d.lastDigestAt(ctx)
	if err != nil {
		return false, err
	}

	// A janela do digest fecha no horario configurado de hoje. Se ainda nao
	// deu a hora, ou se ja mandamos depois dela, nao ha o que fazer.
	fecha := time.Date(agora.Year(), agora.Month(), agora.Day(),
		horario.hora, horario.minuto, 0, 0, agora.Location())
	if agora.Before(fecha) {
		return false, nil
	}
	if !ultimo.IsZero() && !ultimo.Before(fecha) {
		return false, nil
	}

	inicio := fecha.AddDate(0, 0, -1)
	if !ultimo.IsZero() && ultimo.After(inicio) {
		inicio = ultimo
	}

	enviado, err := d.sendDigest(ctx, inicio, agora)
	if err != nil {
		return false, err
	}
	if enviado {
		if err := d.store.SetSetting(ctx, store.KeyLastDigestAt, agora.UTC().Format(time.RFC3339)); err != nil {
			return true, err
		}
	}
	return enviado, nil
}

// SendDigestNow envia o resumo do periodo pedido, ignorando o agendamento.
// Usado pelo botao do painel e pela CLI.
func (d *Dispatcher) SendDigestNow(ctx context.Context, desde time.Time) error {
	_, err := d.sendDigest(ctx, desde, d.now())
	return err
}

func (d *Dispatcher) sendDigest(ctx context.Context, inicio, fim time.Time) (bool, error) {
	vs, err := d.store.ListVerdicts(ctx, store.VerdictFilter{IncludeClean: true, Limit: 2000})
	if err != nil {
		return false, err
	}

	contagem := map[schema.Level]int{}
	acoes := map[schema.ActionTaken]int{}
	var pendentes []schema.Verdict
	relevantes := 0

	for _, v := range vs {
		if v.CreatedAt.Before(inicio) || v.CreatedAt.After(fim) {
			continue
		}
		contagem[v.Level]++
		acoes[v.ActionTaken]++
		if v.Level != schema.LevelClean {
			relevantes++
		}
		if !v.AcknowledgedByUser && v.Level.AtLeast(schema.LevelSuspicious) &&
			(v.ActionTaken == schema.ActionNone || v.ActionTaken == schema.ActionRecommended) {
			pendentes = append(pendentes, v)
		}
	}

	// O digest sai mesmo sem incidente critico, desde que haja suspeitas
	// acumuladas (cenario 2 da US4). Um resumo vazio todo dia treinaria o
	// usuario a nao abrir o e-mail.
	if relevantes == 0 {
		return false, nil
	}

	msg := email.DigestMessage(inicio, fim, contagem, acoes, pendentes, d.cfg.Alerts.Email.PanelURL)
	if err := d.mailer.Send(ctx, msg); err != nil {
		return false, fmt.Errorf("enviando digest: %w", err)
	}
	return true, nil
}

func (d *Dispatcher) lastDigestAt(ctx context.Context) (time.Time, error) {
	s, err := d.store.GetSetting(ctx, store.KeyLastDigestAt)
	if err != nil {
		return time.Time{}, err
	}
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

type horaDoDia struct{ hora, minuto int }

func parseHoraDoDia(s string) (horaDoDia, error) {
	if s == "" {
		s = "08:00"
	}
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return horaDoDia{}, fmt.Errorf("use o formato HH:MM, veio %q", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return horaDoDia{}, fmt.Errorf("horario fora do intervalo: %q", s)
	}
	return horaDoDia{h, m}, nil
}
