// Package alert despacha eventos para os canais configurados.
//
// A regra que atravessa o pacote inteiro: falha de entrega NUNCA derruba um
// ciclo nem impede uma quarentena. Um webhook fora do ar e um problema de
// notificacao, e a protecao do site nao depende de notificacao.
package alert

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert/email"
	"github.com/thiagoluga/SentinelHost/internal/alert/webhook"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Eventos do contrato.
const (
	EventConfirmed  = "verdict.confirmed"
	EventLikely     = "verdict.likely"
	EventSuspicious = "verdict.suspicious"
	EventQuarantine = "quarantine.action"
	EventScan       = "scan.completed"
	EventEngine     = "engine.failed"
)

// Dispatcher entrega eventos aos canais habilitados.
type Dispatcher struct {
	cfg    *config.Config
	store  *store.Store
	hooks  *webhook.Client
	mailer *email.Sender
	now    func() time.Time
	// instanceID identifica esta instalacao nos payloads.
	instanceID string
}

// NewDispatcher monta o despachante.
func NewDispatcher(ctx context.Context, cfg *config.Config, st *store.Store) *Dispatcher {
	d := &Dispatcher{
		cfg:    cfg,
		store:  st,
		hooks:  webhook.New(),
		mailer: email.New(cfg.Alerts.Email),
		now:    time.Now,
	}
	d.instanceID = d.ensureInstanceID(ctx)
	return d
}

// WithClock troca o relogio. Uso restrito a testes.
func (d *Dispatcher) WithClock(fn func() time.Time) *Dispatcher {
	d.now = fn
	return d
}

// WithMailer troca o remetente. Uso restrito a testes.
func (d *Dispatcher) WithMailer(s *email.Sender) *Dispatcher {
	d.mailer = s
	return d
}

func (d *Dispatcher) ensureInstanceID(ctx context.Context) string {
	id, err := d.store.GetSetting(ctx, store.KeyInstanceID)
	if err == nil && id != "" {
		return id
	}
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "i_desconhecido"
	}
	id = "i_" + hex.EncodeToString(buf)
	_ = d.store.SetSetting(ctx, store.KeyInstanceID, id)
	return id
}

// Dispatch entrega um evento a todos os canais inscritos.
//
// Enfileira a entrega no banco ANTES de tentar enviar. Se o processo morrer no
// meio (a hospedagem mata processos longos), a entrega pendente e retomada no
// proximo ciclo em vez de perdida.
func (d *Dispatcher) Dispatch(ctx context.Context, event string, data any) error {
	var erros []error

	if err := d.dispatchWebhooks(ctx, event, data); err != nil {
		erros = append(erros, err)
	}
	if err := d.dispatchEmail(ctx, event, data); err != nil {
		erros = append(erros, err)
	}
	return errors.Join(erros...)
}

func (d *Dispatcher) dispatchWebhooks(ctx context.Context, event string, data any) error {
	var erros []error
	for _, w := range d.cfg.Alerts.Webhooks {
		if !w.Enabled || !subscribed(w, event) {
			continue
		}
		env := d.envelope(event, data)
		payload, err := json.Marshal(env)
		if err != nil {
			erros = append(erros, err)
			continue
		}
		del := store.Delivery{
			DeliveryID: env.DeliveryID, Channel: "webhook", Target: w.ID,
			Event: event, PayloadJSON: string(payload),
			Status: store.DeliveryPending, CreatedAt: d.now(),
		}
		if err := d.store.EnqueueDelivery(ctx, del); err != nil {
			erros = append(erros, err)
			continue
		}
		if err := d.attemptWebhook(ctx, w, env, 1); err != nil {
			erros = append(erros, err)
		}
	}
	return errors.Join(erros...)
}

// attemptWebhook faz uma tentativa e agenda a proxima em caso de falha.
func (d *Dispatcher) attemptWebhook(ctx context.Context, w config.Webhook, env webhook.Envelope, tentativa int) error {
	res, _, err := d.hooks.Deliver(ctx, w, env)
	if err != nil {
		_ = d.store.RecordAttempt(ctx, env.DeliveryID, false, 0, err.Error(), time.Time{})
		return err
	}

	if res.OK {
		return d.store.RecordAttempt(ctx, env.DeliveryID, true, res.HTTPStatus, "", time.Time{})
	}

	motivo := "sem resposta"
	if res.Err != nil {
		motivo = res.Err.Error()
	}
	proxima := time.Time{}
	if b := webhook.Backoff(tentativa); b > 0 {
		proxima = d.now().Add(b)
	}
	_ = d.store.RecordAttempt(ctx, env.DeliveryID, false, res.HTTPStatus, motivo, proxima)

	if proxima.IsZero() {
		return fmt.Errorf("webhook %s falhou definitivamente apos %d tentativas: %s", w.ID, tentativa, motivo)
	}
	// A retentativa fica pendente no banco. Quem a retoma e RetryPending, no
	// proximo ciclo — nao um goroutine que morre junto com o processo.
	return nil
}

// RetryPending retoma entregas pendentes.
//
// Chamado no inicio de cada ciclo. E o que faz o backoff sobreviver a um
// processo morto pela hospedagem.
func (d *Dispatcher) RetryPending(ctx context.Context) (int, error) {
	pendentes, err := d.store.PendingDeliveries(ctx, d.now(), 50)
	if err != nil {
		return 0, err
	}

	n := 0
	var erros []error
	for _, del := range pendentes {
		if del.Channel != "webhook" {
			continue
		}
		w, ok := d.webhookByID(del.Target)
		if !ok || !w.Enabled {
			// Webhook removido da configuracao: a entrega nao tem mais para
			// onde ir. Encerra em vez de tentar para sempre.
			_ = d.store.RecordAttempt(ctx, del.DeliveryID, false, 0,
				"webhook removido da configuracao", time.Time{})
			continue
		}
		var env webhook.Envelope
		if err := json.Unmarshal([]byte(del.PayloadJSON), &env); err != nil {
			_ = d.store.RecordAttempt(ctx, del.DeliveryID, false, 0,
				"payload da entrega corrompido: "+err.Error(), time.Time{})
			continue
		}
		if err := d.attemptWebhook(ctx, w, env, del.Attempts+1); err != nil {
			erros = append(erros, err)
		}
		n++
	}
	return n, errors.Join(erros...)
}

func (d *Dispatcher) webhookByID(id string) (config.Webhook, bool) {
	for _, w := range d.cfg.Alerts.Webhooks {
		if w.ID == id {
			return w, true
		}
	}
	return config.Webhook{}, false
}

func (d *Dispatcher) dispatchEmail(ctx context.Context, event string, data any) error {
	e := d.cfg.Alerts.Email
	if !e.Enabled {
		return nil
	}

	msg, ok := d.emailFor(event, data)
	if !ok {
		return nil
	}

	env := d.envelope(event, data)
	payload, _ := json.Marshal(msg)
	_ = d.store.EnqueueDelivery(ctx, store.Delivery{
		DeliveryID: env.DeliveryID, Channel: "email", Target: joinTo(e.To),
		Event: event, PayloadJSON: string(payload),
		Status: store.DeliveryPending, CreatedAt: d.now(),
	})

	if err := d.mailer.Send(ctx, msg); err != nil {
		_ = d.store.RecordAttempt(ctx, env.DeliveryID, false, 0, err.Error(), time.Time{})
		return fmt.Errorf("enviando e-mail de %s: %w", event, err)
	}
	return d.store.RecordAttempt(ctx, env.DeliveryID, true, 0, "", time.Time{})
}

// emailFor decide se este evento vira e-mail e monta a mensagem.
func (d *Dispatcher) emailFor(event string, data any) (email.Message, bool) {
	e := d.cfg.Alerts.Email

	switch event {
	case EventConfirmed, EventLikely, EventSuspicious:
		v, ok := data.(schema.Verdict)
		if !ok {
			return email.Message{}, false
		}
		if !levelSelected(e.Levels, v.Level) {
			return email.Message{}, false
		}
		recomendada := v.ActionTaken == schema.ActionRecommended
		return email.VerdictMessage(v, e.PanelURL, recomendada), true

	case EventEngine:
		rep, ok := data.(schema.ScanReport)
		if !ok {
			return email.Message{}, false
		}
		return email.EngineFailedMessage(rep.Engine, rep.Error, rep.ScanID), true
	}

	// scan.completed e quarantine.action nao viram e-mail imediato: iriam
	// entupir a caixa do usuario a cada hora e treina-lo a ignorar os alertas
	// que importam. Eles entram no digest.
	return email.Message{}, false
}

func levelSelected(levels []string, l schema.Level) bool {
	for _, s := range levels {
		if schema.Level(s) == l {
			return true
		}
	}
	return false
}

func (d *Dispatcher) envelope(event string, data any) webhook.Envelope {
	host, _ := os.Hostname()
	root := ""
	if len(d.cfg.General.Roots) > 0 {
		root = d.cfg.General.Roots[0]
	}
	return webhook.Envelope{
		SchemaVersion: schema.Version,
		Event:         event,
		DeliveryID:    newDeliveryID(d.now()),
		OccurredAt:    d.now(),
		Instance:      webhook.Instance{ID: d.instanceID, Hostname: host, Root: root},
		Data:          data,
	}
}

func subscribed(w config.Webhook, event string) bool {
	for _, e := range w.Events {
		if e == event {
			return true
		}
	}
	return false
}

func newDeliveryID(t time.Time) string {
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("d_%s_%s", t.UTC().Format("20060102150405"), hex.EncodeToString(buf))
}

func joinTo(to []string) string {
	if len(to) == 0 {
		return ""
	}
	out := to[0]
	for _, t := range to[1:] {
		out += "," + t
	}
	return out
}
