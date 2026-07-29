// Package alert dispatches events to the configured channels.
//
// The rule that runs through the whole package: a delivery failure NEVER takes a
// cycle down nor prevents a quarantine. A webhook that is down is a notification
// problem, and the site's protection does not depend on notification.
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

// Events of the contract.
const (
	EventConfirmed  = "verdict.confirmed"
	EventLikely     = "verdict.likely"
	EventSuspicious = "verdict.suspicious"
	EventQuarantine = "quarantine.action"
	EventScan       = "scan.completed"
	EventEngine     = "engine.failed"
)

// Dispatcher delivers events to the enabled channels.
type Dispatcher struct {
	cfg    *config.Config
	store  *store.Store
	hooks  *webhook.Client
	mailer *email.Sender
	now    func() time.Time
	// instanceID identifies this installation in the payloads.
	instanceID string
}

// NewDispatcher assembles the dispatcher.
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

// WithClock swaps the clock. Tests only.
func (d *Dispatcher) WithClock(fn func() time.Time) *Dispatcher {
	d.now = fn
	return d
}

// WithMailer swaps the sender. Tests only.
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
		return "i_unknown"
	}
	id = "i_" + hex.EncodeToString(buf)
	_ = d.store.SetSetting(ctx, store.KeyInstanceID, id)
	return id
}

// Dispatch delivers an event to every subscribed channel.
//
// It queues the delivery in the database BEFORE trying to send. If the process
// dies halfway (the hosting kills long processes), the pending delivery is resumed
// in the next cycle instead of being lost.
func (d *Dispatcher) Dispatch(ctx context.Context, event string, data any) error {
	var failures []error

	if err := d.dispatchWebhooks(ctx, event, data); err != nil {
		failures = append(failures, err)
	}
	if err := d.dispatchEmail(ctx, event, data); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (d *Dispatcher) dispatchWebhooks(ctx context.Context, event string, data any) error {
	var failures []error
	for _, w := range d.cfg.Alerts.Webhooks {
		if !w.Enabled || !subscribed(w, event) {
			continue
		}
		env := d.envelope(event, data)
		payload, err := json.Marshal(env)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		del := store.Delivery{
			DeliveryID: env.DeliveryID, Channel: "webhook", Target: w.ID,
			Event: event, PayloadJSON: string(payload),
			Status: store.DeliveryPending, CreatedAt: d.now(),
		}
		if err := d.store.EnqueueDelivery(ctx, del); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := d.attemptWebhook(ctx, w, env, 1); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// attemptWebhook makes one attempt and schedules the next on failure.
func (d *Dispatcher) attemptWebhook(ctx context.Context, w config.Webhook, env webhook.Envelope, attempt int) error {
	res, _, err := d.hooks.Deliver(ctx, w, env)
	if err != nil {
		_ = d.store.RecordAttempt(ctx, env.DeliveryID, false, 0, err.Error(), time.Time{})
		return err
	}

	if res.OK {
		return d.store.RecordAttempt(ctx, env.DeliveryID, true, res.HTTPStatus, "", time.Time{})
	}

	reason := "no response"
	if res.Err != nil {
		reason = res.Err.Error()
	}
	next := time.Time{}
	if b := webhook.Backoff(attempt); b > 0 {
		next = d.now().Add(b)
	}
	_ = d.store.RecordAttempt(ctx, env.DeliveryID, false, res.HTTPStatus, reason, next)

	if next.IsZero() {
		return fmt.Errorf("webhook %s failed for good after %d attempts: %s", w.ID, attempt, reason)
	}
	// The retry stays pending in the database. What resumes it is RetryPending, in
	// the next cycle — not a goroutine that dies along with the process.
	return nil
}

// RetryPending resumes pending deliveries.
//
// Called at the start of every cycle. It is what makes the backoff survive a
// process killed by the hosting.
func (d *Dispatcher) RetryPending(ctx context.Context) (int, error) {
	pending, err := d.store.PendingDeliveries(ctx, d.now(), 50)
	if err != nil {
		return 0, err
	}

	n := 0
	var failures []error
	for _, del := range pending {
		if del.Channel != "webhook" {
			continue
		}
		w, ok := d.webhookByID(del.Target)
		if !ok || !w.Enabled {
			// The webhook was removed from the configuration: the delivery has
			// nowhere left to go. Close it out instead of trying forever.
			_ = d.store.RecordAttempt(ctx, del.DeliveryID, false, 0,
				"the webhook was removed from the configuration", time.Time{})
			continue
		}
		var env webhook.Envelope
		if err := json.Unmarshal([]byte(del.PayloadJSON), &env); err != nil {
			_ = d.store.RecordAttempt(ctx, del.DeliveryID, false, 0,
				"the delivery payload is corrupted: "+err.Error(), time.Time{})
			continue
		}
		if err := d.attemptWebhook(ctx, w, env, del.Attempts+1); err != nil {
			failures = append(failures, err)
		}
		n++
	}
	return n, errors.Join(failures...)
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
		return fmt.Errorf("sending the %s e-mail: %w", event, err)
	}
	return d.store.RecordAttempt(ctx, env.DeliveryID, true, 0, "", time.Time{})
}

// emailFor decides whether this event becomes an e-mail and builds the message.
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
		recommended := v.ActionTaken == schema.ActionRecommended
		return email.VerdictMessage(v, e.PanelURL, recommended), true

	case EventEngine:
		rep, ok := data.(schema.ScanReport)
		if !ok {
			return email.Message{}, false
		}
		return email.EngineFailedMessage(rep.Engine, rep.Error, rep.ScanID), true
	}

	// scan.completed and quarantine.action do not become an immediate e-mail: they
	// would clog the user's inbox every hour and train them to ignore the alerts
	// that matter. They go into the digest.
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
