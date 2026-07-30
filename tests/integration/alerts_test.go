package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/alert/webhook"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// receiver records the deliveries it got and answers whatever the test tells it to.
type receiver struct {
	mu         sync.Mutex
	deliveries []delivery
	status     int
}

type delivery struct {
	event      string
	deliveryID string
	timestamp  string
	signature  string
	body       []byte
}

func (r *receiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(body)

		r.mu.Lock()
		r.deliveries = append(r.deliveries, delivery{
			event:      req.Header.Get(webhook.HeaderEvent),
			deliveryID: req.Header.Get(webhook.HeaderDelivery),
			timestamp:  req.Header.Get(webhook.HeaderTimestamp),
			signature:  req.Header.Get(webhook.HeaderSignature),
			body:       body,
		})
		status := r.status
		r.mu.Unlock()

		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	}
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.deliveries)
}

func (r *receiver) last() delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deliveries[len(r.deliveries)-1]
}

func setupAlerts(t *testing.T, url, secret string, events []string) (*alert.Dispatcher, *store.Store, *config.Config) {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Default()
	cfg.General.Roots = []string{"/home/user/public_html"}
	cfg.Alerts.Webhooks = []config.Webhook{{
		ID: "test", Enabled: true, URL: url, Secret: secret, Events: events,
	}}
	return alert.NewDispatcher(ctx, cfg, st), st, cfg
}

func sampleVerdict() schema.Verdict {
	return schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     "v_1",
		FileSHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FilePath:      "/home/user/public_html/x.php",
		Level:         schema.LevelConfirmed,
		Score:         0.95,
		Votes: []schema.Vote{
			{Engine: "maldet", Weight: 1.0, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 1.0, Rule: "php.x", Category: schema.CategoryBackdoor},
		},
		Abstentions:   []string{"php-malware-finder"},
		ActionTaken:   schema.ActionQuarantined,
		QuarantineRef: "q_1",
		ScanID:        "s_1",
		CreatedAt:     time.Now(),
	}
}

func TestTheWebhookDeliveryIsSigned(t *testing.T) {
	rec := &receiver{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	const secret = "t3st-s3cr3t"
	d, _, _ := setupAlerts(t, srv.URL, secret, []string{alert.EventConfirmed})

	if err := d.Dispatch(context.Background(), alert.EventConfirmed, sampleVerdict()); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("expected 1 delivery, got %d", rec.count())
	}

	e := rec.last()
	if e.event != alert.EventConfirmed {
		t.Errorf("event header: %q", e.event)
	}
	if e.deliveryID == "" {
		t.Error("delivery_id missing: the destination would have no way to be idempotent")
	}

	// The signature covers the timestamp + the body. Without the timestamp, a
	// captured delivery could be replayed forever with a valid signature.
	ts, err := strconv.ParseInt(e.timestamp, 10, 64)
	if err != nil {
		t.Fatalf("invalid timestamp: %q", e.timestamp)
	}
	if !webhook.Verify(secret, ts, e.body, e.signature) {
		t.Fatal("the signature does not check out")
	}
	// A signature with the wrong secret has to fail.
	if webhook.Verify("wrong-secret", ts, e.body, e.signature) {
		t.Fatal("the signature was accepted with the wrong secret")
	}
	// A signature with a different timestamp has to fail (replay protection).
	if webhook.Verify(secret, ts+1, e.body, e.signature) {
		t.Fatal("the signature survived swapping the timestamp: a replay would be possible")
	}
}

func TestTheWebhookPayloadFollowsTheContract(t *testing.T) {
	rec := &receiver{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, _, _ := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})
	if err := d.Dispatch(context.Background(), alert.EventConfirmed, sampleVerdict()); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	var env struct {
		SchemaVersion string          `json:"schema_version"`
		Event         string          `json:"event"`
		DeliveryID    string          `json:"delivery_id"`
		OccurredAt    time.Time       `json:"occurred_at"`
		Instance      map[string]any  `json:"instance"`
		Data          json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.last().body, &env); err != nil {
		t.Fatalf("the payload is not valid JSON: %v", err)
	}
	if env.SchemaVersion != schema.Version || env.Event != alert.EventConfirmed {
		t.Errorf("the envelope is off contract: %+v", env)
	}
	if env.Instance["id"] == "" {
		t.Error("instance.id is empty")
	}

	var v schema.Verdict
	if err := json.Unmarshal(env.Data, &v); err != nil {
		t.Fatalf("data is not a Verdict: %v", err)
	}
	// The votes and the abstentions travel with it: without them the destination
	// cannot explain anything to whoever receives the alert.
	if len(v.Votes) == 0 {
		t.Error("the votes did not come in the payload")
	}
	if len(v.Abstentions) == 0 {
		t.Error("the abstentions did not come in the payload")
	}
}

func TestTheWebhookOnlyReceivesSubscribedEvents(t *testing.T) {
	rec := &receiver{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	// Subscribed to verdict.confirmed only.
	d, _, _ := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})

	_ = d.Dispatch(context.Background(), alert.EventSuspicious, sampleVerdict())
	_ = d.Dispatch(context.Background(), alert.EventScan, map[string]any{"scan_id": "s_1"})
	if rec.count() != 0 {
		t.Fatalf("an unsubscribed event was delivered: %d delivery/ies", rec.count())
	}

	_ = d.Dispatch(context.Background(), alert.EventConfirmed, sampleVerdict())
	if rec.count() != 1 {
		t.Fatalf("the subscribed event was not delivered")
	}
}

func TestAFailureSchedulesARetryWithAStableID(t *testing.T) {
	rec := &receiver{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, st, _ := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})
	ctx := context.Background()

	// The first attempt fails; the delivery stays pending with a backoff.
	_ = d.Dispatch(ctx, alert.EventConfirmed, sampleVerdict())
	if rec.count() != 1 {
		t.Fatalf("expected 1 attempt, got %d", rec.count())
	}
	originalID := rec.last().deliveryID

	deliveries, err := st.ListDeliveries(ctx, "webhook", "test", 10)
	if err != nil {
		t.Fatalf("ListDeliveries: %v", err)
	}
	if len(deliveries) != 1 || deliveries[0].Status != store.DeliveryPending {
		t.Fatalf("the delivery should be pending: %+v", deliveries)
	}
	if deliveries[0].HTTPStatus != 500 {
		t.Errorf("the error's real status should be on record, got %d", deliveries[0].HTTPStatus)
	}

	// Now the endpoint comes back. The retry reuses the SAME delivery_id, which is
	// the idempotency key on the destination's side.
	rec.mu.Lock()
	rec.status = http.StatusOK
	rec.mu.Unlock()

	// Move the clock forward to clear the backoff.
	d.WithClock(func() time.Time { return time.Now().Add(time.Hour) })
	n, err := d.RetryPending(ctx)
	if err != nil {
		t.Fatalf("RetryPending: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 retry, got %d", n)
	}
	if rec.last().deliveryID != originalID {
		t.Errorf("the delivery_id changed between attempts: %q -> %q", originalID, rec.last().deliveryID)
	}

	deliveries, _ = st.ListDeliveries(ctx, "webhook", "test", 10)
	if deliveries[0].Status != store.DeliveryDelivered {
		t.Errorf("after the success the delivery should be delivered, got %q", deliveries[0].Status)
	}
	if deliveries[0].Attempts != 2 {
		t.Errorf("attempts: %d, expected 2", deliveries[0].Attempts)
	}
}

func TestTheBackoffGrowsAndRunsOutInFiveAttempts(t *testing.T) {
	expected := []time.Duration{time.Second, 4 * time.Second, 16 * time.Second, 64 * time.Second}
	for i, want := range expected {
		if got := webhook.Backoff(i + 1); got != want {
			t.Errorf("Backoff(%d) = %v, expected %v", i+1, got, want)
		}
	}
	// On the fifth attempt the chances have run out.
	if got := webhook.Backoff(webhook.MaxAttempts); got != 0 {
		t.Errorf("Backoff(%d) should be 0, got %v", webhook.MaxAttempts, got)
	}
}

func TestTheWebhookTestShowsTheRealError(t *testing.T) {
	// FR-012: the real result, not "failed to send". Finding out that the endpoint
	// answers 403 is the button's entire purpose.
	rec := &receiver{status: http.StatusForbidden}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, _, _ := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})
	res := d.TestWebhook(context.Background(), "test")

	if res.OK {
		t.Fatal("the test should have failed")
	}
	if res.HTTPStatus != http.StatusForbidden {
		t.Errorf("the real status was lost: %d", res.HTTPStatus)
	}
	if res.Err == nil {
		t.Fatal("the real error should be present")
	}
	// The test delivery is identifiable by the destination.
	if got := rec.last().deliveryID; len(got) < 7 || got[:7] != "d_test_" {
		t.Errorf("the test delivery_id should carry the d_test_ prefix, got %q", got)
	}
}

func TestTestingANonExistentWebhookFailsWithAClearMessage(t *testing.T) {
	d, _, _ := setupAlerts(t, "http://127.0.0.1:1", "s", []string{alert.EventConfirmed})
	res := d.TestWebhook(context.Background(), "does-not-exist")
	if res.OK {
		t.Fatal("a non-existent webhook must not succeed")
	}
	if res.Err == nil {
		t.Fatal("expected an error")
	}
}

func TestTheDeliveryIsPersistedBeforeItGoesOut(t *testing.T) {
	// If the process dies halfway (the hosting kills long processes), the pending
	// delivery has to be in the database to be resumed.
	rec := &receiver{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, st, _ := setupAlerts(t, srv.URL, "s", []string{alert.EventQuarantine})
	ctx := context.Background()

	_ = d.Dispatch(ctx, alert.EventQuarantine, map[string]any{"action": "quarantined", "quarantine_ref": "q_1"})

	pending, err := st.PendingDeliveries(ctx, time.Now().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("PendingDeliveries: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("the delivery should be persisted as pending, got %d", len(pending))
	}
	if pending[0].PayloadJSON == "" {
		t.Error("the payload should be persisted for the retry")
	}
}

func TestAWebhookRemovedFromTheConfigDoesNotKeepRetryingForever(t *testing.T) {
	rec := &receiver{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, st, cfg := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})
	ctx := context.Background()

	_ = d.Dispatch(ctx, alert.EventConfirmed, sampleVerdict())

	// The user removes the webhook from the configuration.
	cfg.Alerts.Webhooks = nil

	d.WithClock(func() time.Time { return time.Now().Add(time.Hour) })
	if _, err := d.RetryPending(ctx); err != nil {
		t.Fatalf("RetryPending: %v", err)
	}

	deliveries, _ := st.ListDeliveries(ctx, "webhook", "test", 10)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveries))
	}
	if deliveries[0].Status != store.DeliveryFailed {
		t.Errorf("the orphaned delivery should be closed out, got %q", deliveries[0].Status)
	}
}

// Chat destinations -------------------------------------------------------------

// TestASlackWebhookReceivesASlackShapedBody closes the gap US4 promised.
//
// Slack's incoming webhook does not accept an arbitrary payload, so until the
// format existed, "integrates with Slack" meant "posts something Slack rejects or
// renders empty". This runs the real dispatch path — envelope, formatter, HTTP —
// and inspects what actually arrived on the wire.
func TestASlackWebhookReceivesASlackShapedBody(t *testing.T) {
	rec := &receiver{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, _, cfg := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})
	cfg.Alerts.Webhooks[0].Format = config.FormatSlack

	if err := d.Dispatch(context.Background(), alert.EventConfirmed, sampleVerdict()); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("expected 1 delivery, got %d", rec.count())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.last().body, &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.last().body)
	}
	text, ok := body["text"].(string)
	if !ok || text == "" {
		t.Fatalf("Slack needs a non-empty `text`, got %v", body)
	}
	if _, leaked := body["schema_version"]; leaked {
		t.Error("the envelope leaked into the Slack body")
	}
	// The votes are why the alert is worth reading.
	if !strings.Contains(text, "maldet") {
		t.Errorf("the message does not carry the votes:\n%s", text)
	}
	// The headers still identify the delivery, so a receiver that does care can be
	// idempotent.
	if rec.last().deliveryID == "" {
		t.Error("the delivery id header is missing")
	}
}

func TestADiscordWebhookReceivesADiscordShapedBody(t *testing.T) {
	rec := &receiver{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, _, cfg := setupAlerts(t, srv.URL, "", []string{alert.EventConfirmed})
	cfg.Alerts.Webhooks[0].Format = config.FormatDiscord

	if err := d.Dispatch(context.Background(), alert.EventConfirmed, sampleVerdict()); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.last().body, &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.last().body)
	}
	content, ok := body["content"].(string)
	if !ok || content == "" {
		t.Fatalf("Discord needs a non-empty `content`, got %v", body)
	}
	if len([]rune(content)) > 2000 {
		t.Errorf("the content is over Discord's 2000-character limit: %d", len([]rune(content)))
	}
}

func TestARetryToSlackKeepsTheSlackShape(t *testing.T) {
	// The retry path rebuilds the envelope from the persisted payload. If the
	// formatter only handled the typed struct, every retry to Slack would arrive
	// degraded — and a retry is exactly the path nobody watches.
	rec := &receiver{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, _, cfg := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})
	cfg.Alerts.Webhooks[0].Format = config.FormatSlack
	ctx := context.Background()

	_ = d.Dispatch(ctx, alert.EventConfirmed, sampleVerdict())
	first := rec.last().body

	rec.mu.Lock()
	rec.status = http.StatusOK
	rec.mu.Unlock()

	d.WithClock(func() time.Time { return time.Now().Add(time.Hour) })
	if _, err := d.RetryPending(ctx); err != nil {
		t.Fatalf("RetryPending: %v", err)
	}
	if rec.count() != 2 {
		t.Fatalf("expected a second attempt, got %d delivery/ies", rec.count())
	}

	var firstBody, retryBody map[string]any
	_ = json.Unmarshal(first, &firstBody)
	if err := json.Unmarshal(rec.last().body, &retryBody); err != nil {
		t.Fatalf("the retry body is not JSON: %v\n%s", err, rec.last().body)
	}
	if retryBody["text"] == nil || retryBody["text"] == "" {
		t.Fatalf("the retry lost the Slack shape: %v", retryBody)
	}
	if firstBody["text"] != retryBody["text"] {
		t.Errorf("the retry rendered differently:\nfirst: %v\nretry: %v", firstBody["text"], retryBody["text"])
	}
}

func TestAnUnknownFormatFailsTheDeliveryInsteadOfSendingTheWrongShape(t *testing.T) {
	rec := &receiver{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, st, cfg := setupAlerts(t, srv.URL, "s", []string{alert.EventConfirmed})
	cfg.Alerts.Webhooks[0].Format = "teams"
	ctx := context.Background()

	if err := d.Dispatch(ctx, alert.EventConfirmed, sampleVerdict()); err == nil {
		t.Error("an unknown format should make the dispatch report an error")
	}
	if rec.count() != 0 {
		t.Errorf("nothing should have been posted, got %d delivery/ies", rec.count())
	}
	// And it has to be on record: a delivery that never left must not look like a
	// delivery that succeeded.
	deliveries, err := st.ListDeliveries(ctx, "webhook", "test", 10)
	if err != nil {
		t.Fatalf("ListDeliveries: %v", err)
	}
	if len(deliveries) != 1 || deliveries[0].Status == store.DeliveryDelivered {
		t.Errorf("the failed delivery was not recorded as such: %+v", deliveries)
	}
}

func TestAnAlertDoesNotHangWhenTheEndpointIsDown(t *testing.T) {
	// A webhook that is down is a notification problem, not a protection one.
	d, _, _ := setupAlerts(t, "http://127.0.0.1:1", "s", []string{alert.EventConfirmed})

	// Dispatch returns an error (for the caller to record), but it neither panics
	// nor blocks.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = d.Dispatch(context.Background(), alert.EventConfirmed, sampleVerdict())
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Dispatch hung with the endpoint down")
	}
}
