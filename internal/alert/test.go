package alert

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert/email"
	"github.com/thiagoluga/SentinelHost/internal/alert/webhook"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// TestResult is the outcome of a test delivery.
//
// It carries the REAL error, never a generic message: finding out that the hosting
// blocks port 587 is the entire point of the test button (FR-012).
type TestResult struct {
	OK         bool
	Channel    string
	Target     string
	HTTPStatus int
	Body       string
	Duration   time.Duration
	Err        error
}

func (r TestResult) String() string {
	if r.OK {
		if r.HTTPStatus > 0 {
			return fmt.Sprintf("success: %s answered %d in %s", r.Target, r.HTTPStatus, r.Duration.Round(time.Millisecond))
		}
		return fmt.Sprintf("success: the delivery to %s completed in %s", r.Target, r.Duration.Round(time.Millisecond))
	}
	msg := "unknown error"
	if r.Err != nil {
		msg = r.Err.Error()
	}
	if r.HTTPStatus > 0 {
		return fmt.Sprintf("failure: %s answered %d — %s", r.Target, r.HTTPStatus, msg)
	}
	return fmt.Sprintf("failure: %s — %s", r.Target, msg)
}

// TestEmail sends a test e-mail.
func (d *Dispatcher) TestEmail(ctx context.Context) TestResult {
	start := d.now()
	res := TestResult{Channel: "email", Target: joinTo(d.cfg.Alerts.Email.To)}

	if !d.cfg.Alerts.Email.Enabled {
		res.Err = errors.New("e-mail is disabled in the configuration")
		return res
	}
	if err := d.mailer.Send(ctx, email.TestMessage()); err != nil {
		res.Err = err
		res.Duration = time.Since(start)
		return res
	}
	res.OK = true
	res.Duration = time.Since(start)
	return res
}

// TestWebhook sends a test delivery to a webhook.
//
// The delivery_id is prefixed with `d_test_` so the destination can tell a test
// from a real event without having to inspect the payload.
func (d *Dispatcher) TestWebhook(ctx context.Context, id string) TestResult {
	res := TestResult{Channel: "webhook", Target: id}

	w, ok := d.webhookByID(id)
	if !ok {
		res.Err = fmt.Errorf("webhook %q does not exist in the configuration", id)
		return res
	}

	env := d.envelope(EventConfirmed, sampleVerdict(d.now()))
	env.DeliveryID = "d_test_" + env.DeliveryID[2:]

	result, _, err := d.hooks.Deliver(ctx, w, env)
	res.Duration = result.Duration
	res.HTTPStatus = result.HTTPStatus
	res.Body = result.Body
	switch {
	case err != nil:
		res.Err = err
	case !result.OK:
		res.Err = result.Err
	default:
		res.OK = true
	}
	return res
}

// sampleVerdict is the test delivery's example payload.
//
// It points at a clearly fictitious path: if the user has any automation wired to
// the webhook, the test must not make it act on a file that really exists.
func sampleVerdict(now time.Time) schema.Verdict {
	return schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     "v_sample",
		FileSHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FilePath:      "/sample/does-not-exist/test-delivery.php",
		Level:         schema.LevelConfirmed,
		Score:         0.95,
		Votes: []schema.Vote{
			{Engine: "amwscan", Weight: 0.8, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 0.8, Rule: "TEST_SAMPLE", Category: schema.CategoryBackdoor},
			{Engine: "maldet", Weight: 1.0, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 1.0, Rule: "test.sample", Category: schema.CategoryBackdoor},
		},
		Abstentions: []string{"php-malware-finder"},
		ActionTaken: schema.ActionNone,
		ScanID:      "s_sample",
		CreatedAt:   now,
	}
}

// VerifyTestSignature checks a delivery's signature. Re-exported so the project's
// tests and the documentation use exactly the same logic as the real delivery.
func VerifyTestSignature(secret string, timestamp int64, body []byte, signature string) bool {
	return webhook.Verify(secret, timestamp, body, signature)
}
