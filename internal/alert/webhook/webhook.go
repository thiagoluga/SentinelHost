// Package webhook delivers events as a signed JSON POST.
//
// Full contract: specs/001-orquestrador-mvp/contracts/webhooks.md.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// Headers of the contract.
const (
	HeaderEvent     = "X-Sentinel-Event"
	HeaderDelivery  = "X-Sentinel-Delivery"
	HeaderTimestamp = "X-Sentinel-Timestamp"
	HeaderSignature = "X-Sentinel-Signature"
)

// MaxAttempts is the total number of attempts (1 initial + 4 retries).
const MaxAttempts = 5

// RequestTimeout of each attempt.
const RequestTimeout = 10 * time.Second

// maxResponseBody caps what we read from the response. The body only helps the
// user diagnose; a hostile endpoint must not be able to fill our memory.
const maxResponseBody = 8 << 10

// Envelope is the body that gets delivered.
type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Event         string    `json:"event"`
	DeliveryID    string    `json:"delivery_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	Instance      Instance  `json:"instance"`
	Data          any       `json:"data"`
}

// Instance identifies where the delivery came from.
type Instance struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Root     string `json:"root"`
}

// Result is the outcome of one attempt.
type Result struct {
	OK         bool
	HTTPStatus int
	Body       string
	Err        error
	Duration   time.Duration
}

// Client delivers webhooks.
type Client struct {
	http *http.Client
}

// New creates the client.
func New() *Client {
	return &Client{http: &http.Client{Timeout: RequestTimeout}}
}

// Sign computes a delivery's signature.
//
// The timestamp enters the signature so a captured delivery cannot be replayed
// indefinitely. Without it, whoever intercepted a `quarantine.action` POST could
// repeat it forever and the signature would stay valid.
func Sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature in constant time.
//
// Exported because the project's own tests and any receiver implementation need
// the same logic — and because comparing a signature with `==` leaks timing and is
// the classic mistake in this kind of code.
func Verify(secret string, timestamp int64, body []byte, signature string) bool {
	expected := Sign(secret, timestamp, body)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// Deliver makes ONE delivery attempt.
//
// Retrying is the caller's responsibility (the dispatcher), which persists the
// state between attempts: a process killed by the hosting in the middle of a
// backoff must not lose the delivery.
func (c *Client) Deliver(ctx context.Context, w config.Webhook, env Envelope) (Result, []byte, error) {
	start := time.Now()

	body, err := json.Marshal(env)
	if err != nil {
		return Result{Err: err}, nil, fmt.Errorf("serializing the payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return Result{Err: err}, body, fmt.Errorf("building the request: %w", err)
	}

	ts := env.OccurredAt.Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SentinelHost/1.0")
	req.Header.Set(HeaderEvent, env.Event)
	req.Header.Set(HeaderDelivery, env.DeliveryID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	if w.Secret != "" {
		req.Header.Set(HeaderSignature, Sign(w.Secret, ts, body))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{Err: err, Duration: time.Since(start)}, body, nil
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	res := Result{
		HTTPStatus: resp.StatusCode,
		Body:       string(respBody),
		Duration:   time.Since(start),
		OK:         resp.StatusCode >= 200 && resp.StatusCode < 300,
	}
	if !res.OK {
		res.Err = fmt.Errorf("the endpoint answered %s", resp.Status)
	}
	return res, body, nil
}

// Backoff returns the interval before the next attempt.
//
// 1s, 4s, 16s, 64s, 256s — powers of 4. It grows fast on purpose: an endpoint that
// is down usually takes minutes to come back, and insisting once per second only
// produces traffic and log noise.
//
// It returns zero when the attempts have run out.
func Backoff(attempt int) time.Duration {
	if attempt < 1 || attempt >= MaxAttempts {
		return 0
	}
	d := time.Second
	for i := 1; i < attempt; i++ {
		d *= 4
	}
	return d
}
