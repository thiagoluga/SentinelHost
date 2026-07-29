// Package webhook entrega eventos como POST JSON assinado.
//
// Contrato completo: specs/001-orquestrador-mvp/contracts/webhooks.md.
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

// Cabecalhos do contrato.
const (
	HeaderEvent     = "X-Sentinel-Event"
	HeaderDelivery  = "X-Sentinel-Delivery"
	HeaderTimestamp = "X-Sentinel-Timestamp"
	HeaderSignature = "X-Sentinel-Signature"
)

// MaxAttempts e o numero total de tentativas (1 inicial + 4 retentativas).
const MaxAttempts = 5

// RequestTimeout de cada tentativa.
const RequestTimeout = 10 * time.Second

// maxResponseBody limita o que lemos da resposta. O corpo so serve para o
// usuario diagnosticar; um endpoint hostil nao pode encher nossa memoria.
const maxResponseBody = 8 << 10

// Envelope e o corpo entregue.
type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Event         string    `json:"event"`
	DeliveryID    string    `json:"delivery_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	Instance      Instance  `json:"instance"`
	Data          any       `json:"data"`
}

// Instance identifica de onde veio a entrega.
type Instance struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Root     string `json:"root"`
}

// Result e o desfecho de uma tentativa.
type Result struct {
	OK         bool
	HTTPStatus int
	Body       string
	Err        error
	Duration   time.Duration
}

// Client entrega webhooks.
type Client struct {
	http *http.Client
}

// New cria o cliente.
func New() *Client {
	return &Client{http: &http.Client{Timeout: RequestTimeout}}
}

// Sign calcula a assinatura de uma entrega.
//
// O timestamp entra na assinatura para que uma entrega capturada nao possa ser
// reenviada indefinidamente. Sem ele, quem interceptasse um POST de
// `quarantine.action` poderia repeti-lo para sempre, e a assinatura continuaria
// valida.
func Sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify confere uma assinatura em tempo constante.
//
// Exportada porque o teste do proprio projeto e qualquer implementacao de
// receptor precisam da mesma logica — e porque comparar assinatura com `==`
// vaza tempo e e o erro classico deste tipo de codigo.
func Verify(secret string, timestamp int64, body []byte, signature string) bool {
	esperado := Sign(secret, timestamp, body)
	return hmac.Equal([]byte(esperado), []byte(signature))
}

// Deliver faz UMA tentativa de entrega.
//
// A retentativa e responsabilidade do chamador (o despachante), que persiste o
// estado entre tentativas: um processo morto pela hospedagem no meio de um
// backoff nao pode perder a entrega.
func (c *Client) Deliver(ctx context.Context, w config.Webhook, env Envelope) (Result, []byte, error) {
	inicio := time.Now()

	body, err := json.Marshal(env)
	if err != nil {
		return Result{Err: err}, nil, fmt.Errorf("serializando payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return Result{Err: err}, body, fmt.Errorf("montando requisicao: %w", err)
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
		return Result{Err: err, Duration: time.Since(inicio)}, body, nil
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	res := Result{
		HTTPStatus: resp.StatusCode,
		Body:       string(respBody),
		Duration:   time.Since(inicio),
		OK:         resp.StatusCode >= 200 && resp.StatusCode < 300,
	}
	if !res.OK {
		res.Err = fmt.Errorf("o endpoint respondeu %s", resp.Status)
	}
	return res, body, nil
}

// Backoff devolve o intervalo antes da proxima tentativa.
//
// 1s, 4s, 16s, 64s, 256s — potencias de 4. Cresce rapido de proposito: um
// endpoint fora do ar costuma demorar minutos para voltar, e insistir de
// segundo em segundo so gera trafego e log.
//
// Devolve zero quando as tentativas acabaram.
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
