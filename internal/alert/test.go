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

// TestResult e o desfecho de uma entrega de teste.
//
// Carrega o erro REAL, nunca uma mensagem generica: descobrir que a hospedagem
// bloqueia a porta 587 e o objetivo inteiro do botao de teste (FR-012).
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
			return fmt.Sprintf("sucesso: %s respondeu %d em %s", r.Target, r.HTTPStatus, r.Duration.Round(time.Millisecond))
		}
		return fmt.Sprintf("sucesso: entrega para %s concluida em %s", r.Target, r.Duration.Round(time.Millisecond))
	}
	msg := "erro desconhecido"
	if r.Err != nil {
		msg = r.Err.Error()
	}
	if r.HTTPStatus > 0 {
		return fmt.Sprintf("falha: %s respondeu %d — %s", r.Target, r.HTTPStatus, msg)
	}
	return fmt.Sprintf("falha: %s — %s", r.Target, msg)
}

// TestEmail envia um e-mail de teste.
func (d *Dispatcher) TestEmail(ctx context.Context) TestResult {
	inicio := d.now()
	res := TestResult{Channel: "email", Target: joinTo(d.cfg.Alerts.Email.To)}

	if !d.cfg.Alerts.Email.Enabled {
		res.Err = errors.New("o e-mail esta desabilitado na configuracao")
		return res
	}
	if err := d.mailer.Send(ctx, email.TestMessage()); err != nil {
		res.Err = err
		res.Duration = time.Since(inicio)
		return res
	}
	res.OK = true
	res.Duration = time.Since(inicio)
	return res
}

// TestWebhook envia uma entrega de teste a um webhook.
//
// O delivery_id vem prefixado com `d_test_` para que o destino consiga
// distinguir teste de evento real sem precisar inspecionar o payload.
func (d *Dispatcher) TestWebhook(ctx context.Context, id string) TestResult {
	res := TestResult{Channel: "webhook", Target: id}

	w, ok := d.webhookByID(id)
	if !ok {
		res.Err = fmt.Errorf("webhook %q nao existe na configuracao", id)
		return res
	}

	env := d.envelope(EventConfirmed, exemploVerdict(d.now()))
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

// exemploVerdict e o payload de exemplo da entrega de teste.
//
// Aponta para um caminho claramente ficticio: se o usuario tiver alguma
// automacao ligada ao webhook, o teste nao pode fazer ela agir sobre um
// arquivo que existe de verdade.
func exemploVerdict(agora time.Time) schema.Verdict {
	return schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     "v_exemplo",
		FileSHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FilePath:      "/exemplo/nao-existe/entrega-de-teste.php",
		Level:         schema.LevelConfirmed,
		Score:         0.95,
		Votes: []schema.Vote{
			{Engine: "amwscan", Weight: 0.8, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 0.8, Rule: "EXEMPLO_DE_TESTE", Category: schema.CategoryBackdoor},
			{Engine: "maldet", Weight: 1.0, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 1.0, Rule: "exemplo.de.teste", Category: schema.CategoryBackdoor},
		},
		Abstentions: []string{"php-malware-finder"},
		ActionTaken: schema.ActionNone,
		ScanID:      "s_exemplo",
		CreatedAt:   agora,
	}
}

// VerifyTestSignature confere a assinatura de uma entrega. Reexportada para
// que o teste do projeto e a documentacao usem exatamente a mesma logica que a
// entrega real.
func VerifyTestSignature(secret string, timestamp int64, body []byte, signature string) bool {
	return webhook.Verify(secret, timestamp, body, signature)
}
