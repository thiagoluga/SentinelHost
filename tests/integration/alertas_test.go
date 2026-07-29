package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/alert/webhook"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// receptor grava as entregas recebidas e responde o que o teste mandar.
type receptor struct {
	mu       sync.Mutex
	entregas []entrega
	status   int
}

type entrega struct {
	evento     string
	deliveryID string
	timestamp  string
	assinatura string
	corpo      []byte
}

func (r *receptor) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		corpo := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(corpo)

		r.mu.Lock()
		r.entregas = append(r.entregas, entrega{
			evento:     req.Header.Get(webhook.HeaderEvent),
			deliveryID: req.Header.Get(webhook.HeaderDelivery),
			timestamp:  req.Header.Get(webhook.HeaderTimestamp),
			assinatura: req.Header.Get(webhook.HeaderSignature),
			corpo:      corpo,
		})
		status := r.status
		r.mu.Unlock()

		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	}
}

func (r *receptor) contar() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entregas)
}

func (r *receptor) ultima() entrega {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entregas[len(r.entregas)-1]
}

func montarAlertas(t *testing.T, url, segredo string, eventos []string) (*alert.Dispatcher, *store.Store, *config.Config) {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "estado.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Default()
	cfg.General.Roots = []string{"/home/user/public_html"}
	cfg.Alerts.Webhooks = []config.Webhook{{
		ID: "teste", Enabled: true, URL: url, Secret: segredo, Events: eventos,
	}}
	return alert.NewDispatcher(ctx, cfg, st), st, cfg
}

func verditoExemplo() schema.Verdict {
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

func TestWebhookEntregaAssinada(t *testing.T) {
	rec := &receptor{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	const segredo = "s3gr3d0-de-teste"
	d, _, _ := montarAlertas(t, srv.URL, segredo, []string{alert.EventConfirmed})

	if err := d.Dispatch(context.Background(), alert.EventConfirmed, verditoExemplo()); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if rec.contar() != 1 {
		t.Fatalf("esperava 1 entrega, veio %d", rec.contar())
	}

	e := rec.ultima()
	if e.evento != alert.EventConfirmed {
		t.Errorf("cabecalho de evento: %q", e.evento)
	}
	if e.deliveryID == "" {
		t.Error("delivery_id ausente: o destino nao teria como fazer idempotencia")
	}

	// A assinatura cobre timestamp + corpo. Sem o timestamp, uma entrega
	// capturada poderia ser reenviada para sempre com assinatura valida.
	ts, err := strconv.ParseInt(e.timestamp, 10, 64)
	if err != nil {
		t.Fatalf("timestamp invalido: %q", e.timestamp)
	}
	if !webhook.Verify(segredo, ts, e.corpo, e.assinatura) {
		t.Fatal("a assinatura nao confere")
	}
	// Assinatura com segredo errado tem que falhar.
	if webhook.Verify("segredo-errado", ts, e.corpo, e.assinatura) {
		t.Fatal("a assinatura foi aceita com o segredo errado")
	}
	// Assinatura com timestamp diferente tem que falhar (protecao de replay).
	if webhook.Verify(segredo, ts+1, e.corpo, e.assinatura) {
		t.Fatal("a assinatura sobreviveu a troca do timestamp: replay seria possivel")
	}
}

func TestWebhookPayloadSegueOContrato(t *testing.T) {
	rec := &receptor{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, _, _ := montarAlertas(t, srv.URL, "s", []string{alert.EventConfirmed})
	if err := d.Dispatch(context.Background(), alert.EventConfirmed, verditoExemplo()); err != nil {
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
	if err := json.Unmarshal(rec.ultima().corpo, &env); err != nil {
		t.Fatalf("payload nao e JSON valido: %v", err)
	}
	if env.SchemaVersion != schema.Version || env.Event != alert.EventConfirmed {
		t.Errorf("envelope fora do contrato: %+v", env)
	}
	if env.Instance["id"] == "" {
		t.Error("instance.id vazio")
	}

	var v schema.Verdict
	if err := json.Unmarshal(env.Data, &v); err != nil {
		t.Fatalf("data nao e um Verdict: %v", err)
	}
	// Os votos e as abstencoes viajam junto: sem eles o destino nao consegue
	// explicar nada a quem recebe o alerta.
	if len(v.Votes) == 0 {
		t.Error("os votos nao vieram no payload")
	}
	if len(v.Abstentions) == 0 {
		t.Error("as abstencoes nao vieram no payload")
	}
}

func TestWebhookSoRecebeEventosAssinados(t *testing.T) {
	rec := &receptor{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	// Inscrito apenas em verdict.confirmed.
	d, _, _ := montarAlertas(t, srv.URL, "s", []string{alert.EventConfirmed})

	_ = d.Dispatch(context.Background(), alert.EventSuspicious, verditoExemplo())
	_ = d.Dispatch(context.Background(), alert.EventScan, map[string]any{"scan_id": "s_1"})
	if rec.contar() != 0 {
		t.Fatalf("evento nao assinado foi entregue: %d entrega(s)", rec.contar())
	}

	_ = d.Dispatch(context.Background(), alert.EventConfirmed, verditoExemplo())
	if rec.contar() != 1 {
		t.Fatalf("evento assinado nao foi entregue")
	}
}

func TestWebhookFalhaAgendaRetentativaComIDEstavel(t *testing.T) {
	rec := &receptor{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, st, _ := montarAlertas(t, srv.URL, "s", []string{alert.EventConfirmed})
	ctx := context.Background()

	// A primeira tentativa falha; a entrega fica pendente com backoff.
	_ = d.Dispatch(ctx, alert.EventConfirmed, verditoExemplo())
	if rec.contar() != 1 {
		t.Fatalf("esperava 1 tentativa, veio %d", rec.contar())
	}
	idOriginal := rec.ultima().deliveryID

	entregas, err := st.ListDeliveries(ctx, "webhook", "teste", 10)
	if err != nil {
		t.Fatalf("ListDeliveries: %v", err)
	}
	if len(entregas) != 1 || entregas[0].Status != store.DeliveryPending {
		t.Fatalf("a entrega deveria estar pendente: %+v", entregas)
	}
	if entregas[0].HTTPStatus != 500 {
		t.Errorf("o status real do erro deveria ficar registrado, veio %d", entregas[0].HTTPStatus)
	}

	// Agora o endpoint volta. A retentativa reusa o MESMO delivery_id, que e
	// a chave de idempotencia do lado do destino.
	rec.mu.Lock()
	rec.status = http.StatusOK
	rec.mu.Unlock()

	// Adianta o relogio para vencer o backoff.
	d.WithClock(func() time.Time { return time.Now().Add(time.Hour) })
	n, err := d.RetryPending(ctx)
	if err != nil {
		t.Fatalf("RetryPending: %v", err)
	}
	if n != 1 {
		t.Fatalf("esperava 1 retentativa, veio %d", n)
	}
	if rec.ultima().deliveryID != idOriginal {
		t.Errorf("o delivery_id mudou entre tentativas: %q -> %q", idOriginal, rec.ultima().deliveryID)
	}

	entregas, _ = st.ListDeliveries(ctx, "webhook", "teste", 10)
	if entregas[0].Status != store.DeliveryDelivered {
		t.Errorf("apos o sucesso a entrega deveria estar delivered, veio %q", entregas[0].Status)
	}
	if entregas[0].Attempts != 2 {
		t.Errorf("tentativas: %d, esperado 2", entregas[0].Attempts)
	}
}

func TestBackoffCresceEAcabaEmCincoTentativas(t *testing.T) {
	esperado := []time.Duration{time.Second, 4 * time.Second, 16 * time.Second, 64 * time.Second}
	for i, want := range esperado {
		if got := webhook.Backoff(i + 1); got != want {
			t.Errorf("Backoff(%d) = %v, esperado %v", i+1, got, want)
		}
	}
	// Na quinta tentativa acabaram as chances.
	if got := webhook.Backoff(webhook.MaxAttempts); got != 0 {
		t.Errorf("Backoff(%d) deveria ser 0, veio %v", webhook.MaxAttempts, got)
	}
}

func TestTesteDeWebhookMostraOErroReal(t *testing.T) {
	// FR-012: o resultado real, nao "falha ao enviar". Descobrir que o
	// endpoint responde 403 e o proposito inteiro do botao.
	rec := &receptor{status: http.StatusForbidden}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, _, _ := montarAlertas(t, srv.URL, "s", []string{alert.EventConfirmed})
	res := d.TestWebhook(context.Background(), "teste")

	if res.OK {
		t.Fatal("o teste deveria ter falhado")
	}
	if res.HTTPStatus != http.StatusForbidden {
		t.Errorf("status real perdido: %d", res.HTTPStatus)
	}
	if res.Err == nil {
		t.Fatal("o erro real deveria estar presente")
	}
	// O delivery de teste e identificavel pelo destino.
	if got := rec.ultima().deliveryID; len(got) < 7 || got[:7] != "d_test_" {
		t.Errorf("o delivery_id de teste deveria ter prefixo d_test_, veio %q", got)
	}
}

func TestTesteDeWebhookInexistenteFalhaComMensagemClara(t *testing.T) {
	d, _, _ := montarAlertas(t, "http://127.0.0.1:1", "s", []string{alert.EventConfirmed})
	res := d.TestWebhook(context.Background(), "nao-existe")
	if res.OK {
		t.Fatal("webhook inexistente nao pode dar sucesso")
	}
	if res.Err == nil {
		t.Fatal("esperava erro")
	}
}

func TestEntregaEPersistidaAntesDeSair(t *testing.T) {
	// Se o processo morrer no meio (a hospedagem mata processos longos), a
	// entrega pendente precisa estar no banco para ser retomada.
	rec := &receptor{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, st, _ := montarAlertas(t, srv.URL, "s", []string{alert.EventQuarantine})
	ctx := context.Background()

	_ = d.Dispatch(ctx, alert.EventQuarantine, map[string]any{"action": "quarantined", "quarantine_ref": "q_1"})

	pendentes, err := st.PendingDeliveries(ctx, time.Now().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("PendingDeliveries: %v", err)
	}
	if len(pendentes) != 1 {
		t.Fatalf("a entrega deveria estar persistida como pendente, veio %d", len(pendentes))
	}
	if pendentes[0].PayloadJSON == "" {
		t.Error("o payload deveria estar persistido para a retentativa")
	}
}

func TestWebhookRemovidoDaConfigNaoFicaTentandoParaSempre(t *testing.T) {
	rec := &receptor{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	d, st, cfg := montarAlertas(t, srv.URL, "s", []string{alert.EventConfirmed})
	ctx := context.Background()

	_ = d.Dispatch(ctx, alert.EventConfirmed, verditoExemplo())

	// O usuario remove o webhook da configuracao.
	cfg.Alerts.Webhooks = nil

	d.WithClock(func() time.Time { return time.Now().Add(time.Hour) })
	if _, err := d.RetryPending(ctx); err != nil {
		t.Fatalf("RetryPending: %v", err)
	}

	entregas, _ := st.ListDeliveries(ctx, "webhook", "teste", 10)
	if len(entregas) != 1 {
		t.Fatalf("esperava 1 entrega, veio %d", len(entregas))
	}
	if entregas[0].Status != store.DeliveryFailed {
		t.Errorf("a entrega orfa deveria ser encerrada, veio %q", entregas[0].Status)
	}
}

func TestAlertaNaoDerrubaQuandoOEndpointEstaFora(t *testing.T) {
	// Um webhook fora do ar e problema de notificacao, nao de protecao.
	d, _, _ := montarAlertas(t, "http://127.0.0.1:1", "s", []string{alert.EventConfirmed})

	// Dispatch devolve erro (para o chamador registrar), mas nao entra em
	// panico nem bloqueia.
	feito := make(chan struct{})
	go func() {
		defer close(feito)
		_ = d.Dispatch(context.Background(), alert.EventConfirmed, verditoExemplo())
	}()
	select {
	case <-feito:
	case <-time.After(30 * time.Second):
		t.Fatal("o Dispatch travou com o endpoint fora do ar")
	}
}
