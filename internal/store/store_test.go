package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func openTemp(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAplicaMigracoes(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 1 {
		t.Fatalf("esperava esquema migrado, veio versao %d", v)
	}
}

func TestOpenEIdempotente(t *testing.T) {
	// Reabrir o banco a cada execucao do cron nao pode reaplicar migracao.
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	s1, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("primeira abertura: %v", err)
	}
	v1, _ := s1.SchemaVersion(ctx)
	_ = s1.Close()

	s2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("segunda abertura: %v", err)
	}
	defer func() { _ = s2.Close() }()
	v2, _ := s2.SchemaVersion(ctx)

	if v1 != v2 {
		t.Errorf("versao mudou ao reabrir: %d -> %d", v1, v2)
	}
}

func verdictExemplo(id string, level schema.Level, score float64) schema.Verdict {
	return schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     id,
		FileSHA256:    sha,
		FilePath:      "/home/user/public_html/cache.php",
		FileSize:      1024,
		Level:         level,
		Score:         score,
		Votes: []schema.Vote{
			{Engine: "amwscan", Weight: 0.8, Confidence: schema.ConfidenceSignature, EffectiveWeight: 0.8, Rule: "eval_backdoor", Category: schema.CategoryBackdoor},
			{Engine: "php-malware-finder", Weight: 0.8, Confidence: schema.ConfidenceHeuristic, EffectiveWeight: 0.64, Rule: "ObfuscatedPhp", Category: schema.CategoryObfuscation},
		},
		Abstentions: []string{"maldet"},
		ActionTaken: schema.ActionNone,
		ScanID:      "s_1",
		CreatedAt:   time.Now(),
	}
}

func TestVerdictRoundTripPreservaVotosEAbstencoes(t *testing.T) {
	// Os votos SAO o veredito: sem eles o usuario nao consegue responder
	// "por que este arquivo foi quarentenado?" (Principio V).
	ctx := context.Background()
	s := openTemp(t)

	orig := verdictExemplo("v_1", schema.LevelConfirmed, 0.92)
	if err := s.SaveVerdict(ctx, orig); err != nil {
		t.Fatalf("SaveVerdict: %v", err)
	}

	back, err := s.GetVerdict(ctx, "v_1")
	if err != nil {
		t.Fatalf("GetVerdict: %v", err)
	}
	if len(back.Votes) != 2 {
		t.Fatalf("esperava 2 votos, veio %d", len(back.Votes))
	}
	if back.Votes[0].Engine != "amwscan" || back.Votes[0].EffectiveWeight != 0.8 {
		t.Errorf("voto corrompido: %+v", back.Votes[0])
	}
	if back.Votes[1].Rule != "ObfuscatedPhp" {
		t.Errorf("regra perdida: %+v", back.Votes[1])
	}
	if len(back.Abstentions) != 1 || back.Abstentions[0] != "maldet" {
		t.Errorf("abstencoes perdidas: %v", back.Abstentions)
	}
	if back.Level != schema.LevelConfirmed || back.Score != 0.92 {
		t.Errorf("nivel/score perdidos: %s %v", back.Level, back.Score)
	}
}

func TestSaveVerdictRecusaVereditoInvalido(t *testing.T) {
	// Persistir um veredito quebrado espalharia o defeito para o painel, os
	// alertas e o webhook.
	ctx := context.Background()
	s := openTemp(t)

	v := verdictExemplo("v_bad", schema.LevelConfirmed, 0.92)
	v.ActionTaken = schema.ActionQuarantined // sem quarantine_ref

	if err := s.SaveVerdict(ctx, v); err == nil {
		t.Fatal("veredito quarentenado sem referencia deveria ser recusado")
	}
}

func TestSaveVerdictAtualizaEmVezDeDuplicar(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	v := verdictExemplo("v_1", schema.LevelLikely, 0.7)
	if err := s.SaveVerdict(ctx, v); err != nil {
		t.Fatalf("primeiro save: %v", err)
	}
	v.Level = schema.LevelConfirmed
	v.Score = 0.95
	if err := s.SaveVerdict(ctx, v); err != nil {
		t.Fatalf("segundo save: %v", err)
	}

	all, err := s.ListVerdicts(ctx, store.VerdictFilter{})
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("esperava 1 veredito, veio %d", len(all))
	}
	if all[0].Level != schema.LevelConfirmed {
		t.Errorf("atualizacao nao pegou: %s", all[0].Level)
	}
}

func TestListVerdictsEscondeCleanPorPadrao(t *testing.T) {
	// Mostrar milhares de arquivos limpos esconderia os 3 que importam.
	ctx := context.Background()
	s := openTemp(t)

	_ = s.SaveVerdict(ctx, verdictExemplo("v_clean", schema.LevelClean, 0.0))
	_ = s.SaveVerdict(ctx, verdictExemplo("v_conf", schema.LevelConfirmed, 0.95))

	semClean, err := s.ListVerdicts(ctx, store.VerdictFilter{})
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(semClean) != 1 || semClean[0].VerdictID != "v_conf" {
		t.Errorf("esperava so o confirmed, veio %d itens", len(semClean))
	}

	comClean, err := s.ListVerdicts(ctx, store.VerdictFilter{IncludeClean: true})
	if err != nil {
		t.Fatalf("ListVerdicts(IncludeClean): %v", err)
	}
	if len(comClean) != 2 {
		t.Errorf("esperava 2 itens com clean, veio %d", len(comClean))
	}
}

func TestUpdateVerdictActionEAcknowledge(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	_ = s.SaveVerdict(ctx, verdictExemplo("v_1", schema.LevelConfirmed, 0.95))

	if err := s.UpdateVerdictAction(ctx, "v_1", schema.ActionQuarantined, "q_1", ""); err != nil {
		t.Fatalf("UpdateVerdictAction: %v", err)
	}
	v, _ := s.GetVerdict(ctx, "v_1")
	if v.ActionTaken != schema.ActionQuarantined || v.QuarantineRef != "q_1" {
		t.Errorf("acao nao registrada: %+v", v)
	}
	if v.ActionAt.IsZero() {
		t.Error("action_at deveria ter sido preenchido")
	}

	if err := s.AcknowledgeVerdict(ctx, "v_1"); err != nil {
		t.Fatalf("AcknowledgeVerdict: %v", err)
	}
	v, _ = s.GetVerdict(ctx, "v_1")
	if !v.AcknowledgedByUser {
		t.Error("veredito deveria estar marcado como decidido")
	}
}

func TestUpdateDeVereditoInexistenteEErro(t *testing.T) {
	// Um UPDATE que nao acha a linha e sucesso para o SQL e falha para o
	// usuario: a acao que ele mandou registrar nao ficou registrada.
	ctx := context.Background()
	s := openTemp(t)

	err := s.UpdateVerdictAction(ctx, "nao-existe", schema.ActionQuarantined, "q_1", "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("esperava ErrNotFound, veio %v", err)
	}
}

// Quarentena -----------------------------------------------------------------

func itemExemplo(ref string, retencao time.Time) store.QuarantineItem {
	return store.QuarantineItem{
		Ref:            ref,
		VerdictID:      "v_1",
		OriginalPath:   "/home/user/public_html/cache.php",
		VaultPath:      "/home/user/.sentinelhost/quarantine/" + ref + ".quarantined",
		SHA256:         sha,
		SizeBytes:      1024,
		Perms:          "0644",
		Owner:          "user",
		QuarantinedAt:  time.Now(),
		RetentionUntil: retencao,
	}
}

func TestQuarentenaRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	it := itemExemplo("q_1", time.Now().Add(30*24*time.Hour))
	if err := s.InsertQuarantineItem(ctx, it); err != nil {
		t.Fatalf("InsertQuarantineItem: %v", err)
	}

	back, err := s.GetQuarantineItem(ctx, "q_1")
	if err != nil {
		t.Fatalf("GetQuarantineItem: %v", err)
	}
	// Estes campos sao exatamente o que torna a acao reversivel.
	if back.OriginalPath != it.OriginalPath || back.VaultPath != it.VaultPath ||
		back.SHA256 != it.SHA256 || back.Perms != it.Perms {
		t.Errorf("metadados de restauracao perdidos: %+v", back)
	}
	if back.Status != store.QuarantineActive {
		t.Errorf("status inicial deveria ser quarantined, veio %q", back.Status)
	}
}

func TestQuarentenaSemMetadadosERecusada(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	it := itemExemplo("q_1", time.Now())
	it.VaultPath = ""
	if err := s.InsertQuarantineItem(ctx, it); err == nil {
		t.Fatal("item sem vault_path nao e restauravel e deveria ser recusado")
	}
}

func TestPurgaRecusaItemDentroDaRetencao(t *testing.T) {
	// Principio I no nivel do banco: nem uma chamada errada em outro pacote
	// consegue apagar item ainda dentro do prazo.
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, itemExemplo("q_1", time.Now().Add(30*24*time.Hour)))

	err := s.MarkPurged(ctx, "q_1", time.Now())
	if err == nil {
		t.Fatal("purga dentro da retencao deveria ser recusada")
	}
	if !strings.Contains(err.Error(), "retencao") {
		t.Errorf("o erro deveria explicar o motivo, veio: %v", err)
	}

	it, _ := s.GetQuarantineItem(ctx, "q_1")
	if it.Status != store.QuarantineActive {
		t.Errorf("item deveria continuar ativo, veio %q", it.Status)
	}
}

func TestPurgaAceitaItemExpirado(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, itemExemplo("q_1", time.Now().Add(-time.Hour)))

	if err := s.MarkPurged(ctx, "q_1", time.Now()); err != nil {
		t.Fatalf("MarkPurged: %v", err)
	}
	it, _ := s.GetQuarantineItem(ctx, "q_1")
	if it.Status != store.QuarantinePurged {
		t.Errorf("esperava purged, veio %q", it.Status)
	}
}

func TestForcePurgeIgnoraRetencao(t *testing.T) {
	// A constituicao permite purga definitiva por acao manual do usuario.
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, itemExemplo("q_1", time.Now().Add(30*24*time.Hour)))
	if err := s.ForcePurge(ctx, "q_1"); err != nil {
		t.Fatalf("ForcePurge: %v", err)
	}
	it, _ := s.GetQuarantineItem(ctx, "q_1")
	if it.Status != store.QuarantinePurged {
		t.Errorf("esperava purged, veio %q", it.Status)
	}
}

func TestExpiredItemsIgnoraRestaurados(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, itemExemplo("q_ativo", time.Now().Add(-time.Hour)))
	_ = s.InsertQuarantineItem(ctx, itemExemplo("q_restaurado", time.Now().Add(-time.Hour)))
	if err := s.MarkRestored(ctx, "q_restaurado", "/home/user/public_html/cache.php"); err != nil {
		t.Fatalf("MarkRestored: %v", err)
	}

	exp, err := s.ExpiredItems(ctx, time.Now())
	if err != nil {
		t.Fatalf("ExpiredItems: %v", err)
	}
	if len(exp) != 1 || exp[0].Ref != "q_ativo" {
		t.Errorf("item restaurado nao pode reaparecer como candidato a purga: %+v", exp)
	}
}

func TestRestaurarDuasVezesFalha(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, itemExemplo("q_1", time.Now().Add(time.Hour)))
	if err := s.MarkRestored(ctx, "q_1", "/x"); err != nil {
		t.Fatalf("primeira restauracao: %v", err)
	}
	if err := s.MarkRestored(ctx, "q_1", "/x"); err == nil {
		t.Fatal("restaurar item ja restaurado deveria falhar")
	}
}

// Relatorios, entregas e log --------------------------------------------------

func TestRelatorioDeFalhaEArquivado(t *testing.T) {
	// A degradacao silenciosa de cobertura e o modo de falha mais perigoso de
	// um orquestrador: o relatorio de falha tem que sobreviver ao ciclo.
	ctx := context.Background()
	s := openTemp(t)

	if err := s.StartScan(ctx, store.ScanRecord{
		ScanID: "s_1", Mode: schema.ModeIncremental,
		Roots: []string{"/home/user/public_html"}, StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	falha := schema.FailedReport("s_1", "maldet", schema.StatusTimeout,
		errors.New("timeout apos 300s"), time.Now())
	if err := s.SaveScanReport(ctx, falha); err != nil {
		t.Fatalf("SaveScanReport: %v", err)
	}

	reports, err := s.ListScanReports(ctx, "s_1")
	if err != nil {
		t.Fatalf("ListScanReports: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("esperava 1 relatorio, veio %d", len(reports))
	}
	if reports[0].Status != schema.StatusTimeout || reports[0].Error == "" {
		t.Errorf("motivo da falha perdido: %+v", reports[0])
	}
	if !reports[0].Abstains() {
		t.Error("relatorio de timeout deveria contar como abstencao")
	}
}

func TestEntregaMantemIDEntreTentativas(t *testing.T) {
	// O delivery_id e a chave de idempotencia do lado do destino (contrato de
	// webhooks): ele nao pode mudar a cada retentativa.
	ctx := context.Background()
	s := openTemp(t)

	d := store.Delivery{
		DeliveryID: "d_1", Channel: "webhook", Target: "slack",
		Event: "verdict.confirmed", PayloadJSON: `{"x":1}`,
		CreatedAt: time.Now(),
	}
	if err := s.EnqueueDelivery(ctx, d); err != nil {
		t.Fatalf("EnqueueDelivery: %v", err)
	}

	prox := time.Now().Add(time.Second)
	if err := s.RecordAttempt(ctx, "d_1", false, 500, "erro do servidor", prox); err != nil {
		t.Fatalf("RecordAttempt 1: %v", err)
	}
	got, _ := s.GetDelivery(ctx, "d_1")
	if got.Attempts != 1 || got.Status != store.DeliveryPending {
		t.Errorf("apos falha com retentativa agendada: %+v", got)
	}

	if err := s.RecordAttempt(ctx, "d_1", true, 200, "", time.Time{}); err != nil {
		t.Fatalf("RecordAttempt 2: %v", err)
	}
	got, _ = s.GetDelivery(ctx, "d_1")
	if got.Status != store.DeliveryDelivered || got.Attempts != 2 {
		t.Errorf("apos sucesso: %+v", got)
	}
	if got.DeliveredAt.IsZero() {
		t.Error("delivered_at deveria ter sido preenchido")
	}
}

func TestEntregaSemProximaTentativaVireFailed(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.EnqueueDelivery(ctx, store.Delivery{
		DeliveryID: "d_1", Channel: "webhook", Target: "slack",
		Event: "scan.completed", PayloadJSON: "{}", CreatedAt: time.Now(),
	})
	if err := s.RecordAttempt(ctx, "d_1", false, 0, "conexao recusada", time.Time{}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	got, _ := s.GetDelivery(ctx, "d_1")
	if got.Status != store.DeliveryFailed {
		t.Errorf("esperava failed, veio %q", got.Status)
	}
	if got.Error == "" {
		t.Error("o erro real deveria ficar registrado para aparecer no painel")
	}
}

func TestPendingDeliveriesRespeitaBackoff(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.EnqueueDelivery(ctx, store.Delivery{
		DeliveryID: "d_futuro", Channel: "webhook", Target: "x", Event: "scan.completed",
		PayloadJSON: "{}", CreatedAt: time.Now(), NextAttemptAt: time.Now().Add(time.Hour),
	})
	_ = s.EnqueueDelivery(ctx, store.Delivery{
		DeliveryID: "d_agora", Channel: "webhook", Target: "x", Event: "scan.completed",
		PayloadJSON: "{}", CreatedAt: time.Now(), NextAttemptAt: time.Now().Add(-time.Minute),
	})

	pend, err := s.PendingDeliveries(ctx, time.Now(), 0)
	if err != nil {
		t.Fatalf("PendingDeliveries: %v", err)
	}
	if len(pend) != 1 || pend[0].DeliveryID != "d_agora" {
		t.Errorf("backoff nao respeitado: %+v", pend)
	}
}

func TestLogEstruturadoEConsultavel(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.Log(ctx, store.Event{
		Level: "warn", Category: store.CatQuarantine,
		Message: "arquivo quarentenado",
		Fields:  map[string]any{"ref": "q_1", "score": 0.95},
		ScanID:  "s_1",
	})
	_ = s.Log(ctx, store.Event{Level: "info", Category: store.CatScan, Message: "ciclo iniciado"})

	todos, err := s.ListEvents(ctx, store.EventFilter{})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(todos) != 2 {
		t.Fatalf("esperava 2 eventos, veio %d", len(todos))
	}

	quarentena, err := s.ListEvents(ctx, store.EventFilter{Category: store.CatQuarantine})
	if err != nil {
		t.Fatalf("ListEvents(filtro): %v", err)
	}
	if len(quarentena) != 1 {
		t.Fatalf("filtro por categoria falhou: %d", len(quarentena))
	}
	if quarentena[0].Fields["ref"] != "q_1" {
		t.Errorf("campos estruturados perdidos: %v", quarentena[0].Fields)
	}
}

func TestSettingAusenteNaoEErro(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	v, err := s.GetSetting(ctx, store.KeyPanelPasswordHash)
	if err != nil {
		t.Fatalf("chave ausente nao deveria ser erro: %v", err)
	}
	if v != "" {
		t.Errorf("esperava vazio, veio %q", v)
	}

	if err := s.SetSetting(ctx, store.KeyPanelPasswordHash, "argon2id$..."); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	v, _ = s.GetSetting(ctx, store.KeyPanelPasswordHash)
	if v != "argon2id$..." {
		t.Errorf("valor perdido: %q", v)
	}
}

func TestSessaoExpiradaNaoEValida(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	if err := s.CreateSession(ctx, "tok-valido", time.Now().Add(time.Hour), "ua", "127.0.0.1"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.CreateSession(ctx, "tok-vencido", time.Now().Add(-time.Hour), "ua", "127.0.0.1"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	ok, err := s.SessionValid(ctx, "tok-valido")
	if err != nil || !ok {
		t.Errorf("sessao valida foi recusada: ok=%v err=%v", ok, err)
	}
	ok, _ = s.SessionValid(ctx, "tok-vencido")
	if ok {
		t.Error("sessao vencida foi aceita")
	}
	ok, _ = s.SessionValid(ctx, "tok-inexistente")
	if ok {
		t.Error("token inexistente foi aceito")
	}
}

func TestEngineStatePreservaDataDeAssinaturas(t *testing.T) {
	// Um probe que nao conseguiu ler a versao das assinaturas nao pode apagar
	// a data que ja era conhecida.
	ctx := context.Background()
	s := openTemp(t)

	sig := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := s.SaveEngineState(ctx, store.EngineState{
		Slug: "amwscan", Available: true, Version: "0.10.4",
		SignaturesUpdatedAt: sig, LastProbeAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveEngineState: %v", err)
	}
	if err := s.SaveEngineState(ctx, store.EngineState{
		Slug: "amwscan", Available: false, UnavailableReason: "PHP CLI ausente",
		LastProbeAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveEngineState 2: %v", err)
	}

	states, err := s.ListEngineStates(ctx)
	if err != nil {
		t.Fatalf("ListEngineStates: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("esperava 1 engine, veio %d", len(states))
	}
	if states[0].Available {
		t.Error("disponibilidade deveria ter sido atualizada para false")
	}
	if states[0].UnavailableReason == "" {
		t.Error("motivo da indisponibilidade e obrigatorio para o painel (FR-001)")
	}
	if states[0].SignaturesUpdatedAt.IsZero() {
		t.Error("a data de assinaturas conhecida nao pode ser apagada por um probe que falhou")
	}
}

func TestCountByLevel(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.SaveVerdict(ctx, verdictExemplo("v_1", schema.LevelConfirmed, 0.95))
	_ = s.SaveVerdict(ctx, verdictExemplo("v_2", schema.LevelSuspicious, 0.4))
	_ = s.SaveVerdict(ctx, verdictExemplo("v_3", schema.LevelSuspicious, 0.35))

	counts, err := s.CountByLevel(ctx, "")
	if err != nil {
		t.Fatalf("CountByLevel: %v", err)
	}
	if counts[schema.LevelConfirmed] != 1 || counts[schema.LevelSuspicious] != 2 {
		t.Errorf("contagem errada: %v", counts)
	}
}
