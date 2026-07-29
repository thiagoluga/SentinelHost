package housekeeping_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/housekeeping"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

type ambiente struct {
	cfg   *config.Config
	store *store.Store
}

func montar(t *testing.T) ambiente {
	t.Helper()
	base := t.TempDir()

	cfg := config.Default()
	cfg.General.Roots = []string{filepath.Join(base, "site")}
	cfg.General.DataDir = filepath.Join(base, "dados")
	if err := cfg.EnsureDataDirs(); err != nil {
		t.Fatalf("EnsureDataDirs: %v", err)
	}

	st, err := store.Open(context.Background(), cfg.DatabasePath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	return ambiente{cfg: cfg, store: st}
}

// Retenção de log -------------------------------------------------------------

func TestPodaLogAlemDaRetencao(t *testing.T) {
	// Sem esta poda a tabela de eventos cresce para sempre. Numa conta com
	// cota, isso enche o disco e derruba o site — a ferramenta causando
	// exatamente o dano que o Principio IV existe para evitar.
	env := montar(t)
	ctx := context.Background()
	env.cfg.Logging.RetentionDays = 30

	antigo := time.Now().AddDate(0, 0, -60)
	recente := time.Now().AddDate(0, 0, -1)
	for i := 0; i < 5; i++ {
		_ = env.store.Log(ctx, store.Event{TS: antigo, Level: "info", Category: store.CatScan, Message: "velho"})
	}
	for i := 0; i < 3; i++ {
		_ = env.store.Log(ctx, store.Event{TS: recente, Level: "info", Category: store.CatScan, Message: "novo"})
	}

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: env.cfg, Store: env.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PrunedEvents != 5 {
		t.Errorf("esperava 5 eventos podados, veio %d", res.PrunedEvents)
	}

	restantes, err := env.store.ListEvents(ctx, store.EventFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, e := range restantes {
		if e.Message == "velho" {
			t.Error("evento alem da retencao sobreviveu")
		}
	}
}

func TestRetencaoZeroNaoPodaNada(t *testing.T) {
	// Retencao 0 significa "guarde tudo", nunca "apague tudo".
	env := montar(t)
	ctx := context.Background()
	env.cfg.Logging.RetentionDays = 0

	_ = env.store.Log(ctx, store.Event{
		TS: time.Now().AddDate(-5, 0, 0), Level: "info",
		Category: store.CatScan, Message: "muito velho",
	})

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: env.cfg, Store: env.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PrunedEvents != 0 {
		t.Errorf("com retencao 0 nada deveria ser podado, veio %d", res.PrunedEvents)
	}
}

// Retenção da saída bruta -------------------------------------------------------

func TestPodaSaidaBrutaAlemDaRetencao(t *testing.T) {
	// A saida bruta e o que mais cresce: cada ciclo grava o stdout completo de
	// cada engine.
	env := montar(t)
	ctx := context.Background()
	env.cfg.Logging.RawOutputRetentionDays = 14

	raiz := env.cfg.RawOutputDir()
	velho := filepath.Join(raiz, "s_20260101_000000")
	novo := filepath.Join(raiz, "s_20260729_000000")
	for _, d := range []string{velho, novo} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(d, "amwscan.stdout"), []byte("saida"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	antigo := time.Now().AddDate(0, 0, -60)
	if err := os.Chtimes(velho, antigo, antigo); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: env.cfg, Store: env.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PrunedRawDirs != 1 {
		t.Fatalf("esperava 1 diretorio removido, veio %d", res.PrunedRawDirs)
	}
	if _, err := os.Stat(velho); !os.IsNotExist(err) {
		t.Error("o diretorio antigo deveria ter sido removido")
	}
	if _, err := os.Stat(novo); err != nil {
		t.Error("o diretorio recente NAO deveria ter sido removido")
	}
}

func TestPodaSaidaBrutaIgnoraArquivosSoltos(t *testing.T) {
	// A poda remove diretorios de ciclo inteiros. Um arquivo solto na raiz de
	// raw/ nao e um ciclo e nao deve ser tocado.
	env := montar(t)
	ctx := context.Background()
	env.cfg.Logging.RawOutputRetentionDays = 1

	solto := filepath.Join(env.cfg.RawOutputDir(), "LEIA-ME.txt")
	if err := os.WriteFile(solto, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	antigo := time.Now().AddDate(0, 0, -60)
	_ = os.Chtimes(solto, antigo, antigo)

	if _, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: env.cfg, Store: env.store}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(solto); err != nil {
		t.Error("arquivo solto foi removido pela poda de diretorios")
	}
}

// Ciclos interrompidos ----------------------------------------------------------

func TestCicloInterrompidoEFechadoComoKilled(t *testing.T) {
	// A hospedagem mata processos longos. Um ciclo que fica `running` para
	// sempre faz o historico mentir por omissao sobre a cobertura daquele
	// periodo.
	env := montar(t)
	ctx := context.Background()

	if err := env.store.StartScan(ctx, store.ScanRecord{
		ScanID: "s_morto", Mode: schema.ModeIncremental,
		Roots: []string{"/site"}, StartedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: env.cfg, Store: env.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RecoveredScans != 1 {
		t.Fatalf("esperava 1 ciclo recuperado, veio %d", res.RecoveredScans)
	}

	pendentes, err := env.store.InterruptedScans(ctx)
	if err != nil {
		t.Fatalf("InterruptedScans: %v", err)
	}
	if len(pendentes) != 0 {
		t.Errorf("o ciclo deveria ter sido fechado, restam %v", pendentes)
	}

	ultimo, err := env.store.LastScan(ctx)
	if err != nil {
		t.Fatalf("LastScan: %v", err)
	}
	if ultimo.Status != schema.StatusKilled {
		t.Errorf("o ciclo deveria constar como killed, veio %q", ultimo.Status)
	}
}

// Alertas -----------------------------------------------------------------------

type alerterFalso struct {
	retentativas int
	digest       bool
	erro         error
}

func (a *alerterFalso) RetryPending(context.Context) (int, error) {
	return a.retentativas, a.erro
}

func (a *alerterFalso) SendDigestIfDue(context.Context) (bool, error) {
	return a.digest, nil
}

func TestManutencaoRetomaEntregasEEnviaDigest(t *testing.T) {
	env := montar(t)
	al := &alerterFalso{retentativas: 3, digest: true}

	res, err := housekeeping.Run(context.Background(), housekeeping.Deps{
		Cfg: env.cfg, Store: env.store, Alerts: al,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RetriedDeliveries != 3 {
		t.Errorf("retentativas: %d", res.RetriedDeliveries)
	}
	if !res.DigestSent {
		t.Error("o resumo periodico deveria ter sido enviado")
	}
}

func TestFalhaDeAlertaNaoImpedeAPodaDeDisco(t *testing.T) {
	// Se o webhook esta fora do ar, a limpeza de disco ainda precisa
	// acontecer: uma coisa e notificacao, a outra e a conta do usuario nao
	// estourar a cota.
	env := montar(t)
	ctx := context.Background()
	env.cfg.Logging.RetentionDays = 1

	_ = env.store.Log(ctx, store.Event{
		TS: time.Now().AddDate(0, 0, -30), Level: "info",
		Category: store.CatScan, Message: "velho",
	})

	al := &alerterFalso{erro: errFalso{}}
	res, err := housekeeping.Run(ctx, housekeeping.Deps{
		Cfg: env.cfg, Store: env.store, Alerts: al,
	})

	if err == nil {
		t.Error("a falha do alerta deveria ser reportada ao chamador")
	}
	if res.PrunedEvents == 0 {
		t.Error("a poda de log nao aconteceu por causa da falha do alerta")
	}
}

func TestManutencaoSemNadaAFazerEVazia(t *testing.T) {
	env := montar(t)
	res, err := housekeeping.Run(context.Background(), housekeeping.Deps{
		Cfg: env.cfg, Store: env.store,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Empty() {
		t.Errorf("esperava resultado vazio, veio %+v", res)
	}
}

type errFalso struct{}

func (errFalso) Error() string { return "endpoint fora do ar" }
