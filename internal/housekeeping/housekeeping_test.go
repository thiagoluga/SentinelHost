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

type env struct {
	cfg   *config.Config
	store *store.Store
}

func setup(t *testing.T) env {
	t.Helper()
	base := t.TempDir()

	cfg := config.Default()
	cfg.General.Roots = []string{filepath.Join(base, "site")}
	cfg.General.DataDir = filepath.Join(base, "data")
	if err := cfg.EnsureDataDirs(); err != nil {
		t.Fatalf("EnsureDataDirs: %v", err)
	}

	st, err := store.Open(context.Background(), cfg.DatabasePath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	return env{cfg: cfg, store: st}
}

// Log retention ----------------------------------------------------------------

func TestItPrunesTheLogBeyondTheRetention(t *testing.T) {
	// Without this pruning the events table grows forever. On an account with a
	// quota that fills the disk and takes the site down — the tool causing exactly
	// the damage Principle IV exists to avoid.
	e := setup(t)
	ctx := context.Background()
	e.cfg.Logging.RetentionDays = 30

	old := time.Now().AddDate(0, 0, -60)
	recent := time.Now().AddDate(0, 0, -1)
	for i := 0; i < 5; i++ {
		_ = e.store.Log(ctx, store.Event{TS: old, Level: "info", Category: store.CatScan, Message: "old"})
	}
	for i := 0; i < 3; i++ {
		_ = e.store.Log(ctx, store.Event{TS: recent, Level: "info", Category: store.CatScan, Message: "new"})
	}

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: e.cfg, Store: e.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PrunedEvents != 5 {
		t.Errorf("expected 5 pruned events, got %d", res.PrunedEvents)
	}

	remaining, err := e.store.ListEvents(ctx, store.EventFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, ev := range remaining {
		if ev.Message == "old" {
			t.Error("an event beyond the retention survived")
		}
	}
}

func TestARetentionOfZeroPrunesNothing(t *testing.T) {
	// A retention of 0 means "keep everything", never "delete everything".
	e := setup(t)
	ctx := context.Background()
	e.cfg.Logging.RetentionDays = 0

	_ = e.store.Log(ctx, store.Event{
		TS: time.Now().AddDate(-5, 0, 0), Level: "info",
		Category: store.CatScan, Message: "very old",
	})

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: e.cfg, Store: e.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PrunedEvents != 0 {
		t.Errorf("with a retention of 0 nothing should be pruned, got %d", res.PrunedEvents)
	}
}

// Raw-output retention ---------------------------------------------------------

func TestItPrunesRawOutputBeyondTheRetention(t *testing.T) {
	// The raw output is what grows fastest: every cycle writes each engine's
	// complete stdout.
	e := setup(t)
	ctx := context.Background()
	e.cfg.Logging.RawOutputRetentionDays = 14

	root := e.cfg.RawOutputDir()
	old := filepath.Join(root, "s_20260101_000000")
	recent := filepath.Join(root, "s_20260729_000000")
	for _, d := range []string{old, recent} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(d, "amwscan.stdout"), []byte("output"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	past := time.Now().AddDate(0, 0, -60)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: e.cfg, Store: e.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PrunedRawDirs != 1 {
		t.Fatalf("expected 1 removed directory, got %d", res.PrunedRawDirs)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("the old directory should have been removed")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("the recent directory should NOT have been removed")
	}
}

func TestTheRawOutputPruningIgnoresLooseFiles(t *testing.T) {
	// The pruning removes whole cycle directories. A loose file at the root of raw/
	// is not a cycle and must not be touched.
	e := setup(t)
	ctx := context.Background()
	e.cfg.Logging.RawOutputRetentionDays = 1

	loose := filepath.Join(e.cfg.RawOutputDir(), "README.txt")
	if err := os.WriteFile(loose, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	past := time.Now().AddDate(0, 0, -60)
	_ = os.Chtimes(loose, past, past)

	if _, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: e.cfg, Store: e.store}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(loose); err != nil {
		t.Error("a loose file was removed by the directory pruning")
	}
}

// Interrupted cycles -----------------------------------------------------------

func TestAnInterruptedCycleIsClosedAsKilled(t *testing.T) {
	// The hosting kills long processes. A cycle that stays `running` forever makes
	// the history lie by omission about that period's coverage.
	e := setup(t)
	ctx := context.Background()

	if err := e.store.StartScan(ctx, store.ScanRecord{
		ScanID: "s_dead", Mode: schema.ModeIncremental,
		Roots: []string{"/site"}, StartedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	res, err := housekeeping.Run(ctx, housekeeping.Deps{Cfg: e.cfg, Store: e.store})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RecoveredScans != 1 {
		t.Fatalf("expected 1 recovered cycle, got %d", res.RecoveredScans)
	}

	pending, err := e.store.InterruptedScans(ctx)
	if err != nil {
		t.Fatalf("InterruptedScans: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("the cycle should have been closed, %v remain", pending)
	}

	last, err := e.store.LastScan(ctx)
	if err != nil {
		t.Fatalf("LastScan: %v", err)
	}
	if last.Status != schema.StatusKilled {
		t.Errorf("the cycle should show up as killed, got %q", last.Status)
	}
}

// Alerts -----------------------------------------------------------------------

type fakeAlerter struct {
	retries int
	digest  bool
	err     error
}

func (a *fakeAlerter) RetryPending(context.Context) (int, error) {
	return a.retries, a.err
}

func (a *fakeAlerter) SendDigestIfDue(context.Context) (bool, error) {
	return a.digest, nil
}

func TestTheMaintenanceResumesDeliveriesAndSendsTheDigest(t *testing.T) {
	e := setup(t)
	al := &fakeAlerter{retries: 3, digest: true}

	res, err := housekeeping.Run(context.Background(), housekeeping.Deps{
		Cfg: e.cfg, Store: e.store, Alerts: al,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RetriedDeliveries != 3 {
		t.Errorf("retries: %d", res.RetriedDeliveries)
	}
	if !res.DigestSent {
		t.Error("the periodic summary should have been sent")
	}
}

func TestAnAlertFailureDoesNotBlockTheDiskPruning(t *testing.T) {
	// If the webhook is down, the disk cleanup still has to happen: one thing is
	// notification, the other is the user's account not blowing its quota.
	e := setup(t)
	ctx := context.Background()
	e.cfg.Logging.RetentionDays = 1

	_ = e.store.Log(ctx, store.Event{
		TS: time.Now().AddDate(0, 0, -30), Level: "info",
		Category: store.CatScan, Message: "old",
	})

	al := &fakeAlerter{err: fakeErr{}}
	res, err := housekeeping.Run(ctx, housekeeping.Deps{
		Cfg: e.cfg, Store: e.store, Alerts: al,
	})

	if err == nil {
		t.Error("the alert failure should be reported to the caller")
	}
	if res.PrunedEvents == 0 {
		t.Error("the log pruning did not happen because of the alert failure")
	}
}

func TestMaintenanceWithNothingToDoIsEmpty(t *testing.T) {
	e := setup(t)
	res, err := housekeeping.Run(context.Background(), housekeeping.Deps{
		Cfg: e.cfg, Store: e.store,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Empty() {
		t.Errorf("expected an empty result, got %+v", res)
	}
}

type fakeErr struct{}

func (fakeErr) Error() string { return "the endpoint is down" }
