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

func TestOpenAppliesMigrations(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 1 {
		t.Fatalf("expected a migrated schema, got version %d", v)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	// Reopening the database on every cron run must not reapply a migration.
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	s1, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	v1, _ := s1.SchemaVersion(ctx)
	_ = s1.Close()

	s2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer func() { _ = s2.Close() }()
	v2, _ := s2.SchemaVersion(ctx)

	if v1 != v2 {
		t.Errorf("the version changed on reopen: %d -> %d", v1, v2)
	}
}

func sampleVerdict(id string, level schema.Level, score float64) schema.Verdict {
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

func TestVerdictRoundTripPreservesVotesAndAbstentions(t *testing.T) {
	// The votes ARE the verdict: without them the user cannot answer "why was
	// this file quarantined?" (Principle V).
	ctx := context.Background()
	s := openTemp(t)

	orig := sampleVerdict("v_1", schema.LevelConfirmed, 0.92)
	if err := s.SaveVerdict(ctx, orig); err != nil {
		t.Fatalf("SaveVerdict: %v", err)
	}

	back, err := s.GetVerdict(ctx, "v_1")
	if err != nil {
		t.Fatalf("GetVerdict: %v", err)
	}
	if len(back.Votes) != 2 {
		t.Fatalf("expected 2 votes, got %d", len(back.Votes))
	}
	if back.Votes[0].Engine != "amwscan" || back.Votes[0].EffectiveWeight != 0.8 {
		t.Errorf("corrupt vote: %+v", back.Votes[0])
	}
	if back.Votes[1].Rule != "ObfuscatedPhp" {
		t.Errorf("rule lost: %+v", back.Votes[1])
	}
	if len(back.Abstentions) != 1 || back.Abstentions[0] != "maldet" {
		t.Errorf("abstentions lost: %v", back.Abstentions)
	}
	if back.Level != schema.LevelConfirmed || back.Score != 0.92 {
		t.Errorf("level/score lost: %s %v", back.Level, back.Score)
	}
}

func TestSaveVerdictRejectsAnInvalidVerdict(t *testing.T) {
	// Persisting a broken verdict would spread the defect to the panel, the
	// alerts and the webhook.
	ctx := context.Background()
	s := openTemp(t)

	v := sampleVerdict("v_bad", schema.LevelConfirmed, 0.92)
	v.ActionTaken = schema.ActionQuarantined // with no quarantine_ref

	if err := s.SaveVerdict(ctx, v); err == nil {
		t.Fatal("a quarantined verdict with no reference should have been rejected")
	}
}

func TestSaveVerdictUpdatesInsteadOfDuplicating(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	v := sampleVerdict("v_1", schema.LevelLikely, 0.7)
	if err := s.SaveVerdict(ctx, v); err != nil {
		t.Fatalf("first save: %v", err)
	}
	v.Level = schema.LevelConfirmed
	v.Score = 0.95
	if err := s.SaveVerdict(ctx, v); err != nil {
		t.Fatalf("second save: %v", err)
	}

	all, err := s.ListVerdicts(ctx, store.VerdictFilter{})
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(all))
	}
	if all[0].Level != schema.LevelConfirmed {
		t.Errorf("the update did not take effect: %s", all[0].Level)
	}
}

func TestListVerdictsHidesCleanByDefault(t *testing.T) {
	// Showing thousands of clean files would hide the 3 that matter.
	ctx := context.Background()
	s := openTemp(t)

	_ = s.SaveVerdict(ctx, sampleVerdict("v_clean", schema.LevelClean, 0.0))
	_ = s.SaveVerdict(ctx, sampleVerdict("v_conf", schema.LevelConfirmed, 0.95))

	withoutClean, err := s.ListVerdicts(ctx, store.VerdictFilter{})
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(withoutClean) != 1 || withoutClean[0].VerdictID != "v_conf" {
		t.Errorf("expected only the confirmed one, got %d items", len(withoutClean))
	}

	withClean, err := s.ListVerdicts(ctx, store.VerdictFilter{IncludeClean: true})
	if err != nil {
		t.Fatalf("ListVerdicts(IncludeClean): %v", err)
	}
	if len(withClean) != 2 {
		t.Errorf("expected 2 items including clean, got %d", len(withClean))
	}
}

func TestUpdateVerdictActionAndAcknowledge(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	_ = s.SaveVerdict(ctx, sampleVerdict("v_1", schema.LevelConfirmed, 0.95))

	if err := s.UpdateVerdictAction(ctx, "v_1", schema.ActionQuarantined, "q_1", ""); err != nil {
		t.Fatalf("UpdateVerdictAction: %v", err)
	}
	v, _ := s.GetVerdict(ctx, "v_1")
	if v.ActionTaken != schema.ActionQuarantined || v.QuarantineRef != "q_1" {
		t.Errorf("action not recorded: %+v", v)
	}
	if v.ActionAt.IsZero() {
		t.Error("action_at should have been filled in")
	}

	if err := s.AcknowledgeVerdict(ctx, "v_1"); err != nil {
		t.Fatalf("AcknowledgeVerdict: %v", err)
	}
	v, _ = s.GetVerdict(ctx, "v_1")
	if !v.AcknowledgedByUser {
		t.Error("the verdict should be marked as decided")
	}
}

func TestUpdatingANonExistentVerdictIsAnError(t *testing.T) {
	// An UPDATE that finds no row is a success to SQL and a failure to the user:
	// the action they asked to be recorded was not recorded.
	ctx := context.Background()
	s := openTemp(t)

	err := s.UpdateVerdictAction(ctx, "does-not-exist", schema.ActionQuarantined, "q_1", "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// Quarantine -----------------------------------------------------------------

func sampleItem(ref string, retention time.Time) store.QuarantineItem {
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
		RetentionUntil: retention,
	}
}

func TestQuarantineRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	it := sampleItem("q_1", time.Now().Add(30*24*time.Hour))
	if err := s.InsertQuarantineItem(ctx, it); err != nil {
		t.Fatalf("InsertQuarantineItem: %v", err)
	}

	back, err := s.GetQuarantineItem(ctx, "q_1")
	if err != nil {
		t.Fatalf("GetQuarantineItem: %v", err)
	}
	// These fields are exactly what makes the action reversible.
	if back.OriginalPath != it.OriginalPath || back.VaultPath != it.VaultPath ||
		back.SHA256 != it.SHA256 || back.Perms != it.Perms {
		t.Errorf("restore metadata lost: %+v", back)
	}
	if back.Status != store.QuarantineActive {
		t.Errorf("initial status should be quarantined, got %q", back.Status)
	}
}

func TestQuarantineWithoutMetadataIsRejected(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	it := sampleItem("q_1", time.Now())
	it.VaultPath = ""
	if err := s.InsertQuarantineItem(ctx, it); err == nil {
		t.Fatal("an item with no vault_path is not restorable and should have been rejected")
	}
}

func TestPurgeRejectsAnItemInsideRetention(t *testing.T) {
	// Principle I at the database level: not even a wrong call from another
	// package can delete an item still inside its window.
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, sampleItem("q_1", time.Now().Add(30*24*time.Hour)))

	err := s.MarkPurged(ctx, "q_1", time.Now())
	if err == nil {
		t.Fatal("purging inside the retention window should have been rejected")
	}
	if !strings.Contains(err.Error(), "retention") {
		t.Errorf("the error should explain the reason, got: %v", err)
	}

	it, _ := s.GetQuarantineItem(ctx, "q_1")
	if it.Status != store.QuarantineActive {
		t.Errorf("the item should still be active, got %q", it.Status)
	}
}

func TestPurgeAcceptsAnExpiredItem(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, sampleItem("q_1", time.Now().Add(-time.Hour)))

	if err := s.MarkPurged(ctx, "q_1", time.Now()); err != nil {
		t.Fatalf("MarkPurged: %v", err)
	}
	it, _ := s.GetQuarantineItem(ctx, "q_1")
	if it.Status != store.QuarantinePurged {
		t.Errorf("expected purged, got %q", it.Status)
	}
}

func TestForcePurgeIgnoresRetention(t *testing.T) {
	// The constitution allows a permanent purge by manual user action.
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, sampleItem("q_1", time.Now().Add(30*24*time.Hour)))
	if err := s.ForcePurge(ctx, "q_1"); err != nil {
		t.Fatalf("ForcePurge: %v", err)
	}
	it, _ := s.GetQuarantineItem(ctx, "q_1")
	if it.Status != store.QuarantinePurged {
		t.Errorf("expected purged, got %q", it.Status)
	}
}

func TestExpiredItemsIgnoresRestoredOnes(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, sampleItem("q_active", time.Now().Add(-time.Hour)))
	_ = s.InsertQuarantineItem(ctx, sampleItem("q_restored", time.Now().Add(-time.Hour)))
	if err := s.MarkRestored(ctx, "q_restored", "/home/user/public_html/cache.php"); err != nil {
		t.Fatalf("MarkRestored: %v", err)
	}

	exp, err := s.ExpiredItems(ctx, time.Now())
	if err != nil {
		t.Fatalf("ExpiredItems: %v", err)
	}
	if len(exp) != 1 || exp[0].Ref != "q_active" {
		t.Errorf("a restored item must not reappear as a purge candidate: %+v", exp)
	}
}

func TestRestoringTwiceFails(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.InsertQuarantineItem(ctx, sampleItem("q_1", time.Now().Add(time.Hour)))
	if err := s.MarkRestored(ctx, "q_1", "/x"); err != nil {
		t.Fatalf("first restore: %v", err)
	}
	if err := s.MarkRestored(ctx, "q_1", "/x"); err == nil {
		t.Fatal("restoring an already restored item should fail")
	}
}

// Reports, deliveries and the log ---------------------------------------------

func TestFailureReportIsArchived(t *testing.T) {
	// Silent coverage degradation is an orchestrator's most dangerous failure
	// mode: the failure report has to survive the cycle.
	ctx := context.Background()
	s := openTemp(t)

	if err := s.StartScan(ctx, store.ScanRecord{
		ScanID: "s_1", Mode: schema.ModeIncremental,
		Roots: []string{"/home/user/public_html"}, StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	failure := schema.FailedReport("s_1", "maldet", schema.StatusTimeout,
		errors.New("timed out after 300s"), time.Now())
	if err := s.SaveScanReport(ctx, failure); err != nil {
		t.Fatalf("SaveScanReport: %v", err)
	}

	reports, err := s.ListScanReports(ctx, "s_1")
	if err != nil {
		t.Fatalf("ListScanReports: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	if reports[0].Status != schema.StatusTimeout || reports[0].Error == "" {
		t.Errorf("the failure reason was lost: %+v", reports[0])
	}
	if !reports[0].Abstains() {
		t.Error("a timeout report should count as an abstention")
	}
}

func TestDeliveryKeepsItsIDAcrossAttempts(t *testing.T) {
	// The delivery_id is the idempotency key on the destination's side (webhook
	// contract): it must not change between retries.
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

	next := time.Now().Add(time.Second)
	if err := s.RecordAttempt(ctx, "d_1", false, 500, "server error", next); err != nil {
		t.Fatalf("RecordAttempt 1: %v", err)
	}
	got, _ := s.GetDelivery(ctx, "d_1")
	if got.Attempts != 1 || got.Status != store.DeliveryPending {
		t.Errorf("after a failure with a retry scheduled: %+v", got)
	}

	if err := s.RecordAttempt(ctx, "d_1", true, 200, "", time.Time{}); err != nil {
		t.Fatalf("RecordAttempt 2: %v", err)
	}
	got, _ = s.GetDelivery(ctx, "d_1")
	if got.Status != store.DeliveryDelivered || got.Attempts != 2 {
		t.Errorf("after success: %+v", got)
	}
	if got.DeliveredAt.IsZero() {
		t.Error("delivered_at should have been filled in")
	}
}

func TestDeliveryWithNoNextAttemptBecomesFailed(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.EnqueueDelivery(ctx, store.Delivery{
		DeliveryID: "d_1", Channel: "webhook", Target: "slack",
		Event: "scan.completed", PayloadJSON: "{}", CreatedAt: time.Now(),
	})
	if err := s.RecordAttempt(ctx, "d_1", false, 0, "connection refused", time.Time{}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	got, _ := s.GetDelivery(ctx, "d_1")
	if got.Status != store.DeliveryFailed {
		t.Errorf("expected failed, got %q", got.Status)
	}
	if got.Error == "" {
		t.Error("the real error should stay recorded so it shows up in the panel")
	}
}

func TestPendingDeliveriesRespectsBackoff(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.EnqueueDelivery(ctx, store.Delivery{
		DeliveryID: "d_future", Channel: "webhook", Target: "x", Event: "scan.completed",
		PayloadJSON: "{}", CreatedAt: time.Now(), NextAttemptAt: time.Now().Add(time.Hour),
	})
	_ = s.EnqueueDelivery(ctx, store.Delivery{
		DeliveryID: "d_now", Channel: "webhook", Target: "x", Event: "scan.completed",
		PayloadJSON: "{}", CreatedAt: time.Now(), NextAttemptAt: time.Now().Add(-time.Minute),
	})

	pending, err := s.PendingDeliveries(ctx, time.Now(), 0)
	if err != nil {
		t.Fatalf("PendingDeliveries: %v", err)
	}
	if len(pending) != 1 || pending[0].DeliveryID != "d_now" {
		t.Errorf("backoff not respected: %+v", pending)
	}
}

func TestStructuredLogIsQueryable(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.Log(ctx, store.Event{
		Level: "warn", Category: store.CatQuarantine,
		Message: "file quarantined",
		Fields:  map[string]any{"ref": "q_1", "score": 0.95},
		ScanID:  "s_1",
	})
	_ = s.Log(ctx, store.Event{Level: "info", Category: store.CatScan, Message: "cycle started"})

	all, err := s.ListEvents(ctx, store.EventFilter{})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 events, got %d", len(all))
	}

	quarantine, err := s.ListEvents(ctx, store.EventFilter{Category: store.CatQuarantine})
	if err != nil {
		t.Fatalf("ListEvents(filter): %v", err)
	}
	if len(quarantine) != 1 {
		t.Fatalf("the category filter failed: %d", len(quarantine))
	}
	if quarantine[0].Fields["ref"] != "q_1" {
		t.Errorf("structured fields lost: %v", quarantine[0].Fields)
	}
}

func TestPruneEventsDeletesOnlyOldOnes(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.Log(ctx, store.Event{TS: time.Now().Add(-100 * 24 * time.Hour), Category: store.CatScan, Message: "old"})
	_ = s.Log(ctx, store.Event{TS: time.Now(), Category: store.CatScan, Message: "recent"})

	n, err := s.PruneEvents(ctx, time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 pruned event, got %d", n)
	}

	left, _ := s.ListEvents(ctx, store.EventFilter{})
	if len(left) != 1 || left[0].Message != "recent" {
		t.Errorf("the wrong event was pruned: %+v", left)
	}
}

func TestMissingSettingIsNotAnError(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	v, err := s.GetSetting(ctx, store.KeyPanelPasswordHash)
	if err != nil {
		t.Fatalf("a missing key should not be an error: %v", err)
	}
	if v != "" {
		t.Errorf("expected empty, got %q", v)
	}

	if err := s.SetSetting(ctx, store.KeyPanelPasswordHash, "argon2id$..."); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	v, _ = s.GetSetting(ctx, store.KeyPanelPasswordHash)
	if v != "argon2id$..." {
		t.Errorf("value lost: %q", v)
	}
}

func TestAnExpiredSessionIsNotValid(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	if err := s.CreateSession(ctx, "tok-valid", time.Now().Add(time.Hour), "ua", "127.0.0.1"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.CreateSession(ctx, "tok-expired", time.Now().Add(-time.Hour), "ua", "127.0.0.1"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	ok, err := s.SessionValid(ctx, "tok-valid")
	if err != nil || !ok {
		t.Errorf("a valid session was refused: ok=%v err=%v", ok, err)
	}
	ok, _ = s.SessionValid(ctx, "tok-expired")
	if ok {
		t.Error("an expired session was accepted")
	}
	ok, _ = s.SessionValid(ctx, "tok-nonexistent")
	if ok {
		t.Error("a non-existent token was accepted")
	}
}

func TestEngineStatePreservesTheSignatureDate(t *testing.T) {
	// A probe that could not read the signature version must not erase the date
	// that was already known.
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
		Slug: "amwscan", Available: false, UnavailableReason: "PHP CLI missing",
		LastProbeAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveEngineState 2: %v", err)
	}

	states, err := s.ListEngineStates(ctx)
	if err != nil {
		t.Fatalf("ListEngineStates: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("expected 1 engine, got %d", len(states))
	}
	if states[0].Available {
		t.Error("availability should have been updated to false")
	}
	if states[0].UnavailableReason == "" {
		t.Error("the unavailability reason is mandatory for the panel (FR-001)")
	}
	if states[0].SignaturesUpdatedAt.IsZero() {
		t.Error("a known signature date must not be erased by a probe that failed")
	}
}

func TestCountByLevel(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)

	_ = s.SaveVerdict(ctx, sampleVerdict("v_1", schema.LevelConfirmed, 0.95))
	_ = s.SaveVerdict(ctx, sampleVerdict("v_2", schema.LevelSuspicious, 0.4))
	_ = s.SaveVerdict(ctx, sampleVerdict("v_3", schema.LevelSuspicious, 0.35))

	counts, err := s.CountByLevel(ctx, "")
	if err != nil {
		t.Fatalf("CountByLevel: %v", err)
	}
	if counts[schema.LevelConfirmed] != 1 || counts[schema.LevelSuspicious] != 2 {
		t.Errorf("wrong counts: %v", counts)
	}
}

func TestInterruptedScansFindsCyclesWithNoOutcome(t *testing.T) {
	// A cycle killed by the host stays "running" with no finished_at — the signal
	// the watchdog looks for.
	ctx := context.Background()
	s := openTemp(t)

	if err := s.StartScan(ctx, store.ScanRecord{
		ScanID: "s_killed", Mode: schema.ModeIncremental,
		Roots: []string{"/x"}, StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	if err := s.StartScan(ctx, store.ScanRecord{
		ScanID: "s_done", Mode: schema.ModeIncremental,
		Roots: []string{"/x"}, StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	if err := s.FinishScan(ctx, store.ScanRecord{
		ScanID: "s_done", FinishedAt: time.Now(), Status: schema.StatusCompleted,
	}); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}

	ids, err := s.InterruptedScans(ctx)
	if err != nil {
		t.Fatalf("InterruptedScans: %v", err)
	}
	if len(ids) != 1 || ids[0] != "s_killed" {
		t.Errorf("expected only the killed cycle, got %v", ids)
	}
}
