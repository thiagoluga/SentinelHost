package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

func seedFinding(t *testing.T, st *store.Store, scanID, engine, rule, fileSHA string, at time.Time) {
	t.Helper()
	f := schema.Finding{
		SchemaVersion: schema.Version,
		ID:            fmt.Sprintf("f_%s_%s", scanID, engine),
		ScanID:        scanID,
		Engine:        engine,
		Kind:          "malware",
		Rule:          rule,
		File: schema.FileRef{
			Path:      "/home/u/pluggable.php",
			SHA256:    fileSHA,
			SizeBytes: 1024,
		},
		Category:       schema.CategoryOther,
		Severity:       schema.SeverityMedium,
		Confidence:     schema.ConfidenceSignature,
		MatchedContent: "core file altered: wp-includes/pluggable.php",
		DetectedAt:     at,
	}
	if err := st.SaveFinding(context.Background(), f); err != nil {
		t.Fatalf("saving finding: %v", err)
	}
}

// A verdict's evidence is the evidence that verdict was built from.
//
// FindingsForHash returns every finding for that content across every cycle, and a cron
// running every fifteen minutes re-detects the same file all day. The panel showed ONE
// wp-checksums vote above THREE identical wp-checksums evidence blocks — not merely
// noisy, but contradicting the votes printed directly above it.
func TestEvidenceComesFromTheCycleThatDecided(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	fileSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := time.Unix(1785000000, 0).UTC()
	for i := 0; i < 3; i++ {
		seedFinding(t, st, fmt.Sprintf("s_%d", i), "wp-checksums", "core_file_modified",
			fileSHA, base.Add(time.Duration(i)*15*time.Minute))
	}

	// What the panel used to ask for.
	all, err := st.FindingsForHash(ctx, fileSHA)
	if err != nil {
		t.Fatalf("FindingsForHash: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("the history holds %d findings, expected all 3 — scoping the panel must "+
			"not delete the record", len(all))
	}

	// What it asks for now: one cycle's worth.
	one, err := st.FindingsForVerdict(ctx, fileSHA, "s_1", "")
	if err != nil {
		t.Fatalf("FindingsForVerdict: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("the verdict from cycle s_1 shows %d evidence blocks; it has one vote", len(one))
	}
	if one[0].ScanID != "s_1" {
		t.Errorf("showed evidence from cycle %q under a verdict from s_1", one[0].ScanID)
	}
}

// A cycle that recorded nothing returns nothing, rather than borrowing another cycle's
// evidence. The panel says so in words; an empty list and a failed request look identical
// otherwise.
func TestACycleWithNoEvidenceBorrowsNone(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	fileSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	seedFinding(t, st, "s_1", "amwscan", "Function", fileSHA, time.Unix(1785000000, 0).UTC())

	got, err := st.FindingsForVerdict(ctx, fileSHA, "s_2", "")
	if err != nil {
		t.Fatalf("FindingsForVerdict: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("cycle s_2 recorded nothing but %d block(s) were shown under it", len(got))
	}
}
