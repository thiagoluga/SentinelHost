package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

func evidenceStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func saveFinding(t *testing.T, st *store.Store, id, scanID, path, sha string, at time.Time) {
	t.Helper()
	f := schema.Finding{
		SchemaVersion: schema.Version,
		ID:            id,
		ScanID:        scanID,
		Engine:        "wp-checksums",
		Kind:          "malware",
		Rule:          "core_file_modified",
		File:          schema.FileRef{Path: path, SHA256: sha, SizeBytes: 1024},
		Category:      schema.CategoryOther,
		Severity:      schema.SeverityMedium,
		Confidence:    schema.ConfidenceSignature,
		DetectedAt:    at,
	}
	if err := st.SaveFinding(context.Background(), f); err != nil {
		t.Fatalf("saving %s: %v", id, err)
	}
}

// The panel showed one wp-checksums vote above three identical wp-checksums evidence
// blocks — not merely noisy, it contradicts the votes printed directly above it.
//
// Findings are stored per file, and byte-identical content at several paths produces one
// finding each. This account carries three WordPress copies under .trash whose
// pluggable.php is identical, so the card for one path was showing the evidence for all
// three. A verdict's identity is (path, content); its evidence has to match.
func TestEvidenceIsScopedToOnePath(t *testing.T) {
	ctx := context.Background()
	st := evidenceStore(t)
	at := time.Unix(1785000000, 0).UTC()
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// The same content, found at three paths, in one cycle.
	saveFinding(t, st, "f_1", "s_1", "/home/u/.trash/wordpress/wp-includes/pluggable.php", sha, at)
	saveFinding(t, st, "f_2", "s_1", "/home/u/.trash/blog/wp-includes/pluggable.php", sha, at)
	saveFinding(t, st, "f_3", "s_1", "/home/u/.trash/motel_new/wp-includes/pluggable.php", sha, at)

	got, err := st.FindingsForVerdict(ctx, sha, "s_1",
		"/home/u/.trash/wordpress/wp-includes/pluggable.php")
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the card for one path shows %d evidence blocks; the other copies of the "+
			"file are their own findings and belong on their own cards", len(got))
	}
	if got[0].File.Path != "/home/u/.trash/wordpress/wp-includes/pluggable.php" {
		t.Errorf("the block shown belongs to %s", got[0].File.Path)
	}
}

// FindingsForHash keeps its old meaning — every path, every cycle — because the history
// is a different question from "why does this verdict say what it says".
func TestTheHistoryQueryStillSpansEverything(t *testing.T) {
	ctx := context.Background()
	st := evidenceStore(t)
	at := time.Unix(1785000000, 0).UTC()
	sha := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	saveFinding(t, st, "f_1", "s_1", "/home/u/a.php", sha, at)
	saveFinding(t, st, "f_2", "s_2", "/home/u/b.php", sha, at)

	got, err := st.FindingsForHash(ctx, sha)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("the history query returned %d, wanted both", len(got))
	}
}
