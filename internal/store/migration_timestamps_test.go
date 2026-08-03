package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// Its own constant: the one in store_test.go belongs to the external test package, and
// these tests are internal because they reach for s.db to seed the old shape directly.
const oldSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// The migration has to repair rows written by earlier versions, because a table holding
// both shapes sorts wrongly at every boundary between them — which is precisely where
// "most recent" is decided.
func TestMigrationPadsTimestampsAlreadyOnDisk(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// Build a database at the state a previous release left behind: schema applied, then
	// rows written in the trimmed form.
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	old := map[string]string{
		"v_whole":  "2026-08-03T17:01:23Z",           // no fraction at all
		"v_short":  "2026-08-03T17:01:23.9Z",         // one digit
		"v_full":   "2026-08-03T17:01:23.905504385Z", // already nine
		"v_medium": "2026-08-03T17:01:23.5Z",
	}
	for id, ts := range old {
		_, err := s.db.ExecContext(ctx, `INSERT INTO verdicts
			(verdict_id, file_sha256, file_path, file_size, level, score, votes_json,
			 action_taken, scan_id, created_at, updated_at)
			VALUES (?,?,?,0,'suspicious',0.5,'[]','none','s_1',?,?)`,
			id, oldSHA, "/home/u/"+id+".php", ts, ts)
		if err != nil {
			t.Fatalf("seeding %s: %v", id, err)
		}
	}
	// Rewind the recorded version so the migration runs against these rows.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 3`); err != nil {
		t.Fatalf("rewinding: %v", err)
	}
	_ = s.Close()

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = s2.Close() }()

	want := map[string]string{
		"v_whole":  "2026-08-03T17:01:23.000000000Z",
		"v_short":  "2026-08-03T17:01:23.900000000Z",
		"v_full":   "2026-08-03T17:01:23.905504385Z",
		"v_medium": "2026-08-03T17:01:23.500000000Z",
	}
	for id, expect := range want {
		var got string
		if err := s2.db.QueryRowContext(ctx,
			`SELECT created_at FROM verdicts WHERE verdict_id = ?`, id).Scan(&got); err != nil {
			t.Fatalf("reading %s: %v", id, err)
		}
		if got != expect {
			t.Errorf("%s: stored %q, wanted %q", id, got, expect)
		}
	}

	// And now they sort the way the clock does.
	rows, err := s2.db.QueryContext(ctx,
		`SELECT verdict_id FROM verdicts ORDER BY created_at ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var order []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		order = append(order, id)
	}
	wantOrder := []string{"v_whole", "v_medium", "v_short", "v_full"}
	for i := range wantOrder {
		if i >= len(order) || order[i] != wantOrder[i] {
			t.Fatalf("sorted %v, wanted %v — before the migration v_whole sorted last",
				order, wantOrder)
		}
	}
}

// A NULL or an empty timestamp means "never happened". The migration must leave it alone
// rather than turn it into a plausible-looking instant.
func TestMigrationLeavesAbsentTimestampsAbsent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO verdicts
		(verdict_id, file_sha256, file_path, file_size, level, score, votes_json,
		 action_taken, action_at, acknowledged_at, scan_id, created_at, updated_at)
		VALUES ('v_1',?,'/home/u/x.php',0,'suspicious',0.5,'[]','none',NULL,NULL,'s_1',
		        '2026-08-03T17:01:23Z','2026-08-03T17:01:23Z')`, oldSHA)
	if err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 3`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = s2.Close() }()

	var actionAt, ackAt sql.NullString
	err = s2.db.QueryRowContext(ctx,
		`SELECT action_at, acknowledged_at FROM verdicts WHERE verdict_id = 'v_1'`).
		Scan(&actionAt, &ackAt)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if actionAt.Valid || ackAt.Valid {
		t.Errorf("a NULL timestamp was filled in: action_at=%v acknowledged_at=%v. "+
			"'Never happened' and 'happened in year zero' are not the same thing",
			actionAt, ackAt)
	}
}

// Running the migration twice must not pad an already-padded value again.
func TestMigrationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.db")

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO verdicts
		(verdict_id, file_sha256, file_path, file_size, level, score, votes_json,
		 action_taken, scan_id, created_at, updated_at)
		VALUES ('v_1',?,'/home/u/x.php',0,'suspicious',0.5,'[]','none','s_1',
		        '2026-08-03T17:01:23.905504385Z','2026-08-03T17:01:23.905504385Z')`, oldSHA)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 3`); err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(ctx); err != nil {
			t.Fatalf("re-running the migration: %v", err)
		}
	}
	var got string
	if err := s.db.QueryRowContext(ctx,
		`SELECT created_at FROM verdicts WHERE verdict_id = 'v_1'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if got != "2026-08-03T17:01:23.905504385Z" {
		t.Errorf("three passes produced %q", got)
	}
}
