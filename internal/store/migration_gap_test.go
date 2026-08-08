package store

import (
	"context"
	"path/filepath"
	"testing"
)

// A migration missing from the middle of the record must run.
//
// The runner asked `SELECT MAX(version)` and skipped everything at or below it. That is the
// right answer only while the recorded versions are a contiguous run from 1 — the moment one
// is missing in the middle, the highest one hides it and it never runs again.
//
// It cost a real test. Two of them simulate "a database an earlier release left behind" by
// deleting the row for the migration under test and reopening, which is the natural way to
// write it. They worked until a later migration existed; then MAX came back higher, the
// migration was skipped, and TestMigrationIsIdempotent started passing while exercising
// nothing. A test that cannot fail is worse than no test, because it is counted as coverage.
//
// So this asserts the reading directly rather than through a migration's side effects,
// which is what let the problem hide the first time.
func TestAMigrationMissingFromTheMiddleIsApplied(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "gap.db")

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer func() { _ = s.Close() }()

	highest := migrations[len(migrations)-1].version
	if highest < 2 {
		t.Skip("there is only one migration, so there is no middle to leave a gap in")
	}

	// Take out one that is NOT the highest. Under the old reading, MAX still reported the
	// highest and this row would never come back.
	gap := highest - 1
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version = ?`, gap); err != nil {
		t.Fatalf("removing version %d: %v", gap, err)
	}

	var before int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, gap).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 0 {
		t.Fatalf("the gap was not made: version %d is still recorded", gap)
	}

	if err := s.migrate(ctx); err != nil {
		t.Fatalf("re-running the migrations: %v", err)
	}

	var after int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, gap).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 1 {
		t.Errorf("version %d was not re-applied; a migration missing from the middle of the "+
			"record stays missing forever, and the schema it needed never arrives", gap)
	}

	// And every version is recorded exactly once. A runner that re-applied everything would
	// also satisfy the check above, and would be a different kind of wrong.
	for _, m := range migrations {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("version %d (%s) is recorded %d times, wanted once", m.version, m.name, n)
		}
	}
}

// Opening a database twice must not run anything the second time.
//
// The cheapest possible guard against a runner that re-applies what is already recorded:
// every migration here is DDL, and a second `ALTER TABLE ... ADD COLUMN` fails outright.
func TestOpeningTwiceAppliesNothing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "twice.db")

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	_ = s.Close()

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopening ran a migration that had already been applied: %v", err)
	}
	defer func() { _ = s2.Close() }()

	v, err := s2.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := migrations[len(migrations)-1].version; v != want {
		t.Errorf("schema version %d, wanted %d", v, want)
	}
}
