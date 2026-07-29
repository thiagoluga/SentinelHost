package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// checkAffected turns "no rows affected" into an explicit error.
//
// An UPDATE that finds no row is a success to SQL and a failure to the user: the
// quarantine they asked to be recorded simply was not recorded, and nobody said
// so.
func checkAffected(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking affected rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}
