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

// checkAffected transforma "nenhuma linha afetada" em erro explicito.
//
// Um UPDATE que nao encontra a linha e sucesso para o SQL e falha para o
// usuario: a quarentena que ele mandou registrar simplesmente nao ficou
// registrada, e ninguem avisou.
func checkAffected(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("verificando linhas afetadas: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}
