package store

import (
	"database/sql"
	"time"
)

// O banco guarda tempo como RFC3339 em UTC. Texto porque o painel, os
// relatorios JSON e o proprio SQLite ficam legiveis; UTC porque a hospedagem
// pode mudar de fuso sem avisar, e um historico de incidente com timestamps
// ambiguos nao serve para investigar nada.

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// nullTime converte tempo zero em NULL, para que "nunca aconteceu" e "aconteceu
// no ano zero" nao virem a mesma coisa no banco.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return formatTime(t)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func timeFromNull(ns sql.NullString) time.Time {
	if !ns.Valid {
		return time.Time{}
	}
	return parseTime(ns.String)
}

func strFromNull(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
