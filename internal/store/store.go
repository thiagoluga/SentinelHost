// Package store guarda o estado do SentinelHost em SQLite.
//
// Driver: modernc.org/sqlite (Go puro). O binario tem que ser estatico e sem
// CGO para rodar numa hospedagem compartilhada qualquer (Principio VII), o que
// exclui o mattn/go-sqlite3.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // driver "sqlite"
)

// Store e a conexao com o banco de estado.
type Store struct {
	db   *sql.DB
	path string
}

// Open abre (criando se preciso) o banco no caminho dado e aplica as migracoes
// pendentes.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("criando diretorio do banco: %w", err)
	}

	// _busy_timeout: o painel e o ciclo de scan escrevem no mesmo banco. Sem
	// timeout, uma escrita concorrente devolveria SQLITE_BUSY na hora em vez
	// de esperar — e perder o registro de uma quarentena por lock e
	// inaceitavel.
	// WAL: leitura do painel nao bloqueia a escrita do ciclo.
	dsn := path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("abrindo banco: %w", err)
	}

	// SQLite nao ganha nada com muitas conexoes de escrita e perde em
	// contencao de lock.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("conectando ao banco: %w", err)
	}

	s := &Store{db: db, path: path}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrando banco: %w", err)
	}

	// O banco guarda hash de senha do painel e segredos de sessao.
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		return s, fmt.Errorf("ajustando permissao do banco: %w", err)
	}
	return s, nil
}

// Close fecha a conexao.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB expoe a conexao para casos que precisam de SQL direto (relatorios do
// painel). Escritas devem passar pelos DAOs.
func (s *Store) DB() *sql.DB { return s.db }

// Path devolve o caminho do arquivo de banco.
func (s *Store) Path() string { return s.path }

// tx roda fn dentro de uma transacao, com rollback em erro ou panico.
//
// Consolidar aqui garante que nenhuma escrita de quarentena fique pela metade:
// mover o arquivo e registrar o item precisam ser tudo ou nada, senao existe
// arquivo no cofre sem registro de como restaura-lo.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("iniciando transacao: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = t.Rollback()
			panic(p)
		}
	}()
	if err := fn(t); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Commit()
}
