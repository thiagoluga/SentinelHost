package lock_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/lock"
)

func TestAcquireERelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	l, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("o arquivo de lock deveria existir: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("o arquivo de lock deveria ter sido removido")
	}
}

func TestSegundaInstanciaERecusadaComMensagemClara(t *testing.T) {
	// O cenario real: o cron dispara enquanto o usuario clica em "escanear
	// agora" no painel. O segundo processo tem que sair com mensagem clara.
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	primeiro, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("primeiro Acquire: %v", err)
	}
	defer func() { _ = primeiro.Release() }()

	_, err = lock.Acquire(path)
	if !errors.Is(err, lock.ErrLocked) {
		t.Fatalf("esperava ErrLocked, veio %v", err)
	}
	if err == nil || !contains(err.Error(), fmt.Sprint(os.Getpid())) {
		t.Errorf("a mensagem deveria dizer qual processo detem o lock: %v", err)
	}
}

func TestLockOrfaoERecuperado(t *testing.T) {
	// A hospedagem mata processos longos. Um lock orfao nao pode deixar a
	// ferramenta travada para sempre.
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	// PID absurdamente alto: nao existe.
	conteudo := fmt.Sprintf("%d\n%s\nhost-antigo\n", 4194303, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(conteudo), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	l, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("lock orfao deveria ser recuperado: %v", err)
	}
	defer func() { _ = l.Release() }()

	info, err := lock.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("o lock deveria ter sido reescrito com o PID atual, veio %d", info.PID)
	}
}

func TestReleaseDuasVezesESeguro(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")
	l, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("primeiro Release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Errorf("segundo Release deveria ser no-op: %v", err)
	}
}

func TestReadDevolveDono(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")
	l, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = l.Release() }()

	info, err := lock.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("PID: esperado %d, veio %d", os.Getpid(), info.PID)
	}
	if info.StartedAt.IsZero() {
		t.Error("o horario de inicio deveria estar registrado")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
