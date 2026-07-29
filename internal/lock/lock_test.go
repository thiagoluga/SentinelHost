package lock_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/lock"
)

func TestAcquireAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	l, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the lock file should exist: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the lock file should have been removed")
	}
}

func TestSecondInstanceIsRefusedWithAClearMessage(t *testing.T) {
	// The real scenario: cron fires while the user clicks "scan now" in the
	// panel. The second process has to exit with a clear message.
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	first, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer func() { _ = first.Release() }()

	_, err = lock.Acquire(path)
	if !errors.Is(err, lock.ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), fmt.Sprint(os.Getpid())) {
		t.Errorf("the message should say which process holds the lock: %v", err)
	}
}

func TestStaleLockIsRecovered(t *testing.T) {
	// The host kills long-running processes. A stale lock must not leave the
	// tool stuck forever.
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	// An absurdly high PID: it does not exist.
	content := fmt.Sprintf("%d\n%s\nold-host\n", 4194303, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	l, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("a stale lock should have been recovered: %v", err)
	}
	defer func() { _ = l.Release() }()

	info, err := lock.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("the lock should have been rewritten with the current PID, got %d", info.PID)
	}
}

func TestReleaseTwiceIsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")
	l, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Errorf("the second Release should be a no-op: %v", err)
	}
}

func TestReadReturnsTheOwner(t *testing.T) {
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
		t.Errorf("PID: expected %d, got %d", os.Getpid(), info.PID)
	}
	if info.StartedAt.IsZero() {
		t.Error("the start time should have been recorded")
	}
}
