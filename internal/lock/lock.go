// Package lock prevents two instances of SentinelHost from running at once.
//
// The real scenario: cron fires a cycle while the user clicks "scan now" in the
// panel. Two concurrent cycles would write to the same baseline and could try to
// quarantine the same file twice.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrLocked signals that another instance is running.
var ErrLocked = errors.New("another SentinelHost instance is already running")

// Lock is a file lock with an identified owner.
type Lock struct {
	path string
	held bool
}

// Info describes who holds the lock.
type Info struct {
	PID       int
	StartedAt time.Time
	Host      string
}

// Acquire tries to obtain the lock.
//
// It uses O_EXCL, which is atomic even on modern NFS — which matters because
// shared hosting sometimes mounts the home directory over the network, where
// flock is not reliable.
func Acquire(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating lock directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		host, _ := os.Hostname()
		content := fmt.Sprintf("%d\n%s\n%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339), host)
		if _, werr := f.WriteString(content); werr != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("writing lock: %w", werr)
		}
		if cerr := f.Close(); cerr != nil {
			return nil, fmt.Errorf("closing lock: %w", cerr)
		}
		return &Lock{path: path, held: true}, nil
	}
	if !os.IsExist(err) {
		return nil, fmt.Errorf("creating lock: %w", err)
	}

	// The lock exists. Does it belong to a live process, or is it the leftover
	// of a process the host killed? The second case is common and must not leave
	// the tool stuck forever.
	info, readErr := Read(path)
	if readErr != nil {
		return nil, fmt.Errorf("%w (unreadable lock at %s: %v)", ErrLocked, path, readErr)
	}
	if processAlive(info.PID) {
		return nil, fmt.Errorf("%w: PID %d since %s", ErrLocked, info.PID, info.StartedAt.Format(time.RFC3339))
	}

	// Stale lock: remove it and try once more. If the second attempt fails, it
	// is because another instance won the race — and then it won fairly.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale lock: %w", err)
	}
	return Acquire(path)
}

// Read reads who holds the lock.
func Read(path string) (Info, error) {
	data, err := os.ReadFile(path) // path derived from the data directory
	if err != nil {
		return Info{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return Info{}, errors.New("unexpected lock format")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return Info{}, fmt.Errorf("invalid PID in lock: %w", err)
	}
	info := Info{PID: pid}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(lines[1])); err == nil {
		info.StartedAt = t
	}
	if len(lines) > 2 {
		info.Host = strings.TrimSpace(lines[2])
	}
	return info, nil
}

// Release drops the lock. Calling it twice is safe.
func (l *Lock) Release() error {
	if l == nil || !l.held {
		return nil
	}
	l.held = false
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("releasing lock: %w", err)
	}
	return nil
}

// Path returns the lock's path.
func (l *Lock) Path() string { return l.path }
