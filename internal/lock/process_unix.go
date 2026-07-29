//go:build unix

package lock

import (
	"os"
	"syscall"
)

// processAlive answers whether the process still exists.
//
// Signal 0 delivers nothing: it only asks the kernel whether the process exists
// and whether we are allowed to signal it. That is the standard way to detect a
// stale lock without depending on /proc, which not every host exposes.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM means the process exists but belongs to another user. On a shared
	// server the PID may have been recycled by another account; treating it as
	// alive is the safe side: at worst the tool waits for the next cycle instead
	// of running twice.
	return os.IsPermission(err)
}
