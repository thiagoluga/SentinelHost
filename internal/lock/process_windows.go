//go:build windows

package lock

import "os"

// processAlive on Windows: FindProcess only fails when the process does not
// exist. The production target is Linux (DECISIONS.md D-002); this version
// exists so the test suite runs on the workstation.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.FindProcess(pid)
	return err == nil
}
