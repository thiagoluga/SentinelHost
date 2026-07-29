//go:build windows

package quarantine

import "os"

// On Windows there is no POSIX uid. The real target is Linux userland (D-002).
func ownerOf(os.FileInfo) string { return "" }
