//go:build windows

package quarantine

import "os"

// No Windows nao ha uid POSIX. O alvo real e Linux userland (D-002).
func ownerOf(os.FileInfo) string { return "" }
