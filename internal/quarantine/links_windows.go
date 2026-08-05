//go:build windows

package quarantine

import (
	"fmt"
	"os"
)

// otherNamesFor reports additional names for this file's content.
//
// Windows has hard links and its own reparse points, and the link count is reachable only
// through a handle-based call this package does not otherwise need. What is checked here
// is the part that matters and is cheap: that the path is a plain file rather than a link.
//
// The hard-link count is NOT checked on Windows, and that limit is stated rather than
// implied. This project's production target is Linux shared hosting; a Windows workstation
// is where the suite runs, not where files are quarantined. Two defects have already hidden
// behind Windows ignoring POSIX behaviour, so an unchecked case is written down instead of
// being left to look identical to a checked one.
func otherNamesFor(path string) (int, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return 0, fmt.Errorf("reading %s before acting: %w", path, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("%w: %s is a link. Removing it would delete the link and leave "+
			"the file it points at untouched", ErrNotAPlainFile, path)
	}
	if !li.Mode().IsRegular() {
		return 0, fmt.Errorf("%w: %s is not a regular file", ErrNotAPlainFile, path)
	}
	return 0, nil
}
