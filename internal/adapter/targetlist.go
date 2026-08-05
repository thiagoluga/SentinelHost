package adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteTargetList materializes a scan scope as a newline-separated file and returns its
// path plus a cleanup function.
//
// Several engines accept the scope only as a file (`yara --scan-list`,
// `maldet -f/--file-list`) rather than as arguments, and getting this wrong is
// expensive in a specific way: an engine that silently falls back to walking the whole
// root turns an incremental cycle into a full one. On maldet that is the difference
// between ~100s and the 28m36s a 3,000-file WordPress measured in the validation
// container.
//
// Two details are load-bearing:
//
//   - The file goes under the account's own DataDir, mode 0700, and never into the
//     shared system temp directory. It names every path about to be scanned, which on a
//     compromised site is a map of where the interesting files are.
//   - It ends with a trailing newline. Both engines read it with a line loop that drops
//     a final line lacking one — silently, so the last file of every scan would go
//     unexamined while the report still counted it.
//
// A path that cannot be expressed in this format is REFUSED and returned to the caller to
// be counted. It is not silently dropped: see PathIsExpressible for what one line
// containing a newline does to the scope.
func WriteTargetList(dataDir, engineSlug string, paths []string) (string, func(), []string, error) {
	noop := func() {}
	paths, refused := FilterExpressiblePaths(paths)
	dir := filepath.Join(dataDir, "engines", engineSlug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", noop, refused, fmt.Errorf("creating the working directory: %w", err)
	}
	f, err := os.CreateTemp(dir, "targets-*.txt")
	if err != nil {
		return "", noop, refused, fmt.Errorf("creating the target list: %w", err)
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := f.WriteString(strings.Join(paths, "\n") + "\n"); err != nil {
		_ = f.Close()
		cleanup()
		return "", noop, refused, fmt.Errorf("writing the target list: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", noop, refused, fmt.Errorf("closing the target list: %w", err)
	}
	return name, cleanup, refused, nil
}
