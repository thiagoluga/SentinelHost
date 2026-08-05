package pmf

import (
	"context"
	"fmt"
	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// maxRulesBytes caps the rules download. php.yar is tens of KB; 16 MiB is
// generous and keeps an anomalous response from filling the account's disk.
const maxRulesBytes = 16 << 20

// downloadFile downloads a file to dest atomically.
//
// Writing straight to the destination would leave half-written rules if the
// connection dropped mid-way — and truncated rules make yara fail on every
// following cycle, turning a momentary network glitch into a permanently dead
// engine.
// downloadVerified is the only way this package fetches anything.
//
// There is no unverified variant to reach for. A helper that skips the digest is a helper
// somebody calls.
func downloadVerified(ctx context.Context, pin adapter.Pinned, dest string) error {
	return downloadPinned(ctx, pin, dest, true)
}

// downloadPinned downloads and refuses anything whose digest is not the pinned one.
//
// The digest is computed while the bytes stream past, and the file reaches its final name
// only after it matches. Checking afterwards by re-reading the path would be a race
// anything sharing the temporary directory could win, and on shared hosting that
// directory is not private.
func downloadPinned(ctx context.Context, pin adapter.Pinned, dest string, verify bool) error {
	url := pin.URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("building the download: %w", err)
	}
	req.Header.Set("User-Agent", "SentinelHost (+https://github.com/thiagoluga/SentinelHost)")

	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the download of %s answered %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return fmt.Errorf("creating the temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	h, sum := adapter.Hasher()
	var w io.Writer = tmp
	if verify {
		w = io.MultiWriter(tmp, h)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxRulesBytes))
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing the download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing the download: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("the download of %s came back empty", url)
	}
	if verify {
		// Before the rename, so a rejected file never exists under the name the engine
		// loads. The temporary file is removed by the deferred cleanup either way.
		if err := pin.Verify(sum()); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("adjusting permissions: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("installing at %s: %w", dest, err)
	}
	return nil
}
