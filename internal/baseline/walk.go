// Package baseline walks the configured roots, keeps the hash map the
// incremental cycles use, and decides what needs to be re-scanned.
package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
)

// WalkOptions parameterizes the walk.
type WalkOptions struct {
	// Root is the authorized root. Nothing outside it is ever walked.
	Root string
	// Exclude are globs.
	Exclude []string
	// MaxDepth caps the depth from the root.
	MaxDepth int
	// MaxFileSizeBytes: larger files are skipped and COUNTED.
	MaxFileSizeBytes int64
	// MaxFiles cuts the walk short, signalling truncation.
	MaxFiles int
}

// Entry is a file that was found.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	SHA256 string `json:"sha256"`
	Perms  string `json:"perms"`
}

// WalkResult is the result of the walk.
type WalkResult struct {
	Entries []Entry
	// SkippedCounts explains what was left out and why. A file is never skipped
	// silently: the user needs to know that 12 files were not looked at because
	// they were too large, otherwise the coverage looks complete.
	SkippedCounts map[string]int
	// Truncated says MaxFiles was reached. The cycle becomes `partial`.
	Truncated bool
	// Considered is how many entries were evaluated (before the exclusions).
	Considered int
}

// ErrRootUnsafe means the root is invalid.
var ErrRootUnsafe = errors.New("invalid root for a walk")

// Walk walks the root applying the exclusions and limits.
//
// Symlinks are NEVER followed. A link pointing outside the root would take the
// scanner out of the directory the user authorized — and, on a shared server,
// into someone else's account.
func Walk(ctx context.Context, opts WalkOptions) (WalkResult, error) {
	res := WalkResult{SkippedCounts: map[string]int{}}

	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrRootUnsafe, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrRootUnsafe, err)
	}
	if !info.IsDir() {
		return res, fmt.Errorf("%w: %s is not a directory", ErrRootUnsafe, root)
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// An unreadable directory or file does not take down the walk: on
			// shared hosting it is normal to have folders without permission.
			res.SkippedCounts["unreadable"]++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path == root {
				return nil
			}
			if depth(root, path) > opts.MaxDepth {
				res.SkippedCounts["too_deep"]++
				return fs.SkipDir
			}
			if pathmatch.MatchAny(opts.Exclude, path) {
				res.SkippedCounts["excluded"]++
				return fs.SkipDir
			}
			return nil
		}

		res.Considered++

		// Symlink: count it and move on without opening it.
		if d.Type()&fs.ModeSymlink != 0 {
			res.SkippedCounts["symlink"]++
			return nil
		}
		if !d.Type().IsRegular() {
			res.SkippedCounts["not_regular"]++
			return nil
		}
		if pathmatch.MatchAny(opts.Exclude, path) {
			res.SkippedCounts["excluded"]++
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			res.SkippedCounts["unreadable"]++
			return nil
		}
		if opts.MaxFileSizeBytes > 0 && fi.Size() > opts.MaxFileSizeBytes {
			res.SkippedCounts["too_large"]++
			return nil
		}
		if opts.MaxFiles > 0 && len(res.Entries) >= opts.MaxFiles {
			res.Truncated = true
			return filepath.SkipAll
		}

		res.Entries = append(res.Entries, Entry{
			Path:  path,
			Size:  fi.Size(),
			MTime: fi.ModTime().Unix(),
			Perms: fmt.Sprintf("%04o", fi.Mode().Perm()),
		})
		return nil
	})

	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, walkErr
	}
	return res, nil
}

func depth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return 0
	}
	return strings.Count(rel, "/") + 1
}

// HashFile computes a file's sha256.
func HashFile(path string) (string, error) {
	f, err := os.Open(path) // path comes from walking the configured root
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashEntries fills in the entries' sha256.
//
// An unreadable entry is dropped from the result and counted, rather than kept
// with an empty hash: an empty hash would become an invalid deduplication key in
// the consensus.
func HashEntries(ctx context.Context, entries []Entry, skipped map[string]int) []Entry {
	out := entries[:0]
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		sum, err := HashFile(e.Path)
		if err != nil {
			if skipped != nil {
				skipped["unreadable"]++
			}
			continue
		}
		e.SHA256 = sum
		out = append(out, e)
	}
	return out
}
