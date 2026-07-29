package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Baseline is the path->state map the incremental cycles use.
type Baseline struct {
	Version   int              `json:"version"`
	UpdatedAt time.Time        `json:"updated_at"`
	Roots     []string         `json:"roots"`
	Files     map[string]Entry `json:"files"`
}

// New creates an empty baseline.
func New(roots []string) *Baseline {
	return &Baseline{Version: 1, Roots: roots, Files: map[string]Entry{}}
}

// Load reads the baseline from disk. An absent file returns an empty baseline,
// not an error: the first run has no baseline, and that is normal.
func Load(path string, roots []string) (*Baseline, error) {
	data, err := os.ReadFile(path) // path derived from the data directory
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(roots), nil
		}
		return New(roots), fmt.Errorf("reading the baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		// A corrupted baseline must not block protection. Starting over costs one
		// full scan; blocking costs all of the protection.
		return New(roots), fmt.Errorf("corrupted baseline, starting over from scratch: %w", err)
	}
	if b.Files == nil {
		b.Files = map[string]Entry{}
	}
	return &b, nil
}

// Save writes the baseline atomically.
//
// Atomic because the hosting kills long processes: an interrupted write would
// leave a truncated baseline, and a truncated baseline makes the next cycle
// re-scan the whole site believing everything changed.
func (b *Baseline) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating the baseline directory: %w", err)
	}
	b.UpdatedAt = time.Now()

	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("serializing the baseline: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*.json")
	if err != nil {
		return fmt.Errorf("creating the temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing the baseline: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing the baseline: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing the baseline: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("adjusting the baseline's permissions: %w", err)
	}
	return os.Rename(tmpName, path)
}

// Diff is the result of comparing the disk against the baseline.
type Diff struct {
	// New are files that did not exist before.
	New []Entry
	// Modified are files whose content changed.
	Modified []Entry
	// Unchanged is the count of those that stayed the same.
	Unchanged int
	// Removed are the paths that vanished since the last cycle.
	Removed []string
}

// Targets returns the paths that need to be scanned in this cycle.
func (d Diff) Targets() []string {
	out := make([]string, 0, len(d.New)+len(d.Modified))
	for _, e := range d.New {
		out = append(out, e.Path)
	}
	for _, e := range d.Modified {
		out = append(out, e.Path)
	}
	return out
}

// Compare finds out what changed since the last cycle.
//
// The comparison uses size and mtime as a cheap filter and the sha256 as the
// tie-breaker. Trusting mtime alone would be naive: `touch` is the first thing an
// attacker does to hide a change. Trusting the hash alone would mean reading the
// whole site every hour, which the hosting account cannot take.
func (b *Baseline) Compare(current []Entry) Diff {
	var d Diff
	seen := make(map[string]bool, len(current))

	for _, e := range current {
		seen[e.Path] = true
		previous, existed := b.Files[e.Path]
		switch {
		case !existed:
			d.New = append(d.New, e)
		case e.SHA256 != "" && previous.SHA256 != "" && e.SHA256 != previous.SHA256:
			d.Modified = append(d.Modified, e)
		case e.SHA256 == "" && (e.Size != previous.Size || e.MTime != previous.MTime):
			// Still no hash computed: the size+mtime pair is the cheap filter that
			// decides WHO deserves to be hashed.
			d.Modified = append(d.Modified, e)
		default:
			d.Unchanged++
		}
	}

	for path := range b.Files {
		if !seen[path] {
			d.Removed = append(d.Removed, path)
		}
	}
	return d
}

// NeedsHash returns the entries whose size+mtime pair changed.
//
// It is the step that makes the incremental cycle cheap: only these files have to
// be read from disk to compute a hash.
func (b *Baseline) NeedsHash(current []Entry) []Entry {
	var out []Entry
	for _, e := range current {
		previous, existed := b.Files[e.Path]
		if !existed || previous.Size != e.Size || previous.MTime != e.MTime || previous.SHA256 == "" {
			out = append(out, e)
		}
	}
	return out
}

// Update applies the current state to the baseline.
func (b *Baseline) Update(current []Entry, removed []string) {
	if b.Files == nil {
		b.Files = map[string]Entry{}
	}
	for _, e := range current {
		if e.SHA256 == "" {
			// An entry with no hash is an intermediate state; writing it would make
			// the next cycle believe it already knows the file.
			if previous, ok := b.Files[e.Path]; ok {
				e.SHA256 = previous.SHA256
			} else {
				continue
			}
		}
		b.Files[e.Path] = e
	}
	for _, p := range removed {
		delete(b.Files, p)
	}
}

// Get returns the known entry for a path.
func (b *Baseline) Get(path string) (Entry, bool) {
	e, ok := b.Files[path]
	return e, ok
}

// Len returns how many files the baseline knows about.
func (b *Baseline) Len() int { return len(b.Files) }
