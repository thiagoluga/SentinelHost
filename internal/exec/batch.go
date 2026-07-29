package exec

import (
	"context"
	"time"
)

// Batcher splits a file list into batches and pauses between them.
//
// The pause is what separates a tolerated scanner from one that gets the account
// suspended: without it, a cycle over 20,000 files keeps the CPU busy end to
// end, and the host's resource dashboard only sees continuous usage.
type Batcher struct {
	Size  int
	Pause time.Duration
}

// NewBatcher creates a Batcher with safe minimums.
func NewBatcher(size int, pause time.Duration) *Batcher {
	if size <= 0 {
		size = 200
	}
	if pause < 0 {
		pause = 0
	}
	return &Batcher{Size: size, Pause: pause}
}

// Each calls fn for every batch, pausing between them.
//
// The pause happens BETWEEN batches, never after the last one: a cycle should
// not end by sleeping for nothing.
func (b *Batcher) Each(ctx context.Context, items []string, fn func(context.Context, []string) error) error {
	for i := 0; i < len(items); i += b.Size {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(i+b.Size, len(items))

		if err := fn(ctx, items[i:end]); err != nil {
			return err
		}

		if end < len(items) && b.Pause > 0 {
			if err := sleepCtx(ctx, b.Pause); err != nil {
				return err
			}
		}
	}
	return nil
}

// Batches returns the batches without running anything (useful for reporting
// and tests).
func (b *Batcher) Batches(items []string) [][]string {
	var out [][]string
	for i := 0; i < len(items); i += b.Size {
		out = append(out, items[i:min(i+b.Size, len(items))])
	}
	return out
}

// sleepCtx sleeps while respecting cancellation. A pause that ignores the
// context would make the `scan` command slow to answer a Ctrl-C.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
