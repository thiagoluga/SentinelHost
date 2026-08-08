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

	// sleep is how a pause is taken. nil means sleepCtx, which is the only thing
	// production ever uses.
	//
	// It exists so a test can COUNT pauses instead of timing them. The rule below —
	// never a pause after the last batch — used to be checked by measuring the whole
	// call and requiring it to finish inside twice the time it actually sleeps. That
	// measures the machine as much as the code: on a loaded container it read 248ms
	// against a 200ms ceiling and failed while the code was correct. A suite that
	// reports a fault where there is none teaches its readers to skip the output, which
	// costs more than the test was ever worth.
	sleep func(context.Context, time.Duration) error
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
			if err := b.takePause(ctx); err != nil {
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

// takePause waits out one gap between batches.
//
// A zero sleep field means the real one, so a Batcher built any way at all — the
// constructor, a struct literal, a copy — pauses for real unless something deliberately
// replaced it.
func (b *Batcher) takePause(ctx context.Context) error {
	if b.sleep != nil {
		return b.sleep(ctx, b.Pause)
	}
	return sleepCtx(ctx, b.Pause)
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
