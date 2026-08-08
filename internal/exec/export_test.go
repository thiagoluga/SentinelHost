package exec

import (
	"context"
	"time"
)

// SetSleepForTest replaces how a Batcher takes its pause.
//
// In a _test.go file, so it exists only when the test binary is built and cannot be
// reached by anything that imports this package. The seam stays unexported in production
// and the public API does not grow a knob whose only caller is a test.
//
// What it buys: the pauses can be COUNTED and placed in order, rather than inferred from
// how long the whole call took. Timing was the original approach and it measured the
// machine — see the comment on Batcher.sleep.
func SetSleepForTest(b *Batcher, fn func(context.Context, time.Duration) error) {
	b.sleep = fn
}
