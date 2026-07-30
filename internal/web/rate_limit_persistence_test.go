package web

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/store"
)

// The brute-force lock-out has to survive the process, not just the request.
//
// It used to be a map in memory. That works for exactly one deployment shape — `serve`,
// where a single process sees every request — and fails silently for every other one.
// Under any per-request model the map arrives empty, so the lock-out does not exist
// while the panel looks and behaves exactly as before, and nothing anywhere says the
// protection was switched off.
//
// These tests open a SECOND limiter against the SAME database, which is what a second
// process would see. If the count does not cross, the protection is decorative.

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestTheLockOutSurvivesANewProcess(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Unix(1785000000, 0)
	const ip = "203.0.113.7"

	// Process one: exhaust the allowance.
	first := newRateLimiter(st, 3)
	for i := range 3 {
		if !first.allow(ctx, ip, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("attempt %d was refused before the limit", i+1)
		}
	}
	if first.allow(ctx, ip, now.Add(3*time.Second)) {
		t.Fatal("the fourth attempt was allowed within the same process")
	}

	// Process two: a brand-new limiter, as a CGI invocation would build.
	second := newRateLimiter(st, 3)
	if second.allow(ctx, ip, now.Add(4*time.Second)) {
		t.Error("a fresh process allowed the attempt: the lock-out did not survive, " +
			"so every per-request deployment has no brute-force protection at all")
	}
}

func TestTheWindowStillSlides(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Unix(1785000000, 0)
	const ip = "203.0.113.8"

	r := newRateLimiter(st, 2)
	r.allow(ctx, ip, now)
	r.allow(ctx, ip, now.Add(time.Second))
	if r.allow(ctx, ip, now.Add(2*time.Second)) {
		t.Fatal("the limit did not apply")
	}
	// Past the window, the old attempts must stop counting. Otherwise one burst pins an
	// IP out of their own panel indefinitely.
	if !r.allow(ctx, ip, now.Add(2*time.Minute)) {
		t.Error("an attempt after the window was still refused: the window is not sliding")
	}
}

func TestASuccessfulLoginForgetsTheIP(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Unix(1785000000, 0)
	const ip = "203.0.113.9"

	r := newRateLimiter(st, 2)
	r.allow(ctx, ip, now)
	r.allow(ctx, ip, now.Add(time.Second))
	r.reset(ctx, ip)

	if !newRateLimiter(st, 2).allow(ctx, ip, now.Add(2*time.Second)) {
		t.Error("after a successful login the IP is still counted, in a new process too")
	}
}

// Two IPs must not share a budget: one attacker would otherwise lock everyone else out.
func TestOneIPDoesNotConsumeAnothersAllowance(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Unix(1785000000, 0)

	r := newRateLimiter(st, 2)
	r.allow(ctx, "198.51.100.1", now)
	r.allow(ctx, "198.51.100.1", now.Add(time.Second))
	if !r.allow(ctx, "198.51.100.2", now.Add(2*time.Second)) {
		t.Error("a different IP was refused because of the first one's attempts")
	}
}

// Housekeeping has to be able to remove counters left by an IP that tried once and never
// returned, or the settings table grows with the internet rather than with the account.
func TestStaleCountersCanBePruned(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	const ip = "198.51.100.55"

	newRateLimiter(st, 5).allow(ctx, ip, time.Now())
	if got, _ := st.RecentLoginAttempts(ctx, ip, time.Now().Add(-time.Minute)); len(got) != 1 {
		t.Fatalf("the attempt was not recorded (%d)", len(got))
	}
	if _, err := st.PruneLoginAttempts(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("pruning: %v", err)
	}
	if got, _ := st.RecentLoginAttempts(ctx, ip, time.Now().Add(-time.Minute)); len(got) != 0 {
		t.Errorf("the counter survived pruning (%d entries)", len(got))
	}
}

// A store error must not lock the legitimate owner out of their own panel. The failure
// is loud elsewhere; turning a database hiccup into a denial of service against the one
// person entitled to log in would be the worse trade.
func TestAStoreFailureAllowsTheAttemptRatherThanLockingTheOwnerOut(t *testing.T) {
	st := testStore(t)
	_ = st.Close() // every query from here on fails

	if !newRateLimiter(st, 1).allow(context.Background(), "203.0.113.10", time.Now()) {
		t.Error("a broken store refused the login: the owner is locked out of their own panel")
	}
}
