package disburse

// overlap_test.go is the regression suite for the OVERLAP GATE (see
// disburse.go's package doc comment and RunOnce's own doc comment):
// Engine.RunOnce previously had NO mutual exclusion of any kind, so
// invoking the same *Engine instance's RunOnce twice concurrently for
// the same (algo, network) could make both calls see the same payable
// balance rows and both call the real wallet.Transfer RPC for them --
// a genuine double-payment of real money. This is a REAL concurrency
// test, not a unit test that happens to pass: it spawns two goroutines
// that call RunOnce at (as close as possible to) the same instant on
// the SAME Engine and proves, via a fake wallet that blocks inside
// Transfer until released, that only one of them ever reaches the
// wallet at all.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunOnce_OverlapGateAllowsExactlyOneConcurrentCallThrough spawns
// exactly two goroutines that both call the same *Engine's RunOnce at
// (as close as possible to) the same instant, synchronized via a
// shared "go" signal so they genuinely race rather than accidentally
// serialize due to goroutine scheduling. It asserts, after both
// goroutines return:
//
//   - the fake wallet's Transfer call counter is exactly 1 (not 0,
//     not 2) -- proving only ONE goroutine ever reached the wallet;
//   - exactly one of the two Results has Overlapped set and the
//     other does not;
//   - the overlapped one's error satisfies errors.Is(err, ErrOverlapped);
//   - the overlapped call made literally zero repository/wallet
//     calls, verified via the fake repository's PayableBalances call
//     counter also being exactly 1 -- proving the rejected call never
//     even reached the balance query.
func TestRunOnce_OverlapGateAllowsExactlyOneConcurrentCallThrough(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
		},
	}}
	// block is closed (not sent-on) so that BOTH a buggy
	// no-overlap-guard run (where two goroutines could reach
	// Transfer) and the correct single-winner run are released the
	// same way once the test is ready to let the winner finish.
	block := make(chan struct{})
	w := &fakeWallet{unlocked: 10000, total: 10000, blockTransfer: block}
	e := New(repo, testConfig(w))

	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})

	type outcome struct {
		result Result
		err    error
	}
	results := make(chan outcome, 2)

	run := func() {
		ready.Done()
		<-start // wait for the shared "go" signal: both goroutines fire together, not one-after-another.
		result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
		results <- outcome{result, err}
	}

	go run()
	go run()
	ready.Wait() // both goroutines are launched and waiting on start.
	close(start) // release both at once: this is the actual race.

	// Deterministically wait for the winner to have reached (and be
	// blocked inside) the real Transfer call, rather than sleeping
	// an arbitrary amount -- this is what proves the loser's
	// rejection is genuine (it returned despite the winner still
	// being mid-cycle), not just an artifact of timing.
	waitForCount(t, &w.transferCallCount, 1)

	// Now release the blocked winner so it can finish the cycle.
	close(block)

	o1 := <-results
	o2 := <-results

	if got := w.transferCallCount.Load(); got != 1 {
		t.Fatalf("wallet Transfer call count = %d, want exactly 1 -- the overlap gate must let only one goroutine ever reach the real wallet call", got)
	}
	if got := repo.payableBalancesCalls.Load(); got != 1 {
		t.Fatalf("repo PayableBalances call count = %d, want exactly 1 -- the rejected call must make no repository call at all", got)
	}

	overlapped, winner := o1, o2
	if overlapped.result.Overlapped == 0 {
		overlapped, winner = o2, o1
	}
	if overlapped.result.Overlapped != 1 {
		t.Fatalf("got results %+v and %+v, want exactly one Result with Overlapped=1", o1.result, o2.result)
	}
	if winner.result.Overlapped != 0 {
		t.Fatalf("got results %+v and %+v, want exactly one Result WITHOUT Overlapped set", o1.result, o2.result)
	}
	if !errors.Is(overlapped.err, ErrOverlapped) {
		t.Fatalf("overlapped call: got err=%v, want an error satisfying errors.Is(err, ErrOverlapped)", overlapped.err)
	}

	if winner.err != nil {
		t.Fatalf("winning call: unexpected error: %v", winner.err)
	}
	if winner.result.BatchesSent != 1 || winner.result.TotalSent != 500 {
		t.Fatalf("winning call: got %+v, want the single batch actually sent (500 atomic units)", winner.result)
	}
	if len(repo.sentCalls) != 1 {
		t.Fatalf("got %d CompletePayoutSent calls, want exactly 1", len(repo.sentCalls))
	}
}

// waitForCount polls c until it reaches (or exceeds) want, failing
// the test if that does not happen within a generous deadline --
// deterministic synchronization on the winner's real progress rather
// than a fixed sleep, per this file's doc comment.
func waitForCount(t *testing.T, c *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for counter to reach %d (got %d)", want, c.Load())
}
