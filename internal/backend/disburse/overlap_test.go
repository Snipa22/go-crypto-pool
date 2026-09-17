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
//
// Also covers, as a pair proving the overlap gate and the
// (algo, network, currency) scoping interact correctly: the gate is
// scoped to the *Engine INSTANCE, not to the (algo, network,
// currency) triple, so a shared engine still overlap-rejects across
// different currencies
// (TestRunOnce_SameEngineInstanceOverlapsAcrossDifferentCurrencies),
// while the codebase's real deployment pattern of one *Engine per
// currency/wallet means the two independent legs of ALGO_RXM
// genuinely run concurrently without either blocking the other
// (TestRunOnce_SeparateEnginesPerCurrencyRunConcurrentlyWithoutOverlap).

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
		key("RXM", "TESTNET", "XMR"): {
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
		result, err := e.RunOnce(context.Background(), "RXM", "TESTNET", "XMR")
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

// TestRunOnce_SameEngineInstanceOverlapsAcrossDifferentCurrencies
// proves the OVERLAP GATE's runMu is scoped to the *Engine INSTANCE
// only, NOT to the (algo, network, currency) triple: two concurrent
// RunOnce calls on the SAME *Engine for the SAME (algo, network) but
// DIFFERENT currency (RXM/TESTNET/XMR and RXM/TESTNET/XTM) still
// overlap-reject each other exactly like two calls for the identical
// triple would. This is deliberately the "if you get this wrong"
// half of the pair with
// TestRunOnce_SeparateEnginesPerCurrencyRunConcurrentlyWithoutOverlap
// below: it documents, with a real concurrency test rather than a
// comment, exactly why cmd/backend/main.go MUST construct a genuinely
// separate *disburse.Engine per currency/wallet (see
// buildDisburseEngine/buildTariDisburseEngine's own doc comments) --
// if a future change ever made ALGO_RXM's two legs share ONE *Engine
// instance, this same mechanism would incorrectly block one
// currency's cycle while the other is running, which would be a real
// money-availability bug (not a double-payment one, but still wrong).
func TestRunOnce_SameEngineInstanceOverlapsAcrossDifferentCurrencies(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET", "XMR"): {
			{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
		},
		key("RXM", "TESTNET", "XTM"): {
			{ID: 2, PaymentAddress: "bob", PendingBalance: 500},
		},
	}}
	block := make(chan struct{})
	w := &fakeWallet{unlocked: 10000, total: 10000, blockTransfer: block}
	e := New(repo, testConfig(w))

	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})

	type outcome struct {
		currency string
		result   Result
		err      error
	}
	results := make(chan outcome, 2)

	run := func(currency string) {
		ready.Done()
		<-start
		result, err := e.RunOnce(context.Background(), "RXM", "TESTNET", currency)
		results <- outcome{currency, result, err}
	}

	go run("XMR")
	go run("XTM")
	ready.Wait()
	close(start)

	// Same synchronization technique as the test above: deterministically
	// wait for whichever call won the race to be blocked inside the real
	// Transfer call before asserting anything about the loser.
	waitForCount(t, &w.transferCallCount, 1)
	close(block)

	o1 := <-results
	o2 := <-results

	if got := w.transferCallCount.Load(); got != 1 {
		t.Fatalf("wallet Transfer call count = %d, want exactly 1 -- despite the two calls being for DIFFERENT currencies, the shared *Engine instance's runMu must still only let one through", got)
	}

	overlapped, winner := o1, o2
	if overlapped.result.Overlapped == 0 {
		overlapped, winner = o2, o1
	}
	if overlapped.result.Overlapped != 1 {
		t.Fatalf("got results %+v and %+v, want exactly one Result with Overlapped=1 -- the overlap gate does not look at currency at all, only at the *Engine instance", o1, o2)
	}
	if winner.result.Overlapped != 0 {
		t.Fatalf("got results %+v and %+v, want exactly one Result WITHOUT Overlapped set", o1, o2)
	}
	if !errors.Is(overlapped.err, ErrOverlapped) {
		t.Fatalf("overlapped call (currency=%s): got err=%v, want an error satisfying errors.Is(err, ErrOverlapped)", overlapped.currency, overlapped.err)
	}
	if winner.err != nil {
		t.Fatalf("winning call (currency=%s): unexpected error: %v", winner.currency, winner.err)
	}
}

// TestRunOnce_SeparateEnginesPerCurrencyRunConcurrentlyWithoutOverlap
// is this file's other half: it proves that the codebase's ACTUAL
// deployment pattern -- a genuinely separate *disburse.Engine per
// currency/wallet, not a shared instance with a currency argument
// (see cmd/backend/main.go's buildDisburseEngine, for ALGO_RXM's
// primary/XMR leg on the real monero-wallet-rpc connection, and
// buildTariDisburseEngine, for every Tari-family algo including
// ALGO_RXM's secondary/XTM leg on the real Tari wallet GRPC
// connection -- buildTariDisburseEngine's own doc comment says
// explicitly it "is a genuinely SEPARATE *disburse.Engine (not a
// second Target on the Monero one)") -- means two concurrent
// disbursement cycles for the SAME (algo, network) but DIFFERENT
// currency legs of ALGO_RXM do NOT overlap-reject each other at all:
// each currency's own *Engine has its own independent runMu. Proven
// here by actually starting both calls concurrently and confirming,
// via each wallet's own blocked Transfer call, that BOTH are
// simultaneously mid-cycle at once -- neither is serialized behind
// the other, and neither's Result has Overlapped set.
func TestRunOnce_SeparateEnginesPerCurrencyRunConcurrentlyWithoutOverlap(t *testing.T) {
	xmrRepo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET", "XMR"): {
			{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
		},
	}}
	xtmRepo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET", "XTM"): {
			{ID: 2, PaymentAddress: "bob", PendingBalance: 500},
		},
	}}

	xmrBlock := make(chan struct{})
	xtmBlock := make(chan struct{})
	xmrWallet := &fakeWallet{unlocked: 10000, total: 10000, blockTransfer: xmrBlock}
	xtmWallet := &fakeWallet{unlocked: 10000, total: 10000, blockTransfer: xtmBlock}

	// Two genuinely separate *Engine instances -- mirroring
	// buildDisburseEngine/buildTariDisburseEngine constructing two
	// separate engines in cmd/backend/main.go, one per currency/wallet.
	xmrEngine := New(xmrRepo, testConfig(xmrWallet))
	xtmEngine := New(xtmRepo, testConfig(xtmWallet))

	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})

	type outcome struct {
		currency string
		result   Result
		err      error
	}
	results := make(chan outcome, 2)

	run := func(e *Engine, currency string) {
		ready.Done()
		<-start
		result, err := e.RunOnce(context.Background(), "RXM", "TESTNET", currency)
		results <- outcome{currency, result, err}
	}

	go run(xmrEngine, "XMR")
	go run(xtmEngine, "XTM")
	ready.Wait()
	close(start)

	// The key assertion of this test: BOTH wallets must reach their
	// Transfer call (and be blocked inside it) at the same time --
	// if the two engines contended on any shared lock, one of these
	// waits would time out while the other's call sat blocked
	// waiting for a lock that never releases (the other goroutine is
	// itself blocked inside Transfer, not inside the overlap gate).
	waitForCount(t, &xmrWallet.transferCallCount, 1)
	waitForCount(t, &xtmWallet.transferCallCount, 1)

	close(xmrBlock)
	close(xtmBlock)

	o1 := <-results
	o2 := <-results

	for _, o := range []outcome{o1, o2} {
		if o.result.Overlapped != 0 {
			t.Fatalf("currency=%s: got Overlapped=1, want 0 -- separate *Engine instances per currency must never overlap-reject each other", o.currency)
		}
		if o.err != nil {
			t.Fatalf("currency=%s: unexpected error: %v", o.currency, o.err)
		}
		if o.result.BatchesSent != 1 {
			t.Fatalf("currency=%s: got %+v, want exactly one batch sent", o.currency, o.result)
		}
	}
	if got := xmrWallet.transferCallCount.Load(); got != 1 {
		t.Fatalf("XMR wallet Transfer call count = %d, want 1", got)
	}
	if got := xtmWallet.transferCallCount.Load(); got != 1 {
		t.Fatalf("XTM wallet Transfer call count = %d, want 1", got)
	}
}
