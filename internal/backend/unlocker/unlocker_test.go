package unlocker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/chain"
)

// fakeRepo is an in-memory Repository test double.
type fakeRepo struct {
	pending      map[string][]Block
	pendingErr   error
	statusCalls  []statusCall
	statusErrFor map[int64]error
	// onStatus, if non-nil, is called on every successful
	// SetBlockStatus — used by the ordering test below to record when
	// the status write happens relative to the payout.
	onStatus func()
}

type statusCall struct {
	id              int64
	valid, unlocked bool
}

func (f *fakeRepo) PendingBlocks(_ context.Context, algo string) ([]Block, error) {
	if f.pendingErr != nil {
		return nil, f.pendingErr
	}
	return f.pending[algo], nil
}

func (f *fakeRepo) SetBlockStatus(_ context.Context, id int64, valid, unlocked bool) error {
	if err, ok := f.statusErrFor[id]; ok {
		return err
	}
	f.statusCalls = append(f.statusCalls, statusCall{id: id, valid: valid, unlocked: unlocked})
	if f.onStatus != nil {
		f.onStatus()
	}
	return nil
}

// fakeVerifier is an in-memory chain.ChainVerifier test double, keyed
// by hash.
type fakeVerifier struct {
	results map[string]chain.VerifyResult
	errs    map[string]error
}

func (f *fakeVerifier) Verify(_ context.Context, hashHex string, _ int64) (chain.VerifyResult, error) {
	if err, ok := f.errs[hashHex]; ok {
		return chain.VerifyResult{}, err
	}
	return f.results[hashHex], nil
}

// fakePayoutTrigger records every Block it's invoked with, so tests
// can assert on exactly what value made it through checkBlock's
// override logic (see TestRunOnce_PayoutTriggerReceivesFreshRewardNotStaleValue).
type fakePayoutTrigger struct {
	calls []Block
	err   error
	// onCall, if non-nil, is called on every invocation — used by the
	// ordering test below.
	onCall func()
}

func (f *fakePayoutTrigger) TriggerPayout(_ context.Context, b Block) error {
	f.calls = append(f.calls, b)
	if f.onCall != nil {
		f.onCall()
	}
	return f.err
}

func TestRunOnce_MaturedBlock(t *testing.T) {
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {{ID: 1, Algo: "RXM", Hash: "deadbeef", Height: 100}},
	}}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"deadbeef": {Found: true, Confirmations: 60},
	}}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}})

	result := u.RunOnce(context.Background())
	if result.Matured != 1 || result.Checked != 1 || result.Orphaned != 0 || result.Pending != 0 || result.Errors != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 matured / 1 checked / 0 else", result)
	}
	if len(repo.statusCalls) != 1 || repo.statusCalls[0] != (statusCall{id: 1, valid: true, unlocked: true}) {
		t.Fatalf("RunOnce: got statusCalls=%+v, want a single {id:1 valid:true unlocked:true} call", repo.statusCalls)
	}
}

func TestRunOnce_OrphanedBlock(t *testing.T) {
	repo := &fakeRepo{pending: map[string][]Block{
		"RXT": {{ID: 2, Algo: "RXT", Hash: "aabbcc", Height: 50}},
	}}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"aabbcc": {Found: true, Orphaned: true, CanonicalHash: "112233"},
	}}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXT": {Verifier: verifier, MaturityDepth: 6},
	}})

	result := u.RunOnce(context.Background())
	if result.Orphaned != 1 || result.Matured != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 orphaned / 0 matured", result)
	}
	if len(repo.statusCalls) != 1 || repo.statusCalls[0] != (statusCall{id: 2, valid: false, unlocked: true}) {
		t.Fatalf("RunOnce: got statusCalls=%+v, want a single {id:2 valid:false unlocked:true} call", repo.statusCalls)
	}
}

func TestRunOnce_NotYetFound_LeftPending(t *testing.T) {
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {{ID: 3, Algo: "RXM", Hash: "notseen", Height: 999}},
	}}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{}} // no entry -> zero value, Found=false
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}})

	result := u.RunOnce(context.Background())
	if result.Pending != 1 || result.Matured != 0 || result.Orphaned != 0 || result.Errors != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 pending only", result)
	}
	if len(repo.statusCalls) != 0 {
		t.Fatalf("RunOnce: got statusCalls=%+v, want none for a not-found block", repo.statusCalls)
	}
}

func TestRunOnce_NotYetMature_LeftPending(t *testing.T) {
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {{ID: 4, Algo: "RXM", Hash: "confirming", Height: 100}},
	}}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"confirming": {Found: true, Confirmations: 5},
	}}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}})

	result := u.RunOnce(context.Background())
	if result.Pending != 1 || result.Matured != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 pending / 0 matured (5 < 60 confirmations)", result)
	}
	if len(repo.statusCalls) != 0 {
		t.Fatalf("RunOnce: got statusCalls=%+v, want none", repo.statusCalls)
	}
}

func TestRunOnce_VerifyErrorIsCountedAndLeftPending(t *testing.T) {
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {{ID: 5, Algo: "RXM", Hash: "broken", Height: 100}},
	}}
	verifier := &fakeVerifier{errs: map[string]error{"broken": errors.New("rpc down")}}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}})

	result := u.RunOnce(context.Background())
	if result.Errors != 1 || result.Matured != 0 || result.Orphaned != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 error only", result)
	}
	if len(repo.statusCalls) != 0 {
		t.Fatalf("RunOnce: got statusCalls=%+v, want none", repo.statusCalls)
	}
}

func TestRunOnce_PendingBlocksErrorIsCounted(t *testing.T) {
	repo := &fakeRepo{pendingErr: errors.New("db down")}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: &fakeVerifier{}, MaturityDepth: 60},
	}})

	result := u.RunOnce(context.Background())
	if result.Errors != 1 || result.Checked != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 error / 0 checked", result)
	}
}

func TestRunOnce_UnconfiguredAlgoIsUntouched(t *testing.T) {
	// Only "RXM" is in Coins — an "RXT" entry in the fake repo's
	// pending map must never be queried/touched, mirroring the "algos
	// with no CoinConfig entry are never polled" contract documented
	// on Config.Coins.
	repo := &fakeRepo{pending: map[string][]Block{
		"RXT": {{ID: 6, Algo: "RXT", Hash: "untouched", Height: 1}},
	}}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: &fakeVerifier{}, MaturityDepth: 60},
	}})

	result := u.RunOnce(context.Background())
	if result.Checked != 0 {
		t.Fatalf("RunOnce: got Checked=%d, want 0 (RXT not configured)", result.Checked)
	}
}

func TestSetBlockStatusFailureIsCountedAsError(t *testing.T) {
	repo := &fakeRepo{
		pending: map[string][]Block{
			"RXM": {{ID: 7, Algo: "RXM", Hash: "deadbeef", Height: 100}},
		},
		statusErrFor: map[int64]error{7: errors.New("write failed")},
	}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"deadbeef": {Found: true, Confirmations: 60},
	}}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}})

	result := u.RunOnce(context.Background())
	if result.Errors != 1 || result.Matured != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 error / 0 matured when SetBlockStatus fails", result)
	}
}

// TestRunOnce_PayoutFailureLeavesBlockPendingForAutomaticRetry is the
// direct regression test for finding #5's unlocker half: a matured
// block whose payout fails must NOT be marked unlocked.
//
// The old code marked it valid=TRUE/unlocked=TRUE first and then
// merely logged a payout failure, which dropped the block out of
// PendingBlocks (`valid = TRUE AND unlocked = FALSE`) forever — the
// payout was never retried by anything and no durable marker existed
// that it was owed. Now nothing is written at all, so the block stays
// in the pending queue and the next pass retries it.
func TestRunOnce_PayoutFailureLeavesBlockPendingForAutomaticRetry(t *testing.T) {
	reward := int64(600000000000)
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {{ID: 8, Algo: "RXM", Hash: "deadbeef", Height: 100, PoolType: "SOLO", Difficulty: 1, Value: &reward}},
	}}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"deadbeef": {Found: true, Confirmations: 60, Reward: reward},
	}}
	trigger := &fakePayoutTrigger{err: errors.New("payout exploded")}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}, PayoutTrigger: trigger})

	result := u.RunOnce(context.Background())
	if result.PayoutRetries != 1 || result.Matured != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 payout retry / 0 matured", result)
	}
	if len(repo.statusCalls) != 0 {
		t.Fatalf("RunOnce: got statusCalls=%+v, want NONE — marking the block unlocked would drop it out of PendingBlocks and lose the payout forever", repo.statusCalls)
	}

	// The next pass must pick the very same block up again and retry
	// the payout, with no operator intervention. Let the payout
	// succeed this time and confirm the block is finally unlocked.
	trigger.err = nil
	result = u.RunOnce(context.Background())
	if result.Matured != 1 || result.PayoutRetries != 0 {
		t.Fatalf("RunOnce (retry pass): got %+v, want 1 matured / 0 payout retries", result)
	}
	if len(trigger.calls) != 2 {
		t.Fatalf("TriggerPayout called %d times across both passes, want 2 (the failure must be retried automatically)", len(trigger.calls))
	}
	if len(repo.statusCalls) != 1 || repo.statusCalls[0] != (statusCall{id: 8, valid: true, unlocked: true}) {
		t.Fatalf("RunOnce (retry pass): got statusCalls=%+v, want a single {id:8 valid:true unlocked:true} call once the payout succeeded", repo.statusCalls)
	}
}

// TestRunOnce_PayoutRunsBeforeTheStatusWrite pins the ordering itself,
// independently of either call failing: `unlocked = TRUE` is this
// schema's only "handled" marker, so it must never be written before
// the money side has actually succeeded. See checkBlock's doc comment.
func TestRunOnce_PayoutRunsBeforeTheStatusWrite(t *testing.T) {
	var order []string
	repo := &fakeRepo{
		pending: map[string][]Block{
			"RXM": {{ID: 9, Algo: "RXM", Hash: "deadbeef", Height: 100, PoolType: "SOLO", Difficulty: 1}},
		},
		onStatus: func() { order = append(order, "status") },
	}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"deadbeef": {Found: true, Confirmations: 60, Reward: 1},
	}}
	trigger := &fakePayoutTrigger{onCall: func() { order = append(order, "payout") }}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}, PayoutTrigger: trigger})

	if result := u.RunOnce(context.Background()); result.Matured != 1 {
		t.Fatalf("RunOnce: got %+v, want 1 matured", result)
	}
	if len(order) != 2 || order[0] != "payout" || order[1] != "status" {
		t.Fatalf("call order = %v, want [payout status] — the status write must come strictly after a successful payout", order)
	}
}

// TestRunOnce_OrphanedBlockNeverTriggersAPayout confirms the reorder
// did not accidentally start paying out reorged blocks: an orphan is
// still marked invalid+unlocked with no payout attempted at all.
func TestRunOnce_OrphanedBlockNeverTriggersAPayout(t *testing.T) {
	repo := &fakeRepo{pending: map[string][]Block{
		"RXT": {{ID: 10, Algo: "RXT", Hash: "aabbcc", Height: 50, PoolType: "PPLNS"}},
	}}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"aabbcc": {Found: true, Orphaned: true, Reward: 999},
	}}
	trigger := &fakePayoutTrigger{}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXT": {Verifier: verifier, MaturityDepth: 6},
	}, PayoutTrigger: trigger})

	if result := u.RunOnce(context.Background()); result.Orphaned != 1 {
		t.Fatalf("RunOnce: got %+v, want 1 orphaned", result)
	}
	if len(trigger.calls) != 0 {
		t.Fatalf("TriggerPayout called %d times for an orphaned block, want 0", len(trigger.calls))
	}
}

// TestRunOnce_PayoutTriggerReceivesTheRealBlockID confirms the
// `blocks.id` reaches the trigger: it is the idempotency key the
// whole `block_payouts` ledger hangs off (see payout.MaturedBlock), so
// a zero/wrong id here would silently defeat the entire mechanism.
func TestRunOnce_PayoutTriggerReceivesTheRealBlockID(t *testing.T) {
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {{ID: 4242, Algo: "RXM", Hash: "deadbeef", Height: 100, PoolType: "SOLO", Difficulty: 1}},
	}}
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"deadbeef": {Found: true, Confirmations: 60, Reward: 7},
	}}
	trigger := &fakePayoutTrigger{}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}, PayoutTrigger: trigger})

	u.RunOnce(context.Background())
	if len(trigger.calls) != 1 {
		t.Fatalf("TriggerPayout called %d times, want 1", len(trigger.calls))
	}
	if got := trigger.calls[0].ID; got != 4242 {
		t.Fatalf("TriggerPayout received block ID=%d, want 4242 (the payout idempotency key)", got)
	}
}

func TestRunLoop_StopsOnContextCancel(t *testing.T) {
	repo := &fakeRepo{}
	u := New(repo, Config{
		Coins:        map[string]CoinConfig{"RXM": {Verifier: &fakeVerifier{}, MaturityDepth: 1}},
		PollInterval: time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		u.RunLoop(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunLoop did not return after context cancellation")
	}
}

func TestRunLoop_ZeroPollIntervalReturnsImmediately(t *testing.T) {
	u := New(&fakeRepo{}, Config{PollInterval: 0})
	done := make(chan struct{})
	go func() {
		u.RunLoop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunLoop with PollInterval<=0 did not return immediately")
	}
}

// TestRunOnce_PayoutTriggerReceivesFreshRewardNotStaleValue is the
// real regression test for a real correctness bug: PayoutTrigger must
// receive the block's REAL, CURRENT reward as reported by this same
// poll pass's chain.VerifyResult.Reward, never whatever stale value
// blocks.value happened to hold from submission time. Deliberately
// configures the pending block's Value to a wrong/stale number and
// confirms checkBlock overwrites it before invoking the trigger.
func TestRunOnce_PayoutTriggerReceivesFreshRewardNotStaleValue(t *testing.T) {
	staleValue := int64(999999999) // deliberately wrong -- must never reach the trigger
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {{ID: 1, Algo: "RXM", Hash: "deadbeef", Height: 100, PoolType: "SOLO", Difficulty: 12345, Value: &staleValue}},
	}}
	const freshReward = int64(600000000000) // the real, current reward Verify reports
	verifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"deadbeef": {Found: true, Confirmations: 60, Reward: freshReward},
	}}
	trigger := &fakePayoutTrigger{}
	u := New(repo, Config{Coins: map[string]CoinConfig{
		"RXM": {Verifier: verifier, MaturityDepth: 60},
	}, PayoutTrigger: trigger})

	result := u.RunOnce(context.Background())
	if result.Matured != 1 {
		t.Fatalf("RunOnce: got %+v, want 1 matured", result)
	}
	if len(trigger.calls) != 1 {
		t.Fatalf("PayoutTrigger.TriggerPayout called %d times, want 1", len(trigger.calls))
	}
	got := trigger.calls[0]
	if got.Value == nil {
		t.Fatal("PayoutTrigger received a nil Value, want the fresh reward")
	}
	if *got.Value != freshReward {
		t.Fatalf("PayoutTrigger received Value=%d, want the fresh chain.VerifyResult.Reward=%d (stale blocks.value was %d)",
			*got.Value, freshReward, staleValue)
	}
	// Confirm the other pass-through fields (needed for dispatch)
	// still arrive correctly alongside the corrected Value.
	if got.PoolType != "SOLO" || got.Difficulty != 12345 {
		t.Fatalf("PayoutTrigger received PoolType=%q Difficulty=%d, want SOLO/12345 unchanged", got.PoolType, got.Difficulty)
	}
}
