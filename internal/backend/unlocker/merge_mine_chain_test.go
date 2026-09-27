package unlocker

import (
	"context"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/chain"
)

// strp is a tiny *string helper for building Block.MergeMineChain
// test fixtures inline.
func strp(s string) *string { return &s }

// TestRunOnce_MergeMineChain_RoutesToItsOwnVerifier is this task's
// own required regression test: a single RXM merge-mine PoW
// submission can independently clear the primary (Monero) leg, the
// merge-mined-chain (Tari) leg, or both -- each becomes its OWN
// pending blocks row (MergeMineChain nil vs "TARI"), and each must be
// verified/matured against its OWN chain.ChainVerifier, never the
// other's.
func TestRunOnce_MergeMineChain_RoutesToItsOwnVerifier(t *testing.T) {
	moneroVerifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"monerohash": {Found: true, Orphaned: false, Confirmations: 100, Reward: 111},
	}}
	tariVerifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"tarihash": {Found: true, Orphaned: false, Confirmations: 100, Reward: 222},
	}}

	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {
			{ID: 1, Algo: "RXM", Hash: "monerohash", Height: 500, MergeMineChain: nil},
			{ID: 2, Algo: "RXM", Hash: "tarihash", Height: 500, MergeMineChain: strp("TARI")},
		},
	}}

	u := New(repo, Config{
		Coins:                   map[string]CoinConfig{"RXM": {Verifier: moneroVerifier, MaturityDepth: 10}},
		MergeMineChainVerifiers: map[string]CoinConfig{"TARI": {Verifier: tariVerifier, MaturityDepth: 10}},
		Logf:                    func(string, ...any) {},
	})

	result := u.RunOnce(context.Background())
	if result.Matured != 2 {
		t.Fatalf("RunOnce: matured = %d, want 2 (both legs independently matured)", result.Matured)
	}
	if result.Errors != 0 {
		t.Fatalf("RunOnce: errors = %d, want 0", result.Errors)
	}

	// The primary leg must have been checked against moneroVerifier
	// only, never tariVerifier -- and vice versa. fakeVerifier's own
	// results map is keyed by hash, so a misrouted call (checking
	// "tarihash" against moneroVerifier, which has no such key)
	// would silently return a zero VerifyResult{Found:false} --
	// confirm via SetBlockStatus calls instead, which only ever
	// fire on a genuinely resolved (matured/orphaned) outcome.
	wantCalls := map[int64]statusCall{
		1: {id: 1, valid: true, unlocked: true},
		2: {id: 2, valid: true, unlocked: true},
	}
	if len(repo.statusCalls) != 2 {
		t.Fatalf("SetBlockStatus calls = %d, want 2: %+v", len(repo.statusCalls), repo.statusCalls)
	}
	for _, c := range repo.statusCalls {
		want, ok := wantCalls[c.id]
		if !ok || want != c {
			t.Fatalf("unexpected SetBlockStatus call %+v", c)
		}
	}
}

// TestRunOnce_MergeMineChain_UnconfiguredChainLeftPending covers the
// "no verifier configured for merge_mine_chain" case: the block must
// be left pending (not errored, not matured) -- mirrors Coins' own
// established "no entry = never polled" convention.
func TestRunOnce_MergeMineChain_UnconfiguredChainLeftPending(t *testing.T) {
	moneroVerifier := &fakeVerifier{results: map[string]chain.VerifyResult{}}
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {
			{ID: 3, Algo: "RXM", Hash: "somehash", Height: 500, MergeMineChain: strp("UNCONFIGURED")},
		},
	}}
	u := New(repo, Config{
		Coins: map[string]CoinConfig{"RXM": {Verifier: moneroVerifier, MaturityDepth: 10}},
		// MergeMineChainVerifiers deliberately left nil/empty.
		Logf: func(string, ...any) {},
	})

	result := u.RunOnce(context.Background())
	if result.Pending != 1 {
		t.Fatalf("RunOnce: pending = %d, want 1", result.Pending)
	}
	if result.Errors != 0 {
		t.Fatalf("RunOnce: errors = %d, want 0 (unconfigured chain is not an error)", result.Errors)
	}
	if len(repo.statusCalls) != 0 {
		t.Fatalf("SetBlockStatus calls = %d, want 0 (never mutated when no verifier is configured)", len(repo.statusCalls))
	}
}

// TestRunOnce_MergeMineChain_OrphanedIndependently proves the two
// legs' outcomes are genuinely independent: the Tari leg orphaning
// must not affect the Monero leg's own maturity outcome, or
// vice versa.
func TestRunOnce_MergeMineChain_OrphanedIndependently(t *testing.T) {
	moneroVerifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"monerohash": {Found: true, Orphaned: false, Confirmations: 100, Reward: 111},
	}}
	tariVerifier := &fakeVerifier{results: map[string]chain.VerifyResult{
		"tarihash": {Found: true, Orphaned: true},
	}}
	repo := &fakeRepo{pending: map[string][]Block{
		"RXM": {
			{ID: 1, Algo: "RXM", Hash: "monerohash", Height: 500, MergeMineChain: nil},
			{ID: 2, Algo: "RXM", Hash: "tarihash", Height: 500, MergeMineChain: strp("TARI")},
		},
	}}
	u := New(repo, Config{
		Coins:                   map[string]CoinConfig{"RXM": {Verifier: moneroVerifier, MaturityDepth: 10}},
		MergeMineChainVerifiers: map[string]CoinConfig{"TARI": {Verifier: tariVerifier, MaturityDepth: 10}},
		Logf:                    func(string, ...any) {},
	})

	result := u.RunOnce(context.Background())
	if result.Matured != 1 {
		t.Fatalf("RunOnce: matured = %d, want 1 (Monero leg only)", result.Matured)
	}
	if result.Orphaned != 1 {
		t.Fatalf("RunOnce: orphaned = %d, want 1 (Tari leg only)", result.Orphaned)
	}
}
