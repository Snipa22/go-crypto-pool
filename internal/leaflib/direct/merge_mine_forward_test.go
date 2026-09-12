// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"reflect"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// TestMatchMergeMineForwards_MoneroOnly covers the "one submission
// clears Monero only" scenario: no aux_chain_data at all (the
// merge-mined chain's own target was not cleared) -- zero merge-mine
// Block messages should ever be forwarded, regardless of how many
// merge-mine chains are configured.
func TestMatchMergeMineForwards_MoneroOnly(t *testing.T) {
	configured := []MergeMineChainConfig{{Name: "TARI", AuxChainID: "xtr"}}
	var auxChains []solo.AuxChainResult // Tari's target was not cleared -- proxy reports nothing

	got := matchMergeMineForwards(configured, auxChains)
	if len(got) != 0 {
		t.Fatalf("Monero-only find: got %d merge-mine forwards, want 0 (never fabricate a leg that didn't clear): %+v", len(got), got)
	}
}

// TestMatchMergeMineForwards_MergeMinedChainOnly covers "one
// submission clears the merge-mined chain only": the matching logic
// itself has NO knowledge of whether the primary (Monero) leg's own
// submit_block outcome succeeded or failed -- it purely maps
// configured chains against whatever aux_chain_data the proxy
// reported for THIS submission. This is deliberately tested at this
// pure-function level (rather than only via a full handleSubmit
// round trip) because today's leaf only ever calls submit_block at
// all once Monero's OWN job.NetworkTargetDifficulty gate has already
// been cleared (see handleSubmit's block-find dispatch) -- a
// standalone "Tari cleared, Monero's own share difficulty did not"
// case cannot be produced end-to-end without ALSO changing that
// gating (an explicitly out-of-scope, deliberately-flagged
// architectural boundary; see this PR's summary). This test proves
// the matching/forwarding decision itself is correctly independent
// of Monero's outcome, which is the property that boundary depends
// on remaining true if that gate is ever revisited.
func TestMatchMergeMineForwards_MergeMinedChainOnly(t *testing.T) {
	configured := []MergeMineChainConfig{{Name: "TARI", AuxChainID: "xtr"}}
	auxChains := []solo.AuxChainResult{{ChainID: "xtr", Hash: "aa11bb22"}}

	got := matchMergeMineForwards(configured, auxChains)
	want := []mergeMineBlockForward{{chainName: "TARI", hashHex: "aa11bb22"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge-mined-chain-only find: got %+v, want %+v", got, want)
	}
}

// TestMatchMergeMineForwards_Both covers "one submission clears
// both": exactly one merge-mine forward, carrying the real Tari
// hash, on top of whatever the caller does for the primary Monero
// leg separately (this function has no opinion on that -- see
// handleSubmit).
func TestMatchMergeMineForwards_Both(t *testing.T) {
	configured := []MergeMineChainConfig{{Name: "TARI", AuxChainID: "xtr"}}
	auxChains := []solo.AuxChainResult{{ChainID: "xtr", Hash: "deadbeef"}}

	got := matchMergeMineForwards(configured, auxChains)
	if len(got) != 1 {
		t.Fatalf("both-cleared find: got %d merge-mine forwards, want exactly 1: %+v", len(got), got)
	}
	if got[0].chainName != "TARI" || got[0].hashHex != "deadbeef" {
		t.Fatalf("both-cleared find: got %+v, want chainName=TARI hashHex=deadbeef", got[0])
	}
}

// TestMatchMergeMineForwards_NoChainsConfigured is the pre-existing-
// behavior regression guard: with ServerConfig.MergeMineChains left
// empty (every -coin=tari process, and any -coin=monero process that
// hasn't set -merge-mine-chains), matchMergeMineForwards must always
// return nothing, no matter what the proxy's response carried --
// this is the "unconfigured = feature entirely off" contract.
func TestMatchMergeMineForwards_NoChainsConfigured(t *testing.T) {
	auxChains := []solo.AuxChainResult{{ChainID: "xtr", Hash: "deadbeef"}}
	got := matchMergeMineForwards(nil, auxChains)
	if len(got) != 0 {
		t.Fatalf("no chains configured: got %d merge-mine forwards, want 0: %+v", len(got), got)
	}
}

// TestMatchMergeMineForwards_EmptyHashNeverForwarded guards the
// "never fabricate" contract at the boundary case: an aux_chain_data
// entry whose block_hash is empty (a real Tari acceptance the proxy
// couldn't resolve a hash for) must never be forwarded, exactly
// mirroring the primary Monero leg's own skipBackendForward
// convention for its unresolved-hash case.
func TestMatchMergeMineForwards_EmptyHashNeverForwarded(t *testing.T) {
	configured := []MergeMineChainConfig{{Name: "TARI", AuxChainID: "xtr"}}
	auxChains := []solo.AuxChainResult{{ChainID: "xtr", Hash: ""}}
	got := matchMergeMineForwards(configured, auxChains)
	if len(got) != 0 {
		t.Fatalf("empty-hash aux entry: got %d merge-mine forwards, want 0: %+v", len(got), got)
	}
}

// TestMatchMergeMineForwards_MultipleConfiguredChains proves the
// generalization requirement: more than one configured merge-mine
// chain is handled without a hardcoded Tari-only branch -- each is
// matched independently against auxChains by its own AuxChainID.
func TestMatchMergeMineForwards_MultipleConfiguredChains(t *testing.T) {
	configured := []MergeMineChainConfig{
		{Name: "TARI", AuxChainID: "xtr"},
		{Name: "OTHERCHAIN", AuxChainID: "oc"},
	}
	auxChains := []solo.AuxChainResult{
		{ChainID: "xtr", Hash: "tarihash"},
		// "oc" not present -- OTHERCHAIN did not clear its target.
	}
	got := matchMergeMineForwards(configured, auxChains)
	want := []mergeMineBlockForward{{chainName: "TARI", hashHex: "tarihash"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multi-chain config: got %+v, want %+v", got, want)
	}
}
