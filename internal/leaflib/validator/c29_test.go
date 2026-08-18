// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"context"
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// NOTE ON TEST COVERAGE HONESTY: unlike SHA3X (which has real legacy test
// vectors we could directly reuse — see sha3x_test.go), go-tari-c29-solo-stratum
// has NO test files at all (confirmed: zero _test.go files in that repo), and
// powkit's own test suite (cuckoo_test.go) only has real solved-cycle vectors
// for its Aeternity/Cortex configurations, not for
// NewCuckarooWithSipBlock24(29, 42) (Tari's exact C29 config). powkit is a
// verify-only library — it has no solver to generate a genuine, real,
// difficulty-passing 42-edge Cuckaroo29 cycle for a test header, and finding
// one by brute force is a genuinely expensive memory-hard mining operation,
// not something to fake inline in a unit test. Rather than inventing
// synthetic "cycle" data that only coincidentally happens to be internally
// consistent (which would prove nothing about the real cuckoo.Client.Verify
// call), these tests exercise the validator's real behavior against
// structurally-invalid inputs (wrong edge_bits, wrong cycle length, garbage
// cycle data that real Verify legitimately rejects) plus the non-PoW
// plumbing (nil share, wrong proof type). This is honest, real coverage of
// what these tests can actually prove — it does NOT claim to have verified
// this validator against a genuine known-good C29 solution end-to-end. That
// gap should be closed with a real integration test against Alex's existing
// C29 miner-side code/pool once available (see architecture doc's note that
// the C29Proof field shape is meant to match that real code, not be
// independently re-derived).
func c29Share(edgeBits uint32, cycle []uint64, header []byte, nonce uint64, blockDiff int64) *poolpb.Share {
	return &poolpb.Share{
		BlockDiff: blockDiff,
		RawProof: &poolpb.Share_C29Proof{
			C29Proof: &poolpb.C29Proof{
				EdgeBits: edgeBits,
				Cycle:    cycle,
				Header:   header,
				Nonce:    nonce,
			},
		},
	}
}

func TestC29Validator_Validate(t *testing.T) {
	v := NewC29Validator()
	ctx := context.Background()

	validLenCycle := make([]uint64, c29ProofSize) // all zeros -- structurally right-sized, not a real solved cycle

	t.Run("wrong edge_bits is rejected without calling the real verifier", func(t *testing.T) {
		valid, err := v.Validate(ctx, c29Share(30, validLenCycle, []byte("header"), 1, 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false for edge_bits != 29")
		}
	})

	t.Run("wrong cycle length is rejected without calling the real verifier", func(t *testing.T) {
		shortCycle := make([]uint64, c29ProofSize-1)
		valid, err := v.Validate(ctx, c29Share(c29EdgeBits, shortCycle, []byte("header"), 1, 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false for a cycle that isn't exactly %d edges", c29ProofSize)
		}
	})

	t.Run("correctly-shaped but non-solving cycle is rejected by the real cuckoo.Verify call", func(t *testing.T) {
		// All-zero edges are correctly *shaped* (right edge_bits, right
		// length) but not a real solved Cuckaroo29 cycle for this header —
		// this exercises the actual ported cuckoo.Client.Verify call
		// (see c29.go), not just the pre-checks above.
		valid, err := v.Validate(ctx, c29Share(c29EdgeBits, validLenCycle, []byte("some-header-bytes"), 42, 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false for an all-zero non-solution cycle")
		}
	})

	t.Run("nil share", func(t *testing.T) {
		_, err := v.Validate(ctx, nil)
		if err == nil {
			t.Errorf("expected error for nil share")
		}
	})

	t.Run("wrong proof type", func(t *testing.T) {
		wrong := &poolpb.Share{RawProof: &poolpb.Share_Sha3XProof{Sha3XProof: &poolpb.SHA3XProof{}}}
		_, err := v.Validate(ctx, wrong)
		if err != ErrWrongProofType {
			t.Errorf("expected ErrWrongProofType, got %v", err)
		}
	})
}

func TestC29EdgePacking_DeterministicAndNonEmpty(t *testing.T) {
	// Regression coverage for the ported edgePacking helper: same input
	// always packs to the same bytes (used as blake2b input for the
	// difficulty derivation -- non-determinism here would silently break
	// every C29 difficulty check).
	cycle := []uint64{1, 2, 3, 4, 5, 6, 7}
	a := c29EdgePacking(cycle, c29EdgeBits)
	b := c29EdgePacking(cycle, c29EdgeBits)
	if len(a) == 0 {
		t.Fatalf("expected non-empty packed output")
	}
	if string(a) != string(b) {
		t.Errorf("c29EdgePacking is not deterministic for identical input")
	}
}
