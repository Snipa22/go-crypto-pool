// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"context"
	"testing"
	"time"
)

// TestPureGoRandomXValidator_ValidateBlobSeedResult uses the exact,
// well-known, already-independently-confirmed-correct RandomX reference
// vector (git.gammaspectra.live/P2Pool/go-randomx@v1.0.0's own test
// suite, and the same vector randomx_real_daemon_test.go confirmed
// against a real, live randomx-service daemon): seed "test key 000",
// input "This is a test" ->
// 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f.
//
// This is a genuine, real, in-process pure-Go RandomX computation --
// NOT a mock, NOT a stub, no live daemon involved. It is expected to
// take a real, non-trivial amount of wall-clock time (hundreds of ms,
// per this session's own earlier ~258ms/hash benchmark of this exact
// library) -- a suspiciously-instant pass would indicate the real
// hashing path was accidentally skipped/short-circuited, not a good
// sign.
func TestPureGoRandomXValidator_ValidateBlobSeedResult(t *testing.T) {
	seed := []byte("test key 000")
	input := []byte("This is a test")
	const wantHex = "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"

	v := NewPureGoRandomXValidator()

	start := time.Now()
	valid, err := v.ValidateBlobSeedResult(context.Background(), input, seed, wantHex)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateBlobSeedResult (correct hash): %v", err)
	}
	if !valid {
		t.Fatal("expected the real, correct RandomX hash to validate successfully")
	}
	// Real RandomX cache init (Argon2d over a 256MiB cache) + a real
	// VM-executed hash is genuinely slow in pure Go -- this session's
	// own benchmark put a single hash at ~258ms on real hardware. A
	// pass that returns in, say, under 10ms almost certainly means the
	// real hashing path was skipped, not that this environment is
	// unusually fast.
	if elapsed < 10*time.Millisecond {
		t.Fatalf("ValidateBlobSeedResult returned suspiciously fast (%s) for a real RandomX computation -- real hashing path may have been short-circuited", elapsed)
	}
	t.Logf("real pure-Go RandomX ValidateBlobSeedResult (correct hash) took %s", elapsed)

	// Negative case: a wrong claimed hash for the exact same seed+input
	// must be rejected, not accepted -- this reuses the seed cache built
	// above, so it exercises the actual hash-comparison logic, not just
	// "did cache init succeed".
	wrongHex := "0000000000000000000000000000000000000000000000000000000000000000"[:64]
	valid, err = v.ValidateBlobSeedResult(context.Background(), input, seed, wrongHex)
	if err != nil {
		t.Fatalf("ValidateBlobSeedResult (wrong hash): %v", err)
	}
	if valid {
		t.Fatal("expected a wrong claimed hash to be rejected, not accepted")
	}
}

// TestPureGoRandomXValidator_MalformedResultHex confirms a malformed
// (non-hex) claimed result is reported as an ordinary invalid share
// (false, nil), not an error -- mirroring RandomXValidator's own
// contract for the same failure mode.
func TestPureGoRandomXValidator_MalformedResultHex(t *testing.T) {
	v := NewPureGoRandomXValidator()
	valid, err := v.ValidateBlobSeedResult(context.Background(), []byte("blob"), []byte("seed"), "not-hex")
	if err != nil {
		t.Fatalf("expected no error for malformed result hex, got: %v", err)
	}
	if valid {
		t.Fatal("expected malformed result hex to be rejected")
	}
}
