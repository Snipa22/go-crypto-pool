// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"testing"
)

// legacyTargetHex is an independent, from-scratch reimplementation of
// the REAL legacy nodejs-pool-sxmr wire-target algorithm
// (lib/pool.js's Miner.getTargetHex, protoVersion===1 — the only
// branch that exists there — combined with lib/coins/xmr.js's
// baseDiff = 2^256-1), written here with Go's own math/big so the
// tests below compare DiffToTargetHex's native-uint32 shortcut against
// the genuine arbitrary-precision algorithm rather than against a
// hardcoded magic string:
//
//	padded = 32 zero bytes
//	diffBuff = big-endian minimal bytes of (2^256-1)/difficulty
//	diffBuff right-aligned into padded
//	buff = padded[0:4]          (TOP 4 bytes)
//	buffReversed = reverse(buff) (little-endian wire order)
//	hex(buffReversed)            (8 hex chars)
func legacyTargetHex(difficulty uint64) string {
	if difficulty == 0 {
		difficulty = 1
	}
	// baseDiff = 2^256-1, exactly the legacy
	// "FFFF...FF" (64 F's) bignum literal.
	baseDiff := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	quotient := new(big.Int).Div(baseDiff, new(big.Int).SetUint64(difficulty))

	// diffBuff.copy(padded, 32 - diffBuff.length): right-align the
	// minimal big-endian bytes into a 32-byte zero buffer.
	diffBuff := quotient.Bytes()
	padded := make([]byte, 32)
	if len(diffBuff) > 32 {
		// Cannot happen for difficulty >= 1, but keep the
		// reference implementation total rather than panicking.
		diffBuff = diffBuff[len(diffBuff)-32:]
	}
	copy(padded[32-len(diffBuff):], diffBuff)

	// padded.slice(0, 4), then .reverse() for little-endian.
	buff := padded[0:4]
	reversed := []byte{buff[3], buff[2], buff[1], buff[0]}
	return hex.EncodeToString(reversed)
}

// preFix8ByteTargetHex is the EXACT pre-fix body of DiffToTargetHex
// (target = (2^64-1)/difficulty, 8 raw little-endian bytes, 16 hex
// chars), preserved verbatim here so the above-0xFFFFFFFF fallback
// path can be regression-proofed as byte-for-byte unchanged by the
// two-stage fix.
func preFix8ByteTargetHex(difficulty uint64) string {
	if difficulty == 0 {
		difficulty = 1
	}
	target := uint64(math.MaxUint64) / difficulty
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, target)
	return hex.EncodeToString(buf)
}

// TestDiffToTargetHexMatchesRealLegacyFormula is the core proof
// demanded by the fix: for every difficulty at or below the
// 0xFFFFFFFF precision floor, the native-uint32 shortcut
// DiffToTargetHex now uses must be BYTE-IDENTICAL to the real
// arbitrary-precision legacy algorithm. Any single discrepancy here
// means the shortcut is invalid and the bignum algorithm must be used
// instead.
func TestDiffToTargetHexMatchesRealLegacyFormula(t *testing.T) {
	difficulties := []uint64{
		0, // divide-by-zero guard -> treated as 1
		1,
		2,
		3,
		7,
		100,
		1000,
		1500,
		50000,         // today's real production min-difficulty
		65535,         // 2^16-1
		65536,         // 2^16
		1_000_000,     // a real mid-tier port difficulty
		1_000_000_000, // today's real -max-difficulty ceiling on every leaf
		math.MaxUint32 - 1,
		math.MaxUint32, // the exact inclusive boundary
	}
	for _, d := range difficulties {
		got := DiffToTargetHex(d)
		want := legacyTargetHex(d)
		if got != want {
			t.Errorf("DiffToTargetHex(%d) = %q, real legacy formula gives %q", d, got, want)
		}
		if len(got) != 8 {
			t.Errorf("DiffToTargetHex(%d) length = %d, want 8 hex chars (4 bytes)", d, len(got))
		}
	}
}

// TestDiffToTargetHexShortcutExhaustiveOverPowersAndNeighbors widens
// the equivalence proof well past a handful of hand-picked values:
// every power of two in range plus its immediate neighbors, plus a
// dense low sweep, all compared against the real bignum algorithm.
func TestDiffToTargetHexShortcutExhaustiveOverPowersAndNeighbors(t *testing.T) {
	var difficulties []uint64
	for d := uint64(1); d <= 4096; d++ {
		difficulties = append(difficulties, d)
	}
	for shift := uint(0); shift <= 32; shift++ {
		p := uint64(1) << shift
		for _, d := range []uint64{p - 1, p, p + 1} {
			if d >= 1 && d <= math.MaxUint32 {
				difficulties = append(difficulties, d)
			}
		}
	}
	for _, d := range difficulties {
		got := DiffToTargetHex(d)
		want := legacyTargetHex(d)
		if got != want {
			t.Fatalf("shortcut/bignum mismatch at difficulty %d: got %q, real legacy formula gives %q", d, got, want)
		}
	}
}

// TestDiffToTargetHexProductionMinDifficulty pins the real production
// min-difficulty (50000) to the legacy-compatible 4-byte form.
func TestDiffToTargetHexProductionMinDifficulty(t *testing.T) {
	got := DiffToTargetHex(50000)
	if len(got) != 8 {
		t.Fatalf("DiffToTargetHex(50000) = %q (%d hex chars), want 8 hex chars (4 bytes)", got, len(got))
	}
	if want := legacyTargetHex(50000); got != want {
		t.Fatalf("DiffToTargetHex(50000) = %q, real legacy formula gives %q", got, want)
	}
	// Independent cross-check of the decoded numeric value: the
	// little-endian 4 bytes must decode to floor((2^32-1)/50000).
	raw, err := hex.DecodeString(got)
	if err != nil {
		t.Fatalf("DiffToTargetHex(50000) = %q is not valid hex: %v", got, err)
	}
	if gotTarget, wantTarget := binary.LittleEndian.Uint32(raw), uint32(math.MaxUint32/50000); gotTarget != wantTarget {
		t.Errorf("decoded target = %d, want %d ((2^32-1)/50000)", gotTarget, wantTarget)
	}
}

// TestDiffToTargetHexDifficultyOne covers the lowest real difficulty.
func TestDiffToTargetHexDifficultyOne(t *testing.T) {
	got := DiffToTargetHex(1)
	if len(got) != 8 {
		t.Fatalf("DiffToTargetHex(1) = %q (%d hex chars), want 8 hex chars (4 bytes)", got, len(got))
	}
	if want := legacyTargetHex(1); got != want {
		t.Fatalf("DiffToTargetHex(1) = %q, real legacy formula gives %q", got, want)
	}
	// (2^32-1)/1 = 0xFFFFFFFF, whose little-endian bytes are all
	// 0xFF — the same string either way, but assert the decoded
	// value too so the test is not byte-order-blind.
	raw, _ := hex.DecodeString(got)
	if gotTarget := binary.LittleEndian.Uint32(raw); gotTarget != math.MaxUint32 {
		t.Errorf("decoded target at difficulty 1 = %d, want %d", gotTarget, uint64(math.MaxUint32))
	}
}

// TestDiffToTargetHexBoundaryInclusive proves 0xFFFFFFFF itself (the
// objective 4-byte precision floor) is still on the 4-byte path.
func TestDiffToTargetHexBoundaryInclusive(t *testing.T) {
	got := DiffToTargetHex(math.MaxUint32)
	if len(got) != 8 {
		t.Fatalf("DiffToTargetHex(math.MaxUint32=%d) = %q (%d hex chars), want 8 hex chars (4 bytes)", uint64(math.MaxUint32), got, len(got))
	}
	if want := legacyTargetHex(math.MaxUint32); got != want {
		t.Fatalf("DiffToTargetHex(math.MaxUint32) = %q, real legacy formula gives %q", got, want)
	}
	// At the exact boundary the target is still a meaningful,
	// non-degenerate integer: (2^32-1)/(2^32-1) = 1.
	raw, _ := hex.DecodeString(got)
	if gotTarget := binary.LittleEndian.Uint32(raw); gotTarget != 1 {
		t.Errorf("decoded target at the boundary = %d, want 1 (the precision floor: still >= 1)", gotTarget)
	}
}

// TestDiffToTargetHexBoundaryPlusOneKeeps8Byte is the regression proof
// that the pre-existing 8-byte fallback path is completely untouched
// above the boundary.
func TestDiffToTargetHexBoundaryPlusOneKeeps8Byte(t *testing.T) {
	const d = uint64(math.MaxUint32) + 1 // 4294967296
	got := DiffToTargetHex(d)
	if len(got) != 16 {
		t.Fatalf("DiffToTargetHex(%d) = %q (%d hex chars), want 16 hex chars (8 bytes)", d, got, len(got))
	}
	if want := preFix8ByteTargetHex(d); got != want {
		t.Fatalf("DiffToTargetHex(%d) = %q, pre-fix 8-byte behavior was %q (the fallback path must be unchanged)", d, got, want)
	}
	raw, _ := hex.DecodeString(got)
	if gotTarget, wantTarget := binary.LittleEndian.Uint64(raw), uint64(math.MaxUint64)/d; gotTarget != wantTarget {
		t.Errorf("decoded target = %d, want %d ((2^64-1)/%d)", gotTarget, wantTarget, d)
	}
}

// TestDiffToTargetHexAbove32BitFallbackUnchanged spot-checks a wider
// spread of above-boundary difficulties against the preserved pre-fix
// implementation, so the gate itself (not just the +1 case) is proven
// to have changed nothing on that side.
func TestDiffToTargetHexAbove32BitFallbackUnchanged(t *testing.T) {
	difficulties := []uint64{
		uint64(math.MaxUint32) + 1,
		uint64(math.MaxUint32) + 2,
		10_000_000_000,
		1 << 40,
		1 << 63,
		math.MaxUint64 - 1,
		math.MaxUint64,
	}
	for _, d := range difficulties {
		got := DiffToTargetHex(d)
		if len(got) != 16 {
			t.Errorf("DiffToTargetHex(%d) = %q (%d hex chars), want 16 hex chars (8 bytes)", d, got, len(got))
			continue
		}
		if want := preFix8ByteTargetHex(d); got != want {
			t.Errorf("DiffToTargetHex(%d) = %q, pre-fix 8-byte behavior was %q", d, got, want)
		}
	}
}

// TestDiffToTargetHexMaxDifficultyCeiling proves that the real,
// currently-configured -max-difficulty ceiling on every leaf
// (1_000_000_000, per cmd/leaf-direct, cmd/leaf-solo and
// cmd/leaf-proxy's own flag defaults) is comfortably inside the
// 4-byte path — i.e. every difficulty this pool can currently ever
// actually issue gets the legacy-compatible 4-byte encoding.
func TestDiffToTargetHexMaxDifficultyCeiling(t *testing.T) {
	const d = uint64(1_000_000_000)
	if d > math.MaxUint32 {
		t.Fatalf("test premise broken: %d must be <= math.MaxUint32 (%d)", d, uint64(math.MaxUint32))
	}
	got := DiffToTargetHex(d)
	if len(got) != 8 {
		t.Fatalf("DiffToTargetHex(%d) = %q (%d hex chars), want 8 hex chars (4 bytes)", d, got, len(got))
	}
	if want := legacyTargetHex(d); got != want {
		t.Fatalf("DiffToTargetHex(%d) = %q, real legacy formula gives %q", d, got, want)
	}
	raw, _ := hex.DecodeString(got)
	if gotTarget, wantTarget := binary.LittleEndian.Uint32(raw), uint32(math.MaxUint32/d); gotTarget != wantTarget || gotTarget < 1 {
		t.Errorf("decoded target = %d, want %d and >= 1 (non-degenerate at the configured ceiling)", gotTarget, wantTarget)
	}
}

// TestDiffToTargetHexZeroDegradesToOne pins the pre-existing
// divide-by-zero guard's behavior as unchanged: difficulty 0 is
// treated as difficulty 1, and now takes the new default 4-byte path.
func TestDiffToTargetHexZeroDegradesToOne(t *testing.T) {
	got := DiffToTargetHex(0)
	if want := DiffToTargetHex(1); got != want {
		t.Errorf("DiffToTargetHex(0) = %q, want %q (identical to difficulty 1)", got, want)
	}
	if len(got) != 8 {
		t.Errorf("DiffToTargetHex(0) = %q (%d hex chars), want 8 hex chars (4 bytes)", got, len(got))
	}
	if want := legacyTargetHex(0); got != want {
		t.Errorf("DiffToTargetHex(0) = %q, real legacy formula gives %q", got, want)
	}
}
