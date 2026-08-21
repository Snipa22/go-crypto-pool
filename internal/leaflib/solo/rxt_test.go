// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestCreateTariMiningBlobExactByteLayout hand-computes the expected
// 76-byte output of createTariMiningBlob for a synthetic
// header/nonce/pow_data with known values and asserts the exact
// resulting byte sequence byte-for-byte against the real Tari Rust
// create_tari_mining_blob layout confirmed in this pass:
//
//	| 3 bytes zero | 32 bytes mining_hash | 8 bytes nonce BE | 33 bytes pow.to_bytes() padded |
//
// where pow.to_bytes() = [pow_algo byte] ++ pow_data, zero-padded to 33
// bytes total.
func TestCreateTariMiningBlobExactByteLayout(t *testing.T) {
	miningHash := bytes.Repeat([]byte{0xAB}, 32) // distinctive, non-zero 32-byte fixture
	const nonce = uint64(0x0102030405060708)
	const powAlgo = rxtPowAlgoByte // 2, confirmed real RandomXT discriminant
	powData := []byte{0xCC, 0xDD, 0xEE}

	got := createTariMiningBlob(miningHash, nonce, powAlgo, powData)

	if len(got) != tariMiningBlobSize {
		t.Fatalf("blob length = %d, want %d (the real Tari mining blob is always exactly 76 bytes: 3+32+8+33)", len(got), tariMiningBlobSize)
	}
	if tariMiningBlobSize != 76 {
		t.Fatalf("tariMiningBlobSize constant = %d, want 76", tariMiningBlobSize)
	}

	// Hand-build the exact expected byte sequence per the real Rust
	// layout, independently of createTariMiningBlob's own
	// implementation, so this test can't just be checking the
	// function against itself.
	want := make([]byte, 0, 76)
	want = append(want, 0x00, 0x00, 0x00) // major/minor/timestamp placeholders
	want = append(want, miningHash...)    // 32 bytes
	nonceBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBuf, nonce) // BIG-ENDIAN, confirmed from real Rust `to_be_bytes()`
	want = append(want, nonceBuf...)
	powBytes := append([]byte{powAlgo}, powData...) // pow.to_bytes() = [pow_algo] ++ pow_data
	padded := make([]byte, 33)
	copy(padded, powBytes) // zero-padded to 33 bytes (pad-to-33-then-take-0..33)
	want = append(want, padded...)

	if len(want) != 76 {
		t.Fatalf("test's own hand-built expected blob length = %d, want 76 (test bug)", len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("createTariMiningBlob byte layout mismatch:\n got  = %s\n want = %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Spot-check individual segments by exact byte offset, as an extra
	// belt-and-suspenders assertion beyond the whole-blob comparison
	// above.
	if !bytes.Equal(got[0:3], []byte{0, 0, 0}) {
		t.Errorf("bytes[0:3] = %x, want zero placeholder bytes", got[0:3])
	}
	if !bytes.Equal(got[3:35], miningHash) {
		t.Errorf("bytes[3:35] (mining_hash) = %x, want %x", got[3:35], miningHash)
	}
	gotNonce := binary.BigEndian.Uint64(got[35:43])
	if gotNonce != nonce {
		t.Errorf("bytes[35:43] decoded as big-endian nonce = %#x, want %#x", gotNonce, nonce)
	}
	if got[43] != powAlgo {
		t.Errorf("byte[43] (pow_algo) = %d, want %d", got[43], powAlgo)
	}
	if !bytes.Equal(got[44:47], powData) {
		t.Errorf("bytes[44:47] (pow_data prefix) = %x, want %x", got[44:47], powData)
	}
	if !bytes.Equal(got[47:76], make([]byte, 29)) {
		t.Errorf("bytes[47:76] (pow_data zero-padding tail) = %x, want all-zero", got[47:76])
	}
}

// TestCreateTariMiningBlobEmptyPowData covers the real, typical RXT
// case: a fresh template's ProofOfWork.PowData is empty (VmKey/seed is
// derived by height, not stored in-block for native RXT), so the
// pow.to_bytes() segment is just the single pow_algo byte, zero-padded
// out to 33 bytes.
func TestCreateTariMiningBlobEmptyPowData(t *testing.T) {
	miningHash := bytes.Repeat([]byte{0x11}, 32)
	got := createTariMiningBlob(miningHash, 42, rxtPowAlgoByte, nil)

	if len(got) != 76 {
		t.Fatalf("blob length = %d, want 76", len(got))
	}
	if got[43] != rxtPowAlgoByte {
		t.Errorf("byte[43] (pow_algo) = %d, want %d", got[43], rxtPowAlgoByte)
	}
	if !bytes.Equal(got[44:76], make([]byte, 32)) {
		t.Errorf("bytes[44:76] (pow_data, empty+padded) = %x, want all-zero", got[44:76])
	}
}

// TestRxtLittleEndianDifficultyKnownVectors hand-computes expected
// difficulties for a few known input byte sequences per the real Tari
// Difficulty::little_endian_difficulty formula (U256::MAX /
// little_endian(hash), clamped to u64::MAX) — not just a structural
// round-trip test.
func TestRxtLittleEndianDifficultyKnownVectors(t *testing.T) {
	t.Run("all 0xFF hash -> very LOW difficulty (near 1)", func(t *testing.T) {
		// U256::MAX interpreted little-endian from an all-0xFF hash is
		// ALSO U256::MAX (every byte is 0xFF regardless of byte
		// order), so U256::MAX / U256::MAX == 1 exactly.
		hash := bytes.Repeat([]byte{0xFF}, 32)
		diff, err := rxtLittleEndianDifficulty(hash)
		if err != nil {
			t.Fatalf("rxtLittleEndianDifficulty: %v", err)
		}
		if diff != 1 {
			t.Errorf("difficulty for all-0xFF hash = %d, want 1 (U256::MAX / U256::MAX)", diff)
		}
	})

	t.Run("hash with small low-byte scalar -> very HIGH difficulty", func(t *testing.T) {
		// Little-endian: hash[0] is the LEAST significant byte. An
		// all-zero hash except hash[0]=64 encodes the scalar value 64
		// (mostly-zero high bytes, small low-byte value) —
		// U256::MAX / 64 is a very large difficulty, clamped to
		// u64::MAX since it overflows a uint64. This exactly mirrors
		// the real Rust source's own `le_stop_overflow` test
		// (difficulty.rs): `little_endian_difficulty(&64u64.to_be_bytes())`
		// (a big-endian encoding of 64 as the high-order bytes of a
		// hash IS, when read little-endian, the scalar 64 in the
		// LOWEST bytes) also expects u64::MAX.
		hash := make([]byte, 32)
		hash[0] = 64
		diff, err := rxtLittleEndianDifficulty(hash)
		if err != nil {
			t.Fatalf("rxtLittleEndianDifficulty: %v", err)
		}
		if diff != ^uint64(0) {
			t.Errorf("difficulty for {64,0,0,...} (LE scalar 64) = %d, want u64::MAX (%d) — clamped overflow", diff, ^uint64(0))
		}
	})

	t.Run("real Rust le_stop_overflow vector: big-endian 64 as a hash", func(t *testing.T) {
		// Ported directly from the real Rust test
		// (base_layer/transaction_components/src/tari_proof_of_work/
		// difficulty.rs's `le_stop_overflow`):
		//   let target: u64 = 64;
		//   little_endian_difficulty(&target.to_be_bytes()) == u64::MAX
		// target.to_be_bytes() is only 8 bytes; little_endian_difficulty
		// treats whatever slice it's given as the full little-endian
		// integer (U256::from_little_endian pads implicitly), so this
		// is scalar = 64 as well (an 8-byte big-endian encoding of 64
		// has its nonzero byte LAST, which is the MOST-significant
		// position under a little-endian read — same effective value
		// as putting 64 in the first byte of a longer buffer since
		// leading/trailing zero bytes don't change the numeric value).
		target := uint64(64)
		be := make([]byte, 8)
		for i := 0; i < 8; i++ {
			be[i] = byte(target >> (8 * (7 - i)))
		}
		diff, err := rxtLittleEndianDifficulty(be)
		if err != nil {
			t.Fatalf("rxtLittleEndianDifficulty: %v", err)
		}
		if diff != ^uint64(0) {
			t.Errorf("difficulty = %d, want u64::MAX (%d)", diff, ^uint64(0))
		}
	})

	t.Run("all-zero hash is an error (division by zero)", func(t *testing.T) {
		hash := make([]byte, 32)
		if _, err := rxtLittleEndianDifficulty(hash); err == nil {
			t.Error("expected an error for an all-zero hash (division by zero), got nil")
		}
	})

	t.Run("le_max_difficulty real Rust vector", func(t *testing.T) {
		// Ported from the real Rust test `le_max_difficulty`:
		//   let target = U256::MAX / U256::from(u64::MAX);
		//   target.to_little_endian(&mut bytes);
		//   little_endian_difficulty(&bytes) == Difficulty::max() (u64::MAX)
		// U256::MAX / u64::MAX, written little-endian, should itself
		// come back out at difficulty u64::MAX (the max clamp value).
		// U256::MAX / u64::MAX == 2^192 + 2^128 + 2^64 + 1 (a real,
		// hand-verifiable identity: (2^256-1)/(2^64-1) sums that
		// geometric series) — construct that scalar's little-endian
		// bytes directly rather than re-deriving it via uint256 division
		// in the test (which would just be testing the implementation
		// against itself).
		bytesLE := make([]byte, 32)
		bytesLE[0] = 1  // 2^0
		bytesLE[8] = 1  // 2^64
		bytesLE[16] = 1 // 2^128
		bytesLE[24] = 1 // 2^192
		diff, err := rxtLittleEndianDifficulty(bytesLE)
		if err != nil {
			t.Fatalf("rxtLittleEndianDifficulty: %v", err)
		}
		if diff != ^uint64(0) {
			t.Errorf("difficulty = %d, want u64::MAX (%d)", diff, ^uint64(0))
		}
	})
}
