// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"encoding/binary"
	"errors"

	"github.com/holiman/uint256"
)

// rxtPowAlgoByte is the real Tari tari_proof_of_work::proof_of_work_algorithm::
// PowAlgorithm::RandomXT discriminant (#[repr(u8)] enum, confirmed from the
// real Tari Rust source in this session:
// base_layer/transaction_components/src/tari_proof_of_work/
// proof_of_work_algorithm.rs — `RandomXM = 0, Sha3x = 1, RandomXT = 2,
// Cuckaroo = 3`). This is the SAME value as the GRPC wire's
// tari_generated.PowAlgo_POW_ALGOS_RANDOMXT (also confirmed = 2,
// block.pb.go) — both the internal Rust enum and the GRPC enum happen to
// use identical discriminants for RandomXT, but they are two distinct
// enums serving two distinct purposes (this one is the single byte baked
// into ProofOfWork.to_bytes()'s pre-image; the GRPC one selects which
// template to request) — do not assume this coincidence generalizes to
// every algo without checking (e.g. verify before reusing this pattern
// for a hypothetical fifth algo).
const rxtPowAlgoByte byte = 2

// tariMiningBlobSize is the real, fixed size of create_tari_mining_blob's
// output for every algo it's used for (doc-commented in the real Rust
// source as "the 76-byte XMRig-compatible mining blob for Tari
// RandomXT"): 3 (zero placeholder) + 32 (mining_hash) + 8 (nonce) +
// 33 (pow.to_bytes(), padded) = 76.
const tariMiningBlobSize = 3 + 32 + 8 + 33

// rxtXmrigNonceOffset/rxtXmrigNonceSize are the REAL, hardcoded byte
// offset and width a stock, unmodified XMRig client patches its own
// search nonce into for any generic RandomX-family ("rx/0") job —
// confirmed from XMRig's actual real source
// (src/base/net/stratum/Job.cpp's Job::nonceOffset(): the generic
// `default:` case, used for every RandomX-family algo that isn't
// KAWPOW/GHOSTRIDER/RX_YADA, returns the fixed constant 39; Job.h's
// nonceSize() returns 4 for that same default case, and nonce() is
// typed `uint32_t*`). This is NOT something XMRig reads from a wire
// field — there is no "nonce_offset"/"reserved_offset" JSON field
// anywhere in XMRig's real stratum job-parsing code
// (Client.cpp::parseJob); the offset is purely a compiled-in constant
// keyed off the algorithm family, matching the real Monero
// block-header blob convention this same constant was originally
// derived from. Any pool wanting a stock XMRig binary to correctly
// locate and patch its own nonce into a job's blob MUST place that
// nonce at this exact offset — there is no alternative negotiation
// mechanism to fall back on.
//
// For RXT specifically, this lands squarely inside
// createTariMiningBlob's own 8-byte big-endian nonce field (bytes
// [35:43) — offset 39 is exactly the midpoint of that field, i.e. its
// low-order 4 bytes. Sending an outbound blob built with nonce=0
// leaves bytes [35:39) zero and bytes [39:43) as the placeholder
// XMRig will overwrite with its own raw 4 search-nonce bytes (native
// byte order — XMRig hex-encodes and reports back whatever raw bytes
// physically sit at that memory location, see Client.cpp::submit's
// `Cvt::toHex(nonce, ..., reinterpret_cast<const uint8_t*>(&result.nonce), sizeof(uint32_t))`,
// not some reinterpreted/byte-swapped value). Reconstructing the
// SAME 76 bytes the miner actually hashed for share verification is
// therefore just: decode the reported 4 raw nonce bytes as a
// big-endian uint32, zero-extend to uint64, and feed that straight
// back into createTariMiningBlob (whose own to_be_bytes(nonce) write
// reproduces bytes [35:39)=0, [39:43)=the same 4 raw bytes,
// byte-for-byte) — see session.go's handleSubmit ALGO_RXT case.
const (
	rxtXmrigNonceOffset = 39
	rxtXmrigNonceSize   = 4
)

// createTariMiningBlob ports the real Tari base node's
// create_tari_mining_blob (base_layer/core/src/proof_of_work/monero_rx/
// helpers.rs, confirmed from the actual Rust source in this session — NOT
// guessed) byte-for-byte:
//
//	| 3 bytes  | 32 bytes    | 8 bytes           | 33 bytes                |
//	| zero     | mining_hash | nonce, big-endian | pow.to_bytes(), padded  |
//
// The real Rust code:
//
//	let mut blob = vec![0u8; 3];                       // major/minor/timestamp placeholders — always zero here
//	blob.extend_from_slice(header.mining_hash().as_slice()); // 32 bytes
//	let nonce = header.nonce.to_be_bytes();             // 8 bytes, BIG-ENDIAN (confirmed different from
//	blob.extend_from_slice(&nonce);                     // SHA3X's little-endian nonce convention in this codebase)
//	let mut pow_bytes = header.pow.to_bytes();          // ProofOfWork::to_bytes() = [pow_algo byte] ++ pow_data
//	if pow_bytes.len() < 33 { pow_bytes.resize(33, 0) } // zero-pad to 33 bytes if shorter
//	blob.extend_from_slice(pow_bytes.get(0..33).expect("This should exist")); // take exactly the first 33 bytes
//
// (base_layer/transaction_components/src/tari_proof_of_work/proof_of_work.rs's
// ProofOfWork::to_bytes(): `buf.put_u8(self.pow_algo as u8); buf.put_slice(&self.pow_data); buf` —
// confirmed from the real Rust source: the doc comment on the real function
// calls this "32 bytes" but the ACTUAL behavior is pad-to-33-then-take-0..33,
// i.e. 1 byte pow_algo + 32 bytes pow_data, NOT a bare 32-byte field — this
// implementation follows the real code, not the doc comment's rounding.)
//
// miningHash is the job's Header field (result.GetMergeMiningHash() — the
// same field SHA3X/C29 already reuse for their own hash pre-image
// material, per node.go/job.go), truncated/zero-padded to exactly 32
// bytes defensively. nonce is encoded big-endian, matching the real Rust
// `to_be_bytes()` call — CONFIRMED DIFFERENT from this codebase's
// existing SHA3X little-endian nonce convention. powAlgo is the single
// discriminant byte (rxtPowAlgoByte for RXT). powData is the job's
// current ProofOfWork.PowData (typically empty for a fresh RXT
// template — RandomX's VmKey/seed is derived by height, not stored
// in-block), zero-padded/truncated to 32 bytes to fill out the 33-byte
// pow.to_bytes() segment exactly like the real pad-to-33 behavior.
func createTariMiningBlob(miningHash []byte, nonce uint64, powAlgo byte, powData []byte) []byte {
	blob := make([]byte, 0, tariMiningBlobSize)

	// 3 zero placeholder bytes (major/minor/timestamp) — the real Rust
	// code literally initializes these as zero (`vec![0u8; 3]`); XMRig
	// fills its own view of these in for its own purposes, but for this
	// leaf's own hash pre-image construction they are simply zero.
	blob = append(blob, 0, 0, 0)

	// 32-byte mining hash, defensively padded/truncated to exactly 32
	// bytes (a real Job.Header should always already be exactly 32
	// bytes — this guards a malformed/short input rather than silently
	// producing an under/oversized blob).
	mh := make([]byte, 32)
	n := copy(mh, miningHash)
	_ = n
	blob = append(blob, mh...)

	// 8-byte BIG-ENDIAN nonce (confirmed different from SHA3X's
	// little-endian convention already in this codebase).
	nonceBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBuf, nonce)
	blob = append(blob, nonceBuf...)

	// pow.to_bytes() = [pow_algo] ++ pow_data, zero-padded to 33 bytes
	// total, then take exactly the first 33 bytes — ported exactly from
	// the real Rust pad-then-slice behavior (see doc comment above).
	powBytes := make([]byte, 0, 1+len(powData))
	powBytes = append(powBytes, powAlgo)
	powBytes = append(powBytes, powData...)
	if len(powBytes) < 33 {
		padded := make([]byte, 33)
		copy(padded, powBytes)
		powBytes = padded
	}
	blob = append(blob, powBytes[0:33]...)

	return blob
}

// errRXTHashIsZero mirrors the real Rust `DifficultyError::DivideByZero`
// (Difficulty::u256_scalar_to_difficulty) — an all-zero hash has no
// sound difficulty (division by zero), and the real code treats this as
// an error rather than an infinite/undefined difficulty.
var errRXTHashIsZero = errors.New("solo: rxt hash is all-zero, cannot derive a difficulty (division by zero)")

// rxtLittleEndianDifficulty ports the real Tari
// Difficulty::little_endian_difficulty (base_layer/transaction_components/
// src/tari_proof_of_work/difficulty.rs, confirmed from the actual Rust
// source in this session — NOT guessed):
//
//	let scalar = U256::from_little_endian(hash); // little-endian, so the hash has TRAILING zeroes for a "good" (low) hash
//	let result = U256::MAX / scalar;
//	let result = result.min(u64::MAX.into());     // clamp to u64::MAX rather than overflow
//	Difficulty::from_u64(result.low_u64())
//
// This is CONFIRMED DIFFERENT from SHA3X's triple-SHA3-256-based
// difficulty derivation and from C29's blake2b256-of-packed-cycle,
// BIG-ENDIAN-interpreted difficulty (validator.C29Difficulty) — RXT's
// real formula interprets the raw hash bytes as a LITTLE-ENDIAN U256.
// hash is expected to be the real, randomx-service-confirmed 32-byte
// RandomX output (see session.go's handleSubmit: this is called only
// AFTER RandomXValidator.Validate has already confirmed the miner's
// claimed hash really is what the real daemon computed for the
// submitted blob+seed — this function does not itself verify anything
// cryptographic, it only classifies an already-confirmed-real hash's
// difficulty).
func rxtLittleEndianDifficulty(hash []byte) (uint64, error) {
	if len(hash) == 0 {
		return 0, errRXTHashIsZero
	}

	// uint256.Int.SetBytes32 interprets its input as BIG-ENDIAN (matching
	// Go's math/big and this codebase's existing C29Difficulty use of
	// uint256.SetBytes). To interpret hash as LITTLE-ENDIAN (matching the
	// real U256::from_little_endian call), reverse the byte order first,
	// then feed the result through the same big-endian setter — that is
	// mathematically identical to a native little-endian parse.
	buf := make([]byte, 32)
	n := len(hash)
	if n > 32 {
		n = 32
	}
	for i := 0; i < n; i++ {
		buf[31-i] = hash[i]
	}

	scalar := new(uint256.Int).SetBytes32(buf)
	if scalar.IsZero() {
		return 0, errRXTHashIsZero
	}

	maxU256 := new(uint256.Int).SetAllOne() // U256::MAX
	result := new(uint256.Int).Div(maxU256, scalar)

	if !result.IsUint64() {
		// Ported from the real `.min(u64::MAX.into())` clamp: a result
		// that doesn't fit in a u64 is clamped to u64::MAX rather than
		// wrapping/truncating.
		return ^uint64(0), nil
	}
	return result.Uint64(), nil
}
