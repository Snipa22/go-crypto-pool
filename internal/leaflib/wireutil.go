// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"

	"github.com/holiman/uint256"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// This file is the EXTRACTION target for a real, confirmed
// (byte-for-byte-diffed) duplication between internal/leaflib/solo and
// internal/leaflib/direct: every function/const/var below used to
// exist twice — once as an unexported symbol in solo (spread across
// job.go/session.go/rxt.go) and once more, re-derived by hand,
// unexported, in internal/leaflib/direct/wireutil.go (that file's own
// former doc comment explained this was because leaf-direct was
// scoped as unable to import leaf-solo — a constraint since LIFTED;
// see this repo's dispatch history). solo.* and direct.* now both
// delegate to these single, real implementations (see solo/rxt.go,
// solo/job.go, solo/session.go's thin wrappers, and direct's own call
// sites, which call these directly) instead of each carrying their own
// copy — a wire-shape/algo-label bugfix (see e.g. commit 0659143,
// "wire-label RXT jobs as rx/0, not rxt") now lands exactly once,
// here, rather than needing to be manually re-applied to a second
// hand-derived copy.
//
// leaf-proxy does NOT consume this file: it has no RXT/SHA3X/C29
// concept at all (pure Monero-family RandomX only) and already has
// its own, genuinely independent equivalents where an equivalent
// exists at all (diffToTargetHex, littleEndianDifficulty,
// newRandomHexID — the latter deliberately generates a DIFFERENT
// number of random bytes than NewRandomHexID below, see
// proxy/job.go's own doc comment) — nothing here was invented for or
// forced onto that package.

// RandomNonceBuf returns 8 cryptographically-random bytes. Mirrors
// leaf-direct's own node.go's buildCoinbaseExtra use (a fresh,
// cryptographically-independent per-template coinbase-extra nonce).
// NOTE: leaf-solo's own GRPCNodeClient.buildCoinbaseExtra performs the
// analogous randomization using math/rand's Uint64 instead of
// crypto/rand — a genuine, confirmed difference (not unified here),
// so this helper remains a direct.NodeClient-only consumer.
func RandomNonceBuf() []byte {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return buf
}

// NewRandomHexID returns 8 cryptographically-random bytes,
// hex-encoded. Used for the per-connection session/login "id" the
// wire protocol hands a miner (solo.LoginResult.ID), AND (as of the
// random-job-id fix — see solo/node.go's tariJobFromResult and
// solo/monero_node.go's GetBlockTemplate doc comments for the full
// real-production-bug rationale) for every freshly-minted Job's own
// job_id: a purely random, opaque wire token that miners only ever
// echo back verbatim in submit, never derived from a block
// hash/prevHash/height/any other template content.
func NewRandomHexID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// NewSessionXN returns a fresh per-session extranonce (xn): 2
// cryptographically-random bytes, hex-encoded to a 4-character string
// — ported exactly from go-tari-sha3x-solo-stratum's miner.go
// connection-init (`buf := make([]byte, 8);
// binary.LittleEndian.PutUint64(buf, rand.Uint64());
// m.xn = fmt.Sprintf("%x", buf[0:2])`): same size (2 bytes/4 hex
// chars) and same "generated once per connection at accept time, not
// per-job" timing, sourced from crypto/rand.
func NewSessionXN() (string, error) {
	buf := make([]byte, 2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// AlgoWireName maps a Job's stamped poolpb.Algo onto the real wire
// "algo" label real miner software expects — confirmed against both
// reference implementations' MinerJobJSON.Algo: go-tari-sha3x-solo-stratum
// literally hardcodes "sha3x", go-tari-c29-solo-stratum's GetJobJSON
// sets "C29" (lowercased here for consistency). ALGO_RXT and ALGO_RXM
// both map to "rx/0" — real RandomX-family miner software (XMRig et
// al.) has no concept of an algorithm called "rxt"/"rxm"; they only
// dispatch on their own fixed algo-name set (see commit 0659143's own
// live-production root-cause analysis, ported here unchanged). Every
// standalone monerod-family coin algo added via
// internal/coinprofile.Registry (ALGO_XMR and below) ALSO maps to
// "rx/0" for the exact same reason — every confirmed coin there is a
// genuine, unmodified-RandomX monero-project/monero source fork (see
// that package's doc comment), so a real RandomX-aware miner client
// needs the SAME "rx/0" wire label to select the right hashing
// algorithm, not the "sha3x" fallback below (which would tell the
// miner to hash the wrong algorithm entirely).
// ALGO_UNSPECIFIED falls back to "sha3x" for defensive backward
// compatibility.
func AlgoWireName(algo poolpb.Algo) string {
	switch algo {
	case poolpb.Algo_ALGO_C29:
		return "c29"
	case poolpb.Algo_ALGO_RXT, poolpb.Algo_ALGO_RXM:
		return "rx/0"
	default:
		if _, ok := coinprofile.ByAlgo(algo); ok {
			return "rx/0"
		}
		return "sha3x"
	}
}

// DiffToTargetHex encodes a session difficulty into the wire "target"
// field, in two stages.
//
// STAGE 1 (difficulty <= math.MaxUint32, i.e. 0xFFFFFFFF — the
// default, and the only path any difficulty this pool can currently
// issue takes): the REAL legacy sxmr encoding, ported from
// nodejs-pool-sxmr's `lib/pool.js` Miner.getTargetHex +
// `lib/coins/xmr.js` baseDiff:
//
//	let padded = new Buffer(32); padded.fill(0);
//	let diffBuff = baseDiff.div(this.difficulty).toBuffer();  // baseDiff = 2^256-1
//	diffBuff.copy(padded, 32 - diffBuff.length);              // right-align into 32 bytes
//	let buff = padded.slice(0, 4);                            // TOP 4 bytes
//	let buffArray = buff.toByteArray().reverse();             // -> little-endian
//	return new Buffer(buffArray).toString("hex");             // 8 hex chars
//
// That legacy code has NO other branch and no protoVersion gate: it is
// unconditionally 4-byte for every session at every difficulty. This
// 32-bit little-endian target is the standard, universally-compatible
// CryptoNight/RandomX stratum convention that xmrig, xmr-stak et al.
// parse correctly by default; the 8-byte "extended" form below is NOT
// what an unmodified miner client assumes, and a client that computes
// its local target from a 16-hex-char value as if it were 8 hex chars
// submits shares it believes valid that the pool then correctly
// rejects as difficulty_floor_miss.
//
// The legacy bignum expression above is exactly equal to
// uint32(math.MaxUint32 / difficulty) in native uint32 arithmetic, for
// EVERY difficulty >= 1 — no arbitrary-precision arithmetic needed.
// Proof: taking the top 4 bytes of the 32-byte right-aligned
// big-endian quotient is floor(floor((2^256-1)/d) / 2^224), which by
// the nested-floor identity is floor((2^256-1) / (d * 2^224)). Write
// M = 2^32-1 and note (2^256-1) = M*2^224 + (2^224-1) exactly. With
// M = d*k + r (0 <= r < d), the numerator is d*k*2^224 +
// (r+1)*2^224 - 1, so the quotient is k + ((r+1)*2^224 - 1)/(d*2^224),
// whose floor is k iff (r+1)*2^224 - 1 < d*2^224, i.e. iff
// r + 1 <= d — always true because r < d. Hence the result is exactly
// k = floor((2^32-1)/d). TestDiffToTargetHexMatchesRealLegacyFormula
// verifies this against a real math/big implementation of the legacy
// algorithm across the full boundary set, so this is a proven
// equivalence and not an assertion.
//
// STAGE 2 (difficulty > math.MaxUint32): the pre-existing 8-byte
// behavior, UNCHANGED — ported from go-tari-sha3x-solo-stratum's
// minerTracking.MinerJob.diffToTarget + GetJobJSON encoding:
// target = uint64(2^64-1) / difficulty, written out as 8 raw
// LITTLE-ENDIAN bytes, hex-encoded (16 hex chars). 0xFFFFFFFF is the
// objective precision floor for a 4-byte target — at or below it
// (2^32-1)/difficulty is still a meaningful, non-degenerate integer
// (>= 1); above it a 4-byte target would round toward 0 and lose real
// precision, so the wider encoding is retained as a fallback for any
// future difficulty config that exceeds that ceiling.
//
// A difficulty of 0 is treated as 1 purely to avoid a runtime
// division-by-zero panic on a misconfiguration, rather than changing
// either real formula.
func DiffToTargetHex(difficulty uint64) string {
	if difficulty == 0 {
		difficulty = 1
	}
	if difficulty <= math.MaxUint32 {
		target32 := uint32(math.MaxUint32 / difficulty)
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, target32)
		return hex.EncodeToString(buf)
	}
	target := uint64(math.MaxUint64) / difficulty
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, target)
	return hex.EncodeToString(buf)
}

// SafeInt64 converts a uint64 to int64 by clamping to math.MaxInt64
// rather than allowing a silent two's-complement wraparound — see
// solo's original doc comment (git history) for the real production
// bug class this guards (a naive int64(x) conversion of a uint64
// value at or above 1<<63 wraps NEGATIVE, silently disabling a
// validator's `> 0` difficulty guard).
func SafeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// CloneBlockWithNonce returns a deep copy of block (via proto.Clone,
// to avoid copying protobuf's internal sync.Mutex-bearing
// MessageState by value) with Header.Nonce set to nonce, so the
// shared job template isn't mutated by a (potentially losing)
// submission race between miners on the same job.
func CloneBlockWithNonce(block *tari_generated.Block, nonce uint64) *tari_generated.Block {
	if block == nil {
		return nil
	}
	blockCopy := proto.Clone(block).(*tari_generated.Block)
	if blockCopy.Header == nil {
		blockCopy.Header = &tari_generated.BlockHeader{}
	}
	blockCopy.Header.Nonce = nonce
	return blockCopy
}

// CloneBlockWithC29Proof is CloneBlockWithNonce's C29 counterpart: in
// addition to stamping Header.Nonce, it also stamps Header.Pow.PowData
// with the real, edge-packed submitted cycle (edgePacker(cycle,
// edgeBits) — callers pass validator.C29EdgePacking) — ported exactly
// from go-tari-c29-solo-stratum's SubmitJob
// (`job.BlockResult.Block.Header.Pow.PowData = packedData`).
func CloneBlockWithC29Proof(block *tari_generated.Block, nonce uint64, cycle []uint64, edgeBits int, edgePacker func([]uint64, int) []byte) *tari_generated.Block {
	if block == nil {
		return nil
	}
	blockCopy := proto.Clone(block).(*tari_generated.Block)
	if blockCopy.Header == nil {
		blockCopy.Header = &tari_generated.BlockHeader{}
	}
	blockCopy.Header.Nonce = nonce
	if blockCopy.Header.Pow == nil {
		blockCopy.Header.Pow = &tari_generated.ProofOfWork{}
	}
	blockCopy.Header.Pow.PowData = edgePacker(cycle, edgeBits)
	return blockCopy
}

// RXTPowAlgoByte is the real Tari
// tari_proof_of_work::proof_of_work_algorithm::PowAlgorithm::RandomXT
// discriminant (#[repr(u8)] enum; confirmed from the real Tari Rust
// source: base_layer/transaction_components/src/tari_proof_of_work/
// proof_of_work_algorithm.rs — `RandomXM = 0, Sha3x = 1,
// RandomXT = 2, Cuckaroo = 3`).
const RXTPowAlgoByte byte = 2

// TariMiningBlobSize is the real, fixed size of
// create_tari_mining_blob's output: 3 (zero placeholder) + 32
// (mining_hash) + 8 (nonce) + 33 (pow.to_bytes(), padded) = 76.
const TariMiningBlobSize = 3 + 32 + 8 + 33

// RXTXmrigNonceOffset/RXTXmrigNonceSize are the REAL, hardcoded byte
// offset and width a stock, unmodified XMRig client patches its own
// search nonce into for any generic RandomX-family ("rx/0") job —
// confirmed from XMRig's actual real source (src/base/net/stratum/
// Job.cpp's Job::nonceOffset(): the generic `default:` case returns
// the fixed constant 39; Job.h's nonceSize() returns 4 for that same
// default case).
const (
	RXTXmrigNonceOffset = 39
	RXTXmrigNonceSize   = 4
)

// CreateTariMiningBlob ports the real Tari base node's
// create_tari_mining_blob (base_layer/core/src/proof_of_work/
// monero_rx/helpers.rs) byte-for-byte:
//
//	| 3 bytes  | 32 bytes    | 8 bytes           | 33 bytes                |
//	| zero     | mining_hash | nonce, big-endian | pow.to_bytes(), padded  |
//
// miningHash is the job's own merge-mining-hash pre-image material,
// truncated/zero-padded to exactly 32 bytes defensively. nonce is
// encoded big-endian, matching the real Rust `to_be_bytes()` call —
// CONFIRMED DIFFERENT from this codebase's SHA3X little-endian nonce
// convention. powAlgo is the single discriminant byte (RXTPowAlgoByte
// for RXT). powData is the job's current ProofOfWork.PowData,
// zero-padded/truncated to 32 bytes to fill out the 33-byte
// pow.to_bytes() segment exactly like the real pad-to-33 behavior.
func CreateTariMiningBlob(miningHash []byte, nonce uint64, powAlgo byte, powData []byte) []byte {
	blob := make([]byte, 0, TariMiningBlobSize)
	blob = append(blob, 0, 0, 0)

	mh := make([]byte, 32)
	copy(mh, miningHash)
	blob = append(blob, mh...)

	nonceBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBuf, nonce)
	blob = append(blob, nonceBuf...)

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

// ErrRXTHashIsZero mirrors the real Rust
// `DifficultyError::DivideByZero`
// (Difficulty::u256_scalar_to_difficulty) — an all-zero hash has no
// sound difficulty (division by zero), treated as an error rather
// than an infinite/undefined difficulty.
var ErrRXTHashIsZero = errors.New("leaflib: rxt hash is all-zero, cannot derive a difficulty (division by zero)")

// RXTLittleEndianDifficulty ports the real Tari
// Difficulty::little_endian_difficulty
// (base_layer/transaction_components/src/tari_proof_of_work/
// difficulty.rs):
//
//	let scalar = U256::from_little_endian(hash);
//	let result = U256::MAX / scalar;
//	let result = result.min(u64::MAX.into());
//	Difficulty::from_u64(result.low_u64())
//
// CONFIRMED DIFFERENT from SHA3X's triple-SHA3-256-based difficulty
// derivation and from C29's blake2b256-of-packed-cycle, BIG-ENDIAN-
// interpreted difficulty (validator.C29Difficulty) — RXT's real
// formula interprets the raw hash bytes as a LITTLE-ENDIAN U256. hash
// is expected to be the real, already-confirmed-valid RandomX output
// (this function does not itself verify anything cryptographic, it
// only classifies an already-confirmed-real hash's difficulty).
func RXTLittleEndianDifficulty(hash []byte) (uint64, error) {
	if len(hash) == 0 {
		return 0, ErrRXTHashIsZero
	}

	// uint256.Int.SetBytes32 interprets its input as BIG-ENDIAN.
	// Reversing the byte order first, then feeding the result
	// through that same big-endian setter, is mathematically
	// identical to a native little-endian parse.
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
		return 0, ErrRXTHashIsZero
	}

	maxU256 := new(uint256.Int).SetAllOne() // U256::MAX
	result := new(uint256.Int).Div(maxU256, scalar)

	if !result.IsUint64() {
		// Ported from the real `.min(u64::MAX.into())` clamp.
		return ^uint64(0), nil
	}
	return result.Uint64(), nil
}
