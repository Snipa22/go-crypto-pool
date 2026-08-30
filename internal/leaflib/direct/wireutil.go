// Copyright and license: see repository LICENSE (MIT).
//
// This file duplicates a handful of small, pure helper functions that
// exist as UNEXPORTED functions in the read-only internal/leaflib/solo
// package (rxt.go, job.go, session.go). solo/* is explicitly read-only
// reference material for this task (do not modify leaf-solo's own
// behavior or exports), so these cannot be imported directly; they are
// re-derived here byte-for-byte from the same real, confirmed-from-source
// Tari protocol math solo already ports. See each function's doc
// comment for the exact solo.go counterpart it mirrors.
package direct

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/holiman/uint256"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// randomNonceBuf returns 8 cryptographically-random bytes,
// little-endian-encoded from a random uint64 — mirrors solo/node.go's
// GetBlockTemplate coinbase-extra randomization exactly (real
// per-xn-template-uniqueness mechanism, see that function's doc
// comment).
func randomNonceBuf() []byte {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return buf
}

// newRandomHexID mirrors solo/job.go's unexported newRandomHexID: 8
// cryptographically-random bytes, hex-encoded, used for the
// per-connection login "id" handed to a miner.
func newRandomHexID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// newSessionXN mirrors solo/job.go's unexported newSessionXN exactly:
// 2 cryptographically-random bytes, hex-encoded to a 4-character
// string, assigned once per session at connect time.
func newSessionXN() (string, error) {
	buf := make([]byte, 2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// jobIDFromBlockHash mirrors solo/job.go's unexported
// jobIDFromBlockHash exactly: the first 16 hex characters of
// hex(blockHash).
func jobIDFromBlockHash(blockHash []byte) (string, error) {
	full := hex.EncodeToString(blockHash)
	if len(full) < 16 {
		return "", fmt.Errorf("direct: block hash too short to derive a job id: got %d hex chars, need at least 16 (raw hash %d bytes)", len(full), len(blockHash))
	}
	return full[:16], nil
}

// algoWireName mirrors solo/session.go's unexported algoWireName
// exactly.
func algoWireName(algo poolpb.Algo) string {
	switch algo {
	case poolpb.Algo_ALGO_C29:
		return "c29"
	case poolpb.Algo_ALGO_RXT:
		// RXT is plain RandomX under the hood (same hash as rx/0,
		// Tari's own block/nonce/blob layout); real RandomX miners
		// have no concept of an algo named "rxt" — mirrors solo's own
		// algoWireName fix. NOT "rxt" — that's the internal
		// poolpb.Algo enum name / -algo=rxt CLI flag value, unchanged.
		return "rx/0"
	case poolpb.Algo_ALGO_RXM:
		// "rx/0" is the real wire algo string a real Monero-family
		// miner actually expects — mirrors solo's own algoWireName and
		// leaf-proxy's own real Monero wiring, NOT the internal
		// poolpb.Algo enum name "rxm".
		return "rx/0"
	default:
		return "sha3x"
	}
}

// diffToTargetHex mirrors solo/session.go's unexported diffToTargetHex
// exactly.
func diffToTargetHex(difficulty uint64) string {
	if difficulty == 0 {
		difficulty = 1
	}
	target := uint64(math.MaxUint64) / difficulty
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, target)
	return hex.EncodeToString(buf)
}

// safeInt64 mirrors solo/session.go's unexported safeInt64 exactly —
// see that function's doc comment for why a naive int64(uint64) cast
// is a real, previously-found security bug (silently disables the
// difficulty check for values >= 1<<63).
func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// cloneBlockWithNonce mirrors solo/session.go's unexported
// cloneBlockWithNonce exactly.
func cloneBlockWithNonce(block *tari_generated.Block, nonce uint64) *tari_generated.Block {
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

// cloneBlockWithC29Proof mirrors solo/session.go's unexported
// cloneBlockWithC29Proof exactly, reusing the same exported
// validator.C29EdgePacking helper solo itself uses.
func cloneBlockWithC29Proof(block *tari_generated.Block, nonce uint64, cycle []uint64, edgeBits int, edgePacker func([]uint64, int) []byte) *tari_generated.Block {
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

// rxtPowAlgoByte mirrors solo/rxt.go's unexported rxtPowAlgoByte
// exactly (real Tari PowAlgorithm::RandomXT discriminant = 2).
const rxtPowAlgoByte byte = 2

// tariMiningBlobSize mirrors solo/rxt.go's unexported
// tariMiningBlobSize exactly (76 bytes).
const tariMiningBlobSize = 3 + 32 + 8 + 33

// rxtXmrigNonceOffset/rxtXmrigNonceSize mirror solo/rxt.go's
// unexported constants of the same name exactly — see that file's doc
// comment for the full, confirmed-from-XMRig's-real-source rationale
// (Job::nonceOffset()'s generic RandomX-family default case = 39,
// Job::nonceSize()'s default case = 4; not a wire-negotiated field).
const (
	rxtXmrigNonceOffset = 39
	rxtXmrigNonceSize   = 4
)

// createTariMiningBlob mirrors solo/rxt.go's unexported
// createTariMiningBlob byte-for-byte — see that function's doc comment
// for the full, confirmed-from-the-real-Rust-source provenance of this
// 76-byte layout.
func createTariMiningBlob(miningHash []byte, nonce uint64, powAlgo byte, powData []byte) []byte {
	blob := make([]byte, 0, tariMiningBlobSize)
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

// errRXTHashIsZero mirrors solo/rxt.go's unexported errRXTHashIsZero.
var errRXTHashIsZero = errors.New("direct: rxt hash is all-zero, cannot derive a difficulty (division by zero)")

// rxtLittleEndianDifficulty mirrors solo/rxt.go's unexported
// rxtLittleEndianDifficulty byte-for-byte — see that function's doc
// comment for the full, confirmed-from-the-real-Rust-source formula.
func rxtLittleEndianDifficulty(hash []byte) (uint64, error) {
	if len(hash) == 0 {
		return 0, errRXTHashIsZero
	}

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

	maxU256 := new(uint256.Int).SetAllOne()
	result := new(uint256.Int).Div(maxU256, scalar)

	if !result.IsUint64() {
		return ^uint64(0), nil
	}
	return result.Uint64(), nil
}
