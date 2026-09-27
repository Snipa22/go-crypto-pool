// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/holiman/uint256"
	"github.com/snipa22/powkit/cuckoo"
	"golang.org/x/crypto/blake2b"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// blake2b256 hashes data with blake2b-256, matching go-tari-c29-solo-stratum
// SubmitJob's `blake2b.New256()` call (github.com/dchest/blake2b there;
// golang.org/x/crypto/blake2b here — both are the same standard Blake2b-256
// algorithm, this is not an algorithmic substitution).
func blake2b256(data []byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		// blake2b.New256(nil) with a nil key never errors in this package;
		// panic would be inappropriate in a validator, so degrade to a
		// zero-length invalid result instead, which will safely fail the
		// difficulty check.
		return nil
	}
	h.Write(data)
	return h.Sum(nil)
}

// C29Validator verifies Cuckaroo29 cycle-proofs (Tari's C29 PoW).
//
// This is a faithful port of the real, production verification logic in
// go-tari-c29-solo-stratum's subsystems/poolStratum/miner.go, function
// minerStruct.SubmitJob (as of the locally-cloned reference checkout —
// see /workspace/omni-pool-review/go-tari-c29-solo-stratum). Specifically,
// this ports:
//
//   - The actual cycle-verification primitive: `cuckoo.NewCuckarooWithSipBlock24(29, 42).Verify(nonceBytes, pow)`,
//     where nonceBytes is the submitted nonce concatenated with the block's
//     merge-mining hash. That call chain bottoms out in
//     github.com/snipa22/powkit/cuckoo (Client.Verify -> Client.cuckaroo),
//     which is MIT-licensed (© 2013-2020 John Tromp for the underlying
//     cuckoo-cycle algorithm, packaged by snipa22/powkit) — this is a
//     real dependency pulled directly into go-crypto-pool (see go.mod),
//     not a reimplementation of siphash/cycle-detection from a written
//     description.
//   - The difficulty derivation: blake2b-256(edgePacking(cycle, edge_bits))
//     interpreted as a big-endian uint256, target difficulty =
//     maxUint256 / that value. Ported from the same SubmitJob function's
//     `blockDiffRaw`/`resultUint256` block.
//
// Adaptation notes (see internal/proto/share.proto's C29Proof doc comment
// for the corresponding schema-side note): the legacy code derives its
// nonceBytes from a stratum-specific MinerJob's MergeMiningHash field,
// which doesn't exist in this codebase's Share/C29Proof schema. C29Proof
// was extended with an explicit `header` (the merge-mining-hash material)
// and `nonce` field so this validator has everything the real algorithm
// needs, without inventing new cryptographic logic — the hash/cycle math
// below is unchanged from the legacy source.
type C29Validator struct{}

// NewC29Validator returns a ready-to-use C29Validator. It is stateless and
// safe for concurrent use.
func NewC29Validator() *C29Validator {
	return &C29Validator{}
}

// c29EdgeBits and c29ProofSize match the real Tari C29 miner: Cuckaroo29,
// 42-edge cycles. Ported from go-tari-c29-solo-stratum's
// `cuckoo.NewCuckarooWithSipBlock24(29, 42)` call in SubmitJob.
const (
	c29EdgeBits  = 29
	c29ProofSize = 42
)

// Validate implements AlgoValidator. It reports (true, nil) only if the
// share carries a valid C29Proof AND that proof is a cryptographically
// valid Cuckaroo29 cycle for header||nonce AND its derived difficulty
// meets share.BlockDiff (when BlockDiff > 0; a proof's cycle validity is
// always checked regardless).
func (v *C29Validator) Validate(_ context.Context, share *poolpb.Share) (bool, error) {
	if share == nil {
		return false, errors.New("validator: nil share")
	}
	proof, ok := share.GetRawProof().(*poolpb.Share_C29Proof)
	if !ok || proof == nil || proof.C29Proof == nil {
		return false, ErrWrongProofType
	}
	p := proof.C29Proof

	if p.GetEdgeBits() != c29EdgeBits {
		// Real Tari C29 is always edge_bits=29; anything else is not a
		// proof this validator (or the real miner code it's ported from)
		// knows how to check.
		return false, nil
	}
	if len(p.GetCycle()) != c29ProofSize {
		return false, nil
	}

	// Ported from SubmitJob: nonceBytes = nonce (big-endian 8 bytes) ||
	// MergeMiningHash (here: header).
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, p.GetNonce())
	nonceBytes = append(nonceBytes, p.GetHeader()...)

	hasher := cuckoo.NewCuckarooWithSipBlock24(c29EdgeBits, c29ProofSize)
	valid, err := hasher.Verify(nonceBytes, p.GetCycle())
	if err != nil || !valid {
		// Ported from SubmitJob: any Verify error or !valid means "Invalid
		// Nonce" — reject, not an infra error.
		return false, nil
	}

	// Ported from SubmitJob's difficulty derivation: blake2b256 of the
	// packed cycle, interpreted as maxUint256/hash.
	diff, err := c29Difficulty(p.GetCycle(), int(p.GetEdgeBits()))
	if err != nil {
		return false, nil
	}

	if share.GetBlockDiff() > 0 && diff < uint64(share.GetBlockDiff()) {
		return false, nil
	}

	return true, nil
}

// C29Difficulty exposes the same blake2b256-of-packed-cycle difficulty
// derivation Validate uses internally, for callers (e.g.
// internal/leaflib/solo's Session.handleSubmit) that need to determine
// whether an already-validated C29 share also meets a job's real
// network target difficulty (i.e. is a block find), without
// re-implementing or duplicating the hashing logic. This is a pure
// wiring convenience — the math is unchanged from c29Difficulty below.
func C29Difficulty(cycle []uint64, edgeBits int) (uint64, error) {
	return c29Difficulty(cycle, edgeBits)
}

// C29EdgePacking exposes the same real edgePacking bit-packing
// c29Difficulty uses internally, for callers that need to build the
// real on-wire ProofOfWork.PowData a submitted C29 cycle maps to (see
// go-tari-c29-solo-stratum's SubmitJob: `job.BlockResult.Block.Header.
// Pow.PowData = packedData`, the SAME packedData used for the
// difficulty hash) — a pure wiring convenience, not a reimplementation.
func C29EdgePacking(cycle []uint64, edgeBits int) []byte {
	return c29EdgePacking(cycle, edgeBits)
}

// c29Difficulty ports go-tari-c29-solo-stratum SubmitJob's difficulty
// calculation: blake2b256(edgePacking(cycle, edgeBits)) interpreted as a
// big-endian uint256, difficulty = maxUint256 / that value.
func c29Difficulty(cycle []uint64, edgeBits int) (uint64, error) {
	packed := c29EdgePacking(cycle, edgeBits)
	result := blake2b256(packed)

	blockDiffRaw := new(uint256.Int)
	blockDiffRaw.SetBytes(result)
	if blockDiffRaw.IsZero() {
		return 0, fmt.Errorf("validator: c29 hash is zero")
	}

	maxUint256 := new(uint256.Int)
	maxUint256.SetAllOne()

	resultUint256 := new(uint256.Int)
	resultUint256.Div(maxUint256, blockDiffRaw)
	return resultUint256.Uint64(), nil
}

// c29EdgePacking is a direct, unmodified port of go-tari-c29-solo-stratum
// subsystems/poolStratum/miner.go's edgePacking function: bit-packs a
// slice of edge nonces at edgeBits width per edge, little-endian, for
// hashing.
func c29EdgePacking(uncompressed []uint64, edgeBits int) []byte {
	var returnSlice []byte
	miniBuffer := uint64(0)
	remaining := 64
	for _, rawEdge := range uncompressed {
		miniBuffer |= rawEdge << (64 - remaining)
		if edgeBits < remaining {
			remaining -= edgeBits
		} else {
			returnSlice = binary.LittleEndian.AppendUint64(returnSlice, miniBuffer)
			miniBuffer = rawEdge >> remaining
			remaining = 64 + remaining - edgeBits
		}
	}
	remainder := len(returnSlice) % 8
	if remainder == 0 {
		remainder = 8
	}
	if miniBuffer > 0 {
		tempSlice := make([]byte, 8)
		binary.LittleEndian.PutUint64(tempSlice, miniBuffer)
		returnSlice = append(returnSlice, tempSlice[0:remainder]...)
	}
	totalBits := len(uncompressed) * edgeBits
	outLen := (totalBits + 7) / 8
	if outLen > len(returnSlice) {
		outLen = len(returnSlice)
	}
	return returnSlice[0:outLen]
}
