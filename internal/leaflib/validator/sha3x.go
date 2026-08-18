// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"context"
	"crypto/sha3"
	"encoding/binary"
	"errors"

	"github.com/holiman/uint256"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// sha3xPowAlgoByte is the wire value of tari_generated's
// PowAlgo_POW_ALGOS_SHA3X (see go-tari-grpc-lib/v3/tari_generated's
// block.pb.go: `PowAlgo_POW_ALGOS_SHA3X PowAlgo_PowAlgos = 1`). The real
// GetHeaderDiff hashes this byte in as part of the header pre-image; since
// this validator only ever handles SHA3X shares, it's a fixed constant
// here rather than a field threaded through SHA3XProof.
const sha3xPowAlgoByte = byte(1)

// SHA3XValidator verifies Tari's SHA3X PoW: a triple-chained SHA3-256
// hash of (nonce || header-hash-material || pow-algo byte), compared
// against a difficulty target.
//
// This is a faithful port of the real, production verification logic in
// go-tari-sha3x-solo-stratum's subsystems/blockTemplateCache/blockTemplate.go,
// function GetHeaderDiff (as of the locally-cloned reference checkout —
// see /workspace/omni-pool-review/go-tari-sha3x-solo-stratum), which
// minerStruct.SubmitJob (subsystems/poolStratum/miner.go) calls directly
// for its difficulty check. GetHeaderDiff's real algorithm, unchanged
// here:
//
//	h1 := sha3.New256(); h1.Write(LE64(nonce)); h1.Write(miningHash); h1.Write([]byte{powAlgo})
//	resp := h1.Sum(nil)
//	h2 := sha3.New256(); h2.Write(resp); resp2 := h2.Sum(nil)
//	h3 := sha3.New256(); h3.Write(resp2); resp3 := h3.Sum(nil)
//	diff = maxUint256 / uint256(resp3)
//
// This uses Go's stdlib crypto/sha3 (added in Go 1.24, same as the legacy
// code's own `crypto/sha3` import — this is the same package, not a
// substitute implementation).
//
// Adaptation note (see internal/proto/share.proto's SHA3XProof doc
// comment): the legacy GetHeaderDiff takes a full grpc BlockHeader plus a
// separately-tracked MergeMiningHash. This codebase's SHA3XProof only
// carries `header` (bytes) + `nonce` (uint64), per the schema's existing
// "straight header+nonce pair" design. This validator treats
// SHA3XProof.header as the miningHash pre-image material GetHeaderDiff
// hashes alongside the nonce — the triple-SHA3-256-chain-to-uint256-diff
// math itself (the actual "hash comparison, difficulty-target math" this
// task calls out) is unchanged from the real function.
type SHA3XValidator struct{}

// NewSHA3XValidator returns a ready-to-use SHA3XValidator. It is
// stateless and safe for concurrent use.
func NewSHA3XValidator() *SHA3XValidator {
	return &SHA3XValidator{}
}

// Validate implements AlgoValidator. It reports (true, nil) only if the
// share carries a SHA3XProof and its derived difficulty meets
// share.BlockDiff (when BlockDiff > 0).
func (v *SHA3XValidator) Validate(_ context.Context, share *poolpb.Share) (bool, error) {
	if share == nil {
		return false, errors.New("validator: nil share")
	}
	proof, ok := share.GetRawProof().(*poolpb.Share_Sha3XProof)
	if !ok || proof == nil || proof.Sha3XProof == nil {
		return false, ErrWrongProofType
	}
	p := proof.Sha3XProof

	diff := sha3xHeaderDiff(p.GetNonce(), p.GetHeader())

	if share.GetBlockDiff() > 0 && diff < uint64(share.GetBlockDiff()) {
		return false, nil
	}
	return true, nil
}

// sha3xHeaderDiff is a direct, unmodified port of
// go-tari-sha3x-solo-stratum's GetHeaderDiff (see type doc comment for
// the algorithm and provenance).
func sha3xHeaderDiff(nonce uint64, miningHash []byte) uint64 {
	nonceLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceLE, nonce)

	h1 := sha3.New256()
	h1.Write(nonceLE)
	h1.Write(miningHash)
	h1.Write([]byte{sha3xPowAlgoByte})
	resp := h1.Sum(nil)

	h2 := sha3.New256()
	h2.Write(resp)
	resp2 := h2.Sum(nil)

	h3 := sha3.New256()
	h3.Write(resp2)
	resp3 := h3.Sum(nil)

	blockDiffRaw := new(uint256.Int)
	blockDiffRaw.SetBytes(resp3)
	if blockDiffRaw.IsZero() {
		return 0
	}

	maxUint256 := new(uint256.Int)
	maxUint256.SetAllOne()

	result := new(uint256.Int)
	result.Div(maxUint256, blockDiffRaw)
	return result.Uint64()
}
