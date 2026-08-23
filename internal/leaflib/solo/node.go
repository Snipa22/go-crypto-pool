// Copyright and license: see repository LICENSE (MIT).
//
// Package solo implements the leaf-solo vertical slice: a miner-facing
// TCP protocol (see protocol.go/session.go), a coin-agnostic
// NodeClient/Job/JobManager pipeline (this file + job.go) with a real
// Tari base-node GRPC implementation (GRPCNodeClient, below) and a
// real Monero daemon JSON-RPC implementation (monero_node.go), and
// wiring (server.go) that ties both to the already-merged
// internal/leaflib.ConnectionManager and
// internal/leaflib/validator.SHA3XValidator/RandomXValidator. There is
// no backend connection in this mode — see cmd/leaf-solo/main.go's doc
// comment.
package solo

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/nodeGRPC"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// SubmitProof carries whatever a submitted share's proof genuinely
// has that is shared, at the NodeClient boundary, across every algo
// this codebase supports (SHA3X, C29, RXT, and Monero's own RandomX
// variant): the C29 edge cycle (nil for every other algo) and the
// already-hex-decoded claimed RandomX result hash (empty for SHA3X/
// C29, populated for RXT and Monero). The nonce itself is passed as
// BuildCandidateBlock's own separate, explicit parameter rather than
// folded into this struct, since every algo has exactly one nonce and
// it is never coin-specific in shape (a bare uint64).
type SubmitProof struct {
	// Cycle is the C29 42-edge Cuckaroo29 cycle (poolpb.SubmitRequest.POW,
	// pre-decoded). nil/empty for every other algo.
	Cycle []uint64

	// ResultHex is the miner's claimed RandomX result hash, hex
	// encoded, EXACTLY as it rode the wire (poolpb.SubmitRequest.Result)
	// — used by RXT and by Monero's own RandomX PoW. Empty for SHA3X/
	// C29, which have no separate claimed-result-hash wire field (their
	// hash is re-derived by the validator from the header+nonce
	// instead of trusted from the miner).
	ResultHex string
}

// NodeClient is the coin-agnostic set of block-source operations
// leaf-solo (and leaf-direct, which supplies its own implementation —
// see internal/leaflib/direct/node.go) needs, independent of which
// coin/PoW family the owning process is configured for. Each concrete
// implementation owns:
//
//   - its own real block-template-fetch/parsing logic, populating a
//     fully-formed *Job directly (GetBlockTemplate) rather than handing
//     JobManager a coin-typed result to parse itself;
//   - its own real candidate-block construction (BuildCandidateBlock),
//     given a validated share's nonce/proof, returning an opaque
//     candidate value only that SAME implementation's SubmitBlock
//     knows how to interpret;
//   - its own real block-submission RPC (SubmitBlock).
//
// GRPCNodeClient (below) is the production Tari implementation, backed
// by go-tari-grpc-lib/v3's nodeGRPC package (the real, current API
// surface for this library as of v3.2.0: a package-level
// InitNodeGRPC(address) call followed by package-level RPC wrapper
// functions operating on that connection — there is no per-call
// injectable *Client type in this version, so GRPCNodeClient wraps the
// package-level singleton behind this interface instead of assuming an
// API shape that doesn't exist yet). MoneroNodeClient (monero_node.go)
// is the production Monero implementation, backed by a real monerod
// JSON-RPC 2.0 connection. internal/leaflib/direct's own NodeClient is
// a second, independently-connected Tari implementation (real
// per-call-injectable GRPC client, for leaf-direct's own multi-node
// submission needs).
type NodeClient interface {
	// GetBlockTemplate fetches a fresh block template for algo with a
	// single coinbase output paying payoutAddress, and returns it as a
	// fully-formed *Job (ID/Height/Header/BlockHash/
	// NetworkTargetDifficulty/TemplateData/VmKey/CreatedAt all
	// populated by this call — StaticDifficulty is deliberately left
	// at its zero value; JobManager stamps that itself, since it is a
	// per-session/per-request concern, not a template-fetch concern).
	// algo is required (not defaulted here); callers that want the
	// pre-multi-algo SHA3X-only behavior pass poolpb.Algo_ALGO_SHA3X
	// explicitly — see job.go's JobManagerConfig.Algo, which is what
	// normalizes an unconfigured/zero-value Algo to SHA3X for backward
	// compatibility before it ever reaches this method.
	GetBlockTemplate(ctx context.Context, payoutAddress string, algo poolpb.Algo) (*Job, error)

	// GetTipInfo fetches the current chain tip height, mirroring
	// go-tari-sha3x-solo-stratum's subsystems/tipDataCache/tip.go
	// (Tari) or a real monerod get_last_block_header/get_info call
	// (Monero). Returning a bare height (rather than a coin-typed
	// response) keeps JobManager's own tip-poll loop (job.go's
	// tipPollLoop) coin-agnostic.
	GetTipInfo(ctx context.Context) (height uint64, err error)

	// BuildCandidateBlock computes the real, algo-appropriate
	// difficulty of an already-validated share (nonce + proof) against
	// job, and the real candidate block that would be submitted if
	// that difficulty turns out to meet job.NetworkTargetDifficulty
	// (the caller — session.go's handleSubmit — decides whether to
	// actually call SubmitBlock with it). candidate is opaque to every
	// caller outside this SAME NodeClient implementation; only its own
	// SubmitBlock ever type-asserts it back to a concrete type (for
	// Tari, *tari_generated.Block; for Monero, the nonce-patched
	// blocktemplate_blob bytes).
	BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (diff uint64, candidate any, err error)

	// SubmitBlock submits a completed candidate block (as produced by
	// this SAME NodeClient's own BuildCandidateBlock) to the real node.
	SubmitBlock(ctx context.Context, candidate any) error
}

// TariPowDataFromJob is the explicitly-named escape hatch for RXT's
// own proof construction (session.go's handleSubmit, building the
// real 76-byte Tari mining blob via rxt.go's createTariMiningBlob):
// RXT's blob format needs the job's current real
// ProofOfWork.pow_data bytes, which is genuinely Tari-protocol-specific
// (see rxt.go's doc comment) and is not part of the coin-agnostic
// Job/NodeClient shell. This extracts those bytes IF job.TemplateData
// holds a real *tari_generated.GetNewBlockResult with a populated
// Block/Header/Pow chain (true for every Tari NodeClient
// implementation — GRPCNodeClient here and direct.NodeClient), and
// returns nil otherwise (job.TemplateData is nil, holds some other
// coin's payload, or the chain is incomplete) — callers should treat a
// nil return exactly as they treated an empty/absent pow_data before
// this refactor (rxt.go's createTariMiningBlob already zero-pads a
// nil/short powData correctly).
func TariPowDataFromJob(job *Job) []byte {
	if job == nil {
		return nil
	}
	result, ok := job.TemplateData.(*tari_generated.GetNewBlockResult)
	if !ok || result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return nil
	}
	return result.GetBlock().GetHeader().GetPow().GetPowData()
}

// MoneroHashingBlobForSubmit is the explicitly-named escape hatch
// (mirroring TariPowDataFromJob above) that session-level submit
// handling (this package's own session.go, and leaf-direct's
// internal/leaflib/direct/session.go) uses to build the real RandomX
// verification input for an ALGO_RXM (Monero) submit.
//
// WHY THIS EXISTS: job.Header for a Monero job holds the UNPATCHED
// blockhashing_blob (nonce field still zero — see MoneroNodeClient's
// GetBlockTemplate, monero_node.go) because BuildCandidateBlock patches
// the nonce into the SEPARATE full blocktemplate_blob for submission,
// not into job.Header. validator.RandomXValidator needs the nonce
// actually patched into the hashing blob (the real pre-image Monero's
// own RandomX hashes) to verify a miner's claimed result hash — so this
// function re-derives job's real nonce offset (via the SAME real,
// never-hardcoded varint walk documented on monero_node.go) and returns
// a patched COPY, leaving job/job.TemplateData untouched.
//
// Returns an error if job.TemplateData does not hold a real
// *moneroTemplateData (i.e. this is not actually a Monero job) so
// callers can distinguish "not applicable" from "applicable but
// malformed" exactly like TariPowDataFromJob's nil-vs-error contract
// for Tari's RXT.
func MoneroHashingBlobForSubmit(job *Job, nonce uint64) ([]byte, error) {
	if job == nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForSubmit: nil job")
	}
	data, ok := job.TemplateData.(*moneroTemplateData)
	if !ok || data == nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForSubmit: job.TemplateData does not hold a real *moneroTemplateData (algo %v)", job.Algo)
	}
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(data.HashingBlob)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: re-parsing nonce offset for RandomX verification blob: %w", err)
	}
	if nonceOffset+4 > len(data.HashingBlob) {
		return nil, fmt.Errorf("solo: monero: nonce offset %d + 4 exceeds hashing blob length %d", nonceOffset, len(data.HashingBlob))
	}
	blob := make([]byte, len(data.HashingBlob))
	copy(blob, data.HashingBlob)
	var nonceBuf [4]byte
	binary.LittleEndian.PutUint32(nonceBuf[:], uint32(nonce))
	copy(blob[nonceOffset:nonceOffset+4], nonceBuf[:])
	return blob, nil
}

// GRPCNodeClient is the production NodeClient, backed by
// go-tari-grpc-lib/v3's nodeGRPC package against a real Tari base node.
type GRPCNodeClient struct{}

// NewGRPCNodeClient dials address (host:port) via nodeGRPC.InitNodeGRPC
// and returns a ready-to-use GRPCNodeClient. nodeGRPC's connection is a
// package-level singleton (see doc comment on NodeClient), so only one
// GRPCNodeClient should be constructed per process.
func NewGRPCNodeClient(address string) *GRPCNodeClient {
	nodeGRPC.InitNodeGRPC(address)
	return &GRPCNodeClient{}
}

// poolCoinbaseExtraTag identifies go-crypto-pool leaf-solo in the
// coinbase extra field, analogous to the legacy pool's "WUF"-bracketed
// squad-identifier scheme in blockTemplate.go's GetBlockSha3.
var poolCoinbaseExtraTag = []byte("GCPOOL-SOLO")

// tariPowAlgo maps this codebase's poolpb.Algo onto the real
// tari_generated.PowAlgo_PowAlgos wire value GetNewBlockTemplateWithCoinbases
// expects. Confirmed against go-tari-grpc-lib/v3's own generated enum
// (tari_generated/block.pb.go): the real C29/Cuckaroo29 value is
// POW_ALGOS_CUCKAROO (= 3), NOT some "C29"-named constant — there is no
// enum value with "C29" in its name in this library. ALGO_UNSPECIFIED
// maps to SHA3X for defensive backward compatibility (JobManagerConfig.Algo
// already normalizes this before it ever reaches here — see job.go — but
// this method doesn't assume that normalization has definitely happened).
// ALGO_RXT (Tari's own native RandomX PoW — NOT merge-mining RXM, which
// remains explicitly out of scope for this leaf) maps to the real
// tari_generated.PowAlgo_POW_ALGOS_RANDOMXT value — confirmed = 2 in this
// session's research (go-tari-grpc-lib/v3's block.pb.go), matching the
// real Tari Rust source's own PowAlgorithm::RandomXT discriminant (also
// 2, base_layer/transaction_components/src/tari_proof_of_work/
// proof_of_work_algorithm.rs). Do NOT confuse this with
// PowAlgo_POW_ALGOS_RANDOMXM (value 0) — that is RXM/merge-mining,
// explicitly out of scope.
// ALGO_RXM is not supported by this leaf's block-template fetch — RXM
// (Monero merge-mining) requires an entirely different
// minotari_merge_mining_proxy-style pipeline this leaf does not
// implement.
func tariPowAlgo(algo poolpb.Algo) (tari_generated.PowAlgo_PowAlgos, error) {
	switch algo {
	case poolpb.Algo_ALGO_UNSPECIFIED, poolpb.Algo_ALGO_SHA3X:
		return tari_generated.PowAlgo_POW_ALGOS_SHA3X, nil
	case poolpb.Algo_ALGO_C29:
		return tari_generated.PowAlgo_POW_ALGOS_CUCKAROO, nil
	case poolpb.Algo_ALGO_RXT:
		return tari_generated.PowAlgo_POW_ALGOS_RANDOMXT, nil
	default:
		return 0, fmt.Errorf("solo: leaf-solo does not support fetching Tari block templates for algo %v (only SHA3X, C29, and RXT are supported via GRPCNodeClient — RXM merge-mining is explicitly out of scope, and Monero has its own MoneroNodeClient)", algo)
	}
}

// GetBlockTemplate implements NodeClient. This is a faithful port of
// go-tari-sha3x-solo-stratum's GetBlockSha3 (subsystems/blockTemplateCache/
// blockTemplate.go) / go-tari-c29-solo-stratum's equivalent (both call the
// exact same GetNewBlockTemplateWithCoinbases GRPC method, varying only the
// requested PowAlgo — see tariPowAlgo above), adapted for solo mode: a
// single coinbase output paying the leaf's configured solo payout address
// gets 100% of the coinbase share (Value: 100 mirrors the legacy code's
// coinbase-share weighting field, not an absolute currency amount — the
// base node computes the actual reward split from this), instead of the
// legacy per-miner multi-coinbase pool scheme.
//
// IMPORTANT for per-xn extranonce support (job.go's JobManager.JobForXN):
// this already appends a FRESH, cryptographically-independent random
// 8-byte nonce buffer to the coinbase-extra field on EVERY call — see
// nonceBuf below — mirroring the legacy GetBlockSha3's own
// `binary.LittleEndian.PutUint64(buf, rand.Uint64())` coinbase-extra
// randomization exactly. That random data flows into the coinbase
// transaction, which changes the resulting block's MergeMiningHash, so
// two calls to this method (e.g. for two different sessions' xn values)
// already produce genuinely distinct, non-overlapping hash pre-images
// even at the same chain height — this method did NOT need any new
// randomization logic added for per-xn support; JobManager only needed
// to call it once per newly-seen xn and cache the result (see job.go).
func (c *GRPCNodeClient) GetBlockTemplate(_ context.Context, payoutAddress string, algo poolpb.Algo) (*Job, error) {
	powAlgo, err := tariPowAlgo(algo)
	if err != nil {
		return nil, err
	}

	nonceBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBuf, rand.Uint64())
	coinbaseExtra := make([]byte, 0, len(poolCoinbaseExtraTag)+len(nonceBuf))
	coinbaseExtra = append(coinbaseExtra, poolCoinbaseExtraTag...)
	coinbaseExtra = append(coinbaseExtra, nonceBuf...)

	coinbases := []*tari_generated.NewBlockCoinbase{
		{
			Address:            payoutAddress,
			Value:              100,
			StealthPayment:     false,
			RevealedValueProof: true,
			CoinbaseExtra:      coinbaseExtra,
		},
	}

	result, err := nodeGRPC.GetNewBlockTemplateWithCoinbases(&tari_generated.GetNewBlockTemplateWithCoinbasesRequest{
		Algo:      &tari_generated.PowAlgo{PowAlgo: powAlgo},
		Coinbases: coinbases,
	})
	if err != nil {
		return nil, err
	}
	return tariJobFromResult(result, algo)
}

// tariJobFromResult builds a coin-agnostic *Job from a real Tari
// GetNewBlockResult — shared by GRPCNodeClient here and reusable (by
// package copy, following this codebase's own established
// duplicate-small-helpers-across-packages convention — see
// internal/leaflib/direct/wireutil.go's doc comment) by
// direct.NodeClient's own GetBlockTemplate.
func tariJobFromResult(result *tari_generated.GetNewBlockResult, algo poolpb.Algo) (*Job, error) {
	if result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return nil, fmt.Errorf("solo: GetBlockTemplate returned an incomplete result")
	}
	id, err := jobIDFromBlockHash(result.GetBlockHash())
	if err != nil {
		return nil, fmt.Errorf("solo: deriving job id from block hash: %w", err)
	}
	return &Job{
		ID:                      id,
		Algo:                    algo,
		Height:                  result.GetBlock().GetHeader().GetHeight(),
		Header:                  result.GetMergeMiningHash(),
		BlockHash:               result.GetBlockHash(),
		NetworkTargetDifficulty: result.GetMinerData().GetTargetDifficulty(),
		TemplateData:            result,
		VmKey:                   result.GetVmKey(),
		CreatedAt:               time.Now(),
	}, nil
}

// GetTipInfo implements NodeClient, wrapping nodeGRPC.GetTipInfo.
func (c *GRPCNodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	tip, err := nodeGRPC.GetTipInfo()
	if err != nil {
		return 0, err
	}
	return tip.GetMetadata().GetBestBlockHeight(), nil
}

// BuildCandidateBlock implements NodeClient. This is the real,
// per-algo candidate-construction logic that used to live directly in
// session.go's own blockCandidate method — moved here so that ALL of
// this leaf's real Tari-specific block-cloning/nonce-patching/
// difficulty-derivation logic lives inside the NodeClient
// implementation that owns the Tari-shaped template data, not in the
// coin-agnostic session/wire-handling layer.
func (c *GRPCNodeClient) BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (uint64, any, error) {
	return tariBuildCandidateBlock(job, nonce, proof)
}

// tariBuildCandidateBlock is BuildCandidateBlock's real implementation,
// factored out so both GRPCNodeClient (production) and this package's
// own test doubles (job_test.go's fakeNodeClient) exercise the exact
// same real difficulty/candidate-construction logic — a fake NodeClient
// that reimplemented a SHADOW of this logic would defeat the point of
// session-level regression tests.
func tariBuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (diff uint64, candidate any, err error) {
	result, ok := job.TemplateData.(*tari_generated.GetNewBlockResult)
	if !ok || result == nil || result.GetBlock() == nil {
		return 0, nil, fmt.Errorf("solo: job.TemplateData does not hold a real Tari GetNewBlockResult with a populated Block (algo %v)", job.Algo)
	}
	switch job.Algo {
	case poolpb.Algo_ALGO_C29:
		diff, err = validator.C29Difficulty(proof.Cycle, c29SubmitEdgeBits)
		if err != nil {
			return 0, nil, err
		}
		return diff, cloneBlockWithC29Proof(result.GetBlock(), nonce, proof.Cycle), nil
	case poolpb.Algo_ALGO_RXT:
		hashBytes, hexErr := hex.DecodeString(proof.ResultHex)
		if hexErr != nil {
			return 0, nil, fmt.Errorf("solo: rxt claimed result hash is not valid hex: %w", hexErr)
		}
		diff, err = rxtLittleEndianDifficulty(hashBytes)
		if err != nil {
			return 0, nil, err
		}
		// RXT has no supplemental on-chain pow_data to stamp (unlike
		// C29's edge-packed cycle) — the template's own Header.Pow
		// (pow_algo=RandomXT, whatever pow_data the base node already
		// populated it with) is left exactly as fetched; only
		// Header.Nonce is mutated, same as SHA3X/cloneBlockWithNonce.
		return diff, cloneBlockWithNonce(result.GetBlock(), nonce), nil
	default:
		diff = validator.SHA3XHeaderDiff(nonce, job.Header)
		return diff, cloneBlockWithNonce(result.GetBlock(), nonce), nil
	}
}

// SubmitBlock implements NodeClient, wrapping nodeGRPC.SubmitBlock.
// candidate must be a *tari_generated.Block produced by this SAME
// implementation's own BuildCandidateBlock.
func (c *GRPCNodeClient) SubmitBlock(_ context.Context, candidate any) error {
	block, ok := candidate.(*tari_generated.Block)
	if !ok {
		return fmt.Errorf("solo: SubmitBlock: candidate is not a *tari_generated.Block (got %T)", candidate)
	}
	_, err := nodeGRPC.SubmitBlock(block)
	return err
}
