// Copyright and license: see repository LICENSE (MIT).
//
// Package solo implements the leaf-solo vertical slice: a miner-facing
// TCP protocol (see protocol.go/session.go), a Tari base-node GRPC job
// pipeline (this file + job.go), and wiring (server.go) that ties both
// to the already-merged internal/leaflib.ConnectionManager and
// internal/leaflib/validator.SHA3XValidator. There is no backend
// connection in this mode — see cmd/leaf-solo/main.go's doc comment.
package solo

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/Snipa22/go-tari-grpc-lib/v3/nodeGRPC"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// NodeClient is the set of Tari base-node GRPC operations leaf-solo
// needs. It exists so JobManager (job.go) is testable against a fake
// implementation without a real Tari base node — GRPCNodeClient below is
// the production implementation, backed by go-tari-grpc-lib/v3's
// nodeGRPC package (the real, current API surface for this library as
// of v3.2.0: a package-level InitNodeGRPC(address) call followed by
// package-level RPC wrapper functions operating on that connection —
// there is no per-call injectable *Client type in this version, so
// GRPCNodeClient wraps the package-level singleton behind this
// interface instead of assuming an API shape that doesn't exist yet).
type NodeClient interface {
	// GetBlockTemplate fetches a fresh block template for algo with a
	// single coinbase output paying payoutAddress, mirroring the real
	// GetBlockSha3 flow in go-tari-sha3x-solo-stratum's
	// subsystems/blockTemplateCache/blockTemplate.go (SHA3X) and
	// go-tari-c29-solo-stratum's equivalent (Cuckaroo/C29) — both
	// reference implementations call the exact same
	// GetNewBlockTemplateWithCoinbases GRPC method, varying only the
	// requested tari_generated.PowAlgo. algo is required (not
	// defaulted here); callers that want the pre-multi-algo SHA3X-only
	// behavior pass poolpb.Algo_ALGO_SHA3X explicitly — see
	// job.go's JobManagerConfig.Algo, which is what normalizes an
	// unconfigured/zero-value Algo to SHA3X for backward compatibility
	// before it ever reaches this method.
	GetBlockTemplate(ctx context.Context, payoutAddress string, algo poolpb.Algo) (*tari_generated.GetNewBlockResult, error)

	// GetTipInfo fetches the current chain tip, mirroring
	// go-tari-sha3x-solo-stratum's subsystems/tipDataCache/tip.go.
	GetTipInfo(ctx context.Context) (*tari_generated.TipInfoResponse, error)

	// SubmitBlock submits a completed block to the base node, mirroring
	// the real call site in go-tari-sha3x-solo-stratum's
	// subsystems/poolStratum/miner.go (SubmitJob, around line 493).
	SubmitBlock(ctx context.Context, block *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error)
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
		return 0, fmt.Errorf("solo: leaf-solo does not support fetching block templates for algo %v (only SHA3X, C29, and RXT are supported — RXM merge-mining is explicitly out of scope)", algo)
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
// This is the FIRST time this leaf has ever requested a non-SHA3X
// (algo=C29) template from a real node — the same GRPC call/coinbase
// shape is reused unchanged, only the PowAlgo enum value differs.
func (c *GRPCNodeClient) GetBlockTemplate(_ context.Context, payoutAddress string, algo poolpb.Algo) (*tari_generated.GetNewBlockResult, error) {
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

	return nodeGRPC.GetNewBlockTemplateWithCoinbases(&tari_generated.GetNewBlockTemplateWithCoinbasesRequest{
		Algo:      &tari_generated.PowAlgo{PowAlgo: powAlgo},
		Coinbases: coinbases,
	})
}

// GetTipInfo implements NodeClient, wrapping nodeGRPC.GetTipInfo.
func (c *GRPCNodeClient) GetTipInfo(_ context.Context) (*tari_generated.TipInfoResponse, error) {
	return nodeGRPC.GetTipInfo()
}

// SubmitBlock implements NodeClient, wrapping nodeGRPC.SubmitBlock.
func (c *GRPCNodeClient) SubmitBlock(_ context.Context, block *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	return nodeGRPC.SubmitBlock(block)
}
