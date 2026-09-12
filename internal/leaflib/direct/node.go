// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	tarilib "github.com/Snipa22/go-tari-lib/nodeGRPC"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// NodeClient is leaf-direct's own implementation of solo.NodeClient
// (the coin-agnostic interface — see internal/leaflib/solo/node.go's
// own doc comment), backed by github.com/Snipa22/go-tari-lib's real
// per-call-injectable *nodeGRPC.Client (v1.2.0), NOT
// go-tari-grpc-lib/v3's older package-level-singleton-only API that
// solo.GRPCNodeClient wraps. leaf-direct's primary template-fetch
// connection uses this same safe, independently-connected Client type
// as the multi-node block submitter (multisubmit.go) — there is no
// reason for the primary connection to use the unsafe singleton API
// just because leaf-solo historically did.
type NodeClient struct {
	client *tarilib.Client

	// coinbaseExtraTag is this instance's configured coinbase-extra
	// ownership tag, leaf-direct's own counterpart to
	// solo/node.go's GRPCNodeClient.coinbaseExtraTag — see that
	// field's doc comment. Runtime-configurable (was formerly a
	// single hardcoded package-level "GCPOOL-DIRECT" constant) —
	// see cmd/leaf-direct/main.go's -coinbase-extra-tag flag.
	coinbaseExtraTag []byte
}

// NewNodeClient dials address (host:port) via tarilib.NewClient and
// returns a ready-to-use NodeClient. Unlike solo.NewGRPCNodeClient,
// this holds its own independent connection — constructing more than
// one of these (e.g. for template source + a distinct GRPC relay
// consumer node) is fully safe, unlike the singleton API leaf-solo
// uses. coinbaseExtraTag is already-normalized (see
// solo.NormalizeCoinbaseExtraTag) and is appended to every fetched
// block template's coinbase-extra field ahead of the per-xn random
// nonce (see GetBlockTemplate).
func NewNodeClient(address string, coinbaseExtraTag []byte) (*NodeClient, error) {
	c, err := tarilib.NewClient(address)
	if err != nil {
		return nil, err
	}
	return &NodeClient{client: c, coinbaseExtraTag: coinbaseExtraTag}, nil
}

// tariPowAlgo mirrors solo/node.go's own unexported tariPowAlgo exactly
// (same real tari_generated.PowAlgo_PowAlgos mapping — see that
// function's doc comment for the full provenance) — duplicated here
// rather than imported because it is unexported in the read-only solo
// package.
func tariPowAlgo(algo poolpb.Algo) tari_generated.PowAlgo_PowAlgos {
	switch algo {
	case poolpb.Algo_ALGO_C29:
		return tari_generated.PowAlgo_POW_ALGOS_CUCKAROO
	case poolpb.Algo_ALGO_RXT:
		return tari_generated.PowAlgo_POW_ALGOS_RANDOMXT
	default:
		return tari_generated.PowAlgo_POW_ALGOS_SHA3X
	}
}

// GetBlockTemplate implements solo.NodeClient. Mirrors
// solo.GRPCNodeClient.GetBlockTemplate's real coinbase-extra
// randomization exactly (see that method's doc comment for the full
// per-xn rationale) — duplicated rather than reused because
// solo.GRPCNodeClient is a concrete type bound to the singleton API,
// not something this type can delegate to while using its own
// independent connection. Builds a fully-formed *solo.Job directly
// (per the coin-agnostic NodeClient contract — see solo/node.go's doc
// comment), not a coin-typed result JobManager would need to parse
// itself.
func (c *NodeClient) GetBlockTemplate(_ context.Context, payoutAddress string, algo poolpb.Algo) (*solo.Job, error) {
	coinbaseExtra := c.buildCoinbaseExtra()

	coinbases := []*tari_generated.NewBlockCoinbase{
		{
			Address:            payoutAddress,
			Value:              100,
			StealthPayment:     false,
			RevealedValueProof: true,
			CoinbaseExtra:      coinbaseExtra,
		},
	}

	result, err := c.client.GetNewBlockTemplateWithCoinbases(&tari_generated.GetNewBlockTemplateWithCoinbasesRequest{
		Algo:      &tari_generated.PowAlgo{PowAlgo: tariPowAlgo(algo)},
		Coinbases: coinbases,
	})
	if err != nil {
		return nil, err
	}
	return tariJobFromResult(result, algo)
}

// buildCoinbaseExtra combines this instance's configured
// coinbaseExtraTag with a fresh per-xn random nonce buffer into the
// exact []byte GetBlockTemplate submits as CoinbaseExtra — leaf-direct's
// own counterpart to solo.GRPCNodeClient.buildCoinbaseExtra. Factored
// out so tests can exercise the exact tag-inclusion logic without a
// real GRPC connection (see node_test.go).
func (c *NodeClient) buildCoinbaseExtra() []byte {
	nonceBuf := leaflib.RandomNonceBuf()
	coinbaseExtra := make([]byte, 0, len(c.coinbaseExtraTag)+len(nonceBuf))
	coinbaseExtra = append(coinbaseExtra, c.coinbaseExtraTag...)
	coinbaseExtra = append(coinbaseExtra, nonceBuf...)
	return coinbaseExtra
}

// tariJobFromResult mirrors solo/node.go's own unexported
// tariJobFromResult exactly — builds a coin-agnostic *solo.Job from a
// real Tari GetNewBlockResult.
//
// job_id must be a purely random, opaque wire token, NEVER derived
// from BlockHash (or any other template content) — this used to call
// leaflib.JobIDFromBlockHash, which was CONFIRMED unsafe: see
// internal/leaflib/solo/monero_node.go's GetBlockTemplate doc comment
// for the concrete real production incident (RXM's prevHash+height
// colliding across two genuinely different templates at an unmoved
// tip) that this fix applies here too, and
// internal/leaflib/solo/node.go's tariJobFromResult doc comment for
// why a content-derived ID was never doing real collision-avoidance
// work in the first place, even for Tari/SHA3X, since
// JobManager.RestampDifficulty (solo/job.go) deliberately reuses the
// SAME job_id for the SAME template on purpose whenever only
// difficulty changes.
func tariJobFromResult(result *tari_generated.GetNewBlockResult, algo poolpb.Algo) (*solo.Job, error) {
	if result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return nil, fmt.Errorf("direct: GetBlockTemplate returned an incomplete result")
	}
	id, err := leaflib.NewRandomHexID()
	if err != nil {
		return nil, fmt.Errorf("direct: generating random job id: %w", err)
	}
	return &solo.Job{
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

// GetTipInfo implements solo.NodeClient.
func (c *NodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	tip, err := c.client.GetTipInfo()
	if err != nil {
		return 0, err
	}
	return tip.GetMetadata().GetBestBlockHeight(), nil
}

// BuildCandidateBlock implements solo.NodeClient. This is the real,
// per-algo candidate-construction logic that used to live directly in
// session.go's own blockCandidate method — moved here (leaf-direct's
// own NodeClient implementation) so ALL of this leaf's real
// Tari-specific block-cloning/nonce-patching/difficulty-derivation
// logic lives inside the NodeClient implementation that owns the
// Tari-shaped template data, mirroring solo.GRPCNodeClient's own
// BuildCandidateBlock exactly (same real formulas, this package's own
// wireutil.go helpers).
func (c *NodeClient) BuildCandidateBlock(job *solo.Job, nonce uint64, proof solo.SubmitProof) (uint64, any, error) {
	return tariBuildCandidateBlock(job, nonce, proof)
}

// tariBuildCandidateBlock is BuildCandidateBlock's real implementation,
// factored out so both NodeClient (production) and this package's own
// test double (session_test.go's fakeDirectNodeClient) exercise the
// exact same real difficulty/candidate-construction logic.
func tariBuildCandidateBlock(job *solo.Job, nonce uint64, proof solo.SubmitProof) (diff uint64, candidate any, err error) {
	result, ok := job.TemplateData.(*tari_generated.GetNewBlockResult)
	if !ok || result == nil || result.GetBlock() == nil {
		return 0, nil, fmt.Errorf("direct: job.TemplateData does not hold a real Tari GetNewBlockResult with a populated Block (algo %v)", job.Algo)
	}
	switch job.Algo {
	case poolpb.Algo_ALGO_C29:
		diff, err = validator.C29Difficulty(proof.Cycle, c29SubmitEdgeBits)
		if err != nil {
			return 0, nil, err
		}
		return diff, leaflib.CloneBlockWithC29Proof(result.GetBlock(), nonce, proof.Cycle, c29SubmitEdgeBits, validator.C29EdgePacking), nil
	case poolpb.Algo_ALGO_RXT:
		hashBytes, hexErr := hex.DecodeString(proof.ResultHex)
		if hexErr != nil {
			return 0, nil, fmt.Errorf("direct: rxt claimed result hash is not valid hex: %w", hexErr)
		}
		diff, err = leaflib.RXTLittleEndianDifficulty(hashBytes)
		if err != nil {
			return 0, nil, err
		}
		return diff, leaflib.CloneBlockWithNonce(result.GetBlock(), nonce), nil
	default:
		diff = validator.SHA3XHeaderDiff(nonce, job.Header)
		return diff, leaflib.CloneBlockWithNonce(result.GetBlock(), nonce), nil
	}
}

// SubmitBlock implements solo.NodeClient. candidate must be a
// *tari_generated.Block produced by this SAME implementation's own
// BuildCandidateBlock. This is leaf-direct's PRIMARY node's submission
// path — used only as a fallback/legacy single-node path (e.g.
// Probe-adjacent code, or if no LEAF_DIRECT_SUBMIT_NODES are configured
// at all beyond the primary). The real, primary block-submission path
// for a genuine find is MultiNodeSubmitter.SubmitBlock (multisubmit.go),
// which always includes the primary node's own address alongside any
// additionally configured ones — see cmd/leaf-direct/main.go's wiring.
func (c *NodeClient) SubmitBlock(_ context.Context, candidate any) error {
	block, ok := candidate.(*tari_generated.Block)
	if !ok {
		return fmt.Errorf("direct: SubmitBlock: candidate is not a *tari_generated.Block (got %T)", candidate)
	}
	_, err := c.client.SubmitBlock(block)
	return err
}

// Close releases the underlying GRPC connection.
func (c *NodeClient) Close() error {
	return c.client.Close()
}

// Compile-time assertion that NodeClient satisfies solo.NodeClient
// (the coin-agnostic interface this package's own NodeClient
// implementation must match).
var _ solo.NodeClient = (*NodeClient)(nil)
