// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	tarilib "github.com/Snipa22/go-tari-lib/nodeGRPC"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// NodeClient is leaf-direct's own implementation of solo.NodeClient
// (reused, not modified — see internal/leaflib/solo/node.go's own
// interface), backed by github.com/Snipa22/go-tari-lib's real
// per-call-injectable *nodeGRPC.Client (v1.2.0), NOT
// go-tari-grpc-lib/v3's older package-level-singleton-only API that
// solo.GRPCNodeClient wraps. leaf-direct's primary template-fetch
// connection uses this same safe, independently-connected Client type
// as the multi-node block submitter (multisubmit.go) — there is no
// reason for the primary connection to use the unsafe singleton API
// just because leaf-solo historically did.
type NodeClient struct {
	client *tarilib.Client
}

// NewNodeClient dials address (host:port) via tarilib.NewClient and
// returns a ready-to-use NodeClient. Unlike solo.NewGRPCNodeClient,
// this holds its own independent connection — constructing more than
// one of these (e.g. for template source + a distinct GRPC relay
// consumer node) is fully safe, unlike the singleton API leaf-solo
// uses.
func NewNodeClient(address string) (*NodeClient, error) {
	c, err := tarilib.NewClient(address)
	if err != nil {
		return nil, err
	}
	return &NodeClient{client: c}, nil
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

// poolCoinbaseExtraTag identifies go-crypto-pool leaf-direct in the
// coinbase extra field, leaf-direct's own counterpart to
// solo/node.go's poolCoinbaseExtraTag.
var poolCoinbaseExtraTag = []byte("GCPOOL-DIRECT")

// GetBlockTemplate implements solo.NodeClient. Mirrors
// solo.GRPCNodeClient.GetBlockTemplate's real coinbase-extra
// randomization exactly (see that method's doc comment for the full
// per-xn rationale) — duplicated rather than reused because
// solo.GRPCNodeClient is a concrete type bound to the singleton API,
// not something this type can delegate to while using its own
// independent connection.
func (c *NodeClient) GetBlockTemplate(_ context.Context, payoutAddress string, algo poolpb.Algo) (*tari_generated.GetNewBlockResult, error) {
	nonceBuf := randomNonceBuf()
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

	return c.client.GetNewBlockTemplateWithCoinbases(&tari_generated.GetNewBlockTemplateWithCoinbasesRequest{
		Algo:      &tari_generated.PowAlgo{PowAlgo: tariPowAlgo(algo)},
		Coinbases: coinbases,
	})
}

// GetTipInfo implements solo.NodeClient.
func (c *NodeClient) GetTipInfo(_ context.Context) (*tari_generated.TipInfoResponse, error) {
	return c.client.GetTipInfo()
}

// SubmitBlock implements solo.NodeClient. This is leaf-direct's
// PRIMARY node's submission path — used only as a fallback/legacy
// single-node path (e.g. Probe-adjacent code, or if no
// LEAF_DIRECT_SUBMIT_NODES are configured at all beyond the primary).
// The real, primary block-submission path for a genuine find is
// MultiNodeSubmitter.SubmitBlock (multisubmit.go), which always
// includes the primary node's own address alongside any additionally
// configured ones — see cmd/leaf-direct/main.go's wiring.
func (c *NodeClient) SubmitBlock(_ context.Context, block *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	return c.client.SubmitBlock(block)
}

// Close releases the underlying GRPC connection.
func (c *NodeClient) Close() error {
	return c.client.Close()
}

// Compile-time assertion that NodeClient satisfies solo.NodeClient
// (the interface this package reuses as-is, per the task's explicit
// direction not to reinvent it).
var _ solo.NodeClient = (*NodeClient)(nil)
