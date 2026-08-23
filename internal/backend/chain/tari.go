// Copyright and license: see repository LICENSE (MIT).
package chain

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Snipa22/go-tari-grpc-lib/v3/nodeGRPC"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tariNodeRPC is the narrow slice of go-tari-grpc-lib/v3's nodeGRPC
// package-level API TariVerifier actually needs — GetHeaderByHash and
// GetBlocks (wrapped by nodeGRPC as GetBlockByHeight, see node.go in
// internal/leaflib/solo for the same wrapper already used by
// GRPCNodeClient). This exists purely so tests can inject a fake
// without a real Tari base node: nodeGRPC itself has no injectable
// client type (it's a package-level singleton connection — see
// internal/leaflib/solo/node.go's doc comment on GRPCNodeClient for
// the same constraint), so tariNodeRPCAdapter below is the one real
// place this package touches that singleton.
type tariNodeRPC interface {
	GetHeaderByHash(hash []byte) (*tari_generated.BlockHeaderResponse, error)
	GetBlockByHeight(heights []uint64) ([]*tari_generated.Block, error)
}

// tariNodeRPCAdapter adapts nodeGRPC's package-level functions to
// tariNodeRPC.
type tariNodeRPCAdapter struct{}

func (tariNodeRPCAdapter) GetHeaderByHash(hash []byte) (*tari_generated.BlockHeaderResponse, error) {
	return nodeGRPC.GetHeaderByHash(hash)
}

func (tariNodeRPCAdapter) GetBlockByHeight(heights []uint64) ([]*tari_generated.Block, error) {
	return nodeGRPC.GetBlockByHeight(heights)
}

// TariVerifier is the production ChainVerifier for ALGO_RXT/ALGO_C29/
// ALGO_SHA3X (every algo mined against a Tari base node — see
// internal/leaflib/solo/node.go's tariPowAlgo for the same three-algo
// grouping), backed by a real Tari base node GRPC connection.
type TariVerifier struct {
	rpc tariNodeRPC
}

// NewTariVerifier dials address (host:port) via nodeGRPC.InitNodeGRPC
// (a package-level singleton connection — see this file's tariNodeRPC
// doc comment) and returns a ready-to-use TariVerifier. As with
// GRPCNodeClient (internal/leaflib/solo/node.go), only one
// TariVerifier's worth of nodeGRPC usage should exist per process,
// since InitNodeGRPC's connection is shared process-wide state.
func NewTariVerifier(address string) *TariVerifier {
	nodeGRPC.InitNodeGRPC(address)
	return &TariVerifier{rpc: tariNodeRPCAdapter{}}
}

// newTariVerifierWithRPC is the test seam: constructs a TariVerifier
// against an injected fake tariNodeRPC instead of the real
// process-wide nodeGRPC singleton.
func newTariVerifierWithRPC(rpc tariNodeRPC) *TariVerifier {
	return &TariVerifier{rpc: rpc}
}

// Verify implements ChainVerifier for Tari. It performs two real GRPC
// calls:
//
//  1. GetHeaderByHash(hashHex) — does the base node know this block at
//     all, and if so at what height/with how many confirmations
//     (BlockHeaderResponse.Confirmations is the base node's own
//     tip-depth field — see tari_generated.BlockHeaderResponse's doc
//     comment, confirmed from base_node.pb.go this session).
//  2. GetBlocks (wrapped as GetBlockByHeight) at that SAME height — is
//     the submitted hash still the block the node's current canonical
//     chain actually has at that height, or has it been superseded by
//     a different block (i.e. orphaned/reorged away)? GetHeaderByHash
//     alone cannot answer this: a base node may still serve a header
//     for a hash it once validated even after a competing block won
//     that height, so the two calls together are required to
//     distinguish "confirmed and canonical" from "was real, now
//     orphaned".
func (v *TariVerifier) Verify(_ context.Context, hashHex string, height int64) (VerifyResult, error) {
	if height < 0 {
		return VerifyResult{}, fmt.Errorf("chain: tari: height must be non-negative, got %d", height)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("chain: tari: hash %q is not valid hex: %w", hashHex, err)
	}

	headerResp, err := v.rpc.GetHeaderByHash(hashBytes)
	if err != nil {
		if isTariNotFound(err) {
			return VerifyResult{Found: false}, nil
		}
		return VerifyResult{}, fmt.Errorf("chain: tari: GetHeaderByHash(%s): %w", hashHex, err)
	}
	if headerResp == nil || headerResp.GetHeader() == nil {
		return VerifyResult{Found: false}, nil
	}
	if int64(headerResp.GetHeader().GetHeight()) != height {
		return VerifyResult{}, fmt.Errorf("chain: tari: GetHeaderByHash(%s) returned a header at height %d, but the block was submitted as height %d — refusing to guess which is right",
			hashHex, headerResp.GetHeader().GetHeight(), height)
	}

	canonicalBlocks, err := v.rpc.GetBlockByHeight([]uint64{uint64(height)})
	if err != nil {
		return VerifyResult{}, fmt.Errorf("chain: tari: GetBlocks(height=%d): %w", height, err)
	}

	orphaned := true
	canonicalHashHex := ""
	for _, b := range canonicalBlocks {
		if b == nil || b.GetHeader() == nil {
			continue
		}
		ch := hex.EncodeToString(b.GetHeader().GetHash())
		if canonicalHashHex == "" {
			canonicalHashHex = ch
		}
		if strings.EqualFold(ch, hashHex) {
			orphaned = false
			canonicalHashHex = ch
			break
		}
	}

	return VerifyResult{
		Found:         true,
		Orphaned:      orphaned,
		Confirmations: int64(headerResp.GetConfirmations()),
		CanonicalHash: canonicalHashHex,
	}, nil
}

// isTariNotFound reports whether err is the GRPC status this base
// node returns for a hash it has never seen (pruned, unknown, or
// simply not yet propagated to it) — codes.NotFound is the real,
// standard GRPC status the tari base node's GetHeaderByHash handler
// returns for that case. Treating this as "not found" rather than a
// hard error mirrors this package's documented ChainVerifier contract
// (chain.go): a genuinely-not-yet-visible block is expected steady
// state, not a failure.
func isTariNotFound(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	return st.Code() == codes.NotFound
}
