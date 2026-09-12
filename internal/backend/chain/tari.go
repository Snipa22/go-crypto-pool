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
//
// # ctx handling (PROD_HARDENING_REVIEW.md finding #20)
//
// v.rpc (nodeGRPC's package-level GetHeaderByHash/GetBlockByHeight)
// does NOT accept a context.Context at all — checked against
// go-tari-grpc-lib/v3's real nodeGRPC package this session: every one
// of its exported functions builds its own context.Background()
// internally for the underlying GRPC call, with no variant that
// takes a caller-supplied context. So ctx genuinely CANNOT be
// threaded into the GRPC call itself without modifying that external
// dependency, which is out of scope here.
//
// What IS feasible without touching go-tari-grpc-lib, and what this
// method does: run each blocking RPC call in its own goroutine and
// race it against ctx via callWithContext below, so a canceled/
// timed-out ctx unblocks THIS METHOD's caller (the unlocker's poll
// pass) promptly instead of waiting on however long the underlying
// GRPC call takes to fail or a genuinely hung base node's TCP-level
// timeout. This bounds the CALLER's wait — the exact problem
// statement ("a hung base node can stall an entire unlocker pass
// with no way for the caller to bound it") — even though it cannot
// cancel the in-flight GRPC call itself: that goroutine keeps running
// (and its result is simply discarded) until the real call returns on
// its own. This is a real, if partial, fix: it is a goroutine-per-
// call-that-times-out leak under sustained base-node unavailability,
// not a free win, but it is strictly better than the caller being
// unable to bound its own wait at all, and it requires zero changes
// to the external dependency.
func (v *TariVerifier) Verify(ctx context.Context, hashHex string, height int64) (VerifyResult, error) {
	if height < 0 {
		return VerifyResult{}, fmt.Errorf("chain: tari: height must be non-negative, got %d", height)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("chain: tari: hash %q is not valid hex: %w", hashHex, err)
	}

	headerResp, err := callWithContext(ctx, func() (*tari_generated.BlockHeaderResponse, error) {
		return v.rpc.GetHeaderByHash(hashBytes)
	})
	if err != nil {
		// A ctx cancellation/deadline (see callWithContext) is not a
		// GRPC status error, so isTariNotFound below correctly
		// returns false for it and it falls through to the generic
		// wrapped error path -- exactly what should happen: "ctx
		// gave up waiting" must never be silently treated the same
		// as "the base node confirmed it doesn't have this block".
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

	canonicalBlocks, err := callWithContext(ctx, func() ([]*tari_generated.Block, error) {
		return v.rpc.GetBlockByHeight([]uint64{uint64(height)})
	})
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
		Reward:        int64(headerResp.GetReward()),
	}, nil
}

// callWithContext runs fn (a blocking call into a client with no
// context support of its own, e.g. nodeGRPC's package-level
// functions — see Verify's own doc comment) on a separate goroutine
// and returns as soon as EITHER fn returns OR ctx is done, whichever
// comes first. If ctx wins the race, fn's eventual result (if any) is
// silently discarded — the goroutine is not, and cannot be, killed;
// it simply keeps running until the real underlying call returns on
// its own, mirroring exactly what would happen if the caller had
// instead just given up waiting on a synchronous call with no way to
// cancel it.
func callWithContext[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type result struct {
		val T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		val, err := fn()
		ch <- result{val: val, err: err}
	}()
	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case r := <-ch:
		return r.val, r.err
	}
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
