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
	GetHeaderByHash(ctx context.Context, hash []byte) (*tari_generated.BlockHeaderResponse, error)
	GetBlockByHeight(ctx context.Context, heights []uint64) ([]*tari_generated.Block, error)
}

// tariNodeRPCAdapter adapts nodeGRPC's package-level functions to
// tariNodeRPC. As of go-tari-grpc-lib/v3 v3.3.0, every one of these
// package-level functions takes a leading context.Context (see
// NewTariVerifier's doc comment) — this adapter passes straight
// through whatever ctx its caller (Verify, below) supplies.
type tariNodeRPCAdapter struct{}

func (tariNodeRPCAdapter) GetHeaderByHash(ctx context.Context, hash []byte) (*tari_generated.BlockHeaderResponse, error) {
	return nodeGRPC.GetHeaderByHash(ctx, hash)
}

func (tariNodeRPCAdapter) GetBlockByHeight(ctx context.Context, heights []uint64) ([]*tari_generated.Block, error) {
	return nodeGRPC.GetBlockByHeight(ctx, heights)
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
//
// As of go-tari-grpc-lib/v3 v3.3.0, InitNodeGRPC itself returns an
// error (previously void) — a real dial-time failure (e.g. malformed
// address) is now reported here instead of surfacing later as a
// confusing failure from the first real RPC call made against an
// unusable connection. Callers must check err and fail fast rather
// than proceeding with a half-constructed TariVerifier.
func NewTariVerifier(address string) (*TariVerifier, error) {
	if err := nodeGRPC.InitNodeGRPC(address); err != nil {
		return nil, fmt.Errorf("chain: tari: NewTariVerifier: dialing %s: %w", address, err)
	}
	return &TariVerifier{rpc: tariNodeRPCAdapter{}}, nil
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
// // # ctx handling (PROD_HARDENING_REVIEW.md finding #20)
//
// As of go-tari-grpc-lib/v3 v3.3.0, v.rpc (nodeGRPC's package-level
// GetHeaderByHash/GetBlockByHeight) DOES accept a leading
// context.Context, and this method passes ctx straight through to
// both calls (see tariNodeRPCAdapter) — a canceled/timed-out ctx now
// genuinely cancels the in-flight GRPC call at the transport level,
// not just this method's own wait on it.
//
// This method ALSO still races each call against ctx in its own
// goroutine via callWithContext below. That defensive wrapper
// predates v3.3.0's ctx support (see callWithContext's own doc
// comment for the full original finding #20 rationale, when nodeGRPC
// had no ctx parameter at all and this was the ONLY way to bound the
// caller's wait) and is kept as belt-and-braces: it guarantees this
// method's caller (the unlocker's poll pass) is unblocked promptly on
// ctx cancellation even in the hypothetical case where the underlying
// transport doesn't itself honor ctx cancellation as promptly as
// expected (e.g. slow DNS resolution ahead of the actual RPC). With a
// real, ctx-respecting connection this second layer should rarely if
// ever actually win the race against the real RPC returning on its
// own — but it costs nothing to keep and removes a way this method
// could regress back to unbounded blocking if that assumption about
// the underlying transport is ever wrong.
func (v *TariVerifier) Verify(ctx context.Context, hashHex string, height int64) (VerifyResult, error) {
	if height < 0 {
		return VerifyResult{}, fmt.Errorf("chain: tari: height must be non-negative, got %d", height)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("chain: tari: hash %q is not valid hex: %w", hashHex, err)
	}

	headerResp, err := callWithContext(ctx, func() (*tari_generated.BlockHeaderResponse, error) {
		return v.rpc.GetHeaderByHash(ctx, hashBytes)
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
		return v.rpc.GetBlockByHeight(ctx, []uint64{uint64(height)})
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

// callWithContext runs fn (a blocking call, e.g. one of
// tariNodeRPCAdapter's own methods — see Verify's own doc comment for
// why this races the call rather than relying solely on fn honoring
// ctx itself) on a separate goroutine and returns as soon as EITHER
// fn returns OR ctx is done, whichever comes first. If ctx wins the
// race, fn's eventual result (if any) is silently discarded — the
// goroutine is not, and cannot be, killed; it simply keeps running
// until the real underlying call returns on its own (fn is expected
// to ALSO have been given ctx itself, so in the common case it
// returns promptly on its own once the underlying transport observes
// the same cancellation — this is a defensive upper bound on the
// caller's wait, not the primary cancellation mechanism).
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
