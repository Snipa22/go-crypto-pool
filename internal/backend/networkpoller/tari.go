// Copyright and license: see repository LICENSE (MIT).
package networkpoller

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/Snipa22/go-tari-grpc-lib/v3/nodeGRPC"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tariNodeRPC is the narrow slice of go-tari-grpc-lib/v3's nodeGRPC
// package-level API TariNetworkSource actually needs -- GetTipInfo
// (real chain tip height/hash) and GetNetworkState (real per-algo
// estimated hashrate). Exists purely so tests can inject a fake
// without a real Tari base node, mirroring
// internal/backend/chain.tariNodeRPC's identical role/rationale for
// TariVerifier.
type tariNodeRPC interface {
	GetTipInfo(ctx context.Context) (*tari_generated.TipInfoResponse, error)
	GetNetworkState(ctx context.Context) (*tari_generated.GetNetworkStateResponse, error)
}

type tariNodeRPCAdapter struct{}

func (tariNodeRPCAdapter) GetTipInfo(ctx context.Context) (*tari_generated.TipInfoResponse, error) {
	return nodeGRPC.GetTipInfo(ctx)
}

func (tariNodeRPCAdapter) GetNetworkState(ctx context.Context) (*tari_generated.GetNetworkStateResponse, error) {
	return nodeGRPC.GetNetworkState(ctx)
}

// TariAlgo identifies which of the three real Tari-merge-mined PoW
// algos (see internal/leaflib/solo/node.go's tariPowAlgo for the same
// three-algo grouping this codebase's ALGO_RXT/ALGO_C29/ALGO_SHA3X
// enum spans) a TariNetworkSource should report GetNetworkState's
// real per-algo estimated-hashrate field for.
type TariAlgo int

const (
	TariAlgoRandomX  TariAlgo = iota // ALGO_RXT
	TariAlgoCuckaroo                 // ALGO_C29
	TariAlgoSHA3X                    // ALGO_SHA3X
)

// TariNetworkSource is the production Source for ALGO_RXT/ALGO_C29/
// ALGO_SHA3X, backed by a real Tari base node GRPC connection --
// exactly the same nodeGRPC package-level singleton connection
// internal/backend/chain.TariVerifier and
// internal/leaflib/solo.GRPCNodeClient already use (see either's doc
// comment for why only one InitNodeGRPC call's worth of address
// should be live per process; cmd/backend's wiring calls
// nodeGRPC.InitNodeGRPC exactly once with the SAME
// GCPOOL_TARI_GRPC_ADDR the unlocker's TariVerifier is configured
// against, so this Source and that Verifier safely share the one
// connection).
//
// Two real GRPC calls make up one fetch:
//
//   - GetTipInfo -- the real chain's current tip height/hash
//     (TipInfoResponse.Metadata.BestBlockHeight/BestBlockHash), the
//     same real height every one of the three Tari algos shares
//     (Tari merge-mines all three PoW algos onto ONE chain -- there
//     is no separate "RXT chain height" vs "SHA3X chain height").
//   - GetNetworkState -- the real base node's own per-algo estimated
//     hashrate figures (GetNetworkStateResponse.
//     TariRandomxEstimatedHashRate / CuckarooEstimatedHashRate /
//     Sha3XEstimatedHashRate), which IS genuinely algo-specific --
//     Tari's own base node computes each algo's difficulty-adjustment
//     window independently, so these three numbers really do differ
//     per algo.
//
// GetNetworkState is NOT universally reachable: it's confirmed live
// against the real Esmeralda testnet base node to come back
// PermissionDenied/Unauthenticated (some real node operators run
// grpc_server_allow_methods allowlists that admit GetTipInfo but not
// GetNetworkState) -- a real, RPC-permission-scoped restriction, not
// a transient/connectivity failure. FetchNetworkState treats exactly
// that class of error as "this node just doesn't expose per-algo
// hashrate" and degrades to a real height/hash State with a nil
// EstimatedHashrateHS, rather than failing the whole poll (which
// would also blank out the real, independently-fetched tip
// height/hash for no good reason). Any OTHER GetNetworkState error
// (Unavailable, real connection drop, etc.) still fails the fetch --
// see isTariMethodForbidden below for the exact code set.
//
// Difficulty is deliberately left nil (see State.Difficulty's doc
// comment): resolving one clean, current, PER-ALGO difficulty figure
// for a three-way merge-mined chain from a single cheap RPC call is
// not possible with what this base node's GRPC surface exposes today
// -- GetNetworkDiff/GetNetworkDifficulty only ever returns the
// difficulty of whichever ONE algo most recently mined the observed
// tip block (see NetworkDifficultyResponse.PowAlgo), which would
// require walking back over recent blocks per algo to reconstruct a
// real per-algo figure, a materially heavier poll-loop operation this
// package does not attempt. The real per-algo estimated hashrate
// above is the figure a pool-stats page actually wants to show
// anyway.
type TariNetworkSource struct {
	rpc  tariNodeRPC
	algo TariAlgo
}

// NewTariNetworkSource returns a TariNetworkSource for algo, backed
// by the real, already-initialized nodeGRPC package-level connection
// (see nodeGRPC.InitNodeGRPC -- this constructor does NOT call it
// itself; the caller, cmd/backend, is responsible for calling it
// exactly once, exactly as TariVerifier's own constructor already
// documents).
func NewTariNetworkSource(algo TariAlgo) *TariNetworkSource {
	return &TariNetworkSource{rpc: tariNodeRPCAdapter{}, algo: algo}
}

// newTariNetworkSourceWithRPC is the test seam.
func newTariNetworkSourceWithRPC(rpc tariNodeRPC, algo TariAlgo) *TariNetworkSource {
	return &TariNetworkSource{rpc: rpc, algo: algo}
}

// FetchNetworkState implements Source for Tari. ctx is a real,
// already-in-scope context (the poll loop's own per-cycle ctx) and is
// threaded straight through to both real GRPC calls below — as of
// go-tari-grpc-lib/v3 v3.3.0, nodeGRPC.GetTipInfo/GetNetworkState both
// accept a leading context.Context (see tariNodeRPCAdapter), so a
// canceled/timed-out ctx now genuinely cancels an in-flight call
// rather than this method waiting on it unbounded.
func (s *TariNetworkSource) FetchNetworkState(ctx context.Context) (State, error) {
	tip, err := s.rpc.GetTipInfo(ctx)
	if err != nil {
		return State{}, fmt.Errorf("networkpoller: tari: GetTipInfo: %w", err)
	}
	if tip == nil || tip.GetMetadata() == nil {
		return State{}, fmt.Errorf("networkpoller: tari: GetTipInfo returned no metadata")
	}
	meta := tip.GetMetadata()

	netState, err := s.rpc.GetNetworkState(ctx)
	if err != nil && !isTariMethodForbidden(err) {
		return State{}, fmt.Errorf("networkpoller: tari: GetNetworkState: %w", err)
	}
	// isTariMethodForbidden(err) case: this base node's real GRPC
	// permission scope doesn't admit GetNetworkState (confirmed live
	// against Esmeralda testnet -- see TariNetworkSource's doc
	// comment). netState is nil here, so the hashrate block below is
	// skipped and this State comes back with a real height/hash and
	// a nil EstimatedHashrateHS instead of failing the whole fetch.

	var hashrate *float64
	if netState != nil {
		var hr float64
		switch s.algo {
		case TariAlgoRandomX:
			hr = float64(netState.GetTariRandomxEstimatedHashRate())
		case TariAlgoSHA3X:
			hr = float64(netState.GetSha3XEstimatedHashRate())
		case TariAlgoCuckaroo:
			if cw := netState.GetCuckarooEstimatedHashRate(); cw != nil {
				// UDecimalValue's real fixed-point shape is
				// {Units uint64, Nanos uint32} (Nanos = 10^-9 unit
				// fractional part) -- see tari_generated's own type.
				// A hashrate estimate's fractional H/s component is
				// immaterial for this poller's purposes, so this
				// takes Units as the real estimate and drops Nanos
				// rather than doing sub-1-H/s fixed-point math for a
				// figure that gets rendered as one JSON float
				// anyway.
				hr = float64(cw.GetUnits()) + float64(cw.GetNanos())/1e9
			}
		}
		hashrate = &hr
	}

	return State{
		Height:              int64(meta.GetBestBlockHeight()),
		Difficulty:          nil,
		EstimatedHashrateHS: hashrate,
		BestBlockHash:       hex.EncodeToString(meta.GetBestBlockHash()),
	}, nil
}

// isTariMethodForbidden reports whether err is the real base node
// GRPC server telling us a method exists but this connection isn't
// permitted to call it -- PermissionDenied/Unauthenticated (an
// explicit grpc_server_allow_methods-style rejection) or Unimplemented
// (some real node builds/configs report a disabled method this way
// instead). This is exactly the class of error confirmed live against
// the real Esmeralda testnet base node for GetNetworkState: a real
// RPC-permission scope restriction, not a transient/connectivity
// failure, so it should degrade this Source's hashrate field to nil
// rather than fail the whole fetch. Errors that aren't a real GRPC
// status (e.g. plain connection-refused errors, which status.FromError
// maps to codes.Unknown) fall through as real failures, same as
// before.
func isTariMethodForbidden(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.PermissionDenied, codes.Unauthenticated, codes.Unimplemented:
		return true
	default:
		return false
	}
}
