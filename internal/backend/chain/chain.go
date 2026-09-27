// Package chain implements the backend's coin-agnostic block
// verification surface: given a submitted (hash, height) pair for a
// pool-found block, ask the REAL upstream node/daemon whether that
// block genuinely exists on the canonical chain, whether it has since
// been orphaned/reorged away, and how many confirmations (blocks mined
// on top of it) it currently has.
//
// This is the read side of the trust boundary internal/backend/api's
// doc comment describes: the backend accepts a leaf's FoundBlock
// report on faith at ingestion time (POST /api/v1/block), but a block
// is not actually payable until an independent chain query confirms
// it. ChainVerifier is that independent check.
//
// Two production implementations exist, one per coin family this
// codebase's ALGO_* enum spans:
//
//   - TariVerifier (tari.go): ALGO_RXT/ALGO_C29/ALGO_SHA3X, backed by a
//     real Tari base node over GRPC (GetHeaderByHash + GetBlocks, via
//     go-tari-grpc-lib/v3's nodeGRPC package — the same library
//     internal/leaflib/solo's GRPCNodeClient already depends on).
//   - MoneroVerifier (monero.go): ALGO_RXM, backed by a real monerod
//     JSON-RPC 2.0 get_block_header_by_height call.
//
// Package internal/backend/unlocker is this package's only production
// consumer: it polls pending blocks and calls ChainVerifier.Verify to
// decide when/whether to mark them unlocked (mature+payable) or
// invalid (orphaned).
package chain

import "context"

// VerifyResult is the coin-agnostic outcome of checking one submitted
// (hash, height) pair against a real node/daemon.
type VerifyResult struct {
	// Found reports whether the node knows about a block matching the
	// submitted hash at all. false means "not found (yet)" — this is
	// deliberately not treated as an error by either implementation,
	// since a just-submitted block may simply not have propagated to
	// the queried node yet; callers should leave the block pending and
	// re-check later rather than treating this as a hard failure.
	Found bool

	// Orphaned reports whether the submitted hash, despite once being a
	// real block the node had validated, is NOT (or is no longer) part
	// of the node's current canonical/main chain at the submitted
	// height — i.e. it was reorged away. Only meaningful when Found is
	// true.
	Orphaned bool

	// Confirmations is the number of blocks the node has mined on top
	// of this one (0 means this block is the current tip). Only
	// meaningful when Found is true and Orphaned is false.
	Confirmations int64

	// CanonicalHash is the hex-encoded hash of whatever block the node
	// currently considers canonical at the submitted height — equal to
	// the hash the caller submitted unless Orphaned is true. Populated
	// on a best-effort basis for logging/diagnostics; callers should
	// key their decisions off Orphaned, not off comparing this field
	// themselves.
	CanonicalHash string

	// Reward is the real coinbase reward for this block, as reported
	// live by the node/daemon in the SAME real RPC response Verify
	// already makes for hash/orphan/confirmation checking — no
	// additional RPC call is needed for either coin family:
	//   - Tari: BlockHeaderResponse.GetReward() (confirmed present on
	//     the real GetHeaderByHash response this session).
	//   - Monero: the real get_block_header_by_height response's own
	//     "reward" field (confirmed present via a real live daemon
	//     call this session).
	// This is deliberately the REAL, CURRENT reward at verification
	// time, not whatever value (if any) was recorded on the blocks
	// row at submission time — block rewards can change (halvings,
	// protocol changes) between submission and maturity, and a payout
	// engine paying out a stale reward would be a real, if rare,
	// correctness bug. Only meaningful when Found is true and
	// Orphaned is false; 0 for an orphaned/not-found result.
	Reward int64
}

// ChainVerifier is the coin-agnostic interface internal/backend/unlocker
// depends on. Each concrete implementation (TariVerifier, MoneroVerifier)
// owns its own real RPC/GRPC wire protocol entirely; this interface's
// only job is to let the unlocker poll loop stay coin-agnostic, exactly
// mirroring internal/leaflib/solo's own NodeClient interface's role for
// block-template fetching.
type ChainVerifier interface {
	// Verify checks hashHex (lowercase-or-uppercase hex, either is
	// accepted) at height against the real chain this ChainVerifier is
	// configured against. It returns a non-nil error only for a genuine
	// operational failure (RPC/network/decode error) — "block not found
	// (yet)" is reported via VerifyResult.Found == false with a nil
	// error, not as an error, since that is an entirely expected steady
	// -state outcome for a freshly-submitted block.
	Verify(ctx context.Context, hashHex string, height int64) (VerifyResult, error)
}
