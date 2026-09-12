// Package unlocker implements the backend's block-maturity poll loop:
// periodically re-checking every pending (valid, not-yet-unlocked)
// block against the real chain via a coin-agnostic
// internal/backend/chain.ChainVerifier, and updating that block's
// valid/unlocked columns once its real chain status is resolved
// (mature+payable, or orphaned+dead). "Unlocked" here means the same
// thing api.go's BlockRecord.Unlocked field already means (see
// internal/backend/api/api.go and migrations/0001_initial_schema.up.sql)
// — this package is simply the first thing in this codebase that
// actually computes and writes that field with a real chain query,
// rather than leaving every submitted block permanently at whatever
// unlocked value the leaf happened to submit (false, in every leaf
// implementation to date — see internal/leaflib's Block wire
// construction, which never sets it).
package unlocker

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/chain"
	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// Block is the minimal shape the Unlocker needs for one pending block
// row — mirrors db.PendingBlock field-for-field, kept as this
// package's own type (rather than importing internal/backend/db
// directly) for the same dependency-direction reason
// internal/backend/api.ShareRecord/BlockRecord exist (see api.go's
// doc comment): cmd/backend is the only place this package and
// internal/backend/db need to meet.
type Block struct {
	ID      int64
	Algo    string
	Network string
	Hash    string
	Height  int64

	// PoolType and Difficulty are only needed for the optional
	// PayoutTrigger path below (see Config.PayoutTrigger) —
	// checkBlock's own chain-maturity logic never reads them. They
	// mirror db.PendingBlock's identical fields exactly.
	//
	// Value starts as whatever blocks.value held at submission time
	// (populated from db.PendingBlock, possibly nil), but checkBlock
	// OVERWRITES it with the real, current chain.VerifyResult.Reward
	// from this same poll pass's Verify call before invoking
	// PayoutTrigger — see checkBlock's own comment for why the fresh
	// value is used instead of the stale submission-time one. By the
	// time PayoutTrigger.TriggerPayout runs, Value is always the real,
	// live reward.
	PoolType   string
	Difficulty int64
	Value      *int64
}

// PayoutTrigger is invoked once for every block RunOnce/checkBlock
// resolves as matured, after the corresponding SetBlockStatus(valid=
// true, unlocked=true) call has already succeeded — i.e. this is the
// hook that wires internal/backend/payout.Calculator's real PPS/
// PPLNS/Solo payout math onto "a block just became payable", without
// this package needing to import internal/backend/payout directly
// (same narrow-interface pattern as Repository above).
//
// A TriggerPayout error is logged and counted (see
// Config.Metrics.PayoutCyclesTotal) but never changes checkBlock's
// own outcome or reverts the block's now-matured/unlocked status —
// the chain-maturity determination and the payout calculation are
// deliberately independent failure domains: a payout bug must not
// make this codebase forget that a block matured, and a stuck payout
// can always be retried out-of-band (e.g. a manual admin re-run)
// without re-verifying the chain.
type PayoutTrigger interface {
	TriggerPayout(ctx context.Context, b Block) error
}

// Repository is the narrow persistence surface Unlocker depends on.
// *db.Repository satisfies this interface as-is (PendingBlocks/
// SetBlockStatus, db/repository.go) via cmd/backend's adapter, exactly
// mirroring api.ShareBlockRepository's role for the ingestion side.
type Repository interface {
	PendingBlocks(ctx context.Context, algo string) ([]Block, error)
	SetBlockStatus(ctx context.Context, id int64, valid, unlocked bool) error
}

// CoinConfig configures one algo's worth of chain verification: which
// ChainVerifier to query, and how many confirmations that coin
// requires before a block is considered mature/payable.
type CoinConfig struct {
	// Verifier performs the real chain query for this algo. Required.
	Verifier chain.ChainVerifier

	// MaturityDepth is the minimum VerifyResult.Confirmations a
	// non-orphaned block needs before Unlocker marks it unlocked. This
	// is a pool-operator-configured value (see cmd/backend's doc
	// comment for the env vars that set it and their placeholder
	// defaults), not something this package hardcodes per coin — real
	// coinbase-maturity/reorg-safety requirements vary by
	// coin/deployment and are an operational decision, not a protocol
	// constant this codebase should bake in silently.
	MaturityDepth int64
}

// Config configures an Unlocker.
type Config struct {
	// Coins maps an algo string (db.ValidAlgos' values: "RXT", "C29",
	// "SHA3X", "RXM") to that algo's CoinConfig. Algos with no entry
	// here are never polled — e.g. a deployment with only a Monero RPC
	// endpoint configured should only set an "RXM" entry, and RXT/C29/
	// SHA3X blocks simply stay pending forever (visible/inspectable in
	// the DB, just never auto-unlocked) until a Tari verifier is
	// configured too.
	Coins map[string]CoinConfig

	// PollInterval is how often RunLoop re-checks every configured
	// algo's pending blocks. Required to be > 0 for RunLoop (RunOnce
	// ignores it entirely — it always runs exactly one pass).
	PollInterval time.Duration

	// Logf receives one line per notable event (an algo's poll pass
	// summary, or a per-block verification error). Defaults to
	// log.Printf if nil. Exists as a seam so tests can capture output
	// without depending on the log package's global state.
	Logf func(format string, args ...any)

	// PayoutTrigger, if non-nil, is called once for every block a
	// poll pass resolves as matured (see PayoutTrigger's doc comment
	// above). nil means no payout calculation is triggered at all —
	// same "config knob absent -> feature disabled" convention as
	// Coins above; a deployment that hasn't wired
	// internal/backend/payout in yet still gets correct chain-
	// maturity tracking out of this package alone.
	PayoutTrigger PayoutTrigger

	// Metrics, if non-nil, is the metrics.Metrics instance RunOnce
	// increments/observes (unlocker_blocks_total,
	// unlocker_poll_duration_seconds). If nil, metrics are simply
	// not recorded — this package works perfectly well without a
	// Metrics instance, it just loses observability. cmd/backend
	// wires in the same *metrics.Metrics instance the HTTP API
	// serves on GET /metrics, so unlocker/payout metrics show up on
	// that one process-wide endpoint rather than a second one.
	Metrics *metrics.Metrics

	// Debug, if non-nil and enabled, adds verbose [DEBUG]-tagged
	// logging to every RunOnce poll pass -- what was checked (algo,
	// pending count) and what changed (per-block outcome), on top
	// of Logf's existing per-notable-event lines. See
	// internal/leaflib/debuglog.go's doc comment and
	// cmd/backend/main.go's -debug/GCPOOL_DEBUG wiring. nil (the
	// default for every pre-existing caller/test) is a complete
	// no-op.
	Debug *leaflib.DebugLogger
}

// Unlocker runs Config's poll loop against a Repository.
type Unlocker struct {
	repo Repository
	cfg  Config
	logf func(format string, args ...any)
}

// New constructs an Unlocker. cfg.Coins should be non-empty for this
// to do anything useful, but an empty map is accepted (RunOnce/RunLoop
// simply do nothing) rather than rejected, since "no verifiers
// configured" is a legitimate deployment state (see Config.Coins' doc
// comment), not a caller error.
func New(repo Repository, cfg Config) *Unlocker {
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	return &Unlocker{repo: repo, cfg: cfg, logf: logf}
}

// PassResult summarizes the outcome of one RunOnce call, primarily for
// tests and operational logging.
type PassResult struct {
	Checked  int
	Matured  int
	Orphaned int
	Pending  int
	Errors   int
}

// RunOnce performs exactly one poll pass: for every algo configured in
// cfg.Coins, fetches its pending blocks and verifies each one against
// that algo's ChainVerifier, writing back a status update for every
// block whose chain status resolved definitively (matured or
// orphaned). Blocks whose ChainVerifier.Verify call itself errored, or
// which are simply not yet found or not yet mature, are left pending
// untouched — see checkBlock's doc comment for the exact decision
// table.
func (u *Unlocker) RunOnce(ctx context.Context) PassResult {
	var total PassResult
	for algo, coinCfg := range u.cfg.Coins {
		pollStart := time.Now()
		pending, err := u.repo.PendingBlocks(ctx, algo)
		if err != nil {
			u.logf("unlocker: %s: listing pending blocks: %v", algo, err)
			total.Errors++
			continue
		}
		u.cfg.Debug.Debugf("unlocker: %s: poll pass checking %d pending block(s) (maturity depth %d)", algo, len(pending), coinCfg.MaturityDepth)
		for _, b := range pending {
			total.Checked++
			switch outcome, err := u.checkBlock(ctx, b, coinCfg); {
			case err != nil:
				u.logf("unlocker: %s: block id=%d height=%d hash=%s: %v", algo, b.ID, b.Height, b.Hash, err)
				total.Errors++
				u.observeOutcome(algo, metrics.UnlockerOutcomeError)
			case outcome == outcomeMatured:
				total.Matured++
				u.logf("unlocker: %s: block id=%d height=%d hash=%s: matured, marking unlocked", algo, b.ID, b.Height, b.Hash)
				u.observeOutcome(algo, metrics.UnlockerOutcomeMatured)
			case outcome == outcomeOrphaned:
				total.Orphaned++
				u.logf("unlocker: %s: block id=%d height=%d hash=%s: orphaned, marking invalid+unlocked", algo, b.ID, b.Height, b.Hash)
				u.observeOutcome(algo, metrics.UnlockerOutcomeOrphaned)
			default:
				total.Pending++
				u.cfg.Debug.Debugf("unlocker: %s: block id=%d height=%d hash=%s: still pending, no change", algo, b.ID, b.Height, b.Hash)
			}
		}
		if u.cfg.Metrics != nil {
			u.cfg.Metrics.UnlockerPollDuration.WithLabelValues(algo).Observe(time.Since(pollStart).Seconds())
		}
	}
	return total
}

// observeOutcome increments Config.Metrics.UnlockerBlocksTotal for one
// resolved block, a no-op if no Metrics is configured. outcome is one
// of metrics.UnlockerOutcomeMatured/Orphaned/Error, passed as a plain
// string here to avoid an import cycle concern that doesn't actually
// exist (metrics doesn't import unlocker) — kept as a private helper
// purely to keep RunOnce's switch above readable.
func (u *Unlocker) observeOutcome(algo, outcome string) {
	if u.cfg.Metrics == nil {
		return
	}
	u.cfg.Metrics.UnlockerBlocksTotal.WithLabelValues(algo, outcome).Inc()
}

// RunLoop calls RunOnce every cfg.PollInterval until ctx is canceled.
// It never returns an error itself — RunOnce already swallows and logs
// per-algo/per-block failures, since one bad RPC call or one
// out-of-sync row must not take the whole poll loop (and, by
// extension, cmd/backend's process) down.
func (u *Unlocker) RunLoop(ctx context.Context) {
	if u.cfg.PollInterval <= 0 {
		u.logf("unlocker: PollInterval <= 0, RunLoop exiting without polling")
		return
	}
	ticker := time.NewTicker(u.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.RunOnce(ctx)
		}
	}
}

// blockOutcome is checkBlock's own decision result.
type blockOutcome int

const (
	outcomePending blockOutcome = iota
	outcomeMatured
	outcomeOrphaned
)

// checkBlock verifies one pending block and, for the two outcomes that
// resolve its status definitively, writes that resolution back via
// u.repo.SetBlockStatus. The decision table:
//
//   - Verify returns an error: outcomePending, err — a genuine RPC/
//     operational failure. The block is left untouched (not marked
//     anything) so the next poll pass retries it; this is NOT the same
//     as "not found", which is a normal, expected outcome (see below).
//   - Verify succeeds but VerifyResult.Found is false: outcomePending,
//     nil — the block simply hasn't propagated to/been seen by the
//     queried node yet. Expected for a just-submitted block; retried
//     next pass.
//   - Verify succeeds, Found, and Orphaned: outcomeOrphaned — this
//     block was real but has been reorged off the canonical chain.
//     SetBlockStatus(valid=false, unlocked=true) marks it dead and
//     final; it will never be retried again (no reorg-of-a-reorg
//     recovery path in this pass — an operator can always fix a row
//     by hand if a coin's chain somehow un-orphans a block later,
//     which none of the coins this codebase supports actually do).
//   - Verify succeeds, Found, not Orphaned, Confirmations >=
//     coinCfg.MaturityDepth: outcomeMatured — SetBlockStatus(valid=
//     true, unlocked=true) marks it mature/payable.
//   - Verify succeeds, Found, not Orphaned, Confirmations <
//     coinCfg.MaturityDepth: outcomePending, nil — still confirming,
//     retried next pass.
func (u *Unlocker) checkBlock(ctx context.Context, b Block, coinCfg CoinConfig) (blockOutcome, error) {
	if coinCfg.Verifier == nil {
		return outcomePending, fmt.Errorf("no ChainVerifier configured for this algo")
	}

	result, err := coinCfg.Verifier.Verify(ctx, b.Hash, b.Height)
	if err != nil {
		return outcomePending, fmt.Errorf("verify: %w", err)
	}
	if !result.Found {
		return outcomePending, nil
	}
	if result.Orphaned {
		if err := u.repo.SetBlockStatus(ctx, b.ID, false, true); err != nil {
			return outcomePending, fmt.Errorf("marking orphaned block invalid+unlocked: %w", err)
		}
		return outcomeOrphaned, nil
	}
	if result.Confirmations < coinCfg.MaturityDepth {
		return outcomePending, nil
	}
	if err := u.repo.SetBlockStatus(ctx, b.ID, true, true); err != nil {
		return outcomePending, fmt.Errorf("marking matured block unlocked: %w", err)
	}
	if u.cfg.PayoutTrigger != nil {
		// Use the REAL, CURRENT reward the chain just reported in
		// this same Verify call (result.Reward), not whatever value
		// (if any) blocks.value held at submission time — block
		// rewards can change between submission and maturity, and
		// this is the one, single real chain query this pass makes
		// for this block, so it's the freshest data available. See
		// chain.VerifyResult.Reward's doc comment for the full
		// reasoning.
		b.Value = &result.Reward
		if err := u.cfg.PayoutTrigger.TriggerPayout(ctx, b); err != nil {
			// Deliberately does not change the return outcome/error
			// here — the block itself has already matured/unlocked
			// successfully (see PayoutTrigger's doc comment on why
			// this is a separate failure domain). Just log it; the
			// trigger implementation itself is responsible for its
			// own PayoutCyclesTotal error accounting.
			u.logf("unlocker: %s: block id=%d height=%d hash=%s: payout trigger failed: %v", b.Algo, b.ID, b.Height, b.Hash, err)
		}
	}
	return outcomeMatured, nil
}
