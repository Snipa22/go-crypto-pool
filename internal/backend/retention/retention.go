// Package retention implements the backend's shares-retention/cleanup
// poll loop: periodically dropping whole `shares` block_height leaf
// partitions that have aged out of a configured retention window, for
// every (algo, pool_type) combination an operator has opted into.
//
// This is deliberately a PARTITION-DROP design, never row-level
// DELETE — see internal/backend/db/partition.go's DropOldPartitions
// (the mechanism this package turns into a scheduled policy) and
// internal/backend/db/README.md's "Retention model for shares"
// section for why: `shares` is already declaratively partitioned
// LIST(algo) -> LIST(pool_type) -> RANGE(block_height), so an entire
// aged-out block_height bucket can be discarded with one fast
// DROP TABLE (a catalog operation) instead of a row-by-row DELETE that
// would have to visit, WAL-log, and vacuum every dead tuple. On a
// pool ingesting real share volume, that difference is the whole
// reason this package exists instead of a cron'd `DELETE FROM shares
// WHERE block_height < ...`.
//
// Mirrors the structure of internal/backend/unlocker (poll loop over
// a fixed target set, RunOnce/RunLoop split, narrow Repository
// interface, own local types instead of importing internal/backend/db
// directly — cmd/backend is the only place this package and db need
// to meet, via the adapter it defines).
//
// CRITICAL: a leaf partition is never dropped purely because it is
// old — Repository.DropOldPartitions also checks `blocks` for any
// still-unresolved (unlocked = FALSE) row inside that partition's
// height range, and leaves that ONE partition alone (skipped, not an
// error) if one exists. See SkippedPartition's doc comment for the
// data-loss scenario this guards against.
package retention

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
)

// Target names one (algo, pool_type) combination this job should
// retain/clean up, and how far back (in block-height units) live data
// must reach before an older partition is eligible to be dropped.
type Target struct {
	Algo     string
	PoolType string

	// RetentionBlocks is the width, in block-height units, of the
	// live window this target keeps. A leaf partition is dropped
	// only once the highest block_height this target has EVER seen
	// a partition created for (the "frontier" — see frontier's own
	// doc comment below) has advanced RetentionBlocks past that
	// partition's own upper bound. Must be > 0 for this target to
	// ever drop anything; a zero or negative value disables
	// retention for this target (RunOnce skips it) rather than
	// dropping every partition including the live one.
	RetentionBlocks int64
}

// Repository is the narrow persistence surface Runner depends on.
// *db.Repository-adjacent free functions (db.ListHeightPartitions,
// db.DropOldPartitions) are wrapped to satisfy this via a small
// adapter in cmd/backend, mirroring unlocker.Repository/
// disburse.Repository's role.
type Repository interface {
	// ListHeightPartitions returns every existing block_height leaf
	// partition under shares_<algo>_<poolType>, ordered by range
	// start — mirrors db.ListHeightPartitions exactly.
	ListHeightPartitions(ctx context.Context, algo, poolType string) ([]HeightPartition, error)

	// DropOldPartitions drops every leaf partition whose entire
	// range already falls below belowHeight and returns the names
	// dropped — mirrors db.DropOldPartitions exactly (whole-
	// partition DROP TABLE, never row-level DELETE). A partition
	// that would otherwise be eligible (its whole range is below
	// belowHeight) but still has an unresolved (unlocked = FALSE)
	// `blocks` row inside its height range is NOT dropped — it is
	// returned in skipped instead, and every other eligible
	// partition for this same (algo, poolType) is still dropped
	// normally (this call never aborts early because of one
	// skipped partition). See SkippedPartition's doc comment for
	// why: destroying that partition would delete a still-pending
	// (or forever-retrying-payout) block's winning shares before
	// the unlocker/payout pass ever reads them.
	DropOldPartitions(ctx context.Context, algo, poolType string, belowHeight int64) (dropped []string, skipped []SkippedPartition, err error)
}

// HeightPartition mirrors db.HeightPartition field-for-field (see
// that type's doc comment in internal/backend/db/partition.go).
type HeightPartition struct {
	Name       string
	RangeStart int64
	RangeEnd   int64
}

// SkippedPartition mirrors db.SkippedPartition field-for-field (see
// that type's doc comment in internal/backend/db/partition.go) — one
// leaf partition RunOnce found otherwise eligible to drop (fully
// below its target's retention cutoff) but did NOT drop, because
// `blocks` still has an unresolved (unlocked = FALSE) row inside that
// partition's height range. BlockID/BlockHeight identify the
// earliest such row found, purely so an operator has somewhere to
// start looking; there may be more than one.
type SkippedPartition struct {
	Name       string
	RangeStart int64
	RangeEnd   int64

	BlockID     int64
	BlockHeight int64
}

// Config configures a Runner.
type Config struct {
	// Targets is the fixed set of (algo, pool_type, retention
	// window) combinations this job manages. A combination with no
	// entry here is never touched — same "config knob absent means
	// feature disabled for that slice" convention as
	// unlocker.Config.Coins.
	Targets []Target

	// PollInterval is how often RunLoop re-evaluates every target.
	// Required to be > 0 for RunLoop (RunOnce ignores it entirely —
	// it always runs exactly one pass over every target).
	PollInterval time.Duration

	// Logf receives one line per notable event (a target's pass
	// summary, or a per-target drop/list error). Defaults to
	// log.Printf if nil.
	Logf func(format string, args ...any)

	// Metrics, if non-nil, is the metrics.Metrics instance RunOnce
	// records retention_partitions_dropped_total/
	// retention_partitions_skipped_unresolved_total/
	// retention_run_duration_seconds/retention_run_errors_total on.
	// If nil, metrics are simply not recorded.
	Metrics *metrics.Metrics
}

// Runner runs Config's retention poll loop against a Repository.
type Runner struct {
	repo Repository
	cfg  Config
	logf func(format string, args ...any)
}

// New constructs a Runner. cfg.Targets should be non-empty for this to
// do anything useful, but an empty slice is accepted (RunOnce/RunLoop
// simply do nothing) rather than rejected — "no retention targets
// configured" is a legitimate deployment state (an operator who wants
// to keep shares forever), not a caller error.
func New(repo Repository, cfg Config) *Runner {
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	return &Runner{repo: repo, cfg: cfg, logf: logf}
}

// TargetResult summarizes the outcome of one target's evaluation
// within a single RunOnce pass.
type TargetResult struct {
	Algo     string
	PoolType string
	Dropped  []string

	// Skipped lists every partition this target's pass found
	// otherwise eligible to drop but did NOT drop because `blocks`
	// still has an unresolved row in its height range — see
	// SkippedPartition's doc comment. This is expected, healthy
	// behavior (a genuinely pending block, or one stuck retrying a
	// failed payout forever), never counted as an Err.
	Skipped []SkippedPartition

	Err error
}

// PassResult summarizes the outcome of one RunOnce call, primarily for
// tests and operational logging.
type PassResult struct {
	TargetsChecked    int
	PartitionsDropped int

	// PartitionsSkipped is the total count of partitions skipped
	// across every target in this pass because they still hold an
	// unresolved block — see TargetResult.Skipped. Not an error
	// count: a skip here is expected, healthy behavior, distinct
	// from both "dropped" and "errored".
	PartitionsSkipped int

	Errors  int
	Targets []TargetResult
}

// RunOnce performs exactly one retention pass: for every configured
// target, lists that target's existing block_height leaf partitions,
// computes a cutoff height from the highest partition frontier seen
// so far minus that target's RetentionBlocks, and drops every leaf
// partition that falls entirely below the cutoff via
// Repository.DropOldPartitions (a whole-partition DROP TABLE, never a
// row-level DELETE — see this package's doc comment) — EXCEPT a
// partition that still has an unresolved (unlocked = FALSE) `blocks`
// row inside its height range, which is left alone (skipped, not
// dropped, not an error) so a genuinely pending block — or one stuck
// retrying a failed payout forever, see internal/backend/unlocker's
// outcomePayoutRetry — never loses the shares its payout calculation
// will eventually need to replay. A skipped partition is retried
// automatically on the next RunOnce pass; nothing about it is
// special-cased or remembered between calls.
//
// The "frontier" used as the cutoff's basis is simply the highest
// RangeEnd among that target's OWN currently-existing partitions —
// i.e. this job infers "how far the live data has advanced" from the
// partition catalog itself (which EnsureHeightPartition/InsertShare
// keep advancing on every real insert) rather than querying MAX(block_
// height) directly. This deliberately avoids an unindexed full-table
// MAX() scan across every partition on every retention pass; the
// partition catalog lookup ListHeightPartitions already needs to make
// (to decide what to drop) doubles as the frontier signal for free.
// The tradeoff: a target that has stopped receiving new shares
// entirely (no new EnsureHeightPartition calls) will never advance
// its frontier and so never drop anything further, even though those
// old partitions are just as safely droppable by real elapsed time —
// that's an accepted limitation of a purely height-driven retention
// model, not a bug in this pass.
func (r *Runner) RunOnce(ctx context.Context) PassResult {
	var total PassResult
	for _, target := range r.cfg.Targets {
		total.TargetsChecked++
		tr := TargetResult{Algo: target.Algo, PoolType: target.PoolType}
		passStart := time.Now()

		if target.RetentionBlocks <= 0 {
			r.logf("retention: %s/%s: RetentionBlocks <= 0, skipping (retention disabled for this target)", target.Algo, target.PoolType)
			continue
		}

		partitions, err := r.repo.ListHeightPartitions(ctx, target.Algo, target.PoolType)
		if err != nil {
			tr.Err = fmt.Errorf("listing partitions: %w", err)
			total.Errors++
			r.logf("retention: %s/%s: %v", target.Algo, target.PoolType, tr.Err)
			total.Targets = append(total.Targets, tr)
			r.observeRun(target.Algo, target.PoolType, false, time.Since(passStart))
			continue
		}
		if len(partitions) == 0 {
			// Nothing exists yet for this target (no shares
			// submitted so far) -- not an error, just nothing to do.
			total.Targets = append(total.Targets, tr)
			r.observeRun(target.Algo, target.PoolType, true, time.Since(passStart))
			continue
		}

		var frontier int64
		for _, p := range partitions {
			if p.RangeEnd > frontier {
				frontier = p.RangeEnd
			}
		}
		belowHeight := frontier - target.RetentionBlocks

		dropped, skipped, err := r.repo.DropOldPartitions(ctx, target.Algo, target.PoolType, belowHeight)
		if err != nil {
			tr.Err = fmt.Errorf("dropping partitions below height %d: %w", belowHeight, err)
			total.Errors++
			r.logf("retention: %s/%s: %v", target.Algo, target.PoolType, tr.Err)
			total.Targets = append(total.Targets, tr)
			r.observeRun(target.Algo, target.PoolType, false, time.Since(passStart))
			continue
		}

		tr.Dropped = dropped
		tr.Skipped = skipped
		total.PartitionsDropped += len(dropped)
		total.PartitionsSkipped += len(skipped)
		if len(dropped) > 0 {
			r.logf("retention: %s/%s: frontier=%d retention_blocks=%d cutoff=%d: dropped %d partition(s): %v",
				target.Algo, target.PoolType, frontier, target.RetentionBlocks, belowHeight, len(dropped), dropped)
		}
		for _, sp := range skipped {
			r.logf("retention: %s/%s: partition %s NOT dropped (block id=%d height=%d still unresolved, unlocked=false)",
				target.Algo, target.PoolType, sp.Name, sp.BlockID, sp.BlockHeight)
			if r.cfg.Metrics != nil {
				r.cfg.Metrics.RetentionPartitionsSkippedUnresolvedTotal.WithLabelValues(target.Algo, target.PoolType).Inc()
			}
		}
		total.Targets = append(total.Targets, tr)
		r.observeRun(target.Algo, target.PoolType, true, time.Since(passStart))
		if r.cfg.Metrics != nil && len(dropped) > 0 {
			r.cfg.Metrics.RetentionPartitionsDroppedTotal.WithLabelValues(target.Algo, target.PoolType).Add(float64(len(dropped)))
		}
	}
	return total
}

// observeRun records retention_run_duration_seconds and (on failure)
// retention_run_errors_total for one target's evaluation, a no-op if
// no Metrics is configured.
func (r *Runner) observeRun(algo, poolType string, ok bool, d time.Duration) {
	if r.cfg.Metrics == nil {
		return
	}
	r.cfg.Metrics.RetentionRunDuration.WithLabelValues(algo, poolType).Observe(d.Seconds())
	if !ok {
		r.cfg.Metrics.RetentionRunErrorsTotal.WithLabelValues(algo, poolType).Inc()
	}
}

// RunLoop calls RunOnce every cfg.PollInterval until ctx is canceled.
// It never returns an error itself — RunOnce already swallows and logs
// per-target failures, since one bad list/drop call must not take the
// whole poll loop (and, by extension, cmd/backend's process) down.
func (r *Runner) RunLoop(ctx context.Context) {
	if r.cfg.PollInterval <= 0 {
		r.logf("retention: PollInterval <= 0, RunLoop exiting without polling")
		return
	}
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.RunOnce(ctx)
		}
	}
}
