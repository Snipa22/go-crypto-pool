// Package metrics defines the backend's standard, ops-facing Prometheus
// instrumentation: counters for share/block accept-reject-error
// outcomes, histograms for real DB insert timing, and a basic
// in-flight request gauge. It is deliberately separate from
// internal/backend/api so the metric definitions/registration can be
// unit-tested (and reused from cmd/backend) without pulling the HTTP
// handler logic along with them.
//
// Scope note: this is the backend HTTP API's metric set only. It does
// NOT carry per-miner/per-session labels — unbounded label cardinality
// on something like a miner payment address is a well-known Prometheus
// production anti-pattern, and that level of detail is the leaf-solo
// side's separate stats effort, not this one's.
package metrics

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Result label values for shares_total/blocks_total. These map
// directly onto the outcomes the backend's HTTP handlers actually
// distinguish today (see internal/backend/api's handleShare/
// handleBlock): a share/block is either persisted (Accepted),
// rejected for failing the shared-secret auth check specifically
// (Unauthorized — see PROD_HARDENING_REVIEW.md finding #1: this
// exists so a real, queryable/alertable count of
// rejected-for-auth ingestion attempts doesn't require standing up
// a brand new, parallel metric family, since it reuses this same
// counter/label shape), rejected before ever reaching the DB for
// any OTHER reason (malformed body, failed validation, network
// mismatch — all Rejected), or it reached the DB and the insert
// itself failed (Error). Do not add new values here without a
// corresponding new code path in api.go that actually produces
// them.
const (
	ResultAccepted     = "accepted"
	ResultRejected     = "rejected"
	ResultError        = "error"
	ResultUnauthorized = "unauthorized"
	// ResultRateLimited — the share/block was rejected before any
	// decode/DB work because its source IP exceeded the configured
	// per-IP ingestion rate limit (see internal/backend/api's
	// checkRateLimit / Config.IngestionRateLimit). Distinct from
	// ResultUnauthorized/ResultRejected: this is a DoS-focused
	// per-source throttle outcome, not an auth or validation
	// failure, and is worth its own queryable/alertable count for
	// telling "a leaf is being throttled" apart from either of
	// those.
	ResultRateLimited = "rate_limited"

	// UnknownLabel is used for algo/network/pool_type when a
	// share/block is rejected before it could be decoded far enough
	// to know those values (e.g. auth failure or malformed
	// protobuf). It is a single fixed string, not per-request data,
	// so it does not add unbounded cardinality.
	UnknownLabel = "unknown"
)

// Outcome label values for unlocker_blocks_total — the same
// vocabulary internal/backend/unlocker.PassResult already reports as
// counts, mirrored here per-block instead of per-pass so a single
// block's fate is directly queryable/alertable. "pending" is
// deliberately NOT one of these values: a block left pending is, by
// definition, not a terminal outcome yet and generates no event here
// (see unlocker.checkBlock's decision table) — only Verify errors,
// maturation, orphaning, and a matured block whose payout could not
// be applied are.
const (
	UnlockerOutcomeMatured  = "matured"
	UnlockerOutcomeOrphaned = "orphaned"
	UnlockerOutcomeError    = "error"
	// UnlockerOutcomePayoutFailed — the block is confirmed mature on
	// the real chain, but its payout run did not succeed, so the
	// block was deliberately LEFT PENDING (valid=TRUE,
	// unlocked=FALSE) for the next poll pass to retry rather than
	// marked unlocked with its payout dropped. See
	// unlocker.checkBlock's doc comment; the payout itself is
	// idempotent (migrations/0013_block_payouts.up.sql), which is
	// what makes that automatic retry safe.
	//
	// This is distinct from "error" on purpose: an "error" block's
	// chain status is still unknown, a "payout_failed" block's is
	// settled and it is real money that is stuck. A sustained
	// non-zero rate here is an actionable incident — the same block
	// is being retried every poll tick and no miner has been
	// credited for it.
	UnlockerOutcomePayoutFailed = "payout_failed"
	// UnlockerOutcomeStuckDisabled — the block sat in one of the
	// three chain-unresolved states (Verify error, not-found, or
	// below-maturity-depth) longer than
	// unlocker.Config.StuckTimeout, so it was auto-marked
	// invalid+unlocked (identical SetBlockStatus write to the
	// orphaned path) purely because this backend gave up waiting on
	// it, WITHOUT the real chain ever having told it the block was
	// reorged off.
	//
	// This is DELIBERATELY a distinct label from "orphaned", not a
	// reuse of it, even though both write the exact same
	// (valid=false, unlocked=true) row shape: "orphaned" means the
	// real chain affirmatively confirmed a reorg; "stuck_disabled"
	// means the chain never gave a definitive answer at all within
	// the configured timeout. An operator grepping logs or querying
	// this metric later must be able to tell "the chain told us this
	// was reorged off" apart from "we gave up waiting after N
	// minutes and nothing had happened yet" — conflating the two
	// here would erase exactly the distinction that matters for
	// diagnosing which failure mode actually occurred. Zero for
	// every algo while StuckTimeout is unconfigured (0, the
	// default).
	UnlockerOutcomeStuckDisabled = "stuck_disabled"
)

// Result label values for payout_cycles_total — whether one
// matured-block payout calculation (Calculate{PPS,PPLNS,Solo} +
// Apply, see internal/backend/payout.Calculator) completed and
// credited balances, correctly did nothing because that block's
// payout had already been applied, or failed partway through.
const (
	PayoutResultSuccess = "success"
	PayoutResultError   = "error"
	// PayoutResultAlreadyApplied — the block's `block_payouts` ledger
	// row was already APPLIED, so this cycle credited nothing and
	// rolled back without touching a balance (see
	// db.Repository.ApplyBlockPayout). Healthy, expected traffic:
	// it is what the unlocker's retry of a block whose payout
	// committed but whose status write did not looks like. Counted
	// separately from "success" so a dashboard is not misled into
	// reading retries as real payout cycles, and so
	// payout_amount_credited_total (which such a cycle deliberately
	// does NOT add to) still reconciles against the "success" count.
	PayoutResultAlreadyApplied = "already_applied"
)

// Result label values for auth_attempts_total — whether one POST
// /authenticate attempt (internal/backend/authapi) ended in a
// successfully-issued JWT or a rejected credential check. See
// PROD_HARDENING_REVIEW.md finding #19: this endpoint was previously
// entirely metric-invisible, despite being the standard
// credential-stuffing/brute-force target.
const (
	AuthResultSuccess = "success"
	AuthResultFailure = "failure"
)

// Result label values for force_payout_writes_total — whether one
// POST /user/forcePayment write (internal/backend/authapi) actually
// flagged a real `balance` row's force_payout column, or failed (most
// commonly: no matching balance row for that address/algo/network).
// Per PROD_HARDENING_REVIEW.md finding #19, every force-payout write
// moves real money ahead of a miner's normal payout schedule and is
// worth its own always-on counter regardless of outcome.
const (
	ForcePayoutResultSuccess = "success"
	ForcePayoutResultFailure = "failure"
)

// Result label values for disbursement_batches_total — whether one
// real on-chain transfer batch (internal/backend/disburse.Engine)
// was actually sent, failed at the wallet RPC layer, was skipped
// before ever attempting a Transfer call (e.g. insufficient unlocked
// wallet balance for this cycle — see disburse.go's doc comment), or
// ended AMBIGUOUS.
//
// "failed" and "ambiguous" are deliberately distinct and must not be
// conflated in dashboards/alerts: "failed" means the wallet provably
// never broadcast anything and the balance is safely retried next
// cycle (routine, not necessarily actionable), whereas "ambiguous"
// means real coin MAY already have moved, the balance has been frozen
// out of PayableBalances, and disbursement for that (algo, network)
// is halted pending a human. An ambiguous batch is always a
// page-worthy incident; a failed one usually is not.
const (
	DisbursementResultSent      = "sent"
	DisbursementResultFailed    = "failed"
	DisbursementResultSkipped   = "skipped"
	DisbursementResultAmbiguous = "ambiguous"
	// DisbursementResultOverlapped — RunOnce refused to run at all
	// because another call to RunOnce was already in progress on
	// the SAME *disburse.Engine instance (see that package's
	// in-process-only OVERLAP GATE). Like "skipped", this is
	// recorded once per whole REJECTED call rather than per batch —
	// no batch was ever built, since the call returned before the
	// balance query.
	DisbursementResultOverlapped = "overlapped"
)

// Cause label values for disbursement_ambiguous_payouts_total — which
// of the two real code paths pushed a payout into the AMBIGUOUS state
// (see internal/backend/disburse's runBatch and
// migrations/0010_payouts_ambiguous_status.up.sql).
const (
	// AmbiguousCauseTransfer — the wallet's Transfer call returned an
	// error that could not be proven pre-broadcast (a timeout, a
	// transport failure, Tari's transfer-succeeded-but-fee-lookup-
	// failed path, ...). Whether coin moved is unknown.
	AmbiguousCauseTransfer = "transfer_error"
	// AmbiguousCauseBookkeeping — the Transfer SUCCEEDED (there is a
	// real tx_hash) but the local CompletePayoutSent write that
	// debits balances and records it failed. Coin definitely moved;
	// the ledger does not know it yet.
	AmbiguousCauseBookkeeping = "bookkeeping_error"
)

// Reason label values for disbursement_halts_total — why a
// disbursement cycle (or a whole (algo, network)'s loop, at startup)
// refused to pay anything out.
const (
	// HaltReasonUnresolvedPayouts — an unresolved (PENDING or
	// AMBIGUOUS) payout row already existed for this (algo,
	// network) when the cycle/process started, so nothing was
	// attempted at all.
	HaltReasonUnresolvedPayouts = "unresolved_payouts"
	// HaltReasonAmbiguousBatch — a batch went AMBIGUOUS partway
	// through this cycle, so the remaining batches were abandoned
	// rather than attempted.
	HaltReasonAmbiguousBatch = "ambiguous_batch"
)

// Metrics holds every Prometheus collector the backend registers, plus
// the registry they live in. It is constructed via New and is safe for
// concurrent use (all wrapped Prometheus collectors are).
type Metrics struct {
	registry *prometheus.Registry

	SharesTotal          *prometheus.CounterVec
	BlocksTotal          *prometheus.CounterVec
	ShareInsertDuration  prometheus.Histogram
	BlockInsertDuration  prometheus.Histogram
	HTTPRequestsInFlight prometheus.Gauge
	BuildInfo            *prometheus.GaugeVec

	// BlocksRejectedEmptyHashTotal counts, separately from the
	// generic BlocksTotal{result="rejected"} bucket, every block
	// rejected specifically because it carried an empty/missing
	// hash, by algo and network. See internal/backend/api's
	// errEmptyBlockHash and PROD_HARDENING_REVIEW.md finding #13:
	// internal/leaflib/direct's realBlockHashHex can return "" when
	// every accepting node reports an empty
	// SubmitBlockResponse.block_hash, silently dropping that block's
	// accounting with only a leaf-side log line previously -- this
	// metric makes that specific failure mode operator-visible on
	// GET /metrics.
	BlocksRejectedEmptyHashTotal *prometheus.CounterVec

	// UnlockerBlocksTotal counts every terminal per-block outcome
	// the poll loop in internal/backend/unlocker produces — matured,
	// orphaned, or a Verify/SetBlockStatus error — labeled by algo
	// and outcome (see UnlockerOutcome* above). "Pending" blocks
	// never increment this (see those constants' doc comment).
	UnlockerBlocksTotal *prometheus.CounterVec
	// UnlockerPollDuration observes wall-clock time for one algo's
	// worth of one Unlocker.RunOnce pass (fetching + verifying every
	// pending block for that algo), labeled by algo.
	UnlockerPollDuration *prometheus.HistogramVec

	// UnlockerPendingBlocks is the current number of blocks still
	// pending (not yet resolved matured/orphaned) at the end of the
	// most recent Unlocker.RunOnce pass, by algo and network. A
	// Gauge, not a Counter -- this is live state, mirroring
	// DisbursementUnresolvedPayouts' role on the disbursement side.
	// Zero (or a small, expected-for-fresh-confirmations number) is
	// healthy; a persistently large or growing value is exactly the
	// "blocks stuck" failure mode PROD_HARDENING_REVIEW.md finding
	// #11 flags as previously metric-invisible.
	UnlockerPendingBlocks *prometheus.GaugeVec
	// UnlockerPendingBlockOldestAgeSeconds is how long ago (in
	// seconds) the OLDEST still-pending block for an (algo, network)
	// was first seen by this backend (blocks.inserted_at), by algo
	// and network. Only set when at least one pending block's
	// InsertedAt is known — see unlocker.observePending. A steadily
	// climbing value for a pair that should be maturing normally is
	// the same "stuck pending" signal UnlockerPendingBlocks reports
	// as a count, viewed as an age instead — the two are
	// deliberately complementary (a single very-old block among
	// otherwise-healthy ones raises this without necessarily
	// raising the count much, and vice versa).
	UnlockerPendingBlockOldestAgeSeconds *prometheus.GaugeVec

	// PayoutCyclesTotal counts every payout calculation cycle
	// (internal/backend/payout.Calculator's Calculate{PPS,PPLNS,
	// Solo} + Apply, triggered once per matured block by the
	// unlocker), labeled by algo, pool_type, and result (success/
	// error — see PayoutResult* above).
	PayoutCyclesTotal *prometheus.CounterVec
	// PayoutAmountCreditedTotal is the running total of atomic units
	// credited to miner balances by successful payout cycles,
	// labeled by algo and network. Cumulative — a Counter, not the
	// current balance table state.
	PayoutAmountCreditedTotal *prometheus.CounterVec
	// PayoutCycleDuration observes wall-clock time for one payout
	// calculation cycle, labeled by algo and pool_type.
	PayoutCycleDuration *prometheus.HistogramVec

	// DisbursementBatchesTotal counts every real on-chain transfer
	// batch internal/backend/disburse.Engine attempts, labeled by
	// algo, network, and result (sent/failed/skipped — see
	// DisbursementResult* above).
	DisbursementBatchesTotal *prometheus.CounterVec
	// DisbursementAmountSentTotal is the running total of atomic
	// units actually sent on-chain by successful disbursement
	// batches, labeled by algo and network. Cumulative — mirrors
	// PayoutAmountCreditedTotal's role on the credit side.
	DisbursementAmountSentTotal *prometheus.CounterVec
	// DisbursementFeeTotal is the running total of real on-chain
	// network fees paid by successful disbursement batches, labeled
	// by algo and network — the hot wallet's own cost of paying
	// out, never deducted from any miner's balance.
	DisbursementFeeTotal *prometheus.CounterVec
	// DisbursementCycleDuration observes wall-clock time for one
	// full disbursement cycle (RunOnce: balance query + every
	// batch's Transfer call + bookkeeping), labeled by algo and
	// network.
	DisbursementCycleDuration *prometheus.HistogramVec

	// DisbursementAmbiguousPayoutsTotal counts every payout pushed
	// into the AMBIGUOUS state — "real coin may already have moved
	// on-chain, a human must check" — labeled by algo, network, and
	// cause (see AmbiguousCause* above).
	//
	// This class of incident was previously entirely
	// metric-invisible: the engine recorded the payout FAILED,
	// re-paid the same balance next cycle, and the only trace was a
	// log line. ANY non-zero increment here is a page-worthy event:
	// by construction it means disbursement for that (algo, network)
	// is now halted and real funds are in an unknown state.
	DisbursementAmbiguousPayoutsTotal *prometheus.CounterVec
	// DisbursementHaltsTotal counts every disbursement cycle that
	// refused to pay anything out because of an unresolved payout,
	// labeled by algo, network, and reason (see HaltReason* above).
	// Incremented once per halted cycle (so it climbs steadily for
	// as long as an incident stays unresolved, making "how long has
	// this been stuck" directly queryable) and once per (algo,
	// network) blocked by cmd/backend's startup check.
	DisbursementHaltsTotal *prometheus.CounterVec
	// DisbursementUnresolvedPayouts is the current number of
	// unresolved (PENDING or AMBIGUOUS) `payouts` rows for an (algo,
	// network) — a Gauge, i.e. live state, not a cumulative count.
	// Zero is the only healthy value; anything above zero means
	// disbursement for that pair is halted until an operator
	// resolves the rows (`backend payout list-unresolved`, then
	// `backend payout resolve-sent` / `resolve-not-sent`).
	//
	// Freshness note, deliberate: this is refreshed by every
	// disbursement cycle for pairs whose loop is running, and set
	// once at startup for pairs cmd/backend's startup check REFUSED
	// to start a loop for. For those blocked pairs the value stays
	// put until the process is restarted — which is correct, since
	// the loop itself also stays halted until then: a persistent
	// non-zero reading is exactly the "this pair is stuck and needs
	// a human" signal wanted, not a stale artifact.
	DisbursementUnresolvedPayouts *prometheus.GaugeVec

	// WalletBalance is the hot wallet's real, currently-reported
	// balance, labeled by algo, network, currency, and kind
	// (available/pending_incoming/pending_outgoing/timelocked — see
	// WalletBalanceKind* below). A Gauge, not a Counter: this is a
	// live, point-in-time snapshot of what the wallet reports on
	// each scrape, populated by a dedicated background poll loop
	// (see cmd/backend's buildWalletStatsPoller) rather than pushed
	// inline from disburse.Engine's own GetBalance calls, so it
	// stays fresh even between disbursement cycles. Monero's
	// wallet.Balance only has Total/Unlocked (mapped onto
	// available/pending_outgoing here — see the poller's own doc
	// comment for the exact mapping); Tari's GetBalanceResponse has
	// all four real fields natively.
	//
	// The `currency` label (see
	// migrations/0014_balance_payouts_currency.up.sql) exists
	// specifically so ALGO_RXM's two independent real wallets — the
	// Monero wallet backing its primary/XMR leg, and the Tari wallet
	// backing its secondary/XTM leg — each get their own,
	// non-colliding time series under the same algo/network label
	// pair. Every non-RXM algo always reports "XTM" here.
	WalletBalance *prometheus.GaugeVec
	// WalletBalancePollErrorsTotal counts every failed
	// WalletClient.GetBalance call the stats poller makes, labeled
	// by algo, network, and currency (see WalletBalance's doc
	// comment on why currency is needed) — a stuck/unreachable
	// wallet RPC should be visible here even though WalletBalance
	// itself simply stops updating (a Gauge can't distinguish "still
	// the last real value" from "the poller is broken"; this counter
	// can).
	WalletBalancePollErrorsTotal *prometheus.CounterVec

	// RetentionPartitionsDroppedTotal counts every `shares`
	// block_height leaf partition actually dropped by the
	// internal/backend/retention poll loop's whole-partition
	// DROP TABLE (never a row-level DELETE — see that package's
	// doc comment), labeled by algo and pool_type. A partition
	// dropping to zero rows would still count 1 here per
	// partition, not per row — this is a partition-count metric,
	// not a rows-reclaimed estimate.
	RetentionPartitionsDroppedTotal *prometheus.CounterVec
	// RetentionPartitionsSkippedUnresolvedTotal counts every
	// `shares` block_height leaf partition that the
	// internal/backend/retention poll loop found otherwise eligible
	// to drop (fully below its target's retention cutoff) but did
	// NOT drop, because the `blocks` table still has an unresolved
	// (unlocked = FALSE) row inside that partition's height range —
	// labeled by algo and pool_type, incremented once per skipped
	// partition (not once per pass). This is the load-bearing
	// observability for the CRITICAL data-loss bug this metric was
	// added alongside the fix for: without this check, retention
	// could DROP TABLE a partition holding a still-pending (or
	// forever-retrying-payout, see internal/backend/unlocker's
	// outcomePayoutRetry) block's winning shares before the
	// unlocker/payout pass ever read them. A skip is expected,
	// healthy behavior on its own (a genuinely pending block is
	// normal) — but a SUSTAINED non-zero rate for one (algo,
	// pool_type), or one that never clears, means some block is
	// stuck unresolved long enough for retention to keep bumping
	// into it every pass, which an operator should go investigate
	// (e.g. via the unlocker's pending-blocks-age gauge and
	// `backend block` CLI) rather than assume will resolve itself.
	RetentionPartitionsSkippedUnresolvedTotal *prometheus.CounterVec
	// RetentionRunDuration observes wall-clock time for one
	// target's (algo, pool_type) worth of one retention RunOnce
	// pass (listing existing partitions + dropping any that aged
	// out), labeled by algo and pool_type.
	RetentionRunDuration *prometheus.HistogramVec
	// RetentionRunErrorsTotal counts every target evaluation within
	// a retention pass that failed (listing or dropping partitions
	// errored), labeled by algo and pool_type. A target skipped
	// because RetentionBlocks <= 0 is not an error and does not
	// increment this.
	RetentionRunErrorsTotal *prometheus.CounterVec

	// StatsRequestsTotal counts every request handled by
	// internal/backend/statsapi's read-only miner stats endpoints,
	// labeled by endpoint (balance/hashrate/hashrate_workers) and
	// result (ok/rejected/error) — deliberately NOT labeled by
	// payment address (see this package's doc comment on unbounded
	// cardinality).
	StatsRequestsTotal *prometheus.CounterVec
	// StatsRequestDuration observes wall-clock time for one
	// read-only miner stats API request, labeled by endpoint.
	StatsRequestDuration *prometheus.HistogramVec

	// NetworkPollsTotal counts every real, live upstream chain-state
	// query internal/backend/networkpoller's poll loop makes (a real
	// Tari GRPC GetTipInfo+GetNetworkState pair, or a real monerod
	// get_info call), labeled by algo, network, and result
	// (ok/error). This is entirely independent of StatsRequestsTotal
	// above -- that counts inbound HTTP requests to this backend's
	// own read-only stats API; this counts outbound queries this
	// backend makes to the REAL upstream network it mines against
	// (subsystem gap audit items 2+4).
	NetworkPollsTotal *prometheus.CounterVec
	// NetworkPollDuration observes wall-clock time for one Target's
	// worth of one networkpoller poll pass, labeled by algo and
	// network.
	NetworkPollDuration *prometheus.HistogramVec

	// AuthAttemptsTotal counts every POST /authenticate attempt
	// (internal/backend/authapi), by result (success/failure — see
	// AuthResult* above). Previously entirely metric-invisible (see
	// PROD_HARDENING_REVIEW.md finding #19) despite being the
	// standard credential-stuffing/brute-force target.
	AuthAttemptsTotal *prometheus.CounterVec

	// ForcePayoutWritesTotal counts every POST /user/forcePayment
	// write (internal/backend/authapi), by algo, network, and result
	// (success/failure — see ForcePayoutResult* above). Per the
	// audit (PROD_HARDENING_REVIEW.md finding #19), every
	// force-payout write moves real money ahead of a miner's normal
	// payout schedule and is worth its own always-on counter
	// regardless of outcome.
	ForcePayoutWritesTotal *prometheus.CounterVec

	// AddressMapWritesTotal counts every POST /api/v1/address-map
	// write (internal/backend/addressmap), by result (success/error
	// — using the same Result* vocabulary api.go's shares_total/
	// blocks_total already use). Flagged by the audit
	// (PROD_HARDENING_REVIEW.md finding #19) as "the single most
	// alert-worthy event" this backend can emit: every address-map
	// set is either a legitimate first-time mapping OR evidence
	// someone tried (and, per the set-once upsert behavior, may have
	// succeeded in overwriting) an existing XMR->Tari mapping.
	AddressMapWritesTotal *prometheus.CounterVec

	// PendingBalanceOutstanding is the current sum of every positive
	// `balance.pending_balance` row, by algo and network — a Gauge,
	// i.e. live state, refreshed periodically by cmd/backend's own
	// pending-balance poller (see runPendingBalancePoller). Per
	// PROD_HARDENING_REVIEW.md finding #19: existing coverage tracks
	// payout/disburse/unlocker/wallet-balance activity, but nothing
	// previously reported the OUTSTANDING liability itself -- how
	// much this pool currently owes its miners in total, regardless
	// of whether any payout/disbursement cycle has run recently.
	PendingBalanceOutstanding *prometheus.GaugeVec
}

// New constructs a Metrics using a fresh, private *prometheus.Registry
// (rather than prometheus.DefaultRegisterer/DefaultGatherer). This is a
// deliberate choice, mirroring the established local convention (see
// tari-p2p-exporter) of keeping dependencies injectable: a private
// registry means constructing multiple Handlers (as tests do, one per
// test case) never panics on "duplicate metrics collector
// registration" the way reusing the global registry across tests
// would, and it keeps this package free of hidden global state.
// Handler() below still serves the real, standard promhttp handler —
// just scoped to this registry instead of the global one.
//
// version is recorded on the build_info gauge (e.g. a git tag/commit
// set via -ldflags at build time in cmd/backend); pass "" or "dev" if
// unknown.
func New(version string) *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{registry: reg}

	m.SharesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "shares_total",
		Help: "Total number of shares submitted to the backend, by algo, network, pool_type, and result (accepted/rejected/error).",
	}, []string{"algo", "network", "pool_type", "result"})

	m.BlocksTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "blocks_total",
		Help: "Total number of blocks submitted to the backend, by algo, network, and result (accepted/rejected/error).",
	}, []string{"algo", "network", "result"})

	m.BlocksRejectedEmptyHashTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "blocks_rejected_empty_hash_total",
		Help: "Total number of blocks rejected specifically for carrying an empty/missing hash, by algo and network -- a distinct, more specific signal than blocks_total{result=\"rejected\"} for this one failure mode (see internal/leaflib/direct's realBlockHashHex).",
	}, []string{"algo", "network"})

	m.ShareInsertDuration = registerHistogram(reg, prometheus.HistogramOpts{
		Name:    "share_insert_duration_seconds",
		Help:    "Time taken by Repository.InsertShare DB calls that were actually attempted (rejected shares never reach this timer).",
		Buckets: prometheus.DefBuckets,
	})

	m.BlockInsertDuration = registerHistogram(reg, prometheus.HistogramOpts{
		Name:    "block_insert_duration_seconds",
		Help:    "Time taken by Repository.InsertBlock DB calls that were actually attempted (rejected blocks never reach this timer).",
		Buckets: prometheus.DefBuckets,
	})

	m.HTTPRequestsInFlight = registerGauge(reg, prometheus.GaugeOpts{
		Name: "http_requests_in_flight",
		Help: "Number of /api/v1/share and /api/v1/block HTTP requests currently being handled.",
	})

	m.BuildInfo = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "backend_build_info",
		Help: "Always 1; version label carries the running build's version string.",
	}, []string{"version"})
	m.BuildInfo.WithLabelValues(version).Set(1)

	m.UnlockerBlocksTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "unlocker_blocks_total",
		Help: "Total number of pending blocks resolved to a terminal outcome by the block unlocker, by algo and outcome (matured/orphaned/error/payout_failed/stuck_disabled).",
	}, []string{"algo", "outcome"})

	m.UnlockerPollDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "unlocker_poll_duration_seconds",
		Help:    "Wall-clock time for one algo's pending-block poll pass in the block unlocker, by algo.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo"})

	m.UnlockerPendingBlocks = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "unlocker_pending_blocks",
		Help: "Current number of blocks still pending (not yet resolved matured/orphaned) after the most recent block-unlocker poll pass, by algo and network.",
	}, []string{"algo", "network"})

	m.UnlockerPendingBlockOldestAgeSeconds = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "unlocker_pending_block_oldest_age_seconds",
		Help: "Age, in seconds, of the oldest still-pending block for an (algo, network) pair, measured from when this backend first received it (blocks.inserted_at).",
	}, []string{"algo", "network"})

	m.PayoutCyclesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "payout_cycles_total",
		Help: "Total number of payout calculation cycles run, by algo, pool_type, and result (success/error).",
	}, []string{"algo", "pool_type", "result"})

	m.PayoutAmountCreditedTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "payout_amount_credited_total",
		Help: "Cumulative atomic units credited to miner balances by successful payout cycles, by algo and network.",
	}, []string{"algo", "network"})

	m.PayoutCycleDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "payout_cycle_duration_seconds",
		Help:    "Wall-clock time for one payout calculation cycle (Calculate + Apply), by algo and pool_type.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo", "pool_type"})

	m.DisbursementBatchesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "disbursement_batches_total",
		Help: "Total number of real on-chain transfer batches attempted by the payout disbursement engine, by algo, network, and result (sent/failed/skipped).",
	}, []string{"algo", "network", "result"})

	m.DisbursementAmountSentTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "disbursement_amount_sent_total",
		Help: "Cumulative atomic units actually sent on-chain by successful disbursement batches, by algo and network.",
	}, []string{"algo", "network"})

	m.DisbursementFeeTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "disbursement_fee_total",
		Help: "Cumulative real on-chain network fees paid by successful disbursement batches (hot wallet cost, never deducted from miner balances), by algo and network.",
	}, []string{"algo", "network"})

	m.DisbursementCycleDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "disbursement_cycle_duration_seconds",
		Help:    "Wall-clock time for one full disbursement cycle (balance query + every batch's Transfer call + bookkeeping), by algo and network.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo", "network"})

	m.DisbursementAmbiguousPayoutsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "disbursement_ambiguous_payouts_total",
		Help: "Total number of payouts entering the AMBIGUOUS state (real coin may already have moved on-chain; disbursement halted pending manual resolution), by algo, network, and cause (transfer_error/bookkeeping_error). Any increment is a page-worthy incident.",
	}, []string{"algo", "network", "cause"})

	m.DisbursementHaltsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "disbursement_halts_total",
		Help: "Total number of disbursement halts triggered by an unresolved (PENDING/AMBIGUOUS) payout row, by algo, network, and reason (unresolved_payouts/ambiguous_batch).",
	}, []string{"algo", "network", "reason"})

	m.DisbursementUnresolvedPayouts = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "disbursement_unresolved_payouts",
		Help: "Current number of unresolved (PENDING or AMBIGUOUS) payouts rows blocking disbursement, by algo and network. Zero is the only healthy value.",
	}, []string{"algo", "network"})

	m.WalletBalance = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "wallet_balance_atomic",
		Help: "Real, currently-reported hot-wallet balance in atomic units, by algo, network, currency, and kind (available/pending_incoming/pending_outgoing/timelocked).",
	}, []string{"algo", "network", "currency", "kind"})
	m.WalletBalancePollErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "wallet_balance_poll_errors_total",
		Help: "Total number of failed WalletClient.GetBalance calls made by the wallet-stats poller, by algo, network, and currency.",
	}, []string{"algo", "network", "currency"})

	m.StatsRequestsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "stats_requests_total",
		Help: "Total number of requests handled by the read-only miner stats API (internal/backend/statsapi), by endpoint and result (ok/rejected/error).",
	}, []string{"endpoint", "result"})

	m.RetentionPartitionsDroppedTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "retention_partitions_dropped_total",
		Help: "Total number of shares block_height leaf partitions dropped by the retention job's whole-partition DROP TABLE, by algo and pool_type.",
	}, []string{"algo", "pool_type"})

	m.RetentionPartitionsSkippedUnresolvedTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "retention_partitions_skipped_unresolved_total",
		Help: "Total number of shares block_height leaf partitions the retention job found otherwise eligible to drop but skipped because a blocks row inside that partition's height range is still unresolved (unlocked = false), by algo and pool_type. A sustained non-zero rate means a block is stuck unresolved long enough for retention to keep bumping into it.",
	}, []string{"algo", "pool_type"})

	m.RetentionRunDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "retention_run_duration_seconds",
		Help:    "Wall-clock time for one (algo, pool_type) target's evaluation in one retention RunOnce pass.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo", "pool_type"})

	m.RetentionRunErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "retention_run_errors_total",
		Help: "Total number of retention target evaluations that failed (listing or dropping partitions errored), by algo and pool_type.",
	}, []string{"algo", "pool_type"})

	m.StatsRequestDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "stats_request_duration_seconds",
		Help:    "Wall-clock time for one read-only miner stats API request, by endpoint.",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint"})

	m.NetworkPollsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "network_poll_total",
		Help: "Total number of real, live upstream chain-state queries made by the network-state poller, by algo, network, and result (ok/error).",
	}, []string{"algo", "network", "result"})

	m.NetworkPollDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "network_poll_duration_seconds",
		Help:    "Wall-clock time for one algo/network target's real upstream chain-state query in the network-state poller, by algo and network.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo", "network"})

	m.AuthAttemptsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "auth_attempts_total",
		Help: "Total number of POST /authenticate attempts, by result (success/failure).",
	}, []string{"result"})

	m.ForcePayoutWritesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "force_payout_writes_total",
		Help: "Total number of POST /user/forcePayment writes, by algo, network, and result (success/failure). Every write moves real money ahead of a miner's normal payout schedule.",
	}, []string{"algo", "network", "result"})

	m.AddressMapWritesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "address_map_writes_total",
		Help: "Total number of POST /api/v1/address-map writes, by result (accepted/rejected/error). Every write is either a legitimate first-time mapping or evidence of an attempted hijack of an existing XMR->Tari mapping.",
	}, []string{"result"})

	m.PendingBalanceOutstanding = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "pending_balance_outstanding",
		Help: "Current sum of every positive balance.pending_balance row, by algo and network -- the total this pool currently owes its miners.",
	}, []string{"algo", "network"})

	return m
}

// ObserveNetworkPoll increments NetworkPollsTotal and records
// NetworkPollDuration for one internal/backend/networkpoller.Poller
// pass against one Target, satisfying networkpoller.Metrics without
// that package needing to import this one's collector types
// directly (mirrors ObserveRequest's role for statsapi).
func (m *Metrics) ObserveNetworkPoll(algo, network, result string, duration time.Duration) {
	m.NetworkPollsTotal.WithLabelValues(algo, network, result).Inc()
	m.NetworkPollDuration.WithLabelValues(algo, network).Observe(duration.Seconds())
}

// ObserveRequest increments StatsRequestsTotal and records
// StatsRequestDuration for one statsapi request, satisfying
// statsapi.StatsMetrics without that package needing to import this
// one's collector types directly.
func (m *Metrics) ObserveRequest(endpoint, result string, duration time.Duration) {
	m.StatsRequestsTotal.WithLabelValues(endpoint, result).Inc()
	m.StatsRequestDuration.WithLabelValues(endpoint).Observe(duration.Seconds())
}

// Handler returns the standard Prometheus text-exposition HTTP handler
// (promhttp's real handler, not a hand-rolled renderer) scoped to this
// Metrics' private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// registerCounterVec/registerHistogram/registerGauge/registerGaugeVec
// all follow the same graceful-registration convention: a registration
// failure (most realistically prometheus.AlreadyRegisteredError, e.g.
// if New is ever called twice against a registry that already has
// these names, which should not happen in normal use but must not
// crash the server if it somehow does) is logged and, where possible,
// the already-registered collector is reused rather than panicking —
// a metrics-registration issue must never be allowed to take the whole
// backend process down.
func registerCounterVec(reg *prometheus.Registry, opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	cv := prometheus.NewCounterVec(opts, labels)
	if err := reg.Register(cv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register counter %s: %v", opts.Name, err)
	}
	return cv
}

func registerGaugeVec(reg *prometheus.Registry, opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	gv := prometheus.NewGaugeVec(opts, labels)
	if err := reg.Register(gv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.GaugeVec); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register gauge vec %s: %v", opts.Name, err)
	}
	return gv
}

func registerGauge(reg *prometheus.Registry, opts prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(opts)
	if err := reg.Register(g); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(prometheus.Gauge); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register gauge %s: %v", opts.Name, err)
	}
	return g
}

func registerHistogram(reg *prometheus.Registry, opts prometheus.HistogramOpts) prometheus.Histogram {
	h := prometheus.NewHistogram(opts)
	if err := reg.Register(h); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(prometheus.Histogram); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register histogram %s: %v", opts.Name, err)
	}
	return h
}

func registerHistogramVec(reg *prometheus.Registry, opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	hv := prometheus.NewHistogramVec(opts, labels)
	if err := reg.Register(hv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register histogram vec %s: %v", opts.Name, err)
	}
	return hv
}
