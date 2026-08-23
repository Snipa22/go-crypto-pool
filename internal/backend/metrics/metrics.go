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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Result label values for shares_total/blocks_total. These map
// directly onto the three outcomes the backend's HTTP handlers
// actually distinguish today (see internal/backend/api's
// handleShare/handleBlock): a share/block is either persisted
// (Accepted), rejected before ever reaching the DB (auth failure,
// malformed body, failed validation, network mismatch — all
// Rejected), or it reached the DB and the insert itself failed
// (Error). Do not add new values here without a corresponding new
// code path in api.go that actually produces them.
const (
	ResultAccepted = "accepted"
	ResultRejected = "rejected"
	ResultError    = "error"

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
// maturation, and orphaning are.
const (
	UnlockerOutcomeMatured  = "matured"
	UnlockerOutcomeOrphaned = "orphaned"
	UnlockerOutcomeError    = "error"
)

// Result label values for payout_cycles_total — whether one
// matured-block payout calculation (Calculate{PPS,PPLNS,Solo} +
// Apply, see internal/backend/payout.Calculator) completed and
// credited balances, or failed partway through.
const (
	PayoutResultSuccess = "success"
	PayoutResultError   = "error"
)

// Result label values for disbursement_batches_total — whether one
// real on-chain transfer batch (internal/backend/disburse.Engine)
// was actually sent, failed at the wallet RPC layer, or was skipped
// before ever attempting a Transfer call (e.g. insufficient unlocked
// wallet balance for this cycle — see disburse.go's doc comment).
const (
	DisbursementResultSent    = "sent"
	DisbursementResultFailed  = "failed"
	DisbursementResultSkipped = "skipped"
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

	// WalletBalance is the hot wallet's real, currently-reported
	// balance, labeled by algo, network, and kind
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
	WalletBalance *prometheus.GaugeVec
	// WalletBalancePollErrorsTotal counts every failed
	// WalletClient.GetBalance call the stats poller makes, labeled
	// by algo and network — a stuck/unreachable wallet RPC should be
	// visible here even though WalletBalance itself simply stops
	// updating (a Gauge can't distinguish "still the last real
	// value" from "the poller is broken"; this counter can).
	WalletBalancePollErrorsTotal *prometheus.CounterVec
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
		Help: "Total number of pending blocks resolved to a terminal outcome by the block unlocker, by algo and outcome (matured/orphaned/error).",
	}, []string{"algo", "outcome"})

	m.UnlockerPollDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "unlocker_poll_duration_seconds",
		Help:    "Wall-clock time for one algo's pending-block poll pass in the block unlocker, by algo.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo"})

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

	m.WalletBalance = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "wallet_balance_atomic",
		Help: "Real, currently-reported hot-wallet balance in atomic units, by algo, network, and kind (available/pending_incoming/pending_outgoing/timelocked).",
	}, []string{"algo", "network", "kind"})
	m.WalletBalancePollErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "wallet_balance_poll_errors_total",
		Help: "Total number of failed WalletClient.GetBalance calls made by the wallet-stats poller, by algo and network.",
	}, []string{"algo", "network"})

	return m
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
