// Copyright and license: see repository LICENSE (MIT).

// Package metrics defines leaf-proxy's Prometheus instrumentation.
// It reuses internal/leaflib/metrics's generic, mode-agnostic
// conventions (bounded-cardinality address capping, remote-IP
// normalization, graceful AlreadyRegisteredError-tolerant Prometheus
// registration) rather than re-copying internal/leaflib/solo/metrics
// verbatim, while defining leaf-proxy's own, genuinely distinct
// metrics surface on top of them:
//
//   - ShareDecisionsTotal: leaf-proxy's own real accept/forward
//     split -- a share below the real upstream pool's requested
//     share difficulty is credited LOCALLY only; a share meeting or
//     exceeding it is FORWARDED upstream (see
//     internal/leaflib/proxy/session.go's handleSubmit and
//     internal/leaflib/proxy/job.go's Job.UpstreamShareDiff doc
//     comment for the exact, confirmed-correct comparison this
//     tracks). This has no leaf-solo analogue: leaf-solo's
//     shares_total is a plain accepted/rejected split, not a
//     local-vs-forward one.
//   - UpstreamConnected / UpstreamReconnectsTotal: leaf-proxy has
//     exactly one upstream pool connection (UpstreamClient) whose
//     real connect/disconnect/reconnect health has no leaf-solo
//     analogue (leaf-solo talks GRPC directly to a Tari base node,
//     not through anything shaped like a reconnecting pool
//     session).
//   - ConnectionErrorsTotal / BuildInfo / ActiveConnections /
//     UniqueRemoteIPs / MinersByAddress / vardiff difficulty
//     histogram: the same snapshot-derived, per-downstream-connection
//     shape leaf-solo's metrics package already established (see
//     that package's doc comment for the full cardinality-bounding
//     rationale, reused here identically via
//     internal/leaflib/metrics.CapAddressCounts/RemoteIPOf).
package metrics

import (
	"log"
	"net/http"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	shared "github.com/Snipa22/go-crypto-pool/internal/leaflib/metrics"
)

// Decision label values for ShareDecisionsTotal -- leaf-proxy's own
// real accept/forward split (see this package's doc comment).
const (
	DecisionLocalCredit     = "local_credit"
	DecisionUpstreamForward = "upstream_forward"
)

// Result label values for SharesTotal/BlocksTotal -- Fix 9
// (DISPATCH_BRIEF.md 2026-09-10): distinct from ShareDecisionsTotal
// above (which tracks WHERE a share was credited, local vs
// upstream-forwarded) -- these track WHETHER a submit was ultimately
// accepted or rejected at all, mirroring solo/direct's identical
// ResultAccepted/ResultRejected convention exactly (see
// internal/leaflib/solo/metrics.ResultAccepted).
const (
	ResultAccepted = "accepted"
	ResultRejected = "rejected"
)

// BanRejectionPhase label values for BanRejectionsTotal -- Fix 9
// (DISPATCH_BRIEF.md 2026-09-10): a rejection can happen at either of
// two real call sites (session.go's handleLogin ban check, or
// handleSubmit's mid-session ban re-check) -- labeled separately so
// an operator can tell which is actually firing.
const (
	BanRejectionPhaseLogin  = "login"
	BanRejectionPhaseSubmit = "submit"
)

// Connection-error categories for ConnectionErrorsTotal -- the same
// fixed, bounded category set internal/leaflib/solo/metrics defines,
// duplicated here as small string constants (not the surrounding
// registration/collector machinery, which IS shared -- see this
// package's doc comment) because leaf-proxy's session.go has its own
// real classifyCloseError call site distinct from leaf-solo's.
const (
	ConnErrorIdleTimeout    = "idle-timeout"
	ConnErrorRemoteEOF      = "remote-eof"
	ConnErrorProtocolError  = "protocol-error"
	ConnErrorRejectedByGate = "rejected-by-gate"
	ConnErrorOther          = "other"
)

// OtherAddressLabel/DefaultMaxAddressLabels/CapAddressCounts/RemoteIPOf
// are re-exported from the shared package so callers only need to
// import this one package for every leaf-proxy-metrics-related helper.
const (
	OtherAddressLabel       = shared.OtherAddressLabel
	DefaultMaxAddressLabels = shared.DefaultMaxAddressLabels
)

var (
	CapAddressCounts = shared.CapAddressCounts
	RemoteIPOf       = shared.RemoteIPOf
)

// SessionSnapshot is the minimal point-in-time view of one connected
// downstream session this package needs for its snapshot-derived
// metrics -- deliberately decoupled from proxy.Session (this package
// must not import the proxy package, to avoid an import cycle: proxy
// imports this package to wire metrics, not the other way around).
// Mirrors internal/leaflib/solo/metrics.SessionSnapshot's shape.
type SessionSnapshot struct {
	Address    string
	RemoteIP   string
	Difficulty uint64
}

// SnapshotFunc returns the current set of connected downstream
// sessions. Called synchronously from Metrics.Collect on every
// /metrics scrape, so it must be cheap and non-blocking.
type SnapshotFunc func() []SessionSnapshot

// AsyncPoolStats/AsyncPoolStatsFunc mirror solo/metrics's own
// identical types exactly (Fix 9, DISPATCH_BRIEF.md 2026-09-10) --
// leaf-proxy shares the exact same solo.AsyncValidationPool
// implementation (see server.go's randomxPool field) leaf-direct
// does, so its own metrics package needs the exact same
// snapshot-derived shape -- decoupled from *solo.AsyncValidationPool
// itself for the same import-cycle-avoidance reason SessionSnapshot
// is decoupled from proxy.Session (see this package's doc comment).
type AsyncPoolStats struct {
	QueueDepth         int
	InFlightWorkers    int64
	SubmitBlockedTotal uint64
}

type AsyncPoolStatsFunc func() AsyncPoolStats

// Metrics holds every Prometheus collector leaf-proxy registers, plus
// the registry they live in. Constructed via New; safe for concurrent
// use.
type Metrics struct {
	registry *prometheus.Registry

	// ShareDecisionsTotal is leaf-proxy's own real local-credit vs
	// upstream-forward split -- see this package's doc comment.
	ShareDecisionsTotal *prometheus.CounterVec

	// SharesTotal/BlocksTotal are the Fix 9 (DISPATCH_BRIEF.md
	// 2026-09-10) real accept/reject counters, mirroring solo/
	// direct's identical SharesTotal/BlocksTotal exactly (result
	// label only, not by miner address) -- distinct from
	// ShareDecisionsTotal above (see ResultAccepted's own doc
	// comment for the exact distinction).
	SharesTotal *prometheus.CounterVec
	BlocksTotal *prometheus.CounterVec

	// BanRejectionsTotal is the Fix 9 real counter for the address-
	// ban enforcement points that were previously log-only -- see
	// BanRejectionPhaseLogin/BanRejectionPhaseSubmit's doc comment.
	BanRejectionsTotal *prometheus.CounterVec

	// UpstreamConnected is 1 when the single upstream pool
	// connection is currently up, 0 when it is down/reconnecting.
	UpstreamConnected prometheus.Gauge
	// UpstreamReconnectsTotal is a real, monotonically-increasing
	// count of successful upstream reconnects since process start
	// (the initial Connect on startup is NOT counted as a
	// "reconnect" -- only a real re-establishment after a real
	// connection loss is).
	UpstreamReconnectsTotal prometheus.Counter

	ConnectionErrorsTotal *prometheus.CounterVec

	BuildInfo *prometheus.GaugeVec

	maxAddressLabels int
	snapshot         SnapshotFunc
	asyncPoolStats   AsyncPoolStatsFunc
}

// New constructs a Metrics using a fresh, private *prometheus.Registry
// (mirrors internal/leaflib/solo/metrics.New's rationale exactly).
// version is recorded on the leaf_proxy_build_info gauge.
// maxAddressLabels bounds the leaf_proxy_miners_by_address
// cardinality; <= 0 falls back to DefaultMaxAddressLabels.
func New(version string, maxAddressLabels int) *Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = DefaultMaxAddressLabels
	}
	reg := prometheus.NewRegistry()
	m := &Metrics{registry: reg, maxAddressLabels: maxAddressLabels}

	m.ShareDecisionsTotal = shared.RegisterCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_proxy_share_decisions_total",
		Help: "Total number of downstream submits, by the real decision this leaf-proxy made: local_credit (below the upstream pool's requested share difficulty) or upstream_forward (met/exceeded it, forwarded via a real upstream submit RPC).",
	}, []string{"decision"})

	m.SharesTotal = shared.RegisterCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_proxy_shares_total",
		Help: "Total number of shares submitted to this leaf-proxy instance, by result (accepted/rejected). Not labeled by miner address. Distinct from leaf_proxy_share_decisions_total (which tracks local-credit vs upstream-forward, not accept/reject).",
	}, []string{"result"})

	m.BlocksTotal = shared.RegisterCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_proxy_blocks_total",
		Help: "Total number of genuine block-level finds forwarded upstream by this leaf-proxy instance, by result (accepted/rejected by the real upstream pool).",
	}, []string{"result"})

	m.BanRejectionsTotal = shared.RegisterCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_proxy_ban_rejections_total",
		Help: "Total number of downstream login/submit attempts rejected because the address-flags cache reports the address as banned, by phase (login/submit).",
	}, []string{"phase"})

	m.UpstreamConnected = shared.RegisterGauge(reg, prometheus.GaugeOpts{
		Name: "leaf_proxy_upstream_connected",
		Help: "1 if leaf-proxy's single upstream pool connection is currently established, 0 otherwise.",
	})

	m.UpstreamReconnectsTotal = shared.RegisterCounter(reg, prometheus.CounterOpts{
		Name: "leaf_proxy_upstream_reconnects_total",
		Help: "Total number of times leaf-proxy has successfully re-established its upstream pool connection after a real connection loss (does not count the initial startup connect).",
	})

	m.ConnectionErrorsTotal = shared.RegisterCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_connection_errors_total",
		Help: "Total number of downstream miner connections that ended in an error/non-graceful category, by category (idle-timeout/remote-eof/protocol-error/rejected-by-gate/other). Same category set as leaf-solo's identically-named metric.",
	}, []string{"category"})

	m.BuildInfo = shared.RegisterGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_proxy_build_info",
		Help: "Always 1; version label carries the running build's version string.",
	}, []string{"version"})
	m.BuildInfo.WithLabelValues(version).Set(1)

	if err := reg.Register(m); err != nil {
		log.Printf("metrics: failed to register leaf-proxy snapshot collector: %v", err)
	}

	return m
}

// SetSnapshotSource wires the live downstream-session-snapshot
// provider. Must be called once, before the /metrics endpoint is ever
// served, for the snapshot-derived metrics to report real data
// instead of zeros.
func (m *Metrics) SetSnapshotSource(fn SnapshotFunc) {
	m.snapshot = fn
}

// SetAsyncPoolSource mirrors solo/metrics's own identical method
// exactly -- see AsyncPoolStats' doc comment.
func (m *Metrics) SetAsyncPoolSource(fn AsyncPoolStatsFunc) {
	m.asyncPoolStats = fn
}

// Handler returns the standard Prometheus text-exposition HTTP handler
// scoped to this Metrics' private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// --- snapshot-derived metrics (recomputed on every scrape) ---

var (
	activeConnectionsDesc = prometheus.NewDesc(
		"leaf_proxy_active_connections",
		"Current number of active downstream miner connections (live count).",
		nil, nil,
	)
	// uniqueRemoteIPsDesc deliberately has NO per-IP label -- same
	// unbounded-cardinality-risk rationale as
	// internal/leaflib/solo/metrics.uniqueRemoteIPsDesc's doc
	// comment (this is a WAN-facing, untrusted-input surface).
	uniqueRemoteIPsDesc = prometheus.NewDesc(
		"leaf_proxy_unique_remote_ips_gauge",
		"Current number of distinct remote IPs among active downstream miner connections (bounded by active-connection count, never a per-IP label).",
		nil, nil,
	)
	// minersByAddressDesc: capped at maxAddressLabels distinct
	// series via CapAddressCounts -- see this package's doc comment
	// and internal/leaflib/metrics.CapAddressCounts's doc comment
	// for the full cardinality-bounding rationale (a payment address
	// is attacker-controllable, so this cap is enforced regardless
	// of how small real-world cardinality usually is).
	minersByAddressDesc = prometheus.NewDesc(
		"leaf_proxy_miners_by_address",
		"Current number of connected downstream sessions per mining/payout address (live snapshot, capped cardinality -- overflow addresses are aggregated into address=\"other\").",
		[]string{"address"}, nil,
	)

	// asyncPool*Desc mirrors solo/metrics's own identical Desc vars
	// exactly, INCLUDING the deliberately mode-agnostic
	// "leaf_async_validation_*" naming (not "leaf_proxy_*") -- see
	// that package's doc comment on these vars for why: this is the
	// exact same shared solo.AsyncValidationPool component leaf-solo
	// and leaf-direct also use, and each leaf mode's own private
	// registry never collides with the others' (one leaf mode per
	// process).
	asyncPoolQueueDepthDesc = prometheus.NewDesc(
		"leaf_async_validation_queue_depth",
		"Current number of RandomX-family (RXT/RXM) share-validation closures sitting in the shared AsyncValidationPool's bounded queue, waiting for a free worker.",
		nil, nil,
	)
	asyncPoolInFlightWorkersDesc = prometheus.NewDesc(
		"leaf_async_validation_in_flight_workers",
		"Current number of the shared AsyncValidationPool's fixed worker goroutines actively running a validation closure right now.",
		nil, nil,
	)
	asyncPoolSubmitBlockedTotalDesc = prometheus.NewDesc(
		"leaf_async_validation_submit_blocked_total",
		"Total number of Submit calls to the shared AsyncValidationPool that could not take the fast, non-blocking path (queue full and every worker busy) -- the real saturation signal for Finding 2's bounded-queue/NumCPU-workers fix.",
		nil, nil,
	)
)

// vardiffDifficultyBuckets mirrors
// internal/leaflib/solo/metrics.vardiffDifficultyBuckets exactly --
// leaf-proxy's own -min-difficulty/-max-difficulty defaults
// (cmd/leaf-proxy/main.go) cover the same real range.
var vardiffDifficultyBuckets = prometheus.ExponentialBuckets(1, 10, 10)

// Describe deliberately sends nothing -- see
// internal/leaflib/solo/metrics.Metrics.Describe's doc comment for
// why this "unchecked collector" pattern is required here (dynamic
// per-address label values only known at Collect time).
func (m *Metrics) Describe(_ chan<- *prometheus.Desc) {}

// Collect recomputes every snapshot-derived metric from the live
// downstream-session set (via m.snapshot) at scrape time.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	var snaps []SessionSnapshot
	if m.snapshot != nil {
		snaps = m.snapshot()
	}

	ch <- prometheus.MustNewConstMetric(activeConnectionsDesc, prometheus.GaugeValue, float64(len(snaps)))

	ipSet := make(map[string]struct{}, len(snaps))
	addrCounts := make(map[string]int)
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "leaf_proxy_vardiff_current_difficulty",
		Help:    "Distribution of currently-connected downstream sessions' current (post-vardiff) share difficulty, recomputed on every scrape.",
		Buckets: vardiffDifficultyBuckets,
	})
	for _, s := range snaps {
		if s.RemoteIP != "" {
			ipSet[s.RemoteIP] = struct{}{}
		}
		if s.Address != "" {
			addrCounts[s.Address]++
		}
		hist.Observe(float64(s.Difficulty))
	}
	hist.Collect(ch)

	ch <- prometheus.MustNewConstMetric(uniqueRemoteIPsDesc, prometheus.GaugeValue, float64(len(ipSet)))

	kept, other := CapAddressCounts(addrCounts, m.maxAddressLabels)
	// Deterministic iteration order for tests/reproducibility.
	addrs := make([]string, 0, len(kept))
	for addr := range kept {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)
	for _, addr := range addrs {
		ch <- prometheus.MustNewConstMetric(minersByAddressDesc, prometheus.GaugeValue, float64(kept[addr]), addr)
	}
	if other > 0 {
		ch <- prometheus.MustNewConstMetric(minersByAddressDesc, prometheus.GaugeValue, float64(other), OtherAddressLabel)
	}

	if m.asyncPoolStats != nil {
		stats := m.asyncPoolStats()
		ch <- prometheus.MustNewConstMetric(asyncPoolQueueDepthDesc, prometheus.GaugeValue, float64(stats.QueueDepth))
		ch <- prometheus.MustNewConstMetric(asyncPoolInFlightWorkersDesc, prometheus.GaugeValue, float64(stats.InFlightWorkers))
		ch <- prometheus.MustNewConstMetric(asyncPoolSubmitBlockedTotalDesc, prometheus.CounterValue, float64(stats.SubmitBlockedTotal))
	}
}
