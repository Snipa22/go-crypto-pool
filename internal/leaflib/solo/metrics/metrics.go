// Package metrics defines leaf-solo's Prometheus instrumentation: this
// is the LEAF-SIDE stats layer, deliberately distinct in scope from
// internal/backend/metrics (which intentionally excludes per-miner
// labels because it aggregates across every leaf in the whole pool).
// A leaf-solo instance runs far fewer simultaneous connections (one
// leaf, one stratum port), so per-miner-address label cardinality is
// a reasonable, operator-relevant tradeoff at THIS level, subject to
// the explicit cap documented on MinersByAddress below.
//
// Mirrors the local convention established by internal/backend/metrics:
// a private *prometheus.Registry via New, graceful non-panicking
// registration, served via promhttp.HandlerFor.
package metrics

import (
	"errors"
	"log"
	"net"
	"net/http"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Result label values for shares_total/blocks_total, mirroring the
// backend metrics package's low-cardinality-by-result convention
// exactly (see internal/backend/metrics.ResultAccepted/ResultRejected):
// deliberately NOT labeled by miner address on this counter (address
// granularity lives on MinersByAddress below instead, where it's a
// live/current-state gauge rather than an ever-growing counter).
const (
	ResultAccepted = "accepted"
	ResultRejected = "rejected"
)

// Connection-error categories for ConnectionErrorsTotal. These map
// directly onto real close paths this package's callers (session.go's
// Run, server.go's handleConn) actually observe:
//   - ConnErrorIdleTimeout: the rolling idle deadline
//     (internal/leaflib.ManagedConnection's armDeadline) fired — the
//     read returned a net.Error with Timeout() == true.
//   - ConnErrorRemoteEOF: the miner closed the connection / sent a
//     clean EOF (bufio.Scanner's normal end-of-stream, Err() == nil).
//   - ConnErrorProtocolError: the miner sent something the wire
//     protocol couldn't parse as a line-delimited message within the
//     scanner's buffer (bufio.ErrTooLong), or the connection was
//     already torn down from under the read
//     (internal/leaflib.ErrConnectionClosed).
//   - ConnErrorRejectedByGate: internal/leaflib.ConnectionManager's
//     ConnectionGate declined to admit the connection at all (over
//     MaxConnections) — see internal/leaflib.ErrConnectionRejected.
//   - ConnErrorOther: any other, unclassified read error (e.g. a raw
//     TCP reset) — kept as a single bounded fallback bucket rather
//     than inventing new fixed categories that don't correspond to a
//     real code path.
const (
	ConnErrorIdleTimeout    = "idle-timeout"
	ConnErrorRemoteEOF      = "remote-eof"
	ConnErrorProtocolError  = "protocol-error"
	ConnErrorRejectedByGate = "rejected-by-gate"
	ConnErrorOther          = "other"
)

// OtherAddressLabel is the bucket every address beyond the configured
// cardinality cap (see CapAddressCounts) is aggregated into, on both
// the leaf_miners_by_address metric and the stats HTML page.
const OtherAddressLabel = "other"

// DefaultMaxAddressLabels is used when a caller passes maxAddressLabels
// <= 0 to New. 50 distinct concurrently-mining addresses is generously
// above what a real single-leaf solo deployment is expected to see
// (this is a single port on a single leaf, not the whole pool), while
// still bounding worst-case label cardinality from a malicious flood
// of junk login addresses to a small, fixed number.
const DefaultMaxAddressLabels = 50

// SessionSnapshot is the minimal point-in-time view of one connected
// session that this package needs to compute the snapshot-derived
// metrics/UI data below (active connections, unique remote IPs,
// per-address counts, vardiff difficulty distribution). It is
// deliberately decoupled from solo.Session (this package must not
// import the solo package, to avoid an import cycle — solo imports
// this package to wire metrics, not the other way around).
type SessionSnapshot struct {
	// Address is the session's logged-in mining/payout address, or ""
	// if the session hasn't completed login yet. Empty-address
	// sessions are excluded from the per-address breakdown (there's
	// nothing meaningful to attribute them to) but still counted in
	// ActiveConnections.
	Address string
	// RemoteIP is the connection's remote IP (port stripped — see
	// this package's doc comment on why per-IP is a bounded COUNT,
	// not a per-IP label).
	RemoteIP string
	// Difficulty is the session's current (post-vardiff) share
	// difficulty at the moment of the snapshot.
	Difficulty uint64
	// Agent is the real miner software/version string the session's
	// miner self-reported at login (solo.LoginRequest.Agent), or ""
	// if not logged in / not sent. Miner-controlled, diagnostic-only
	// — never used in any accept/reject decision.
	Agent string
	// Hashrate is this session's real, per-session estimated
	// hashrate in hashes/second at the moment of the snapshot (see
	// leaflib.EstimateHashrateHz's doc comment for the formula).
	Hashrate float64
}

// SnapshotFunc returns the current set of connected sessions. It is
// called synchronously from Metrics.Collect on every /metrics scrape
// (and from the stats HTML handler), so it must be cheap and
// non-blocking — solo.Server's real implementation is a single
// RLock'd map iteration.
type SnapshotFunc func() []SessionSnapshot

// Metrics holds every Prometheus collector leaf-solo registers, plus
// the registry they live in. Constructed via New; safe for concurrent
// use.
type Metrics struct {
	registry *prometheus.Registry

	// SharesTotal/BlocksTotal are real accept/reject counters
	// incremented at handleSubmit's real branch points (session.go).
	// Labeled by result only (accepted/rejected) — NOT by miner
	// address, mirroring the backend's low-cardinality convention.
	SharesTotal *prometheus.CounterVec
	BlocksTotal *prometheus.CounterVec

	// ConnectionErrorsTotal is incremented at real connection
	// teardown points, labeled by the small fixed category set
	// above.
	ConnectionErrorsTotal *prometheus.CounterVec

	BuildInfo *prometheus.GaugeVec

	maxAddressLabels int
	snapshot         SnapshotFunc
}

// New constructs a Metrics using a fresh, private *prometheus.Registry
// (see internal/backend/metrics.New's doc comment for the rationale —
// this mirrors that convention exactly). version is recorded on the
// leaf_solo_build_info gauge. maxAddressLabels bounds the
// leaf_miners_by_address cardinality (see CapAddressCounts); <= 0
// falls back to DefaultMaxAddressLabels.
func New(version string, maxAddressLabels int) *Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = DefaultMaxAddressLabels
	}
	reg := prometheus.NewRegistry()
	m := &Metrics{registry: reg, maxAddressLabels: maxAddressLabels}

	m.SharesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_shares_total",
		Help: "Total number of shares submitted to this leaf-solo instance, by result (accepted/rejected). Not labeled by miner address.",
	}, []string{"result"})

	m.BlocksTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_blocks_total",
		Help: "Total number of blocks found/submitted by this leaf-solo instance, by result (accepted/rejected). Not labeled by miner address.",
	}, []string{"result"})

	m.ConnectionErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_connection_errors_total",
		Help: "Total number of miner connections that ended in an error/non-graceful category, by category (idle-timeout/remote-eof/protocol-error/rejected-by-gate/other).",
	}, []string{"category"})

	m.BuildInfo = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_solo_build_info",
		Help: "Always 1; version label carries the running build's version string.",
	}, []string{"version"})
	m.BuildInfo.WithLabelValues(version).Set(1)

	// m itself implements prometheus.Collector for the
	// snapshot-derived metrics (active connections, unique remote
	// IPs, per-address gauge, vardiff difficulty histogram) — see
	// Describe/Collect below.
	if err := reg.Register(m); err != nil {
		log.Printf("metrics: failed to register leaf-solo snapshot collector: %v", err)
	}

	return m
}

// SetSnapshotSource wires the live session-snapshot provider (see
// SnapshotFunc). Must be called once, before the /metrics endpoint is
// ever served, for the snapshot-derived metrics to report real data
// instead of zeros. Not safe to call concurrently with Collect (in
// practice this is called once at startup, before the metrics HTTP
// listener is started).
func (m *Metrics) SetSnapshotSource(fn SnapshotFunc) {
	m.snapshot = fn
}

// Handler returns the standard Prometheus text-exposition HTTP handler
// scoped to this Metrics' private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// --- snapshot-derived metrics (recomputed on every scrape) ---

var (
	activeConnectionsDesc = prometheus.NewDesc(
		"leaf_active_connections",
		"Current number of active miner connections (live count, len(sessions)).",
		nil, nil,
	)
	// uniqueRemoteIPsDesc deliberately has NO per-IP label — see this
	// package's doc comment and the doc comment above on
	// SessionSnapshot.RemoteIP: exposing one Prometheus label value
	// per distinct remote IP that has ever connected is an unbounded
	// cardinality risk on WAN-facing, untrusted input (unlike the
	// address gauge below, an attacker can trivially cycle through
	// far more distinct source IPs than distinct useful addresses,
	// e.g. via IPv6). A bounded distinct-IP-count-of-currently-
	// connected-sessions gauge gives the requested "connections by
	// IP" visibility (how spread out is the current connection set)
	// without that risk; per-session RemoteAddr is still available
	// via the stats HTML page's per-session table for be operators
	// who need to look up a *specific* IP by hand.
	uniqueRemoteIPsDesc = prometheus.NewDesc(
		"leaf_unique_remote_ips_gauge",
		"Current number of distinct remote IPs among active miner connections (bounded by active-connection count, never a per-IP label).",
		nil, nil,
	)
	// minersByAddressDesc: unlike the backend's blanket exclusion of
	// per-miner labels (unbounded pool-wide cardinality), a leaf-solo
	// instance's connection count is naturally bounded by
	// MaxConnections/practical stratum-port capacity, so real
	// distinct-address cardinality here is small in practice. Still,
	// a payment address IS attacker-controllable (anyone can log in
	// with any string), so CapAddressCounts below enforces a hard cap
	// on distinct label values regardless: the top maxAddressLabels-1
	// addresses by live connection count get their own series, and
	// every address beyond that is aggregated into a single
	// OtherAddressLabel series, so this metric can never grow past
	// maxAddressLabels distinct label values no matter how many
	// distinct junk addresses a flood presents.
	minersByAddressDesc = prometheus.NewDesc(
		"leaf_miners_by_address",
		"Current number of connected sessions per mining/payout address (live snapshot, capped cardinality — overflow addresses are aggregated into address=\"other\").",
		[]string{"address"}, nil,
	)
	// minerHashrateByAddressDesc reports the real, summed per-session
	// estimated hashrate (leaflib.EstimateHashrateHz) of every
	// currently-connected session, aggregated by mining/payout
	// address and subject to the EXACT SAME cardinality cap as
	// minersByAddressDesc above (CapAddressHashrates, the float64
	// analogue of CapAddressCounts) — an address is attacker-
	// controllable (any login string), so this gauge's cardinality
	// must be bounded identically to the miners-by-address gauge it
	// is aggregated alongside, never per raw session (session IDs
	// are even more attacker-controllable via connection churn).
	minerHashrateByAddressDesc = prometheus.NewDesc(
		"leaf_miner_hashrate_hash_per_second",
		"Real, per-address SUM of currently-connected sessions' estimated hashrate in hashes/second (see leaflib.EstimateHashrateHz's doc comment for the difficulty/time estimation formula). Same capped cardinality as leaf_miners_by_address; overflow aggregated into address=\"other\".",
		[]string{"address"}, nil,
	)
)

// vardiffDifficultyBuckets covers LEAF_SOLO_MIN_DIFFICULTY..
// LEAF_SOLO_MAX_DIFFICULTY's typical real range (1 up to ~1e9, see
// cmd/leaf-solo/main.go's defaults) with exponentially-spaced buckets.
var vardiffDifficultyBuckets = prometheus.ExponentialBuckets(1, 10, 10)

// Describe deliberately sends nothing: this makes Metrics an
// "unchecked" Prometheus collector (an explicitly-supported pattern,
// see the prometheus.Collector doc comment on Describe), which is
// required here because leaf_miners_by_address's label VALUES are
// dynamic and only known at Collect time (the whole point of the
// cardinality cap above is that the exact set of addresses reported
// varies scrape to scrape as sessions connect/disconnect).
func (m *Metrics) Describe(_ chan<- *prometheus.Desc) {}

// Collect recomputes every snapshot-derived metric from the live
// session set (via m.snapshot, set by SetSnapshotSource) at scrape
// time, rather than maintaining running per-session state that would
// leak/go stale after a session disconnects.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	var snaps []SessionSnapshot
	if m.snapshot != nil {
		snaps = m.snapshot()
	}

	ch <- prometheus.MustNewConstMetric(activeConnectionsDesc, prometheus.GaugeValue, float64(len(snaps)))

	ipSet := make(map[string]struct{}, len(snaps))
	addrCounts := make(map[string]int)
	addrHashrates := make(map[string]float64)
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "leaf_vardiff_current_difficulty",
		Help:    "Distribution of currently-connected sessions' current (post-vardiff) share difficulty, recomputed on every scrape.",
		Buckets: vardiffDifficultyBuckets,
	})
	for _, s := range snaps {
		if s.RemoteIP != "" {
			ipSet[s.RemoteIP] = struct{}{}
		}
		if s.Address != "" {
			addrCounts[s.Address]++
			addrHashrates[s.Address] += s.Hashrate
		}
		hist.Observe(float64(s.Difficulty))
	}
	hist.Collect(ch)

	ch <- prometheus.MustNewConstMetric(uniqueRemoteIPsDesc, prometheus.GaugeValue, float64(len(ipSet)))

	kept, other := CapAddressCounts(addrCounts, m.maxAddressLabels)
	for addr, count := range kept {
		ch <- prometheus.MustNewConstMetric(minersByAddressDesc, prometheus.GaugeValue, float64(count), addr)
	}
	if other > 0 {
		ch <- prometheus.MustNewConstMetric(minersByAddressDesc, prometheus.GaugeValue, float64(other), OtherAddressLabel)
	}

	keptRates, otherRate := CapAddressHashrates(addrHashrates, m.maxAddressLabels)
	for addr, rate := range keptRates {
		ch <- prometheus.MustNewConstMetric(minerHashrateByAddressDesc, prometheus.GaugeValue, rate, addr)
	}
	if otherRate > 0 {
		ch <- prometheus.MustNewConstMetric(minerHashrateByAddressDesc, prometheus.GaugeValue, otherRate, OtherAddressLabel)
	}
}

// CapAddressCounts enforces the leaf_miners_by_address cardinality cap
// documented above: if counts already has max or fewer distinct
// addresses, it is returned unchanged with otherTotal == 0. Otherwise
// the top (max-1) addresses by count (ties broken by address, for
// deterministic output) are kept verbatim and every remaining
// address's count is summed into otherTotal, which the caller is
// expected to render/export under OtherAddressLabel — so the exported
// series count never exceeds max regardless of how many distinct
// addresses actually connected.
func CapAddressCounts(counts map[string]int, max int) (kept map[string]int, otherTotal int) {
	if max <= 0 {
		max = DefaultMaxAddressLabels
	}
	if len(counts) <= max {
		return counts, 0
	}

	type kv struct {
		addr  string
		count int
	}
	items := make([]kv, 0, len(counts))
	for a, c := range counts {
		items = append(items, kv{a, c})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].addr < items[j].addr
	})

	keepN := max - 1 // reserve one label slot for the "other" bucket
	if keepN < 0 {
		keepN = 0
	}
	kept = make(map[string]int, keepN)
	for i := 0; i < len(items); i++ {
		if i < keepN {
			kept[items[i].addr] = items[i].count
		} else {
			otherTotal += items[i].count
		}
	}
	return kept, otherTotal
}

// CapAddressHashrates is CapAddressCounts' float64 analogue, used to
// bound leaf_miner_hashrate_hash_per_second's cardinality identically
// to leaf_miners_by_address's (see minerHashrateByAddressDesc's doc
// comment): if rates already has max or fewer distinct addresses, it
// is returned unchanged with otherTotal == 0. Otherwise the top
// (max-1) addresses by rate (ties broken by address, for deterministic
// output) are kept verbatim and every remaining address's rate is
// summed into otherTotal, under OtherAddressLabel.
func CapAddressHashrates(rates map[string]float64, max int) (kept map[string]float64, otherTotal float64) {
	if max <= 0 {
		max = DefaultMaxAddressLabels
	}
	if len(rates) <= max {
		return rates, 0
	}

	type kv struct {
		addr string
		rate float64
	}
	items := make([]kv, 0, len(rates))
	for a, r := range rates {
		items = append(items, kv{a, r})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].rate != items[j].rate {
			return items[i].rate > items[j].rate
		}
		return items[i].addr < items[j].addr
	})

	keepN := max - 1
	if keepN < 0 {
		keepN = 0
	}
	kept = make(map[string]float64, keepN)
	for i := 0; i < len(items); i++ {
		if i < keepN {
			kept[items[i].addr] = items[i].rate
		} else {
			otherTotal += items[i].rate
		}
	}
	return kept, otherTotal
}

// RemoteIPOf extracts just the IP (no port) from a net.Addr's string
// form, falling back to the raw string if it isn't a host:port pair
// (e.g. a net.Pipe address in tests, which nets.SplitHostPort can't
// parse). Exported so solo.Server's real net.Conn.RemoteAddr() values
// can be normalized the same way this package's tests construct
// SessionSnapshot.RemoteIP.
func RemoteIPOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// --- graceful registration helpers (mirrors internal/backend/metrics) ---

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
