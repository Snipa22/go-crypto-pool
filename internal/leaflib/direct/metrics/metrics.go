// Package metrics defines leaf-direct's Prometheus instrumentation,
// mirroring internal/leaflib/solo/metrics's own conventions exactly
// (private *prometheus.Registry, graceful non-panicking registration,
// bounded per-address label cardinality) plus one genuinely new metric
// (TransportErrorsTotal) leaf-solo has no equivalent of, since
// leaf-solo never forwards anything to a backend.
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

const (
	ResultAccepted = "accepted"
	ResultRejected = "rejected"
)

const OtherAddressLabel = "other"

const DefaultMaxAddressLabels = 50

// SessionSnapshot mirrors solo/metrics's own SessionSnapshot exactly.
type SessionSnapshot struct {
	Address    string
	RemoteIP   string
	Difficulty uint64
	// Agent mirrors solo/metrics's own SessionSnapshot.Agent exactly:
	// the real miner software/version string self-reported at login
	// (solo.LoginRequest.Agent), or "" if not logged in / not sent.
	Agent string
	// Hashrate mirrors solo/metrics's own SessionSnapshot.Hashrate
	// exactly: this session's real, per-session estimated hashrate
	// in hashes/second at the moment of the snapshot (see
	// leaflib.EstimateHashrateHz's doc comment for the formula).
	Hashrate float64
}

type SnapshotFunc func() []SessionSnapshot

// Metrics holds every Prometheus collector leaf-direct registers.
type Metrics struct {
	registry *prometheus.Registry

	SharesTotal           *prometheus.CounterVec
	BlocksTotal           *prometheus.CounterVec
	ConnectionErrorsTotal *prometheus.CounterVec

	// TransportErrorsTotal counts real failures forwarding a validated
	// share/block to the backend over transport.ShareTransport,
	// labeled by kind ("share"/"block"). This is a genuinely NEW
	// observability axis vs. leaf-solo (which has no backend
	// connection at all) — see session.go's forwardShare/forwardBlock.
	TransportErrorsTotal *prometheus.CounterVec

	BuildInfo *prometheus.GaugeVec

	maxAddressLabels int
	snapshot         SnapshotFunc
}

// New constructs a Metrics using a fresh, private *prometheus.Registry.
func New(version string, maxAddressLabels int) *Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = DefaultMaxAddressLabels
	}
	reg := prometheus.NewRegistry()
	m := &Metrics{registry: reg, maxAddressLabels: maxAddressLabels}

	m.SharesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_shares_total",
		Help: "Total number of shares submitted to this leaf-direct instance, by result (accepted/rejected).",
	}, []string{"result"})

	m.BlocksTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_blocks_total",
		Help: "Total number of blocks found/submitted by this leaf-direct instance, by result (accepted/rejected).",
	}, []string{"result"})

	m.ConnectionErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_connection_errors_total",
		Help: "Total number of miner connections that ended in an error/non-graceful category.",
	}, []string{"category"})

	m.TransportErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_transport_errors_total",
		Help: "Total number of failures forwarding a validated share/block to the backend over the ShareTransport, by kind (share/block).",
	}, []string{"kind"})

	m.BuildInfo = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_direct_build_info",
		Help: "Always 1; version label carries the running build's version string.",
	}, []string{"version"})
	m.BuildInfo.WithLabelValues(version).Set(1)

	if err := reg.Register(m); err != nil {
		log.Printf("metrics: failed to register leaf-direct snapshot collector: %v", err)
	}

	return m
}

func (m *Metrics) SetSnapshotSource(fn SnapshotFunc) {
	m.snapshot = fn
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

var (
	activeConnectionsDesc = prometheus.NewDesc(
		"leaf_direct_active_connections",
		"Current number of active miner connections.",
		nil, nil,
	)
	uniqueRemoteIPsDesc = prometheus.NewDesc(
		"leaf_direct_unique_remote_ips_gauge",
		"Current number of distinct remote IPs among active miner connections.",
		nil, nil,
	)
	minersByAddressDesc = prometheus.NewDesc(
		"leaf_direct_miners_by_address",
		"Current number of connected sessions per mining/payout address (capped cardinality).",
		[]string{"address"}, nil,
	)
	// minerHashrateByAddressDesc mirrors solo/metrics's own
	// minerHashrateByAddressDesc exactly (same real per-session
	// leaflib.EstimateHashrateHz estimate, summed per address,
	// capped identically to minersByAddressDesc above via
	// CapAddressHashrates).
	minerHashrateByAddressDesc = prometheus.NewDesc(
		"leaf_direct_miner_hashrate_hash_per_second",
		"Real, per-address SUM of currently-connected sessions' estimated hashrate in hashes/second (see leaflib.EstimateHashrateHz's doc comment for the difficulty*2^32/time estimation formula). Same capped cardinality as leaf_direct_miners_by_address; overflow aggregated into address=\"other\".",
		[]string{"address"}, nil,
	)
)

func ResultLabel(accepted bool) string {
	if accepted {
		return ResultAccepted
	}
	return ResultRejected
}

func (m *Metrics) Describe(_ chan<- *prometheus.Desc) {}

func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	var snaps []SessionSnapshot
	if m.snapshot != nil {
		snaps = m.snapshot()
	}

	ch <- prometheus.MustNewConstMetric(activeConnectionsDesc, prometheus.GaugeValue, float64(len(snaps)))

	ipSet := make(map[string]struct{}, len(snaps))
	addrCounts := make(map[string]int)
	addrHashrates := make(map[string]float64)
	for _, s := range snaps {
		if s.RemoteIP != "" {
			ipSet[s.RemoteIP] = struct{}{}
		}
		if s.Address != "" {
			addrCounts[s.Address]++
			addrHashrates[s.Address] += s.Hashrate
		}
	}

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

// CapAddressCounts mirrors solo/metrics's own CapAddressCounts exactly.
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

	keepN := max - 1
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

// CapAddressHashrates mirrors solo/metrics's own CapAddressHashrates
// exactly (the float64 analogue of CapAddressCounts).
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

// RemoteIPOf mirrors solo/metrics's own RemoteIPOf exactly.
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
