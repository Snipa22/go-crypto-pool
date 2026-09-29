// Copyright and license: see repository LICENSE (MIT).

// Package metrics holds the genuinely generic Prometheus-instrumentation
// conventions shared across every leaf mode (leaf-solo, leaf-proxy, and
// any future leaf/direct mode) -- NOT a leaf-mode-specific metrics
// package itself. internal/leaflib/solo/metrics established these
// conventions first (private-registry-via-New, graceful
// AlreadyRegisteredError-tolerant registration, promhttp.HandlerFor,
// and a bounded-cardinality per-address gauge with an overflow
// "other" bucket); this package extracts the mode-agnostic pieces of
// that so a second leaf mode (leaf-proxy, as of this pass) can reuse
// them instead of copy-pasting metrics.go wholesale, mirroring this
// repo's own established "shared extraction" convention (see
// internal/leaflib/vardiff.go's history: vardiff logic was extracted
// out of leaf-solo into a shared internal/leaflib location for the
// exact same reason once a second consumer needed it).
//
// internal/leaflib/solo/metrics itself is intentionally left
// untouched by this extraction (per this pass's explicit scope): its
// existing private CapAddressCounts/RemoteIPOf/register-helper
// implementations are NOT migrated to delegate to this package, so
// leaf-solo's already-shipped, already-tested metrics behavior has
// zero diff risk from this change. New consumers (leaf-proxy's own
// internal/leaflib/proxy/metrics package) import this package
// directly instead of duplicating the logic a second time.
package metrics

import (
	"errors"
	"log"
	"net"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
)

// OtherAddressLabel is the bucket every address beyond a configured
// cardinality cap (see CapAddressCounts) is aggregated into on any
// per-address gauge/table built on top of this package -- mirrors
// internal/leaflib/solo/metrics.OtherAddressLabel's exact convention.
const OtherAddressLabel = "other"

// DefaultMaxAddressLabels is the fallback used when a caller passes
// maxAddressLabels <= 0. Mirrors
// internal/leaflib/solo/metrics.DefaultMaxAddressLabels's value and
// rationale: generously above what a single leaf process is expected
// to see concurrently, while still bounding worst-case cardinality
// from a flood of junk login addresses to a small, fixed number.
const DefaultMaxAddressLabels = 50

// CapAddressCounts enforces a per-address label cardinality cap: if
// counts already has max or fewer distinct addresses, it is returned
// unchanged with otherTotal == 0. Otherwise the top (max-1) addresses
// by count (ties broken by address, for deterministic output) are
// kept verbatim and every remaining address's count is summed into
// otherTotal, which the caller is expected to render/export under
// OtherAddressLabel -- so the exported series count never exceeds max
// regardless of how many distinct addresses actually connected. This
// is a direct, behavior-for-behavior port of
// internal/leaflib/solo/metrics.CapAddressCounts (that implementation
// is left in place, untouched, per this pass's scope -- see this
// package's doc comment).
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

// RemoteIPOf extracts just the IP (no port) from a net.Addr's string
// form, falling back to the raw string if it isn't a host:port pair
// (e.g. a net.Pipe address in tests, which net.SplitHostPort can't
// parse). Direct port of
// internal/leaflib/solo/metrics.RemoteIPOf.
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

// RegisterCounterVec registers cv's underlying CounterVec on reg,
// gracefully returning the ALREADY-registered collector instead of a
// second, discarded one if this exact metric name was already
// registered on reg -- the "graceful non-panicking registration"
// convention internal/backend/metrics established and
// internal/leaflib/solo/metrics mirrors. Kept genuinely private-
// registry-per-Metrics-instance safe (the AlreadyRegisteredError case
// mainly matters for tests that construct multiple *Metrics against
// process-global state; each leaf's real Metrics.New already uses its
// own fresh *prometheus.Registry, so this mostly guards against
// double-New in tests rather than a real production double-register).
func RegisterCounterVec(reg *prometheus.Registry, opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
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

// RegisterGaugeVec is RegisterCounterVec's GaugeVec counterpart.
func RegisterGaugeVec(reg *prometheus.Registry, opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
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

// RegisterCounter is RegisterCounterVec's unlabeled Counter
// counterpart (used for e.g. a real total-reconnects counter that has
// no meaningful label dimension).
func RegisterCounter(reg *prometheus.Registry, opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register counter %s: %v", opts.Name, err)
	}
	return c
}

// RegisterGauge is RegisterCounterVec's unlabeled Gauge counterpart
// (used for e.g. leaf-proxy's single upstream-connection-health
// gauge).
func RegisterGauge(reg *prometheus.Registry, opts prometheus.GaugeOpts) prometheus.Gauge {
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

// RegisterHistogramVec is RegisterCounterVec's labeled HistogramVec
// counterpart (used for e.g. leaf-proxy's submit-processing-latency
// histogram).
func RegisterHistogramVec(reg *prometheus.Registry, opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
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

// RegisterHistogram is RegisterHistogramVec's unlabeled counterpart
// (used for e.g. leaf-proxy's submit-validation-latency histogram,
// which has no meaningful per-algo label dimension -- leaf-proxy is a
// single, fixed pure-Go RandomX upstream-forwarding proxy with no
// job.Algo concept at all, unlike leaf-solo/leaf-direct's own
// identically-named, algo-labeled metric).
func RegisterHistogram(reg *prometheus.Registry, opts prometheus.HistogramOpts) prometheus.Histogram {
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
