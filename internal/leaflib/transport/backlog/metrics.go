package backlog

import (
	"errors"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds this package's Prometheus instrumentation, mirroring
// internal/leaflib/direct/metrics's exact registration convention
// (private-by-default registry, AlreadyRegisteredError-tolerant
// registerX helpers -- see that package's doc comment) with one
// difference: this package accepts an OPTIONAL caller-supplied
// *prometheus.Registry (Config.Registry) so an embedding binary can
// fold these metrics into its own existing /metrics endpoint. A nil
// Registry gets a fresh private one instead (never
// prometheus.DefaultRegisterer -- a library package should not
// silently mutate global process state).
type Metrics struct {
	registry *prometheus.Registry

	// EnqueuedTotal/DrainedTotal/FullDropsTotal/RetryAttemptsTotal/
	// RequeueFailuresTotal/CorruptDropsTotal are deliberately SEPARATE
	// counters from whatever recordTransportError/recordTransportSuccess
	// increments in internal/leaflib/direct (see DISPATCH_BRIEF.md) --
	// that pre-existing pair distinguishes real permanent loss from
	// durably-recoverable delay, and must not be conflated with this
	// package's own bookkeeping.
	EnqueuedTotal        *prometheus.CounterVec
	DrainedTotal         *prometheus.CounterVec
	FullDropsTotal       *prometheus.CounterVec
	RetryAttemptsTotal   *prometheus.CounterVec
	RequeueFailuresTotal *prometheus.CounterVec
	CorruptDropsTotal    prometheus.Counter
	DepthGauge           *prometheus.GaugeVec
	BytesGauge           *prometheus.GaugeVec
}

func newMetrics(reg *prometheus.Registry) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{registry: reg}

	m.EnqueuedTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_backlog_enqueued_total",
		Help: "Total number of shares/blocks durably enqueued to the disk-backed backlog after a transport-level delivery failure to the backend, by kind (share/block).",
	}, []string{"kind"})

	m.DrainedTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_backlog_drained_total",
		Help: "Total number of backlog entries successfully delivered to the backend by the background drain loop and permanently removed (acked) from the queue, by kind (share/block).",
	}, []string{"kind"})

	m.FullDropsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_backlog_full_drops_total",
		Help: "Total number of shares/blocks dropped (falling back to the pre-backlog log-and-drop behavior) because the disk-backed backlog was already at Config.MaxBytes capacity, by kind (share/block). Any non-zero value here means real data is being lost -- the backlog is not (yet) sized for this outage's duration/volume.",
	}, []string{"kind"})

	m.RetryAttemptsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_backlog_retry_attempts_total",
		Help: "Total number of background drain-loop delivery attempts against the inner transport that failed and were re-queued for another retry, by kind (share/block).",
	}, []string{"kind"})

	m.RequeueFailuresTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_backlog_requeue_failures_total",
		Help: "Total number of backlog entries permanently lost because re-enqueueing them onto the disk queue after a failed delivery attempt itself failed (a genuine disk I/O error) -- distinct from leaf_backlog_full_drops_total (capacity, not I/O failure).",
	}, []string{"kind"})

	m.CorruptDropsTotal = registerCounter(reg, prometheus.CounterOpts{
		Name: "leaf_backlog_corrupt_drops_total",
		Help: "Total number of backlog entries permanently dropped because they could not be decoded (corrupt envelope header, or a payload that fails to unmarshal as its envelope's claimed kind) -- these would never succeed no matter how many times retried.",
	})

	m.DepthGauge = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_backlog_depth",
		Help: "Current number of entries pending in the disk-backed backlog, by kind (share/block).",
	}, []string{"kind"})

	m.BytesGauge = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_backlog_bytes",
		Help: "Current on-disk bytes used by the backlog queue, by kind (share/block). The sum across both kinds is bounded by Config.MaxBytes.",
	}, []string{"kind"})

	return m
}

// Handler returns this Metrics' Prometheus /metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// registerCounterVec/registerGaugeVec/registerCounter mirror
// internal/leaflib/direct/metrics's identical, AlreadyRegisteredError-
// tolerant helpers exactly (see that package's own copies) -- kept as
// private, unexported duplicates here rather than an import, since
// direct/metrics's helpers are themselves unexported and this package
// must not depend on internal/leaflib/direct (the dependency edge
// runs the other way: direct depends on transport, never vice versa).
func registerCounterVec(reg *prometheus.Registry, opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	cv := prometheus.NewCounterVec(opts, labels)
	if err := reg.Register(cv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
		log.Printf("backlog/metrics: failed to register counter vec %s: %v", opts.Name, err)
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
		log.Printf("backlog/metrics: failed to register gauge vec %s: %v", opts.Name, err)
	}
	return gv
}

func registerCounter(reg *prometheus.Registry, opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
		}
		log.Printf("backlog/metrics: failed to register counter %s: %v", opts.Name, err)
	}
	return c
}
