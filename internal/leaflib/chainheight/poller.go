// Copyright and license: see repository LICENSE (MIT).

// Package chainheight is a small, reusable poll-and-cache wrapper
// around any node client's GetTipInfo(ctx) (uint64, error) method
// (both solo.MoneroNodeClient (monerod get_info) and
// direct.NodeClient/solo.GRPCNodeClient (Tari base-node GRPC
// GetTipInfo) already implement exactly this shape via the shared
// solo.NodeClient interface) -- used to back the
// leaf_monero_chain_height / leaf_tari_chain_height Prometheus
// gauges (leaf-direct/direct/server.go's EnableMetrics) without
// hitting monerod/the Tari base node on every single Prometheus
// scrape, mirroring this codebase's existing poll-and-cache
// conventions (e.g. shared.RateTracker's own background-ticker
// pattern in internal/leaflib/metrics).
package chainheight

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// TipInfoSource is the minimal subset of solo.NodeClient this package
// depends on -- deliberately NOT importing solo.NodeClient itself
// (or the direct/solo packages), so this small, reusable poller
// never pulls in either leaf mode's full dependency graph, and can
// be wired against either implementation identically.
type TipInfoSource interface {
	GetTipInfo(ctx context.Context) (uint64, error)
}

// DefaultInterval mirrors the 15-30s cadence Alex's legacy Zabbix
// UserParameter script polled monerod/tari_mm_daemon at.
const DefaultInterval = 20 * time.Second

// DefaultTimeout bounds each individual GetTipInfo call so a
// wedged/unreachable daemon can never pile up goroutines or block
// Stop() -- generous relative to a plain get_info/GetTipInfo call's
// normal latency, but well under DefaultInterval.
const DefaultTimeout = 10 * time.Second

// Poller periodically calls a TipInfoSource's GetTipInfo and caches
// the last successfully-observed height, so a Prometheus Collect()
// call (see directmetrics.Metrics.Collect) never itself blocks on --
// or triggers -- a live daemon RPC/GRPC round-trip. Safe for
// concurrent use: Height may be called from the Prometheus scrape
// goroutine while run's background goroutine keeps updating it.
type Poller struct {
	source   TipInfoSource
	interval time.Duration
	timeout  time.Duration
	logger   *log.Logger

	height  atomic.Uint64
	haveVal atomic.Bool

	stop chan struct{}
	done chan struct{}
}

// New constructs a Poller against source. interval<=0 falls back to
// DefaultInterval; a nil logger falls back to log.Default().
// Start must be called separately to begin polling.
func New(source TipInfoSource, interval time.Duration, logger *log.Logger) *Poller {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Poller{source: source, interval: interval, timeout: DefaultTimeout, logger: logger}
}

// Start polls once synchronously (so a Height() call immediately
// after Start already has a value whenever the source is reachable
// at startup, rather than waiting a full interval) and then begins
// the background polling goroutine. Must be called at most once per
// Poller.
func (p *Poller) Start() {
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	p.pollOnce()
	go p.run()
}

func (p *Poller) run() {
	defer close(p.done)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.pollOnce()
		}
	}
}

// pollOnce makes one real GetTipInfo call, bounded by p.timeout. A
// failed call is logged and otherwise ignored -- the previously
// cached height (if any) is left untouched, matching this feature's
// "stale-but-present beats absent" cache semantics: a transient
// daemon hiccup should not make the gauge disappear or snap to 0.
func (p *Poller) pollOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	h, err := p.source.GetTipInfo(ctx)
	if err != nil {
		p.logger.Printf("chainheight: GetTipInfo failed: %v", err)
		return
	}
	p.height.Store(h)
	p.haveVal.Store(true)
}

// Height returns the last successfully-polled height and true, or
// (0, false) if no poll has EVER succeeded yet (e.g. the daemon has
// been unreachable since process start) -- callers (the
// directmetrics.ChainHeightFunc wiring) must treat false as "emit no
// sample this scrape", not "emit 0".
func (p *Poller) Height() (uint64, bool) {
	if !p.haveVal.Load() {
		return 0, false
	}
	return p.height.Load(), true
}

// Stop signals the background goroutine to exit and blocks until it
// has. Safe to call on a Poller that was never Start()'d (no-op).
func (p *Poller) Stop() {
	if p.stop == nil {
		return
	}
	close(p.stop)
	<-p.done
}
