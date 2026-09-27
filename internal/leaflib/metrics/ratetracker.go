// Copyright and license: see repository LICENSE (MIT).

// This file adds a small, reusable, thread-safe rolling-rate tracker
// on top of common.go's already-generic, mode-agnostic conventions
// (see that file's own doc comment). Motivation: a real operator-
// visibility problem surfaced on a test deployment -- ever-increasing
// Prometheus counters (shares_total/blocks_total) are the
// theoretically-correct primitive (a dashboard is supposed to apply
// rate()/irate() at query time), but this pool's actual Grafana
// dashboards apparently aren't reliably doing that, so leaf-direct
// and leaf-solo's own metrics packages now ALSO compute and expose a
// genuine per-second rate directly (leaf_direct_shares_per_second and
// friends), additive to the existing _total counters, which remain
// completely unchanged.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRateTrackerWindow is the number of samples a production
// RateTracker (see NewRateTracker) retains -- combined with
// DefaultRateTrackerInterval (one sample per second), this covers a
// 60-second rolling window.
const DefaultRateTrackerWindow = 60

// DefaultRateTrackerInterval is how often a production RateTracker
// (see NewRateTracker) samples its getter in the background.
const DefaultRateTrackerInterval = time.Second

// RateTracker samples a monotonically-increasing uint64 counter value
// on a fixed cadence into a fixed-size ring buffer, and computes a
// per-second rate on demand from the oldest and newest retained
// samples: (newest - oldest) / elapsed_seconds. It is the leaf-side
// alternative to relying on every Grafana panel being configured with
// the right PromQL rate()/irate() query -- see this file's own doc
// comment.
//
// Safe for concurrent use: Tick() (sampling) and Rate() (reading) may
// be called from different goroutines at once.
type RateTracker struct {
	getter func() uint64
	clock  func() time.Time
	window int

	mu     sync.Mutex
	values []uint64
	times  []time.Time
	next   int // ring index the NEXT sample will be written to
	n      int // number of valid samples written so far (caps at window)

	started  bool
	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewRateTracker constructs a production RateTracker: getter is
// called once per DefaultRateTrackerInterval (in a background
// goroutine this constructor starts immediately) to sample the live
// value of some real, monotonically-increasing counter, retaining the
// most recent DefaultRateTrackerWindow samples. Callers MUST call
// Stop() to release the background goroutine once this RateTracker is
// no longer needed (mirrors solo.AsyncValidationPool's identical
// "constructed already running, explicit Stop to release" convention
// -- see that type's own doc comment); a RateTracker backing a
// process-lifetime singleton (the normal case here -- see
// LabeledRateTrackers, which every leaf-direct/leaf-solo Metrics
// singleton owns for its own process lifetime) is fine to simply
// leak if the owning process is exiting anyway, exactly like
// AsyncValidationPool's own Stop being optional in that same
// scenario.
func NewRateTracker(getter func() uint64) *RateTracker {
	return newRateTracker(getter, time.Now, DefaultRateTrackerWindow, DefaultRateTrackerInterval, true)
}

// NewRateTrackerForTest constructs a RateTracker that does NOT start
// a real background ticker goroutine, and uses clock (instead of
// time.Now) for every sample's timestamp. Tests drive sampling
// deterministically via Tick() and control elapsed time via clock,
// so a unit test can assert a RateTracker converges to a known,
// exact rate without ever sleeping or waiting on a real ticker (see
// ratetracker_test.go).
func NewRateTrackerForTest(getter func() uint64, clock func() time.Time, window int, interval time.Duration) *RateTracker {
	return newRateTracker(getter, clock, window, interval, false)
}

func newRateTracker(getter func() uint64, clock func() time.Time, window int, interval time.Duration, autoStart bool) *RateTracker {
	if window <= 0 {
		window = DefaultRateTrackerWindow
	}
	if interval <= 0 {
		interval = DefaultRateTrackerInterval
	}
	rt := &RateTracker{
		getter: getter,
		clock:  clock,
		window: window,
		values: make([]uint64, window),
		times:  make([]time.Time, window),
		stopCh: make(chan struct{}),
	}
	if autoStart {
		rt.started = true
		rt.wg.Add(1)
		go rt.run(interval)
	}
	return rt
}

func (rt *RateTracker) run(interval time.Duration) {
	defer rt.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rt.stopCh:
			return
		case <-ticker.C:
			rt.Tick()
		}
	}
}

// Tick takes one sample right now (getter's current value, clock's
// current time) and stores it in the ring buffer, overwriting the
// oldest retained sample once the buffer has filled. NewRateTracker's
// background goroutine calls this automatically once per interval;
// it is exported so NewRateTrackerForTest callers (and this
// package's own tests) can drive sampling manually and
// deterministically instead of waiting on a real ticker.
func (rt *RateTracker) Tick() {
	v := rt.getter()
	t := rt.clock()
	rt.mu.Lock()
	rt.values[rt.next] = v
	rt.times[rt.next] = t
	rt.next = (rt.next + 1) % rt.window
	if rt.n < rt.window {
		rt.n++
	}
	rt.mu.Unlock()
}

// Rate returns the current rolling-window per-second rate: (newest
// retained sample's value - oldest retained sample's value) / the
// elapsed seconds between them. Returns 0 if fewer than 2 samples
// have been taken yet (e.g. right after construction, before the
// first real tick has even fired once -- never a spurious rate
// before real samples exist), or if the elapsed time between the
// oldest and newest retained sample is <= 0 (never divides by zero),
// or if the newest sample's value is somehow less than the oldest's
// (a real monotonic counter should never decrease within one
// process's lifetime; guarded anyway rather than ever reporting a
// nonsensical negative rate).
func (rt *RateTracker) Rate() float64 {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.n < 2 {
		return 0
	}

	oldestIdx := 0
	if rt.n == rt.window {
		// Buffer has wrapped at least once: the oldest surviving
		// sample is the one about to be overwritten next.
		oldestIdx = rt.next
	}
	newestIdx := rt.next - 1
	if newestIdx < 0 {
		newestIdx = rt.window - 1
	}

	oldestVal, oldestTime := rt.values[oldestIdx], rt.times[oldestIdx]
	newestVal, newestTime := rt.values[newestIdx], rt.times[newestIdx]

	elapsed := newestTime.Sub(oldestTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	if newestVal < oldestVal {
		return 0
	}
	return float64(newestVal-oldestVal) / elapsed
}

// Stop signals the background ticker goroutine (if this RateTracker
// was constructed via NewRateTracker, which starts one automatically)
// to exit, and blocks until it has. Safe to call at most once. A
// no-op on a RateTracker constructed via NewRateTrackerForTest, which
// never started a goroutine in the first place.
func (rt *RateTracker) Stop() {
	if !rt.started {
		return
	}
	rt.stopOnce.Do(func() {
		close(rt.stopCh)
	})
	rt.wg.Wait()
}

// LabeledRateTrackers manages one RateTracker per label combination,
// created lazily the first time Inc is called for that combination --
// mirroring how a *prometheus.CounterVec itself lazily materializes a
// per-label-combination counter via WithLabelValues (see this
// package's own doc comment for why: a CounterVec's per-label value
// isn't independently queryable as a live uint64 outside the
// collector's own internal state, so each label combination's raw
// cumulative value is tracked here in a parallel atomic.Uint64
// instead -- simpler and less fragile than extracting it back out of
// an already-registered prometheus.Counter via its low-level
// Write(*dto.Metric) protobuf interface).
//
// Safe for concurrent use.
type LabeledRateTrackers struct {
	window    int
	interval  time.Duration
	clock     func() time.Time
	autoStart bool

	mu       sync.Mutex
	counters map[string]*atomic.Uint64
	trackers map[string]*RateTracker
}

// NewLabeledRateTrackers constructs a production LabeledRateTrackers:
// every label combination's lazily-created RateTracker uses
// NewRateTracker's own real-ticker, real-clock defaults (60-sample,
// 1-per-second window).
func NewLabeledRateTrackers() *LabeledRateTrackers {
	return &LabeledRateTrackers{
		window:    DefaultRateTrackerWindow,
		interval:  DefaultRateTrackerInterval,
		clock:     time.Now,
		autoStart: true,
		counters:  make(map[string]*atomic.Uint64),
		trackers:  make(map[string]*RateTracker),
	}
}

// NewLabeledRateTrackersForTest mirrors NewRateTrackerForTest: every
// label combination's lazily-created RateTracker is itself
// constructed via NewRateTrackerForTest (no real background ticker;
// clock/window/interval are test-controlled). Tick (below) drives
// every CURRENTLY EXISTING label's tracker forward by exactly one
// manual sample -- see the direct/metrics and solo/metrics packages'
// own integration tests for the intended usage (increment a known
// number of times across simulated Tick() calls, then scrape).
func NewLabeledRateTrackersForTest(clock func() time.Time, window int, interval time.Duration) *LabeledRateTrackers {
	return &LabeledRateTrackers{
		window:    window,
		interval:  interval,
		clock:     clock,
		autoStart: false,
		counters:  make(map[string]*atomic.Uint64),
		trackers:  make(map[string]*RateTracker),
	}
}

func (l *LabeledRateTrackers) getOrCreate(label string) (*atomic.Uint64, *RateTracker) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c, ok := l.counters[label]; ok {
		return c, l.trackers[label]
	}
	c := &atomic.Uint64{}
	l.counters[label] = c

	var rt *RateTracker
	if l.autoStart {
		rt = newRateTracker(c.Load, time.Now, l.window, l.interval, true)
	} else {
		rt = newRateTracker(c.Load, l.clock, l.window, l.interval, false)
	}
	l.trackers[label] = rt
	return c, rt
}

// Inc increments label's raw counter by 1, lazily creating both the
// counter and its RateTracker on first use for that label -- callers
// call this ALONGSIDE (never instead of) the real
// prometheus.CounterVec.WithLabelValues(label).Inc() call at the same
// real accept/reject branch point, so the two stay in exact lockstep.
func (l *LabeledRateTrackers) Inc(label string) {
	c, _ := l.getOrCreate(label)
	c.Add(1)
}

// Rate returns label's current rolling-window per-second rate, or 0
// if label has never been incremented yet (no tracker exists for it
// at all -- naturally consistent with RateTracker.Rate's own "fewer
// than 2 samples" zero-rate contract, which every label combination
// starts in before its first Inc).
func (l *LabeledRateTrackers) Rate(label string) float64 {
	l.mu.Lock()
	rt, ok := l.trackers[label]
	l.mu.Unlock()
	if !ok {
		return 0
	}
	return rt.Rate()
}

// Tick manually advances every label combination's RateTracker that
// exists SO FAR by exactly one sample. Only meaningful for a group
// constructed via NewLabeledRateTrackersForTest (autoStart == false);
// calling it on a production (autoStart == true) group is harmless
// (just an extra sample layered on top of that label's own real
// background ticker) but not the intended usage.
func (l *LabeledRateTrackers) Tick() {
	l.mu.Lock()
	trackers := make([]*RateTracker, 0, len(l.trackers))
	for _, rt := range l.trackers {
		trackers = append(trackers, rt)
	}
	l.mu.Unlock()
	for _, rt := range trackers {
		rt.Tick()
	}
}

// Stop stops every RateTracker this group has created so far (see
// RateTracker.Stop -- a no-op for any created by a non-autoStart,
// i.e. NewLabeledRateTrackersForTest, group).
func (l *LabeledRateTrackers) Stop() {
	l.mu.Lock()
	trackers := make([]*RateTracker, 0, len(l.trackers))
	for _, rt := range l.trackers {
		trackers = append(trackers, rt)
	}
	l.mu.Unlock()
	for _, rt := range trackers {
		rt.Stop()
	}
}
