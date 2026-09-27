// Copyright and license: see repository LICENSE (MIT).
package metrics

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// fakeClock is a manually-advanced time source for deterministic
// RateTracker tests -- see NewRateTrackerForTest's doc comment on why
// this package never sleep-based-tests a real 60-second window.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func TestRateTracker_ZeroBeforeTwoSamples(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	var counter uint64
	rt := NewRateTrackerForTest(func() uint64 { return counter }, fc.Now, 60, time.Second)

	if got := rt.Rate(); got != 0 {
		t.Fatalf("Rate() before any samples = %v, want 0", got)
	}

	counter = 5
	rt.Tick()
	if got := rt.Rate(); got != 0 {
		t.Fatalf("Rate() after exactly 1 sample = %v, want 0", got)
	}

	fc.Advance(time.Second)
	counter = 10
	rt.Tick()
	if got := rt.Rate(); got == 0 {
		t.Fatalf("Rate() after 2 samples = 0, want a nonzero rate")
	}
}

func TestRateTracker_ConvergesToKnownConstantRate(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	var counter uint64
	rt := NewRateTrackerForTest(func() uint64 { return counter }, fc.Now, 60, time.Second)

	// Simulate a synthetic counter that increments by exactly 3 every
	// simulated 1-second tick, for 10 ticks -- the real known
	// constant rate is 3.0/second.
	for i := 0; i < 10; i++ {
		fc.Advance(time.Second)
		counter += 3
		rt.Tick()
	}

	got := rt.Rate()
	want := 3.0
	if got != want {
		t.Fatalf("Rate() = %v, want exactly %v (buffer not yet wrapped, oldest sample is index 0)", got, want)
	}
}

func TestRateTracker_ConvergesAfterBufferWraps(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	var counter uint64
	const window = 5
	rt := NewRateTrackerForTest(func() uint64 { return counter }, fc.Now, window, time.Second)

	// Tick well past the window size so the ring buffer wraps at
	// least once; the real known constant rate (2/second) must still
	// be recovered from whatever `window` most-recent samples remain.
	for i := 0; i < 20; i++ {
		fc.Advance(time.Second)
		counter += 2
		rt.Tick()
	}

	got := rt.Rate()
	want := 2.0
	if got != want {
		t.Fatalf("Rate() after buffer wrap = %v, want %v", got, want)
	}
}

func TestRateTracker_NeverDividesByZero(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	var counter uint64
	rt := NewRateTrackerForTest(func() uint64 { return counter }, fc.Now, 60, time.Second)

	// Two samples with the SAME timestamp (no clock advance between
	// ticks) must never panic or report a nonsensical value.
	counter = 1
	rt.Tick()
	counter = 2
	rt.Tick()

	got := rt.Rate()
	if got != 0 {
		t.Fatalf("Rate() with zero elapsed time = %v, want 0", got)
	}
}

func TestRateTracker_StopOnTestTrackerIsNoop(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	rt := NewRateTrackerForTest(func() uint64 { return 0 }, fc.Now, 60, time.Second)
	// Must not panic/block: a NewRateTrackerForTest tracker never
	// started a background goroutine.
	rt.Stop()
}

func TestRateTracker_ProductionConstructorStopReleasesGoroutine(t *testing.T) {
	rt := NewRateTracker(func() uint64 { return 42 })
	rt.Stop()
	// A second Stop must also be safe (sync.Once-guarded).
	rt.Stop()
}

// TestRateTracker_StopReleasesBackgroundGoroutine confirms Stop
// genuinely terminates NewRateTracker's background ticker goroutine
// (not just that Stop itself returns) -- mirrors
// internal/leaflib/leak_test.go's own goleak.VerifyNone convention
// for regression-guarding exactly this class of bug.
func TestRateTracker_StopReleasesBackgroundGoroutine(t *testing.T) {
	defer goleak.VerifyNone(t)
	rt := NewRateTracker(func() uint64 { return 1 })
	rt.Stop()
}

// TestLabeledRateTrackers_StopReleasesEveryBackgroundGoroutine is
// TestRateTracker_StopReleasesBackgroundGoroutine's LabeledRateTrackers
// analogue: multiple lazily-created per-label trackers' goroutines
// must ALL be released by one Stop() call.
func TestLabeledRateTrackers_StopReleasesEveryBackgroundGoroutine(t *testing.T) {
	defer goleak.VerifyNone(t)
	l := NewLabeledRateTrackers()
	l.Inc("a")
	l.Inc("b")
	l.Inc("c")
	l.Stop()
}

// TestLabeledRateTrackers_PerLabelLazyCreationIsIndependent confirms
// a rate tracker is created independently per label combination and
// one combination's activity does not affect another's rate.
func TestLabeledRateTrackers_PerLabelLazyCreationIsIndependent(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	l := NewLabeledRateTrackersForTest(fc.Now, 60, time.Second)

	if got := l.Rate("accepted"); got != 0 {
		t.Fatalf("Rate(%q) before any Inc = %v, want 0", "accepted", got)
	}

	for i := 0; i < 10; i++ {
		fc.Advance(time.Second)
		l.Inc("accepted")
		l.Inc("accepted")
		l.Inc("accepted")
		// "rejected" gets a completely different, much slower rate.
		if i%2 == 0 {
			l.Inc("rejected")
		}
		l.Tick()
	}

	acceptedRate := l.Rate("accepted")
	rejectedRate := l.Rate("rejected")

	if acceptedRate != 3.0 {
		t.Errorf("Rate(accepted) = %v, want 3.0", acceptedRate)
	}
	// rejected is incremented on every OTHER tick (i%2==0, 5 times
	// across the 9-second span between the oldest and newest
	// retained sample): (5-1)/9 = 4/9.
	wantRejected := 4.0 / 9.0
	if rejectedRate != wantRejected {
		t.Errorf("Rate(rejected) = %v, want %v", rejectedRate, wantRejected)
	}
	if acceptedRate == rejectedRate {
		t.Errorf("expected accepted/rejected rates to be independent, both reported %v", acceptedRate)
	}

	// A never-incremented label combination must still report 0,
	// unaffected by any other label's activity.
	if got := l.Rate("never-incremented"); got != 0 {
		t.Errorf("Rate(never-incremented) = %v, want 0", got)
	}
}

func TestLabeledRateTrackers_StopStopsEveryCreatedTracker(t *testing.T) {
	l := NewLabeledRateTrackers()
	l.Inc("a")
	l.Inc("b")
	// Must not panic/hang: stops both lazily-created trackers' real
	// background goroutines.
	l.Stop()
}
