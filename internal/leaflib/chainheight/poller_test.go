// Copyright and license: see repository LICENSE (MIT).
package chainheight

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource is a synthetic TipInfoSource for tests: returns
// height.Load() and, when failNext is set, a single canned error
// (then clears the flag, mirroring one transient RPC hiccup).
type fakeSource struct {
	height   atomic.Uint64
	calls    atomic.Int64
	failNext atomic.Bool
}

func (f *fakeSource) GetTipInfo(_ context.Context) (uint64, error) {
	f.calls.Add(1)
	if f.failNext.CompareAndSwap(true, false) {
		return 0, errors.New("fake: daemon unreachable")
	}
	return f.height.Load(), nil
}

// TestPoller_HeightAbsentBeforeFirstSuccess proves the required
// "false means no sample yet" contract: a Poller that has never
// completed a successful poll must report ok=false, not (0, true).
func TestPoller_HeightAbsentBeforeFirstSuccess(t *testing.T) {
	p := &Poller{source: &fakeSource{}, interval: time.Hour, timeout: time.Second}
	if h, ok := p.Height(); ok {
		t.Fatalf("Height() = (%d, true) before any poll, want ok=false", h)
	}
}

// TestPoller_StartPollsSynchronouslyBeforeReturning proves Start's
// documented synchronous first poll: Height() must already report
// the real value immediately after Start returns, with no need to
// wait out a full interval.
func TestPoller_StartPollsSynchronouslyBeforeReturning(t *testing.T) {
	src := &fakeSource{}
	src.height.Store(12345)

	p := New(src, time.Hour, nil) // interval long enough the ticker never fires during this test
	p.Start()
	defer p.Stop()

	h, ok := p.Height()
	if !ok {
		t.Fatal("Height() ok=false immediately after Start, want true")
	}
	if h != 12345 {
		t.Fatalf("Height() = %d, want 12345", h)
	}
}

// TestPoller_RePollsOnInterval proves the background goroutine keeps
// polling and updating the cached value on the configured interval,
// not just once at Start.
func TestPoller_RePollsOnInterval(t *testing.T) {
	src := &fakeSource{}
	src.height.Store(100)

	p := New(src, 10*time.Millisecond, nil)
	p.Start()
	defer p.Stop()

	src.height.Store(200)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h, ok := p.Height(); ok && h == 200 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Height() never reflected the updated value 200 within 2s of re-polling")
}

// TestPoller_FailedPollKeepsPreviousValue proves the documented
// "stale-but-present beats absent" cache contract: a single failed
// poll must not clear or zero out a previously-cached successful
// value.
func TestPoller_FailedPollKeepsPreviousValue(t *testing.T) {
	src := &fakeSource{}
	src.height.Store(500)

	p := New(src, time.Hour, nil)
	p.Start()
	defer p.Stop()

	if h, ok := p.Height(); !ok || h != 500 {
		t.Fatalf("Height() = (%d, %v) after first successful poll, want (500, true)", h, ok)
	}

	src.failNext.Store(true)
	p.pollOnce() // simulate the next scheduled poll failing

	h, ok := p.Height()
	if !ok {
		t.Fatal("Height() ok=false after a single failed poll, want the previous value to remain cached")
	}
	if h != 500 {
		t.Fatalf("Height() = %d after a failed poll, want the previous cached value 500", h)
	}
}

// TestPoller_StopIsIdempotentAndSafeUnstarted proves Stop's
// documented no-op-when-never-started safety and that calling it
// once on a started Poller cleanly halts the background goroutine
// (no hang, no panic).
func TestPoller_StopIsIdempotentAndSafeUnstarted(t *testing.T) {
	p := New(&fakeSource{}, time.Hour, nil)
	p.Stop() // never started -- must not panic/block

	p.Start()
	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() on a started Poller did not return within 2s")
	}
}
