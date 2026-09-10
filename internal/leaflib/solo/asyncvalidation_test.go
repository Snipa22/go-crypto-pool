// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDefaultAsyncValidationWorkersIsNumCPU is the direct, minimal
// regression guard for DISPATCH_BRIEF.md's (2026-09-10, Fix 2a) own
// explicit requirement: "why only 8 workers? numcpu is the correct
// number of workers that we can send the backend." -- the default
// worker count must track runtime.NumCPU(), not a hardcoded literal.
func TestDefaultAsyncValidationWorkersIsNumCPU(t *testing.T) {
	if got, want := DefaultAsyncValidationWorkers(), runtime.NumCPU(); got != want {
		t.Fatalf("DefaultAsyncValidationWorkers() = %d, want runtime.NumCPU() = %d", got, want)
	}
}

// TestNewAsyncValidationPoolDefaultsToNumCPUWorkers proves the pool
// ITSELF (not just the standalone helper function) actually applies
// this default when constructed with workers<=0 -- the shape every
// real production call site (solo/direct/proxy's own NewServer) now
// uses (see each package's server.go: `NewAsyncValidationPool(0,
// ...)`), confirmed via the pool's own Workers() introspection method
// rather than re-deriving the expected value through a separate,
// potentially-diverging code path.
func TestNewAsyncValidationPoolDefaultsToNumCPUWorkers(t *testing.T) {
	p := NewAsyncValidationPool(0, 0)
	defer p.Stop()
	if got, want := p.Workers(), runtime.NumCPU(); got != want {
		t.Fatalf("NewAsyncValidationPool(0, 0).Workers() = %d, want runtime.NumCPU() = %d", got, want)
	}

	// A negative value must be treated identically to 0/unset (the
	// exact same "non-positive" fallback NewAsyncValidationPool's own
	// doc comment documents).
	pNeg := NewAsyncValidationPool(-1, -1)
	defer pNeg.Stop()
	if got, want := pNeg.Workers(), runtime.NumCPU(); got != want {
		t.Fatalf("NewAsyncValidationPool(-1, -1).Workers() = %d, want runtime.NumCPU() = %d", got, want)
	}
}

// TestNewAsyncValidationPoolHonorsExplicitWorkerCount confirms an
// operator-supplied positive worker count is NOT overridden by the
// runtime.NumCPU() default -- the "runtime.NumCPU() should be the
// DEFAULT when unset, not a forced value that removes operator
// control" half of Fix 2a's own requirement.
func TestNewAsyncValidationPoolHonorsExplicitWorkerCount(t *testing.T) {
	const explicit = 3
	p := NewAsyncValidationPool(explicit, 0)
	defer p.Stop()
	if got := p.Workers(); got != explicit {
		t.Fatalf("NewAsyncValidationPool(%d, 0).Workers() = %d, want %d (explicit value must not be overridden by the default)", explicit, got, explicit)
	}
}

// TestAsyncValidationPool_InFlightWorkers_TracksRunningClosures is
// the required Fix 9 test (DISPATCH_BRIEF.md 2026-09-10):
// InFlightWorkers() must actually reflect how many dispatched
// closures are genuinely running right now, rising while they're
// blocked and falling back to 0 once released.
func TestAsyncValidationPool_InFlightWorkers_TracksRunningClosures(t *testing.T) {
	const workers = 2
	p := NewAsyncValidationPool(workers, workers)
	defer p.Stop()

	release := make(chan struct{})
	started := make(chan struct{}, workers)
	for i := 0; i < workers; i++ {
		if !p.Submit(func() {
			started <- struct{}{}
			<-release
		}) {
			t.Fatal("Submit returned false against a live pool")
		}
	}
	for i := 0; i < workers; i++ {
		<-started
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if p.InFlightWorkers() == int64(workers) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("InFlightWorkers() never reached %d, got %d", workers, p.InFlightWorkers())
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	deadline = time.Now().Add(2 * time.Second)
	for {
		if p.InFlightWorkers() == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("InFlightWorkers() never returned to 0 after release, got %d", p.InFlightWorkers())
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAsyncValidationPool_QueueDepth_ReflectsPendingClosures is the
// required Fix 9 test: QueueDepth() must reflect the real number of
// closures sitting in the bounded queue, waiting for a free worker.
func TestAsyncValidationPool_QueueDepth_ReflectsPendingClosures(t *testing.T) {
	// A single-worker pool with room for exactly 3 queued closures
	// beyond the one already running, so this test can deterministically
	// observe a real non-zero queue depth.
	p := NewAsyncValidationPool(1, 4)
	defer p.Stop()

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	if !p.Submit(func() {
		started <- struct{}{}
		<-release
	}) {
		t.Fatal("Submit returned false against a live pool")
	}
	<-started // the sole worker is now occupied.

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Submit(func() {})
		}()
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if p.QueueDepth() == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("QueueDepth() never reached 3, got %d", p.QueueDepth())
		}
		time.Sleep(time.Millisecond)
	}
	if cap := p.QueueCapacity(); cap != 4 {
		t.Errorf("QueueCapacity() = %d, want 4", cap)
	}

	close(release)
	wg.Wait()
}

// TestAsyncValidationPool_SubmitBlockedTotal_CountsOnlyRealBlocking is
// the required Fix 9 test: SubmitBlockedTotal only increments when a
// Submit call genuinely could not take the fast, non-blocking path
// (queue full and every worker busy) -- it must stay 0 for ordinary,
// non-saturated Submit calls that complete immediately, and must
// increment once a Submit call is genuinely forced onto the slow,
// blocking path.
func TestAsyncValidationPool_SubmitBlockedTotal_CountsOnlyRealBlocking(t *testing.T) {
	// Ordinary, unsaturated submits (a generously-sized queue
	// relative to how few closures this submits, so there is no
	// realistic way for the queue to fill up): must NOT count as
	// blocked. A separate pool from the saturation check below, so
	// the two scenarios can never interact.
	unsaturated := NewAsyncValidationPool(2, 16)
	defer unsaturated.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		if !unsaturated.Submit(func() { defer wg.Done() }) {
			t.Fatal("Submit returned false against a live pool")
		}
	}
	wg.Wait()
	if got := unsaturated.SubmitBlockedTotal(); got != 0 {
		t.Fatalf("SubmitBlockedTotal() = %d after ordinary unsaturated submits, want 0", got)
	}

	// A single-worker, single-queue-slot pool for the genuine
	// saturation check -- the smallest possible pool that still lets
	// this test deterministically construct "worker busy AND queue
	// full" without racing against how many workers/queue slots a
	// larger pool happens to have free at any given instant.
	p := NewAsyncValidationPool(1, 1)
	defer p.Stop()

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	if !p.Submit(func() {
		started <- struct{}{}
		<-release
	}) {
		t.Fatal("Submit returned false against a live pool")
	}
	<-started // the sole worker is now genuinely busy.

	// Fill the one queue slot with a closure that also blocks on
	// release, so the pool is genuinely fully saturated (worker
	// busy, queue full) once this Submit call returns.
	if !p.Submit(func() { <-release }) {
		t.Fatal("Submit returned false against a live pool")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if p.QueueDepth() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue never reached depth 1, got %d", p.QueueDepth())
		}
		time.Sleep(time.Millisecond)
	}

	// The pool is now genuinely saturated (1 worker busy, 1/1 queue
	// slot full) -- this next Submit call MUST take the slow,
	// blocking path.
	blockedDone := make(chan struct{})
	go func() {
		p.Submit(func() { <-release })
		close(blockedDone)
	}()

	deadline = time.Now().Add(2 * time.Second)
	for {
		if p.SubmitBlockedTotal() >= 1 {
			break
		}
		if time.Now().After(deadline) {
			close(release) // avoid leaking blocked goroutines/deadlocking p.Stop() on failure.
			t.Fatalf("SubmitBlockedTotal() never incremented for a genuinely saturated Submit, got %d", p.SubmitBlockedTotal())
		}
		time.Sleep(time.Millisecond)
	}

	close(release)
	<-blockedDone
}

// TestAsyncValidationPool_TrySubmit_NeverBlocksTheCaller is the
// required Fix 12 test (DISPATCH_BRIEF.md 2026-09-10) for
// TrySubmit's own core contract: unlike Submit, it must return false
// IMMEDIATELY -- never block the calling goroutine -- once the pool
// is genuinely saturated (queue full, every worker busy), and fn
// must never run in that case. This is what makes it safe for a
// caller that is itself already running on a DIFFERENT pool's own
// worker goroutine (see direct/session.go's forwardShare/forwardBlock
// dispatch onto Server.forwardPool from inside a Server.randomxPool
// worker).
func TestAsyncValidationPool_TrySubmit_NeverBlocksTheCaller(t *testing.T) {
	p := NewAsyncValidationPool(1, 1)
	defer p.Stop()

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	if !p.Submit(func() {
		started <- struct{}{}
		<-release
	}) {
		t.Fatal("Submit returned false against a live pool")
	}
	<-started // the sole worker is now genuinely busy.

	// Fill the one queue slot too, via TrySubmit itself -- this one
	// must succeed (the fast path has room).
	var ran atomic.Bool
	if !p.TrySubmit(func() { ran.Store(true); <-release }) {
		t.Fatal("TrySubmit returned false while the queue still had room")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if p.QueueDepth() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue never reached depth 1, got %d", p.QueueDepth())
		}
		time.Sleep(time.Millisecond)
	}

	// The pool is now genuinely saturated (1 worker busy, 1/1 queue
	// slot full) -- TrySubmit must return false immediately, and fn
	// must never run.
	var secondFnRan atomic.Bool
	done := make(chan bool, 1)
	go func() { done <- p.TrySubmit(func() { secondFnRan.Store(true) }) }()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("TrySubmit reported success against a genuinely saturated pool")
		}
	case <-time.After(500 * time.Millisecond):
		close(release) // avoid leaking goroutines / deadlocking p.Stop() on failure.
		t.Fatal("TrySubmit blocked the caller instead of returning immediately -- this defeats its entire purpose")
	}

	close(release)
	// Give the (never-dispatched) fn a moment to prove it truly never
	// ran, rather than merely racing a fast completion.
	time.Sleep(10 * time.Millisecond)
	if secondFnRan.Load() {
		t.Fatal("the closure passed to a failed TrySubmit call must never run")
	}
}

// TestAsyncValidationPool_TrySubmit_RunsOnceDispatched is the
// non-regression complement: a TrySubmit call that succeeds must
// still genuinely run fn, exactly like Submit.
func TestAsyncValidationPool_TrySubmit_RunsOnceDispatched(t *testing.T) {
	p := NewAsyncValidationPool(2, 4)
	defer p.Stop()

	done := make(chan struct{})
	if !p.TrySubmit(func() { close(done) }) {
		t.Fatal("TrySubmit returned false against a fresh, unsaturated live pool")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TrySubmit-dispatched closure never ran")
	}
}
