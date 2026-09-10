// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// PERFORMANCE FIX (Alex, live production incident, 2026-08-30): Session.Run's
// read loop (session.go) used to call handleSubmit synchronously and block on
// its result before scanning the next wire line. For SHA3X/C29 that's a cheap
// local CPU hash and genuinely fine. For ALGO_RXT/ALGO_RXM, handleSubmit's
// validator dispatch (validator.RandomXValidator.Validate) makes a REAL,
// SYNCHRONOUS HTTP round-trip to an external randomx-service daemon for every
// single submitted share -- confirmed via a live timing test to take ~4ms+
// per call even under light load, serialized ACROSS every connection hitting
// that daemon under real concurrent load. A real miner submits shares far
// faster than one sequential ~4ms+ round-trip can drain, so shares piled up
// in the OS receive buffer faster than the read loop could process them.
//
// CONFIRMED VIA REAL WIRE CAPTURE: against the live public RXM leaf
// (148.163.90.157:4450), a real xmrig client's own outbound submit request
// ids climbed into the thousands (id:8454, id:8458, ...) while the pool's
// most recently WRITTEN response was still echoing id:6127 -- a growing,
// unbounded backlog of over 2000 unprocessed requests, which eventually
// produced a client-side write failure and a full miner disconnect,
// recurring roughly every ~30s under sustained real load.
//
// THE FIX: dispatch each RandomX-family submit's validation (and everything
// downstream of it -- the actual randomx-service call, accept/reject
// bookkeeping, block-candidate construction/submission, and the wire
// response) onto a small, FIXED-SIZE worker pool instead of running it
// inline in Session.Run's read loop. The read loop itself only does cheap,
// synchronous work per submit (parse, session/job-ownership checks,
// MarkNonceUsed) before handing the rest off and immediately looping back to
// scanner.Scan() for the next line -- see session.go's handleSubmit for the
// exact split.
//
// WHY A FIXED WORKER POOL WITH A BOUNDED QUEUE, NOT goroutine-per-share (even
// gated by a semaphore): a semaphore-gated `go func(){ sem.Acquire(); ...
// }()` still spawns one goroutine per submitted share -- under a genuine
// flood (the exact production symptom being fixed here, or a deliberately
// abusive miner spamming garbage submits as fast as possible) the goroutine
// COUNT is unbounded even though the real HTTP-call concurrency is capped,
// which is exactly the failure mode this fix is required to avoid (see the
// task's explicit "not unbounded goroutine-per-share" constraint). A fixed
// pool of asyncValidationWorkers goroutines, each pulling closures off a
// bounded channel, keeps both the goroutine count AND the queued-but-not-
// yet-running work bounded and known at all times.
//
// WHY SERVER-SCOPED, NOT PER-SESSION: the actual contended resource is the
// single shared randomx-service daemon per leaf deployment, not any
// per-connection state -- see validator/randomx.go's RandomXValidator doc
// comment and this session's tari-protocol-research skill notes (recorded
// from real production investigation of randomx-service): that daemon
// supports exactly ONE active RandomX seed/VmKey at a time, and reseeding is
// a real, BLOCKING operation that pauses ALL other in-flight requests until
// it completes. A per-session pool would let N independently-configured caps
// (one per connection) collectively overwhelm that one shared daemon with no
// server-wide ceiling at all; a single server-wide pool gives one real,
// meaningful bound on how much concurrent randomx-service load THIS leaf
// process ever generates, regardless of how many miners are connected.
//
// THE BOUND ITSELF -- HARDENING FIX (Alex, DISPATCH_BRIEF.md,
// 2026-09-10): this pool's worker count used to be a hardcoded literal
// 8, justified below (in this doc comment's git history) purely by
// analogy to defaultSessionJobHistorySize -- a fixed, arbitrary
// constant with no actual relationship to how much real concurrency
// THIS process's host can usefully drive against randomx-service.
// Alex's explicit correction: "why only 8 workers? numcpu is the
// correct number of workers that we can send the backend." The
// worker count is now DefaultAsyncValidationWorkers() ==
// runtime.NumCPU() by default (see NewAsyncValidationPool's workers<=0
// fallback below) -- scales with the actual host this leaf process is
// running on (a small VM and a large bare-metal box get correspondingly
// different, host-appropriate concurrency, rather than the same fixed
// 8 either way) -- while still fully operator-overridable (see
// Server.SetRandomXWorkerPoolSize / cmd/leaf-solo, cmd/leaf-direct,
// cmd/leaf-proxy's own -randomx-workers flag) for a deployment that
// genuinely needs a different fixed number (e.g. to deliberately cap
// concurrent load against a randomx-service instance shared with other
// processes on the same host). AsyncValidationQueueSize (256) is
// unaffected by this change and keeps its original justification:
// generous headroom for a genuine, sustained multi-thousand-share/sec
// flood to be absorbed for a moment without the dispatching Submit call
// itself blocking, while still being a small, fixed, memory-bounded
// number -- once the queue is genuinely full, Submit blocks the CALLER
// (real backpressure, not a silent drop and not more goroutines), and since
// Submit is itself always called from within a spawned dispatch already
// off the read loop (see session.go's handleSubmit), that backpressure
// never blocks Session.Run's own scanner.Scan() loop.
const AsyncValidationQueueSize = 256

// DefaultAsyncValidationWorkers returns the DEFAULT worker count
// NewAsyncValidationPool falls back to when its caller passes
// workers <= 0 -- runtime.NumCPU(), per this file's own doc comment
// above (Alex's explicit direction: NumCPU, not a fixed literal).
// Computed fresh on every call (not cached at package-init/var-init
// time) so it reflects this process's actual runtime.GOMAXPROCS-
// relevant CPU count at the moment a pool is genuinely constructed,
// not whatever it happened to be at process startup (matters for e.g.
// a container whose CPU quota is applied/changed before this runs).
func DefaultAsyncValidationWorkers() int {
	return runtime.NumCPU()
}

// AsyncValidationPool is a small, fixed-size worker pool used to run
// RandomX-family (RXT/RXM) share validation off Session.Run's read loop --
// see this file's package-level doc comment above for the full rationale.
// Safe for concurrent use by any number of caller goroutines. Exported so
// internal/leaflib/direct (which already imports this package for
// solo.Job/solo.NodeClient/etc — see that package's session.go/server.go)
// can share the exact same pool implementation for its own, structurally
// identical read-loop-blocking bug, rather than duplicating it.
type AsyncValidationPool struct {
	jobs    chan func()
	done    chan struct{}
	wg      sync.WaitGroup
	workers int

	// inFlight/submitBlockedTotal are Fix 9's real observability
	// instrumentation (DISPATCH_BRIEF.md 2026-09-10): this pool is
	// shared across all three leaf modes (solo/direct/proxy all
	// construct one via NewAsyncValidationPool -- see this file's
	// own doc comment on "WHY SERVER-SCOPED"), and until this fix it
	// exposed NO metrics at all -- an operator had no way to alert
	// on the exact saturation condition Finding 2's own fix (the
	// bounded queue/NumCPU workers above) was designed around,
	// short of inferring it indirectly from share-response latency.
	//
	// Deliberately kept Prometheus-agnostic here (plain atomics, no
	// prometheus import in this package): each leaf mode's own
	// metrics package (solo/metrics, direct/metrics, proxy/metrics)
	// already has its OWN, genuinely different registration
	// convention (private lowercase registerGauge/registerCounter
	// helpers for solo/direct vs. the shared
	// internal/leaflib/metrics package's exported RegisterGauge/
	// RegisterCounter for proxy -- see those packages' own doc
	// comments) -- this pool has no business picking one of those
	// conventions over the others. Instead it exposes plain getter
	// methods (QueueDepth/InFlightWorkers/SubmitBlockedTotal below)
	// that ANY of the three metrics packages can poll generically at
	// scrape time, exactly mirroring the existing SnapshotFunc/
	// Collect "recomputed live at scrape time" pattern each of those
	// packages already uses for their own per-session snapshot
	// metrics -- see e.g. solo/metrics.Metrics.Collect.
	inFlight           atomic.Int64
	submitBlockedTotal atomic.Uint64
}

// NewAsyncValidationPool starts workers goroutines immediately, each ready
// to pull closures off a queue bounded to queueSize entries. A non-positive
// workers falls back to DefaultAsyncValidationWorkers() (runtime.NumCPU())
// and a non-positive queueSize falls back to AsyncValidationQueueSize, so a
// caller can pass zero values (e.g. a Server built without deliberately
// overriding either) and still get the documented, justified default bound
// rather than an unbounded or zero-capacity pool -- and an operator who
// DOES want a specific fixed worker count can still get one by passing a
// positive value (see Server.SetRandomXWorkerPoolSize).
func NewAsyncValidationPool(workers, queueSize int) *AsyncValidationPool {
	if workers <= 0 {
		workers = DefaultAsyncValidationWorkers()
	}
	if queueSize <= 0 {
		queueSize = AsyncValidationQueueSize
	}
	p := &AsyncValidationPool{
		jobs:    make(chan func(), queueSize),
		done:    make(chan struct{}),
		workers: workers,
	}
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.worker()
	}
	return p
}

// Workers reports how many worker goroutines this pool was actually
// constructed with (post the workers<=0 -> DefaultAsyncValidationWorkers()
// fallback in NewAsyncValidationPool) -- diagnostic/test use, so a
// caller (or a test) can confirm the real, live worker count rather
// than re-deriving what NewAsyncValidationPool's fallback would have
// picked independently.
func (p *AsyncValidationPool) Workers() int {
	return p.workers
}

// QueueDepth returns the current number of closures sitting in this
// pool's bounded queue, waiting for a free worker -- a live gauge
// value (len of a channel), NOT a cumulative counter. See this
// type's own doc comment (inFlight/submitBlockedTotal) for why this
// is exposed as a plain getter rather than tied to any one leaf
// mode's own metrics-registration convention.
func (p *AsyncValidationPool) QueueDepth() int {
	return len(p.jobs)
}

// QueueCapacity returns this pool's fixed queue capacity (the
// queueSize NewAsyncValidationPool was constructed with, post its own
// <=0 fallback) -- useful alongside QueueDepth for an operator to
// compute a saturation ratio (depth/capacity) without this package
// needing to expose that ratio itself.
func (p *AsyncValidationPool) QueueCapacity() int {
	return cap(p.jobs)
}

// InFlightWorkers returns how many of this pool's fixed worker
// goroutines are, at this exact instant, actually running a
// dispatched validation closure (as opposed to idle, blocked on
// <-p.jobs) -- a live gauge value bounded by Workers().
func (p *AsyncValidationPool) InFlightWorkers() int64 {
	return p.inFlight.Load()
}

// SubmitBlockedTotal returns the real, monotonically-increasing count
// of Submit calls that could NOT take the fast, non-blocking path
// (see Submit's own doc comment) -- i.e. how many times a caller
// actually had to wait for queue room/a free worker. This is the
// direct signal for the saturation condition Finding 2's fix (the
// bounded queue + NumCPU workers) was designed to bound.
func (p *AsyncValidationPool) SubmitBlockedTotal() uint64 {
	return p.submitBlockedTotal.Load()
}

func (p *AsyncValidationPool) worker() {
	defer p.wg.Done()
	for {
		select {
		case fn := <-p.jobs:
			// Backpressure/graceful-degradation guarantee (task
			// constraint 4): fn is ALWAYS one of session.go's
			// finishSubmit-style closures, which unconditionally
			// ends in a real writeShareResponse call (accept or
			// reject) on every return path -- there is no path
			// through fn that leaves a submit unanswered. A panic
			// inside fn would otherwise take this whole worker down
			// silently (and eventually starve the pool one worker at
			// a time under adversarial input); recover it, log it,
			// and keep this worker alive to keep draining the queue.
			//
			// inFlight brackets the ENTIRE dispatched call (not just
			// runProtected's recover span) so InFlightWorkers()
			// accurately reflects "how many of this pool's fixed
			// workers are currently busy running a real validation
			// closure right now" for the whole time fn actually
			// occupies this worker goroutine.
			p.inFlight.Add(1)
			p.runProtected(fn)
			p.inFlight.Add(-1)
		case <-p.done:
			return
		}
	}
}

func (p *AsyncValidationPool) runProtected(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			// Intentionally no logger plumbed through here (this
			// type has no reference back to Server.logger) --
			// panics here would indicate a real bug in fn's own
			// closure body, not a randomx-service/network condition,
			// and go test -race plus this package's own test suite
			// is the intended place to catch that; production
			// visibility is via leaf_shares_total simply not getting
			// an accept/reject increment for that one share, which
			// is already an existing, monitored signal.
			_ = r
		}
	}()
	fn()
}

// Submit enqueues fn to run on one of this pool's fixed worker goroutines.
// It returns true if fn was (or will be) run, or false if the pool has
// already been stopped (fn was NOT run and never will be -- callers must
// treat this as "validation could not be dispatched" and respond to the
// miner accordingly, e.g. session.go's handleSubmit writes a real rejection
// response rather than leaving the submit unanswered; see task constraint
// 4, "no orphaned unresolved submits").
//
// Submit blocks the CALLER (real backpressure, never a silent drop and
// never additional goroutines) when the bounded queue is full and no worker
// is free yet -- see this file's package doc comment for why that never
// blocks Session.Run's own read loop in practice (Submit is always called
// from a goroutine already dispatched off that loop).
//
// FIX 9 (DISPATCH_BRIEF.md 2026-09-10): submitBlockedTotal counts every
// time this call could NOT take the fast, non-blocking path below (i.e.
// the queue was genuinely full and every worker was busy at that
// instant) -- this is the real, direct signal for the saturation
// condition Finding 2's fix was designed to bound, as opposed to
// QueueDepth alone (which can legitimately sit near-full under bursty
// but healthy load without ever actually blocking a caller). The
// non-blocking probe (the first select, with its own default case)
// is purely an instrumentation split of the exact same underlying
// channel operation -- it does not change Submit's blocking behavior
// or return semantics at all: if the fast path's default fires, the
// second select below still performs the identical blocking send this
// function always has.
func (p *AsyncValidationPool) Submit(fn func()) bool {
	select {
	case p.jobs <- fn:
		return true
	case <-p.done:
		return false
	default:
	}
	p.submitBlockedTotal.Add(1)
	select {
	case p.jobs <- fn:
		return true
	case <-p.done:
		return false
	}
}

// TrySubmit is Submit's NON-BLOCKING-ONLY counterpart: it takes ONLY
// the fast path (this exact same underlying channel operation, see
// Submit's own doc comment) and returns false immediately -- WITHOUT
// ever blocking the caller -- if the queue is genuinely full/every
// worker busy, or the pool has been stopped. fn is never run in that
// case (identical "not run and never will be" contract as Submit's
// false return).
//
// Fix 12 (DISPATCH_BRIEF.md 2026-09-10): this exists specifically for
// a caller that is ITSELF already running on one of a DIFFERENT
// AsyncValidationPool's own worker goroutines (direct/session.go's
// finishSubmit, running on Server.randomxPool, dispatching
// forwardShare/forwardBlock onto the separate Server.forwardPool) --
// using ordinary, potentially-blocking Submit there would let a
// saturated forwardPool block a randomxPool worker, reproducing
// EXACTLY the cross-pool resource contention Fix 12 exists to
// eliminate, just one level removed. TrySubmit's "drop rather than
// block" contract is the correct choice there: forwardPool's queue is
// already generously sized for any realistic burst (see
// AsyncValidationQueueSize's own doc comment) -- a TrySubmit failure
// there only occurs under a genuinely pathological, sustained backend
// stall, in which case dropping (and logging) that one forward is far
// preferable to ever blocking real RandomX validation throughput for
// other sessions.
func (p *AsyncValidationPool) TrySubmit(fn func()) bool {
	select {
	case p.jobs <- fn:
		return true
	case <-p.done:
		return false
	default:
		return false
	}
}

// Stop signals every worker goroutine to exit once it finishes any job it
// is currently running, and blocks until all of them have. Safe to call at
// most once; a Server that never calls it simply keeps its pool's workers
// alive for the lifetime of the process, which is the normal production
// case (one long-lived Server per leaf-solo/leaf-direct process).
func (p *AsyncValidationPool) Stop() {
	close(p.done)
	p.wg.Wait()
}
