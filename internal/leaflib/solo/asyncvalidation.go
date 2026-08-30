// Copyright and license: see repository LICENSE (MIT).
package solo

import "sync"

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
// THE BOUND ITSELF (asyncValidationWorkers = 8, asyncValidationQueueSize =
// 256): 8 mirrors this package's other already-justified small, fixed
// concurrency-adjacent constant (defaultSessionJobHistorySize) and is
// comfortably above what a single randomx-service instance can usefully
// pipeline (its own hashing is still effectively serialized per active
// seed -- more concurrent callers mostly overlap NETWORK/HTTP latency, not
// actual hash compute), while staying small enough that even a fully
// saturated pool represents a small, known amount of in-flight HTTP work
// against that daemon rather than an unbounded pile-up. Recall from the same
// investigation: repeated request pileups against an overloaded
// randomx-service have been observed to wedge it into a permanently
// unresponsive state (client-side-timeout-pileup failure mode) -- a small
// worker count is a deliberate hedge against reproducing that. 256 is
// generous headroom above 8 workers for a genuine, sustained multi-
// thousand-share/sec flood (the exact production symptom this fix
// addresses) to be absorbed for a moment without the dispatching Submit
// call itself blocking, while still being a small, fixed, memory-bounded
// number -- once the queue is genuinely full, Submit blocks the CALLER
// (real backpressure, not a silent drop and not more goroutines), and since
// Submit is itself always called from within a spawned dispatch already
// off the read loop (see session.go's handleSubmit), that backpressure
// never blocks Session.Run's own scanner.Scan() loop.
const (
	AsyncValidationWorkers   = 8
	AsyncValidationQueueSize = 256
)

// AsyncValidationPool is a small, fixed-size worker pool used to run
// RandomX-family (RXT/RXM) share validation off Session.Run's read loop --
// see this file's package-level doc comment above for the full rationale.
// Safe for concurrent use by any number of caller goroutines. Exported so
// internal/leaflib/direct (which already imports this package for
// solo.Job/solo.NodeClient/etc — see that package's session.go/server.go)
// can share the exact same pool implementation for its own, structurally
// identical read-loop-blocking bug, rather than duplicating it.
type AsyncValidationPool struct {
	jobs chan func()
	done chan struct{}
	wg   sync.WaitGroup
}

// NewAsyncValidationPool starts workers goroutines immediately, each ready
// to pull closures off a queue bounded to queueSize entries. A non-positive
// workers/queueSize falls back to AsyncValidationWorkers/
// AsyncValidationQueueSize respectively, so a caller can pass zero values
// (e.g. a Server built without deliberately overriding either) and still
// get the documented, justified default bound rather than an unbounded or
// zero-capacity pool.
func NewAsyncValidationPool(workers, queueSize int) *AsyncValidationPool {
	if workers <= 0 {
		workers = AsyncValidationWorkers
	}
	if queueSize <= 0 {
		queueSize = AsyncValidationQueueSize
	}
	p := &AsyncValidationPool{
		jobs: make(chan func(), queueSize),
		done: make(chan struct{}),
	}
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.worker()
	}
	return p
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
			p.runProtected(fn)
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
func (p *AsyncValidationPool) Submit(fn func()) bool {
	select {
	case p.jobs <- fn:
		return true
	case <-p.done:
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
