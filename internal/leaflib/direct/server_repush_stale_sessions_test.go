// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// tipPollLoop-stall / template-distribution-metrics-going-dark
// regression test (brief2.md, SAME production leaf/incident as
// session_jobfetch_closewait_test.go's CLOSE-WAIT fix, a second,
// related-but-distinct regression found on the same
// phx-dump.supportxmr.com leaf). See server.go's repushPool field
// doc comment and invalidateAndRepushJobs' own doc comment for the
// full root-cause chain this proves the fix for:
// tipPollLoop -> InvalidateAll -> notify ->
// debouncedInvalidateAndRepushJobs -> invalidateAndRepushJobs, all
// synchronous on tipPollLoop's own single goroutine, amplified by
// (but a real structural bug independent of) the sibling CLOSE-WAIT
// bug's session-map bloat.

// delayedDirectNodeClient wraps *fakeDirectNodeClient, adding a
// small, deliberate, artificial per-call delay to GetBlockTemplate --
// a REAL fixed delay (not an instant no-op), so a sequential-vs-
// parallel implementation difference is actually observable in real
// wall-clock time, per brief2.md's own required-test description.
// Also counts real calls made, so tests can confirm at least one
// batch's real fetches have genuinely started before racing ahead.
type delayedDirectNodeClient struct {
	*fakeDirectNodeClient
	delay time.Duration
	calls atomic.Int64
}

func (d *delayedDirectNodeClient) GetBlockTemplate(ctx context.Context, payoutAddress string, algo poolpb.Algo) (*solo.Job, error) {
	d.calls.Add(1)
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return d.fakeDirectNodeClient.GetBlockTemplate(ctx, payoutAddress, algo)
}

func (d *delayedDirectNodeClient) callCount() int64 {
	return d.calls.Load()
}

// newRepushFanoutTestServer builds a real Server/JobManager wired
// together exactly like NewServer's own production wiring (including
// the real Server.repushPool/invalidateAndRepushJobs subscription --
// see NewServer), backed by a delayedDirectNodeClient so every
// cache-miss JobForXNAtDifficulty call takes real, measurable wall-
// clock time.
func newRepushFanoutTestServer(t *testing.T, delay time.Duration) (*Server, *solo.JobManager, *delayedDirectNodeClient, *leaflib.ConnectionManager, context.Context) {
	t.Helper()
	inner := &fakeDirectNodeClient{height: 42, mergeMiningHash: []byte("repush-fanout-test-merge-mining-hash")}
	inner.targetDifficulty = 1 << 62
	node := &delayedDirectNodeClient{fakeDirectNodeClient: inner, delay: delay}

	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "repush-fanout-test-address",
		StaticDifficulty: 1000,
	})

	v := validator.NewSHA3XValidator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET,
		Algo:    poolpb.Algo_ALGO_SHA3X, PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
	})
	t.Cleanup(server.Shutdown)

	return server, jm, node, cm, ctx
}

// addSyntheticLoggedInSession registers one synthetic, already-
// logged-in *Session (distinct, randomly-generated xn -- see
// newSession) directly into server.sessions (this test lives in
// package direct, same as server.go/session.go, so reaching into
// that package-internal field/newSession is fine -- mirrors this
// package's other white-box tests, e.g. session_jobfetch_closewait_
// test.go reaching into server.sessions/server.jobFetchPool
// directly).
//
// The underlying ManagedConnection is a real one (via cm.Accept, on
// a real net.Pipe pair) but is closed IMMEDIATELY, before this
// session is ever used: pushJob's eventual writeJSON call then
// short-circuits at ManagedConnection.Write's very first line
// (mc.closed.Load()) without ever touching the underlying conn --
// fast and non-blocking, exactly like a real already-gone/stale
// session (this test's own analogue of the sibling CLOSE-WAIT bug's
// "still marked loggedIn, connection already gone" condition -- see
// server.go's invalidateAndRepushJobs doc comment) would behave.
// Using a genuinely open (unclosed) net.Pipe here instead would risk
// this test hanging: nothing ever reads the client side, so a write
// to it would block forever, which is exactly the kind of stall this
// whole fix exists to prevent -- not something this test wants to
// accidentally reintroduce.
func addSyntheticLoggedInSession(t *testing.T, cm *leaflib.ConnectionManager, ctx context.Context, server *Server, difficulty uint64, uniqueXN string) *Session {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	mc, err := cm.Accept(ctx, serverConn)
	if err != nil {
		t.Fatalf("cm.Accept: %v", err)
	}
	_ = mc.Close("test: pre-closed synthetic stale-session stand-in")
	_ = clientConn.Close()

	sess := newSession(mc, server, difficulty)
	sess.loggedIn.Store(true)
	if uniqueXN != "" {
		// newSession's own leaflib.NewSessionXN() draws only 2 random
		// bytes (65536 possible values) -- fine for real production
		// traffic (collisions just mean two sessions briefly share a
		// cached job, harmless), but a real birthday-paradox risk at
		// this test's own session counts (confirmed empirically: 500
		// random draws produced 2 real collisions in one run, making
		// a strict "node.callCount() == numSessions" assertion
		// flaky). Overriding with a caller-supplied, guaranteed-
		// distinct value keeps this test fully deterministic.
		sess.xn.Store(uniqueXN)
	}

	server.mu.Lock()
	server.sessions[mc.ID()] = sess
	server.mu.Unlock()

	return sess
}

// TestServerInvalidateAndRepushJobs_ParallelizesPerSessionFanoutAndRecordsMetricsOnce
// is brief2.md's required regression test items 1-3 and 5: proves
// invalidateAndRepushJobs' per-session fan-out (server.go) actually
// runs concurrently (bounded by repushFanoutConcurrency) rather than
// sequentially one session at a time, and that
// recordTemplateDistribution/the leaf_direct_template_distribution_*
// metrics fire exactly once, after the WHOLE batch has genuinely
// completed, with the correct pushed count.
func TestServerInvalidateAndRepushJobs_ParallelizesPerSessionFanoutAndRecordsMetricsOnce(t *testing.T) {
	const (
		numSessions  = 500
		perCallDelay = 12 * time.Millisecond
		difficulty   = 1000
	)
	// sequential (pre-fix) worst case: numSessions * perCallDelay == 6s.
	// parallel (post-fix) expected: numSessions/repushFanoutConcurrency * perCallDelay
	// == (500/64)*12ms ~= 93.75ms. boundedTimeout below is chosen with
	// generous slack above the parallel estimate while staying WELL
	// below the sequential worst case, so this assertion would have
	// FAILED (timed out) against the old, sequential implementation,
	// but comfortably passes against the real, bounded-concurrent one.
	const boundedTimeout = 2 * time.Second

	server, _, node, cm, ctx := newRepushFanoutTestServer(t, perCallDelay)
	server.EnableMetrics("repush-fanout-test", 0)

	sessions := make([]*Session, 0, numSessions)
	for i := 0; i < numSessions; i++ {
		sessions = append(sessions, addSyntheticLoggedInSession(t, cm, ctx, server, difficulty, fmt.Sprintf("%08x", i)))
	}

	start := time.Now()
	done := make(chan struct{})
	go func() {
		server.invalidateAndRepushJobs("local")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(boundedTimeout):
		t.Fatalf("invalidateAndRepushJobs did not return within %v for %d sessions at %v/call (sequential would need ~%v; this bound only fits real bounded-concurrency execution) -- node saw %d real GetBlockTemplate calls so far", boundedTimeout, numSessions, perCallDelay, time.Duration(numSessions)*perCallDelay, node.callCount())
	}
	elapsed := time.Since(start)
	t.Logf("invalidateAndRepushJobs(%d sessions, %v/call) completed in %v (sequential worst case would be %v)", numSessions, perCallDelay, elapsed, time.Duration(numSessions)*perCallDelay)

	if got := node.callCount(); got != int64(numSessions) {
		t.Fatalf("node.callCount() = %d, want %d (every session has a distinct, never-before-cached xn -- each must be a real, distinct GetBlockTemplate call)", got, numSessions)
	}

	// Every session was fresh (never delivered a job before), so
	// alreadyDelivered is false for all of them -- every one must
	// have actually been pushed.
	for _, sess := range sessions {
		lastID, _ := sess.lastDeliveredJobID.Load().(string)
		if lastID == "" {
			t.Fatalf("session %s (xn %s) was never delivered a job by invalidateAndRepushJobs", sess.sessionID, sess.XN())
		}
	}

	// recordTemplateDistribution must have fired exactly once, with
	// the correct pushed count (== numSessions, since every session
	// was logged-in, fresh, and successfully pushed).
	srvMetrics := server.metrics
	if srvMetrics == nil {
		t.Fatal("server.metrics is nil after EnableMetrics")
	}
	if got := repushCount(server); got != 1 {
		t.Fatalf("repushCount (leaf_direct_template_distribution_seconds sample count) = %d, want exactly 1", got)
	}
	minersGauge := srvMetrics.TemplateDistributionMiners.WithLabelValues("local")
	if got := readGaugeValue(t, minersGauge); got != float64(numSessions) {
		t.Fatalf("leaf_direct_template_distribution_miners{source=\"local\"} = %v, want %v", got, numSessions)
	}
}

// TestServerDebouncedInvalidateAndRepushJobs_DecouplesFromCallerGoroutine
// is brief2.md's required regression test item 4: proves
// debouncedInvalidateAndRepushJobs (the function tipPollLoop's own
// goroutine actually calls, via JobManager.notify -- see
// repushPool's own doc comment) returns promptly even while a real,
// genuinely slow invalidateAndRepushJobs pass dispatched via
// Server.repushPool is STILL in flight -- proving tipPollLoop itself
// (or any other caller reaching debouncedInvalidateAndRepushJobs)
// can never again be blocked on how long a repush pass takes,
// regardless of session-map size.
func TestServerDebouncedInvalidateAndRepushJobs_DecouplesFromCallerGoroutine(t *testing.T) {
	const (
		numSessions  = 500
		perCallDelay = 40 * time.Millisecond
		difficulty   = 1000
		// promptBound is how quickly debouncedInvalidateAndRepushJobs
		// itself must return -- it should be near-instant (just a
		// CurrentBest read, some repushMu bookkeeping, and a
		// TrySubmit dispatch), regardless of numSessions/perCallDelay
		// above. 100ms is brief2.md's own suggested bound.
		promptBound = 100 * time.Millisecond
	)
	// A full batch at this size/delay takes MUCH longer than
	// promptBound (500 sessions / 64 concurrency * 40ms ~= 312ms,
	// itself already > promptBound, and the FIRST dispatched pass
	// below is deliberately raced against while still genuinely
	// in-flight) -- this is intentional: the whole point of this
	// test is that debouncedInvalidateAndRepushJobs's own caller gets
	// control back long before the underlying repush pass is done.

	server, jm, node, cm, ctx := newRepushFanoutTestServer(t, perCallDelay)
	server.EnableMetrics("repush-decouple-test", 0)

	for i := 0; i < numSessions; i++ {
		addSyntheticLoggedInSession(t, cm, ctx, server, difficulty, fmt.Sprintf("d%07x", i))
	}

	// Seed JobManager's own tracked CurrentBest (via one real,
	// distinct, throwaway-xn fetch) so debouncedInvalidateAndRepushJobs
	// below takes the "genuine height increase" branch (server.go's
	// !s.lastRepushSet || height > s.lastRepushHeight) -- the SAME
	// never-debounced, always-immediate-dispatch branch brief2.md's
	// root cause cites as tipPollLoop's own real call path (line
	// ~935/~1147 in that doc), rather than the defensive
	// CurrentBest-not-set fallback.
	if _, err := jm.JobForXNAtDifficulty(context.Background(), "seed-xn-1", difficulty); err != nil {
		t.Fatalf("seed JobForXNAtDifficulty: %v", err)
	}

	// First call: dispatches the slow, 500-session repush pass onto
	// server.repushPool (1 worker) asynchronously and returns.
	firstCallStart := time.Now()
	server.debouncedInvalidateAndRepushJobs("local")
	firstCallElapsed := time.Since(firstCallStart)
	if firstCallElapsed > promptBound {
		t.Fatalf("first debouncedInvalidateAndRepushJobs call took %v, want under %v (dispatchRepush must never block the caller)", firstCallElapsed, promptBound)
	}

	// Wait until the dispatched pass has genuinely started (at least
	// one real GetBlockTemplate call underway) so the second call
	// below is racing against REAL in-flight work, not a pass that
	// happened to already finish.
	startDeadline := time.Now().Add(2 * time.Second)
	for node.callCount() < 1 {
		if time.Now().After(startDeadline) {
			t.Fatal("the first dispatched invalidateAndRepushJobs pass never started (no GetBlockTemplate call observed) -- repushPool dispatch may be broken")
		}
		time.Sleep(time.Millisecond)
	}
	// And confirm it's genuinely NOT finished yet (otherwise the
	// "still in flight" premise of this test doesn't hold -- with
	// 500 sessions at 40ms/call bounded to 64-way concurrency, one
	// full pass needs on the order of ~300ms, so it should still be
	// running here).
	if node.callCount() >= int64(numSessions) {
		t.Fatal("the first dispatched invalidateAndRepushJobs pass already finished before the second call -- increase perCallDelay/numSessions or reduce scheduling slack to keep this test's premise (racing against genuinely in-flight work) valid")
	}

	// Real height increase: seed a strictly higher height via another
	// distinct, throwaway xn, then call debouncedInvalidateAndRepushJobs
	// again. This must STILL return promptly, even though the first
	// pass (occupying repushPool's only worker) is still running --
	// this call's own dispatch just enqueues into repushPool's queue
	// (capacity 256) and returns immediately.
	node.fakeDirectNodeClient.mu.Lock()
	node.fakeDirectNodeClient.height = 43
	node.fakeDirectNodeClient.mu.Unlock()
	if _, err := jm.JobForXNAtDifficulty(context.Background(), "seed-xn-2", difficulty); err != nil {
		t.Fatalf("seed JobForXNAtDifficulty (height increase): %v", err)
	}

	secondCallStart := time.Now()
	server.debouncedInvalidateAndRepushJobs("local")
	secondCallElapsed := time.Since(secondCallStart)
	if secondCallElapsed > promptBound {
		t.Fatalf("second debouncedInvalidateAndRepushJobs call (while the first repush pass was still genuinely in flight) took %v, want under %v -- tipPollLoop's own caller must never block on an in-flight repush pass", secondCallElapsed, promptBound)
	}
	t.Logf("first call=%v second call (while first still in flight, %d/%d GetBlockTemplate calls done)=%v", firstCallElapsed, node.callCount(), numSessions, secondCallElapsed)

	// Let both dispatched passes fully drain before this test's
	// t.Cleanup(server.Shutdown) call stops repushPool, so Shutdown
	// itself doesn't have to wait through this test's own artificial
	// delay. repushCount reaching 2 is the direct, real completion
	// signal for both dispatched invalidateAndRepushJobs passes
	// (recordTemplateDistribution fires exactly once per completed
	// pass -- see that method's own doc comment) -- NOT
	// node.callCount(), since the second pass's own per-session
	// JobForXNAtDifficulty calls are almost all cache HITS (the first
	// pass already warmed every session's per-xn cache entry; only
	// InvalidateAll -- never called by this test -- would have wiped
	// it), so it completes near-instantly and adds ~0 extra real
	// GetBlockTemplate calls, not another numSessions of them.
	if got := waitForRepushCount(t, server, 2, 5*time.Second); got != 2 {
		t.Fatalf("dispatched repush passes never fully drained (repushCount=%d, want 2)", got)
	}
}

// readGaugeValue reads back the current value of a prometheus.Gauge
// via its own Write(*dto.Metric) method -- mirrors this package's
// existing debounce_test.go's repushCount helper's own approach to
// reading real Prometheus internals back out directly in a test,
// rather than needing a full scrape/HTTP round trip.
func readGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("reading gauge value: %v", err)
	}
	if m.Gauge == nil || m.Gauge.Value == nil {
		t.Fatal("gauge metric has no Value")
	}
	return m.Gauge.GetValue()
}
