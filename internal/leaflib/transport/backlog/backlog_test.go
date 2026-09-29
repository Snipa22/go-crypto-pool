// Copyright and license: see repository LICENSE (MIT).
package backlog

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/protobuf/proto"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// testutilCounterVecTotal reads the current value of a labeled
// counter directly via prometheus/testutil, matching this repo's own
// convention for asserting on real counter values in tests rather
// than re-deriving them from log output.
func testutilCounterVecTotal(t *testing.T, cv *prometheus.CounterVec, label string) float64 {
	t.Helper()
	return testutil.ToFloat64(cv.WithLabelValues(label))
}

// fakeTransport is a controllable transport.ShareTransport test
// double -- real behavior tests against a fake/controllable inner
// transport, matching this repo's own house style (see
// internal/leaflib/direct/forward_pool_isolation_test.go and
// forward_pool_sizing_test.go).
type fakeTransport struct {
	mu sync.Mutex

	// failUntil: SubmitShare/SubmitBlock fail (return failErr) for the
	// first failUntil calls of that kind, then succeed. -1 means "fail
	// forever".
	shareFailUntil int
	blockFailUntil int
	failErr        error

	shareCalls int
	blockCalls int
	closed     bool
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{failErr: errors.New("fake transport: simulated backend failure")}
}

func (f *fakeTransport) SubmitShare(_ context.Context, _ *poolpb.Share) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shareCalls++
	if f.shareFailUntil < 0 || f.shareCalls <= f.shareFailUntil {
		return f.failErr
	}
	return nil
}

func (f *fakeTransport) SubmitBlock(_ context.Context, _ *poolpb.Block) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockCalls++
	if f.blockFailUntil < 0 || f.blockCalls <= f.blockFailUntil {
		return f.failErr
	}
	return nil
}

func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeTransport) ShareCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.shareCalls
}

func (f *fakeTransport) BlockCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blockCalls
}

func (f *fakeTransport) setShareFailUntil(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shareFailUntil = n
}

func testShare(id string) *poolpb.Share {
	return &poolpb.Share{
		Algo:           poolpb.Algo_ALGO_RXT,
		Network:        poolpb.Network_NETWORK_TESTNET,
		PaymentAddress: "test-address",
		Identifier:     id,
	}
}

func testBlock(hash string) *poolpb.Block {
	return &poolpb.Block{
		Algo:    poolpb.Algo_ALGO_RXT,
		Network: poolpb.Network_NETWORK_TESTNET,
		Hash:    hash,
	}
}

// fastTestConfig returns a Config tuned for fast, deterministic tests
// (small backoff, small drain-attempt timeout, a real t.TempDir()).
func fastTestConfig(t *testing.T, maxBytes uint64) Config {
	t.Helper()
	return Config{
		Dir:                 t.TempDir(),
		MaxBytes:            maxBytes,
		DrainWorkers:        2,
		MinBackoff:          5 * time.Millisecond,
		MaxBackoff:          20 * time.Millisecond,
		DrainAttemptTimeout: 2 * time.Second,
		Logger:              log.New(&testLogWriter{t: t}, "", 0),
	}
}

// testLogWriter routes this package's log.Logger output through
// t.Logf so `go test -v` output stays attributed to the right test
// and `go test -race` doesn't trip over concurrent direct stderr
// writes racing with test completion.
type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", string(p))
	return len(p), nil
}

// waitFor polls cond every 5ms until it returns true or timeout
// elapses, failing the test if it never does.
func waitFor(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Test 1: inner transport succeeds -> no enqueue, normal success path.
func TestBacklogTransport_InnerSucceeds_NoEnqueue(t *testing.T) {
	inner := newFakeTransport() // shareFailUntil defaults to 0: never fails.
	bt, err := New(inner, fastTestConfig(t, 1024*1024))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bt.Close()

	if err := bt.SubmitShare(context.Background(), testShare("s1")); err != nil {
		t.Fatalf("SubmitShare: %v", err)
	}
	if got := inner.ShareCalls(); got != 1 {
		t.Fatalf("inner.ShareCalls() = %d, want 1", got)
	}

	bt.stateMu.Lock()
	depth := bt.depthByKind[kindShare]
	bt.stateMu.Unlock()
	if depth != 0 {
		t.Fatalf("depthByKind[share] = %d, want 0 -- a successful inner call must never enqueue anything", depth)
	}

	if got := testutilCounterVecTotal(t, bt.metrics.EnqueuedTotal, "share"); got != 0 {
		t.Fatalf("EnqueuedTotal[share] = %v, want 0", got)
	}
}

// Test 2: inner transport fails -> item is queued, SubmitShare/
// SubmitBlock returns nil, distinct log/metric fires.
func TestBacklogTransport_InnerFails_EnqueuesAndReturnsNil(t *testing.T) {
	inner := newFakeTransport()
	inner.shareFailUntil = -1 // fail forever
	inner.blockFailUntil = -1
	bt, err := New(inner, fastTestConfig(t, 1024*1024))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bt.Close()

	if err := bt.SubmitShare(context.Background(), testShare("s1")); err != nil {
		t.Fatalf("SubmitShare returned a real error, want nil (durably queued instead): %v", err)
	}
	if err := bt.SubmitBlock(context.Background(), testBlock("h1")); err != nil {
		t.Fatalf("SubmitBlock returned a real error, want nil (durably queued instead): %v", err)
	}

	if got := testutilCounterVecTotal(t, bt.metrics.EnqueuedTotal, "share"); got != 1 {
		t.Fatalf("EnqueuedTotal[share] = %v, want 1", got)
	}
	if got := testutilCounterVecTotal(t, bt.metrics.EnqueuedTotal, "block"); got != 1 {
		t.Fatalf("EnqueuedTotal[block] = %v, want 1", got)
	}

	// The item must NOT have been dropped/counted as a full-drop --
	// this is the "durably queued", not "backend failure", path.
	if got := testutilCounterVecTotal(t, bt.metrics.FullDropsTotal, "share"); got != 0 {
		t.Fatalf("FullDropsTotal[share] = %v, want 0", got)
	}
}

// Test 3: backend recovers after N failures -> queued item is drained
// and acked automatically without any new incoming submit call
// needed (the background drain loop must run on its own).
func TestBacklogTransport_DrainsAutomaticallyOnceBackendRecovers(t *testing.T) {
	inner := newFakeTransport()
	inner.shareFailUntil = -1 // fail forever, for now.
	bt, err := New(inner, fastTestConfig(t, 1024*1024))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bt.Close()

	if err := bt.SubmitShare(context.Background(), testShare("s1")); err != nil {
		t.Fatalf("SubmitShare: %v", err)
	}

	// Let the drain loop genuinely observe a few failed retries first
	// -- proves the "keep retrying" behavior, not just a lucky single
	// attempt.
	waitFor(t, 2*time.Second, "at least 3 failed drain attempts", func() bool {
		return inner.ShareCalls() >= 3
	})

	// NOW let the backend start succeeding -- no new SubmitShare call
	// is made by this test from here on; the background drain loop
	// alone must pick this up and ack it.
	inner.setShareFailUntil(0)

	waitFor(t, 2*time.Second, "queued share drained/acked", func() bool {
		return testutilCounterVecTotal(t, bt.metrics.DrainedTotal, "share") == 1
	})

	bt.stateMu.Lock()
	depth := bt.depthByKind[kindShare]
	bytesUsed := bt.bytesUsed
	bt.stateMu.Unlock()
	if depth != 0 {
		t.Fatalf("depthByKind[share] = %d, want 0 after successful drain", depth)
	}
	if bytesUsed != 0 {
		t.Fatalf("bytesUsed = %d, want 0 after successful drain", bytesUsed)
	}
}

// Test 4: fill the backlog to MaxBytes with a permanently-failing
// inner transport, confirm further enqueues are rejected (return the
// real error) and the full-drop counter increments -- no silent
// eviction.
func TestBacklogTransport_CapacityExceeded_RejectsAndCountsFullDrop(t *testing.T) {
	inner := newFakeTransport()
	inner.shareFailUntil = -1 // fail forever -- nothing ever drains.

	// Compute one entry's real on-disk size so the test can size
	// MaxBytes to fit EXACTLY one entry, deterministically.
	probePayload, err := marshalForTest(testShare("size-probe"))
	if err != nil {
		t.Fatalf("marshal probe share: %v", err)
	}
	entrySize := uint64(envelopeHeaderLen + len(probePayload))

	bt, err := New(inner, fastTestConfig(t, entrySize))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bt.Close()

	// First enqueue must fit exactly at capacity.
	if err := bt.SubmitShare(context.Background(), testShare("size-probe")); err != nil {
		t.Fatalf("first SubmitShare (should exactly fit MaxBytes): %v", err)
	}
	if got := testutilCounterVecTotal(t, bt.metrics.EnqueuedTotal, "share"); got != 1 {
		t.Fatalf("EnqueuedTotal[share] = %v, want 1", got)
	}

	// Second enqueue must be rejected -- capacity is exhausted, and
	// the drain loop can never free it up (backend always fails).
	err = bt.SubmitShare(context.Background(), testShare("size-probe"))
	if err == nil {
		t.Fatalf("second SubmitShare succeeded (returned nil), want the original transport error -- backlog is at capacity and must reject, not silently evict")
	}
	if !errors.Is(err, inner.failErr) {
		t.Fatalf("second SubmitShare error = %v, want the ORIGINAL transport error unchanged", err)
	}

	if got := testutilCounterVecTotal(t, bt.metrics.FullDropsTotal, "share"); got != 1 {
		t.Fatalf("FullDropsTotal[share] = %v, want 1", got)
	}
	// Still only ONE entry durably queued -- the rejected second share
	// must not have been silently admitted by evicting the first.
	if got := testutilCounterVecTotal(t, bt.metrics.EnqueuedTotal, "share"); got != 1 {
		t.Fatalf("EnqueuedTotal[share] = %v, want still 1 (no eviction-then-admit)", got)
	}
}

// Test 5: restart durability. Enqueue several items with a failing
// inner transport, Close() the BacklogTransport, construct a NEW one
// against the SAME Config.Dir, confirm the previously-queued items are
// still there and get drained once the new instance's inner transport
// succeeds.
func TestBacklogTransport_RestartDurability(t *testing.T) {
	dir := t.TempDir() // Go's own per-test temp dir -- not a manual /tmp reference.

	failingInner := newFakeTransport()
	failingInner.shareFailUntil = -1
	failingInner.blockFailUntil = -1

	cfg := Config{
		Dir:                 dir,
		MaxBytes:            1024 * 1024,
		DrainWorkers:        2,
		MinBackoff:          5 * time.Millisecond,
		MaxBackoff:          20 * time.Millisecond,
		DrainAttemptTimeout: 2 * time.Second,
		Logger:              log.New(&testLogWriter{t: t}, "", 0),
	}

	bt1, err := New(failingInner, cfg)
	if err != nil {
		t.Fatalf("New (first instance): %v", err)
	}

	const numShares = 3
	for i := 0; i < numShares; i++ {
		if err := bt1.SubmitShare(context.Background(), testShare(fmt.Sprintf("restart-%d", i))); err != nil {
			t.Fatalf("SubmitShare %d: %v", i, err)
		}
	}
	if err := bt1.SubmitBlock(context.Background(), testBlock("restart-block")); err != nil {
		t.Fatalf("SubmitBlock: %v", err)
	}

	// Give the drain loop a moment to genuinely observe (and fail on)
	// these entries at least once before we close, proving this isn't
	// just testing "never-yet-read" entries.
	waitFor(t, 2*time.Second, "drain loop observed the queued entries at least once", func() bool {
		return failingInner.ShareCalls() >= 1 && failingInner.BlockCalls() >= 1
	})

	if err := bt1.Close(); err != nil {
		t.Fatalf("Close (first instance): %v", err)
	}
	if !failingInner.closed {
		t.Fatalf("Close on BacklogTransport must also Close() the inner transport")
	}

	// Construct a NEW BacklogTransport against the SAME Config.Dir,
	// with a NEW inner transport that succeeds this time.
	succeedingInner := newFakeTransport() // fails-until-0 == never fails.
	bt2, err := New(succeedingInner, Config{
		Dir:                 dir,
		MaxBytes:            1024 * 1024,
		DrainWorkers:        2,
		MinBackoff:          5 * time.Millisecond,
		MaxBackoff:          20 * time.Millisecond,
		DrainAttemptTimeout: 2 * time.Second,
		Logger:              log.New(&testLogWriter{t: t}, "", 0),
	})
	if err != nil {
		t.Fatalf("New (second instance, same Dir): %v", err)
	}
	defer bt2.Close()

	waitFor(t, 3*time.Second, "all pre-restart entries drained by the new instance", func() bool {
		return testutilCounterVecTotal(t, bt2.metrics.DrainedTotal, "share") == numShares &&
			testutilCounterVecTotal(t, bt2.metrics.DrainedTotal, "block") == 1
	})

	if got := succeedingInner.ShareCalls(); got < numShares {
		t.Fatalf("succeedingInner.ShareCalls() = %d, want >= %d -- the new instance never even attempted the pre-restart entries", got, numShares)
	}
	if got := succeedingInner.BlockCalls(); got < 1 {
		t.Fatalf("succeedingInner.BlockCalls() = %d, want >= 1", got)
	}
}

// Test 6: concurrent SubmitShare calls from multiple goroutines while
// the drain loop is running -- confirm no data race (go test -race)
// and no double-ack/lost item.
func TestBacklogTransport_ConcurrentSubmitShare_NoRaceNoLoss(t *testing.T) {
	inner := newFakeTransport() // never fails -- isolates this test to the enqueue/concurrency path itself, not drain timing.
	// Force every single SubmitShare through the backlog path by
	// making SubmitShare fail exactly once each (first attempt) then
	// succeed. Simpler/more deterministic: use a wrapper that always
	// fails on first call per key isn't easy with the shared fake, so
	// instead directly exercise enqueue() concurrency: many goroutines
	// call SubmitShare against an inner that fails forever, and the
	// drain loop (with a separate always-succeeding path after a
	// short delay) drains them -- proving both concurrent enqueue
	// safety AND concurrent drain safety together.
	inner.shareFailUntil = -1

	bt, err := New(inner, fastTestConfig(t, 64*1024*1024))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer bt.Close()

	const numGoroutines = 20
	const perGoroutine = 10
	var wg sync.WaitGroup
	var enqueueErrs atomic.Int64
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := fmt.Sprintf("race-%d-%d", g, i)
				if err := bt.SubmitShare(context.Background(), testShare(id)); err != nil {
					enqueueErrs.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()

	if got := enqueueErrs.Load(); got != 0 {
		t.Fatalf("%d SubmitShare calls returned a real error (want 0 -- backlog had ample capacity)", got)
	}

	wantTotal := float64(numGoroutines * perGoroutine)
	if got := testutilCounterVecTotal(t, bt.metrics.EnqueuedTotal, "share"); got != wantTotal {
		t.Fatalf("EnqueuedTotal[share] = %v, want %v (every concurrent enqueue must be counted exactly once)", got, wantTotal)
	}

	// Now let the backend start succeeding and confirm every single
	// one of those concurrently-enqueued entries drains -- no
	// double-ack (which would under-count bytesUsed/depth below zero,
	// already guarded defensively in release()) and no lost entry.
	inner.setShareFailUntil(0)
	waitFor(t, 5*time.Second, "all concurrently-enqueued shares drained", func() bool {
		return testutilCounterVecTotal(t, bt.metrics.DrainedTotal, "share") == wantTotal
	})

	bt.stateMu.Lock()
	depth := bt.depthByKind[kindShare]
	bytesUsed := bt.bytesUsed
	bt.stateMu.Unlock()
	if depth != 0 {
		t.Fatalf("depthByKind[share] = %d, want 0 after full drain", depth)
	}
	if bytesUsed != 0 {
		t.Fatalf("bytesUsed = %d, want 0 after full drain", bytesUsed)
	}
}

// marshalForTest lets TestBacklogTransport_CapacityExceeded... compute
// a real entry's exact on-disk size deterministically (header +
// marshaled payload), matching exactly what enqueue itself does.
func marshalForTest(share *poolpb.Share) ([]byte, error) {
	return proto.Marshal(share)
}
