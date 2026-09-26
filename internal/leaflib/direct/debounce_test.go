// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// debounceFakeNode is a minimal solo.NodeClient test double, local to
// this test file, giving these debounce tests direct, independent
// control over both the two knobs isBetterCandidate cares about --
// height (via GetBlockTemplate/GetTipInfo) and serialized template
// size (via TemplateBytesForRelay, read back into
// JobManager.templateSizeForRelay) -- without needing a real Tari
// node or any real proto content. Deliberately simpler than
// session_test.go's fakeDirectNodeClient (that one exists to drive
// real handleSubmit/candidate-block flows this package's debounce
// logic never touches).
type debounceFakeNode struct {
	mu     sync.Mutex
	height uint64
	size   int

	templateCalls atomic.Int64
}

func (f *debounceFakeNode) setHeight(h uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.height = h
}

func (f *debounceFakeNode) setSize(sz int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.size = sz
}

func (f *debounceFakeNode) GetBlockTemplate(_ context.Context, _ string, algo poolpb.Algo) (*solo.Job, error) {
	f.mu.Lock()
	h := f.height
	f.mu.Unlock()
	n := f.templateCalls.Add(1)
	return &solo.Job{
		ID:     fmt.Sprintf("debounce-fake-job-%d", n),
		Height: h,
		Algo:   algo,
	}, nil
}

func (f *debounceFakeNode) GetTipInfo(_ context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.height, nil
}

func (f *debounceFakeNode) BuildCandidateBlock(_ *solo.Job, _ uint64, _ solo.SubmitProof) (uint64, any, error) {
	return 0, nil, nil
}

func (f *debounceFakeNode) SubmitBlock(_ context.Context, _ any) error {
	return nil
}

// TemplateBytesForRelay returns a byte slice of exactly the
// currently-configured f.size length, regardless of job -- this test
// double's whole reason for existing is to let tests dictate a
// candidate's real-serialized-size directly, rather than deriving it
// from real proto content.
func (f *debounceFakeNode) TemplateBytesForRelay(_ *solo.Job) ([]byte, error) {
	f.mu.Lock()
	sz := f.size
	f.mu.Unlock()
	return make([]byte, sz), nil
}

func (f *debounceFakeNode) JobFromTemplateBytes(_ []byte, _ poolpb.Algo) (*solo.Job, error) {
	return nil, fmt.Errorf("debounceFakeNode: JobFromTemplateBytes not supported by this minimal test double")
}

var _ solo.NodeClient = (*debounceFakeNode)(nil)

// newDebounceTestServer builds a real solo.JobManager and a real
// direct.Server wired to it exactly like NewServer's own constructor
// does (JobManager.Subscribe(s.debouncedInvalidateAndRepushJobs)),
// with metrics enabled so tests can count real
// invalidateAndRepushJobs invocations via the
// leaf_direct_template_distribution_seconds histogram's real sample
// count (recordTemplateDistribution is called exactly once per real
// invalidateAndRepushJobs call, regardless of source label or how
// many/few sessions are connected) -- this is the "count a side
// effect invalidateAndRepushJobs already has" approach BRIEF.md's
// test-1 doc comment allows, rather than adding a bespoke spy hook.
func newDebounceTestServer(t *testing.T) (*solo.JobManager, *Server, *debounceFakeNode) {
	t.Helper()
	node := &debounceFakeNode{height: 1, size: 10}
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:          node,
		PayoutAddress: "debounce-test-address",
		Algo:          poolpb.Algo_ALGO_SHA3X,
		// Long refresh/poll intervals: these tests drive
		// InvalidateAll/JobForXN directly rather than relying on
		// Start's background loops, except for the one test
		// (TestDebounceRelayPublishUnaffectedByServerDebounceState)
		// that explicitly needs tipPollLoop's real timing.
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 24 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm,
		JobManager:        jm,
		Node:              node,
		Network:           poolpb.Network_NETWORK_TESTNET,
		Algo:              poolpb.Algo_ALGO_SHA3X,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            1,
	})
	server.EnableMetrics("debounce-test", 0)

	t.Cleanup(func() {
		server.Shutdown()
		cancel()
	})
	return jm, server, node
}

// repushCount returns the real, cumulative number of times
// invalidateAndRepushJobs has actually run against server, read via
// its own recordTemplateDistribution side effect (see
// newDebounceTestServer's doc comment): the real Prometheus histogram
// SAMPLE COUNT (_count) of leaf_direct_template_distribution_seconds
// -- NOT testutil.CollectAndCount, which counts the number of
// distinct time series (one per "source" label value) rather than
// the number of Observe calls -- summed across BOTH the "local" and
// "relay" source labels, since a single test may combine
// notifications from either source.
func repushCount(server *Server) int {
	total := 0
	for _, source := range []string{"local", "relay"} {
		obs := server.metrics.TemplateDistributionDuration.WithLabelValues(source)
		collector, ok := obs.(prometheus.Metric)
		if !ok {
			continue
		}
		var m dto.Metric
		if err := collector.Write(&m); err != nil {
			continue
		}
		if m.Histogram != nil && m.Histogram.SampleCount != nil {
			total += int(*m.Histogram.SampleCount)
		}
	}
	return total
}

// seedBest performs one real fetch (via a fresh, never-before-seen
// xn, so JobForXN can't just return a cache hit) at height/size,
// installing it as jm's own tracked best (solo.JobManager.CurrentBest)
// -- the same real bookkeeping jobForXN already performs in
// production on every fetch (job.go's jobForXN: "size := ...; if
// !best.set || isBetterCandidate(...) { jm.setBest(...) }").
func seedBest(t *testing.T, jm *solo.JobManager, node *debounceFakeNode, xn string, height uint64, size int) {
	t.Helper()
	node.setHeight(height)
	node.setSize(size)
	if _, err := jm.JobForXN(context.Background(), xn); err != nil {
		t.Fatalf("seedBest: JobForXN(%s): %v", xn, err)
	}
}

// TestDebounceTwoSameHeightFiringsWithinWindowYieldOneRepush is
// BRIEF.md test 1: two Subscribe callback firings at the same height
// within the 20s window must result in exactly ONE actual
// invalidateAndRepushJobs call.
func TestDebounceTwoSameHeightFiringsWithinWindowYieldOneRepush(t *testing.T) {
	jm, server, node := newDebounceTestServer(t)

	seedBest(t, jm, node, "xn-1", 5, 100)

	// First notification at height 5: this is the very first repush
	// ever (lastRepushSet is still false) -- always immediate,
	// regardless of debounce.
	jm.InvalidateAll(solo.TemplateSourceLocal)
	if got := repushCount(server); got != 1 {
		t.Fatalf("after first same-height notification: repush count = %d, want 1", got)
	}

	// Second notification at the SAME height, firing immediately
	// afterward (well within the 20s window) -- must be buffered, not
	// repushed again yet.
	jm.InvalidateAll(solo.TemplateSourceLocal)
	if got := repushCount(server); got != 1 {
		t.Fatalf("after second same-height notification (within debounce window): repush count = %d, want still 1 (buffered, not repushed again)", got)
	}

	server.repushMu.Lock()
	pending := server.pendingRepush
	hasTimer := server.pendingRepushTimer != nil
	server.repushMu.Unlock()
	if !pending || !hasTimer {
		t.Fatalf("expected a pending, timer-armed buffered repush after the second same-height notification (pending=%v hasTimer=%v)", pending, hasTimer)
	}
}

// TestDebounceSameHeightAfterWindowElapsedRepushesImmediately is
// BRIEF.md test 2: a same-height notification arriving AFTER the
// debounce window has already elapsed since the last repush triggers
// an immediate repush (no buffering wait).
func TestDebounceSameHeightAfterWindowElapsedRepushesImmediately(t *testing.T) {
	jm, server, node := newDebounceTestServer(t)

	seedBest(t, jm, node, "xn-1", 7, 100)

	jm.InvalidateAll(solo.TemplateSourceLocal)
	if got := repushCount(server); got != 1 {
		t.Fatalf("after first notification: repush count = %d, want 1", got)
	}

	// Simulate the debounce window having already fully elapsed
	// since that first repush -- white-box (same package) rather than
	// actually sleeping equalHeightRepushDebounce (20s) in a test.
	server.repushMu.Lock()
	server.lastRepushAt = time.Now().Add(-(equalHeightRepushDebounce + time.Second))
	server.repushMu.Unlock()

	jm.InvalidateAll(solo.TemplateSourceLocal)
	if got := repushCount(server); got != 2 {
		t.Fatalf("after same-height notification once the debounce window had elapsed: repush count = %d, want 2 (immediate, no buffering wait)", got)
	}

	server.repushMu.Lock()
	pending := server.pendingRepush
	server.repushMu.Unlock()
	if pending {
		t.Fatal("expected no pending buffered repush after an immediate post-window repush")
	}
}

// TestDebounceHeightIncreaseAppliesImmediatelyAndDiscardsPending is
// BRIEF.md test 3: a notification at a strictly HIGHER height than
// the last repush applies immediately regardless of how recently the
// last repush happened, and discards/cancels any same-height pending
// timer that was buffered at the OLD height (asserted here by
// confirming it doesn't fire a stale extra repush afterward).
func TestDebounceHeightIncreaseAppliesImmediatelyAndDiscardsPending(t *testing.T) {
	jm, server, node := newDebounceTestServer(t)

	seedBest(t, jm, node, "xn-1", 10, 100)
	jm.InvalidateAll(solo.TemplateSourceLocal) // first ever: immediate
	if got := repushCount(server); got != 1 {
		t.Fatalf("after first notification: repush count = %d, want 1", got)
	}

	// A second, same-height notification immediately afterward: gets
	// buffered (well within the debounce window) at the OLD height
	// (10).
	jm.InvalidateAll(solo.TemplateSourceLocal)
	server.repushMu.Lock()
	pendingBefore := server.pendingRepush
	timerBefore := server.pendingRepushTimer
	server.repushMu.Unlock()
	if !pendingBefore || timerBefore == nil {
		t.Fatal("expected a pending, timer-armed buffered repush at the old height before the height increase")
	}

	// Now a genuine height increase: seed a strictly higher height
	// and notify.
	seedBest(t, jm, node, "xn-2", 11, 100)
	jm.InvalidateAll(solo.TemplateSourceLocal)

	if got := repushCount(server); got != 2 {
		t.Fatalf("after height-increase notification: repush count = %d, want 2 (applied immediately)", got)
	}

	server.repushMu.Lock()
	pendingAfter := server.pendingRepush
	timerAfter := server.pendingRepushTimer
	lastHeight := server.lastRepushHeight
	server.repushMu.Unlock()
	if pendingAfter || timerAfter != nil {
		t.Fatalf("expected the old same-height pending/timer state to be discarded by the height increase (pending=%v timer!=nil=%v)", pendingAfter, timerAfter != nil)
	}
	if lastHeight != 11 {
		t.Fatalf("lastRepushHeight = %d, want 11", lastHeight)
	}

	// Give the (already-cancelled) old timer every chance to
	// misbehave, then confirm no stale extra repush fired.
	time.Sleep(150 * time.Millisecond)
	if got := repushCount(server); got != 2 {
		t.Fatalf("after waiting past where the stale old-height timer would have fired: repush count = %d, want still 2 (no stale extra repush)", got)
	}
}

// TestDebounceSoloJobManagerStateUnaffectedByServerBuffering is
// BRIEF.md test 4: solo.JobManager's OWN behavior (per-xn cache
// content, CurrentBest tracking) is completely unaffected by
// Server's debounce -- the underlying JobManager state updates
// immediately on every genuinely better candidate regardless of
// whether Server has chosen to defer the miner-visible repush yet.
// This is the test that proves the scope correction was actually
// honored (solo untouched behaviorally).
func TestDebounceSoloJobManagerStateUnaffectedByServerBuffering(t *testing.T) {
	jm, server, node := newDebounceTestServer(t)

	seedBest(t, jm, node, "xn-1", 20, 100)
	jm.InvalidateAll(solo.TemplateSourceLocal) // first ever: immediate repush
	if got := repushCount(server); got != 1 {
		t.Fatalf("after first notification: repush count = %d, want 1", got)
	}

	// A same-height, strictly LARGER candidate: solo.JobManager's own
	// isBetterCandidate/setBest must adopt this as the new tracked
	// best immediately and unconditionally -- regardless of the fact
	// that the resulting notification below will be buffered
	// server-side (well within the debounce window).
	seedBest(t, jm, node, "xn-2", 20, 200)
	if height, size, ok := jm.CurrentBest(); !ok || height != 20 || size != 200 {
		t.Fatalf("solo.JobManager.CurrentBest() = (height=%d size=%d ok=%v), want (20, 200, true) -- JobManager's own best-tracking must update immediately on the better candidate, independent of any Server-side repush timing", height, size, ok)
	}

	jm.InvalidateAll(solo.TemplateSourceLocal)
	// Server-side: this must be buffered (same height as last actual
	// repush, within the window) -- the repush count must NOT have
	// advanced yet, even though JobManager's own state already has.
	if got := repushCount(server); got != 1 {
		t.Fatalf("repush count = %d, want still 1 (buffered server-side) even though JobManager's own tracked best already advanced", got)
	}
	if height, size, ok := jm.CurrentBest(); !ok || height != 20 || size != 200 {
		t.Fatalf("solo.JobManager.CurrentBest() after the buffered notification = (height=%d size=%d ok=%v), want (20, 200, true) unchanged by Server's own buffering decision", height, size, ok)
	}

	// The per-xn cache itself: InvalidateAll always wipes it
	// immediately and unconditionally (job.go's own, pre-existing
	// behavior, untouched by this feature) -- a fresh xn request
	// right now must generate a brand-new Job reflecting the CURRENT
	// node height/state, not something withheld pending Server's own
	// repush decision.
	job, err := jm.JobForXN(context.Background(), "xn-3")
	if err != nil {
		t.Fatalf("JobForXN(xn-3) after buffered notification: %v", err)
	}
	if job.Height != 20 {
		t.Fatalf("JobForXN(xn-3).Height = %d, want 20 (JobManager's per-xn cache/generation is unaffected by Server's own buffering)", job.Height)
	}
}

// startEmbeddedNATSServerForDebounceTest mirrors
// internal/leaflib/relay/relay_test.go's own startEmbeddedNATSServer
// exactly (a REAL, in-process, embedded NATS server bound to an
// OS-assigned free port) -- duplicated here rather than imported
// since that helper is unexported/package-private to relay's own test
// package (the exact same pattern cmd/leaf-direct/relay_wiring_test.go
// and internal/leaflib/solo/job_relay_test.go already each duplicate
// for their own package's tests).
func startEmbeddedNATSServerForDebounceTest(t *testing.T) (url string, shutdown func()) {
	t.Helper()
	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1,
		NoLog:          true,
		NoSigs:         true,
		MaxControlLine: 4096,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("starting embedded NATS server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("embedded NATS server did not become ready within 5s")
	}
	t.Cleanup(func() {
		srv.Shutdown()
		srv.WaitForShutdown()
	})
	return srv.ClientURL(), srv.Shutdown
}

// TestDebounceRelayPublishUnaffectedByServerDebounceState is
// BRIEF.md test 5: solo.JobManager's relay-publish path (tipPollLoop's
// publishTemplateForJob call) still fires immediately/unconditionally
// on a genuine local tip increase, completely independent of whatever
// Server-side debounce state exists -- i.e. broadcast timing is
// provably untouched by this change.
//
// This deliberately puts Server into an ACTIVE, timer-armed buffered
// same-height repush state (a real "debounce in progress" condition)
// immediately before triggering a genuine local tip increase via
// jm.Start's real tipPollLoop, then proves the relay publish for the
// new height is received by an independent external subscriber
// promptly (well under equalHeightRepushDebounce) -- proving the
// broadcast never waited on, or was gated by, Server's own debounce
// state at all.
func TestDebounceRelayPublishUnaffectedByServerDebounceState(t *testing.T) {
	url, shutdown := startEmbeddedNATSServerForDebounceTest(t)
	defer shutdown()

	templateRelay := relay.NewRelay(relay.Config{URL: url})
	defer templateRelay.Close()
	if !templateRelay.Enabled() {
		t.Fatalf("expected templateRelay to be Enabled() after connecting to a real NATS server at %s", url)
	}

	node := &debounceFakeNode{height: 100, size: 10}
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:            node,
		PayoutAddress:   "debounce-relay-test-address",
		Algo:            poolpb.Algo_ALGO_SHA3X,
		Network:         "testnet",
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 20 * time.Millisecond,
		Relay:           templateRelay,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	server := NewServer(ServerConfig{
		ConnectionManager: cm,
		JobManager:        jm,
		Node:              node,
		Network:           poolpb.Network_NETWORK_TESTNET,
		Algo:              poolpb.Algo_ALGO_SHA3X,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            1,
	})
	server.EnableMetrics("debounce-relay-test", 0)
	defer server.Shutdown()

	// Seed a real best + first-ever repush at height 100, then
	// immediately buffer a second same-height notification -- Server
	// now has an ACTIVE, timer-armed pending repush (won't fire for
	// ~20s) at height 100.
	seedBest(t, jm, node, "xn-seed", 100, 10)
	jm.InvalidateAll(solo.TemplateSourceLocal)
	if got := repushCount(server); got != 1 {
		t.Fatalf("after seed notification: repush count = %d, want 1", got)
	}
	jm.InvalidateAll(solo.TemplateSourceLocal)
	server.repushMu.Lock()
	pending := server.pendingRepush
	server.repushMu.Unlock()
	if !pending {
		t.Fatal("expected an active buffered/pending repush at height 100 before triggering the tip increase")
	}

	// Subscribe an independent external observer to the template
	// relay -- this is a genuinely different *relay.Relay connection,
	// proving the publish is real, end-to-end NATS traffic, not just
	// an in-process callback.
	received := make(chan relay.TemplateMessage, 8)
	observerRelay := relay.NewRelay(relay.Config{URL: url})
	defer observerRelay.Close()
	unsub, err := observerRelay.SubscribeTemplate(func(msg relay.TemplateMessage) {
		received <- msg
	})
	if err != nil {
		t.Fatalf("observerRelay.SubscribeTemplate: %v", err)
	}
	defer unsub()
	time.Sleep(100 * time.Millisecond) // let the real NATS subscription land

	jm.Start(ctx)
	time.Sleep(100 * time.Millisecond) // let tipPollLoop seed its height-100 baseline before we move the tip

	// Genuine local tip increase -- must be published immediately by
	// tipPollLoop, regardless of Server's own active buffered-repush
	// state at height 100.
	node.setHeight(101)

	select {
	case msg := <-received:
		if msg.Height != 101 {
			t.Fatalf("received TemplateMessage.Height = %d, want 101", msg.Height)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the tip-increase TemplateMessage publish -- relay broadcast must fire promptly, independent of Server's own debounce state")
	}

	// The height increase must also have applied the real
	// miner-visible repush immediately server-side (discarding the
	// old height-100 buffered timer) -- confirms both halves of this
	// feature's scope (broadcast unconditional; adoption-side
	// debounce still correct) hold together in one real end-to-end
	// flow.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if repushCount(server) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := repushCount(server); got < 2 {
		t.Fatalf("repush count after tip increase = %d, want >= 2 (height increase must repush immediately)", got)
	}
}
