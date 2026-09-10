// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// fakeDelayedShareValidator is a test double standing in for the
// real, ~258ms/hash pure-Go ShareValidator (validator.
// PureGoRandomXValidator): it sleeps for `delay` before returning,
// simulating that real cost so tests can deterministically assert
// dispatch/ordering behavior without paying it for real on every test
// run. Mirrors internal/leaflib/solo/session_async_randomx_test.go's
// identical fakeDelayedRandomXValidator fixture, adapted to this
// package's own ShareValidator interface shape
// (ValidateBlobSeedResult, not Validate).
type fakeDelayedShareValidator struct {
	delay  time.Duration
	accept bool
	err    error

	mu             sync.Mutex
	calls          int
	concurrent     int
	peakConcurrent int
}

func (v *fakeDelayedShareValidator) ValidateBlobSeedResult(_ context.Context, _, _ []byte, _ string) (bool, error) {
	v.mu.Lock()
	v.calls++
	v.concurrent++
	if v.concurrent > v.peakConcurrent {
		v.peakConcurrent = v.concurrent
	}
	v.mu.Unlock()

	if v.delay > 0 {
		time.Sleep(v.delay)
	}

	v.mu.Lock()
	v.concurrent--
	v.mu.Unlock()

	return v.accept, v.err
}

func (v *fakeDelayedShareValidator) snapshot() (calls, peakConcurrent int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls, v.peakConcurrent
}

// newAsyncHarness builds a harness wired to an explicit ShareValidator/
// UpstreamSubmitter pair (rather than newHarness' fixed *fakeValidator/
// *fakeUpstream), so these tests can substitute a fake validator that
// deterministically simulates the real production bottleneck (a slow,
// synchronous pure-Go RandomX re-validation call) -- mirrors
// internal/leaflib/solo/session_async_randomx_test.go's
// newRXTTestHarnessWithValidator exactly, adapted to this package's
// own Server/JobManager construction.
func newAsyncHarness(t *testing.T, validator ShareValidator, upstream UpstreamSubmitter, targetDiff uint64) *harness {
	t.Helper()
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        targetDiff,
		Difficulty:        1000,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, upstream, log.New(nil2Writer{}, "", 0), leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	h := &harness{t: t, server: server, source: source, cancel: cancel}
	t.Cleanup(func() {
		cancel()
		server.Shutdown()
	})
	return h
}

// TestSessionRandomXAsyncDispatch_DoesNotSerializeOnReadLoop is the
// primary regression test for Gap 2 (DISPATCH_BRIEF.md): many genuine
// upstream-forward-candidate submits on the SAME downstream session,
// each requiring a real re-validation call that simulates the real
// production bottleneck (fakeDelayedShareValidator with a real,
// non-trivial delay), must NOT take anywhere close to
// numShares*delay wall-clock time to all get responses -- that would
// mean the read loop is still serializing on each validation exactly
// like the pre-fix bug (session.go's handleSubmit calling
// ValidateBlobSeedResult synchronously, inline). Also asserts
// peakConcurrent > 1, direct proof genuine concurrent dispatch
// happened (not just that the code compiles) -- mirrors
// internal/leaflib/solo/session_async_randomx_test.go's
// TestSessionRandomXConcurrentSubmitsDoNotSerializeOnReadLoop exactly.
func TestSessionRandomXAsyncDispatch_DoesNotSerializeOnReadLoop(t *testing.T) {
	const numShares = 24
	const delay = 40 * time.Millisecond

	v := &fakeDelayedShareValidator{delay: delay, accept: true}
	up := &fakeUpstream{accept: true}
	h := newAsyncHarness(t, v, up, 1_000_000) // matches newHarness' default upstream target diff
	c, _ := h.connect()
	loginResp := c.login(t, "randomx-async-concurrency")
	jobID := loginResp.Result.Job.JobID

	// Comfortably above BOTH the session's own StaticDifficulty
	// (1000, connect()'s default starting difficulty) and the
	// upstream target (1,000,000 above) -- every one of these is a
	// genuine upstream-forward candidate, i.e. every one pays the
	// real re-validation cost this fix moves off the read loop.
	claimedHash := hashForDifficulty(2_000_000)

	start := time.Now()
	for i := 0; i < numShares; i++ {
		submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobID, Nonce: nonceHexAt(uint32(i) + 1), Result: claimedHash})
		if err != nil {
			t.Fatalf("marshal submit params: %v", err)
		}
		c.send(Request{ID: i + 100, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	}

	seen := make(map[int]bool, numShares)
	for i := 0; i < numShares; i++ {
		resp := c.recvShareResponse()
		if resp.ID < 100 || resp.ID >= 100+numShares {
			t.Fatalf("got response with unexpected id %d", resp.ID)
		}
		if seen[resp.ID] {
			t.Fatalf("duplicate response for id %d", resp.ID)
		}
		seen[resp.ID] = true
		if resp.Result == nil {
			t.Fatalf("submit id %d rejected: %v", resp.ID, resp.Error)
		}
	}
	elapsed := time.Since(start)

	// Fully sequential (the pre-fix bug) would take >= numShares*delay
	// = 24*40ms = 960ms. A bounded worker pool with
	// solo.DefaultAsyncValidationWorkers() (runtime.NumCPU(), NOT a
	// fixed literal -- see solo/asyncvalidation.go's doc comment)
	// workers should take roughly ceil(24/numCPU)*40ms, comfortably
	// under this bound on any real multi-core test runner. Assert
	// well under half the fully-serial bound -- generous enough to
	// avoid CI flakiness while still being a real, meaningful
	// regression guard against reintroducing full serialization.
	serialBound := time.Duration(numShares) * delay
	if elapsed >= serialBound/2 {
		t.Fatalf("elapsed %v is not meaningfully less than the fully-serial bound %v -- read loop may be blocking on each validation again (the exact bug this fix addresses)", elapsed, serialBound)
	}

	calls, peak := v.snapshot()
	if calls != numShares {
		t.Fatalf("validator saw %d calls, want %d", calls, numShares)
	}
	if peak <= 1 {
		t.Fatalf("peak concurrent validator calls = %d, want > 1 -- no genuine concurrent dispatch observed", peak)
	}
	if up.callCount() != numShares {
		t.Fatalf("expected every genuine upstream-forward candidate to still reach the upstream pool exactly once each, got %d calls for %d shares", up.callCount(), numShares)
	}
	t.Logf("numShares=%d delay=%v elapsed=%v serialBound=%v peakConcurrent=%d", numShares, delay, elapsed, serialBound, peak)
}

// TestSessionRandomXAsyncDispatch_ReadLoopProcessesSecondLineWhileFirstPending
// is verification-requirement (c) from DISPATCH_BRIEF.md, made
// literal: a slow RandomX validation on one proxy session's FIRST
// submit must not block that SAME session's read loop from reading
// and responding to a SECOND, already-queued line while the first
// submit's async validation is still pending. Submit 1 is a genuine
// upstream-forward candidate (pays the slow, 300ms fake validation
// cost); submit 2 is deliberately a local-credit-only share (below
// job.UpstreamShareDiff), which never calls the validator at all and
// so must get a fast response REGARDLESS of dispatch behavior -- the
// real assertion is that submit 2's response arrives well before
// submit 1's slow validation could possibly have completed, proving
// the read loop moved on to process line 2 instead of blocking on
// line 1's validation.
func TestSessionRandomXAsyncDispatch_ReadLoopProcessesSecondLineWhileFirstPending(t *testing.T) {
	const slowDelay = 300 * time.Millisecond

	v := &fakeDelayedShareValidator{delay: slowDelay, accept: true}
	up := &fakeUpstream{accept: true}
	h := newAsyncHarness(t, v, up, 1_000_000)
	c, _ := h.connect()
	loginResp := c.login(t, "randomx-read-loop-not-blocked")
	jobID := loginResp.Result.Job.JobID

	// Submit 1: a genuine upstream-forward candidate -- triggers the
	// slow (300ms) validator call, which this fix dispatches off the
	// read loop.
	claimedHash1 := hashForDifficulty(2_000_000)
	submit1, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobID, Nonce: nonceHexAt(1), Result: claimedHash1})
	if err != nil {
		t.Fatalf("marshal submit 1 params: %v", err)
	}
	c.send(Request{ID: 10, JsonRPC: "2.0", Method: "submit", Params: submit1})

	// Submit 2: sent immediately after, on the SAME connection/
	// session -- a share BELOW job.UpstreamShareDiff, credited
	// locally only, WITHOUT ever calling the validator (see
	// session.go's handleSubmit doc comment) -- if the read loop
	// were still blocked on submit 1's slow async validation (the
	// pre-fix bug: everything ran inline), this line could not even
	// be READ, let alone responded to, until AFTER slowDelay elapses.
	claimedHash2 := hashForDifficulty(50_000)
	submit2, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobID, Nonce: nonceHexAt(2), Result: claimedHash2})
	if err != nil {
		t.Fatalf("marshal submit 2 params: %v", err)
	}
	start := time.Now()
	c.send(Request{ID: 11, JsonRPC: "2.0", Method: "submit", Params: submit2})

	// The FIRST response to arrive on the wire must be submit 2's
	// (id=11) -- it never touches the validator and is written from
	// the read loop's own synchronous path almost immediately, well
	// before submit 1's response (id=10) can possibly be ready
	// (that one is still waiting on the slow validator call, running
	// on a separate async-pool worker goroutine).
	firstResp := c.recvShareResponse()
	elapsed := time.Since(start)

	if firstResp.ID != 11 {
		t.Fatalf("expected submit id=11 (fast, local-credit-only, never touches the validator) to be the FIRST response while submit id=10's slow async validation is still pending, but got id=%d first -- the read loop may be blocking on submit 1's validation again (the exact bug this fix addresses)", firstResp.ID)
	}
	if firstResp.Result == nil {
		t.Fatalf("expected submit id=11 to be accepted, got error=%v", firstResp.Error)
	}
	if elapsed >= slowDelay/2 {
		t.Fatalf("submit id=11's response took %v (>= half of submit id=10's %v validator delay) -- read loop appears blocked by submit id=10's slow async validation", elapsed, slowDelay)
	}

	// The second response to arrive must be submit 1's own (id=10),
	// completed asynchronously off the read loop, and by now the
	// real upstream forward (this leaf's OWN genuinely-different
	// post-validation behavior vs. solo/direct) must have already
	// happened for it too -- proving the forward call is correctly
	// sequenced strictly after validation completes, on the SAME
	// async-pool worker, never lost or reordered.
	secondResp := c.recvShareResponse()
	if secondResp.ID != 10 {
		t.Fatalf("expected submit id=10's response second, got id=%d", secondResp.ID)
	}
	if secondResp.Result == nil {
		t.Fatalf("expected submit id=10 (genuine upstream-forward candidate) to be accepted, got error=%v", secondResp.Error)
	}

	calls, _ := v.snapshot()
	if calls != 1 {
		t.Fatalf("expected exactly one real validator call (submit id=10 only -- submit id=11 must never call it), got %d", calls)
	}
	if up.callCount() != 1 {
		t.Fatalf("expected exactly one upstream forward call (submit id=10's own, completed asynchronously after its validation), got %d", up.callCount())
	}
	if up.lastJob != "upstream-job-1" {
		t.Errorf("expected the real upstream job_id to have been forwarded, got %q", up.lastJob)
	}

	sess := h.onlySession()
	if sess.blockCount.Load() != 1 {
		t.Errorf("expected local blockCount=1 for the genuine upstream-forward candidate, got %d", sess.blockCount.Load())
	}
	if sess.shareCount.Load() != 2 {
		t.Errorf("expected local shareCount=2 (both submits credited locally, one via the local-only path and one via the upstream-forward path), got %d", sess.shareCount.Load())
	}
}
