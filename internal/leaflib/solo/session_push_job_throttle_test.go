// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestPushFreshJobOnStaleSubmitThrottledDuringBurst is the direct
// regression test for this fix's own core requirement
// (fix/throttle-fresh-job-push-rxm): a burst of several stale-class
// submit rejections against the SAME session, arriving well within
// freshJobOnStaleSubmitMinInterval of each other (here, using the
// real wall clock -- the whole burst completes in microseconds, far
// under the 10s window, so no fake clock seam is even needed to prove
// this), must result in exactly ONE fresh-job push reaching the wire,
// not one per rejection.
func TestPushFreshJobOnStaleSubmitThrottledDuringBurst(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-push-throttle-burst")

	// Make the job pushFreshJobOnStaleSubmit would fetch genuinely
	// different from what login already delivered, so the FIRST call
	// in the burst is not itself swallowed by pushJob's own,
	// unrelated alreadyDelivered dedup gate (see that method's doc
	// comment) -- exactly like every other pushFreshJobOnStaleSubmit
	// test in this package.
	fresh := forceDistinctCachedJob(t, h.testHarness, xn, freshDiff)
	sessionByID(t, h.testHarness, sessionID).currentDifficulty.Store(freshDiff)

	// Three stale-class (unknown job_id) rejections in a tight loop
	// against the same session -- the exact "job-push storm" shape
	// this fix mitigates. The wire-level exchange is fully
	// synchronous per submit (Session.Run's own read-loop goroutine
	// writes both the reject AND -- for the first, un-throttled call
	// only -- the extra job push before it ever reads the next
	// line), so every message the server actually writes must be
	// drained in the order produced: only the FIRST iteration
	// produces a job push, so only it is read here inline, keeping
	// the underlying net.Pipe from blocking a later send behind an
	// unread write.
	const burstSize = 3
	for i := 0; i < burstSize; i++ {
		h.send(Request{ID: 2 + i, Method: "submit", Params: mustJSON(t, SubmitRequest{
			ID: sessionID, JobID: "0000000000000000", Nonce: xnPrefixedNonceHex(xn, uint64(i+1)),
		})})
		resp := h.recvLegacyShareResponse()
		if resp.Result {
			t.Fatalf("burst submit %d: expected rejection, got accepted: %#v", i, resp)
		}
		if i == 0 {
			// Exactly ONE push arrives, from this first
			// (un-throttled) call.
			push := h.recvJobPush()
			if push.Method != "job" {
				t.Fatalf("push method = %q, want job", push.Method)
			}
			if push.Params.JobID != fresh.ID {
				t.Fatalf("push.Params.JobID = %q, want the freshly-restamped job's own id %q", push.Params.JobID, fresh.ID)
			}
		}
	}

	// Every rejection in the burst is still counted individually --
	// the throttle only suppresses the SIDE EFFECT (the extra job
	// push), never the existing per-submit wire rejection or metrics
	// bookkeeping.
	if got := testutil.ToFloat64(h.metrics.ShareRejectionReasonTotal.WithLabelValues(metrics.RejectionReasonStaleOrUnknownJob)); got != float64(burstSize) {
		t.Errorf("reason=%s counter = %v, want %d", metrics.RejectionReasonStaleOrUnknownJob, got, burstSize)
	}
	assertSharesRejectedTotal(t, h.metrics, float64(burstSize))

	// Calls 2 and 3 of the burst must NOT have produced a second/
	// third push -- this is the actual throttle assertion.
	expectNoJobPush(t, h.testHarness)
}

// TestPushFreshJobOnStaleSubmitPushesAgainAfterWindowElapses proves
// the throttle is a genuine sliding window, not a permanent
// one-push-per-session latch: once
// freshJobOnStaleSubmitMinInterval has elapsed since the last actual
// push, the next stale-class rejection pushes again.
//
// Uses the pushFreshJobOnStaleSubmitNow test-only clock seam (see
// that field's own doc comment on Session, mirroring this package's
// own pre-existing noShareSweepNow/nowFunc convention) rather than a
// real time.Sleep(10*time.Second) -- this test completes in
// microseconds regardless of freshJobOnStaleSubmitMinInterval's real
// value.
//
// The fake clock itself is backed by an atomic.Int64 (unix nanos),
// not a plain mutated time.Time closure variable: pushFreshJobOnStaleSubmit
// runs on Session.Run's own read-loop goroutine, a different
// goroutine than this test, and only the WIRE responses this test
// reads back are actually synchronized with that goroutine's own
// writes -- the "throttled, no-op" call for the second submit below
// reads the clock AFTER its own reject write, so a plain unsynchronized
// read/write of a shared time.Time would be a genuine (if narrow in
// practice) data race under `go test -race`. Atomic Load/Store gives
// this real synchronization.
func TestPushFreshJobOnStaleSubmitPushesAgainAfterWindowElapses(t *testing.T) {
	const loginDiff, firstFreshDiff, secondFreshDiff = 2, 1, 3
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-push-throttle-window")
	sess := sessionByID(t, h.testHarness, sessionID)

	var fakeNowNanos atomic.Int64
	fakeNowNanos.Store(time.Now().UnixNano())
	sess.pushFreshJobOnStaleSubmitNow = func() time.Time { return time.Unix(0, fakeNowNanos.Load()) }

	firstFresh := forceDistinctCachedJob(t, h.testHarness, xn, firstFreshDiff)
	sess.currentDifficulty.Store(firstFreshDiff)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	if resp := h.recvLegacyShareResponse(); resp.Result {
		t.Fatalf("first submit: expected rejection, got accepted: %#v", resp)
	}
	firstPush := h.recvJobPush()
	if firstPush.Params.JobID != firstFresh.ID {
		t.Fatalf("first push.Params.JobID = %q, want %q", firstPush.Params.JobID, firstFresh.ID)
	}

	// Still inside the window (fake clock unchanged): a second
	// stale-class rejection must NOT push again.
	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: xnPrefixedNonceHex(xn, 2),
	})})
	if resp := h.recvLegacyShareResponse(); resp.Result {
		t.Fatalf("second submit (still inside window): expected rejection, got accepted: %#v", resp)
	}
	expectNoJobPush(t, h.testHarness)

	// Advance the fake clock PAST freshJobOnStaleSubmitMinInterval and
	// give the fetched job a genuinely different shape (freshDiff2)
	// so pushJob's own alreadyDelivered dedup gate does not (for an
	// unrelated reason) suppress this third push.
	fakeNowNanos.Add(int64(freshJobOnStaleSubmitMinInterval + time.Second))
	secondFresh := forceDistinctCachedJob(t, h.testHarness, xn, secondFreshDiff)
	sess.currentDifficulty.Store(secondFreshDiff)

	h.send(Request{ID: 4, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: xnPrefixedNonceHex(xn, 3),
	})})
	if resp := h.recvLegacyShareResponse(); resp.Result {
		t.Fatalf("third submit (after window elapses): expected rejection, got accepted: %#v", resp)
	}
	secondPush := h.recvJobPush()
	if secondPush.Params.JobID != secondFresh.ID {
		t.Fatalf("second push.Params.JobID = %q, want %q", secondPush.Params.JobID, secondFresh.ID)
	}
}
