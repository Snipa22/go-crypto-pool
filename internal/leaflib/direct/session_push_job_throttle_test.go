// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestDirectPushFreshJobOnStaleSubmitThrottledDuringBurst mirrors
// solo package's own TestPushFreshJobOnStaleSubmitThrottledDuringBurst
// exactly (see that test's doc comment for the full rationale) --
// this leaf has its OWN separate pushFreshJobOnStaleSubmit
// implementation (dispatched onto s.server.jobFetchPool rather than
// solo's inline JobForXNAtDifficulty call), so it needs its own copy
// of this throttle regression test too.
//
// UNLIKE solo, this leaf's fresh-job push happens on a SEPARATE
// jobFetchPool worker goroutine, not synchronously inline in
// handleSubmit -- so this test explicitly drains the first (and only
// expected) push with recvJobPush's own blocking, deadline-bounded
// read BEFORE sending the next burst submit, rather than assuming a
// fixed message count/order across the whole burst up front. That
// keeps the burst's later submits (which the throttle guarantees
// dispatch NO async push at all) from racing an still-in-flight
// worker write from an earlier call.
func TestDirectPushFreshJobOnStaleSubmitThrottledDuringBurst(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-push-throttle-burst"))

	fresh := directForceDistinctCachedJob(t, h.directTestHarness, xn, freshDiff)
	directSessionByID(t, h.directTestHarness, sessionID).currentDifficulty.Store(freshDiff)

	const burstSize = 3
	for i := 0; i < burstSize; i++ {
		h.send(solo.Request{ID: 2 + i, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			ID: sessionID, JobID: "0000000000000000", Nonce: directXNPrefixedNonceHex(xn, uint64(i+1)),
		})})
		resp := h.recvLegacyShareResponse()
		if resp.Result {
			t.Fatalf("burst submit %d: expected rejection, got accepted: %#v", i, resp)
		}
		if i == 0 {
			// Exactly ONE push arrives, from this first
			// (un-throttled) call -- drained here, before the next
			// burst submit is even sent, so it can never race a
			// LATER submit's own reject write.
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
	if got := testutil.ToFloat64(h.metrics.ShareRejectionReasonTotal.WithLabelValues(directmetrics.RejectionReasonStaleOrUnknownJob)); got != float64(burstSize) {
		t.Errorf("reason=%s counter = %v, want %d", directmetrics.RejectionReasonStaleOrUnknownJob, got, burstSize)
	}
	assertDirectSharesRejectedTotal(t, h.metrics, float64(burstSize))

	// Calls 2 and 3 of the burst must NOT have produced a second/
	// third push -- this is the actual throttle assertion. Since
	// pushFreshJobOnStaleSubmit's throttle check/update now happens
	// BEFORE ever touching s.server.jobFetchPool (see that method's
	// own doc comment), calls 2 and 3 never even enqueue a job onto
	// the pool, so there is no delayed/in-flight write to race here.
	directExpectNoJobPush(t, h.directTestHarness)
}

// TestDirectPushFreshJobOnStaleSubmitPushesAgainAfterWindowElapses
// mirrors solo package's own identical test exactly -- see that
// test's doc comment for the full rationale, including why the
// pushFreshJobOnStaleSubmitNow test-only clock seam (mirroring
// solo.Session's own identical field) is used instead of a real
// time.Sleep(10*time.Second), and why the fake clock itself is
// backed by an atomic.Int64 (unix nanos) rather than a plain mutated
// time.Time closure variable (a genuine `go test -race` data race
// otherwise: pushFreshJobOnStaleSubmit's throttle check reads the
// clock on Session.Run's own read-loop goroutine, a different
// goroutine than this test, and only this test's own wire-response
// reads are actually synchronized with that goroutine's writes --
// not every field it touches along the way).
func TestDirectPushFreshJobOnStaleSubmitPushesAgainAfterWindowElapses(t *testing.T) {
	const loginDiff, firstFreshDiff, secondFreshDiff = 2, 1, 3
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-push-throttle-window"))
	sess := directSessionByID(t, h.directTestHarness, sessionID)

	var fakeNowNanos atomic.Int64
	fakeNowNanos.Store(time.Now().UnixNano())
	sess.pushFreshJobOnStaleSubmitNow = func() time.Time { return time.Unix(0, fakeNowNanos.Load()) }

	firstFresh := directForceDistinctCachedJob(t, h.directTestHarness, xn, firstFreshDiff)
	sess.currentDifficulty.Store(firstFreshDiff)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	if resp := h.recvLegacyShareResponse(); resp.Result {
		t.Fatalf("first submit: expected rejection, got accepted: %#v", resp)
	}
	firstPush := h.recvJobPush()
	if firstPush.Params.JobID != firstFresh.ID {
		t.Fatalf("first push.Params.JobID = %q, want %q", firstPush.Params.JobID, firstFresh.ID)
	}

	// Still inside the window (fake clock unchanged): a second
	// stale-class rejection must NOT push again -- and, since the
	// throttle check happens before ever touching jobFetchPool, must
	// not even dispatch anything, so there is nothing async left
	// in-flight for expectNoJobPush to race against.
	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: directXNPrefixedNonceHex(xn, 2),
	})})
	if resp := h.recvLegacyShareResponse(); resp.Result {
		t.Fatalf("second submit (still inside window): expected rejection, got accepted: %#v", resp)
	}
	directExpectNoJobPush(t, h.directTestHarness)

	// Advance the fake clock PAST freshJobOnStaleSubmitMinInterval and
	// give the fetched job a genuinely different shape (secondFreshDiff)
	// so the alreadyDelivered dedup gate does not (for an unrelated
	// reason) suppress this third push.
	fakeNowNanos.Add(int64(freshJobOnStaleSubmitMinInterval + time.Second))
	secondFresh := directForceDistinctCachedJob(t, h.directTestHarness, xn, secondFreshDiff)
	sess.currentDifficulty.Store(secondFreshDiff)

	h.send(solo.Request{ID: 4, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: directXNPrefixedNonceHex(xn, 3),
	})})
	if resp := h.recvLegacyShareResponse(); resp.Result {
		t.Fatalf("third submit (after window elapses): expected rejection, got accepted: %#v", resp)
	}
	secondPush := h.recvJobPush()
	if secondPush.Params.JobID != secondFresh.ID {
		t.Fatalf("second push.Params.JobID = %q, want %q", secondPush.Params.JobID, secondFresh.ID)
	}
}
