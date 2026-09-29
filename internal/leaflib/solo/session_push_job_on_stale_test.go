// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// forceDistinctCachedJob mirrors direct package's identical
// directForceDistinctCachedJob test helper exactly (see that
// function's own doc comment for the full "why not InvalidateAll"
// rationale, equally true here: this package's own Server also
// unconditionally wires jobManager.Subscribe(func(_ string) {
// s.invalidateAndRepushJobs() }) in NewServer, so InvalidateAll would
// race THIS test's own pushFreshJobOnStaleSubmit push against that
// separate, pre-existing, unrelated repush mechanism exactly like it
// does in the direct package). RestampDifficulty touches only
// JobManager's own per-session cache entry, never notify/Subscribe.
//
// xn identifies WHICH live session to act on (see sessionByXN); the
// restamp itself is keyed by that session's OWN job-cache key
// (Session.JobKey), never by its xn -- see leaflib.NewJobCacheKey.
func forceDistinctCachedJob(t *testing.T, h *testHarness, xn string, newDifficulty uint64) *Job {
	t.Helper()
	sess := sessionByXN(t, h, xn)
	job, err := h.jm.RestampDifficulty(context.Background(), sess.JobKey(), newDifficulty)
	if err != nil {
		t.Fatalf("RestampDifficulty(session %s, %d): %v", sess.sessionID, newDifficulty, err)
	}
	job.CreatedAt = time.Now()
	return job
}

// TestPushFreshJobOnStaleOrUnknownJob covers pushFreshJobOnStaleSubmit's
// real RejectionReasonStaleOrUnknownJob call site
// (brief_push_job_on_stale.md) -- leaf-solo's own mirror of
// leaf-direct's identical fix and identical test (see that package's
// TestDirectPushFreshJobOnStaleOrUnknownJob for the full rationale on
// why forceDistinctCachedJob, not InvalidateAll, is used here).
func TestPushFreshJobOnStaleOrUnknownJob(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-push-stale-job")
	loginJobID := currentJobIDForSession(t, h.testHarness, xn)

	fresh := forceDistinctCachedJob(t, h.testHarness, xn, freshDiff)
	sessionByID(t, h.testHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}
	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonStaleOrUnknownJob)
	assertSharesRejectedTotal(t, h.metrics, 1)

	push := h.recvJobPush()
	if push.Method != "job" {
		t.Fatalf("push method = %q, want job", push.Method)
	}
	if push.Params.JobID != fresh.ID {
		t.Fatalf("push.Params.JobID = %q, want the freshly-restamped job's own id %q", push.Params.JobID, fresh.ID)
	}
	if push.Params.JobID != loginJobID {
		t.Fatalf("BUG: RestampDifficulty is documented to preserve job.ID -- push carried %q, login carried %q", push.Params.JobID, loginJobID)
	}
	wantTarget := leaflib.DiffToTargetHex(freshDiff)
	if push.Params.Target != wantTarget {
		t.Fatalf("BUG: fresh push after a stale/unknown submit did not carry the session's OWN current (post-retarget) difficulty -- push.Params.Target = %q, want %q", push.Params.Target, wantTarget)
	}

	// The pushed job must be genuinely recorded into this session's
	// own job history: a subsequent submit against ITS job_id, at
	// the session's own current difficulty, is accepted normally.
	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: push.Params.JobID, Nonce: xnPrefixedNonceHex(xn, 2),
	})})
	followUp := h.recvLegacyShareResponse()
	if !followUp.Result {
		t.Fatalf("expected the fresh pushed job to be legitimately submittable, got rejected: %#v", followUp)
	}
}

// TestPushFreshJobOnJobExpired covers pushFreshJobOnStaleSubmit's real
// RejectionReasonJobExpired call site -- leaf-solo's own mirror of
// leaf-direct's identical fix and identical test (see that package's
// TestDirectPushFreshJobOnJobExpired for the full rationale on the
// direct CreatedAt mutation used here instead of a real time.Sleep
// past a short JobMaxAge).
func TestPushFreshJobOnJobExpired(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	const jobMaxAge = time.Minute
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, jobMaxAge, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-push-job-expired")
	oldJobID := currentJobIDForSession(t, h.testHarness, xn)

	oldJob, ok := h.jm.GetJob(oldJobID)
	if !ok {
		t.Fatalf("GetJob(%q) after login: not found", oldJobID)
	}
	oldJob.CreatedAt = time.Now().Add(-time.Hour)

	fresh := forceDistinctCachedJob(t, h.testHarness, xn, freshDiff)
	sessionByID(t, h.testHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: oldJobID, Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}
	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonJobExpired)
	assertSharesRejectedTotal(t, h.metrics, 1)

	push := h.recvJobPush()
	if push.Method != "job" {
		t.Fatalf("push method = %q, want job", push.Method)
	}
	if push.Params.JobID != fresh.ID {
		t.Fatalf("push.Params.JobID = %q, want the freshly-restamped job's own id %q", push.Params.JobID, fresh.ID)
	}

	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: push.Params.JobID, Nonce: xnPrefixedNonceHex(xn, 2),
	})})
	followUp := h.recvLegacyShareResponse()
	if !followUp.Result {
		t.Fatalf("expected the fresh pushed job to be legitimately submittable, got rejected: %#v", followUp)
	}
}

// TestPushFreshJobOnDuplicateNonce covers pushFreshJobOnStaleSubmit's
// RejectionReasonDuplicateNonce call site
// (this reason was deliberately OUT of scope for the original
// push-on-stale fix and is now IN scope): the existing wire-visible rejection is unchanged, AND a
// fresh job push follows it, exactly as for stale_or_unknown_job.
func TestPushFreshJobOnDuplicateNonce(t *testing.T) {
	// loginDiff must be 1 so the FIRST (accepted) submit really clears
	// the real SHA3XValidator; freshDiff differs from it purely so the
	// pushed job is distinguishable from what login already delivered.
	const loginDiff, freshDiff = 1, 2
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-push-duplicate-nonce")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	nonce := xnPrefixedNonceHex(xn, 42)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	if first := h.recvLegacyShareResponse(); !first.Result {
		t.Fatalf("expected the first submission of a nonce to be accepted, got %#v", first)
	}

	// Give JobManager's per-xn cache a genuinely different shape than
	// what this session was already handed, so pushJob's own
	// alreadyDelivered dedup gate does not (correctly, but unhelpfully
	// for this test) suppress the push -- see
	// forceDistinctCachedJob's doc comment.
	fresh := forceDistinctCachedJob(t, h.testHarness, xn, freshDiff)
	sessionByID(t, h.testHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	second := h.recvLegacyShareResponse()
	if second.Result {
		t.Fatal("expected a replayed nonce to be rejected")
	}
	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonDuplicateNonce)
	assertSharesRejectedTotal(t, h.metrics, 1)

	push := h.recvJobPush()
	if push.Method != "job" {
		t.Fatalf("push method = %q, want job", push.Method)
	}
	if push.Params.JobID != fresh.ID {
		t.Fatalf("push.Params.JobID = %q, want the freshly-restamped job's own id %q", push.Params.JobID, fresh.ID)
	}
	if want := leaflib.DiffToTargetHex(freshDiff); push.Params.Target != want {
		t.Fatalf("push.Params.Target = %q, want %q (the session's OWN current difficulty)", push.Params.Target, want)
	}
}

// TestPushFreshJobOnDifficultyFloorMiss covers
// pushFreshJobOnStaleSubmit's RejectionReasonDifficultyFloorMiss call
// site: the real
// claimed-difficulty-vs-job's-StaticDifficulty floor check in
// handleSubmit's RandomX-family branch.
func TestPushFreshJobOnDifficultyFloorMiss(t *testing.T) {
	// staticDiff deliberately high -- largeResultHash's own claimed
	// difficulty is tiny (~1), so the floor check rejects it.
	const staticDiff, freshDiff = 1000, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, staticDiff, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress("rr-push-difficulty-floor-miss"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
	})})
	loginResp := h.recvLoginResponse()
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", loginResp.Result.Status)
	}
	sessionID := loginResp.Result.ID
	jobID := loginResp.Result.Job.JobID
	xn := sessionXN(t, h.testHarness, sessionID)

	fresh := forceDistinctCachedJob(t, h.testHarness, xn, freshDiff)
	sessionByID(t, h.testHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: "00000001", Result: hex.EncodeToString(largeResultHash(1)),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}
	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonDifficultyFloorMiss)
	assertSharesRejectedTotal(t, h.metrics, 1)

	push := h.recvJobPush()
	if push.Method != "job" {
		t.Fatalf("push method = %q, want job", push.Method)
	}
	if push.Params.JobID != fresh.ID {
		t.Fatalf("push.Params.JobID = %q, want the freshly-restamped job's own id %q", push.Params.JobID, fresh.ID)
	}
	if want := leaflib.DiffToTargetHex(freshDiff); push.Params.Target != want {
		t.Fatalf("push.Params.Target = %q, want %q (the session's OWN current difficulty)", push.Params.Target, want)
	}
}

// TestPushFreshJobDoesNotFireForUnrelatedRejection proves this fix is
// STILL scoped narrowly after this widening: exactly four
// rejection reasons push a fresh job (stale_or_unknown_job,
// job_expired, difficulty_floor_miss, duplicate_nonce -- each covered
// by its own test above), and every OTHER reason must not.
// invalid_xnonce stands in for that out-of-scope set here: it is a
// genuinely different failure (the miner submitted a nonce outside its
// own assigned extranonce space), nothing to do with a stale job.
//
// NOTE: this test previously used duplicate_nonce, which this fix
// has now deliberately moved INTO scope -- the assertion was updated
// rather than left behind as a stale, now-incorrect expectation. The
// forceDistinctCachedJob call below is what makes the "no push"
// assertion meaningful: without it, JobForSessionAtDifficulty would hand
// back the exact job already delivered at login and pushJob's own
// alreadyDelivered dedup gate would suppress the push regardless of
// whether the reason is in scope, so the test would pass vacuously.
func TestPushFreshJobDoesNotFireForUnrelatedRejection(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-push-not-unrelated")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	forceDistinctCachedJob(t, h.testHarness, xn, freshDiff)
	sessionByID(t, h.testHarness, sessionID).currentDifficulty.Store(freshDiff)

	badNonce := flipFirstHexNibble(xnPrefixedNonceHex(xn, 1))
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: badNonce,
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatal("expected a wrong-xn-prefixed nonce to be rejected")
	}
	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonInvalidXNonce)
	assertSharesRejectedTotal(t, h.metrics, 1)

	// The genuinely still-narrow scope of this fix: NO extra job push
	// for an out-of-scope rejection reason.
	expectNoJobPush(t, h.testHarness)
}
