// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// directForceDistinctCachedJob mirrors the exact mechanism
// server.go's own invalidateAndRepushJobs regression test
// (TestDirectInvalidateAndRepushJobsStillPushesOnDifficultyChange)
// already uses to produce a genuinely distinguishable-from-
// lastDelivered cached Job for xn WITHOUT ever calling
// solo.JobManager.InvalidateAll: InvalidateAll's own notify()
// unconditionally fires Server's pre-existing, UNRELATED
// solo.JobManager.Subscribe(s.debouncedInvalidateAndRepushJobs)
// callback too (wired in NewServer whenever cfg.JobManager != nil),
// which would race this test's own explicit
// pushFreshJobOnStaleSubmit push with that separate, pre-existing
// repush mechanism non-deterministically -- confirmed live while
// developing this test (both orderings on the wire were observed
// across repeated runs). RestampDifficulty touches only
// solo.JobManager's own per-session cache entry, never
// notify/Subscribe, so it cannot trigger that unrelated path.
//
// xn identifies WHICH live session to act on (see directSessionByXN);
// the restamp itself is keyed by that session's OWN job-cache key
// (Session.JobKey), never by its xn -- see leaflib.NewJobCacheKey.
//
// RestampDifficulty (job.go) replaces that session's cached *Job with
// a NEW *Job value carrying the SAME job.ID but the new difficulty,
// while copying CreatedAt from whatever was cached before -- so for
// the job_expired variant of this fix (where the ORIGINAL job's
// CreatedAt must already be artificially old to trigger the
// rejection in the first place), this helper also resets the
// resulting cached Job's CreatedAt back to time.Now() afterward
// (mutating solo.Job.CreatedAt directly -- an exported field on an
// exported type, safe and intended for this kind of white-box test
// setup elsewhere in this repo too), so the fresh job this fix
// pushes is not ALSO immediately expired by the same JobMaxAge
// check the moment it is submitted back.
func directForceDistinctCachedJob(t *testing.T, h *directTestHarness, xn string, newDifficulty uint64) *solo.Job {
	t.Helper()
	sess := directSessionByXN(t, h, xn)
	job, err := h.jm.RestampDifficulty(context.Background(), sess.JobKey(), newDifficulty)
	if err != nil {
		t.Fatalf("RestampDifficulty(session %s, %d): %v", sess.sessionID, newDifficulty, err)
	}
	job.CreatedAt = time.Now()
	return job
}

// TestDirectPushFreshJobOnStaleOrUnknownJob covers
// pushFreshJobOnStaleSubmit's real RejectionReasonStaleOrUnknownJob
// call site (brief_push_job_on_stale.md): a submit against a job_id
// this session never owned must STILL get the existing wire-visible
// rejection response, but must ALSO get a genuine, separate, fresh
// "job" push right after -- one the session can legitimately submit
// against.
//
// directForceDistinctCachedJob (see its own doc comment) is used
// between login and the stale submit to give solo.JobManager's own
// per-session cache entry a genuinely different (StaticDifficulty, hence
// Target) shape than whatever this session's own lastDeliveredJobID/
// lastDeliveredDifficulty bookkeeping already recorded at login --
// otherwise JobForSessionAtDifficulty would simply hand back the exact
// same cached Job already delivered at login, and pushJob's own
// alreadyDelivered dedup gate would (correctly, but unhelpfully for
// this test) suppress the push entirely.
func TestDirectPushFreshJobOnStaleOrUnknownJob(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-push-stale-job"))
	loginJobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	fresh := directForceDistinctCachedJob(t, h.directTestHarness, xn, freshDiff)
	directSessionByID(t, h.directTestHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}
	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonStaleOrUnknownJob)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)

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
	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: push.Params.JobID, Nonce: directXNPrefixedNonceHex(xn, 2),
	})})
	followUp := h.recvLegacyShareResponse()
	if !followUp.Result {
		t.Fatalf("expected the fresh pushed job to be legitimately submittable, got rejected: %#v", followUp)
	}
}

// TestDirectPushFreshJobOnJobExpired covers
// pushFreshJobOnStaleSubmit's real RejectionReasonJobExpired call
// site -- same fix, the sibling detection path (a job that WAS this
// session's own, per ownJob, but whose JobMaxAge has elapsed).
//
// The submitted job's own CreatedAt is set directly (via
// solo.JobManager.GetJob, returning the live, shared *solo.Job this
// session's own ownJob will find too) to an hour in the past, rather
// than sleeping past a real, short JobMaxAge: this deterministically
// triggers the expiry check without any dependency on real elapsed
// wall-clock time or scheduling jitter, matching
// directForceDistinctCachedJob's own "no InvalidateAll" rationale
// (see that helper's doc comment) for why an artificial JobMaxAge
// this short cannot be combined with an actual time.Sleep here
// without also making the FOLLOW-UP submit against the freshly
// pushed job immediately re-fail the exact same expiry check (a
// bare RestampDifficulty alone copies the stale CreatedAt forward
// unchanged -- directForceDistinctCachedJob's own CreatedAt reset is
// what actually fixes that).
func TestDirectPushFreshJobOnJobExpired(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	const jobMaxAge = time.Minute
	h := newRejectionReasonHarnessWithJobMaxAge(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, jobMaxAge, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()})
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-push-job-expired"))
	oldJobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	oldJob, ok := h.jm.GetJob(oldJobID)
	if !ok {
		t.Fatalf("GetJob(%q) after login: not found", oldJobID)
	}
	oldJob.CreatedAt = time.Now().Add(-time.Hour)

	fresh := directForceDistinctCachedJob(t, h.directTestHarness, xn, freshDiff)
	directSessionByID(t, h.directTestHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: oldJobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}
	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonJobExpired)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)

	push := h.recvJobPush()
	if push.Method != "job" {
		t.Fatalf("push method = %q, want job", push.Method)
	}
	if push.Params.JobID != fresh.ID {
		t.Fatalf("push.Params.JobID = %q, want the freshly-restamped job's own id %q", push.Params.JobID, fresh.ID)
	}

	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: push.Params.JobID, Nonce: directXNPrefixedNonceHex(xn, 2),
	})})
	followUp := h.recvLegacyShareResponse()
	if !followUp.Result {
		t.Fatalf("expected the fresh pushed job to be legitimately submittable, got rejected: %#v", followUp)
	}
}

// TestDirectPushFreshJobOnDuplicateNonce covers
// pushFreshJobOnStaleSubmit's RejectionReasonDuplicateNonce call site
// (this reason was deliberately OUT of scope for the original
// push-on-stale fix and is now IN scope): the existing wire-visible rejection is unchanged, AND a
// fresh job push follows it, exactly as for stale_or_unknown_job.
func TestDirectPushFreshJobOnDuplicateNonce(t *testing.T) {
	// loginDiff must be 1 so the FIRST (accepted) submit really clears
	// the real SHA3XValidator; freshDiff differs from it purely so the
	// pushed job is distinguishable from what login already delivered.
	const loginDiff, freshDiff = 1, 2
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-push-duplicate-nonce"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	nonce := directXNPrefixedNonceHex(xn, 42)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	if first := h.recvLegacyShareResponse(); !first.Result {
		t.Fatalf("expected the first submission of a nonce to be accepted, got %#v", first)
	}
	waitForShareCount(t, h.transport, 1)

	// Give solo.JobManager's per-session cache a genuinely different shape
	// than what this session was already handed, so the
	// alreadyDelivered dedup gate does not (correctly, but unhelpfully
	// for this test) suppress the push -- see
	// directForceDistinctCachedJob's doc comment.
	fresh := directForceDistinctCachedJob(t, h.directTestHarness, xn, freshDiff)
	directSessionByID(t, h.directTestHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	second := h.recvLegacyShareResponse()
	if second.Result {
		t.Fatal("expected a replayed nonce to be rejected")
	}
	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonDuplicateNonce)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)

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

// TestDirectPushFreshJobOnDifficultyFloorMiss covers
// pushFreshJobOnStaleSubmit's RejectionReasonDifficultyFloorMiss call
// site -- the
// cheap pre-dispatch claimed-difficulty-vs-StaticDifficulty floor
// check in handleSubmit's RandomX-family branch, which is the
// reachable one of this leaf's two call sites for that reason (see
// TestDirectSessionRejectionReason_DifficultyFloorMiss's own doc
// comment on why the post-validate real-derived-difficulty floor check
// is structurally unreachable for RXT: both values are computed from
// the same submit.Result by the same formula, so they cannot diverge).
func TestDirectPushFreshJobOnDifficultyFloorMiss(t *testing.T) {
	// staticDiff deliberately high -- directLargeResultHash's own
	// claimed difficulty is tiny (~1), so the floor check rejects it.
	const staticDiff, freshDiff = 1000, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, staticDiff, 1<<62, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-push-difficulty-floor-miss"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	fresh := directForceDistinctCachedJob(t, h.directTestHarness, xn, freshDiff)
	directSessionByID(t, h.directTestHarness, sessionID).currentDifficulty.Store(freshDiff)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: classificationRXTNonceHex(1),
		Result: hex.EncodeToString(directLargeResultHash(1)),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}
	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonDifficultyFloorMiss)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)

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

// TestDirectPushFreshJobDoesNotFireForUnrelatedRejection proves this
// fix is STILL scoped narrowly after this widening: exactly four
// rejection reasons push a fresh job (stale_or_unknown_job,
// job_expired, difficulty_floor_miss, duplicate_nonce -- each covered
// by its own test above), and every OTHER reason must not.
// invalid_xnonce stands in for that out-of-scope set here: a nonce
// outside this session's own assigned extranonce space has nothing to
// do with a stale job.
//
// NOTE: this test previously used duplicate_nonce, which this fix
// has now deliberately moved INTO scope -- the assertion was updated
// rather than left behind as a stale, now-incorrect expectation. The
// directForceDistinctCachedJob call below is what makes the "no push"
// assertion meaningful: without it, the alreadyDelivered dedup gate
// would suppress the push regardless of whether the reason is in
// scope, and the test would pass vacuously.
func TestDirectPushFreshJobDoesNotFireForUnrelatedRejection(t *testing.T) {
	const loginDiff, freshDiff = 2, 1
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, loginDiff, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-push-not-unrelated"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	directForceDistinctCachedJob(t, h.directTestHarness, xn, freshDiff)
	directSessionByID(t, h.directTestHarness, sessionID).currentDifficulty.Store(freshDiff)

	badNonce := flipFirstHexNibble(directXNPrefixedNonceHex(xn, 1))
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: badNonce,
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatal("expected a wrong-xn-prefixed nonce to be rejected")
	}
	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonInvalidXNonce)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)

	// The genuinely still-narrow scope of this fix: NO extra job push
	// for an out-of-scope rejection reason.
	directExpectNoJobPush(t, h.directTestHarness)
}
