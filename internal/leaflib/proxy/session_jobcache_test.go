// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// This file covers the THIRD report of leaf-proxy's job-staleness bug
// class: JobManager.NextJob had NO caching at all, so every single
// call site (handleLogin, handleGetJob, maybeRetarget,
// Server.repushAllSessions) minted a brand-new random job_id and
// burned a fresh slot in the session's bounded 8-entry job history
// EVEN WHEN the upstream template and requested difficulty were both
// completely unchanged. Confirmed live in production: a job accepted
// normally, then an immediate burst of 8 rejects against that SAME
// job_id in the same millisecond, only ~1.5s after a genuine new
// upstream job event -- far more evictions than the actual upstream
// job cadence (~5-15s) could explain. See Session.currentJob's own
// doc comment (session.go) for the exact caching rule being tested
// here, ported from XNP's own getJob() (lib/xmr.js) and this repo's
// own already-correct solo.JobManager.jobForXN/JobForXNAtDifficulty
// (internal/leaflib/solo/job.go).

// TestSession_CurrentJob_CacheHitOnRepeatedGetJob_ThenInvalidatesOnRealTemplateChange
// is the core caching regression test (required test 1 from the
// brief). It drives the REAL wire handleGetJob path (via the existing
// test harness) so this is genuine end-to-end coverage of the actual
// production entry point, not just a direct call to currentJob.
func TestSession_CurrentJob_CacheHitOnRepeatedGetJob_ThenInvalidatesOnRealTemplateChange(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()

	loginResp := c.login(t, "addr-jobcache-1")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	historyLen := func() int {
		sess.jobsMu.Lock()
		defer sess.jobsMu.Unlock()
		return len(sess.jobList)
	}

	// Baseline: login itself already goes through currentJob and
	// caches a job -- capture the history length right after login,
	// BEFORE issuing the two redundant getjob calls under test.
	beforeGetJob := historyLen()

	// Two EXPLICIT getjob requests in a row, real wire path, with the
	// upstream template and difficulty both completely unchanged
	// between calls (the harness's fakeTemplateSource is not touched
	// at all here).
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "getjob"})
	firstPush := c.recvJobPush()

	c.send(Request{ID: 3, JsonRPC: "2.0", Method: "getjob"})
	secondPush := c.recvJobPush()

	if firstPush.Params.JobID == "" || secondPush.Params.JobID == "" {
		t.Fatal("expected non-empty job_ids from both getjob calls")
	}
	// THE CORE ASSERTION: both calls return the IDENTICAL job_id --
	// proving the cache hit, no new job minted on the second,
	// redundant call.
	if firstPush.Params.JobID != secondPush.Params.JobID {
		t.Fatalf("expected both redundant getjob calls to return the SAME job_id (cache hit), got %q then %q", firstPush.Params.JobID, secondPush.Params.JobID)
	}
	// Since nothing changed since login either, the cache hit should
	// also match what login itself was already handed.
	if firstPush.Params.JobID != loginResp.Result.Job.JobID {
		t.Fatalf("expected the cached job returned by getjob to match login's own job_id (nothing changed since login), got getjob=%q login=%q", firstPush.Params.JobID, loginResp.Result.Job.JobID)
	}

	afterGetJob := historyLen()
	// THE SECOND ASSERTION: the session's own job history gained NO
	// MORE THAN one new entry total across BOTH redundant getjob
	// calls (in practice here, exactly zero, since both calls hit
	// the cache and returned the identical, already-recorded job) --
	// proving no wasted slot was burned by either call, let alone by
	// the second, most-clearly-redundant one. Before this fix, two
	// calls would have burned TWO fresh slots (one per call).
	gained := afterGetJob - beforeGetJob
	if gained > 1 {
		t.Fatalf("expected the job history to gain AT MOST one new entry across both redundant getjob calls, gained %d (before=%d, after=%d) -- a wasted slot was burned", gained, beforeGetJob, afterGetJob)
	}

	// Now genuinely change the upstream template (a real job_id
	// change, mirroring the existing setTemplate pattern already
	// used elsewhere in this package's tests) -- this fires
	// Server.repushAllSessions synchronously (jobs.Subscribe), which
	// itself now goes through sess.currentJob too, so the resulting
	// unsolicited push already proves the THIRD required assertion:
	// the cache correctly invalidates on a real upstream change
	// rather than "never updating again". net.Pipe's write is
	// unbuffered/synchronous, so the read must already be pending
	// before setTemplate is called (mirrors
	// TestServer_RepushAllSessions_PushesFreshJobOnGenuineUpstreamUpdate's
	// identical pattern) -- otherwise the repush's write blocks
	// forever waiting for a reader that hasn't started yet.
	newTmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            999,
		JobID:             "upstream-job-genuinely-new",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
	}
	pushCh := make(chan JobPush, 1)
	go func() { pushCh <- c.recvJobPush() }()

	h.source.setTemplate(newTmpl)

	var thirdPush JobPush
	select {
	case thirdPush = <-pushCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for repushAllSessions to push a fresh job after a real upstream template update")
	}
	if thirdPush.Params.JobID == "" {
		t.Fatal("expected a non-empty job_id from the post-template-change repush")
	}
	if thirdPush.Params.JobID == secondPush.Params.JobID {
		t.Fatal("expected a GENUINELY DIFFERENT job_id after a real upstream template change, but the cache returned the stale job_id")
	}

	// A subsequent explicit getjob, template/difficulty still
	// unchanged since the repush above, must now hit the cache
	// against the just-repushed job.
	c.send(Request{ID: 4, JsonRPC: "2.0", Method: "getjob"})
	fourthPush := c.recvJobPush()
	if fourthPush.Params.JobID != thirdPush.Params.JobID {
		t.Fatalf("expected the getjob immediately after the repush to hit the cache and return the same job_id %q, got %q", thirdPush.Params.JobID, fourthPush.Params.JobID)
	}
}

// TestSession_CurrentJob_DifficultyChangeMintsGenuinelyDistinctJob is
// required test 2 from the brief: with the upstream template held
// constant, currentJob called with two DIFFERENT difficulty values
// must produce two genuinely distinct jobs -- mirroring solo's
// RestampDifficulty StaticDifficulty-changed behavior. Caching must
// not accidentally suppress a legitimate difficulty-driven repush
// (e.g. a real vardiff retarget).
func TestSession_CurrentJob_DifficultyChangeMintsGenuinelyDistinctJob(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	c.login(t, "addr-jobcache-diff")

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	// First call at difficulty 1000 (the harness's default starting
	// difficulty, matching what login already cached) should hit the
	// existing cache.
	jobA, err := sess.currentJob(1000)
	if err != nil {
		t.Fatalf("currentJob(1000): %v", err)
	}

	// A genuinely different requested difficulty, template
	// unchanged, must mint a genuinely fresh job -- caching keyed
	// only on UpstreamJobID would incorrectly suppress this.
	jobB, err := sess.currentJob(2000)
	if err != nil {
		t.Fatalf("currentJob(2000): %v", err)
	}
	if jobA.ID == jobB.ID {
		t.Fatalf("expected a genuinely different difficulty to mint a genuinely distinct job, got the same job_id %q for both difficulty 1000 and 2000", jobA.ID)
	}
	if jobB.StaticDifficulty != 2000 {
		t.Fatalf("expected jobB.StaticDifficulty = 2000, got %d", jobB.StaticDifficulty)
	}

	// Calling again at the SAME (new) difficulty 2000, template still
	// unchanged, must now hit the cache against jobB.
	jobC, err := sess.currentJob(2000)
	if err != nil {
		t.Fatalf("currentJob(2000) again: %v", err)
	}
	if jobC.ID != jobB.ID {
		t.Fatalf("expected a repeated call at the same (new) difficulty to hit the cache and return jobB's id %q, got %q", jobB.ID, jobC.ID)
	}

	// And reverting back to difficulty 1000 (template still
	// unchanged) must mint fresh again -- the cache holds only the
	// SINGLE most recently issued job, not a per-difficulty history.
	jobD, err := sess.currentJob(1000)
	if err != nil {
		t.Fatalf("currentJob(1000) again: %v", err)
	}
	if jobD.ID == jobC.ID {
		t.Fatalf("expected reverting to a different difficulty (1000) to mint a fresh job distinct from the cached difficulty-2000 job %q", jobC.ID)
	}
}

// TestSession_CurrentJob_EmptyUpstreamJobIDNeverCaches is required
// test 3 from the brief: some pool dialects never publish job_id at
// all (UpstreamJobPayload.JobID's own omitempty tag; see also
// upstream.go's applyJob upstream-dupe guard, which has the identical
// empty-job_id-can-never-dedupe rule this test's expected behavior is
// deliberately kept consistent with). In that case an empty id can
// never distinguish "same template" from "genuinely different
// template", so caching must be UNSAFE and currentJob must mint a
// genuinely fresh job on EVERY call, even with nothing else changed
// between calls -- this is the one case where "mint fresh every time"
// remains CORRECT, not a bug, and this test confirms that explicitly.
func TestSession_CurrentJob_EmptyUpstreamJobIDNeverCaches(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()

	// Replace the harness's default template (which has a non-empty
	// JobID) with one carrying an EMPTY JobID, mirroring a pool
	// dialect that omits it entirely, BEFORE logging in so login
	// itself observes the empty-job_id template too.
	emptyIDTmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "", // deliberately empty: some pool dialects omit job_id entirely
		TargetDiff:        1_000_000,
		Difficulty:        1000,
	}
	h.source.setTemplate(emptyIDTmpl)

	c.login(t, "addr-empty-jobid")
	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	// Two consecutive calls with nothing else changed (same
	// template, same difficulty) must STILL each independently mint
	// a genuinely fresh, distinct job -- "no dedup possible" is the
	// correct, safe behavior here, not a caching bug.
	jobA, err := sess.currentJob(1000)
	if err != nil {
		t.Fatalf("currentJob (A): %v", err)
	}
	jobB, err := sess.currentJob(1000)
	if err != nil {
		t.Fatalf("currentJob (B): %v", err)
	}
	if jobA.ID == jobB.ID {
		t.Fatalf("expected an empty upstream job_id to NEVER cache (each call must mint independently), but got the same job_id %q twice", jobA.ID)
	}
	if jobA.UpstreamJobID != "" || jobB.UpstreamJobID != "" {
		t.Fatalf("expected both jobs to carry through the empty UpstreamJobID unchanged, got %q and %q", jobA.UpstreamJobID, jobB.UpstreamJobID)
	}

	// Also confirm the session's own cachedJob field never latches
	// onto a stable value in this case -- each currentJob call
	// leaves s.cachedJob pointing at whatever was JUST minted (the
	// unsafe-to-cache short-circuit in currentJob returns straight
	// from NextJob without ever consulting/updating s.cachedJob), so
	// a THIRD call must mint yet another distinct job too.
	jobC, err := sess.currentJob(1000)
	if err != nil {
		t.Fatalf("currentJob (C): %v", err)
	}
	if jobC.ID == jobB.ID || jobC.ID == jobA.ID {
		t.Fatalf("expected a third call to also mint independently, got a repeated job_id %q", jobC.ID)
	}
}

// TestSession_CurrentJob_ReusingCachedJobDoesNotCorruptJobLogOrLastDelivered
// verifies (required "double-check" item from the brief) that
// reusing the SAME cached *Job across multiple jobPayload/pushJob
// calls to the SAME session does not corrupt Session.recordJob's
// existing exists-check or lastDeliveredJobID/alreadyDelivered
// bookkeeping from the prior PR -- re-recording/re-storing the
// identical values must be idempotent.
func TestSession_CurrentJob_ReusingCachedJobDoesNotCorruptJobLogOrLastDelivered(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "addr-idempotent")
	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	job, err := sess.currentJob(sess.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("currentJob: %v", err)
	}
	if job.ID != loginResp.Result.Job.JobID {
		t.Fatalf("expected currentJob to return the same cached job login already delivered, got %q vs login's %q", job.ID, loginResp.Result.Job.JobID)
	}

	// Deliver the SAME cached job again via jobPayload multiple
	// times, exactly as pushJob/repushAllSessions would if called
	// redundantly.
	_ = sess.jobPayload(job)
	_ = sess.jobPayload(job)
	_ = sess.jobPayload(job)

	// jobLog/jobList: the job must be present exactly once, not
	// duplicated.
	sess.jobsMu.Lock()
	count := 0
	for _, id := range sess.jobList {
		if id == job.ID {
			count++
		}
	}
	_, inLog := sess.jobLog[job.ID]
	sess.jobsMu.Unlock()
	if count != 1 {
		t.Fatalf("expected job.ID to appear exactly once in jobList after repeated re-delivery, appeared %d times", count)
	}
	if !inLog {
		t.Fatal("expected job.ID to still be present in jobLog after repeated re-delivery")
	}

	// lastDeliveredJobID/lastDeliveredDifficulty: still exactly this
	// job, and alreadyDelivered must report true for it.
	lastID, _ := sess.lastDeliveredJobID.Load().(string)
	if lastID != job.ID {
		t.Fatalf("expected lastDeliveredJobID = %q after repeated re-delivery, got %q", job.ID, lastID)
	}
	if !sess.alreadyDelivered(job) {
		t.Fatal("expected alreadyDelivered(job) to be true after repeated re-delivery of the same cached job")
	}

	// ownJob (the real submit-time security lookup) must still find
	// it, unaffected by the repeated re-delivery.
	if _, ok := sess.ownJob(job.ID); !ok {
		t.Fatal("expected ownJob to still find the repeatedly-re-delivered job")
	}
}
