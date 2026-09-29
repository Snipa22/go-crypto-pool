// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- DECISIVE REGRESSION COVERAGE for the job-cache re-keying fix:
// JobManager must cache the Job it serves a session under that
// SESSION'S OWN identity (Session.jobKey / leaflib.NewJobCacheKey),
// never under the session's 2-byte extranonce (Session.xn). ---
//
// ROOT CAUSE THESE TESTS PIN DOWN (maintainer-confirmed): jobForSession
// (formerly jobForXN) does its cache lookup BEFORE minting any fresh
// per-session job, and that lookup used to be keyed by xn. xn is a
// 2-byte draw -- 65,536 possible values -- so two genuinely UNRELATED
// sessions drawing the same xn is an ordinary birthday-paradox event,
// not a pathological one (this repo's own
// internal/leaflib/direct/server_repush_stale_sessions_test.go used to
// carry a determinism workaround precisely because "500 random draws
// produced 2 real collisions in one run"). When it happened, the
// SECOND session to ask for a job was handed the FIRST session's exact
// same *Job object by reference: same job.ID, same header/template
// bytes, and -- the real damage -- the same usedNonces map
// (Job.MarkNonceUsed). The intended design has always been "one
// shared block template -> each miner gets a NEW job stamped with its
// own ID".
//
// REAL-WORLD IMPACT (the second test below reproduces it end to end):
// for the RandomX-family algos, session.go's handleSubmit deliberately
// SKIPS the xn nonce-prefix check entirely (a RandomX miner controls
// the whole nonce field, so the pool imposes no prefix convention on
// it). An xn collision there therefore meant two independent miners
// hashing an IDENTICAL template with ZERO pool-imposed nonce
// separation, so the second miner's genuinely valid, never-before-seen
// share was rejected as a "duplicate nonce" the moment it happened to
// pick a raw nonce the first miner had already used.
//
// TEST SEAM: newSessionXN (job.go) is already a package-level func-var
// for exactly this kind of substitution. collideSessionXN below pins
// it to ONE constant value, so every session created for the lifetime
// of the calling test collides by construction -- no reliance on
// actually winning the birthday lottery during a test run.
//
// xn's own wire-protocol role is asserted to be UNCHANGED by the
// pre-existing TestSessionSubmitWithWrongXNPrefixIsRejectedBeforeValidation
// / TestSessionSHA3XSubmitWithoutXNPrefixIsRejected /
// TestSessionC29SubmitWithoutXNPrefixIsRejected tests, which are
// untouched by this fix.

// collidedXN is the single, fixed xn value collideSessionXN hands to
// every session in a test. Its VALUE is arbitrary; all that matters is
// that it is the same one every time, i.e. a guaranteed collision.
const collidedXN = "beef"

// collideSessionXN forces every session created for the lifetime of
// the calling test onto the SAME xn (collidedXN), restoring the real
// leaflib.NewSessionXN implementation on cleanup. This is the
// deliberate inverse of xn_relogin_test.go's stubDeterministicSessionXN
// (which forces every draw to be DISTINCT to avoid flakes); here the
// collision IS the scenario under test.
func collideSessionXN(t *testing.T) {
	t.Helper()
	orig := newSessionXN
	newSessionXN = func() (string, error) { return collidedXN, nil }
	t.Cleanup(func() { newSessionXN = orig })
}

// twoSessionHarness is one real Server (one JobManager, one
// fakeNodeClient) with TWO independent miner connections attached to
// it -- the shape every test in this file needs and that no
// pre-existing harness in this package provides (they all wire exactly
// one net.Pipe per Server).
type twoSessionHarness struct {
	server *Server
	jm     *JobManager
	node   *fakeNodeClient
	a      *testHarness
	b      *testHarness
}

// newTwoSessionHarness builds one Server for algo and attaches two
// separate connections to it. Both sessions go through the real
// Server.handleConn/newSession path (no synthetic session
// construction), so both draw their xn through the real newSessionXN
// func-var -- which collideSessionXN has pinned to a single value.
func newTwoSessionHarness(t *testing.T, algo poolpb.Algo, staticDiff, networkTargetDiff uint64, registry validator.Registry) *twoSessionHarness {
	t.Helper()
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: networkTargetDiff,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
		vmKey:            []byte("test key 000"),
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
		Algo:             algo,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	newConn := func() *testHarness {
		serverConn, clientConn := net.Pipe()
		go server.handleConn(ctx, serverConn, staticDiff)
		t.Cleanup(func() { _ = clientConn.Close() })
		return &testHarness{
			t: t, server: server, cm: cm, jm: jm, node: node,
			client: clientConn,
			reader: bufio.NewReader(clientConn),
			writer: bufio.NewWriter(clientConn),
			cancel: cancel,
		}
	}

	h := &twoSessionHarness{server: server, jm: jm, node: node}
	h.a = newConn()
	h.b = newConn()
	t.Cleanup(func() {
		cancel()
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
	})
	return h
}

// loginOn performs one real wire login on h and returns the
// LoginResponse -- a per-connection variant of session_test.go's own
// login helper (which is hard-wired to one harness and also resolves
// the session's xn, which is deliberately NOT interesting here: this
// file's whole point is that two sessions share one xn).
//
// login is the LITERAL wire login field, not a label: handleLogin runs
// real, coin-aware address validation (address.go's
// ValidateAddressForAlgo), so a Tari-shaped address would be rejected
// outright on an ALGO_RXM harness and vice versa. Callers pass
// realTariTestAddress(...) for SHA3X/C29/RXT and realXMRMainnetAddr
// for RXM.
func loginOn(t *testing.T, h *testHarness, id int, login, worker, wireAlgo string) LoginResponse {
	t.Helper()
	h.send(Request{ID: id, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: login, Pass: worker, Agent: "XMRig/6.21.0", Algo: []string{wireAlgo},
	})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login on this connection failed: status=%q", resp.Result.Status)
	}
	return resp
}

// TestTwoSessionsWithCollidingXNGetDistinctJobs is THE decisive
// regression test for this fix, and the one that would have caught the
// original bug: two genuinely unrelated sessions, deliberately forced
// onto the SAME xn, must each be minted their OWN job.
//
// Against the old xn-keyed cache this fails on every assertion that
// matters: session B's login is a cache HIT on session A's entry, so B
// receives A's job_id verbatim, A's *Job pointer, and only ONE real
// GetBlockTemplate call is ever made for the two of them.
func TestTwoSessionsWithCollidingXNGetDistinctJobs(t *testing.T) {
	collideSessionXN(t)
	h := newTwoSessionHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()})

	respA := loginOn(t, h.a, 1, realTariTestAddress("jobkey-collide-a"), "rigA", "sha3x")
	respB := loginOn(t, h.b, 1, realTariTestAddress("jobkey-collide-b"), "rigB", "sha3x")

	sessA := sessionByID(t, h.a, respA.Result.ID)
	sessB := sessionByID(t, h.b, respB.Result.ID)

	// Precondition: the collision genuinely happened. Without this the
	// rest of the test proves nothing.
	if sessA.XN() != sessB.XN() {
		t.Fatalf("setup failure: the two sessions did NOT collide on xn (%q vs %q) -- collideSessionXN must pin both to the same value for this test to mean anything", sessA.XN(), sessB.XN())
	}
	if sessA.sessionID == sessB.sessionID {
		t.Fatalf("setup failure: expected two genuinely distinct sessions, both have sessionID %q", sessA.sessionID)
	}

	// The fix itself: identical xn, but genuinely distinct job-cache
	// keys.
	if sessA.JobKey() == sessB.JobKey() {
		t.Fatalf("BUG: two sessions sharing xn %q were also given the SAME job-cache key %q -- the cache key must be per-session (leaflib.NewJobCacheKey), not per-xn", sessA.XN(), sessA.JobKey())
	}

	// ... and therefore genuinely distinct jobs, on the wire.
	if respA.Result.Job.JobID == respB.Result.Job.JobID {
		t.Fatalf("BUG: two unrelated sessions that drew the same xn %q were served the SAME wire job_id %q -- the second session must be minted its OWN job (this is exactly the xn-collision bug this fix closes)", sessA.XN(), respA.Result.Job.JobID)
	}

	// ... and genuinely distinct *Job VALUES, not one shared object.
	// This is the assertion that speaks to the real damage: a shared
	// *Job means a shared nonceMu/usedNonces set.
	jobA, err := h.jm.JobForSessionAtDifficulty(context.Background(), sessA.JobKey(), sessA.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty(session A): %v", err)
	}
	jobB, err := h.jm.JobForSessionAtDifficulty(context.Background(), sessB.JobKey(), sessB.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty(session B): %v", err)
	}
	if jobA == jobB {
		t.Fatal("BUG: the two colliding-xn sessions resolve to the SAME *Job pointer -- they would share one usedNonces map, which is precisely what produced the spurious duplicate_nonce rejections")
	}
	if jobA.ID != respA.Result.Job.JobID {
		t.Errorf("session A's cached job id %q != the job_id it was actually sent on the wire %q", jobA.ID, respA.Result.Job.JobID)
	}
	if jobB.ID != respB.Result.Job.JobID {
		t.Errorf("session B's cached job id %q != the job_id it was actually sent on the wire %q", jobB.ID, respB.Result.Job.JobID)
	}

	// Two sessions, two real cache entries, two real template fetches
	// (SHA3X is NOT a shared-template algo -- see
	// usesSharedTemplate's doc comment -- so each session's own
	// cache miss is its own genuine GetBlockTemplate call). A count of
	// 1 here is the tell-tale of an xn-keyed cache collapsing both
	// sessions onto one entry.
	if got := h.node.templateCalls.Load(); got != 2 {
		t.Fatalf("GetBlockTemplate call count = %d, want 2 (one genuine template per session, even though both drew the same xn)", got)
	}
	h.jm.mu.RLock()
	cached := len(h.jm.perSession)
	h.jm.mu.RUnlock()
	if cached != 2 {
		t.Fatalf("len(jm.perSession) = %d, want 2 -- two colliding-xn sessions must occupy two SEPARATE cache entries", cached)
	}
}

// TestTwoSessionsWithCollidingXNDoNotFalselyRejectDuplicateNonce is the
// end-to-end reproduction of the real-world damage, run against
// ALGO_RXT.
//
// WHY RXT: handleSubmit skips the xn nonce-prefix check entirely for
// the RandomX family (IsRandomXFamily -- a RandomX miner owns the full
// nonce field), so two sessions CAN legitimately put the byte-identical
// nonce string on the wire. For SHA3X/C29 the xn prefix check would
// incidentally mask the problem at the wire level, which is exactly why
// the brief calls out ALGO_RXM/RandomX-family as where this bug
// actually bites. It is the same reason
// TestSessionRXTReloginPreventsFalseDuplicateNonce (xn_relogin_test.go)
// uses RXT for its own structurally-identical proof.
//
// Against the old xn-keyed cache, session B's submit below is rejected:
// B is handed A's *Job, whose usedNonces map already contains this
// nonce from A's accepted share. Post-fix both are accepted, because
// each session owns its own job and therefore its own nonce space.
func TestTwoSessionsWithCollidingXNDoNotFalselyRejectDuplicateNonce(t *testing.T) {
	collideSessionXN(t)
	h := newTwoSessionHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}})

	respA := loginOn(t, h.a, 1, realTariTestAddress("jobkey-collide-nonce-a"), "rigA", "rx/0")
	respB := loginOn(t, h.b, 1, realTariTestAddress("jobkey-collide-nonce-b"), "rigB", "rx/0")

	sessA := sessionByID(t, h.a, respA.Result.ID)
	sessB := sessionByID(t, h.b, respB.Result.ID)
	if sessA.XN() != sessB.XN() {
		t.Fatalf("setup failure: the two sessions did NOT collide on xn (%q vs %q)", sessA.XN(), sessB.XN())
	}
	if respA.Result.Job.JobID == respB.Result.Job.JobID {
		t.Fatalf("BUG: both colliding-xn sessions were served job_id %q -- see TestTwoSessionsWithCollidingXNGetDistinctJobs", respA.Result.Job.JobID)
	}

	// The SAME raw nonce, submitted by two genuinely different miners
	// against their own respective jobs. Both are first-ever uses
	// FROM THEIR OWN SESSION'S point of view, so both must be
	// accepted.
	const sharedNonce = "00000001"
	claimHex := hex.EncodeToString(largeResultHash(1))

	h.a.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: respA.Result.ID, JobID: respA.Result.Job.JobID, Nonce: sharedNonce, Result: claimHex,
	})})
	if got := h.a.recvShareResponse(); got.Result == nil {
		t.Fatalf("expected session A's submit of nonce %s to be ACCEPTED, got rejected: %#v", sharedNonce, got)
	}

	h.b.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: respB.Result.ID, JobID: respB.Result.Job.JobID, Nonce: sharedNonce, Result: claimHex,
	})})
	got := h.b.recvShareResponse()
	if got.Result == nil {
		msg := ""
		if got.Error != nil {
			msg = got.Error.Message
		}
		t.Fatalf("BUG: session B's submit of nonce %s -- a genuinely valid, never-before-seen share from ITS OWN session, against ITS OWN job -- was rejected: %q. Session B merely drew the same 2-byte xn (%q) as session A. This is exactly the spurious duplicate_nonce rejection the per-session cache key fixes.", sharedNonce, msg, sessB.XN())
	}
}

// TestTwoSessionsWithCollidingXNGenuineReplayStillRejected is the
// false-NEGATIVE guard for the test above: proving the fix closes a
// false positive is only half the job, so this proves real replay
// detection was NOT weakened. One session replaying its OWN nonce
// against its OWN job, with no second session involved in the replay,
// must still be rejected -- even while a colliding-xn peer exists and
// has legitimately used that same raw nonce value itself.
func TestTwoSessionsWithCollidingXNGenuineReplayStillRejected(t *testing.T) {
	collideSessionXN(t)
	h := newTwoSessionHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}})

	respA := loginOn(t, h.a, 1, realTariTestAddress("jobkey-collide-replay-a"), "rigA", "rx/0")
	respB := loginOn(t, h.b, 1, realTariTestAddress("jobkey-collide-replay-b"), "rigB", "rx/0")

	const sharedNonce = "00000042"
	claimHex := hex.EncodeToString(largeResultHash(1))

	// Session B legitimately uses the nonce once (it is B's own first
	// use, so accepted).
	h.b.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: respB.Result.ID, JobID: respB.Result.Job.JobID, Nonce: sharedNonce, Result: claimHex,
	})})
	if got := h.b.recvShareResponse(); got.Result == nil {
		t.Fatalf("setup: expected session B's first submit of nonce %s to be accepted, got %#v", sharedNonce, got)
	}

	// Session A uses it once -- also its own first use, also accepted
	// (this is the fix's behavior, already covered above; asserted
	// here only to set up A's replay).
	h.a.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: respA.Result.ID, JobID: respA.Result.Job.JobID, Nonce: sharedNonce, Result: claimHex,
	})})
	if got := h.a.recvShareResponse(); got.Result == nil {
		t.Fatalf("setup: expected session A's first submit of nonce %s to be accepted, got %#v", sharedNonce, got)
	}

	// Now A replays ITS OWN nonce against ITS OWN job. This is a
	// genuine replay and must still be rejected.
	h.a.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: respA.Result.ID, JobID: respA.Result.Job.JobID, Nonce: sharedNonce, Result: claimHex,
	})})
	if got := h.a.recvShareResponseSkippingJobPushes(); got.Result != nil {
		t.Fatalf("BUG: a genuine replay of session A's OWN nonce against its OWN job was ACCEPTED -- per-session nonce-replay detection must not have been weakened by the cache re-keying: %#v", got)
	}
}

// TestCollidingXNSessionStillGetsSameJobOnRepeatRequest pins the
// caching contract this fix deliberately PRESERVES: only the cache KEY
// changed (xn -> per-session key), never the caching behavior. A single
// session asking again (an explicit getjob after login, a vardiff
// re-fetch, ...) must still be served the SAME job_id, and must NOT
// trigger another template fetch -- and that must remain true even
// while a colliding-xn peer session exists, which is the case that
// would break if the key were reverted or made per-connection-unstable.
func TestCollidingXNSessionStillGetsSameJobOnRepeatRequest(t *testing.T) {
	collideSessionXN(t)
	h := newTwoSessionHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()})

	respA := loginOn(t, h.a, 1, realTariTestAddress("jobkey-collide-stable-a"), "rigA", "sha3x")
	respB := loginOn(t, h.b, 1, realTariTestAddress("jobkey-collide-stable-b"), "rigB", "sha3x")
	callsAfterLogins := h.node.templateCalls.Load()
	if callsAfterLogins != 2 {
		t.Fatalf("setup: GetBlockTemplate call count after two logins = %d, want 2", callsAfterLogins)
	}

	// An explicit getjob from A must return A's SAME job (an
	// unsolicited "job" push, per handleGetJob's documented dispatch).
	h.a.send(Request{ID: 2, Method: "getjob"})
	pushA := h.a.recvJobPush()
	if pushA.Params.JobID != respA.Result.Job.JobID {
		t.Fatalf("session A's getjob returned job_id %q, want its login job_id %q unchanged -- the per-session reuse contract must survive the cache re-keying", pushA.Params.JobID, respA.Result.Job.JobID)
	}

	// ... and likewise B gets B's own job, not A's.
	h.b.send(Request{ID: 2, Method: "getjob"})
	pushB := h.b.recvJobPush()
	if pushB.Params.JobID != respB.Result.Job.JobID {
		t.Fatalf("session B's getjob returned job_id %q, want its login job_id %q unchanged", pushB.Params.JobID, respB.Result.Job.JobID)
	}
	if pushA.Params.JobID == pushB.Params.JobID {
		t.Fatalf("BUG: both colliding-xn sessions' getjob responses carry the SAME job_id %q", pushA.Params.JobID)
	}

	// Neither repeat request may have cost a real daemon round trip:
	// both were genuine cache hits on their own session's entry.
	if got := h.node.templateCalls.Load(); got != callsAfterLogins {
		t.Fatalf("GetBlockTemplate call count = %d after two repeat getjob requests, want it unchanged at %d (repeat requests for the same session must be cache HITS)", got, callsAfterLogins)
	}
}

// TestCollidingXNSessionsGetDistinctSharedTemplateDerivedJobs is the
// Monero-family (shared-template) half of the decisive test: the
// jobForSessionFromSharedTemplate path is a SEPARATE cache-miss branch
// from the per-session-fetch path exercised above (see
// usesSharedTemplate), and it used to be keyed by xn too. ALGO_RXM is
// also the algo the brief identifies as where the bug actually bites
// in production.
//
// The fakeNodeClient here is Tari-shaped, so the extraNonce stamp is
// skipped (see extraNonceStampedTemplate's documented "not a
// Monero-family template" degradation) -- that is deliberate and does
// not weaken this test: what is under test is the CACHE KEY, i.e. that
// two colliding-xn sessions get two distinct *Job values with distinct
// IDs and distinct usedNonces sets, off the ONE shared template.
func TestCollidingXNSessionsGetDistinctSharedTemplateDerivedJobs(t *testing.T) {
	collideSessionXN(t)
	h := newTwoSessionHarness(t, poolpb.Algo_ALGO_RXM, 1000, 1<<62, validator.Registry{})

	respA := loginOn(t, h.a, 1, realXMRMainnetAddr, "rigA", "rx/0")
	respB := loginOn(t, h.b, 1, realXMRMainnetAddr, "rigB", "rx/0")

	sessA := sessionByID(t, h.a, respA.Result.ID)
	sessB := sessionByID(t, h.b, respB.Result.ID)
	if sessA.XN() != sessB.XN() {
		t.Fatalf("setup failure: the two sessions did NOT collide on xn (%q vs %q)", sessA.XN(), sessB.XN())
	}

	if respA.Result.Job.JobID == respB.Result.Job.JobID {
		t.Fatalf("BUG (shared-template path): two colliding-xn RXM sessions were served the SAME job_id %q -- each must get its own job derived from the one shared template", respA.Result.Job.JobID)
	}

	jobA, err := h.jm.JobForSessionAtDifficulty(context.Background(), sessA.JobKey(), sessA.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty(session A): %v", err)
	}
	jobB, err := h.jm.JobForSessionAtDifficulty(context.Background(), sessB.JobKey(), sessB.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty(session B): %v", err)
	}
	if jobA == jobB {
		t.Fatal("BUG (shared-template path): the two colliding-xn RXM sessions resolve to the SAME *Job pointer, so they share one usedNonces map")
	}

	// Shared-template mode's own contract is untouched: ONE real
	// daemon fetch for the whole process, regardless of session count
	// (this is the sxmr-phx-dump incident fix -- see
	// JobManager.sharedTemplate's doc comment). The re-keying must not
	// have reintroduced a per-session daemon call.
	if got := h.node.templateCalls.Load(); got != 1 {
		t.Fatalf("GetBlockTemplate call count = %d, want exactly 1 (shared-template mode must still collapse every session onto ONE real fetch)", got)
	}

	h.jm.mu.RLock()
	cached := len(h.jm.perSession)
	h.jm.mu.RUnlock()
	if cached != 2 {
		t.Fatalf("len(jm.perSession) = %d, want 2 -- one entry per session, off the single shared template", cached)
	}
}

// TestSessionJobKeyIsRolledOnReloginAndNeverEqualsXN guards the two
// remaining structural properties of Session.jobKey that the rest of
// this fix depends on:
//
//  1. It is NEVER the session's xn. A future refactor quietly wiring
//     JobKey() back to the xn value would silently reintroduce the
//     entire bug, and every other test here would still pass if it
//     also happened not to collide.
//  2. It is ROLLED ON RE-LOGIN. The job cache is keyed by this value,
//     so the xn-relogin fix (BRIEF_xn_relogin_fix.md -- an xmrig-proxy
//     `--reuse-timeout` slot rotation handing the same socket to a
//     genuinely different worker must not inherit the previous
//     worker's partially-used nonce space) now depends on THIS key
//     changing, not on the xn changing. TestSessionRXTReloginPreventsFalseDuplicateNonce
//     proves the resulting behavior end to end; this proves the
//     mechanism it now rests on.
func TestSessionJobKeyIsRolledOnReloginAndNeverEqualsXN(t *testing.T) {
	collideSessionXN(t)
	h := newReloginHarness(t, VardiffConfig{})

	respFirst := loginOn(t, h.testHarness, 1, realTariTestAddress("jobkey-relogin-a"), "rigA", "sha3x")
	sess := sessionByID(t, h.testHarness, respFirst.Result.ID)

	firstKey := sess.JobKey()
	if firstKey == "" {
		t.Fatal("session's job-cache key is empty -- newSession must always seed it")
	}
	if firstKey == sess.XN() {
		t.Fatalf("BUG: the job-cache key (%q) IS the session's xn -- the whole point of this fix is that the job cache is NOT keyed by the 2-byte xn (see leaflib.NewJobCacheKey)", firstKey)
	}

	// collideSessionXN pins xn, so the xn is deliberately UNCHANGED
	// across this re-login: that isolates the assertion below to the
	// job-cache key's own roll, with no help from the xn roll.
	respSecond := loginOn(t, h.testHarness, 2, realTariTestAddress("jobkey-relogin-b"), "rigB", "sha3x")
	secondKey := sess.JobKey()
	if secondKey == firstKey {
		t.Fatalf("BUG: the job-cache key was NOT rolled on re-login (still %q) -- a genuinely different downstream worker reusing this connection would inherit the previous worker's partially-used nonce space on the still-cached job", secondKey)
	}
	if respSecond.Result.Job.JobID == respFirst.Result.Job.JobID {
		t.Fatalf("BUG: the re-login was served the SAME job_id %q as the previous login -- the re-login's job-cache lookup must be a guaranteed MISS", respSecond.Result.Job.JobID)
	}

	// A THIRD login must roll it again -- this is not a
	// first-re-login-only fix.
	loginOn(t, h.testHarness, 3, realTariTestAddress("jobkey-relogin-c"), "rigC", "sha3x")
	thirdKey := sess.JobKey()
	if thirdKey == firstKey || thirdKey == secondKey {
		t.Fatalf("BUG: the job-cache key after a second re-login (%q) collides with an earlier value (first=%q second=%q)", thirdKey, firstKey, secondKey)
	}
}
