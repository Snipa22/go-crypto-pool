// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- leaf-direct's own half of the decisive regression coverage for
// the job-cache re-keying fix. See
// internal/leaflib/solo/job_cache_key_test.go's header comment for the
// full, maintainer-confirmed root cause and real-world impact -- not
// repeated here.
//
// WHY THIS FILE EXISTS SEPARATELY rather than relying on the solo
// package's tests alone: the *shared* piece (solo.JobManager's
// perSession cache, and the JobForSession/JobForSessionAtDifficulty/
// RestampDifficulty API on it) is genuinely covered once, over there.
// What is NOT shared is this package's OWN Session.jobKey field, its
// own newSession seeding, its own handleLogin re-login roll, and its
// own call sites (fetchAndDeliverLoginJob/fetchAndDeliverGetJob/
// pushFreshJobOnStaleSubmit/vardiff/invalidateAndRepushJobs) -- all
// hand-mirrored from solo rather than imported, exactly like
// Session.xn itself. A direct.Session whose jobKey was accidentally
// wired to its xn (or never rolled on re-login) would leave every
// solo-package test passing while leaf-direct -- the mode that
// actually runs the real pool -- carried the bug. ---

// collidedDirectXN is the single, fixed xn value
// collideDirectSessionXN hands to every session in a test; see
// solo/job_cache_key_test.go's collidedXN.
const collidedDirectXN = "beef"

// collideDirectSessionXN forces every session created for the lifetime
// of the calling test onto the SAME xn, restoring the real
// leaflib.NewSessionXN implementation on cleanup. Deliberate inverse
// of xn_relogin_test.go's stubDeterministicDirectSessionXN: here the
// collision IS the scenario under test, so it must be guaranteed
// rather than waited for.
func collideDirectSessionXN(t *testing.T) {
	t.Helper()
	orig := newSessionXN
	newSessionXN = func() (string, error) { return collidedDirectXN, nil }
	t.Cleanup(func() { newSessionXN = orig })
}

// twoSessionDirectHarness is one real leaf-direct Server (one
// solo.JobManager, one fakeDirectNodeClient) with TWO independent
// miner connections attached -- newDirectTestHarness wires exactly
// one, and this fix is specifically about two sessions interacting
// through one shared JobManager.
type twoSessionDirectHarness struct {
	server *Server
	jm     *solo.JobManager
	node   *fakeDirectNodeClient
	a      *directTestHarness
	b      *directTestHarness
}

func newTwoSessionDirectHarness(t *testing.T, staticDiff, networkTargetDiff uint64) *twoSessionDirectHarness {
	t.Helper()
	node := &fakeDirectNodeClient{
		height:          42,
		mergeMiningHash: []byte("direct-jobkey-merge-mining-hash"),
	}
	node.targetDifficulty = networkTargetDiff
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
	})

	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}
	tr := &fakeShareTransport{}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm,
		JobManager:        jm,
		Node:              node,
		Validators:        registry,
		Network:           poolpb.Network_NETWORK_TESTNET,
		Transport:         tr,
		MultiSubmit:       multi,
		Algo:              poolpb.Algo_ALGO_SHA3X,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            42,
	})
	t.Cleanup(func() {
		cancel()
		server.Shutdown()
	})

	newConn := func() *directTestHarness {
		serverConn, clientConn := net.Pipe()
		go server.handleConn(ctx, serverConn, staticDiff)
		t.Cleanup(func() { _ = clientConn.Close() })
		return &directTestHarness{
			t: t, server: server, jm: jm, node: node, transport: tr, submit: sub,
			client: clientConn,
			reader: bufio.NewReader(clientConn),
			writer: bufio.NewWriter(clientConn),
			cancel: cancel,
		}
	}

	h := &twoSessionDirectHarness{server: server, jm: jm, node: node}
	h.a = newConn()
	h.b = newConn()
	return h
}

// directLoginOn performs one real wire login on a specific connection
// -- a per-connection variant of directLogin (which is hard-wired to
// one harness and additionally resolves the session's xn, deliberately
// uninteresting here since this file's whole premise is two sessions
// sharing one xn).
func directLoginOn(t *testing.T, h *directTestHarness, id int, address, worker string) solo.LoginResponse {
	t.Helper()
	h.send(solo.Request{ID: id, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: address, Pass: worker, Agent: "XMRig/6.21.0", Algo: []string{"sha3x"},
	})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login on this connection failed: status=%q", resp.Result.Status)
	}
	return resp
}

// TestDirectTwoSessionsWithCollidingXNGetDistinctJobs is leaf-direct's
// decisive regression test: two genuinely unrelated leaf-direct
// sessions, deliberately forced onto the SAME 2-byte xn, must each be
// minted their OWN job.
//
// Against the pre-fix xn-keyed cache, session B's login is a cache HIT
// on session A's entry: B receives A's job_id verbatim, A's *Job
// pointer (and therefore A's usedNonces map), and only ONE real
// GetBlockTemplate call is made for the two of them.
func TestDirectTwoSessionsWithCollidingXNGetDistinctJobs(t *testing.T) {
	collideDirectSessionXN(t)
	h := newTwoSessionDirectHarness(t, 1000, 1<<62)

	respA := directLoginOn(t, h.a, 1, realTariTestAddress("direct-jobkey-a"), "rigA")
	respB := directLoginOn(t, h.b, 1, realTariTestAddress("direct-jobkey-b"), "rigB")

	sessA := directSessionByID(t, h.a, respA.Result.ID)
	sessB := directSessionByID(t, h.b, respB.Result.ID)

	// Precondition: the collision genuinely happened.
	if sessA.XN() != sessB.XN() {
		t.Fatalf("setup failure: the two sessions did NOT collide on xn (%q vs %q)", sessA.XN(), sessB.XN())
	}
	if sessA.sessionID == sessB.sessionID {
		t.Fatalf("setup failure: expected two genuinely distinct sessions, both have sessionID %q", sessA.sessionID)
	}

	// The fix: identical xn, genuinely distinct job-cache keys...
	if sessA.JobKey() == sessB.JobKey() {
		t.Fatalf("BUG: two leaf-direct sessions sharing xn %q were also given the SAME job-cache key %q -- the cache key must be per-session (leaflib.NewJobCacheKey), not per-xn", sessA.XN(), sessA.JobKey())
	}
	if sessA.JobKey() == sessA.XN() {
		t.Fatalf("BUG: this leaf-direct session's job-cache key (%q) IS its xn -- direct.newSession must seed jobKey from leaflib.NewJobCacheKey, never from the xn", sessA.JobKey())
	}

	// ... and therefore distinct jobs on the wire...
	if respA.Result.Job.JobID == respB.Result.Job.JobID {
		t.Fatalf("BUG: two unrelated leaf-direct sessions that drew the same xn %q were served the SAME wire job_id %q", sessA.XN(), respA.Result.Job.JobID)
	}

	// ... backed by two distinct *solo.Job values, i.e. two separate
	// usedNonces sets.
	jobA, err := h.jm.JobForSessionAtDifficulty(context.Background(), sessA.JobKey(), sessA.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty(session A): %v", err)
	}
	jobB, err := h.jm.JobForSessionAtDifficulty(context.Background(), sessB.JobKey(), sessB.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("JobForSessionAtDifficulty(session B): %v", err)
	}
	if jobA == jobB {
		t.Fatal("BUG: the two colliding-xn leaf-direct sessions resolve to the SAME *solo.Job pointer, so they share one usedNonces map")
	}

	// SHA3X is not a shared-template algo, so two cache misses means
	// two genuine daemon fetches. A count of 1 is the tell-tale of an
	// xn-keyed cache collapsing both sessions onto one entry.
	if got := h.node.templateCalls.Load(); got != 2 {
		t.Fatalf("GetBlockTemplate call count = %d, want 2 (one genuine template per session, even though both drew the same xn)", got)
	}
}

// TestDirectSessionJobKeyIsRolledOnRelogin guards the leaf-direct half
// of the re-login mechanism the false-duplicate_nonce fix now rests on
// (see solo/xn_relogin_test.go's header comment): because the job cache
// is keyed by Session.jobKey, handleLogin MUST roll that key on every
// re-login or a genuinely different downstream worker reusing this
// connection inherits the previous worker's partially-used nonce space.
//
// collideDirectSessionXN pins the xn across the re-login on purpose:
// that isolates this assertion to the jobKey roll alone, with no help
// from the xn roll (which TestDirectSessionReloginRollsFreshXN already
// covers separately).
func TestDirectSessionJobKeyIsRolledOnRelogin(t *testing.T) {
	collideDirectSessionXN(t)
	h := newTwoSessionDirectHarness(t, 1000, 1<<62)

	first := directLoginOn(t, h.a, 1, realTariTestAddress("direct-jobkey-relogin-a"), "rigA")
	sess := directSessionByID(t, h.a, first.Result.ID)

	firstKey := sess.JobKey()
	if firstKey == "" {
		t.Fatal("leaf-direct session's job-cache key is empty -- newSession must always seed it")
	}

	second := directLoginOn(t, h.a, 2, realTariTestAddress("direct-jobkey-relogin-b"), "rigB")
	secondKey := sess.JobKey()
	if secondKey == firstKey {
		t.Fatalf("BUG: the job-cache key was NOT rolled on re-login (still %q)", secondKey)
	}
	if sess.XN() != collidedDirectXN {
		t.Fatalf("setup failure: expected the xn to be pinned at %q across the re-login so this test isolates the jobKey roll, got %q", collidedDirectXN, sess.XN())
	}
	if second.Result.Job.JobID == first.Result.Job.JobID {
		t.Fatalf("BUG: the re-login was served the SAME job_id %q as the previous login -- the re-login's job-cache lookup must be a guaranteed MISS", second.Result.Job.JobID)
	}

	// A THIRD login must roll it again: this is not a
	// first-re-login-only fix.
	directLoginOn(t, h.a, 3, realTariTestAddress("direct-jobkey-relogin-c"), "rigC")
	thirdKey := sess.JobKey()
	if thirdKey == firstKey || thirdKey == secondKey {
		t.Fatalf("BUG: the job-cache key after a second re-login (%q) collides with an earlier value (first=%q second=%q)", thirdKey, firstKey, secondKey)
	}
}

// TestDirectCollidingXNSessionsBothGetRepushedDistinctJobs covers the
// one leaf-direct-only call site that has no leaf-solo equivalent
// shape: Server.invalidateAndRepushJobs' bounded, CONCURRENT per-session
// fan-out (server.go -- leaf-solo's is sequential). Two colliding-xn
// sessions must each be repushed their OWN freshly-regenerated job
// after a cache invalidation; pre-fix, whichever of the two raced to
// the cache first would have populated the single shared xn entry and
// the other would have been handed that same job.
func TestDirectCollidingXNSessionsBothGetRepushedDistinctJobs(t *testing.T) {
	collideDirectSessionXN(t)
	h := newTwoSessionDirectHarness(t, 1000, 1<<62)

	respA := directLoginOn(t, h.a, 1, realTariTestAddress("direct-jobkey-repush-a"), "rigA")
	respB := directLoginOn(t, h.b, 1, realTariTestAddress("direct-jobkey-repush-b"), "rigB")
	sessA := directSessionByID(t, h.a, respA.Result.ID)
	sessB := directSessionByID(t, h.b, respB.Result.ID)
	if sessA.XN() != sessB.XN() {
		t.Fatalf("setup failure: the two sessions did NOT collide on xn (%q vs %q)", sessA.XN(), sessB.XN())
	}

	// A real tip movement: bump the fake node's height so the
	// regenerated jobs are genuinely new (a bare invalidation alone
	// would re-fetch the same height and alreadyDelivered could
	// legitimately suppress the push).
	h.node.mu.Lock()
	h.node.height = 43
	h.node.mu.Unlock()
	h.jm.InvalidateAll(solo.TemplateSourceLocal)

	// invalidateAndRepushJobs' writes block on net.Pipe until each
	// client reads, so it must run off this goroutine (exactly as the
	// real JobManager-subscriber callback does).
	go h.server.invalidateAndRepushJobs(solo.TemplateSourceLocal)

	pushA := h.a.recvJobPush()
	pushB := h.b.recvJobPush()
	if pushA.Params.JobID == pushB.Params.JobID {
		t.Fatalf("BUG: after a cache invalidation, both colliding-xn sessions were repushed the SAME job_id %q -- each must be regenerated its OWN job", pushA.Params.JobID)
	}
	if pushA.Params.JobID == respA.Result.Job.JobID {
		t.Errorf("session A's repushed job_id %q is unchanged from its pre-invalidation login job_id -- the invalidation should have regenerated it", pushA.Params.JobID)
	}
	if pushB.Params.JobID == respB.Result.Job.JobID {
		t.Errorf("session B's repushed job_id %q is unchanged from its pre-invalidation login job_id", pushB.Params.JobID)
	}
}
