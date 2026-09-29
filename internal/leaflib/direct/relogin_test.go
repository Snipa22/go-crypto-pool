// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- BRIEF.md "decouple TCP/miner-identity + proxy-aware vardiff
// target time" -- leaf-direct's Part A/Part B/Part C test coverage,
// mirroring internal/leaflib/solo/relogin_test.go's identical
// coverage exactly, adapted to this package's own harness
// (newDirectLoginParseHarness/directLogin/directSessionByID,
// loginfields_test.go/session_test.go). ---

// directRelogin performs a second (or Nth) "login" handshake on an
// ALREADY logged-in directTestHarness connection h -- mirrors
// directLogin's own real wire-level login, but deliberately does NOT
// open a new connection, since the entire point of a re-login is that
// it arrives on the SAME already-established TCP connection.
func directRelogin(t *testing.T, h *directTestHarness, address, worker, agent string) solo.LoginResponse {
	t.Helper()
	h.send(solo.Request{ID: 2, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: address, Pass: worker, Agent: agent, Algo: []string{"sha3x"},
	})})
	return h.recvLoginResponse()
}

// directLoginWithAgent mirrors directLogin (session_test.go) exactly,
// except it lets the caller supply a custom agent string.
func directLoginWithAgent(t *testing.T, h *directTestHarness, address, agent string) (sessionID, xn string) {
	t.Helper()
	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: address, Pass: "rig1", Agent: agent, Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.ID, directSessionXN(t, h, resp.Result.ID)
}

// TestDirectReloginTracksIdentityHistoryAndMetric is the core Part-A
// regression test: two sequential logins on ONE session confirm (a)
// the session's current identity reflects the SECOND login's
// address/worker/agent, not a mix; (b) the history ring contains the
// FIRST login's identity; (c) leaf_relogin_total incremented by
// exactly 1.
func TestDirectReloginTracksIdentityHistoryAndMetric(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{RetargetInterval: time.Hour})
	m := h.server.EnableMetrics("test", 0)

	addr1 := realTariTestAddress("direct-relogin-first")
	sessionID, _ := directLogin(t, h, addr1)
	sess := directSessionByID(t, h, sessionID)

	first := *sess.Identity()
	if got := sess.loginHistory.Len(); got != 0 {
		t.Fatalf("BUG: login history has %d entries after a single, ordinary login, want 0", got)
	}
	if got := testutil.ToFloat64(m.ReloginTotal); got != 0 {
		t.Fatalf("leaf_relogin_total = %v after a single login, want 0", got)
	}

	addr2 := realTariTestAddress("direct-relogin-second")
	resp := directRelogin(t, h, addr2, "rig2", "XMRig/6.22.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", resp.Result.Status)
	}

	// (a) current identity reflects the SECOND login only.
	second := sess.Identity()
	if second.Address != addr2 {
		t.Errorf("post-relogin identity address = %q, want the second login's %q", second.Address, addr2)
	}
	if second.Worker != "rig2" {
		t.Errorf("post-relogin identity worker = %q, want the second login's %q (not a mix with the first)", second.Worker, "rig2")
	}
	if second.Agent != "XMRig/6.22.0" {
		t.Errorf("post-relogin identity agent = %q, want the second login's %q", second.Agent, "XMRig/6.22.0")
	}

	// (b) the history ring contains the FIRST login's identity.
	hist := sess.loginHistory.Snapshot()
	if len(hist) != 1 {
		t.Fatalf("login history has %d entries after one re-login, want exactly 1", len(hist))
	}
	if hist[0].Address != first.Address || hist[0].Worker != first.Worker {
		t.Errorf("login history entry = %+v, want the FIRST login's identity %+v", hist[0], first)
	}

	// (c) leaf_relogin_total incremented by exactly 1.
	if got := testutil.ToFloat64(m.ReloginTotal); got != 1 {
		t.Errorf("leaf_relogin_total = %v after exactly one re-login, want 1", got)
	}
	if !sess.reloginDetected.Load() {
		t.Error("reloginDetected must be true after a real re-login")
	}
}

// TestDirectSingleLoginLeavesReloginCounterAndHistoryEmpty is the
// explicit negative-case counterpart required by BRIEF.md part C.
func TestDirectSingleLoginLeavesReloginCounterAndHistoryEmpty(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{RetargetInterval: time.Hour})
	m := h.server.EnableMetrics("test", 0)

	sessionID, _ := directLogin(t, h, realTariTestAddress("direct-relogin-none"))
	sess := directSessionByID(t, h, sessionID)

	if got := sess.loginHistory.Len(); got != 0 {
		t.Errorf("login history has %d entries after a single login, want 0", got)
	}
	if sess.reloginDetected.Load() {
		t.Error("reloginDetected must be false after a single login")
	}
	if got := testutil.ToFloat64(m.ReloginTotal); got != 0 {
		t.Errorf("leaf_relogin_total = %v after a single login, want 0", got)
	}
	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Errorf("forcedTargetTime = %d after a single, non-proxy login, want 0", got)
	}
}

// TestDirectGenericProxyAgentForcesTargetTimeImmediatelyAtLogin
// confirms the agent-string detection path (solo.IsGenericProxyAgent)
// forces forcedTargetTime to proxyForcedTargetTimeSeconds immediately
// after the FIRST login -- BEFORE any re-login occurs.
func TestDirectGenericProxyAgentForcesTargetTimeImmediatelyAtLogin(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{RetargetInterval: time.Hour})
	sessionID, _ := directLoginWithAgent(t, h, realTariTestAddress("direct-generic-proxy-forced-target"), "SomeProxyThing/1.0")
	sess := directSessionByID(t, h, sessionID)

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a single generic-proxy-agent login, want %d", got, proxyForcedTargetTimeSeconds)
	}
	if sess.reloginDetected.Load() {
		t.Fatal("BUG: reloginDetected must be false -- forcedTargetTime must come from the agent-string path alone")
	}
}

// TestDirectXNPProxyAgentForcesTargetTimeImmediatelyAtLogin mirrors
// the above for the XNP-specific detection path.
func TestDirectXNPProxyAgentForcesTargetTimeImmediatelyAtLogin(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{RetargetInterval: time.Hour})
	sessionID, _ := directLoginWithAgent(t, h, realTariTestAddress("direct-xnp-proxy-forced-target"), "xmr-node-proxy/0.0.3")
	sess := directSessionByID(t, h, sessionID)

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a single XNP-agent login, want %d", got, proxyForcedTargetTimeSeconds)
	}
}

// TestDirectReloginAloneForcesTargetTimeForOrdinaryAgent confirms the
// NEW behavioral (re-login) detection path works INDEPENDENTLY of the
// agent-string path.
func TestDirectReloginAloneForcesTargetTimeForOrdinaryAgent(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{RetargetInterval: time.Hour})
	sessionID, _ := directLogin(t, h, realTariTestAddress("direct-relogin-forces-target"))
	sess := directSessionByID(t, h, sessionID)

	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Fatalf("forcedTargetTime = %d after a single ordinary-agent login, want 0", got)
	}

	resp := directRelogin(t, h, realTariTestAddress("direct-relogin-forces-target-2"), "rig2", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", resp.Result.Status)
	}

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a re-login with an ordinary, never-proxy-matching agent, want %d", got, proxyForcedTargetTimeSeconds)
	}
}

// TestDirectMaybeRetargetUsesForcedTargetTimeNotConfiguredTargetTime
// proves the forced target time actually changes the real retarget
// COMPUTATION's outcome for a proxy-flagged session.
func TestDirectMaybeRetargetUsesForcedTargetTimeNotConfiguredTargetTime(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    1_000_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	sessionID, _ := directLoginWithAgent(t, h, realTariTestAddress("direct-forced-target-retarget"), "xmr-node-proxy/0.0.3")
	sess := directSessionByID(t, h, sessionID)

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d, want %d", got, proxyForcedTargetTimeSeconds)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	sess.currentDifficulty.Store(50000)

	curDiff := sess.currentDifficulty.Load()
	const connSeconds = 90
	const hashes = 600_000

	want10, changed10 := leaflib.ComputeRetarget(curDiff, hashes, connSeconds, proxyForcedTargetTimeSeconds, h.server.vardiff.MinDifficulty, h.server.vardiff.MaxDifficulty)
	want30, _ := leaflib.ComputeRetarget(curDiff, hashes, connSeconds, h.server.vardiff.TargetTime, h.server.vardiff.MinDifficulty, h.server.vardiff.MaxDifficulty)
	if !changed10 {
		t.Fatal("test setup bug: expected the 10s-target computation to actually change the difficulty")
	}
	if want10 == want30 {
		t.Fatalf("test setup bug: 10s-target result (%d) must differ from 30s-target result (%d)", want10, want30)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	h.recvJobPush()
	<-done

	got := sess.currentDifficulty.Load()
	if got != want10 {
		t.Errorf("post-retarget currentDifficulty = %d, want %d (the 10s-forced-target-time result)", got, want10)
	}
	if got == want30 {
		t.Errorf("post-retarget currentDifficulty = %d unexpectedly equals the 30s-configured-target-time result %d", got, want30)
	}
}

// TestDirectOrdinarySessionRetargetsWithConfiguredTargetTimeUnchanged
// is the explicit regression proof for the non-proxy path.
func TestDirectOrdinarySessionRetargetsWithConfiguredTargetTimeUnchanged(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    1_000_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	sessionID, _ := directLogin(t, h, realTariTestAddress("direct-ordinary-no-proxy-signal"))
	sess := directSessionByID(t, h, sessionID)

	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Fatalf("forcedTargetTime = %d for an ordinary session, want 0", got)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	curDiff := sess.currentDifficulty.Load()
	want, changed := leaflib.ComputeRetarget(curDiff, 600_000, 90, 30, h.server.vardiff.MinDifficulty, h.server.vardiff.MaxDifficulty)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	if changed {
		h.recvJobPush()
	}
	<-done

	if got := sess.currentDifficulty.Load(); got != want {
		t.Errorf("post-retarget currentDifficulty = %d, want %d (cfg.TargetTime=30, unchanged)", got, want)
	}
	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Errorf("forcedTargetTime = %d after a retarget tick on an ordinary session, want 0", got)
	}
}
