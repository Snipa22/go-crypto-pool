// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// --- BRIEF.md "decouple TCP/miner-identity + proxy-aware vardiff
// target time" -- leaf-proxy's Part A/Part B/Part C test coverage,
// mirroring internal/leaflib/solo/relogin_test.go's identical
// coverage exactly, adapted to this package's own harness
// (newHarness/testClient/loginWithFields, session_test.go/
// loginfields_test.go). ---

// TestProxyReloginTracksIdentityHistoryAndMetric is the core Part-A
// regression test: two sequential logins on ONE downstream connection
// confirm (a) the session's current identity reflects the SECOND
// login's address/worker/agent, not a mix; (b) the history ring
// contains the FIRST login's identity; (c) leaf_relogin_total
// incremented by exactly 1.
func TestProxyReloginTracksIdentityHistoryAndMetric(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("first login failed: %#v", resp)
	}
	sess := h.onlySession()

	first := *sess.Identity()
	if got := sess.loginHistory.Len(); got != 0 {
		t.Fatalf("BUG: login history has %d entries after a single, ordinary login, want 0", got)
	}
	if got := testutil.ToFloat64(h.server.metrics.ReloginTotal); got != 0 {
		t.Fatalf("leaf_relogin_total = %v after a single login, want 0", got)
	}

	resp2 := c.loginWithFields(t, "relogin-second-address", "rig2", "", "XMRig/6.22.0")
	if resp2.Result.Status != "OK" {
		t.Fatalf("re-login failed: %#v", resp2)
	}

	// (a) current identity reflects the SECOND login only.
	second := sess.Identity()
	if second.Address != "relogin-second-address" {
		t.Errorf("post-relogin identity address = %q, want the second login's %q", second.Address, "relogin-second-address")
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
	if got := testutil.ToFloat64(h.server.metrics.ReloginTotal); got != 1 {
		t.Errorf("leaf_relogin_total = %v after exactly one re-login, want 1", got)
	}
	if !sess.reloginDetected.Load() {
		t.Error("reloginDetected must be true after a real re-login")
	}
}

// TestProxySingleLoginLeavesReloginCounterAndHistoryEmpty is the
// explicit negative-case counterpart required by BRIEF.md part C.
func TestProxySingleLoginLeavesReloginCounterAndHistoryEmpty(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: %#v", resp)
	}
	sess := h.onlySession()

	if got := sess.loginHistory.Len(); got != 0 {
		t.Errorf("login history has %d entries after a single login, want 0", got)
	}
	if sess.reloginDetected.Load() {
		t.Error("reloginDetected must be false after a single login")
	}
	if got := testutil.ToFloat64(h.server.metrics.ReloginTotal); got != 0 {
		t.Errorf("leaf_relogin_total = %v after a single login, want 0", got)
	}
	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Errorf("forcedTargetTime = %d after a single, non-proxy login, want 0", got)
	}
}

// TestProxyGenericProxyAgentForcesTargetTimeImmediatelyAtLogin
// confirms the agent-string detection path (solo.IsGenericProxyAgent)
// forces forcedTargetTime to proxyForcedTargetTimeSeconds immediately
// after the FIRST login -- BEFORE any re-login occurs.
func TestProxyGenericProxyAgentForcesTargetTimeImmediatelyAtLogin(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", "SomeProxyThing/1.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: %#v", resp)
	}
	sess := h.onlySession()

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a single generic-proxy-agent login, want %d", got, proxyForcedTargetTimeSeconds)
	}
	if sess.reloginDetected.Load() {
		t.Fatal("BUG: reloginDetected must be false -- forcedTargetTime must come from the agent-string path alone")
	}
}

// TestProxyReloginAloneForcesTargetTimeForOrdinaryAgent confirms the
// NEW behavioral (re-login) detection path works INDEPENDENTLY of the
// agent-string path.
func TestProxyReloginAloneForcesTargetTimeForOrdinaryAgent(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: %#v", resp)
	}
	sess := h.onlySession()

	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Fatalf("forcedTargetTime = %d after a single ordinary-agent login, want 0", got)
	}

	resp2 := c.loginWithFields(t, "relogin-second-address", "rig2", "", "XMRig/6.21.0")
	if resp2.Result.Status != "OK" {
		t.Fatalf("re-login failed: %#v", resp2)
	}

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a re-login with an ordinary, never-proxy-matching agent, want %d", got, proxyForcedTargetTimeSeconds)
	}
}

// TestProxyMaybeRetargetUsesForcedTargetTimeNotConfiguredTargetTime
// proves the forced target time actually changes the real retarget
// COMPUTATION's outcome for a proxy-flagged session.
func TestProxyMaybeRetargetUsesForcedTargetTimeNotConfiguredTargetTime(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    1_000_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	c, _ := h.connectAtDifficulty(50000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", xnpProxyDownstreamTestAgent)
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: %#v", resp)
	}
	sess := h.onlySession()

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d, want %d", got, proxyForcedTargetTimeSeconds)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)

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
	c.recvJobPush()
	<-done

	got := sess.currentDifficulty.Load()
	if got != want10 {
		t.Errorf("post-retarget currentDifficulty = %d, want %d (the 10s-forced-target-time result)", got, want10)
	}
	if got == want30 {
		t.Errorf("post-retarget currentDifficulty = %d unexpectedly equals the 30s-configured-target-time result %d", got, want30)
	}
}

// TestProxyOrdinarySessionRetargetsWithConfiguredTargetTimeUnchanged
// is the explicit regression proof for the non-proxy path.
func TestProxyOrdinarySessionRetargetsWithConfiguredTargetTimeUnchanged(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    1_000_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	c, _ := h.connectAtDifficulty(50000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: %#v", resp)
	}
	sess := h.onlySession()

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
		c.recvJobPush()
	}
	<-done

	if got := sess.currentDifficulty.Load(); got != want {
		t.Errorf("post-retarget currentDifficulty = %d, want %d (cfg.TargetTime=30, unchanged)", got, want)
	}
	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Errorf("forcedTargetTime = %d after a retarget tick on an ordinary session, want 0", got)
	}
}
