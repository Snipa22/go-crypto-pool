// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- BRIEF.md "decouple TCP/miner-identity + proxy-aware vardiff
// target time" -- Part A (atomic identity + re-login tracking) and
// Part B (proxy-aware forced target time) test coverage. ---

// newReloginHarness is a thin wrapper around the existing
// newRejectionReasonHarness (session_rejection_reason_test.go) --
// reused here purely because it already wires a real *metrics.Metrics
// onto the harness's Server BEFORE the session goroutine starts
// (avoiding a real `go test -race` data race), which this file's
// tests need to assert on leaf_relogin_total.
func newReloginHarness(t *testing.T, vardiff VardiffConfig) *rejectionReasonHarness {
	t.Helper()
	return newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, 0,
		validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
}

// relogin performs a second (or Nth) "login" handshake on an ALREADY
// logged-in testHarness connection h -- mirrors login's (session_test.go)
// own real wire-level login, but deliberately does NOT open a new
// connection (login/newSession always dials a fresh net.Pipe): the
// entire point of a re-login is that it arrives on the SAME already-
// established TCP connection, per BRIEF.md's own framing of the real
// xmrig-proxy `--reuse-timeout` behavior this observes.
func relogin(t *testing.T, h *testHarness, address, worker, agent string) LoginResponse {
	t.Helper()
	h.send(Request{ID: 2, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress(address), Pass: worker, Agent: agent, Algo: []string{"sha3x"},
	})})
	return h.recvLoginResponse()
}

// TestReloginTracksIdentityHistoryAndMetric is the core Part-A
// regression test: two sequential logins on ONE session confirm (a)
// the session's current identity reflects the SECOND login's
// address/worker/agent, not a mix; (b) the history ring contains the
// FIRST login's identity; (c) leaf_relogin_total incremented by
// exactly 1.
func TestReloginTracksIdentityHistoryAndMetric(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{})

	sessionID, _ := login(t, h.testHarness, "relogin-first")
	sess := sessionByID(t, h.testHarness, sessionID)

	firstIdentity := *sess.Identity()
	if firstIdentity.Address != realTariTestAddress("relogin-first") {
		t.Fatalf("first identity address = %q, want %q", firstIdentity.Address, realTariTestAddress("relogin-first"))
	}
	if firstIdentity.Worker != "rig1" {
		t.Fatalf("first identity worker = %q, want %q", firstIdentity.Worker, "rig1")
	}
	if got := sess.loginHistory.Len(); got != 0 {
		t.Fatalf("BUG: login history has %d entries after a single, ordinary login, want 0", got)
	}
	if got := testutil.ToFloat64(h.metrics.ReloginTotal); got != 0 {
		t.Fatalf("leaf_relogin_total = %v after a single login, want 0", got)
	}

	resp := relogin(t, h.testHarness, "relogin-second", "rig2", "XMRig/6.22.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", resp.Result.Status)
	}

	// (a) current identity reflects the SECOND login only.
	second := sess.Identity()
	if second.Address != realTariTestAddress("relogin-second") {
		t.Errorf("post-relogin identity address = %q, want the second login's %q", second.Address, realTariTestAddress("relogin-second"))
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
	if hist[0].Address != firstIdentity.Address || hist[0].Worker != firstIdentity.Worker {
		t.Errorf("login history entry = %+v, want the FIRST login's identity %+v", hist[0], firstIdentity)
	}

	// (c) leaf_relogin_total incremented by exactly 1.
	if got := testutil.ToFloat64(h.metrics.ReloginTotal); got != 1 {
		t.Errorf("leaf_relogin_total = %v after exactly one re-login, want 1", got)
	}

	// reloginDetected is sticky -- confirm it stayed set.
	if !sess.reloginDetected.Load() {
		t.Error("reloginDetected must be true after a real re-login")
	}
}

// TestReloginTotalIncrementsOncePerReloginEventNotPerLogin extends the
// above: a THIRD login (a second re-login) must bump leaf_relogin_total
// again (to 2), proving the metric counts re-login EVENTS, not just
// "has this session ever relogged in" -- distinct from the sticky
// reloginDetected boolean, which stays at its already-true value.
func TestReloginTotalIncrementsOncePerReloginEventNotPerLogin(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{})

	sessionID, _ := login(t, h.testHarness, "relogin-thrice")
	sess := sessionByID(t, h.testHarness, sessionID)

	relogin(t, h.testHarness, "relogin-thrice-2", "rig2", "XMRig/6.22.0")
	if got := testutil.ToFloat64(h.metrics.ReloginTotal); got != 1 {
		t.Fatalf("leaf_relogin_total after 1st re-login = %v, want 1", got)
	}

	relogin(t, h.testHarness, "relogin-thrice-3", "rig3", "XMRig/6.23.0")
	if got := testutil.ToFloat64(h.metrics.ReloginTotal); got != 2 {
		t.Fatalf("leaf_relogin_total after 2nd re-login = %v, want 2 (must count every re-login EVENT, not just the first)", got)
	}
	if got := sess.loginHistory.Len(); got != 2 {
		t.Fatalf("login history has %d entries after 2 re-logins, want 2", got)
	}
	if !sess.reloginDetected.Load() {
		t.Error("reloginDetected must still be true")
	}
}

// TestSingleLoginLeavesReloginCounterAndHistoryEmpty is the explicit
// negative-case counterpart required by BRIEF.md part C: a single
// login (no re-login at all) must leave the relogin counter at 0 and
// the history ring empty.
func TestSingleLoginLeavesReloginCounterAndHistoryEmpty(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{})
	sessionID, _ := login(t, h.testHarness, "relogin-none")
	sess := sessionByID(t, h.testHarness, sessionID)

	if got := sess.loginHistory.Len(); got != 0 {
		t.Errorf("login history has %d entries after a single login, want 0", got)
	}
	if sess.reloginDetected.Load() {
		t.Error("reloginDetected must be false after a single login")
	}
	if got := testutil.ToFloat64(h.metrics.ReloginTotal); got != 0 {
		t.Errorf("leaf_relogin_total = %v after a single login, want 0", got)
	}
	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Errorf("forcedTargetTime = %d after a single, non-proxy login, want 0", got)
	}
}

// TestGenericProxyAgentForcesTargetTimeImmediatelyAtLogin confirms the
// agent-string detection path (IsGenericProxyAgent) forces
// forcedTargetTime to proxyForcedTargetTimeSeconds (10) immediately
// after the FIRST login -- BEFORE any re-login occurs -- proving this
// path works independently of the relogin path.
func TestGenericProxyAgentForcesTargetTimeImmediatelyAtLogin(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{})
	sessionID, _ := loginWithAgent(t, h.testHarness, "generic-proxy-forced-target", "SomeProxyThing/1.0")
	sess := sessionByID(t, h.testHarness, sessionID)

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a single generic-proxy-agent login, want %d", got, proxyForcedTargetTimeSeconds)
	}
	if sess.reloginDetected.Load() {
		t.Fatal("BUG: reloginDetected must be false -- this session never re-logged in, forcedTargetTime must come from the agent-string path alone")
	}
}

// TestXNPProxyAgentForcesTargetTimeImmediatelyAtLogin mirrors the
// above for the XNP-specific detection path (IsXNPProxyAgent).
func TestXNPProxyAgentForcesTargetTimeImmediatelyAtLogin(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{})
	sessionID, _ := loginWithAgent(t, h.testHarness, "xnp-proxy-forced-target", xnpProxyTestAgent)
	sess := sessionByID(t, h.testHarness, sessionID)

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a single XNP-agent login, want %d", got, proxyForcedTargetTimeSeconds)
	}
}

// TestReloginAloneForcesTargetTimeForOrdinaryAgent confirms the NEW
// behavioral (re-login) detection path works INDEPENDENTLY of the
// agent-string path: a session whose agent NEVER matches any proxy
// pattern (plain "XMRig/6.21.0") has forcedTargetTime forced to 10
// only once it receives a SECOND login (simulating an xmrig-proxy
// connection-reuse slot rotation) -- 0 beforehand.
func TestReloginAloneForcesTargetTimeForOrdinaryAgent(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{})
	sessionID, _ := login(t, h.testHarness, "relogin-forces-target") // ordinary "XMRig/6.21.0" agent, see login()'s own doc comment
	sess := sessionByID(t, h.testHarness, sessionID)

	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Fatalf("forcedTargetTime = %d after a single ordinary-agent login, want 0", got)
	}

	resp := relogin(t, h.testHarness, "relogin-forces-target-2", "rig2", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", resp.Result.Status)
	}

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d after a re-login with an ordinary, never-proxy-matching agent, want %d (the relogin-alone behavioral signal)", got, proxyForcedTargetTimeSeconds)
	}
}

// TestMaybeRetargetUsesForcedTargetTimeNotConfiguredTargetTime is the
// required proof that the forced target time actually changes the
// real retarget COMPUTATION's outcome, not just that the flag gets
// set: a proxy-flagged session's maybeRetarget must call
// computeRetarget with targetTime=10, and the resulting difficulty
// must differ from what a targetTime=30 (the harness's configured
// cfg.TargetTime) computation would have produced against the exact
// same curDiff/hashes/connSeconds inputs.
func TestMaybeRetargetUsesForcedTargetTimeNotConfiguredTargetTime(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    1_000_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	sessionID, _ := loginWithAgent(t, h.testHarness, "forced-target-retarget", xnpProxyTestAgent)
	sess := sessionByID(t, h.testHarness, sessionID)

	if got := sess.forcedTargetTime.Load(); got != proxyForcedTargetTimeSeconds {
		t.Fatalf("forcedTargetTime = %d, want %d", got, proxyForcedTargetTimeSeconds)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	// Overridden away from the port tier's default starting
	// difficulty specifically so the 10s-target and 30s-target
	// computations land on two DIFFERENT results below (at the
	// default starting difficulty both would collapse to the same
	// 1.5x-step-limit-clamped value, which would prove nothing) --
	// same fixture math as xnp_fixeddiff_escape_test.go's own
	// analogous proxy-retarget assertions.
	sess.currentDifficulty.Store(50000)

	curDiff := sess.currentDifficulty.Load()
	const connSeconds = 90
	const hashes = 600_000

	want10, changed10 := computeRetarget(curDiff, hashes, connSeconds, proxyForcedTargetTimeSeconds, h.server.vardiff.MinDifficulty, h.server.vardiff.MaxDifficulty)
	want30, _ := computeRetarget(curDiff, hashes, connSeconds, h.server.vardiff.TargetTime, h.server.vardiff.MinDifficulty, h.server.vardiff.MaxDifficulty)
	if !changed10 {
		t.Fatal("test setup bug: expected the 10s-target computation to actually change the difficulty")
	}
	if want10 == want30 {
		t.Fatalf("test setup bug: 10s-target result (%d) must differ from 30s-target result (%d) to prove the override actually matters -- adjust the fixture", want10, want30)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	if changed10 {
		h.recvRaw() // the retarget push -- drain it so maybeRetarget's goroutine can complete the write.
	}
	<-done

	got := sess.currentDifficulty.Load()
	if got != want10 {
		t.Errorf("post-retarget currentDifficulty = %d, want %d (the 10s-forced-target-time result)", got, want10)
	}
	if got == want30 {
		t.Errorf("post-retarget currentDifficulty = %d unexpectedly equals the 30s-configured-target-time result %d -- the override did not take effect", got, want30)
	}
}

// TestOrdinarySessionRetargetsWithConfiguredTargetTimeUnchanged is the
// explicit regression proof for the non-proxy path: a session with no
// proxy signal at all (no agent match, no re-login) must retarget
// using cfg.TargetTime completely unchanged -- forcedTargetTime stays
// 0 for its whole life.
func TestOrdinarySessionRetargetsWithConfiguredTargetTimeUnchanged(t *testing.T) {
	h := newReloginHarness(t, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    1_000_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	sessionID, _ := login(t, h.testHarness, "ordinary-no-proxy-signal")
	sess := sessionByID(t, h.testHarness, sessionID)

	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Fatalf("forcedTargetTime = %d for an ordinary session, want 0", got)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	curDiff := sess.currentDifficulty.Load()
	want, changed := computeRetarget(curDiff, 600_000, 90, 30, h.server.vardiff.MinDifficulty, h.server.vardiff.MaxDifficulty)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	if changed {
		h.recvRaw()
	}
	<-done

	if got := sess.currentDifficulty.Load(); got != want {
		t.Errorf("post-retarget currentDifficulty = %d, want %d (cfg.TargetTime=30, unchanged)", got, want)
	}
	if got := sess.forcedTargetTime.Load(); got != 0 {
		t.Errorf("forcedTargetTime = %d after a retarget tick on an ordinary session, want 0 (still unset)", got)
	}
}

// loginWithAgent mirrors login (session_test.go) exactly, except it
// lets the caller supply a custom agent string instead of the
// hardcoded "XMRig/6.21.0" -- needed to exercise the agent-string
// proxy-detection path at login time.
func loginWithAgent(t *testing.T, h *testHarness, address, agent string) (sessionID, xn string) {
	t.Helper()
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realTariTestAddress(address), Pass: "rig1", Agent: agent, Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.ID, sessionXN(t, h, resp.Result.ID)
}
