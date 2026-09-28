// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// --- leaf-proxy DOWNSTREAM login-field parsing --------------------
//
// Parity coverage for the port of commits 9196a5a (login-field
// address/+diff/.paymentID/.identifier parsing) and 90c485a (the
// XNP-proxy escape hatch from the permanent fixed-diff pin) into
// leaf-proxy's OWN downstream-serving handleLogin. Before that port,
// handleLogin stored login.Login RAW and looked the ban cache up with
// that same raw string, so a "+50000"/".rig1" suffix both evaded an
// operator ban and was silently discarded instead of honored -- see
// handleLogin's own ParseLoginFields block for the full bug
// description.
//
// The parser itself (solo.ParseLoginFields) and the escape-hatch
// predicate (solo.LoginFields.XNPProxyExemptFromFixedDiffPin) are
// exercised exhaustively in internal/leaflib/solo's own
// loginfields_test.go / xnp_fixeddiff_escape_test.go; this file covers
// leaf-proxy's OWN handleLogin/maybeRetarget path through them, plus
// the leaf-proxy-specific concerns those packages have no equivalent
// of (the addressflags lookup-key ordering, and the upstream-login
// isolation proof).

// xnpProxyDownstreamTestAgent is the real reference xmr-node-proxy
// agent string -- the exact value a NESTED xmr-node-proxy connecting
// to THIS leaf's own downstream listener would send, and (not
// coincidentally) the same string this leaf's own upstream client
// sends to its pool (UpstreamConfig.Agent's doc comment, upstream.go).
const xnpProxyDownstreamTestAgent = "xmr-node-proxy/0.0.3"

// realProxyTestXMRAddress is a real Monero mainnet address -- the same
// one devfee.go already hardcodes as devFeeLogin. leaf-proxy performs
// no address-format validation at all (see handleLogin's length-bound
// comment), so these tests do not depend on it decoding; it is used so
// the login strings under test have realistic shape and length.
const realProxyTestXMRAddress = devFeeLogin

// loginWithFields performs a real downstream login handshake with
// caller-supplied login/pass/rigid/agent values. The harness's own
// c.login helper (session_test.go) hardcodes pass/agent, both of which
// every test below needs to vary -- this is the minimal generalization
// of it rather than a second parallel harness.
func (c *testClient) loginWithFields(t *testing.T, login, pass, rigid, agent string) LoginResponse {
	t.Helper()
	params, err := json.Marshal(LoginRequest{Login: login, Pass: pass, RigID: rigid, Agent: agent})
	if err != nil {
		t.Fatalf("marshal login params: %v", err)
	}
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: params})
	return c.recvLoginResponse()
}

// loginWithFieldsExpectReject is loginWithFields for the rejection
// paths. handleLogin's reject path goes through writeGeneralResponse ->
// leaflib.WriteGeneralResponse with legacy=false, whose wire shape is
// an ErrorResponse (a string "result" plus an error object) -- NOT a
// LoginResponse, so it genuinely cannot be decoded as one. This
// decodes the real shape and returns the error message, mirroring
// addressflags_enforcement_test.go's own existing ErrorResponse-based
// reject assertions.
func (c *testClient) loginWithFieldsExpectReject(t *testing.T, login, pass, rigid, agent string) string {
	t.Helper()
	params, err := json.Marshal(LoginRequest{Login: login, Pass: pass, RigID: rigid, Agent: agent})
	if err != nil {
		t.Fatalf("marshal login params: %v", err)
	}
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: params})

	raw := c.recvRaw()
	var resp ErrorResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("login was NOT rejected -- response %s does not decode as an ErrorResponse: %v", raw, err)
	}
	if resp.Error == nil {
		t.Fatalf("login was NOT rejected -- response %s carries no error object", raw)
	}
	return resp.Error.Message
}

// --- Part 1: the "+<difficulty>" suffix ---------------------------

// TestProxyLogin_FixedDiffSuffixIsHonoredAsStartingDifficulty is the
// core Part 1 test: a downstream login of "<address>+50000" must start
// the session at 50000 rather than the port tier's own configured
// default, and must store the STRIPPED address.
//
// The pool target_diff here is deliberately set ABOVE the requested
// value so the existing pool-diff cap does NOT bind -- the
// cap-DOES-bind case is its own test below, as the brief requires both.
func TestProxyLogin_FixedDiffSuffixIsHonoredAsStartingDifficulty(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: time.Hour,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	const portStartDiff = uint64(1000)
	c, _ := h.connectAtDifficulty(portStartDiff)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"+50000", "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login with a +fixed-difficulty suffix was rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got, _ := sess.address.Load().(string); got != realProxyTestXMRAddress {
		t.Errorf("session address = %q, want the STRIPPED address %q (never the raw login string)", got, realProxyTestXMRAddress)
	}
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested fixed 50000 (not the port tier's %d)", got, portStartDiff)
	}
	if !sess.fixedDiff.Load() {
		t.Error("session fixedDiff = false, want true for an ordinary (non-XNP) miner's explicit +diff request")
	}
	if got, want := resp.Result.Job.Target, leaflib.DiffToTargetHex(50000); got != want {
		t.Errorf("login job target = %q, want %q (difficulty 50000)", got, want)
	}
}

// TestProxyLogin_FixedDiffSuffixIsStillSubjectToPoolDiffCap is the
// other half the brief explicitly asks for: the SAME requested value,
// against a pool target_diff LOW enough that the existing
// poolDiffCapEnabled block genuinely binds. The parsed value must be
// FED INTO that existing logic, not bypass it -- a miner's own request
// cannot exceed what the upstream pool is currently asking for.
func TestProxyLogin_FixedDiffSuffixIsStillSubjectToPoolDiffCap(t *testing.T) {
	const poolTargetDiff = uint64(20_000)

	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: time.Hour,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(poolTargetDiff))

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"+50000", "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != poolTargetDiff {
		t.Fatalf("session currentDifficulty = %d, want it capped down to the pool's own target_diff %d -- the parsed fixed difficulty must feed the EXISTING cap logic, not bypass it", got, poolTargetDiff)
	}
	// Still a fixed-difficulty session: a capped request is still a
	// request (mirrors solo's own clamped-but-still-fixed assertion).
	if !sess.fixedDiff.Load() {
		t.Error("session fixedDiff = false, want true (a capped +diff request is still a fixed-difficulty request)")
	}
	if got, want := resp.Result.Job.Target, leaflib.DiffToTargetHex(poolTargetDiff); got != want {
		t.Errorf("login job target = %q, want %q", got, want)
	}
}

// TestProxyLogin_FixedDiffSuffixIsStillSubjectToForcedFloor proves the
// OTHER pre-existing floor in that same block is likewise undisturbed:
// an operator's forced minimum difficulty outranks a miner's own lower
// request, exactly as it already outranks the port tier's default.
func TestProxyLogin_FixedDiffSuffixIsStillSubjectToForcedFloor(t *testing.T) {
	const operatorFloor = uint64(80_000)

	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: time.Hour,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	// Keyed on the STRIPPED address -- which is exactly the ordering
	// property TestProxyLogin_BanCacheIsKeyedOnTheStrippedAddress
	// below pins independently.
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		realProxyTestXMRAddress: {ForcedMinDifficulty: operatorFloor},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"+50000", "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != operatorFloor {
		t.Fatalf("session currentDifficulty = %d, want the operator's forced floor %d to outrank the miner's own lower +50000 request", got, operatorFloor)
	}
}

// TestProxyLogin_TooManyPlusOptionsIsRejected pins the verbatim legacy
// reject for a login field with more than one "+", and proves no
// session state is established by it.
func TestProxyLogin_TooManyPlusOptionsIsRejected(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	c, _ := h.connectAtDifficulty(1000)
	errMsg := c.loginWithFieldsExpectReject(t, realProxyTestXMRAddress+"+5000+9000", "rig1", "", "XMRig/6.21.0")
	if want := "Too many options in the login field"; errMsg != want {
		t.Fatalf("login error = %q, want the verbatim legacy message %q", errMsg, want)
	}

	sess := h.onlySession()
	if sess != nil && sess.loggedIn.Load() {
		t.Fatal("BUG: a rejected login established logged-in session state")
	}
	if got, want := solo.ErrTooManyLoginOptions.Error(), "Too many options in the login field"; got != want {
		t.Errorf("solo.ErrTooManyLoginOptions = %q, want the verbatim legacy message %q", got, want)
	}
}

// TestProxyLogin_EmptyStrippedAddressIsRejected covers the one check
// leaf-proxy needs that leaf-direct/leaf-solo do not: those leaves
// hand the stripped address straight to a real address validator,
// which rejects "" for them. leaf-proxy deliberately validates no
// address format at all, so without an explicit check a login of
// literally "+50000" (non-empty raw, so past the top-of-function empty
// check) would strip to an EMPTY address and be accepted -- storing ""
// as session state and as the ban-cache lookup key.
func TestProxyLogin_EmptyStrippedAddressIsRejected(t *testing.T) {
	for _, login := range []string{"+50000", ".myrig", "." + realProxyTestXMRAddress} {
		t.Run("login="+login, func(t *testing.T) {
			h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
			c, _ := h.connectAtDifficulty(1000)
			errMsg := c.loginWithFieldsExpectReject(t, login, "rig1", "", "XMRig/6.21.0")
			if want := "invalid address provided, please use a valid address"; errMsg != want {
				t.Errorf("login error = %q, want %q", errMsg, want)
			}
			if sess := h.onlySession(); sess != nil && sess.loggedIn.Load() {
				t.Fatal("BUG: a rejected login established logged-in session state")
			}
		})
	}
}

// --- Part 2: the XNP-proxy escape hatch from the permanent pin ----

// TestProxyLogin_XNPProxyFixedDiffSuffixStartsThereButStaysRetargetable
// is the core Part 2 test (commit 90c485a's own pattern, applied to
// leaf-proxy): a NESTED XNP-proxy-detected downstream client logging
// in with "<address>+<diff>" takes that value as its STARTING
// difficulty but is NOT permanently pinned -- a real vardiff tick
// afterward must retarget it, because the aggregate hashrate behind a
// nested proxy genuinely moves over the life of the connection.
func TestProxyLogin_XNPProxyFixedDiffSuffixStartsThereButStaysRetargetable(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"+50000", "rig1", "", xnpProxyDownstreamTestAgent)
	if resp.Result.Status != "OK" {
		t.Fatalf("XNP-proxy login with a +fixed-difficulty suffix was rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got, _ := sess.address.Load().(string); got != realProxyTestXMRAddress {
		t.Errorf("session address = %q, want the STRIPPED address %q", got, realProxyTestXMRAddress)
	}
	// The operator's requested value IS the starting difficulty --
	// only the permanent pin is withheld.
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000 as the STARTING difficulty", got)
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: an XNP-proxy session was permanently pinned by its login-time +diff suffix -- legacy's proxyAddressList clause exists precisely so an aggregating proxy keeps getting retargeted")
	}

	// The real proof: (600000/90)*30 = 199980, clamped by
	// leaflib.ComputeRetarget's 1.5x step limit to 50000*1.5 = 75000.
	// maybeRetarget runs on its own goroutine because it WILL produce
	// a real job push needing a concurrent reader on the net.Pipe.
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	push := c.recvJobPush()
	<-done

	if got := sess.currentDifficulty.Load(); got != 75000 {
		t.Fatalf("currentDifficulty = %d, want 75000 -- vardiff must remain fully live for an XNP-proxy session", got)
	}
	if want := leaflib.DiffToTargetHex(75000); push.Params.Target != want {
		t.Errorf("pushed job target = %q, want %q", push.Params.Target, want)
	}
}

// TestProxyLogin_OrdinaryMinerFixedDiffSuffixIsStillPermanentlyPinned
// is the critical non-regression proof that the XNP carve-out above
// did not weaken the ordinary single-miner fixed-difficulty request:
// the SAME login string from a non-XNP agent is still pinned and still
// never retargeted. Mirrors 90c485a's own test pattern, including the
// near-miss agent that is the exact boundary this introduces (a
// substring that is genuinely not the real one, and does not contain
// "xmr-node-proxy" case-insensitively either).
//
// NOTE: "XMR-NODE-PROXY/0.0.3" (wrong-case XNP agent) is deliberately
// NOT in this list -- solo.IsXNPProxyAgent is now case-INsensitive
// (product-owner direction, see its doc comment in protocol.go), so
// this agent IS now directly matched by IsXNPProxyAgent and must NOT
// stay pinned. See
// TestProxyLogin_WrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly
// below, which pins that exact, intended behavior.
func TestProxyLogin_OrdinaryMinerFixedDiffSuffixIsStillPermanentlyPinned(t *testing.T) {
	for _, agent := range []string{
		"XMRig/6.21.0",
		"",
		"xmr-node-proxie/0.0.3",
	} {
		t.Run("agent="+agent, func(t *testing.T) {
			h := newHarness(t, leaflib.VardiffConfig{
				MinDifficulty:    100,
				MaxDifficulty:    1_000_000,
				TargetTime:       30,
				RetargetInterval: 60 * time.Second,
			}, 0)
			h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

			c, _ := h.connectAtDifficulty(1000)
			resp := c.loginWithFields(t, realProxyTestXMRAddress+"+50000", "rig1", "", agent)
			if resp.Result.Status != "OK" {
				t.Fatalf("login with a +fixed-difficulty suffix was rejected: %#v", resp)
			}

			sess := h.onlySession()
			if !sess.fixedDiff.Load() {
				t.Fatalf("BUG (regression): a NON-XNP session's +diff request lost its permanent fixed-diff pin; agent %q must not be treated as an XNP proxy", agent)
			}
			if got := sess.currentDifficulty.Load(); got != 50000 {
				t.Errorf("session currentDifficulty = %d, want the requested fixed 50000", got)
			}

			// Safe to run synchronously precisely BECAUSE no push may
			// be produced -- maybeRetarget's own pushJob would block
			// on a reader that isn't there, so a hang here would
			// itself be the bug being tested for.
			sess.connectedAt = time.Now().Add(-90 * time.Second)
			sess.hashesAccumulated.Store(600_000)
			sess.maybeRetarget()
			if got := sess.currentDifficulty.Load(); got != 50000 {
				t.Fatalf("BUG (regression): a NON-XNP fixed-difficulty session was retargeted to %d", got)
			}

			// Also exercise the zero-accept-history branch (the 10%
			// idle reduction), which is the path a genuinely idle
			// fixed-difficulty miner would otherwise hit every tick.
			sess.hashesAccumulated.Store(0)
			sess.maybeRetarget()
			if got := sess.currentDifficulty.Load(); got != 50000 {
				t.Fatalf("BUG (regression): a NON-XNP fixed-difficulty session was retargeted (idle-reduction path) to %d", got)
			}
		})
	}
}

// TestProxyLogin_WrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly pins
// the NEW correct behavior at the exact boundary the case-insensitivity
// change moved for leaf-proxy: a downstream client presenting an agent
// that near-misses the legacy JS reference's case-sensitive XNP literal
// is now matched DIRECTLY by solo.IsXNPProxyAgent (product-owner
// direction -- see that function's doc comment in protocol.go), so its
// fixed-diff unpin comes from XNPProxyExemptFromFixedDiffPin, exactly
// like the canonical-case agent -- mirroring solo/direct's own
// TestLoginWrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly-style
// tests.
func TestProxyLogin_WrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly(t *testing.T) {
	const agent = "XMR-NODE-PROXY/0.0.3"
	if !solo.IsXNPProxyAgent(agent) {
		t.Fatalf("solo.IsXNPProxyAgent(%q) = false, want true -- this predicate is now case-INsensitive per product-owner direction", agent)
	}

	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"+50000", "rig1", "", agent)
	if resp.Result.Status != "OK" {
		t.Fatalf("login with a +fixed-difficulty suffix was rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000 as the STARTING difficulty", got)
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: a wrong-case XNP agent (now matched directly by solo.IsXNPProxyAgent) must be unpinned via XNPProxyExemptFromFixedDiffPin, not left permanently pinned")
	}
}

// TestProxyLogin_OrdinaryLoginVardiffIsStillFullyLive is the
// complementary non-regression proof for the common case: a login with
// no "+" and no "." behaves exactly as it did before this pass --
// same address, same port-tier starting difficulty, no fixed-diff pin,
// and vardiff still fully live (the same accept-history/age setup the
// pinned tests above prove is IGNORED must produce a real retarget
// here).
func TestProxyLogin_OrdinaryLoginVardiffIsStillFullyLive(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("ordinary login was rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got, _ := sess.address.Load().(string); got != realProxyTestXMRAddress {
		t.Errorf("session address = %q, want %q", got, realProxyTestXMRAddress)
	}
	if got, _ := sess.worker.Load().(string); got != "rig1" {
		t.Errorf("session worker = %q, want the password-supplied %q", got, "rig1")
	}
	if got, _ := sess.paymentID.Load().(string); got != "" {
		t.Errorf("session paymentID = %q, want empty", got)
	}
	if sess.fixedDiff.Load() {
		t.Error("session fixedDiff = true, want false for an ordinary login")
	}
	if got := sess.currentDifficulty.Load(); got != 1000 {
		t.Errorf("session currentDifficulty = %d, want the port tier's configured 1000", got)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	push := c.recvJobPush()
	<-done

	if got := sess.currentDifficulty.Load(); got != 1500 {
		t.Fatalf("currentDifficulty = %d, want 1500 -- vardiff must remain fully live for a non-fixed-difficulty session", got)
	}
	if want := leaflib.DiffToTargetHex(1500); push.Params.Target != want {
		t.Errorf("pushed job target = %q, want %q", push.Params.Target, want)
	}
}

// --- Part 3: the "." payment-ID / identifier suffix ---------------

// TestProxyLogin_PaymentIDSuffixIsStrippedAndCaptured covers the
// 64-lowercase-hex second dot-segment: the address is stripped, the
// payment ID is captured, and the WORKER still comes from the password
// field (a payment ID is never a worker name).
func TestProxyLogin_PaymentIDSuffixIsStrippedAndCaptured(t *testing.T) {
	const paymentID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"."+paymentID, "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login with a .paymentID suffix was rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got, _ := sess.address.Load().(string); got != realProxyTestXMRAddress {
		t.Errorf("session address = %q, want the STRIPPED address %q", got, realProxyTestXMRAddress)
	}
	if got, _ := sess.paymentID.Load().(string); got != paymentID {
		t.Errorf("session paymentID = %q, want %q", got, paymentID)
	}
	if got, _ := sess.worker.Load().(string); got != "rig1" {
		t.Errorf("session worker = %q, want the password-supplied %q (a 64-hex segment is a payment ID, never a rig name)", got, "rig1")
	}
}

// TestProxyLogin_DotIdentifierFeedsWorkerWithLegacyPrecedence
// documents and pins THE DECISION the brief asked for explicitly: how
// a parsed ".identifier" interacts with leaf-proxy's pre-existing
// `worker := login.Pass; if login.RigID != "" { worker = login.RigID }`
// logic.
//
// DECISION: the dot-segment identifier feeds that SAME worker value
// (leaf-proxy has no other consumer for it), and only when the
// resolved worker is the legacy "x" sentinel -- i.e. the password/rigid
// field wins whenever the miner actually supplied one. This is
// byte-identical to the precedence leaf-solo and leaf-direct already
// merged for the identical situation (pool.js lines 419-423), and it
// leaves the existing RigID-beats-Pass ordering completely untouched.
// See handleLogin's own comment at that line for the full reasoning.
func TestProxyLogin_DotIdentifierFeedsWorkerWithLegacyPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		pass       string
		rigid      string
		wantWorker string
	}{
		// The legacy "old-logins" sentinel: the dot-identifier wins.
		{"password-x/dot-identifier-wins", "x", "", "myrig01"},
		// No password at all -- handleLogin already substitutes "x",
		// so the dot-identifier wins here too.
		{"empty-password/dot-identifier-wins", "", "", "myrig01"},
		// A real password is a deliberate choice: it wins.
		{"real-password/password-wins", "myrealrig", "", "myrealrig"},
		// An explicit modern "rigid" is the MOST deliberate signal of
		// all: it wins over both, and the pre-existing
		// RigID-beats-Pass ordering is unchanged.
		{"explicit-rigid/rigid-wins-over-dot-identifier", "x", "fromrigid", "fromrigid"},
		{"explicit-rigid-and-password/rigid-still-wins", "myrealrig", "fromrigid", "fromrigid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
			c, _ := h.connectAtDifficulty(1000)
			resp := c.loginWithFields(t, realProxyTestXMRAddress+".myrig01", tc.pass, tc.rigid, "XMRig/6.21.0")
			if resp.Result.Status != "OK" {
				t.Fatalf("login with a .identifier suffix was rejected: %#v", resp)
			}

			sess := h.onlySession()
			if got, _ := sess.address.Load().(string); got != realProxyTestXMRAddress {
				t.Errorf("session address = %q, want the STRIPPED address %q", got, realProxyTestXMRAddress)
			}
			if got, _ := sess.worker.Load().(string); got != tc.wantWorker {
				t.Errorf("session worker = %q, want %q", got, tc.wantWorker)
			}
			if got, _ := sess.paymentID.Load().(string); got != "" {
				t.Errorf("session paymentID = %q, want empty (a non-64-hex segment is a worker name)", got)
			}
		})
	}
}

// TestProxyLogin_CombinedSuffixesAreAllHonored covers the fully-loaded
// real-world shape: "<address>.<paymentID>.<rig>+<diff>" -- every
// suffix parsed, and only the address stored as the address.
func TestProxyLogin_CombinedSuffixesAreAllHonored(t *testing.T) {
	const paymentID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: time.Hour,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"."+paymentID+".myrig01+50000", "x", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("combined-suffix login was rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got, _ := sess.address.Load().(string); got != realProxyTestXMRAddress {
		t.Errorf("session address = %q, want the STRIPPED address %q", got, realProxyTestXMRAddress)
	}
	if got, _ := sess.paymentID.Load().(string); got != paymentID {
		t.Errorf("session paymentID = %q, want %q", got, paymentID)
	}
	if got, _ := sess.worker.Load().(string); got != "myrig01" {
		t.Errorf("session worker = %q, want %q", got, "myrig01")
	}
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000", got)
	}
}

// --- Part 4: the addressflags lookup-key ORDERING bug -------------

// TestProxyLogin_BanCacheIsKeyedOnTheStrippedAddress is the real
// ban-evasion regression test, and the reason the ParseLoginFields
// call is positioned BEFORE the addressflags block in handleLogin
// rather than after it. Before this pass the lookup key was the RAW
// login string, so an operator who banned "<address>" did NOT ban the
// same miner reconnecting as "<address>+50000" (or "<address>.rig1"):
// those were three distinct cache keys.
//
// This test fails against the pre-fix code, which happily logged every
// suffixed variant in.
func TestProxyLogin_BanCacheIsKeyedOnTheStrippedAddress(t *testing.T) {
	suffixes := []string{
		"",
		"+50000",
		".myrig01",
		".0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		".0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.myrig01+50000",
	}
	for _, suffix := range suffixes {
		t.Run("suffix="+suffix, func(t *testing.T) {
			h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

			// The operator banned the BARE address, exactly as they
			// would in reality -- nobody maintains a ban list of every
			// possible suffix permutation.
			src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
				realProxyTestXMRAddress: {Banned: true},
			}}
			cache := addressflags.NewCache(src, 0, nil)
			cache.Start(context.Background())
			h.server.EnableAddressFlags(cache)
			waitForCachePoll(t, cache, realProxyTestXMRAddress, true)

			c, _ := h.connectAtDifficulty(1000)
			errMsg := c.loginWithFieldsExpectReject(t, realProxyTestXMRAddress+suffix, "rig1", "", "XMRig/6.21.0")
			if want := "this address is banned from this pool"; errMsg != want {
				t.Fatalf("BAN EVASION or wrong rejection for login %q: error = %q, want %q -- the ban lookup must use the STRIPPED address", realProxyTestXMRAddress+suffix, errMsg, want)
			}
			if sess := h.onlySession(); sess != nil && sess.loggedIn.Load() {
				t.Fatal("BUG: a banned login established logged-in session state")
			}
		})
	}
}

// TestProxyLogin_ForcedFloorCacheIsKeyedOnTheStrippedAddress is the
// forced-minimum-difficulty half of the same lookup-key fix: an
// operator floor set on the bare address must also apply to a suffixed
// login of that same address.
func TestProxyLogin_ForcedFloorCacheIsKeyedOnTheStrippedAddress(t *testing.T) {
	const operatorFloor = uint64(90_000)

	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		RetargetInterval: time.Hour,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		realProxyTestXMRAddress: {ForcedMinDifficulty: operatorFloor},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+".myrig01", "x", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("login rejected: %#v", resp)
	}

	sess := h.onlySession()
	if got := sess.forcedMinDifficulty.Load(); got != operatorFloor {
		t.Fatalf("session forcedMinDifficulty = %d, want the operator's floor %d found under the STRIPPED address key", got, operatorFloor)
	}
	if got := sess.currentDifficulty.Load(); got != operatorFloor {
		t.Errorf("session currentDifficulty = %d, want the forced floor %d", got, operatorFloor)
	}
}
