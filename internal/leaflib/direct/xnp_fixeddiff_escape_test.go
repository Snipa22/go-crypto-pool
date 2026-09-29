// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"math"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- XNP-proxy escape hatch from the permanent fixed-difficulty pin ---
//
// leaf-direct's own integration of the identical carve-out leaf-solo
// applies (solo.LoginFields.XNPProxyExemptFromFixedDiffPin -- see that
// method's doc comment for the verbatim legacy `proxyAddressList`
// citation from retargetMiners and the mechanism-divergence
// rationale). The predicate and the XNP detection it composes
// (solo.IsXNPProxyAgent) are exercised exhaustively in
// internal/leaflib/solo/xnp_fixeddiff_escape_test.go; this file covers
// leaf-direct's own handleLogin/maybeRetarget path through them.

// xnpProxyDirectTestAgent is the real reference xmr-node-proxy agent
// string (see the solo-side constant's own comment).
const xnpProxyDirectTestAgent = "xmr-node-proxy/0.0.3"

// TestDirectLoginXNPProxyFixedDiffSuffixStartsThereButStaysRetargetable
// is the core regression test: an XNP-proxy-detected session logging in
// with "<address>+<diff>" takes that value as its STARTING difficulty
// but is NOT permanently pinned -- a real vardiff tick afterward must
// retarget it.
//
// Harness pattern lifted verbatim from
// TestDirectLoginOrdinaryAddressIsByteForByteUnchanged's own
// live-vardiff proof (loginfields_test.go): maybeRetarget runs on its
// own goroutine because it WILL produce a real job push needing a
// concurrent reader on the net.Pipe.
func TestDirectLoginXNPProxyFixedDiffSuffixStartsThereButStaysRetargetable(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("direct-login-xnp-proxy-fixed-diff")
	sess := directLoginRawFields(t, h, addr+"+50000", "rig1", xnpProxyDirectTestAgent, "sha3x")
	if sess == nil {
		t.Fatal("XNP-proxy login with a +fixed-difficulty suffix was rejected")
	}

	if got := sess.Identity().Address; got != addr {
		t.Errorf("session address = %q, want the STRIPPED address %q", got, addr)
	}
	// The operator's requested value IS the starting difficulty --
	// only the permanent pin is withheld.
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000 as the STARTING difficulty", got)
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: an XNP-proxy session was permanently pinned by its login-time +diff suffix -- legacy's proxyAddressList clause exists precisely so an aggregating proxy keeps getting retargeted")
	}

	// The real proof: BRIEF.md "proxy-aware vardiff target time"
	// forces this XNP-agent-detected session's target time to
	// proxyForcedTargetTimeSeconds (10), unconditionally overriding
	// the harness's configured cfg.TargetTime (30):
	// (600000/90)*10 = 66660, which does not hit the 1.5x step
	// limit (50000*1.5 = 75000) at all, unlike the pre-this-brief
	// 30s-target-time math this test used to assert (199980, clamped
	// to 75000).
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	push := h.recvJobPush()
	<-done
	if got := sess.currentDifficulty.Load(); got != 66660 {
		t.Fatalf("currentDifficulty = %d, want 66660 (10s forced target time) -- vardiff must remain fully live for an XNP-proxy session", got)
	}
	if want := leaflib.DiffToTargetHex(66660); push.Params.Target != want {
		t.Errorf("pushed job target = %q, want %q", push.Params.Target, want)
	}
}

// TestDirectLoginXNPProxyExemptionIsAlgoAgnostic covers the same
// carve-out on RXM -- the algo a real xmr-node-proxy actually
// aggregates, and where jobPayload's OTHER, pre-existing
// solo.IsXNPProxyAgent-gated feature (the raw-template-blob/reservation
// offsets) is simultaneously active. Both must hold at once.
func TestDirectLoginXNPProxyExemptionIsAlgoAgnostic(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, solo.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	sess := directLoginRawFields(t, h, realDirectXMRMainnetAddr+"+50000", "rig1", xnpProxyDirectTestAgent, "rx/0")
	if sess == nil {
		t.Fatal("XNP-proxy RXM login with a +fixed-difficulty suffix was rejected")
	}
	if got := sess.Identity().Address; got != realDirectXMRMainnetAddr {
		t.Errorf("session address = %q, want the miner's own real address %q", got, realDirectXMRMainnetAddr)
	}
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000", got)
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: an XNP-proxy RXM session was permanently pinned by its login-time +diff suffix")
	}
}

// TestDirectLoginGenericProxyFixedDiffSuffixStartsThereButStaysRetargetable
// mirrors TestDirectLoginXNPProxyFixedDiffSuffixStartsThereButStaysRetargetable
// exactly, but for the new, ADDITIVE generic-proxy carve-out
// (solo.LoginFields.GenericProxyExemptFromFixedDiffPin /
// solo.IsGenericProxyAgent): a non-XNP agent that merely contains
// "proxy" (case-varied) still gets its "+<difficulty>" login-suffix
// value as its STARTING difficulty, but is likewise NOT permanently
// pinned -- normal vardiff retargeting keeps running for the life of
// the connection.
func TestDirectLoginGenericProxyFixedDiffSuffixStartsThereButStaysRetargetable(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("direct-login-generic-proxy-fixed-diff")
	// Mixed case, non-XNP, "claims to be a proxy" agent.
	sess := directLoginRawFields(t, h, addr+"+50000", "rig1", "SomeProxyThing/1.0", "sha3x")
	if sess == nil {
		t.Fatal("generic-proxy login with a +fixed-difficulty suffix was rejected")
	}

	if got := sess.Identity().Address; got != addr {
		t.Errorf("session address = %q, want the STRIPPED address %q", got, addr)
	}
	// The operator's requested value IS the starting difficulty --
	// only the permanent pin is withheld.
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000 as the STARTING difficulty", got)
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: a generic-proxy-claiming session was permanently pinned by its login-time +diff suffix -- the generic carve-out exists precisely so it keeps getting retargeted, same as XNP")
	}

	// The real proof: same math as the XNP case -- BRIEF.md
	// "proxy-aware vardiff target time" forces this generic-proxy-
	// detected session's target time to proxyForcedTargetTimeSeconds
	// (10) too: (600000/90)*10 = 66660, which does not hit the 1.5x
	// step limit (50000*1.5 = 75000) at all.
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	push := h.recvJobPush()
	<-done
	if got := sess.currentDifficulty.Load(); got != 66660 {
		t.Fatalf("currentDifficulty = %d, want 66660 (10s forced target time) -- vardiff must remain fully live for a generic-proxy-claiming session", got)
	}
	if want := leaflib.DiffToTargetHex(66660); push.Params.Target != want {
		t.Errorf("pushed job target = %q, want %q", push.Params.Target, want)
	}
}

// TestDirectLoginOrdinaryMinerFixedDiffSuffixIsStillPermanentlyPinned
// is the critical regression-proof that this XNP carve-out did not
// weaken the ordinary single-miner fixed-difficulty request: the SAME
// login string from a non-XNP agent is still pinned and still never
// retargeted, exactly as commit 9196a5a intended. The agent list
// includes the near-miss cases (wrong case, near-miss substring) that
// are the exact boundary this fix introduced.
func TestDirectLoginOrdinaryMinerFixedDiffSuffixIsStillPermanentlyPinned(t *testing.T) {
	for _, agent := range []string{
		"XMRig/6.21.0",
		"",
		// "xmr-node-proxie/0.0.3" is a near-miss substring that
		// matches neither carve-out (no "proxy" case-insensitively
		// either), so it must stay pinned.
		//
		// NOTE: "XMR-NODE-PROXY/0.0.3" is deliberately NOT in this
		// list -- solo.IsXNPProxyAgent is now case-INsensitive
		// (product-owner direction), so this agent is now directly
		// matched by solo.IsXNPProxyAgent and must NOT stay pinned.
		// See
		// TestDirectLoginWrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly
		// below.
		"xmr-node-proxie/0.0.3",
	} {
		t.Run("agent="+agent, func(t *testing.T) {
			h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
				MinDifficulty:    100,
				MaxDifficulty:    1_000_000,
				TargetTime:       30,
				RetargetInterval: 60 * time.Second,
			})
			addr := realTariTestAddress("direct-login-nonxnp-still-pinned-" + agent)
			sess := directLoginRawFields(t, h, addr+"+50000", "rig1", agent, "sha3x")
			if sess == nil {
				t.Fatal("login with a +fixed-difficulty suffix was rejected")
			}
			if !sess.fixedDiff.Load() {
				t.Fatalf("BUG (regression): a NON-XNP session's +diff request lost its permanent fixed-diff pin; agent %q must not be treated as an XNP proxy", agent)
			}
			if got := sess.currentDifficulty.Load(); got != 50000 {
				t.Errorf("session currentDifficulty = %d, want the requested fixed 50000", got)
			}

			// Safe synchronously precisely BECAUSE no push may be
			// produced -- a hang here would itself be the bug.
			sess.connectedAt = time.Now().Add(-90 * time.Second)
			sess.hashesAccumulated.Store(600_000)
			sess.maybeRetarget()
			if got := sess.currentDifficulty.Load(); got != 50000 {
				t.Fatalf("BUG (regression): a NON-XNP fixed-difficulty session was retargeted to %d", got)
			}
			sess.hashesAccumulated.Store(0)
			sess.maybeRetarget()
			if got := sess.currentDifficulty.Load(); got != 50000 {
				t.Fatalf("BUG (regression): a NON-XNP fixed-difficulty session was retargeted (idle-reduction path) to %d", got)
			}
		})
	}
}

// TestDirectLoginWrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly
// mirrors solo's own
// TestLoginWrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly (renamed
// from TestDirectLoginWrongCaseXNPAgentIsUnpinnedByGenericCarveOut,
// whose old name no longer describes what it proves): an agent that
// near-misses the legacy JS reference's case-sensitive XNP literal is
// now matched DIRECTLY by solo.IsXNPProxyAgent (product-owner
// direction), and is therefore EXCLUDED from solo.IsGenericProxyAgent,
// so its fixed-diff unpin now comes from
// solo.LoginFields.XNPProxyExemptFromFixedDiffPin, not
// GenericProxyExemptFromFixedDiffPin.
func TestDirectLoginWrongCaseXNPAgentIsUnpinnedByXNPCarveOutDirectly(t *testing.T) {
	const agent = "XMR-NODE-PROXY/0.0.3"
	if !solo.IsXNPProxyAgent(agent) {
		t.Fatalf("solo.IsXNPProxyAgent(%q) = false, want true -- this predicate is now case-INsensitive per product-owner direction", agent)
	}
	if solo.IsGenericProxyAgent(agent) {
		t.Fatalf("solo.IsGenericProxyAgent(%q) = true, want false -- IsXNPProxyAgent now owns this agent directly, so the generic carve-out must exclude it", agent)
	}

	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("direct-login-wrongcase-xnp-agent-direct-unpin")
	sess := directLoginRawFields(t, h, addr+"+50000", "rig1", agent, "sha3x")
	if sess == nil {
		t.Fatal("login with a +fixed-difficulty suffix was rejected")
	}
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000 as the STARTING difficulty", got)
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: a wrong-case XNP agent (now matched directly by solo.IsXNPProxyAgent) must be unpinned via XNPProxyExemptFromFixedDiffPin, not left permanently pinned")
	}
}

// TestDirectLoginNiceHashXNPAgentIsStillPermanentlyPinned proves the
// NiceHash-agent fixed-diff branch is untouched by this carve-out even
// for an XNP-detected session: the exemption is scoped to the
// login-string "+diff" suffix path only. (A single agent containing
// both markers is synthetic -- it exists purely to exercise the
// predicate's FixedDiffFromLoginSuffix half at the real session level.)
func TestDirectLoginNiceHashXNPAgentIsStillPermanentlyPinned(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, solo.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	sess := directLoginRawFields(t, h, realDirectXMRMainnetAddr, "rig1", "NiceHashMiner/3.0-xmr-node-proxy", "rx/0")
	if sess == nil {
		t.Fatal("login was rejected")
	}
	if !sess.fixedDiff.Load() {
		t.Fatal("BUG: a NiceHash-assigned fixed difficulty lost its pin -- the XNP exemption must cover the login-string +diff suffix path ONLY")
	}
	if got := sess.currentDifficulty.Load(); got != solo.LegacyNiceHashDifficulty {
		t.Errorf("session currentDifficulty = %d, want the cited NiceHash constant %d", got, solo.LegacyNiceHashDifficulty)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != solo.LegacyNiceHashDifficulty {
		t.Fatalf("BUG: a NiceHash fixed-difficulty session was retargeted to %d", got)
	}
}
