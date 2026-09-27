// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"math"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- XNP-proxy escape hatch from the permanent fixed-difficulty pin ---
//
// These pin the real legacy `proxyAddressList` clause of
// retargetMiners (/workspace/nodejs-pool-sxmr/lib/pool.js ~227-236)
// that LoginFields.XNPProxyExemptFromFixedDiffPin implements in terms
// of this leaf's own agent-string XNP detection
// (protocol.go's IsXNPProxyAgent) -- see that method's doc comment for
// the full citation and mechanism-divergence rationale.
//
// The xnpProxyTestAgent constant below is the real agent string the
// reference xmr-node-proxy sends (github.com/Snipa22/xmr-node-proxy,
// proxy.js) and that this repo's own leaf-proxy mode deliberately
// embeds in its upstream agent too (proxy/upstream.go's
// UpstreamConfig.Agent) precisely so a pool's agent sniffing grants it
// the advanced-client treatment.
const xnpProxyTestAgent = "xmr-node-proxy/0.0.3"

// --- Pure parser/predicate level ---

// TestLoginFieldsFixedDiffSourceIsDistinguishable pins the new
// FixedDiffFromLoginSuffix discriminator: it must be true ONLY when
// the "+<difficulty>" login suffix is what set FixedDiff, never for a
// NiceHash-agent-assigned fixed difficulty. Without that distinction
// the XNP escape hatch below could not be scoped to the suffix path
// alone (which is the whole point -- NiceHash is a genuine per-rental
// fixed-difficulty market maker, not an aggregating proxy).
func TestLoginFieldsFixedDiffSourceIsDistinguishable(t *testing.T) {
	cases := []struct {
		name           string
		algo           poolpb.Algo
		login          string
		agent          string
		wantFixed      bool
		wantFromSuffix bool
	}{
		{
			name:           "plain-login/no-fixed-diff-at-all",
			algo:           poolpb.Algo_ALGO_RXM,
			login:          realXMRMainnetAddr,
			agent:          "XMRig/6.21.0",
			wantFixed:      false,
			wantFromSuffix: false,
		},
		{
			name:           "plus-suffix/suffix-driven",
			algo:           poolpb.Algo_ALGO_RXM,
			login:          realXMRMainnetAddr + "+50000",
			agent:          "XMRig/6.21.0",
			wantFixed:      true,
			wantFromSuffix: true,
		},
		{
			name:           "nicehash-agent-only/NOT-suffix-driven",
			algo:           poolpb.Algo_ALGO_RXM,
			login:          realXMRMainnetAddr,
			agent:          "NiceHashMiner/3.0",
			wantFixed:      true,
			wantFromSuffix: false,
		},
		{
			name: "nicehash-agent-plus-suffix/suffix-driven-because-the-suffix-won",
			algo: poolpb.Algo_ALGO_RXM,
			// Legacy's own ordering (pool.js 392-411) has the "+"
			// split OVERWRITE the NiceHash default, so the pin that
			// results is the suffix's pin -- see
			// FixedDiffFromLoginSuffix's doc comment.
			login:          realXMRMainnetAddr + "+50000",
			agent:          "NiceHashMiner/3.0",
			wantFixed:      true,
			wantFromSuffix: true,
		},
		{
			name:           "xnp-agent-plus-suffix/suffix-driven",
			algo:           poolpb.Algo_ALGO_RXM,
			login:          realXMRMainnetAddr + "+50000",
			agent:          xnpProxyTestAgent,
			wantFixed:      true,
			wantFromSuffix: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseLoginFields(tc.algo, tc.login, tc.agent, 5000, 100, 1_000_000)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.FixedDiff != tc.wantFixed {
				t.Errorf("FixedDiff = %v, want %v", got.FixedDiff, tc.wantFixed)
			}
			if got.FixedDiffFromLoginSuffix != tc.wantFromSuffix {
				t.Errorf("FixedDiffFromLoginSuffix = %v, want %v", got.FixedDiffFromLoginSuffix, tc.wantFromSuffix)
			}
		})
	}
}

// TestXNPProxyExemptFromFixedDiffPinPredicate pins the escape-hatch
// predicate itself across every combination that matters, including
// the two ways it must stay CLOSED (non-XNP agent; NiceHash-only fixed
// diff) and the case-sensitivity it inherits from IsXNPProxyAgent.
func TestXNPProxyExemptFromFixedDiffPinPredicate(t *testing.T) {
	cases := []struct {
		name   string
		fields LoginFields
		agent  string
		want   bool
	}{
		{
			name:   "xnp-agent/suffix-driven-fixed-diff/EXEMPT",
			fields: LoginFields{FixedDiff: true, FixedDiffFromLoginSuffix: true},
			agent:  xnpProxyTestAgent,
			want:   true,
		},
		{
			name:   "ordinary-miner/suffix-driven-fixed-diff/PINNED",
			fields: LoginFields{FixedDiff: true, FixedDiffFromLoginSuffix: true},
			agent:  "XMRig/6.21.0",
			want:   false,
		},
		{
			name:   "xnp-agent/nicehash-driven-fixed-diff/PINNED",
			fields: LoginFields{FixedDiff: true, FixedDiffFromLoginSuffix: false},
			agent:  xnpProxyTestAgent,
			want:   false,
		},
		{
			name:   "xnp-agent/no-fixed-diff-at-all/nothing-to-exempt",
			fields: LoginFields{},
			agent:  xnpProxyTestAgent,
			want:   false,
		},
		{
			name: "wrong-case-agent/PINNED",
			// IsXNPProxyAgent is case-sensitive on purpose (real
			// reference uses JS String.includes) -- the exemption must
			// inherit that exactly, not quietly widen it.
			fields: LoginFields{FixedDiff: true, FixedDiffFromLoginSuffix: true},
			agent:  "XMR-NODE-PROXY/0.0.3",
			want:   false,
		},
		{
			name:   "xnp-substring-anywhere-in-agent/EXEMPT",
			fields: LoginFields{FixedDiff: true, FixedDiffFromLoginSuffix: true},
			agent:  "some-wrapper/xmr-node-proxy/2.0.0",
			want:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fields.XNPProxyExemptFromFixedDiffPin(tc.agent); got != tc.want {
				t.Errorf("XNPProxyExemptFromFixedDiffPin(%q) = %v, want %v", tc.agent, got, tc.want)
			}
		})
	}
}

// --- Session-level integration: the real handleLogin + maybeRetarget ---

// TestLoginXNPProxyFixedDiffSuffixStartsThereButStaysRetargetable is
// the core regression test for this fix: an XNP-proxy-detected session
// logging in with "<address>+<diff>" must take that value as its
// STARTING difficulty (the operator asked to skip the vardiff ramp-up
// curve for a connection that starts at a huge aggregate hashrate --
// that part of the request is honored) but must NOT be permanently
// pinned: a real vardiff tick afterward must retarget it, exactly as
// it would any ordinary session.
//
// Harness pattern is lifted verbatim from
// TestLoginOrdinaryAddressIsByteForByteUnchanged's own live-vardiff
// proof (loginfields_test.go): maybeRetarget runs on its own goroutine
// because it WILL produce a real job push that needs a concurrent
// reader on the net.Pipe.
func TestLoginXNPProxyFixedDiffSuffixStartsThereButStaysRetargetable(t *testing.T) {
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("login-xnp-proxy-fixed-diff")
	c, sess, resp := h.loginRaw(addr+"+50000", "rig1", xnpProxyTestAgent)
	if sess == nil {
		t.Fatalf("XNP-proxy login with a +fixed-difficulty suffix was rejected: %#v", resp)
	}

	if got := sess.address.Load().(string); got != addr {
		t.Errorf("session address = %q, want the STRIPPED address %q", got, addr)
	}
	// The operator's requested value IS the starting difficulty --
	// only the permanent pin is withheld.
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000 as the STARTING difficulty", got)
	}
	if got := resp.Result.Job.Target; got != leaflib.DiffToTargetHex(50000) {
		t.Errorf("login job target = %q, want %q (difficulty 50000)", got, leaflib.DiffToTargetHex(50000))
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: an XNP-proxy session was permanently pinned by its login-time +diff suffix -- legacy's proxyAddressList clause exists precisely so an aggregating proxy keeps getting retargeted")
	}

	// And now the real proof: a genuine vardiff retarget tick MUST
	// move this session's difficulty. Same accept-history/age setup
	// the fixed-diff tests prove is ignored for a pinned session:
	// (600000/90)*30 = 199980, clamped by the 1.5x step limit to
	// 50000*1.5 = 75000.
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

// TestLoginXNPProxyExemptionIsAlgoAgnostic covers the same carve-out on
// a Monero-family algo (RXM), which is the algo a real xmr-node-proxy
// actually aggregates -- and where jobPayload's OTHER, pre-existing
// IsXNPProxyAgent-gated feature (the raw-template-blob/reservation
// offsets) is simultaneously active. The two must coexist: the proxy
// still gets its XNP job shape AND stays retargetable.
func TestLoginXNPProxyExemptionIsAlgoAgnostic(t *testing.T) {
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	_, sess, resp := h.loginRaw(realXMRMainnetAddr+"+50000", "rig1", xnpProxyTestAgent)
	if sess == nil {
		t.Fatalf("XNP-proxy RXM login with a +fixed-difficulty suffix was rejected: %#v", resp)
	}
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested 50000", got)
	}
	if sess.fixedDiff.Load() {
		t.Fatal("BUG: an XNP-proxy RXM session was permanently pinned by its login-time +diff suffix")
	}
}

// TestLoginOrdinaryMinerFixedDiffSuffixIsStillPermanentlyPinned is the
// critical regression-proof that this XNP carve-out did NOT weaken the
// ordinary single-miner fixed-difficulty request one bit: the SAME
// login string, from a non-XNP agent, must still be pinned and must
// still never be retargeted -- exactly as commit 9196a5a intended.
//
// This deliberately duplicates
// TestLoginFixedDifficultySuffixIsHonoredAndVardiffIsSkipped's
// assertions on purpose: that test proves the pin works, this one
// proves it is still reached when the agent is merely NEAR-miss
// XNP-looking, which is the exact boundary this fix introduced.
func TestLoginOrdinaryMinerFixedDiffSuffixIsStillPermanentlyPinned(t *testing.T) {
	for _, agent := range []string{
		"XMRig/6.21.0",
		"",
		// Case matters (IsXNPProxyAgent is case-sensitive, matching
		// the real JS reference) -- this is NOT an XNP proxy.
		"XMR-NODE-PROXY/0.0.3",
		// A near-miss substring that is genuinely not the real one.
		"xmr-node-proxie/0.0.3",
	} {
		t.Run("agent="+agent, func(t *testing.T) {
			h := newLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, VardiffConfig{
				MinDifficulty:    100,
				MaxDifficulty:    1_000_000,
				TargetTime:       30,
				RetargetInterval: 60 * time.Second,
			})
			addr := realTariTestAddress("login-nonxnp-still-pinned-" + agent)
			_, sess, resp := h.loginRaw(addr+"+50000", "rig1", agent)
			if sess == nil {
				t.Fatalf("login with a +fixed-difficulty suffix was rejected: %#v", resp)
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

// TestLoginNiceHashXNPAgentIsStillPermanentlyPinned proves the
// NiceHash-agent fixed-diff branch is completely untouched by this
// XNP-specific carve-out, even for a session that IS XNP-detected: the
// exemption is scoped to the login-string "+diff" suffix path only, so
// a NiceHash-assigned fixed difficulty stays pinned at the cited
// LegacyNiceHashDifficulty constant regardless of agent-based proxy
// detection.
//
// (A single agent string containing BOTH markers is admittedly
// synthetic -- it exists here purely to exercise the predicate's
// FixedDiffFromLoginSuffix half at the real session level, where no
// other combination can reach it.)
func TestLoginNiceHashXNPAgentIsStillPermanentlyPinned(t *testing.T) {
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	_, sess, resp := h.loginRaw(realXMRMainnetAddr, "rig1", "NiceHashMiner/3.0-xmr-node-proxy")
	if sess == nil {
		t.Fatalf("login was rejected: %#v", resp)
	}
	if !sess.fixedDiff.Load() {
		t.Fatal("BUG: a NiceHash-assigned fixed difficulty lost its pin -- the XNP exemption must cover the login-string +diff suffix path ONLY")
	}
	if got := sess.currentDifficulty.Load(); got != LegacyNiceHashDifficulty {
		t.Errorf("session currentDifficulty = %d, want the cited NiceHash constant %d", got, LegacyNiceHashDifficulty)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != LegacyNiceHashDifficulty {
		t.Fatalf("BUG: a NiceHash fixed-difficulty session was retargeted to %d", got)
	}
}
