// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// submitLocalShare drives sess through a real getjob + submit
// round-trip for a share comfortably below the harness's upstream
// target_diff (1,000,000) but above its starting difficulty (1000) --
// a real, locally-credited-only share that increments
// sess.shareCount exactly like TestSession_LoginGetJobSubmit_FullFlow
// (session_test.go) already proves. Used by the tests below purely to
// get a session's shareCount above 0; the accept/local-vs-upstream
// distinction itself is already covered elsewhere and is not this
// file's concern.
func submitLocalShare(t *testing.T, c *testClient, loginResp LoginResponse) {
	t.Helper()
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "getjob"})
	jobPush := c.recvJobPush()
	claimedHash := hashForDifficulty(50_000)
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobPush.Params.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 3, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	shareResp := c.recvShareResponse()
	if shareResp.Result == nil {
		t.Fatalf("expected the submit to be accepted, got error=%v", shareResp.Error)
	}
}

// TestMetricsMinSharesFilter_DefaultOff_ByteIdenticalToExistingBehavior
// is DISPATCH_BRIEF_MIN_SHARE_FILTER.md's required "filter OFF
// (default)" regression test: a zero-share session (logged in, never
// submitted) must still show up in Stats() AND sessionSnapshots()
// exactly as it always has, since SetMetricsMinSharesFilter is never
// called here (the filter's zero value is false).
func TestMetricsMinSharesFilter_DefaultOff_ByteIdenticalToExistingBehavior(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	c, _ := h.connect()
	loginResp := c.login(t, "min-shares-filter-default-off-addr")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}
	if got := sess.shareCount.Load(); got != 0 {
		t.Fatalf("test setup bug: expected a zero-share session, got shareCount=%d", got)
	}

	st := h.server.Stats()
	if st.ActiveSessions != 1 {
		t.Errorf("Stats().ActiveSessions = %d, want 1 (filter is off by default, the zero-share session must still count)", st.ActiveSessions)
	}
	if len(st.Sessions) != 1 {
		t.Errorf("len(Stats().Sessions) = %d, want 1", len(st.Sessions))
	}
	if len(st.MinersByAddress) != 1 || st.MinersByAddress[0].Address != "min-shares-filter-default-off-addr" {
		t.Errorf("Stats().MinersByAddress = %+v, want exactly one entry for the zero-share session's address", st.MinersByAddress)
	}
	if st.UniqueRemoteIPs != 1 {
		t.Errorf("Stats().UniqueRemoteIPs = %d, want 1", st.UniqueRemoteIPs)
	}

	snaps := h.server.sessionSnapshots()
	if len(snaps) != 1 {
		t.Errorf("len(sessionSnapshots()) = %d, want 1 (filter is off by default)", len(snaps))
	}
}

// TestMetricsMinSharesFilter_Enabled_ExcludesZeroShareSession is
// DISPATCH_BRIEF_MIN_SHARE_FILTER.md's required "filter ON" regression
// test: once SetMetricsMinSharesFilter(true) is set, a zero-share
// session must be invisible from Stats().ActiveSessions/.Sessions/
// .MinersByAddress/.UniqueRemoteIPs AND from sessionSnapshots()'s
// output -- every one of these surfaces goes through the single
// countableSessions choke point (server.go), so this one test
// exercises all of them against the exact same underlying session.
func TestMetricsMinSharesFilter_Enabled_ExcludesZeroShareSession(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.SetMetricsMinSharesFilter(true)

	c, _ := h.connect()
	loginResp := c.login(t, "min-shares-filter-enabled-addr")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}
	if got := sess.shareCount.Load(); got != 0 {
		t.Fatalf("test setup bug: expected a zero-share session, got shareCount=%d", got)
	}

	// --- filter ON, zero shares: invisible everywhere ---

	st := h.server.Stats()
	if st.ActiveSessions != 0 {
		t.Errorf("Stats().ActiveSessions = %d, want 0 (a zero-share session must be invisible once the filter is enabled)", st.ActiveSessions)
	}
	if len(st.Sessions) != 0 {
		t.Errorf("len(Stats().Sessions) = %d, want 0", len(st.Sessions))
	}
	if len(st.MinersByAddress) != 0 {
		t.Errorf("Stats().MinersByAddress = %+v, want empty", st.MinersByAddress)
	}
	if st.UniqueRemoteIPs != 0 {
		t.Errorf("Stats().UniqueRemoteIPs = %d, want 0", st.UniqueRemoteIPs)
	}

	snaps := h.server.sessionSnapshots()
	if len(snaps) != 0 {
		t.Errorf("len(sessionSnapshots()) = %d, want 0 (a zero-share session must be invisible from the Prometheus snapshot-derived metrics too)", len(snaps))
	}

	// --- same session, now with >= 1 share: visible again everywhere ---

	submitLocalShare(t, c, loginResp)
	if got := sess.shareCount.Load(); got == 0 {
		t.Fatal("test setup bug: expected shareCount > 0 after submitLocalShare")
	}

	st = h.server.Stats()
	if st.ActiveSessions != 1 {
		t.Errorf("after a real share: Stats().ActiveSessions = %d, want 1", st.ActiveSessions)
	}
	if len(st.Sessions) != 1 {
		t.Errorf("after a real share: len(Stats().Sessions) = %d, want 1", len(st.Sessions))
	}
	if len(st.MinersByAddress) != 1 || st.MinersByAddress[0].Address != "min-shares-filter-enabled-addr" {
		t.Errorf("after a real share: Stats().MinersByAddress = %+v, want exactly one entry for the now-countable session's address", st.MinersByAddress)
	}
	if st.UniqueRemoteIPs != 1 {
		t.Errorf("after a real share: Stats().UniqueRemoteIPs = %d, want 1", st.UniqueRemoteIPs)
	}

	snaps = h.server.sessionSnapshots()
	if len(snaps) != 1 {
		t.Errorf("after a real share: len(sessionSnapshots()) = %d, want 1", len(snaps))
	}
}
