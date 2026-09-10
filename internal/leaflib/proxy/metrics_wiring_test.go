// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
)

// TestServer_EnableMetrics_SharesTotalIncrementsOnRealAcceptReject is
// the required Fix 9 test (DISPATCH_BRIEF.md 2026-09-10): the
// previously-missing accept/reject SharesTotal counter increments on
// real handleSubmit/writeShareResponse outcomes, distinct from
// ShareDecisionsTotal (which tracks local-credit vs upstream-forward,
// not accept/reject).
func TestServer_EnableMetrics_SharesTotalIncrementsOnRealAcceptReject(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	loginResp := c.login(t, "addr-shares-metric")

	// A real accepted (below-target, local-credit) share.
	claimedHash := hashForDifficulty(500_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result == nil {
		t.Fatalf("expected accepted share, got error=%v", resp.Error)
	}

	// A real rejected share (duplicate nonce -- the same nonce
	// re-submitted against the same job).
	c.send(Request{ID: 3, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result != nil {
		t.Fatal("expected the duplicate-nonce resubmit to be rejected")
	}

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_shares_total{result="accepted"} 1`) {
		t.Errorf("expected leaf_proxy_shares_total{result=\"accepted\"} 1, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_proxy_shares_total{result="rejected"} 1`) {
		t.Errorf("expected leaf_proxy_shares_total{result=\"rejected\"} 1, got:\n%s", body)
	}
}

// TestServer_EnableMetrics_BlocksTotalIncrementsOnRealUpstreamOutcome
// is the required Fix 9 test: the previously-no-op recordBlock now
// increments a real counter on genuine block-level upstream-forward
// outcomes, both accepted and rejected by the (fake) upstream pool.
func TestServer_EnableMetrics_BlocksTotalIncrementsOnRealUpstreamOutcome(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)
	h.upstream.accept = true

	c, _ := h.connect()
	loginResp := c.login(t, "addr-blocks-metric-accept")
	claimedHash := hashForDifficulty(2_000_000) // above the 1,000,000 upstream block target
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result == nil {
		t.Fatalf("expected an accepted block-level find, got error=%v", resp.Error)
	}

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_blocks_total{result="accepted"} 1`) {
		t.Errorf("expected leaf_proxy_blocks_total{result=\"accepted\"} 1, got:\n%s", body)
	}

	// A second session, this time the (fake) upstream pool rejects
	// the block-level submit with a real error (mirrors
	// UpstreamClient.SubmitShare's real contract: a non-nil error is
	// what handleSubmit's own branch actually checks -- the bool
	// return value alone, with a nil error, is not itself a
	// rejection signal in this leaf's real upstream client).
	h.upstream.err = errors.New("upstream rejected submit: share does not meet configured difficulty")
	c2, _ := h.connect()
	loginResp2 := c2.login(t, "addr-blocks-metric-reject")
	claimedHash2 := hashForDifficulty(2_000_000)
	submitParams2, _ := json.Marshal(SubmitRequest{ID: loginResp2.Result.ID, JobID: loginResp2.Result.Job.JobID, Nonce: nonceHexAt(2), Result: claimedHash2})
	c2.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams2})
	if resp := c2.recvShareResponse(); resp.Result != nil {
		t.Fatal("expected the block-level submit to be rejected by the (fake) upstream pool")
	}

	body = scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_blocks_total{result="rejected"} 1`) {
		t.Errorf("expected leaf_proxy_blocks_total{result=\"rejected\"} 1, got:\n%s", body)
	}
}

// TestServer_EnableMetrics_BanRejectionsTotal_LoginAndSubmitPhases is
// the required Fix 9 test: the previously log-only ban-rejection
// points at both login time and submit time now increment a real
// counter, labeled by phase.
func TestServer_EnableMetrics_BanRejectionsTotal_LoginAndSubmitPhases(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	bannedAtLogin := "banned-at-login-metric"
	bannedMidSession := "banned-mid-session-metric"
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		bannedAtLogin: {Banned: true},
	}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)
	h.server.EnableAddressFlags(cache)

	// Login-phase rejection.
	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: bannedAtLogin, Pass: "rig1", Agent: "XMRig/6.21.0"})})
	var resp ErrorResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		t.Fatalf("unmarshal login rejection response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected the banned-at-login address to be rejected")
	}

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_ban_rejections_total{phase="login"} 1`) {
		t.Errorf("expected leaf_proxy_ban_rejections_total{phase=\"login\"} 1, got:\n%s", body)
	}

	// Submit-phase rejection: log in while unbanned, then get banned
	// mid-session.
	c2, _ := h.connect()
	loginResp2 := c2.login(t, bannedMidSession)
	if loginResp2.Result.Status != "OK" {
		t.Fatalf("setup: expected login to succeed while unbanned, got status=%q", loginResp2.Result.Status)
	}
	jobID := loginResp2.Result.Job.JobID

	src.set(bannedMidSession, addressflags.Flags{Banned: true})
	waitForCachePoll(t, cache, bannedMidSession, true)

	claimedHash := hashForDifficulty(50_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp2.Result.ID, JobID: jobID, Nonce: nonceHexAt(1), Result: claimedHash})
	c2.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if r := c2.recvShareResponse(); r.Result != nil {
		t.Fatal("expected the mid-session-banned submit to be rejected")
	}

	body = scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_ban_rejections_total{phase="submit"} 1`) {
		t.Errorf("expected leaf_proxy_ban_rejections_total{phase=\"submit\"} 1, got:\n%s", body)
	}
	// The login-phase count from earlier must still be intact.
	if !strings.Contains(body, `leaf_proxy_ban_rejections_total{phase="login"} 1`) {
		t.Errorf("expected leaf_proxy_ban_rejections_total{phase=\"login\"} to remain 1, got:\n%s", body)
	}
}

// TestServer_EnableMetrics_AsyncPoolStatsWiredToRealPool is the
// required Fix 9 test: EnableMetrics wires a real, live
// AsyncPoolStatsFunc backed by this Server's actual randomxPool, not
// a stub -- confirmed by driving a real, deliberately-blocked
// dispatch through the pool and observing the exported gauges change
// accordingly, then clearing and observing them return to a resting
// state.
func TestServer_EnableMetrics_AsyncPoolStatsWiredToRealPool(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)
	h.server.SetRandomXWorkerPoolSize(1, 1)

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	if !h.server.randomxPool.Submit(func() {
		started <- struct{}{}
		<-release
	}) {
		t.Fatal("Submit returned false against a live pool")
	}
	<-started

	deadline := time.Now().Add(2 * time.Second)
	for {
		body := scrapeMetrics(t, h.server)
		if strings.Contains(body, "leaf_async_validation_in_flight_workers 1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("leaf_async_validation_in_flight_workers never reached 1, last scrape:\n%s", body)
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(release)
	deadline = time.Now().Add(2 * time.Second)
	for {
		body := scrapeMetrics(t, h.server)
		if strings.Contains(body, "leaf_async_validation_in_flight_workers 0") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("leaf_async_validation_in_flight_workers never returned to 0, last scrape:\n%s", body)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
