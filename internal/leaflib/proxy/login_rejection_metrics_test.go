// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy/metrics"
)

// assertOnlyLoginRejectionReason confirms exactly one
// leaf_proxy_login_rejections_total{reason=want} sample equals 1 and
// every OTHER reason in the full, closed metrics.AllLoginRejectionReasons
// enumeration is still 0 -- mirrors solo/direct's identical
// assertOnly*LoginRejectionReason helpers exactly.
func assertOnlyLoginRejectionReason(t *testing.T, s *Server, want string) {
	t.Helper()
	for _, reason := range metrics.AllLoginRejectionReasons {
		got := testutil.ToFloat64(s.metrics.LoginRejectionsTotal.WithLabelValues(reason))
		if reason == want {
			if got != 1 {
				t.Errorf("reason=%s counter = %v, want 1", reason, got)
			}
		} else if got != 0 {
			t.Errorf("reason=%s counter = %v, want 0 (only reason=%s should have incremented)", reason, got, want)
		}
	}
}

// recvGenericLoginRejection reads one raw login-rejection wire line
// and confirms it is a real rejection (object/null ErrorResponse
// shape, Error non-nil).
func recvGenericLoginRejection(t *testing.T, c *testClient) {
	t.Helper()
	raw := c.recvRaw()
	var resp ErrorResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if resp.Error == nil {
		t.Fatalf("expected login to be rejected, got Error=nil (raw=%s)", raw)
	}
}

// TestSessionLoginRejectionReason_InvalidParams covers handleLogin's
// json.Unmarshal(req.Params, &login) failure call site.
func TestSessionLoginRejectionReason_InvalidParams(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: json.RawMessage(`"not-an-object"`)})
	recvGenericLoginRejection(t, c)

	assertOnlyLoginRejectionReason(t, h.server, metrics.LoginRejectionReasonInvalidParams)
}

// TestSessionLoginRejectionReason_EmptyAddress covers handleLogin's
// login.Login == "" call site.
func TestSessionLoginRejectionReason_EmptyAddress(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: "", Pass: "rig1", Agent: "XMRig/6.21.0"})})
	recvGenericLoginRejection(t, c)

	assertOnlyLoginRejectionReason(t, h.server, metrics.LoginRejectionReasonEmptyAddress)
}

// TestSessionLoginRejectionReason_OversizedLogin covers handleLogin's
// len(login.Login) > maxProxyLoginLen call site -- leaf-proxy's own
// equivalent of solo/direct's invalid_address_format (see this
// package's LoginRejectionReasonOversizedLogin doc comment).
func TestSessionLoginRejectionReason_OversizedLogin(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	oversized := strings.Repeat("a", maxProxyLoginLen+1)
	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: oversized, Pass: "rig1", Agent: "XMRig/6.21.0"})})
	recvGenericLoginRejection(t, c)

	assertOnlyLoginRejectionReason(t, h.server, metrics.LoginRejectionReasonOversizedLogin)
}

// TestSessionLoginRejectionReason_Banned covers handleLogin's
// s.server.addressFlags.Get(...).Banned call site -- the category
// Alex specifically asked this metric to quantify against the
// others. Also confirms the pre-existing
// leaf_proxy_ban_rejections_total{phase="login"} counter still
// increments in lockstep (DISPATCH_BRIEF.md's explicit "both
// counters coexist" requirement).
func TestSessionLoginRejectionReason_Banned(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	bannedAddr := "login-rejection-metric-banned"
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		bannedAddr: {Banned: true},
	}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)
	h.server.EnableAddressFlags(cache)

	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: bannedAddr, Pass: "rig1", Agent: "XMRig/6.21.0"})})
	recvGenericLoginRejection(t, c)

	assertOnlyLoginRejectionReason(t, h.server, metrics.LoginRejectionReasonBanned)

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_login_rejections_total{reason="banned"} 1`) {
		t.Errorf("expected leaf_proxy_login_rejections_total{reason=\"banned\"} 1 to be exposed on /metrics, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_proxy_ban_rejections_total{phase="login"} 1`) {
		t.Errorf("expected leaf_proxy_ban_rejections_total{phase=\"login\"} 1 to still fire alongside the new login-rejections metric, got:\n%s", body)
	}
}

// TestSessionLoginRejectionReason_NoJobTemplate covers handleLogin's
// s.currentJob(...) failure call site -- a real, valid, unbanned
// login that still can't be issued a job because this leaf's
// upstream connection has no live template at all.
func TestSessionLoginRejectionReason_NoJobTemplate(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)
	h.source.setTemplate(nil)

	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: "login-rejection-metric-no-job-template", Pass: "rig1", Agent: "XMRig/6.21.0"})})
	recvGenericLoginRejection(t, c)

	assertOnlyLoginRejectionReason(t, h.server, metrics.LoginRejectionReasonNoJobTemplate)
}
