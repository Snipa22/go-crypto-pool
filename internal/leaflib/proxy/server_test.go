// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestServer_EnableMetrics_ShareDecisionsIncrementOnBothRealCodePaths
// confirms the real local-credit-vs-upstream-forward counter tracks
// each real handleSubmit branch correctly: a share below the
// upstream pool's requested share difficulty increments
// decision="local_credit" only, and a share meeting/exceeding it
// increments decision="upstream_forward" only.
func TestServer_EnableMetrics_ShareDecisionsIncrementOnBothRealCodePaths(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	loginResp := c.login(t, "addr-metrics-local")

	// Below the upstream template's TargetDiff (1,000,000, see
	// newHarness) -> local_credit.
	claimedHash := hashForDifficulty(500_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(2), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result == nil {
		t.Fatalf("expected accepted share, got error=%v", resp.Error)
	}

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_share_decisions_total{decision="local_credit"} 1`) {
		t.Errorf("expected local_credit=1 after a below-target share, got:\n%s", body)
	}
	if strings.Contains(body, `leaf_proxy_share_decisions_total{decision="upstream_forward"} 1`) {
		t.Errorf("did not expect upstream_forward=1 yet, got:\n%s", body)
	}

	// Second connection, meeting/exceeding TargetDiff -> upstream_forward.
	c2, _ := h.connect()
	loginResp2 := c2.login(t, "addr-metrics-forward")
	claimedHash2 := hashForDifficulty(2_000_000)
	submitParams2, _ := json.Marshal(SubmitRequest{ID: loginResp2.Result.ID, JobID: loginResp2.Result.Job.JobID, Nonce: nonceHexAt(3), Result: claimedHash2})
	c2.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams2})
	if resp := c2.recvShareResponse(); resp.Result == nil {
		t.Fatalf("expected accepted block-level find, got error=%v", resp.Error)
	}

	body = scrapeMetrics(t, h.server)
	if !strings.Contains(body, `leaf_proxy_share_decisions_total{decision="local_credit"} 1`) {
		t.Errorf("expected local_credit to remain 1, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_proxy_share_decisions_total{decision="upstream_forward"} 1`) {
		t.Errorf("expected upstream_forward=1 after a meets-target share, got:\n%s", body)
	}
}

// TestServer_MetricsHandler_NotEnabledReturns404 confirms
// MetricsHandler degrades gracefully instead of panicking when
// EnableMetrics was never called.
func TestServer_MetricsHandler_NotEnabledReturns404(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	srv := httptest.NewServer(h.server.MetricsHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when metrics not enabled", resp.StatusCode)
	}
}

// TestServer_EnableMetrics_ActiveConnectionsReflectsRealSessions
// confirms the /metrics endpoint returns valid Prometheus exposition
// format AND that the snapshot-derived active-connections gauge
// reflects a real, currently-logged-in downstream session.
func TestServer_EnableMetrics_ActiveConnectionsReflectsRealSessions(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	c.login(t, "addr-active-conn")

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, "leaf_proxy_active_connections 1") {
		t.Errorf("expected leaf_proxy_active_connections 1 with one logged-in session, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_proxy_miners_by_address{address="addr-active-conn"} 1`) {
		t.Errorf("expected addr-active-conn count 1, got:\n%s", body)
	}
}

// TestServer_SessionSnapshots_UpstreamHealthTypeAssertion confirms
// sessionSnapshots gracefully degrades (no panic, health metrics
// stay zero) when the concrete UpstreamSubmitter does NOT implement
// UpstreamHealth (fakeUpstream in this test package deliberately
// doesn't, mirroring most other tests in this file).
func TestServer_SessionSnapshots_UpstreamHealthTypeAssertion_GracefulWhenUnimplemented(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, "leaf_proxy_upstream_connected 0") {
		t.Errorf("expected leaf_proxy_upstream_connected 0 (no UpstreamHealth implementation), got:\n%s", body)
	}
}

// fakeUpstreamWithHealth additionally implements UpstreamHealth, for
// testing the real Connected()/ReconnectCount() type-assertion path
// in sessionSnapshots.
type fakeUpstreamWithHealth struct {
	fakeUpstream
	connected  bool
	reconnects uint64
}

func (f *fakeUpstreamWithHealth) Connected() bool        { return f.connected }
func (f *fakeUpstreamWithHealth) ReconnectCount() uint64 { return f.reconnects }

func TestServer_SessionSnapshots_UpstreamHealthReportedWhenImplemented(t *testing.T) {
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1, // this fake upstream never publishes client_pool_offset
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	validator := &fakeValidator{accept: true}
	upstream := &fakeUpstreamWithHealth{connected: true, reconnects: 2}

	cm := leaflib.NewConnectionManager(t.Context(), leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, upstream, nil, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	server.EnableMetrics("test", 0)

	body := scrapeMetrics(t, server)
	if !strings.Contains(body, "leaf_proxy_upstream_connected 1") {
		t.Errorf("expected leaf_proxy_upstream_connected 1, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_upstream_reconnects_total 2") {
		t.Errorf("expected leaf_proxy_upstream_reconnects_total 2, got:\n%s", body)
	}

	// A second scrape with no NEW reconnects must not double-count.
	body = scrapeMetrics(t, server)
	if !strings.Contains(body, "leaf_proxy_upstream_reconnects_total 2") {
		t.Errorf("expected leaf_proxy_upstream_reconnects_total to remain 2 on a second scrape with no new reconnects, got:\n%s", body)
	}

	// A real new reconnect between scrapes must add the delta, not
	// reset.
	upstream.reconnects = 5
	body = scrapeMetrics(t, server)
	if !strings.Contains(body, "leaf_proxy_upstream_reconnects_total 5") {
		t.Errorf("expected leaf_proxy_upstream_reconnects_total 5 after 3 more real reconnects, got:\n%s", body)
	}
}

func scrapeMetrics(t *testing.T, s *Server) string {
	t.Helper()
	srv := httptest.NewServer(s.MetricsHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
