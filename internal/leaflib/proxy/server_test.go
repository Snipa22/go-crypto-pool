// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// TestPortLabel_PrefersPortDescFallsBackToAddress is the required
// Finding #1 (per-port stats) unit test for portLabel's own
// documented precedence: non-empty PortDesc wins; an empty PortDesc
// falls back to Address; both empty yields an empty label (no
// synthesized placeholder).
func TestPortLabel_PrefersPortDescFallsBackToAddress(t *testing.T) {
	cases := []struct {
		name string
		port solo.PortConfig
		want string
	}{
		{"PortDesc wins when set", solo.PortConfig{Address: ":4444", PortDesc: "low-diff"}, "low-diff"},
		{"falls back to Address when PortDesc empty", solo.PortConfig{Address: ":4444"}, ":4444"},
		{"both empty yields empty", solo.PortConfig{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := portLabel(tc.port); got != tc.want {
				t.Errorf("portLabel(%+v) = %q, want %q", tc.port, got, tc.want)
			}
		})
	}
}

// TestSessionPort_SurfacesInStatsAndMetrics is the required Finding
// #1 (per-port stats) end-to-end test: the SAME port label a session
// was accepted under (via handleConn) surfaces identically in
// Stats().Sessions[i].Port (and therefore the stats HTML "Port"
// column, which renders that field directly -- see statsui.go) AND
// in the Prometheus leaf_proxy_miners_by_address{address=...,
// port=...} series (via sessionSnapshots -> metrics.SessionSnapshot.
// Port -- see metrics.go's Collect), proving both consumers derive
// from the one canonical value rather than diverging.
func TestSessionPort_SurfacesInStatsAndMetrics(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	const wantPort = "high-diff"
	c, _ := h.connectAtDifficultyWithPort(1000, wantPort)
	loginResp := c.login(t, "addr-port-label-test")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	st := h.server.Stats()
	if len(st.Sessions) != 1 {
		t.Fatalf("expected exactly 1 session in Stats(), got %d", len(st.Sessions))
	}
	if got := st.Sessions[0].Port; got != wantPort {
		t.Errorf("Stats().Sessions[0].Port = %q, want %q", got, wantPort)
	}

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected exactly 1 live session")
	}
	if sess.Port != wantPort {
		t.Errorf("Session.Port = %q, want %q", sess.Port, wantPort)
	}

	body := scrapeMetrics(t, h.server)
	want := `leaf_proxy_miners_by_address{address="addr-port-label-test",port="high-diff"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected %q in /metrics output, got:\n%s", want, body)
	}
}

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
	if !strings.Contains(body, `leaf_proxy_miners_by_address{address="addr-active-conn",port=""} 1`) {
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
	// BUG FIX: a single resp.Body.Read(buf) call is NOT guaranteed to
	// return the entire response body in one call (io.Reader's
	// contract explicitly allows a short read even when more data is
	// available, and a real net/http chunked-transfer response body
	// commonly returns one chunk per Read call) -- this was
	// discovered as a genuine, real flake once this package's
	// /metrics output grew past whatever chunk boundary net/http
	// happened to use (adding FIX_BRIEF.md finding #18's malformed-
	// blob-breaker/seed-hash-decode-error metrics pushed
	// leaf_proxy_upstream_reconnects_total past a chunk boundary,
	// silently truncating it out of a single short Read's result).
	// io.ReadAll is the correct, robust way to read an entire
	// response body regardless of how many underlying chunks/Read
	// calls it takes.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /metrics response body: %v", err)
	}
	return string(body)
}

// TestServer_SessionSnapshots_DevFeeUpstreamHealthTypeAssertion_GracefulWhenDisabled
// confirms the optional dev-fee health gauge/counter pair (DISPATCH_BRIEF.md
// "leaf-proxy dev-fee second-connection") stay at their zero value --
// no panic, no spurious activity -- when EnableDevFeeUpstream was
// never called at all (the default, -dev-fee-percent=0 case).
func TestServer_SessionSnapshots_DevFeeUpstreamHealthTypeAssertion_GracefulWhenDisabled(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	body := scrapeMetrics(t, h.server)
	if !strings.Contains(body, "leaf_proxy_dev_fee_upstream_connected 0") {
		t.Errorf("expected leaf_proxy_dev_fee_upstream_connected 0 (dev-fee mechanism disabled), got:\n%s", body)
	}
}

// TestServer_SessionSnapshots_DevFeeUpstreamHealthReportedWhenEnabled
// confirms that once EnableDevFeeUpstream has been called with a
// concrete UpstreamSubmitter that also implements UpstreamHealth, its
// real Connected()/ReconnectCount() values flow into the dedicated
// leaf_proxy_dev_fee_upstream_connected/
// leaf_proxy_dev_fee_upstream_reconnects_total collectors --
// completely independently of the PRIMARY connection's own
// leaf_proxy_upstream_connected/leaf_proxy_upstream_reconnects_total
// pair (asserted here too, to prove the two are not accidentally
// aliased onto the same collector).
func TestServer_SessionSnapshots_DevFeeUpstreamHealthReportedWhenEnabled(t *testing.T) {
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	validator := &fakeValidator{accept: true}
	primary := &fakeUpstreamWithHealth{connected: true, reconnects: 1}
	devFee := &fakeUpstreamWithHealth{connected: true, reconnects: 7}

	cm := leaflib.NewConnectionManager(t.Context(), leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, primary, nil, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	server.EnableDevFeeUpstream(devFee)
	server.EnableMetrics("test", 0)

	body := scrapeMetrics(t, server)
	if !strings.Contains(body, "leaf_proxy_upstream_connected 1") {
		t.Errorf("expected primary leaf_proxy_upstream_connected 1, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_upstream_reconnects_total 1") {
		t.Errorf("expected primary leaf_proxy_upstream_reconnects_total 1, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_dev_fee_upstream_connected 1") {
		t.Errorf("expected leaf_proxy_dev_fee_upstream_connected 1, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_dev_fee_upstream_reconnects_total 7") {
		t.Errorf("expected leaf_proxy_dev_fee_upstream_reconnects_total 7, got:\n%s", body)
	}

	// A dev-fee disconnect must not affect the primary's own gauge.
	devFee.connected = false
	body = scrapeMetrics(t, server)
	if !strings.Contains(body, "leaf_proxy_dev_fee_upstream_connected 0") {
		t.Errorf("expected leaf_proxy_dev_fee_upstream_connected 0 after a dev-fee-only disconnect, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_upstream_connected 1") {
		t.Errorf("primary leaf_proxy_upstream_connected must remain 1 -- a dev-fee outage must never affect the primary's own health reporting, got:\n%s", body)
	}
}
