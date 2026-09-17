// Copyright and license: see repository LICENSE (MIT).
package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	srv := httptest.NewServer(m.Handler())
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

func TestHandler_ServesValidPrometheusExposition(t *testing.T) {
	m := New("test-version", 0)
	body := scrape(t, m)
	if !strings.Contains(body, "leaf_proxy_build_info") {
		t.Errorf("expected leaf_proxy_build_info in output, got:\n%s", body)
	}
	want := `leaf_proxy_build_info{version="test-version"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected %q in output, got:\n%s", want, body)
	}
}

func TestShareDecisionsTotal_IncrementAndRender(t *testing.T) {
	m := New("dev", 0)
	m.ShareDecisionsTotal.WithLabelValues(DecisionLocalCredit).Inc()
	m.ShareDecisionsTotal.WithLabelValues(DecisionLocalCredit).Inc()
	m.ShareDecisionsTotal.WithLabelValues(DecisionUpstreamForward).Inc()

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_proxy_share_decisions_total{decision="local_credit"} 2`,
		`leaf_proxy_share_decisions_total{decision="upstream_forward"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

func TestUpstreamHealth_ConnectedGaugeAndReconnectCounter(t *testing.T) {
	m := New("dev", 0)
	m.UpstreamConnected.Set(1)
	m.UpstreamReconnectsTotal.Add(3)

	body := scrape(t, m)
	if !strings.Contains(body, "leaf_proxy_upstream_connected 1") {
		t.Errorf("expected leaf_proxy_upstream_connected 1 in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_upstream_reconnects_total 3") {
		t.Errorf("expected leaf_proxy_upstream_reconnects_total 3 in output, got:\n%s", body)
	}

	m.UpstreamConnected.Set(0)
	body = scrape(t, m)
	if !strings.Contains(body, "leaf_proxy_upstream_connected 0") {
		t.Errorf("expected leaf_proxy_upstream_connected 0 after disconnect, got:\n%s", body)
	}
}

func TestConnectionErrorsTotal_LabeledByCategory(t *testing.T) {
	m := New("dev", 0)
	m.ConnectionErrorsTotal.WithLabelValues(ConnErrorIdleTimeout).Inc()
	m.ConnectionErrorsTotal.WithLabelValues(ConnErrorRejectedByGate).Inc()
	m.ConnectionErrorsTotal.WithLabelValues(ConnErrorRejectedByGate).Inc()

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_connection_errors_total{category="idle-timeout"} 1`,
		`leaf_connection_errors_total{category="rejected-by-gate"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

func TestSnapshotDerivedMetrics_ActiveConnectionsAndUniqueIPs(t *testing.T) {
	m := New("dev", 0)
	m.SetSnapshotSource(func() []SessionSnapshot {
		return []SessionSnapshot{
			{Address: "addr-1", RemoteIP: "10.0.0.1", Difficulty: 1000},
			{Address: "addr-1", RemoteIP: "10.0.0.1", Difficulty: 2000},
			{Address: "addr-2", RemoteIP: "10.0.0.2", Difficulty: 3000},
		}
	})

	body := scrape(t, m)

	if !strings.Contains(body, "leaf_proxy_active_connections 3") {
		t.Errorf("expected leaf_proxy_active_connections 3 in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_unique_remote_ips_gauge 2") {
		t.Errorf("expected leaf_proxy_unique_remote_ips_gauge 2 in output, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_proxy_miners_by_address{address="addr-1",port=""} 2`) {
		t.Errorf("expected addr-1 count 2 in output, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_proxy_miners_by_address{address="addr-2",port=""} 1`) {
		t.Errorf("expected addr-2 count 1 in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_vardiff_current_difficulty_count 3") {
		t.Errorf("expected vardiff histogram count 3 in output, got:\n%s", body)
	}
}

func TestSnapshotDerivedMetrics_NoSnapshotSourceIsZero(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	if !strings.Contains(body, "leaf_proxy_active_connections 0") {
		t.Errorf("expected leaf_proxy_active_connections 0 in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_proxy_unique_remote_ips_gauge 0") {
		t.Errorf("expected leaf_proxy_unique_remote_ips_gauge 0 in output, got:\n%s", body)
	}
}

func TestAddressCardinalityCap_OverflowGoesToOtherBucket(t *testing.T) {
	const cap5 = 5
	m := New("dev", cap5)

	snaps := make([]SessionSnapshot, 0, 50)
	for i := 0; i < 50; i++ {
		snaps = append(snaps, SessionSnapshot{
			Address:  fmt.Sprintf("flood-addr-%02d", i),
			RemoteIP: fmt.Sprintf("203.0.113.%d", i%256),
		})
	}
	m.SetSnapshotSource(func() []SessionSnapshot { return snaps })

	body := scrape(t, m)

	seriesCount := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "leaf_proxy_miners_by_address{") {
			seriesCount++
		}
	}
	if seriesCount > cap5 {
		t.Fatalf("got %d leaf_proxy_miners_by_address series, want <= %d (cap)", seriesCount, cap5)
	}
	if !strings.Contains(body, `address="other"`) {
		t.Errorf("expected overflow addresses aggregated into address=\"other\", got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_proxy_miners_by_address{address="other",port=""} 46`) {
		t.Errorf("expected other bucket count 46, got:\n%s", body)
	}
}

// TestSharesTotal_IncrementAndRender is the required Fix 9 test
// (DISPATCH_BRIEF.md 2026-09-10): SharesTotal actually increments
// and renders, labeled by result, distinct from ShareDecisionsTotal.
func TestSharesTotal_IncrementAndRender(t *testing.T) {
	m := New("dev", 0)
	m.SharesTotal.WithLabelValues(ResultAccepted).Inc()
	m.SharesTotal.WithLabelValues(ResultAccepted).Inc()
	m.SharesTotal.WithLabelValues(ResultRejected).Inc()

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_proxy_shares_total{result="accepted"} 2`,
		`leaf_proxy_shares_total{result="rejected"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestBlocksTotal_IncrementAndRender is the required Fix 9 test: the
// previously-no-op recordBlock's real backing counter actually
// increments and renders.
func TestBlocksTotal_IncrementAndRender(t *testing.T) {
	m := New("dev", 0)
	m.BlocksTotal.WithLabelValues(ResultAccepted).Inc()
	m.BlocksTotal.WithLabelValues(ResultRejected).Inc()
	m.BlocksTotal.WithLabelValues(ResultRejected).Inc()

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_proxy_blocks_total{result="accepted"} 1`,
		`leaf_proxy_blocks_total{result="rejected"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestBanRejectionsTotal_LabeledByPhase is the required Fix 9 test:
// the previously log-only ban-rejection points now increment a real
// counter, labeled by which phase (login/submit) rejected.
func TestBanRejectionsTotal_LabeledByPhase(t *testing.T) {
	m := New("dev", 0)
	m.BanRejectionsTotal.WithLabelValues(BanRejectionPhaseLogin).Inc()
	m.BanRejectionsTotal.WithLabelValues(BanRejectionPhaseLogin).Inc()
	m.BanRejectionsTotal.WithLabelValues(BanRejectionPhaseSubmit).Inc()

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_proxy_ban_rejections_total{phase="login"} 2`,
		`leaf_proxy_ban_rejections_total{phase="submit"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestAsyncPoolMetrics_SnapshotDerived is the required Fix 9 test:
// the shared AsyncValidationPool's queue-depth/in-flight-workers/
// submit-blocked-total metrics are recomputed from a real
// AsyncPoolStatsFunc at scrape time, exactly like the existing
// per-session snapshot metrics.
func TestAsyncPoolMetrics_SnapshotDerived(t *testing.T) {
	m := New("dev", 0)
	m.SetAsyncPoolSource(func() AsyncPoolStats {
		return AsyncPoolStats{QueueDepth: 7, InFlightWorkers: 3, SubmitBlockedTotal: 42}
	})

	body := scrape(t, m)
	for _, want := range []string{
		"leaf_async_validation_queue_depth 7",
		"leaf_async_validation_in_flight_workers 3",
		"leaf_async_validation_submit_blocked_total 42",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestAsyncPoolMetrics_NoSourceIsAbsent is the non-regression
// complement: without SetAsyncPoolSource ever being called (mirrors
// SetSnapshotSource's own "nil -> zeros" convention, but here the
// metric is entirely absent rather than zero, since there is no
// meaningful zero-value default for a pool that doesn't exist),
// Collect must not panic and must not emit these series at all.
func TestAsyncPoolMetrics_NoSourceIsAbsent(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	if strings.Contains(body, "leaf_async_validation_queue_depth") {
		t.Errorf("expected no leaf_async_validation_queue_depth series without a source, got:\n%s", body)
	}
}
