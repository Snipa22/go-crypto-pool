// Copyright and license: see repository LICENSE (MIT).
package metrics

import (
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

// TestAsyncPoolMetrics_SnapshotDerived is the required Fix 9 test
// (DISPATCH_BRIEF.md 2026-09-10): mirrors solo/metrics's and
// proxy/metrics's own identical tests exactly -- leaf-direct shares
// the same solo.AsyncValidationPool implementation, so its own
// metrics package needs the exact same snapshot-derived coverage.
func TestAsyncPoolMetrics_SnapshotDerived(t *testing.T) {
	m := New("dev", 0)
	m.SetAsyncPoolSource(func() AsyncPoolStats {
		return AsyncPoolStats{QueueDepth: 5, InFlightWorkers: 2, SubmitBlockedTotal: 8}
	})

	body := scrape(t, m)
	for _, want := range []string{
		"leaf_async_validation_queue_depth 5",
		"leaf_async_validation_in_flight_workers 2",
		"leaf_async_validation_submit_blocked_total 8",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestAsyncPoolMetrics_NoSourceIsAbsent mirrors solo/metrics's and
// proxy/metrics's own identical non-regression check exactly.
func TestAsyncPoolMetrics_NoSourceIsAbsent(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	if strings.Contains(body, "leaf_async_validation_queue_depth") {
		t.Errorf("expected no leaf_async_validation_queue_depth series without a source, got:\n%s", body)
	}
}
