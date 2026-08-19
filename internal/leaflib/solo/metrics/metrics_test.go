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
	if !strings.Contains(body, "leaf_solo_build_info") {
		t.Errorf("expected leaf_solo_build_info in output, got:\n%s", body)
	}
	want := `leaf_solo_build_info{version="test-version"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected %q in output, got:\n%s", want, body)
	}
}

func TestSharesAndBlocksTotal_IncrementAndRender(t *testing.T) {
	m := New("dev", 0)
	m.SharesTotal.WithLabelValues(ResultAccepted).Inc()
	m.SharesTotal.WithLabelValues(ResultAccepted).Inc()
	m.SharesTotal.WithLabelValues(ResultRejected).Inc()
	m.BlocksTotal.WithLabelValues(ResultAccepted).Inc()

	body := scrape(t, m)

	for _, want := range []string{
		`leaf_shares_total{result="accepted"} 2`,
		`leaf_shares_total{result="rejected"} 1`,
		`leaf_blocks_total{result="accepted"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
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

	if !strings.Contains(body, "leaf_active_connections 3") {
		t.Errorf("expected leaf_active_connections 3 in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_unique_remote_ips_gauge 2") {
		t.Errorf("expected leaf_unique_remote_ips_gauge 2 in output, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_miners_by_address{address="addr-1"} 2`) {
		t.Errorf("expected addr-1 count 2 in output, got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_miners_by_address{address="addr-2"} 1`) {
		t.Errorf("expected addr-2 count 1 in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_vardiff_current_difficulty_bucket") {
		t.Errorf("expected vardiff histogram buckets in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_vardiff_current_difficulty_count 3") {
		t.Errorf("expected vardiff histogram count 3 in output, got:\n%s", body)
	}
	// Under the cap, no "other" bucket SERIES should be emitted (the
	// metric's HELP text legitimately mentions the word "other", so
	// check actual sample lines, not the whole body).
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "leaf_miners_by_address{") && strings.Contains(line, `address="other"`) {
			t.Errorf("did not expect an 'other' address series under the cap, got line: %s", line)
		}
	}
}

// TestSnapshotDerivedMetrics_NoSnapshotSourceIsZero confirms the
// package degrades gracefully (zeros, not a panic) if
// SetSnapshotSource is never called.
func TestSnapshotDerivedMetrics_NoSnapshotSourceIsZero(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	if !strings.Contains(body, "leaf_active_connections 0") {
		t.Errorf("expected leaf_active_connections 0 in output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_unique_remote_ips_gauge 0") {
		t.Errorf("expected leaf_unique_remote_ips_gauge 0 in output, got:\n%s", body)
	}
}

// TestAddressCardinalityCap_OverflowGoesToOtherBucket is the required
// "flood more distinct addresses than the cap" test: with a cap of 5,
// 50 distinct addresses must render as at most 5 distinct
// leaf_miners_by_address series (4 real + 1 "other"), never 50.
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
		if strings.HasPrefix(line, "leaf_miners_by_address{") {
			seriesCount++
		}
	}
	if seriesCount > cap5 {
		t.Fatalf("got %d leaf_miners_by_address series, want <= %d (cap)", seriesCount, cap5)
	}
	if !strings.Contains(body, `address="other"`) {
		t.Errorf("expected overflow addresses aggregated into address=\"other\", got:\n%s", body)
	}
	// The "other" bucket must carry the sum of every address beyond
	// the top (cap-1): 50 addresses, each count 1, keep 4 => other
	// must be 46.
	if !strings.Contains(body, `leaf_miners_by_address{address="other"} 46`) {
		t.Errorf("expected other bucket count 46, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_active_connections 50") {
		t.Errorf("expected leaf_active_connections 50 (uncapped — the cap is address-label-only), got:\n%s", body)
	}
}

func TestCapAddressCounts_UnderCapReturnsUnchanged(t *testing.T) {
	counts := map[string]int{"a": 1, "b": 2}
	kept, other := CapAddressCounts(counts, 5)
	if other != 0 {
		t.Errorf("other = %d, want 0", other)
	}
	if len(kept) != 2 {
		t.Errorf("len(kept) = %d, want 2", len(kept))
	}
}

func TestCapAddressCounts_KeepsHighestCounts(t *testing.T) {
	counts := map[string]int{"low": 1, "mid": 5, "high": 10, "extra1": 2, "extra2": 3}
	kept, other := CapAddressCounts(counts, 3) // keep top 2 + other
	if len(kept) != 2 {
		t.Fatalf("len(kept) = %d, want 2: %#v", len(kept), kept)
	}
	if kept["high"] != 10 || kept["mid"] != 5 {
		t.Errorf("expected {high:10, mid:5} kept, got %#v", kept)
	}
	wantOther := 1 + 2 + 3 // low + extra1 + extra2
	if other != wantOther {
		t.Errorf("other = %d, want %d", other, wantOther)
	}
}

func TestRemoteIPOf_StripsPort(t *testing.T) {
	got := RemoteIPOf(fakeAddr("10.1.2.3:4444"))
	if got != "10.1.2.3" {
		t.Errorf("RemoteIPOf = %q, want 10.1.2.3", got)
	}
}

func TestRemoteIPOf_FallsBackOnUnparsableAddr(t *testing.T) {
	got := RemoteIPOf(fakeAddr("pipe"))
	if got != "pipe" {
		t.Errorf("RemoteIPOf = %q, want raw fallback %q", got, "pipe")
	}
}

type fakeAddr string

func (f fakeAddr) Network() string { return "test" }
func (f fakeAddr) String() string  { return string(f) }
