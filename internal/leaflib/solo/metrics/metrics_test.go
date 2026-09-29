package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	shared "github.com/Snipa22/go-crypto-pool/internal/leaflib/metrics"
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

// TestAsyncPoolMetrics_SnapshotDerived is the required Fix 9 test
// (DISPATCH_BRIEF.md 2026-09-10): the shared AsyncValidationPool's
// queue-depth/in-flight-workers/submit-blocked-total metrics are
// recomputed from a real AsyncPoolStatsFunc at scrape time.
func TestAsyncPoolMetrics_SnapshotDerived(t *testing.T) {
	m := New("dev", 0)
	m.SetAsyncPoolSource(func() AsyncPoolStats {
		return AsyncPoolStats{QueueDepth: 9, InFlightWorkers: 4, SubmitBlockedTotal: 11}
	})

	body := scrape(t, m)
	for _, want := range []string{
		"leaf_async_validation_queue_depth 9",
		"leaf_async_validation_in_flight_workers 4",
		"leaf_async_validation_submit_blocked_total 11",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestAsyncPoolMetrics_NoSourceIsAbsent mirrors proxy/metrics's own
// identical non-regression check exactly.
func TestAsyncPoolMetrics_NoSourceIsAbsent(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	if strings.Contains(body, "leaf_async_validation_queue_depth") {
		t.Errorf("expected no leaf_async_validation_queue_depth series without a source, got:\n%s", body)
	}
}

// fakeClock is a manually-advanced time source for deterministic
// rate-tracker integration testing -- mirrors
// internal/leaflib/metrics's own identical test helper exactly (see
// that package's ratetracker_test.go), duplicated here rather than
// exported from the shared package since it exists purely to drive
// shared.NewLabeledRateTrackersForTest's clock parameter in THIS
// package's own tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

// metricValue finds the first scrape-output line for name with the
// given label pairs (label, value, label, value, ...) and parses its
// trailing float64 sample value, failing the test if no such line
// exists.
func metricValue(t *testing.T, body, name string, labelPairs ...string) float64 {
	t.Helper()
	labelStr := ""
	if len(labelPairs) > 0 {
		parts := make([]string, 0, len(labelPairs)/2)
		for i := 0; i < len(labelPairs); i += 2 {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, labelPairs[i], labelPairs[i+1]))
		}
		labelStr = "{" + strings.Join(parts, ",") + "}"
	}
	prefix := name + labelStr + " "
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, prefix)), 64)
			if err != nil {
				t.Fatalf("parse metric value for %q: %v (line: %q)", prefix, err, line)
			}
			return v
		}
	}
	t.Fatalf("metric %q not found in scrape output:\n%s", prefix, body)
	return 0
}

// TestPerSecondRateMetrics_IntegrationAcrossSimulatedTicks is the
// required per-second-rate integration test: increments
// SharesTotal/BlocksTotal (via IncShareResult/IncBlockResult, the
// real call sites server.go's recordShare/recordBlock now use) a
// known number of times across SIMULATED ticks (never a real
// ticker/real sleep -- see
// shared.NewLabeledRateTrackersForTest/LabeledRateTrackers.Tick),
// then scrapes via the real Handler() and asserts:
//   - the existing _total counters report their EXACT, unchanged
//     cumulative values.
//   - the new _per_second gauges report the exact known constant
//     rate each label combination was driven at (a fixed per-tick
//     increment over a fixed number of 1-simulated-second ticks
//     converges to an EXACT, not just in-tolerance, rate -- see
//     internal/leaflib/metrics/ratetracker_test.go's identical
//     convergence tests for why this is deterministic).
//
// Mirrors internal/leaflib/direct/metrics's identical test exactly.
func TestPerSecondRateMetrics_IntegrationAcrossSimulatedTicks(t *testing.T) {
	m := New("dev", 0)

	// Swap in manually-driven, non-autostart rate-tracker groups
	// (same package as Metrics, so the unexported fields are
	// directly reachable) so this test controls sampling cadence
	// deterministically instead of relying on the production
	// 1-real-second background ticker.
	fc := newFakeClock(time.Unix(0, 0))
	m.sharesRate = shared.NewLabeledRateTrackersForTest(fc.Now, 60, time.Second)
	m.blocksRate = shared.NewLabeledRateTrackersForTest(fc.Now, 60, time.Second)

	const ticks = 10
	for i := 0; i < ticks; i++ {
		fc.Advance(time.Second)

		m.IncShareResult(ResultAccepted)
		m.IncShareResult(ResultAccepted)
		m.IncShareResult(ResultAccepted)
		m.IncShareResult(ResultRejected)

		m.IncBlockResult(ResultAccepted)

		m.sharesRate.Tick()
		m.blocksRate.Tick()
	}

	body := scrape(t, m)

	// _total counters: exact, unchanged cumulative values.
	for _, tc := range []struct {
		name   string
		labels []string
		want   float64
	}{
		{"leaf_shares_total", []string{"result", "accepted"}, 30},
		{"leaf_shares_total", []string{"result", "rejected"}, 10},
		{"leaf_blocks_total", []string{"result", "accepted"}, 10},
	} {
		if got := metricValue(t, body, tc.name, tc.labels...); got != tc.want {
			t.Errorf("%s{%s=%q} = %v, want %v", tc.name, tc.labels[0], tc.labels[1], got, tc.want)
		}
	}
	// result="rejected" was never incremented on BlocksTotal, so
	// that label combination's series is genuinely absent.
	if strings.Contains(body, `leaf_blocks_total{result="rejected"}`) {
		t.Errorf("expected no leaf_blocks_total series for result=rejected (never incremented), got:\n%s", body)
	}

	// _per_second gauges: a constant per-tick increment over
	// 1-simulated-second ticks converges to an EXACT rate equal to
	// that per-tick increment.
	for _, tc := range []struct {
		name   string
		labels []string
		want   float64
	}{
		{"leaf_shares_per_second", []string{"result", "accepted"}, 3},
		{"leaf_shares_per_second", []string{"result", "rejected"}, 1},
		{"leaf_blocks_per_second", []string{"result", "accepted"}, 1},
		// Never incremented -- must report exactly 0, not merely
		// "in tolerance" of 0.
		{"leaf_blocks_per_second", []string{"result", "rejected"}, 0},
	} {
		if got := metricValue(t, body, tc.name, tc.labels...); got != tc.want {
			t.Errorf("%s{%s=%q} = %v, want %v", tc.name, tc.labels[0], tc.labels[1], got, tc.want)
		}
	}
}

// TestNew_RegistersGoAndProcessCollectors proves New actually wires
// the standard Go runtime (collectors.NewGoCollector) and process
// (collectors.NewProcessCollector) collectors onto this Metrics' own
// private *prometheus.Registry -- not just that the collectors
// package is imported. go_goroutines is used as the real-Go-collector
// probe metric (always present, always >= 1: this test goroutine
// itself). A simple Gather()+scan for the family name is sufficient;
// this deliberately does not assert specific values (those are
// runtime-dependent).
func TestNew_RegistersGoAndProcessCollectors(t *testing.T) {
	m := New("dev", 0)
	mfs, err := m.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "go_goroutines" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected go_goroutines metric family in Gather() output, proving the Go runtime collector is genuinely registered -- got families: %v", metricFamilyNames(mfs))
	}
}

func metricFamilyNames(mfs []*dto.MetricFamily) []string {
	names := make([]string, 0, len(mfs))
	for _, mf := range mfs {
		names = append(names, mf.GetName())
	}
	return names
}
