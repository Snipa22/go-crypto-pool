// Copyright and license: see repository LICENSE (MIT).
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

	shared "github.com/Snipa22/go-crypto-pool/internal/leaflib/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
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

// TestRelayMetrics_SnapshotDerived proves every leaf_relay_*/
// leaf_direct_relay_resubmit_total series is emitted from a wired
// RelayStatsFunc, with the real values it returns (not re-derived or
// re-counted by this package).
func TestRelayMetrics_SnapshotDerived(t *testing.T) {
	m := New("dev", 0)
	fixedTime := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	m.SetRelaySource(func() relay.RelayStats {
		return relay.RelayStats{
			Connected: true,

			BlockPublishSuccess:    3,
			BlockPublishError:      1,
			BlockReceiveDispatched: 2,
			BlockReceiveDuplicate:  4,

			TemplatePublishSuccess:    5,
			TemplatePublishError:      6,
			TemplateReceiveDispatched: 7,
			TemplateReceiveDuplicate:  8,

			LastBlockPublish:    fixedTime,
			LastBlockReceive:    fixedTime,
			LastTemplatePublish: fixedTime,
			LastTemplateReceive: fixedTime,
		}
	})
	m.RelayResubmitTotal.WithLabelValues(ResultAccepted).Inc()
	m.RelayResubmitTotal.WithLabelValues(ResultRejected).Add(2)
	m.RelayResubmitTotal.WithLabelValues(ResultNoSubmitter).Add(3)

	body := scrape(t, m)
	wantUnix := fixedTime.Unix()
	for _, want := range []string{
		`leaf_relay_block_publish_total{result="success"} 3`,
		`leaf_relay_block_publish_total{result="error"} 1`,
		`leaf_relay_block_receive_total{result="dispatched"} 2`,
		`leaf_relay_block_receive_total{result="duplicate"} 4`,
		`leaf_relay_template_publish_total{result="success"} 5`,
		`leaf_relay_template_publish_total{result="error"} 6`,
		`leaf_relay_template_receive_total{result="dispatched"} 7`,
		`leaf_relay_template_receive_total{result="duplicate"} 8`,
		"leaf_relay_connected 1",
		"leaf_relay_last_block_publish_unixtime " + formatUnix(wantUnix),
		"leaf_relay_last_block_receive_unixtime " + formatUnix(wantUnix),
		"leaf_relay_last_template_publish_unixtime " + formatUnix(wantUnix),
		"leaf_relay_last_template_receive_unixtime " + formatUnix(wantUnix),
		`leaf_direct_relay_resubmit_total{result="accepted"} 1`,
		`leaf_direct_relay_resubmit_total{result="rejected"} 2`,
		`leaf_direct_relay_resubmit_total{result="no_submitter"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

func formatUnix(u int64) string {
	return strconv.FormatFloat(float64(u), 'g', -1, 64)
}

// TestTotalHashrateMetric_ReflectsAllSessionsBeyondCap is the
// required proof for leaf_direct_total_hashrate_hash_per_second: it
// must equal the sum of every connected session's hashrate even when
// the number of distinct addresses exceeds maxAddressLabels (default
// 50) -- i.e. it must NOT be derived from (or limited by)
// leaf_direct_miner_hashrate_hash_per_second's capped per-address
// map. 60 synthetic sessions, one address each (so 60 > 50 forces
// CapAddressHashrates to actually bucket 11 addresses into "other"),
// each contributing a distinct, easily-summed hashrate.
func TestTotalHashrateMetric_ReflectsAllSessionsBeyondCap(t *testing.T) {
	m := New("dev", 0) // maxAddressLabels defaults to 50 via New's own <= 0 fallback

	const sessionCount = 60
	snaps := make([]SessionSnapshot, 0, sessionCount)
	var wantTotal float64
	for i := 0; i < sessionCount; i++ {
		rate := float64(1000 + i) // distinct per-address rate, easy to sum by hand
		snaps = append(snaps, SessionSnapshot{
			Address:  fmt.Sprintf("addr-%02d", i),
			RemoteIP: fmt.Sprintf("10.0.0.%d", i%254+1),
			Hashrate: rate,
		})
		wantTotal += rate
	}
	m.SetSnapshotSource(func() []SessionSnapshot { return snaps })

	body := scrape(t, m)

	wantLine := fmt.Sprintf("leaf_direct_total_hashrate_hash_per_second %s", strconv.FormatFloat(wantTotal, 'g', -1, 64))
	if !strings.Contains(body, wantLine) {
		t.Fatalf("expected %q in scrape output, got:\n%s", wantLine, body)
	}

	// Sanity: confirm the per-address metric really IS capped (fewer
	// than sessionCount distinct address label values, plus an
	// "other" bucket) -- otherwise this test would not actually be
	// exercising the over-the-cap scenario it claims to.
	addrSeries := strings.Count(body, "leaf_direct_miner_hashrate_hash_per_second{")
	if addrSeries >= sessionCount {
		t.Fatalf("expected leaf_direct_miner_hashrate_hash_per_second to be capped below %d series, got %d -- test no longer exercises the over-the-cap case", sessionCount, addrSeries)
	}
	if !strings.Contains(body, `leaf_direct_miner_hashrate_hash_per_second{address="other"}`) {
		t.Fatalf("expected an address=\"other\" overflow bucket once addresses exceed the cap, got:\n%s", body)
	}
}

// TestTotalHashrateMetric_EmptyWhenNoSessions is the zero-sessions
// edge case: with no snapshot source wired (or an empty snapshot),
// the total must be exactly 0, never absent (this is an unlabeled
// gauge, always emitted, unlike the relay_* metrics above which are
// conditionally emitted only when a source is wired).
func TestTotalHashrateMetric_EmptyWhenNoSessions(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	if !strings.Contains(body, "leaf_direct_total_hashrate_hash_per_second 0") {
		t.Fatalf("expected leaf_direct_total_hashrate_hash_per_second 0 with no sessions, got:\n%s", body)
	}
}

// TestChainHeightMetrics_EmittedWhenSourceWired proves
// leaf_monero_chain_height/leaf_tari_chain_height are each emitted,
// with the real value, only once their respective source is wired --
// mirroring the relay_*/asyncPool_* metrics' identical
// wired-vs-absent convention above.
func TestChainHeightMetrics_EmittedWhenSourceWired(t *testing.T) {
	m := New("dev", 0)
	m.SetMoneroChainHeightSource(func() (uint64, bool) { return 3312345, true })
	m.SetTariChainHeightSource(func() (uint64, bool) { return 42, true })

	body := scrape(t, m)
	for _, want := range []string{
		"leaf_monero_chain_height 3.312345e+06",
		"leaf_tari_chain_height 42",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestChainHeightMetrics_AbsentWithoutSource proves neither chain
// height metric appears at all when no source has been wired (a
// Metrics predating this feature, or a leaf whose s.node doesn't
// implement chainheight.TipInfoSource).
func TestChainHeightMetrics_AbsentWithoutSource(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	for _, absent := range []string{"leaf_monero_chain_height", "leaf_tari_chain_height"} {
		if strings.Contains(body, absent) {
			t.Errorf("expected no %q series without a source wired, got:\n%s", absent, body)
		}
	}
}

// TestChainHeightMetrics_AbsentWhenNoSuccessfulPollYet proves a
// wired source that reports ok=false (no successful poll yet, e.g.
// daemon unreachable since process start) still emits NO sample --
// never a misleading 0.
func TestChainHeightMetrics_AbsentWhenNoSuccessfulPollYet(t *testing.T) {
	m := New("dev", 0)
	m.SetMoneroChainHeightSource(func() (uint64, bool) { return 0, false })

	body := scrape(t, m)
	if strings.Contains(body, "leaf_monero_chain_height") {
		t.Errorf("expected no leaf_monero_chain_height series when ok=false, got:\n%s", body)
	}
}

// TestRelayMetrics_NoSourceIsAbsent mirrors
// TestAsyncPoolMetrics_NoSourceIsAbsent exactly, for relay metrics --
// the zero-cost/zero-registration contract at the collector level: an
// unwired Metrics (no SetRelaySource call at all) emits none of the
// leaf_relay_* series.
func TestRelayMetrics_NoSourceIsAbsent(t *testing.T) {
	m := New("dev", 0)
	body := scrape(t, m)
	for _, absent := range []string{
		"leaf_relay_block_publish_total",
		"leaf_relay_block_receive_total",
		"leaf_relay_template_publish_total",
		"leaf_relay_template_receive_total",
		"leaf_relay_connected",
		"leaf_relay_last_block_publish_unixtime",
	} {
		if strings.Contains(body, absent) {
			t.Errorf("expected no %q series without a relay source wired, got:\n%s", absent, body)
		}
	}
}

// TestRelayMetrics_DisabledRelayStaysZero is the required explicit
// zero-cost-when-disabled proof at the Metrics/Collect level: a
// RelayStatsFunc that returns the permanent zero relay.RelayStats{}
// (exactly what relay.Relay.Stats() returns for a disabled/
// unconfigured Relay, see that method's doc comment) must render
// every leaf_relay_* counter/gauge as 0 and leaf_relay_connected as
// 0 -- present (this package still emits the series once a source IS
// wired), but at zero, matching this feature's explicit "stays at
// zero when relay disabled" requirement.
func TestRelayMetrics_DisabledRelayStaysZero(t *testing.T) {
	m := New("dev", 0)
	disabled := relay.NewRelay(relay.Config{URL: ""})
	m.SetRelaySource(func() relay.RelayStats { return disabled.Stats() })

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_relay_block_publish_total{result="success"} 0`,
		`leaf_relay_block_publish_total{result="error"} 0`,
		`leaf_relay_block_receive_total{result="dispatched"} 0`,
		`leaf_relay_block_receive_total{result="duplicate"} 0`,
		`leaf_relay_template_publish_total{result="success"} 0`,
		`leaf_relay_template_publish_total{result="error"} 0`,
		`leaf_relay_template_receive_total{result="dispatched"} 0`,
		`leaf_relay_template_receive_total{result="duplicate"} 0`,
		"leaf_relay_connected 0",
		"leaf_relay_last_block_publish_unixtime 0",
		"leaf_relay_last_block_receive_unixtime 0",
		"leaf_relay_last_template_publish_unixtime 0",
		"leaf_relay_last_template_receive_unixtime 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q (a genuinely-zero sample, not an absent series) in output, got:\n%s", want, body)
		}
	}
}

// TestShareClassificationMetrics proves
// leaf_direct_shares_by_classification_total emits all 3 real label
// values (trusted/validated/invalid) correctly -- a real counter,
// not snapshot-derived, so this mirrors
// TestRelayMetrics_SnapshotDerived's style of driving it via direct
// .WithLabelValues(...).Inc() calls then scraping+asserting.
func TestShareClassificationMetrics(t *testing.T) {
	m := New("dev", 0)
	m.SharesByClassificationTotal.WithLabelValues(ClassificationTrusted).Add(2)
	m.SharesByClassificationTotal.WithLabelValues(ClassificationValidated).Add(5)
	m.SharesByClassificationTotal.WithLabelValues(ClassificationInvalid).Inc()

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_direct_shares_by_classification_total{classification="trusted"} 2`,
		`leaf_direct_shares_by_classification_total{classification="validated"} 5`,
		`leaf_direct_shares_by_classification_total{classification="invalid"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestTemplateDistributionMetrics proves both
// leaf_direct_template_distribution_seconds and
// leaf_direct_template_distribution_miners emit correctly for BOTH
// source="local" and source="relay" after direct Observe/Set calls.
func TestTemplateDistributionMetrics(t *testing.T) {
	m := New("dev", 0)
	m.TemplateDistributionDuration.WithLabelValues("local").Observe(0.25)
	m.TemplateDistributionDuration.WithLabelValues("relay").Observe(1.5)
	m.TemplateDistributionMiners.WithLabelValues("local").Set(12)
	m.TemplateDistributionMiners.WithLabelValues("relay").Set(7)

	body := scrape(t, m)
	for _, want := range []string{
		`leaf_direct_template_distribution_seconds_count{source="local"} 1`,
		`leaf_direct_template_distribution_seconds_sum{source="local"} 0.25`,
		`leaf_direct_template_distribution_seconds_count{source="relay"} 1`,
		`leaf_direct_template_distribution_seconds_sum{source="relay"} 1.5`,
		`leaf_direct_template_distribution_miners{source="local"} 12`,
		`leaf_direct_template_distribution_miners{source="relay"} 7`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
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
// SharesTotal/BlocksTotal/SharesByClassificationTotal (via
// IncShareResult/IncBlockResult/IncShareClassification, the real
// call sites server.go's recordShare/recordBlock/
// recordShareClassification now use) a known number of times across
// SIMULATED ticks (never a real ticker/real sleep -- see
// shared.NewLabeledRateTrackersForTest/LabeledRateTrackers.Tick),
// then scrapes via the real Handler() and asserts:
//   - the existing _total counters report their EXACT, unchanged
//     cumulative values.
//   - the new _per_second gauges report the exact known constant
//     rate each label combination was driven at (a fixed
//     per-tick increment over a fixed number of 1-simulated-second
//     ticks converges to an EXACT, not just in-tolerance, rate --
//     see shared/ratetracker_test.go's identical convergence tests
//     for why this is deterministic).
//   - a label combination that was NEVER incremented
//     (ClassificationInvalid here) reports rate 0.
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
	m.classificationRate = shared.NewLabeledRateTrackersForTest(fc.Now, 60, time.Second)

	const ticks = 10
	for i := 0; i < ticks; i++ {
		fc.Advance(time.Second)

		m.IncShareResult(ResultAccepted)
		m.IncShareResult(ResultAccepted)
		m.IncShareResult(ResultAccepted)
		m.IncShareResult(ResultRejected)

		m.IncBlockResult(ResultAccepted)

		m.IncShareClassification(ClassificationTrusted)
		m.IncShareClassification(ClassificationTrusted)
		m.IncShareClassification(ClassificationValidated)
		// ClassificationInvalid is deliberately never incremented.

		m.sharesRate.Tick()
		m.blocksRate.Tick()
		m.classificationRate.Tick()
	}

	body := scrape(t, m)

	// _total counters: exact, unchanged cumulative values (3/1/1
	// per-tick * 10 ticks; classification 2/1/0 per-tick * 10 ticks).
	for _, tc := range []struct {
		name   string
		labels []string
		want   float64
	}{
		{"leaf_direct_shares_total", []string{"result", "accepted"}, 30},
		{"leaf_direct_shares_total", []string{"result", "rejected"}, 10},
		{"leaf_direct_blocks_total", []string{"result", "accepted"}, 10},
		{"leaf_direct_shares_by_classification_total", []string{"classification", "trusted"}, 20},
		{"leaf_direct_shares_by_classification_total", []string{"classification", "validated"}, 10},
	} {
		if got := metricValue(t, body, tc.name, tc.labels...); got != tc.want {
			t.Errorf("%s{%s=%q} = %v, want %v", tc.name, tc.labels[0], tc.labels[1], got, tc.want)
		}
	}
	// classification="invalid" was never incremented, so (unlike the
	// _per_second gauge below, which always emits all three known
	// classification values) the underlying CounterVec never
	// materializes that label combination's series at all -- confirm
	// it is genuinely ABSENT, not present-and-zero.
	if strings.Contains(body, `leaf_direct_shares_by_classification_total{classification="invalid"}`) {
		t.Errorf("expected no leaf_direct_shares_by_classification_total series for classification=invalid (never incremented), got:\n%s", body)
	}

	// _per_second gauges: a constant per-tick increment over
	// 1-simulated-second ticks converges to an EXACT rate equal to
	// that per-tick increment (see the doc comment above).
	for _, tc := range []struct {
		name   string
		labels []string
		want   float64
	}{
		{"leaf_direct_shares_per_second", []string{"result", "accepted"}, 3},
		{"leaf_direct_shares_per_second", []string{"result", "rejected"}, 1},
		{"leaf_direct_blocks_per_second", []string{"result", "accepted"}, 1},
		{"leaf_direct_shares_by_classification_per_second", []string{"classification", "trusted"}, 2},
		{"leaf_direct_shares_by_classification_per_second", []string{"classification", "validated"}, 1},
		// Never incremented -- must report exactly 0, not merely
		// "in tolerance" of 0.
		{"leaf_direct_shares_by_classification_per_second", []string{"classification", "invalid"}, 0},
	} {
		if got := metricValue(t, body, tc.name, tc.labels...); got != tc.want {
			t.Errorf("%s{%s=%q} = %v, want %v", tc.name, tc.labels[0], tc.labels[1], got, tc.want)
		}
	}
}
