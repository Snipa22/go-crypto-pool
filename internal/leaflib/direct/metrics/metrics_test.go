// Copyright and license: see repository LICENSE (MIT).
package metrics

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

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
