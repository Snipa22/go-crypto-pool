package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandler_ServesValidPrometheusExposition is the basic "does
// /metrics respond and look like valid Prometheus exposition format"
// smoke test: status 200, the expected Content-Type, and a non-empty
// body, served through a real httptest.Server + the real
// promhttp-backed Handler (no mocked metrics interface anywhere).
func TestHandler_ServesValidPrometheusExposition(t *testing.T) {
	m := New("test-version")

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

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if n == 0 {
		t.Fatal("expected non-empty /metrics body")
	}
	body := string(buf[:n])
	if !strings.Contains(body, "backend_build_info") {
		t.Errorf("expected backend_build_info in /metrics output, got:\n%s", body)
	}
}

// TestBuildInfo_CarriesVersionLabel scrapes the real rendered text and
// checks the version label made it through end to end.
func TestBuildInfo_CarriesVersionLabel(t *testing.T) {
	m := New("v9.9.9-test")

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	want := `backend_build_info{version="v9.9.9-test"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected %q in /metrics output, got:\n%s", want, body)
	}
}

// TestSharesTotal_IncrementsAndRenders exercises the counter directly
// (bypassing the HTTP handlers, which have their own tests in the api
// package) and confirms the increment shows up in real scraped output
// with the expected label set.
func TestSharesTotal_IncrementsAndRenders(t *testing.T) {
	m := New("dev")
	m.SharesTotal.WithLabelValues("RXT", "TESTNET", "PPLNS", ResultAccepted).Inc()
	m.SharesTotal.WithLabelValues("RXT", "TESTNET", "PPLNS", ResultAccepted).Inc()
	m.SharesTotal.WithLabelValues(UnknownLabel, UnknownLabel, UnknownLabel, ResultRejected).Inc()

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	wantAccepted := `shares_total{algo="RXT",network="TESTNET",pool_type="PPLNS",result="accepted"} 2`
	if !strings.Contains(body, wantAccepted) {
		t.Errorf("expected %q in /metrics output, got:\n%s", wantAccepted, body)
	}
	wantRejected := `shares_total{algo="unknown",network="unknown",pool_type="unknown",result="rejected"} 1`
	if !strings.Contains(body, wantRejected) {
		t.Errorf("expected %q in /metrics output, got:\n%s", wantRejected, body)
	}
}

// TestBlocksTotal_HasNoPoolTypeLabel documents (via a real render)
// that blocks_total intentionally omits pool_type — the label set for
// blocks_total is algo/network/result only, per spec.
func TestBlocksTotal_HasNoPoolTypeLabel(t *testing.T) {
	m := New("dev")
	m.BlocksTotal.WithLabelValues("C29", "MAINNET", ResultAccepted).Inc()

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	want := `blocks_total{algo="C29",network="MAINNET",result="accepted"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected %q in /metrics output, got:\n%s", want, body)
	}
	if strings.Contains(body, "pool_type") && strings.Contains(body, "blocks_total") {
		// Sanity guard: pool_type must not appear on the blocks_total
		// series specifically (it may legitimately appear elsewhere,
		// e.g. on the shares_total HELP/TYPE lines, so only fail if it
		// shows up on a blocks_total sample line itself).
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "blocks_total{") && strings.Contains(line, "pool_type") {
				t.Errorf("blocks_total must not carry a pool_type label, got line: %s", line)
			}
		}
	}
}

// TestHistograms_ObserveAndRender confirms the insert-duration
// histograms are real, wired Histogram collectors that render sample
// counts/sums through the real text-exposition path.
func TestHistograms_ObserveAndRender(t *testing.T) {
	m := New("dev")
	m.ShareInsertDuration.Observe(0.01)
	m.BlockInsertDuration.Observe(0.02)

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	for _, want := range []string{"share_insert_duration_seconds_count 1", "block_insert_duration_seconds_count 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in /metrics output, got:\n%s", want, body)
		}
	}
}

// TestHTTPRequestsInFlight_RendersGauge confirms the gauge is a real,
// wired Gauge collector.
func TestHTTPRequestsInFlight_RendersGauge(t *testing.T) {
	m := New("dev")
	m.HTTPRequestsInFlight.Inc()
	m.HTTPRequestsInFlight.Inc()
	m.HTTPRequestsInFlight.Dec()

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "http_requests_in_flight 1") {
		t.Errorf("expected http_requests_in_flight 1 in /metrics output, got:\n%s", body)
	}
}

// TestNew_MultipleInstancesDoNotPanic confirms the private-registry
// design: constructing many independent Metrics (as tests/handlers do)
// never triggers Prometheus's "duplicate metrics collector
// registration attempted" panic.
func TestNew_MultipleInstancesDoNotPanic(t *testing.T) {
	for i := 0; i < 5; i++ {
		if m := New("dev"); m == nil {
			t.Fatal("New returned nil")
		}
	}
}

// TestDisbursementAmbiguityMetrics_RegisterAndRender covers the three
// collectors added for the wallet-transfer double-payment fix. The
// audit explicitly flagged that whole class of incident as
// metric-invisible: a payout the engine wrongly recorded as FAILED
// (and then re-sent) produced no signal at all beyond a log line.
// These are now the alertable surface, so this test asserts they
// register, carry the documented labels, and actually render.
func TestDisbursementAmbiguityMetrics_RegisterAndRender(t *testing.T) {
	m := New("test")

	m.DisbursementAmbiguousPayoutsTotal.WithLabelValues("RXM", "MAINNET", AmbiguousCauseTransfer).Inc()
	m.DisbursementAmbiguousPayoutsTotal.WithLabelValues("RXT", "MAINNET", AmbiguousCauseBookkeeping).Inc()
	m.DisbursementHaltsTotal.WithLabelValues("RXM", "MAINNET", HaltReasonUnresolvedPayouts).Inc()
	m.DisbursementHaltsTotal.WithLabelValues("RXM", "MAINNET", HaltReasonAmbiguousBatch).Inc()
	m.DisbursementUnresolvedPayouts.WithLabelValues("RXM", "MAINNET").Set(3)
	// The batch-result label set must include the new "ambiguous"
	// outcome, kept distinct from "failed" (one is a page-worthy
	// incident, the other is routine).
	m.DisbursementBatchesTotal.WithLabelValues("RXM", "MAINNET", DisbursementResultAmbiguous).Inc()

	body := scrapeMetrics(t, m)

	for _, want := range []string{
		`disbursement_ambiguous_payouts_total{algo="RXM",cause="transfer_error",network="MAINNET"} 1`,
		`disbursement_ambiguous_payouts_total{algo="RXT",cause="bookkeeping_error",network="MAINNET"} 1`,
		`disbursement_halts_total{algo="RXM",network="MAINNET",reason="unresolved_payouts"} 1`,
		`disbursement_halts_total{algo="RXM",network="MAINNET",reason="ambiguous_batch"} 1`,
		`disbursement_unresolved_payouts{algo="RXM",network="MAINNET"} 3`,
		`disbursement_batches_total{algo="RXM",network="MAINNET",result="ambiguous"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in /metrics output, got:\n%s", want, body)
		}
	}
}

// scrapeMetrics renders m's registry through the real promhttp
// handler and returns the full exposition body.
func scrapeMetrics(t *testing.T, m *Metrics) string {
	t.Helper()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	var sb strings.Builder
	buf := make([]byte, 8192)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
