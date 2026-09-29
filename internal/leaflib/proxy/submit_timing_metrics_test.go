// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy/metrics"
)

// histogramSampleCount reads the real Prometheus _count of a single
// HistogramVec label combination -- mirrors
// internal/leaflib/direct's own debounce_test.go's repushCount helper
// exactly (Write(*dto.Metric) is the only way to read a histogram's
// real sample count; testutil.CollectAndCount counts distinct time
// series, not Observe() calls).
func histogramSampleCount(t *testing.T, hv *prometheus.HistogramVec, labelValues ...string) int {
	t.Helper()
	obs := hv.WithLabelValues(labelValues...)
	collector, ok := obs.(prometheus.Metric)
	if !ok {
		t.Fatalf("observer for labels %v does not implement prometheus.Metric", labelValues)
	}
	return writeSampleCount(t, collector)
}

// plainHistogramSampleCount is histogramSampleCount's unlabeled
// counterpart, for leaf-proxy's own deliberately-unlabeled
// SubmitValidationSeconds (see that field's own doc comment on why
// it has no "algo" label, unlike solo/direct's identically-named
// metric).
func plainHistogramSampleCount(t *testing.T, h prometheus.Histogram) int {
	t.Helper()
	collector, ok := h.(prometheus.Metric)
	if !ok {
		t.Fatalf("Histogram does not implement prometheus.Metric")
	}
	return writeSampleCount(t, collector)
}

func writeSampleCount(t *testing.T, collector prometheus.Metric) int {
	t.Helper()
	var m dto.Metric
	if err := collector.Write(&m); err != nil {
		t.Fatalf("Write(*dto.Metric): %v", err)
	}
	if m.Histogram == nil || m.Histogram.SampleCount == nil {
		return 0
	}
	return int(*m.Histogram.SampleCount)
}

// waitForHistogramSampleCountAtLeast polls histogramSampleCount until
// it reaches want or a short deadline elapses. NEEDED because
// SubmitProcessingSeconds is observed from a defer that runs AFTER
// handleSubmit/finishSubmit's own response write (the metric's own
// "to the point the response is written" definition includes the
// write itself) -- a test that reads the wire response and then
// immediately checks this histogram (same net.Pipe unblocking both
// sides "simultaneously") would otherwise be racing the still-pending
// deferred Observe call on the session's own goroutine.
func waitForHistogramSampleCountAtLeast(t *testing.T, hv *prometheus.HistogramVec, want int, labelValues ...string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got int
	for {
		got = histogramSampleCount(t, hv, labelValues...)
		if got >= want {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(time.Millisecond)
	}
}

// waitForPlainHistogramSampleCountAtLeast is
// waitForHistogramSampleCountAtLeast's unlabeled counterpart.
func waitForPlainHistogramSampleCountAtLeast(t *testing.T, h prometheus.Histogram, want int) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got int
	for {
		got = plainHistogramSampleCount(t, h)
		if got >= want {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSubmitProcessingSeconds_AcceptedAndRejected_HaveNonZeroObservations
// covers both required cases for metric #1
// (leaf_proxy_submit_processing_seconds): a real, ordinary accepted
// (local-credit) submit round-trip and a real rejected one (duplicate
// nonce) both get a non-zero observation count, labeled correctly by
// result.
func TestSubmitProcessingSeconds_AcceptedAndRejected_HaveNonZeroObservations(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	m := h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	loginResp := c.login(t, "timing-accept-reject")

	// Accepted: a below-upstream-target, local-credit-only claim
	// (never touches the real validator at all).
	claimedHash := hashForDifficulty(500_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result == nil {
		t.Fatalf("setup: expected the first submit to be accepted, got error=%v", resp.Error)
	}

	// Rejected: the same nonce resubmitted against the same job.
	c.send(Request{ID: 3, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result != nil {
		t.Fatal("setup: expected the duplicate-nonce resubmit to be rejected")
	}

	if got := waitForHistogramSampleCountAtLeast(t, m.SubmitProcessingSeconds, 1, metrics.ResultAccepted); got == 0 {
		t.Errorf("leaf_proxy_submit_processing_seconds{result=%q} sample count = 0, want > 0", metrics.ResultAccepted)
	}
	if got := waitForHistogramSampleCountAtLeast(t, m.SubmitProcessingSeconds, 1, metrics.ResultRejected); got == 0 {
		t.Errorf("leaf_proxy_submit_processing_seconds{result=%q} sample count = 0, want > 0", metrics.ResultRejected)
	}
}

// TestSubmitProcessingSeconds_LoginRequiredEarlyExit_IsTimed covers
// the brief's explicit requirement that an early-exit rejection
// (login required before submit) is still timed and counted, not
// special-cased out.
func TestSubmitProcessingSeconds_LoginRequiredEarlyExit_IsTimed(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	m := h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	// No login at all -- submit immediately.
	submitParams, _ := json.Marshal(SubmitRequest{JobID: "unknown", Nonce: nonceHexAt(1), Result: hashForDifficulty(500_000)})
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	var resp leaflib.ErrorResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if resp.Error == nil {
		t.Fatalf("setup: expected a pre-login submit to be rejected, got %#v", resp)
	}

	if got := waitForHistogramSampleCountAtLeast(t, m.SubmitProcessingSeconds, 1, metrics.ResultRejected); got == 0 {
		t.Errorf("leaf_proxy_submit_processing_seconds{result=%q} sample count = 0 for a pre-login submit, want > 0 (early exits must still be timed)", metrics.ResultRejected)
	}
}

// TestSubmitValidationSeconds_ObservedForGenuineUpstreamForwardCandidate
// covers metric #2 (leaf_proxy_submit_validation_seconds): a claim
// meeting or exceeding the real upstream pool's own requested share
// difficulty is a genuine upstream-forward candidate, reaching the
// real ValidateBlobSeedResult call inside finishSubmit -- that call's
// own wall-clock time is observed.
func TestSubmitValidationSeconds_ObservedForGenuineUpstreamForwardCandidate(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	m := h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	loginResp := c.login(t, "timing-validation-real")

	// hashForDifficulty(2_000_000) exceeds this harness's
	// WorkerTemplate.TargetDiff (1_000_000, the real upstream pool's
	// own requested share difficulty) -- a genuine upstream-forward
	// candidate that must pay the real validator call.
	claimedHash := hashForDifficulty(2_000_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result == nil {
		t.Fatalf("setup: expected the genuine upstream-forward candidate to be accepted, got error=%v", resp.Error)
	}

	if got := waitForPlainHistogramSampleCountAtLeast(t, m.SubmitValidationSeconds, 1); got == 0 {
		t.Errorf("leaf_proxy_submit_validation_seconds sample count = 0, want > 0 (real ValidateBlobSeedResult call for a genuine upstream-forward candidate)")
	}
}

// TestSubmitValidationSeconds_NotObservedForLocalCreditOnlyClaim
// covers the brief's explicit requirement that the real
// validation-skip branch NEVER records a sample: a claim below the
// real upstream pool's own requested share difficulty is credited
// locally without ever calling ValidateBlobSeedResult at all -- this
// must leave leaf_proxy_submit_validation_seconds at exactly zero,
// while leaf_proxy_submit_processing_seconds still correctly records
// the accept.
func TestSubmitValidationSeconds_NotObservedForLocalCreditOnlyClaim(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	m := h.server.EnableMetrics("test", 0)

	c, _ := h.connect()
	loginResp := c.login(t, "timing-validation-skip")

	// Below TargetDiff (1_000_000) -- local-credit only, no
	// validator call at all.
	claimedHash := hashForDifficulty(500_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result == nil {
		t.Fatalf("setup: expected the local-credit-only claim to be accepted, got error=%v", resp.Error)
	}

	// Wait for handleSubmit's own deferred SubmitProcessingSeconds
	// observation to land -- since this local-credit path never
	// enters finishSubmit at all, by the time this fires,
	// SubmitValidationSeconds is guaranteed to still be at its
	// initial zero.
	if got := waitForHistogramSampleCountAtLeast(t, m.SubmitProcessingSeconds, 1, metrics.ResultAccepted); got == 0 {
		t.Errorf("leaf_proxy_submit_processing_seconds{result=%q} sample count = 0, want > 0 (the local-credit accept path must still be timed)", metrics.ResultAccepted)
	}
	if got := plainHistogramSampleCount(t, m.SubmitValidationSeconds); got != 0 {
		t.Errorf("leaf_proxy_submit_validation_seconds sample count = %d, want exactly 0 (this path never calls ValidateBlobSeedResult at all)", got)
	}
}
