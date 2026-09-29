// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// histogramSampleCount reads the real Prometheus _count of a single
// HistogramVec label combination -- mirrors
// internal/leaflib/direct/debounce_test.go's own repushCount helper
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

// TestSubmitProcessingSeconds_AcceptedAndRejected_HaveNonZeroObservations
// covers both required cases for metric #1 (leaf_solo_submit_processing_
// seconds): a real, ordinary accepted submit round-trip and a real
// rejected one both get a non-zero observation count, labeled
// correctly by result.
func TestSubmitProcessingSeconds_AcceptedAndRejected_HaveNonZeroObservations(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "timing-accept-reject")
	jobID := currentJobIDForXN(t, h.testHarness, xn)

	// Accepted: a genuine, ordinary submit against the real,
	// currently-owned job.
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	acceptResp := h.recvLegacyShareResponse()
	if !acceptResp.Result {
		t.Fatalf("setup: expected the first submit to be accepted, got %#v", acceptResp)
	}

	// Rejected: an unknown/stale job_id.
	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: xnPrefixedNonceHex(xn, 2),
	})})
	rejectResp := h.recvLegacyShareResponse()
	if rejectResp.Result {
		t.Fatalf("setup: expected the second submit to be rejected, got %#v", rejectResp)
	}

	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, metrics.ResultAccepted); got == 0 {
		t.Errorf("leaf_solo_submit_processing_seconds{result=%q} sample count = 0, want > 0", metrics.ResultAccepted)
	}
	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, metrics.ResultRejected); got == 0 {
		t.Errorf("leaf_solo_submit_processing_seconds{result=%q} sample count = 0, want > 0", metrics.ResultRejected)
	}
}

// TestSubmitProcessingSeconds_LoginRequiredEarlyExit_IsTimed covers the
// brief's explicit requirement that an early-exit rejection (login
// required before submit) is still timed and counted, not
// special-cased out.
func TestSubmitProcessingSeconds_LoginRequiredEarlyExit_IsTimed(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)

	// No login at all -- submit immediately.
	h.send(Request{ID: 1, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: "0000000000000000", Nonce: "0000000000000000",
	})})
	resp := h.recvLegacyErrorResponse()
	if resp.Error == "" {
		t.Fatalf("setup: expected a pre-login submit to be rejected, got %#v", resp)
	}

	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, metrics.ResultRejected); got == 0 {
		t.Errorf("leaf_solo_submit_processing_seconds{result=%q} sample count = 0 for a pre-login submit, want > 0 (early exits must still be timed)", metrics.ResultRejected)
	}
}

// TestSubmitValidationSeconds_ObservedForGenuineBlockFindCandidate
// covers metric #2 (leaf_solo_submit_validation_seconds): a genuine
// RXT block-find candidate reaches the real v.Validate call inside
// finishSubmit, and that call's own wall-clock time is observed,
// labeled algo="rxt".
func TestSubmitValidationSeconds_ObservedForGenuineBlockFindCandidate(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)
	jobID := rxtLoginAndGetJobID(t, h.testHarness, "timing-validation-blockfind")

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: "00000001", Result: hex.EncodeToString(blockFindResultHash(1)),
	})})
	resp := h.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("setup: expected the genuine block-find candidate to be accepted, got %#v", resp)
	}

	if got := histogramSampleCount(t, h.metrics.SubmitValidationSeconds, "rxt"); got == 0 {
		t.Errorf(`leaf_solo_submit_validation_seconds{algo="rxt"} sample count = 0, want > 0 (real v.Validate call for a genuine block-find candidate)`)
	}
}

// TestSubmitValidationSeconds_NotObservedForOrdinarySkippedClaim
// covers the brief's explicit requirement that the real
// validation-skip branch NEVER records a sample: an ordinary,
// sub-block-difficulty RXT claim (DISPATCH_BRIEF.md 2026-09-10 Fix 4)
// is credited without ever calling v.Validate at all -- this must
// leave leaf_solo_submit_validation_seconds{algo="rxt"} at exactly
// zero, while leaf_solo_submit_processing_seconds still correctly
// records the accept.
func TestSubmitValidationSeconds_NotObservedForOrdinarySkippedClaim(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)
	jobID := rxtLoginAndGetJobID(t, h.testHarness, "timing-validation-skip")

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: "00000001", Result: hex.EncodeToString(largeResultHash(1)),
	})})
	resp := h.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("setup: expected the ordinary sub-block claim to be accepted, got %#v", resp)
	}

	// Wait for handleSubmit's own deferred SubmitProcessingSeconds
	// observation to land (see waitForHistogramSampleCountAtLeast's
	// doc comment) -- since this ordinary-claim path never enters
	// finishSubmit at all (confirmed by session.go's own dispatch
	// decision), by the time this fires, SubmitValidationSeconds is
	// GUARANTEED to still be at its initial zero -- no wait/race to
	// account for on that side, since finishSubmit's v.Validate call
	// site is simply never reached in this code path.
	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, metrics.ResultAccepted); got == 0 {
		t.Errorf("leaf_solo_submit_processing_seconds{result=%q} sample count = 0, want > 0 (the ordinary accept path must still be timed)", metrics.ResultAccepted)
	}
	if got := histogramSampleCount(t, h.metrics.SubmitValidationSeconds, "rxt"); got != 0 {
		t.Errorf(`leaf_solo_submit_validation_seconds{algo="rxt"} sample count = %d, want exactly 0 (this path never calls v.Validate at all)`, got)
	}
}
