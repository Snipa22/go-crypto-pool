// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// histogramSampleCount reads the real Prometheus _count of a single
// HistogramVec label combination -- mirrors this package's own
// debounce_test.go's repushCount helper exactly (Write(*dto.Metric)
// is the only way to read a histogram's real sample count;
// testutil.CollectAndCount counts distinct time series, not
// Observe() calls).
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

// TestDirectSubmitProcessingSeconds_AcceptedAndRejected_HaveNonZeroObservations
// covers both required cases for metric #1
// (leaf_direct_submit_processing_seconds): a real, ordinary accepted
// submit round-trip and a real rejected one both get a non-zero
// observation count, labeled correctly by result.
func TestDirectSubmitProcessingSeconds_AcceptedAndRejected_HaveNonZeroObservations(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("timing-accept-reject"))
	jobID := directCurrentJobIDForXN(t, h.directTestHarness, xn)

	// Accepted: a genuine, ordinary submit against the real,
	// currently-owned job.
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	acceptResp := h.recvLegacyShareResponse()
	if !acceptResp.Result {
		t.Fatalf("setup: expected the first submit to be accepted, got %#v", acceptResp)
	}

	// Rejected: an unknown/stale job_id.
	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: directXNPrefixedNonceHex(xn, 2),
	})})
	rejectResp := h.recvLegacyShareResponse()
	if rejectResp.Result {
		t.Fatalf("setup: expected the second submit to be rejected, got %#v", rejectResp)
	}

	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, directmetrics.ResultAccepted); got == 0 {
		t.Errorf("leaf_direct_submit_processing_seconds{result=%q} sample count = 0, want > 0", directmetrics.ResultAccepted)
	}
	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, directmetrics.ResultRejected); got == 0 {
		t.Errorf("leaf_direct_submit_processing_seconds{result=%q} sample count = 0, want > 0", directmetrics.ResultRejected)
	}
}

// TestDirectSubmitProcessingSeconds_LoginRequiredEarlyExit_IsTimed
// covers the brief's explicit requirement that an early-exit
// rejection (login required before submit) is still timed and
// counted, not special-cased out.
func TestDirectSubmitProcessingSeconds_LoginRequiredEarlyExit_IsTimed(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	// No login at all -- submit immediately.
	h.send(solo.Request{ID: 1, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: "0000000000000000", Nonce: "0000000000000000",
	})})
	resp := h.recvLegacyErrorResponse()
	if resp.Error == "" {
		t.Fatalf("setup: expected a pre-login submit to be rejected, got %#v", resp)
	}

	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, directmetrics.ResultRejected); got == 0 {
		t.Errorf("leaf_direct_submit_processing_seconds{result=%q} sample count = 0 for a pre-login submit, want > 0 (early exits must still be timed)", directmetrics.ResultRejected)
	}
}

// TestDirectSubmitValidationSeconds_ObservedForRealValidatedSubmit
// covers metric #2 (leaf_direct_submit_validation_seconds): a real,
// non-skipped RXT submit reaches the real v.Validate call inside
// finishSubmit, and that call's own wall-clock time is observed,
// labeled algo="rxt".
func TestDirectSubmitValidationSeconds_ObservedForRealValidatedSubmit(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("timing-validation-real"))
	jobID := directCurrentJobIDForXN(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID,
		Nonce:  classificationRXTNonceHex(1),
		Result: classificationRXTResultHex, // real-shaped, block-find-crossing claimed hash
	})})
	resp := h.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("setup: expected the real validated RXT submit to be accepted, got %#v", resp)
	}

	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitValidationSeconds, 1, "rxt"); got == 0 {
		t.Errorf(`leaf_direct_submit_validation_seconds{algo="rxt"} sample count = 0, want > 0 (real v.Validate call for a non-skipped submit)`)
	}
}

// TestDirectSubmitValidationSeconds_NotObservedForTrustedMinerSkip
// covers the brief's explicit requirement that the real
// trusted-miner validation-skip branch NEVER records a sample --
// leaf-direct, UNLIKE leaf-solo, still wires Server.EnableTrust (see
// finishSubmit's own doc comment), so this is the genuine "skip"
// branch metric #2 must never time. Mirrors
// trust_integration_test.go's own real, end-to-end
// retry-until-genuinely-skipped pattern exactly (ShouldSkipValidation
// is probabilistic once trust is "ready", not deterministic).
func TestDirectSubmitValidationSeconds_NotObservedForTrustedMinerSkip(t *testing.T) {
	h := newClassificationTestHarness(t, true)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("timing-validation-skip"))
	jobID := directCurrentJobIDForXN(t, h.directTestHarness, xn)

	h.server.mu.RLock()
	var sess *Session
	for _, s := range h.server.sessions {
		if s.sessionID == sessionID {
			sess = s
			break
		}
	}
	h.server.mu.RUnlock()
	if sess == nil {
		t.Fatalf("could not find session %q on server after login", sessionID)
	}
	if sess.trust == nil {
		t.Fatal("session.trust is nil despite EnableTrust having been called before this session was created")
	}
	forceDirectTrustReady(sess.trust)

	var accepted bool
	for attempt := 0; attempt < 20; attempt++ {
		h.send(solo.Request{ID: 70, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			ID:     sessionID,
			JobID:  jobID,
			Nonce:  classificationRXTNonceHex(uint32(1000 + attempt)),
			Result: classificationRXTResultHex,
		})})
		resp := h.recvShareResponse()
		accepted = resp.Result != nil
		if accepted {
			break
		}
		forceDirectTrustReady(sess.trust)
	}
	if !accepted {
		t.Fatalf("expected at least one trusted-share skip to succeed within 20 attempts")
	}

	// Wait for handleSubmit's own deferred SubmitProcessingSeconds
	// observation to land (see waitForHistogramSampleCountAtLeast's
	// doc comment) -- by the time this fires, this genuinely-skipped
	// finishSubmit run has already returned (same closure, same
	// defer ordering), so SubmitValidationSeconds is guaranteed to
	// have already NOT been touched.
	if got := waitForHistogramSampleCountAtLeast(t, h.metrics.SubmitProcessingSeconds, 1, directmetrics.ResultAccepted); got == 0 {
		t.Fatalf("leaf_direct_submit_processing_seconds{result=%q} sample count = 0, want > 0 (the trusted-skip accept path must still be timed)", directmetrics.ResultAccepted)
	}
	if got := histogramSampleCount(t, h.metrics.SubmitValidationSeconds, "rxt"); got != 0 {
		t.Errorf(`leaf_direct_submit_validation_seconds{algo="rxt"} sample count = %d, want exactly 0 (the trusted-miner skip branch never calls v.Validate at all)`, got)
	}
}
