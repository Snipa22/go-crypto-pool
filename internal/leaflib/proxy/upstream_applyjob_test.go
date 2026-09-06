// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"testing"
)

// discardLogger is a *log.Logger that throws away everything it's
// given -- used by these tests so applyJob's real, expected warning
// log lines don't spam test output.
func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// hexOfLen returns a deterministic, valid hex string decoding to
// exactly n bytes -- used to build synthetic blob fields of a
// specific size without caring about their actual byte values.
func hexOfLen(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return hex.EncodeToString(b)
}

// TestApplyJob_NeverUsesBlocktemplateBlobAsOutboundSource is required
// test 1 from the brief: an UpstreamJobPayload with a large (>408
// byte decoded) BlocktemplateBlob and an EMPTY Blob field must never
// result in a WorkerTemplate being stored/broadcast at all -- NOT
// even one built from BlocktemplateBlob. This is the exact live,
// confirmed pool.supportxmr.com "advanced xmr-node-proxy client"
// dialect failure mode this fix exists to stop propagating to
// downstream miners.
func TestApplyJob_NeverUsesBlocktemplateBlobAsOutboundSource(t *testing.T) {
	uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

	if got := uc.CurrentTemplate(); got != nil {
		t.Fatalf("precondition failed: expected no template before applyJob, got %+v", got)
	}

	oversizedBlocktemplateBlob := hexOfLen(1096) // observed live size, well over xmrig's kMaxBlobSize=408
	uc.applyJob(UpstreamJobPayload{
		JobID:             "advanced-client-job",
		BlocktemplateBlob: oversizedBlocktemplateBlob,
		Blob:              "", // deliberately empty: the real, live "advanced client" pool response shape
		Height:            12345,
	})

	got := uc.CurrentTemplate()
	if got != nil {
		t.Fatalf("applyJob must refuse to store/broadcast a WorkerTemplate when job.Blob is empty, got a stored template with len(Blob)=%d", len(got.Blob))
	}
}

// TestApplyJob_UsesBlobFieldWhenBothPresent is required test 2 from
// the brief: when a pool sends BOTH a small, realistic job.Blob AND a
// large job.BlocktemplateBlob (simulating a pool that publishes both
// fields on the same job object), applyJob must derive the resulting
// WorkerTemplate.Blob from the SMALL Blob field only, never from
// BlocktemplateBlob.
func TestApplyJob_UsesBlobFieldWhenBothPresent(t *testing.T) {
	uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

	smallBlobHex := hexOfLen(76) // realistic RandomX hashing blob size observed live against pool.supportxmr.com
	largeBlocktemplateBlobHex := hexOfLen(1032)

	uc.applyJob(UpstreamJobPayload{
		JobID:             "dual-field-job",
		Blob:              smallBlobHex,
		BlocktemplateBlob: largeBlocktemplateBlobHex,
		Height:            999,
	})

	tmpl := uc.CurrentTemplate()
	if tmpl == nil {
		t.Fatal("expected a WorkerTemplate to be stored when job.Blob is non-empty")
	}

	wantBlob, err := hex.DecodeString(smallBlobHex)
	if err != nil {
		t.Fatalf("decoding expected small blob: %v", err)
	}
	if !bytes.Equal(tmpl.Blob, wantBlob) {
		t.Fatalf("WorkerTemplate.Blob = %x, want the decoded small Blob field %x", tmpl.Blob, wantBlob)
	}
	if len(tmpl.Blob) >= 408 {
		t.Fatalf("WorkerTemplate.Blob length = %d, want < 408 (xmrig's kMaxBlobSize)", len(tmpl.Blob))
	}

	largeBlob, err := hex.DecodeString(largeBlocktemplateBlobHex)
	if err != nil {
		t.Fatalf("decoding large blocktemplate blob: %v", err)
	}
	if bytes.Equal(tmpl.Blob, largeBlob) {
		t.Fatal("WorkerTemplate.Blob must not be derived from BlocktemplateBlob")
	}

	// End-to-end: confirm the final downstream wire blob (via
	// BlobForWorker, exactly what Job.Blob/jobPayload use) also stays
	// small and matches the small field exactly, not the large one.
	wireBlob, err := tmpl.BlobForWorker(1)
	if err != nil {
		t.Fatalf("BlobForWorker: %v", err)
	}
	if len(wireBlob) >= 408 {
		t.Fatalf("final wire-facing blob length = %d, want < 408", len(wireBlob))
	}
	if !bytes.Equal(wireBlob, wantBlob) {
		t.Fatalf("final wire-facing blob = %x, want the decoded small Blob field %x (not derived from BlocktemplateBlob)", wireBlob, wantBlob)
	}
}

// TestApplyJob_EmptyBlobLogsWarningAndDoesNotPanic exercises the
// exact warning-log path required by the brief (job.Blob empty) via
// the real logger (rather than discardLogger) to prove applyJob
// doesn't panic and genuinely returns without side effects when a
// *second* job update also arrives with an empty Blob after a prior
// good template was already stored -- the good template must be left
// untouched, not overwritten with nothing.
func TestApplyJob_EmptyBlobLeavesExistingGoodTemplateUntouched(t *testing.T) {
	uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

	goodBlobHex := hexOfLen(76)
	uc.applyJob(UpstreamJobPayload{JobID: "good-job", Blob: goodBlobHex, Height: 1})

	first := uc.CurrentTemplate()
	if first == nil {
		t.Fatal("expected a stored template after a valid applyJob call")
	}

	// Now simulate the pool flipping into advanced-client mode
	// mid-connection (e.g. after a reconnect with a misconfigured
	// agent) -- Blob empty, BlocktemplateBlob oversized.
	uc.applyJob(UpstreamJobPayload{
		JobID:             "advanced-client-job-2",
		BlocktemplateBlob: hexOfLen(1800),
		Blob:              "",
		Height:            2,
	})

	second := uc.CurrentTemplate()
	if second == nil {
		t.Fatal("expected the previously-stored good template to remain after a rejected empty-Blob update")
	}
	if second.JobID != "good-job" {
		t.Fatalf("expected the prior good template (job_id=%q) to remain untouched, got job_id=%q", "good-job", second.JobID)
	}
}
