// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"testing"

	"github.com/Snipa22/go-xmr-lib/support"
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

// Real go-xmr-lib v0.2.5 fixtures, copied verbatim from that module's
// own support/block_test.go (github.com/Snipa22/go-xmr-lib@v0.2.5,
// $(go env GOPATH)/pkg/mod/github.com/!snipa22/go-xmr-lib@v0.2.5/support/block_test.go)
// -- real, valid Monero block template blobs and their real,
// library-verified expected hashing-blob outputs. Do NOT
// hand-fabricate binary block data; these are the same constants
// go-xmr-lib's own TestGetBlockHashingBlob asserts against.
const (
	// onlyMinerBlockTemplate/onlyMinerBlockTemplateHashingBlob: a
	// real raw blocktemplate_blob (no non-coinbase transactions) and
	// its real, correctly-sized RandomX hashing blob.
	onlyMinerBlockTemplate            = "0b0be2e4daec05e1c0a4a7bb5b3b658b518993017090bb110fe09402be9f07fded36391de176af0000000002a1f47401ffe5f3740192f0ffe7e545023306faf1cb524c328257f9d2ad35f78c4bb6ef0167ca60339aff0abb397a73803401c251fe844c41d6e3429efe40d017c7963bb15a4816c6ff611bf8cf3e0ac7bd5702110000000000000000000000000000000000000cd9ab785badfc78eda6ba4d7c2bd279ed450b94ab04e98a5c90ed7a989e8aae93b0c46214d0d68b23af4b7a3ab8ed6cfda825206003cbfa5d4810397a7da13f6c91b3c8617c561a11eea018bb5551cdb7c9552dbc475076e9be8740f5d462761f15d74b504dab729e9bb327e2f0d9c7ae201aa18efe8caee228269bf1c95ee6facc96ef0e2c233165a0193dbbe0fc256ac3511edbe3a981bd5d0541aa2e2b87887e1ccd4ef4e3d4355e25bdbe9ed21e4c2ab599b4d117612caf8c979ba76436413d290aa5a71339a5ccb9c2ae53798dd2d198b7415847277ea398da34fb913b7e6a42a9103d82c4ef2817d1ec47d746b6a3bb81fdaf83d35b0c49e1d6bc6aa69c6b347b1ebaa3ca077a5847a1500f17dba525f41323e3d696b36a2741146ec65e8fae1a4b38bf7dfabe511b964129117bd6d582235c0c2829e0f2fadf51979d9c6ff750bf38250cfd882d3ef7accc9e80b154187a541b0e2be6f9b6096a632c95bd50cec3019496c01345491a1f9aef4ac86b2b1148339667a05fa60e2a0d978f"
	onlyMinerBlockTemplateHashingBlob = "0b0be2e4daec05e1c0a4a7bb5b3b658b518993017090bb110fe09402be9f07fded36391de176af0000000035b8d4dd8cee2f82dcece2dbea5afbdb4d41725c4f5a2d5a0c343921ab7c1e160d"

	// offsetData/offsetDataExtra: a real fixture with a 60-byte
	// reserved-nonce region inside the coinbase tx's tx_extra (see
	// go-xmr-lib's TestBlockOffset/TestNonceChanges,
	// b.MinerTxn.Extra.Nonce is 60 bytes). Used below for the
	// reserved_offset/worker-nonce-patch regression test.
	offsetData      = "0e0ed286da8006ecdc1aab3033cf1716c52f13f9d8ae0051615a2453643de94643b550d543becd0000000002abc78b0101ffefc68b0101fcfcf0d4b422025014bb4a1eade6622fd781cb1063381cad396efa69719b41aa28b4fce8c7ad4b5f019ce1dc670456b24a5e03c2d9058a2df10fec779e2579753b1847b74ee644f16b023c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000051399a1bc46a846474f5b33db24eae173a26393b976054ee14f9feefe99925233802867097564c9db7a36af5bb5ed33ab46e63092bd8d32cef121608c3258edd55562812e21cc7e3ac73045745a72f7d74581d9a0849d6f30e8b2923171253e864f4e9ddea3acb5bc755f1c4a878130a70c26297540bc0b7a57affb6b35c1f03d8dbd54ece8457531f8cba15bb74516779c01193e212050423020e45aa2c15dcb"
	offsetDataExtra = "019ce1dc670456b24a5e03c2d9058a2df10fec779e2579753b1847b74ee644f16b023c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	// offsetDataReservedOffset is the REAL, VERIFIED absolute byte
	// offset (from the start of offsetData's raw blob) where its
	// 60-byte tx_extra nonce region starts. Computed and verified via
	// a throwaway Go program this pass, NOT hand-counted:
	//   - parsed offsetData with support.ParseBlockFromTemplateBlob
	//   - re-serialized (using the exact same library primitives) the
	//     BlockHeader, then the miner tx's version/unlock_time/vin/vout
	//     fields, then the extra-length varint, then the extra's own
	//     internal prefix (pubkey tag+pubkey, nonce tag+nonce-length
	//     byte) -- summing real byte lengths at each step:
	//       header:                              43 bytes
	//       txn prefix (version..vout, no extra): 51 bytes
	//       extra length varint:                   1 byte
	//       extra internal prefix (tags+pubkey):  35 bytes
	//       -----------------------------------------------
	//       absolute offset of nonce region:      130
	//   - ROUND-TRIP VERIFIED in that same program: decoded the raw
	//     blob, confirmed bytes [130:190] exactly equal the parsed
	//     Extra.Nonce (all-zero, matching offsetDataExtra above), then
	//     wrote 60 distinct non-zero test bytes at [130:190] in a
	//     COPY, re-ran ParseBlockFromTemplateBlob on the patched hex,
	//     and confirmed the re-parsed Extra.Nonce read back those
	//     exact same 60 bytes -- proving 130 is genuinely correct, not
	//     merely plausible.
	//   - that same program also confirmed offsetData's real hashing
	//     blob (support.GetBlockHashingBlob) is 76 bytes long -- used
	//     below to assert the worker-nonce-patched result stays the
	//     correctly-sized hashing blob shape, not the raw 352-byte
	//     full blob.
	offsetDataReservedOffset = 130
	offsetDataNonceLen       = 60
	offsetDataHashingBlobLen = 76

	// offsetDataPoolOffset is a SECOND real, verified absolute byte
	// offset within offsetData's own 60-byte tx_extra nonce region
	// ([130:190), per offsetDataReservedOffset's own doc comment
	// above), used by the advanced-client pool-nonce regression test
	// below (TestJobManager_NextJob_AdvancedClientPatchesBothNoncesIntoRawBlobBeforeConverting)
	// to give ReservedOffset and PoolOffset two DISJOINT 4-byte
	// windows within the same real fixture -- reproducing Alex's
	// real production scenario (a pool publishing BOTH offsets
	// together on the advanced/xmr-node-proxy dialect) rather than
	// only one offset at a time. Verified the same way
	// offsetDataReservedOffset was (see its doc comment for the
	// method): a throwaway Go program patched 4 distinct non-zero
	// bytes at [160:164] in a COPY of the raw offsetData blob,
	// re-ran support.ParseBlockFromTemplateBlob on the patched hex,
	// and confirmed the re-parsed Extra.Nonce read back those exact
	// same 4 bytes at Extra.Nonce[30:34] (160-130=30 bytes into the
	// 60-byte nonce region) -- and that a template with BOTH
	// [130:134] and [160:164] patched simultaneously still parses
	// and converts cleanly to the same 76-byte
	// (offsetDataHashingBlobLen) hashing-blob shape.
	offsetDataPoolOffset = 160
)

// TestApplyJob_ConvertsRealBlocktemplateBlobToHashingBlobWhenBlobAbsent
// replaces the old (now-wrong-per-the-real-fix)
// TestApplyJob_NeverUsesBlocktemplateBlobAsOutboundSource: that test's
// premise -- a present BlocktemplateBlob + empty Blob must result in
// NO stored template at all -- was the PR #60 stopgap's behavior, not
// the real fix. Per repo maintainer Alex's explicit feedback ("the
// raw blob needs to be passed through the encoder to convert it to a
// minable blob... there's a helper for that in the library"),
// applyJob must now run a genuine BlocktemplateBlob through
// go-xmr-lib/support's real ParseBlockFromTemplateBlob +
// GetBlockHashingBlob and store the CONVERTED result, using a real,
// library-verified fixture (not hand-fabricated bytes).
func TestApplyJob_ConvertsRealBlocktemplateBlobToHashingBlobWhenBlobAbsent(t *testing.T) {
	uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

	if got := uc.CurrentTemplate(); got != nil {
		t.Fatalf("precondition failed: expected no template before applyJob, got %+v", got)
	}

	uc.applyJob(UpstreamJobPayload{
		JobID:             "advanced-client-job",
		BlocktemplateBlob: onlyMinerBlockTemplate,
		Blob:              "", // deliberately empty: the real, live "advanced client" pool response shape
		Height:            12345,
	})

	got := uc.CurrentTemplate()
	if got == nil {
		t.Fatal("expected applyJob to store a WorkerTemplate converted from a real, valid BlocktemplateBlob, got nil")
	}

	wantHashingBlob, err := hex.DecodeString(onlyMinerBlockTemplateHashingBlob)
	if err != nil {
		t.Fatalf("decoding expected hashing blob fixture: %v", err)
	}
	if !bytes.Equal(got.Blob, wantHashingBlob) {
		t.Fatalf("WorkerTemplate.Blob = %x, want the real go-xmr-lib-derived hashing blob %x", got.Blob, wantHashingBlob)
	}
	if len(got.Blob) >= 408 {
		t.Fatalf("WorkerTemplate.Blob length = %d, want < 408 (xmrig's kMaxBlobSize)", len(got.Blob))
	}

	wantRaw, err := hex.DecodeString(onlyMinerBlockTemplate)
	if err != nil {
		t.Fatalf("decoding raw fixture: %v", err)
	}
	if !bytes.Equal(got.RawBlob, wantRaw) {
		t.Fatalf("WorkerTemplate.RawBlob = %x, want the raw decoded BlocktemplateBlob %x", got.RawBlob, wantRaw)
	}
}

// TestApplyJob_UsesBlobFieldWhenBothPresent is required test 2 from
// the brief: when a pool sends BOTH a small, realistic job.Blob AND a
// large job.BlocktemplateBlob (simulating a pool that publishes both
// fields on the same job object), applyJob must derive the resulting
// WorkerTemplate.Blob from the SMALL Blob field only. This assertion
// is UNCHANGED by the real fix -- the job.Blob != "" branch is
// unaffected; BlocktemplateBlob CAN now be used by applyJob (unlike
// before this fix), but only ever as a fallback when Blob itself is
// absent, never when both are present.
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
	if tmpl.RawBlob != nil {
		t.Fatalf("WorkerTemplate.RawBlob = %x, want nil when job.Blob is present (no full raw template to patch worker-nonces into)", tmpl.RawBlob)
	}

	largeBlob, err := hex.DecodeString(largeBlocktemplateBlobHex)
	if err != nil {
		t.Fatalf("decoding large blocktemplate blob: %v", err)
	}
	if bytes.Equal(tmpl.Blob, largeBlob) {
		t.Fatal("WorkerTemplate.Blob must not be derived from BlocktemplateBlob when Blob is also present")
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

// TestApplyJob_EmptyBlobLeavesExistingGoodTemplateUntouched exercises
// genuinely malformed/truncated-input safety: under the real fix, a
// non-block-structured, arbitrary BlocktemplateBlob (this specific
// 1800-byte deterministic sequential-byte fixture, hexOfLen(1800))
// must fail conversion and leave the previously-stored good template
// untouched, rather than store a broken/garbage WorkerTemplate.
//
// GENUINE, CONFIRMED go-xmr-lib v0.2.5 BUG found while writing this
// test (not a hypothetical): this exact input does not merely fail to
// parse cleanly -- it triggers an INFINITE LOOP inside
// serialization.ConstructTXExtra (that function's tag-byte switch has
// no default case and never advances past an unrecognized tx_extra
// tag byte). A bare `recover()` cannot help against an infinite loop
// (there is nothing to recover from -- the goroutine never panics,
// it just never returns). See convertTemplateBlobToHashingBlob's doc
// comment (upstream.go) for the full explanation and the
// timeout-based mitigation this fix adds specifically because of this
// finding. This test's real job is proving that mitigation actually
// bounds the damage: applyJob must return promptly (well under this
// package's test timeout) rather than hang the calling goroutine
// forever, and must leave the prior good template in place.
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
	// agent) and sending genuinely malformed data under that dialect
	// -- Blob empty, BlocktemplateBlob a non-block-structured garbage
	// fixture that (per the confirmed bug above) triggers
	// ConstructTXExtra's infinite loop rather than a clean parse
	// error.
	uc.applyJob(UpstreamJobPayload{
		JobID:             "advanced-client-job-2",
		BlocktemplateBlob: hexOfLen(1800),
		Blob:              "",
		Height:            2,
	})

	second := uc.CurrentTemplate()
	if second == nil {
		t.Fatal("expected the previously-stored good template to remain after a rejected malformed BlocktemplateBlob update")
	}
	if second.JobID != "good-job" {
		t.Fatalf("expected the prior good template (job_id=%q) to remain untouched, got job_id=%q", "good-job", second.JobID)
	}
}

// TestApplyJob_ReconnectIntoAdvancedDialectReplacesOrdinaryTemplate is
// a NEW test (per the brief) exercising the real, intended behavior
// the maintainer wants: a pool that starts in the ordinary dialect
// (job.Blob present) and later grants/switches to the advanced
// xmr-node-proxy dialect (job.BlocktemplateBlob present, job.Blob
// empty) with a REAL, VALID template must have its update ACCEPTED
// and REPLACE the previously-stored ordinary template -- this is the
// exact scenario PR #60's stopgap silently dropped (and which this
// real fix exists to correctly support instead).
func TestApplyJob_ReconnectIntoAdvancedDialectReplacesOrdinaryTemplate(t *testing.T) {
	uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

	ordinaryBlobHex := hexOfLen(76)
	uc.applyJob(UpstreamJobPayload{JobID: "ordinary-job", Blob: ordinaryBlobHex, Height: 1})

	first := uc.CurrentTemplate()
	if first == nil {
		t.Fatal("expected a stored template after the first, ordinary-dialect applyJob call")
	}
	if first.RawBlob != nil {
		t.Fatalf("ordinary-dialect template's RawBlob = %x, want nil", first.RawBlob)
	}

	// Second update: pool now grants the advanced dialect, with a
	// REAL, valid template (not garbage).
	uc.applyJob(UpstreamJobPayload{
		JobID:             "advanced-job",
		BlocktemplateBlob: onlyMinerBlockTemplate,
		Blob:              "",
		Height:            2,
	})

	second := uc.CurrentTemplate()
	if second == nil {
		t.Fatal("expected the second, valid advanced-dialect update to replace the stored template, got nil")
	}
	if second.JobID != "advanced-job" {
		t.Fatalf("expected the stored template to be REPLACED by the advanced-dialect update (job_id=%q), got job_id=%q -- the real fix must not silently drop a valid advanced-dialect update", "advanced-job", second.JobID)
	}

	wantHashingBlob, err := hex.DecodeString(onlyMinerBlockTemplateHashingBlob)
	if err != nil {
		t.Fatalf("decoding expected hashing blob fixture: %v", err)
	}
	if !bytes.Equal(second.Blob, wantHashingBlob) {
		t.Fatalf("replaced WorkerTemplate.Blob = %x, want the real go-xmr-lib-derived hashing blob %x", second.Blob, wantHashingBlob)
	}
	if second.RawBlob == nil {
		t.Fatal("replaced WorkerTemplate.RawBlob must be non-nil (derived via the real conversion path)")
	}
}

// TestWorkerTemplate_ReservedOffsetPatchesRawBlobAndRederivesHashingBlob
// is a NEW regression test (per the brief) for the reserved_offset /
// worker-nonce-patch semantics: reserved_offset/client_nonce_offset
// refer to byte positions inside the FULL raw blocktemplate_blob's
// coinbase tx_extra field (which doesn't exist at all in the reduced
// hashing blob), so patching a worker-nonce in when RawBlob is
// present must patch the RAW blob and then RE-DERIVE the hashing blob
// -- changing the coinbase tx bytes changes the merkle root, which is
// part of the hashing blob.
//
// Uses the offsetData fixture with its real, VERIFIED absolute
// tx_extra-nonce-region offset (offsetDataReservedOffset -- see that
// constant's doc comment for exactly how it was computed/verified,
// not hand-counted).
func TestWorkerTemplate_ReservedOffsetPatchesRawBlobAndRederivesHashingBlob(t *testing.T) {
	uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

	reservedOffset := offsetDataReservedOffset
	uc.applyJob(UpstreamJobPayload{
		JobID:             "offset-job",
		BlocktemplateBlob: offsetData,
		Blob:              "",
		ReservedOffset:    &reservedOffset,
		Height:            777,
	})

	tmpl := uc.CurrentTemplate()
	if tmpl == nil {
		t.Fatal("expected applyJob to store a WorkerTemplate for the real offsetData fixture")
	}
	if tmpl.RawBlob == nil {
		t.Fatal("expected WorkerTemplate.RawBlob to be set (converted via the real blocktemplate_blob path)")
	}
	rawBlobSnapshotBefore := append([]byte(nil), tmpl.RawBlob...)

	blobA, workerNonceA, err := tmpl.NextBlobForWorker()
	if err != nil {
		t.Fatalf("NextBlobForWorker (worker A): %v", err)
	}
	blobB, workerNonceB, err := tmpl.NextBlobForWorker()
	if err != nil {
		t.Fatalf("NextBlobForWorker (worker B): %v", err)
	}

	// (a) no error -- already asserted via t.Fatalf above.

	// (b) the returned blob is still the correctly-sized RandomX
	// hashing blob shape (offsetData's own real hashing blob length,
	// verified via the throwaway program cited in
	// offsetDataHashingBlobLen's doc comment), NOT the raw full blob
	// (352 bytes).
	if len(blobA) != offsetDataHashingBlobLen {
		t.Fatalf("worker A blob length = %d, want the real hashing-blob length %d (not the raw %d-byte full blob)", len(blobA), offsetDataHashingBlobLen, len(tmpl.RawBlob))
	}
	if len(blobB) != offsetDataHashingBlobLen {
		t.Fatalf("worker B blob length = %d, want the real hashing-blob length %d (not the raw %d-byte full blob)", len(blobB), offsetDataHashingBlobLen, len(tmpl.RawBlob))
	}

	// (c) two different worker-nonce values genuinely produce two
	// DIFFERENT returned hashing blobs (proving the patch actually
	// changes the merkle root / hashing blob, not silently ignored).
	if workerNonceA == workerNonceB {
		t.Fatalf("expected NextBlobForWorker to allocate distinct worker nonces, got %d twice", workerNonceA)
	}
	if bytes.Equal(blobA, blobB) {
		t.Fatalf("expected different worker-nonce values to produce different hashing blobs, got identical blobs %x for nonces %d/%d -- reserved_offset patch may be silently ignored", blobA, workerNonceA, workerNonceB)
	}

	// (d) the template's own RawBlob field is left unmodified across
	// repeated BlobForWorker calls (no shared-buffer mutation bug).
	if !bytes.Equal(tmpl.RawBlob, rawBlobSnapshotBefore) {
		t.Fatalf("WorkerTemplate.RawBlob was mutated by BlobForWorker calls: before=%x after=%x", rawBlobSnapshotBefore, tmpl.RawBlob)
	}
}

// TestJobManager_NextJob_AdvancedClientPatchesBothNoncesIntoRawBlobBeforeConverting
// is the required brief regression test: it reproduces the EXACT
// real production scenario from Alex's log --
//
//	proxy: allocating pool-nonce job: proxy: worker-nonce offset is out
//	of range for this template's blob: offset=179 blob_len=76
//
// -- a WorkerTemplate with a REAL, non-nil RawBlob (the real,
// library-verified offsetData fixture, same as
// TestWorkerTemplate_ReservedOffsetPatchesRawBlobAndRederivesHashingBlob
// above) AND a REAL, valid PoolOffset (offsetDataPoolOffset) set
// TOGETHER with a real ReservedOffset (offsetDataReservedOffset) --
// the advanced-client (xmr-node-proxy-aware) dialect combination that
// was never exercised by any pre-existing test (every pre-existing
// BlobForPool/NextJob pool-nonce test used RawBlob == nil).
//
// Constructed via the real production entry points end-to-end:
// UpstreamClient.applyJob (the real upstream-job-ingestion path) ->
// JobManager.NextJob (the real per-downstream-session job-issuance
// path, via a fakeTemplateSource exactly like
// TestJobManager_NextJob_WorkerAndPoolNoncesBothAdvanceIndependently
// in template_test.go) -- called 3 times, asserting each time:
//
//   - it succeeds, no ErrOffsetOutOfRange (this is the literal
//     regression proof for Alex's exact bug: against the pre-fix
//     code, NextJob's second step -- BlobForPool -- bounds-checked
//     PoolOffset=160 against BlobForWorker's already-converted
//     76-byte hashing-blob output instead of the 352-byte raw blob,
//     and failed with exactly this class of error; confirmed by
//     temporarily reverting job.go/template.go to their pre-fix
//     shape and re-running this exact test during development of
//     this fix, which failed with
//     "proxy: allocating pool-nonce job: proxy: worker-nonce offset
//     is out of range for this template's blob: offset=160
//     blob_len=76" -- the same class of error as Alex's real
//     offset=179 blob_len=76 production log line);
//   - the FINAL delivered blob is the correctly-sized, converted
//     hashing blob (offsetDataHashingBlobLen bytes -- NOT
//     offsetData's own 352-byte raw length) with BOTH the
//     worker-nonce and pool-nonce values genuinely baked in -- proven
//     by independently re-deriving the expected hashing blob from a
//     FRESH copy of the raw offsetData fixture with ONLY the same two
//     nonce values patched in at the same two offsets, run through
//     go-xmr-lib's own support.ParseBlockFromTemplateBlob +
//     support.GetBlockHashingBlob directly (not this package's own
//     code under test), and asserting the two are byte-IDENTICAL --
//     a genuine correctness proof, not just "it didn't error".
func TestJobManager_NextJob_AdvancedClientPatchesBothNoncesIntoRawBlobBeforeConverting(t *testing.T) {
	uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

	reservedOffset := offsetDataReservedOffset
	poolOffset := offsetDataPoolOffset
	uc.applyJob(UpstreamJobPayload{
		JobID:             "advanced-pool-nonce-job",
		BlocktemplateBlob: offsetData,
		Blob:              "", // advanced-client dialect: no pre-converted "blob" field
		ReservedOffset:    &reservedOffset,
		ClientPoolOffset:  &poolOffset,
		Height:            555,
		TargetDiff:        1000,
	})

	tmpl := uc.CurrentTemplate()
	if tmpl == nil {
		t.Fatal("expected applyJob to store a WorkerTemplate for the real offsetData fixture")
	}
	if tmpl.RawBlob == nil {
		t.Fatal("expected WorkerTemplate.RawBlob to be set (advanced-client dialect, converted via the real blocktemplate_blob path) -- this test requires the RawBlob != nil branch to actually exercise the bug")
	}
	if tmpl.PoolOffset != offsetDataPoolOffset {
		t.Fatalf("WorkerTemplate.PoolOffset = %d, want %d", tmpl.PoolOffset, offsetDataPoolOffset)
	}
	if tmpl.ReservedOffset != offsetDataReservedOffset {
		t.Fatalf("WorkerTemplate.ReservedOffset = %d, want %d", tmpl.ReservedOffset, offsetDataReservedOffset)
	}
	rawFixture, err := hex.DecodeString(offsetData)
	if err != nil {
		t.Fatalf("decoding raw offsetData fixture: %v", err)
	}
	rawBlobSnapshotBefore := append([]byte(nil), tmpl.RawBlob...)

	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, discardLogger())

	const numJobs = 3
	seenWorker := make(map[uint32]struct{})
	seenPool := make(map[uint32]struct{})
	for i := 0; i < numJobs; i++ {
		job, err := jm.NextJob(100)
		if err != nil {
			t.Fatalf("NextJob (issuance %d): %v -- this is the exact regression Alex hit in production (proxy: allocating pool-nonce job: proxy: worker-nonce offset is out of range for this template's blob), it must NOT happen after the fix", i, err)
		}

		if len(job.Blob) != offsetDataHashingBlobLen {
			t.Fatalf("job %d: final delivered blob length = %d, want the real hashing-blob length %d (not the raw %d-byte full blob) -- got %x", i, len(job.Blob), offsetDataHashingBlobLen, len(rawFixture), job.Blob)
		}

		if _, dup := seenWorker[job.WorkerNonce]; dup {
			t.Fatalf("job %d: workerNonce %d was issued to an earlier job too -- not monotonically distinct", i, job.WorkerNonce)
		}
		seenWorker[job.WorkerNonce] = struct{}{}
		if _, dup := seenPool[job.PoolNonce]; dup {
			t.Fatalf("job %d: poolNonce %d was issued to an earlier job too -- not monotonically distinct", i, job.PoolNonce)
		}
		seenPool[job.PoolNonce] = struct{}{}

		// Genuine correctness proof: independently re-derive the
		// expected hashing blob from a FRESH copy of the raw fixture
		// with ONLY this job's own two nonce values patched in at
		// the same two real offsets, using go-xmr-lib's support
		// package directly (not any of this package's own code under
		// test), and confirm the bytes are IDENTICAL to what NextJob
		// actually delivered.
		expectedRaw := append([]byte(nil), rawFixture...)
		binary.BigEndian.PutUint32(expectedRaw[offsetDataReservedOffset:offsetDataReservedOffset+4], job.WorkerNonce)
		binary.BigEndian.PutUint32(expectedRaw[offsetDataPoolOffset:offsetDataPoolOffset+4], job.PoolNonce)
		parsedBlock, err := support.ParseBlockFromTemplateBlob(hex.EncodeToString(expectedRaw))
		if err != nil {
			t.Fatalf("job %d: independently re-parsing the nonce-patched raw fixture: %v", i, err)
		}
		expectedHashingBlob, err := support.GetBlockHashingBlob(parsedBlock)
		if err != nil {
			t.Fatalf("job %d: independently re-deriving the expected hashing blob: %v", i, err)
		}
		if !bytes.Equal(job.Blob, expectedHashingBlob) {
			t.Fatalf("job %d: delivered blob = %x, want the independently-derived hashing blob %x (workerNonce=%d poolNonce=%d) -- both nonces must be baked into the SAME raw-blob copy before the ONE conversion call", i, job.Blob, expectedHashingBlob, job.WorkerNonce, job.PoolNonce)
		}
	}

	// The template's own RawBlob must never have been mutated by any
	// of this (non-mutating-copy discipline).
	if !bytes.Equal(tmpl.RawBlob, rawBlobSnapshotBefore) {
		t.Fatalf("WorkerTemplate.RawBlob was mutated by NextJob calls: before=%x after=%x", rawBlobSnapshotBefore, tmpl.RawBlob)
	}
}
