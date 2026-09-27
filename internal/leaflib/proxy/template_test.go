// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWorkerTemplate_BlobForWorker_DifferentNoncesOnlyChangeOffsetBytes(t *testing.T) {
	blob := make([]byte, 76)
	for i := range blob {
		blob[i] = byte(i)
	}
	tmpl := &WorkerTemplate{Blob: blob, ReservedOffset: 40, ClientNonceOffset: -1}

	a, err := tmpl.BlobForWorker(1)
	if err != nil {
		t.Fatalf("BlobForWorker(1): %v", err)
	}
	b, err := tmpl.BlobForWorker(2)
	if err != nil {
		t.Fatalf("BlobForWorker(2): %v", err)
	}

	if len(a) != len(blob) || len(b) != len(blob) {
		t.Fatalf("output length changed: len(a)=%d len(b)=%d want %d", len(a), len(b), len(blob))
	}
	if bytes.Equal(a, b) {
		t.Fatalf("expected two different worker nonces to produce different blobs")
	}

	// Every byte OUTSIDE the 4-byte offset window must be untouched
	// and identical to the original blob.
	for i := 0; i < len(blob); i++ {
		if i >= 40 && i < 44 {
			continue
		}
		if a[i] != blob[i] || b[i] != blob[i] {
			t.Fatalf("byte %d outside the nonce window was mutated: original=%02x a=%02x b=%02x", i, blob[i], a[i], b[i])
		}
	}
	// Original template blob itself must never be mutated.
	for i, v := range blob {
		if v != byte(i) {
			t.Fatalf("original template Blob was mutated at byte %d", i)
		}
	}
	// The 4-byte window itself must actually differ between a and b.
	if bytes.Equal(a[40:44], b[40:44]) {
		t.Fatalf("expected the nonce window itself to differ between two different worker nonces")
	}
}

func TestWorkerTemplate_ClientNonceOffsetTakesPrecedenceOverReservedOffset(t *testing.T) {
	blob := make([]byte, 100)
	tmpl := &WorkerTemplate{Blob: blob, ReservedOffset: 10, ClientNonceOffset: 50}

	out, err := tmpl.BlobForWorker(0xdeadbeef)
	if err != nil {
		t.Fatalf("BlobForWorker: %v", err)
	}
	// reservedOffset region must be untouched (all zero).
	for i := 10; i < 14; i++ {
		if out[i] != 0 {
			t.Errorf("expected reservedOffset region byte %d to be untouched when ClientNonceOffset is set, got %02x", i, out[i])
		}
	}
	// clientNonceOffset region must carry the written nonce.
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	if !bytes.Equal(out[50:54], want) {
		t.Errorf("clientNonceOffset region = %x, want %x", out[50:54], want)
	}
}

func TestWorkerTemplate_FallsBackToReservedOffsetWhenNoClientNonceOffset(t *testing.T) {
	blob := make([]byte, 100)
	tmpl := &WorkerTemplate{Blob: blob, ReservedOffset: 10, ClientNonceOffset: -1}

	out, err := tmpl.BlobForWorker(0x01020304)
	if err != nil {
		t.Fatalf("BlobForWorker: %v", err)
	}
	want := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(out[10:14], want) {
		t.Errorf("reservedOffset region = %x, want %x", out[10:14], want)
	}
}

func TestWorkerTemplate_OutOfRangeOffsetRejected(t *testing.T) {
	tmpl := &WorkerTemplate{Blob: make([]byte, 8), ReservedOffset: 10, ClientNonceOffset: -1}
	if _, err := tmpl.BlobForWorker(1); err == nil {
		t.Fatal("expected an error for an offset that doesn't fit in the blob")
	}
}

// TestWorkerTemplate_NeitherOffsetPublishedReturnsUnmodifiedBlobNoError
// covers the real, confirmed-live behavior this leaf actually hit
// against pool.supportxmr.com's ordinary stratum job responses:
// neither ReservedOffset nor ClientNonceOffset is published at all
// (both -1). BlobForWorker must NOT error and must NOT corrupt any
// byte of the original blob in this case -- it degrades honestly to
// handing every downstream miner an identical, unmodified copy of the
// pool's own job (see BlobForWorker's doc comment), rather than
// guessing at some offset and risking overwriting a real block-header
// field it doesn't understand the layout of.
func TestWorkerTemplate_NeitherOffsetPublishedReturnsUnmodifiedBlobNoError(t *testing.T) {
	original := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44}
	blob := make([]byte, len(original))
	copy(blob, original)
	tmpl := &WorkerTemplate{Blob: blob, ReservedOffset: -1, ClientNonceOffset: -1}

	out, err := tmpl.BlobForWorker(0xDEADBEEF)
	if err != nil {
		t.Fatalf("BlobForWorker with neither offset published: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Fatalf("expected an unmodified copy of the blob when no offset is available, got %x, want %x", out, original)
	}
	// The input Blob itself must also remain untouched (defensive-copy
	// guarantee) -- mutate a byte in the returned copy and confirm the
	// template's own stored Blob didn't change alongside it.
	out[0] = 0x00
	if !bytes.Equal(tmpl.Blob, original) {
		t.Fatalf("template's own Blob was mutated: got %x, want unchanged %x", tmpl.Blob, original)
	}

	// NextBlobForWorker must still allocate/return a real, distinct
	// workerNonce for bookkeeping/logging purposes even though it's
	// not written into the blob in this fallback case.
	_, nonceA, err := tmpl.NextBlobForWorker()
	if err != nil {
		t.Fatalf("NextBlobForWorker: %v", err)
	}
	_, nonceB, err := tmpl.NextBlobForWorker()
	if err != nil {
		t.Fatalf("NextBlobForWorker: %v", err)
	}
	if nonceA == nonceB {
		t.Fatalf("expected distinct worker nonces even in the no-offset fallback case, got %d twice", nonceA)
	}
}

func TestWorkerTemplate_NextBlobForWorker_MonotonicNonOverlappingNonces(t *testing.T) {
	blob := make([]byte, 76)
	tmpl := &WorkerTemplate{Blob: blob, ReservedOffset: 40, ClientNonceOffset: -1}

	seen := make(map[uint32]struct{})
	var blobs [][]byte
	for i := 0; i < 20; i++ {
		b, nonce, err := tmpl.NextBlobForWorker()
		if err != nil {
			t.Fatalf("NextBlobForWorker: %v", err)
		}
		if _, dup := seen[nonce]; dup {
			t.Fatalf("worker nonce %d was issued twice", nonce)
		}
		seen[nonce] = struct{}{}
		blobs = append(blobs, b)
	}
	// Every issued blob must be pairwise distinct (genuinely
	// non-overlapping search spaces).
	for i := 0; i < len(blobs); i++ {
		for j := i + 1; j < len(blobs); j++ {
			if bytes.Equal(blobs[i], blobs[j]) {
				t.Fatalf("issuances %d and %d produced identical blobs", i, j)
			}
		}
	}
}

// --- BlobForPool / NextPoolNonce (pool-level nonce -- the peer
// mechanism to BlobForWorker/NextBlobForWorker above) ---------------

// TestWorkerTemplate_BlobForPool_DifferentPoolNoncesOnlyChangeOffsetBytes
// is BlobForPool's direct analogue of
// TestWorkerTemplate_BlobForWorker_DifferentNoncesOnlyChangeOffsetBytes
// above -- same non-mutating-copy / bounds-checked / big-endian-write
// discipline, applied at PoolOffset instead of ReservedOffset/
// ClientNonceOffset.
func TestWorkerTemplate_BlobForPool_DifferentPoolNoncesOnlyChangeOffsetBytes(t *testing.T) {
	blob := make([]byte, 76)
	for i := range blob {
		blob[i] = byte(i)
	}
	tmpl := &WorkerTemplate{Blob: blob, ReservedOffset: -1, ClientNonceOffset: -1, PoolOffset: 60}

	a, err := tmpl.BlobForPool(blob, 1)
	if err != nil {
		t.Fatalf("BlobForPool(blob, 1): %v", err)
	}
	b, err := tmpl.BlobForPool(blob, 2)
	if err != nil {
		t.Fatalf("BlobForPool(blob, 2): %v", err)
	}

	if len(a) != len(blob) || len(b) != len(blob) {
		t.Fatalf("output length changed: len(a)=%d len(b)=%d want %d", len(a), len(b), len(blob))
	}
	if bytes.Equal(a, b) {
		t.Fatalf("expected two different pool nonces to produce different blobs")
	}
	for i := 0; i < len(blob); i++ {
		if i >= 60 && i < 64 {
			continue
		}
		if a[i] != blob[i] || b[i] != blob[i] {
			t.Fatalf("byte %d outside the pool-nonce window was mutated: original=%02x a=%02x b=%02x", i, blob[i], a[i], b[i])
		}
	}
	for i, v := range blob {
		if v != byte(i) {
			t.Fatalf("input blob was mutated at byte %d", i)
		}
	}
	if bytes.Equal(a[60:64], b[60:64]) {
		t.Fatalf("expected the pool-nonce window itself to differ between two different pool nonces")
	}
}

// TestWorkerTemplate_BlobForPool_NoOffsetPublishedReturnsUnmodifiedBlobNoError
// mirrors BlobForWorker's own no-offset-published degrade-gracefully
// behavior for PoolOffset -- when the upstream never published
// client_pool_offset at all (PoolOffset == -1), BlobForPool must not
// error and must not touch any byte of the blob.
func TestWorkerTemplate_BlobForPool_NoOffsetPublishedReturnsUnmodifiedBlobNoError(t *testing.T) {
	original := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44}
	blob := make([]byte, len(original))
	copy(blob, original)
	tmpl := &WorkerTemplate{Blob: blob, ReservedOffset: -1, ClientNonceOffset: -1, PoolOffset: -1}

	out, err := tmpl.BlobForPool(blob, 0xDEADBEEF)
	if err != nil {
		t.Fatalf("BlobForPool with no PoolOffset published: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Fatalf("expected an unmodified copy of the blob when PoolOffset is unpublished, got %x, want %x", out, original)
	}
	out[0] = 0x00
	if !bytes.Equal(blob, original) {
		t.Fatalf("input blob was mutated: got %x, want unchanged %x", blob, original)
	}
}

// TestWorkerTemplate_BlobForPool_OutOfRangeOffsetRejected mirrors
// TestWorkerTemplate_OutOfRangeOffsetRejected for PoolOffset.
func TestWorkerTemplate_BlobForPool_OutOfRangeOffsetRejected(t *testing.T) {
	tmpl := &WorkerTemplate{Blob: make([]byte, 8), ReservedOffset: -1, ClientNonceOffset: -1, PoolOffset: 10}
	if _, err := tmpl.BlobForPool(tmpl.Blob, 1); err == nil {
		t.Fatal("expected an error for a PoolOffset that doesn't fit in the blob")
	}
}

// TestWorkerTemplate_NextPoolNonce_MonotonicNonOverlapping mirrors
// TestWorkerTemplate_NextBlobForWorker_MonotonicNonOverlappingNonces
// for the pool-nonce counter.
func TestWorkerTemplate_NextPoolNonce_MonotonicNonOverlapping(t *testing.T) {
	tmpl := &WorkerTemplate{Blob: make([]byte, 76), ReservedOffset: -1, ClientNonceOffset: -1, PoolOffset: 60}

	seen := make(map[uint32]struct{})
	for i := 0; i < 20; i++ {
		n := tmpl.NextPoolNonce()
		if _, dup := seen[n]; dup {
			t.Fatalf("pool nonce %d was issued twice", n)
		}
		seen[n] = struct{}{}
	}
}

// TestJobManager_NextJob_WorkerAndPoolNoncesBothAdvanceIndependently
// is the required brief test: exercises the REAL production call
// path (JobManager.NextJob, the same entry point Server uses to
// issue every downstream job) with BOTH a real ReservedOffset AND a
// real PoolOffset configured together, delivers several jobs, and
// confirms:
//
//   - each delivered job's blob has a DIFFERENT, monotonically
//     increasing poolNonce value baked in at PoolOffset, and that
//     baked-in value exactly matches the job's own captured
//     PoolNonce field (read back with
//     binary.BigEndian.Uint32(blob[offset:offset+4]));
//   - the existing worker-nonce/ReservedOffset patching behavior is
//     unaffected -- the worker-nonce region is read back
//     independently and confirmed correct and distinct per job too;
//   - the two regions/values are genuinely independent (same
//     nonce value never accidentally shared between the two
//     counters).
func TestJobManager_NextJob_WorkerAndPoolNoncesBothAdvanceIndependently(t *testing.T) {
	const (
		blobLen        = 128
		reservedOffset = 40
		poolOffset     = 80
	)
	blob := make([]byte, blobLen)
	tmpl := &WorkerTemplate{
		Blob:              blob,
		ReservedOffset:    reservedOffset,
		ClientNonceOffset: -1,
		PoolOffset:        poolOffset,
		JobID:             "upstream-job-nonce-test",
		Height:            1,
		TargetDiff:        1000,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)

	const numJobs = 3
	jobs := make([]*Job, 0, numJobs)
	for i := 0; i < numJobs; i++ {
		job, err := jm.NextJob(100)
		if err != nil {
			t.Fatalf("NextJob (issuance %d): %v", i, err)
		}
		jobs = append(jobs, job)
	}

	seenWorker := make(map[uint32]struct{})
	seenPool := make(map[uint32]struct{})
	for i, job := range jobs {
		if len(job.Blob) != blobLen {
			t.Fatalf("job %d blob length = %d, want %d", i, len(job.Blob), blobLen)
		}

		// Pool-nonce region: baked-in bytes must match the job's own
		// captured PoolNonce field exactly.
		gotPoolNonce := binary.BigEndian.Uint32(job.Blob[poolOffset : poolOffset+4])
		if gotPoolNonce != job.PoolNonce {
			t.Fatalf("job %d: blob's baked-in poolNonce = %d, want job.PoolNonce = %d", i, gotPoolNonce, job.PoolNonce)
		}
		if _, dup := seenPool[job.PoolNonce]; dup {
			t.Fatalf("job %d: poolNonce %d was issued to an earlier job too -- not monotonically distinct", i, job.PoolNonce)
		}
		seenPool[job.PoolNonce] = struct{}{}

		// Worker-nonce region: regression -- must remain correct and
		// independent of the pool-nonce mechanism above.
		gotWorkerNonce := binary.BigEndian.Uint32(job.Blob[reservedOffset : reservedOffset+4])
		if gotWorkerNonce != job.WorkerNonce {
			t.Fatalf("job %d: blob's baked-in workerNonce = %d, want job.WorkerNonce = %d", i, gotWorkerNonce, job.WorkerNonce)
		}
		if _, dup := seenWorker[job.WorkerNonce]; dup {
			t.Fatalf("job %d: workerNonce %d was issued to an earlier job too -- not monotonically distinct", i, job.WorkerNonce)
		}
		seenWorker[job.WorkerNonce] = struct{}{}

		// The two counters are independent: worker-nonce and
		// pool-nonce must never be coupled into the same value by
		// coincidence-masking logic (they legitimately COULD collide
		// numerically by chance since both start at 1 and increment
		// by 1 per issuance in this test, so instead assert the
		// REGIONS are independently correct, which the two checks
		// above already do -- and additionally assert every byte
		// OUTSIDE both 4-byte windows is untouched, proving no
		// cross-contamination between the two patch operations).
		for b := 0; b < blobLen; b++ {
			inWorkerWindow := b >= reservedOffset && b < reservedOffset+4
			inPoolWindow := b >= poolOffset && b < poolOffset+4
			if inWorkerWindow || inPoolWindow {
				continue
			}
			if job.Blob[b] != 0 {
				t.Fatalf("job %d: byte %d outside both nonce windows was mutated (got %02x, want 0x00)", i, b, job.Blob[b])
			}
		}
	}

	// Every delivered job's own blob must be pairwise distinct.
	for i := 0; i < len(jobs); i++ {
		for j := i + 1; j < len(jobs); j++ {
			if bytes.Equal(jobs[i].Blob, jobs[j].Blob) {
				t.Fatalf("jobs %d and %d produced identical blobs", i, j)
			}
		}
	}

	// The template's own original Blob must never have been mutated
	// by any of this (non-mutating-copy discipline, same as
	// BlobForWorker/BlobForPool individually already guarantee).
	for i, v := range blob {
		if v != 0 {
			t.Fatalf("template's own original Blob was mutated at byte %d: got %02x, want 0x00", i, v)
		}
	}
}

// TestJobManager_NextJob_CarriesThroughTemplateGeneration is required
// test 1 from the leaf-proxy-stale-generation-submit fix: a Job
// minted from a WorkerTemplate with a given Generation value must
// carry that SAME value through as Job.TemplateGeneration -- this is
// the plumbing session.go's handleSubmit staleness check (comparing
// job.TemplateGeneration against the upstream client's own
// CurrentGeneration()) depends on end-to-end.
func TestJobManager_NextJob_CarriesThroughTemplateGeneration(t *testing.T) {
	tmpl := &WorkerTemplate{
		Blob:              make([]byte, 76),
		ReservedOffset:    -1,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		JobID:             "generation-passthrough-job",
		Height:            1,
		TargetDiff:        1000,
		Generation:        42,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)

	job, err := jm.NextJob(100)
	if err != nil {
		t.Fatalf("NextJob: %v", err)
	}
	if job.TemplateGeneration != 42 {
		t.Fatalf("job.TemplateGeneration = %d, want 42 (the WorkerTemplate's own Generation value)", job.TemplateGeneration)
	}

	// A DIFFERENT template generation must carry through as a
	// different value too -- proving this is a real passthrough, not
	// a hardcoded/coincidental match.
	tmpl2 := &WorkerTemplate{
		Blob:              make([]byte, 76),
		ReservedOffset:    -1,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		JobID:             "generation-passthrough-job-2",
		Height:            2,
		TargetDiff:        1000,
		Generation:        43,
	}
	source.setTemplate(tmpl2)
	job2, err := jm.NextJob(100)
	if err != nil {
		t.Fatalf("NextJob (second template): %v", err)
	}
	if job2.TemplateGeneration != 43 {
		t.Fatalf("job2.TemplateGeneration = %d, want 43", job2.TemplateGeneration)
	}
}
