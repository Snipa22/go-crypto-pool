// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bytes"
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
