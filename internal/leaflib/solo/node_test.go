// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"github.com/Snipa22/go-xmr-lib/support"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestTariJobFromResult_JobIDsAreRandomNotContentDerived is the direct
// regression test for the "SHA3X was only accidentally safe" finding:
// tariJobFromResult used to derive job.ID from result.GetBlockHash()
// alone (jobIDFromBlockHash). That happened to almost always produce
// distinct IDs in production only because GRPCNodeClient.
// buildCoinbaseExtra randomizes coinbase-extra (and therefore
// BlockHash) on every real call -- an INCIDENTAL side effect, not a
// designed guarantee (see tariJobFromResult's doc comment) -- and it
// provided ZERO real protection against the confirmed RXM case where
// two genuinely different templates DO share their content-derived
// prefix (monero_node.go's GetBlockTemplate doc comment). This test
// calls tariJobFromResult twice with a byte-IDENTICAL
// *tari_generated.GetNewBlockResult (same BlockHash, same Height,
// same everything) and requires the two returned *Job's IDs to still
// be distinct -- which only holds now that job.ID is minted via
// newRandomHexID instead.
func TestTariJobFromResult_JobIDsAreRandomNotContentDerived(t *testing.T) {
	blockHash := bytes.Repeat([]byte{0xAB}, 32)
	result := &tari_generated.GetNewBlockResult{
		BlockHash:       blockHash,
		MergeMiningHash: bytes.Repeat([]byte{0xCD}, 32),
		Block: &tari_generated.Block{
			Header: &tari_generated.BlockHeader{Height: 12345},
		},
		MinerData: &tari_generated.MinerData{TargetDifficulty: 1000},
	}

	job1, err := tariJobFromResult(result, poolpb.Algo_ALGO_SHA3X)
	if err != nil {
		t.Fatalf("tariJobFromResult (1st call): %v", err)
	}
	job2, err := tariJobFromResult(result, poolpb.Algo_ALGO_SHA3X)
	if err != nil {
		t.Fatalf("tariJobFromResult (2nd call): %v", err)
	}

	if !bytes.Equal(job1.BlockHash, job2.BlockHash) {
		t.Fatalf("test premise violated: job1.BlockHash != job2.BlockHash")
	}
	if job1.Height != job2.Height {
		t.Fatalf("test premise violated: job1.Height != job2.Height")
	}
	if job1.ID == job2.ID {
		t.Fatalf("job1.ID == job2.ID (%q) for two tariJobFromResult calls with byte-identical BlockHash/Height -- job_id must be a purely random, opaque token, never content-derived", job1.ID)
	}
	if job1.ID == "" || job2.ID == "" {
		t.Fatalf("job1.ID=%q job2.ID=%q -- job.ID must never be empty", job1.ID, job2.ID)
	}
}

// TestGRPCNodeClientBuildCoinbaseExtraContainsConfiguredTag verifies
// the exact bytes GetBlockTemplate would submit as CoinbaseExtra
// (via buildCoinbaseExtra) start with this instance's configured
// coinbaseExtraTag, without needing a real GRPC connection.
func TestGRPCNodeClientBuildCoinbaseExtraContainsConfiguredTag(t *testing.T) {
	tag := []byte("supportxtm-sha3x")
	c := &GRPCNodeClient{coinbaseExtraTag: tag}

	extra := c.buildCoinbaseExtra()

	if !bytes.HasPrefix(extra, tag) {
		t.Fatalf("buildCoinbaseExtra() = %q, want prefix %q", extra, tag)
	}
	// tag + 8-byte per-xn random nonce.
	if len(extra) != len(tag)+8 {
		t.Errorf("len(buildCoinbaseExtra()) = %d, want %d", len(extra), len(tag)+8)
	}
}

// TestGRPCNodeClientBuildCoinbaseExtraDiffersPerCall confirms the
// per-xn random nonce still varies call-to-call after this refactor
// (mirrors the pre-existing randomization guarantee GetBlockTemplate's
// own doc comment describes).
func TestGRPCNodeClientBuildCoinbaseExtraDiffersPerCall(t *testing.T) {
	c := &GRPCNodeClient{coinbaseExtraTag: []byte("supportxtm-c29")}
	a := c.buildCoinbaseExtra()
	b := c.buildCoinbaseExtra()
	if bytes.Equal(a, b) {
		t.Errorf("two calls to buildCoinbaseExtra() produced identical bytes %q -- nonce is no longer randomized", a)
	}
}

// coinbaseExtraSuffixLen is the fixed "1 NUL byte + 4 random bytes"
// overhead NormalizeCoinbaseExtraTag now always appends after the
// (possibly-truncated) base tag string.
const coinbaseExtraSuffixLen = 1 + 4

func TestNormalizeCoinbaseExtraTagUsesExplicitValueVerbatim(t *testing.T) {
	got := NormalizeCoinbaseExtraTag("my-custom-tag", "supportxtm-sha3x")
	wantBase := "my-custom-tag"
	if len(got) != len(wantBase)+coinbaseExtraSuffixLen {
		t.Fatalf("len(NormalizeCoinbaseExtraTag(...)) = %d, want %d (base tag + NUL + 4 random bytes)", len(got), len(wantBase)+coinbaseExtraSuffixLen)
	}
	if string(got[:len(wantBase)]) != wantBase {
		t.Errorf("NormalizeCoinbaseExtraTag base tag = %q, want %q", got[:len(wantBase)], wantBase)
	}
	if got[len(wantBase)] != 0x00 {
		t.Errorf("byte immediately after base tag = %#x, want 0x00", got[len(wantBase)])
	}
}

func TestNormalizeCoinbaseExtraTagFallsBackWhenEmpty(t *testing.T) {
	for _, tag := range []string{"", "   "} {
		got := NormalizeCoinbaseExtraTag(tag, "supportxtm-rxt")
		wantBase := "supportxtm-rxt"
		if len(got) != len(wantBase)+coinbaseExtraSuffixLen {
			t.Fatalf("NormalizeCoinbaseExtraTag(%q, ...): len = %d, want %d", tag, len(got), len(wantBase)+coinbaseExtraSuffixLen)
		}
		if string(got[:len(wantBase)]) != wantBase {
			t.Errorf("NormalizeCoinbaseExtraTag(%q, ...) base = %q, want fallback %q", tag, got[:len(wantBase)], wantBase)
		}
		if got[len(wantBase)] != 0x00 {
			t.Errorf("NormalizeCoinbaseExtraTag(%q, ...): byte after base tag = %#x, want 0x00", tag, got[len(wantBase)])
		}
	}
}

func TestNormalizeCoinbaseExtraTagTruncatesOverlongInput(t *testing.T) {
	overlong := strings.Repeat("A", MaxCoinbaseExtraTagLen+50)
	got := NormalizeCoinbaseExtraTag(overlong, "supportxtm-sha3x")
	const maxBaseTagLen = MaxCoinbaseExtraTagLen - coinbaseExtraSuffixLen
	if len(got) != MaxCoinbaseExtraTagLen {
		t.Fatalf("len(NormalizeCoinbaseExtraTag(overlong, ...)) = %d, want %d", len(got), MaxCoinbaseExtraTagLen)
	}
	if string(got[:maxBaseTagLen]) != overlong[:maxBaseTagLen] {
		t.Errorf("truncated base tag does not match the expected prefix")
	}
	if got[maxBaseTagLen] != 0x00 {
		t.Errorf("byte immediately after truncated base tag = %#x, want 0x00", got[maxBaseTagLen])
	}
}

func TestNormalizeCoinbaseExtraTagAcceptsExactMaxLength(t *testing.T) {
	// "Exact max length" now means the base tag alone consumes the
	// full maxBaseTagLen budget (MaxCoinbaseExtraTagLen - 5); the
	// total returned length is still capped at MaxCoinbaseExtraTagLen
	// once the NUL+4-random-byte suffix is appended.
	const maxBaseTagLen = MaxCoinbaseExtraTagLen - coinbaseExtraSuffixLen
	exact := strings.Repeat("B", maxBaseTagLen)
	got := NormalizeCoinbaseExtraTag(exact, "supportxtm-sha3x")
	if len(got) != MaxCoinbaseExtraTagLen {
		t.Errorf("len(got) = %d, want %d (exact-max-budget base tag must not be truncated further, and the suffix must still fit)", len(got), MaxCoinbaseExtraTagLen)
	}
}

// --- NUL-delimited random-suffix coinbase-extra-tag scheme tests
// (required tests (a)-(f) from this feature's brief) ---

// TestNormalizeCoinbaseExtraTagSuffixIsExactlyFourBytes is required
// test (a): the random suffix appended after the NUL delimiter is
// exactly 4 bytes.
func TestNormalizeCoinbaseExtraTagSuffixIsExactlyFourBytes(t *testing.T) {
	resetCoinbaseExtraRandomSuffixForTest()
	t.Cleanup(resetCoinbaseExtraRandomSuffixForTest)

	base := "supportxtm-sha3x"
	got := NormalizeCoinbaseExtraTag(base, "fallback")
	// len(got) = len(base) + 1 (NUL) + 4 (random suffix).
	suffix := got[len(base)+1:]
	if len(suffix) != 4 {
		t.Fatalf("len(random suffix) = %d, want 4", len(suffix))
	}
}

// TestNormalizeCoinbaseExtraTagByteAfterBaseTagIsNUL is required test
// (b): the byte immediately following the base tag string in the
// returned slice is exactly 0x00 (a genuine NUL byte, not a printable
// placeholder), since a separate repo (go-tari-explorer) splits on
// this exact byte value to recover the original prefix.
func TestNormalizeCoinbaseExtraTagByteAfterBaseTagIsNUL(t *testing.T) {
	resetCoinbaseExtraRandomSuffixForTest()
	t.Cleanup(resetCoinbaseExtraRandomSuffixForTest)

	base := "supportxtm-rxt"
	got := NormalizeCoinbaseExtraTag(base, "fallback")
	if got[len(base)] != 0x00 {
		t.Fatalf("byte immediately after base tag = %#x, want a genuine 0x00 NUL byte", got[len(base)])
	}
}

// TestNormalizeCoinbaseExtraTagSuffixCachedAcrossCallsSameProcess is
// required test (c): two calls within the same test (same process, no
// reset in between) must return byte-identical suffixes, proving the
// suffix is generated once and cached, not freshly generated per
// call.
func TestNormalizeCoinbaseExtraTagSuffixCachedAcrossCallsSameProcess(t *testing.T) {
	resetCoinbaseExtraRandomSuffixForTest()
	t.Cleanup(resetCoinbaseExtraRandomSuffixForTest)

	base1 := "supportxtm-sha3x"
	got1 := NormalizeCoinbaseExtraTag(base1, "fallback")
	suffix1 := append([]byte(nil), got1[len(base1)+1:]...)

	// A different base tag string (and different fallback) on the
	// second call -- only the suffix itself is asserted identical,
	// confirming the cache is keyed on the process, not the input.
	base2 := "a-completely-different-tag"
	got2 := NormalizeCoinbaseExtraTag(base2, "another-fallback")
	suffix2 := got2[len(base2)+1:]

	if !bytes.Equal(suffix1, suffix2) {
		t.Fatalf("suffix1 = %x, suffix2 = %x -- two NormalizeCoinbaseExtraTag calls in the same process must return byte-identical random suffixes (generated once, cached)", suffix1, suffix2)
	}
}

// TestNormalizeCoinbaseExtraTagSuffixDiffersAfterProcessReset is
// required test (d): after resetCoinbaseExtraRandomSuffixForTest
// (simulating a fresh OS process), a subsequent call must produce a
// suffix that differs from the previous "process"'s suffix.
//
// Four random bytes only guarantee this with overwhelming (not
// absolute) probability: 4 bytes = 2^32 possible values. Across N
// independent 4-byte draws, the collision probability (birthday
// bound) is bounded by ~N^2 / 2^33. This test performs 300
// reset+generate+compare cycles against every prior draw
// (N=300 => N^2/2^33 ~= 90000 / 8.6e9 ~= 1.05e-5, i.e. about a
// 0.001% chance of ANY collision across the whole run) and requires
// zero collisions across all of them -- well below any realistic
// flakiness threshold, and re-run on every `go test` invocation
// rather than relying on a single bare comparison.
func TestNormalizeCoinbaseExtraTagSuffixDiffersAfterProcessReset(t *testing.T) {
	t.Cleanup(resetCoinbaseExtraRandomSuffixForTest)

	const iterations = 300
	seen := make(map[[4]byte]int, iterations)
	base := "supportxtm-sha3x"
	for i := 0; i < iterations; i++ {
		resetCoinbaseExtraRandomSuffixForTest()
		got := NormalizeCoinbaseExtraTag(base, "fallback")
		var suffix [4]byte
		copy(suffix[:], got[len(base)+1:])
		if prev, ok := seen[suffix]; ok {
			t.Fatalf("iteration %d: suffix %x collided with iteration %d's suffix -- astronomically unlikely for 4-byte crypto/rand draws (see this test's doc comment for the birthday-bound math)", i, suffix, prev)
		}
		seen[suffix] = i
	}
}

// TestNormalizeCoinbaseExtraTagTotalLengthNeverExceedsMax is required
// test (e): total returned length never exceeds MaxCoinbaseExtraTagLen
// even when the input tag string is deliberately much longer than
// MaxCoinbaseExtraTagLen.
func TestNormalizeCoinbaseExtraTagTotalLengthNeverExceedsMax(t *testing.T) {
	resetCoinbaseExtraRandomSuffixForTest()
	t.Cleanup(resetCoinbaseExtraRandomSuffixForTest)

	overlong := strings.Repeat("Z", 3*MaxCoinbaseExtraTagLen)
	got := NormalizeCoinbaseExtraTag(overlong, "fallback")
	if len(got) > MaxCoinbaseExtraTagLen {
		t.Fatalf("len(NormalizeCoinbaseExtraTag(overlong, ...)) = %d, exceeds MaxCoinbaseExtraTagLen = %d", len(got), MaxCoinbaseExtraTagLen)
	}
	if len(got) != MaxCoinbaseExtraTagLen {
		t.Errorf("len(got) = %d, want exactly %d for a deliberately overlong input", len(got), MaxCoinbaseExtraTagLen)
	}
}

// TestNormalizeCoinbaseExtraTagOperatorOverrideGetsSameSuffixTreatment
// is required test (f): an operator-supplied non-empty tag argument
// (simulating the -coinbase-extra-tag override path) gets the
// identical NUL+4-random-byte treatment as the fallback-default path.
func TestNormalizeCoinbaseExtraTagOperatorOverrideGetsSameSuffixTreatment(t *testing.T) {
	resetCoinbaseExtraRandomSuffixForTest()
	t.Cleanup(resetCoinbaseExtraRandomSuffixForTest)

	override := "operator-custom-override-tag"
	got := NormalizeCoinbaseExtraTag(override, "this-fallback-must-not-be-used")

	if !bytes.HasPrefix(got, []byte(override)) {
		t.Fatalf("NormalizeCoinbaseExtraTag(override, ...) = %q, want prefix %q", got, override)
	}
	if got[len(override)] != 0x00 {
		t.Fatalf("byte immediately after operator-supplied override tag = %#x, want 0x00", got[len(override)])
	}
	suffix := got[len(override)+1:]
	if len(suffix) != 4 {
		t.Fatalf("len(random suffix after operator override) = %d, want 4", len(suffix))
	}
}

// --- MoneroHashingBlobForXNPSubmit / patchMoneroXNPReservedOffsets
// regression tests (XNP-proxy submit fix: RXM submits from an
// XNP-class multi-tier proxy carry workerNonce/poolNonce params that
// must be patched into the raw template before re-deriving the
// verification hashing blob -- see node.go's doc comments on both
// functions for the full rationale) ---

// xnpFixtureRawTemplateBlob/xnpFixtureReservedOffset/
// xnpFixtureHashingBlobLen are a real, go-xmr-lib-verified raw Monero
// blocktemplate_blob fixture (go-xmr-lib@v0.2.5's own
// support/block_test.go "offsetData"/"offsetDataReservedOffset"/
// "offsetDataHashingBlobLen" constants, duplicated here the same way
// internal/leaflib/proxy/upstream_applyjob_test.go already duplicates
// them -- see that file's own doc comment for the full,
// independently-verified provenance: a real 60-byte tx_extra nonce
// region starting at absolute byte offset 130, confirmed by parsing,
// patching, and re-parsing with go-xmr-lib/support's own real
// primitives, not hand-counted). offset 130 comfortably fits both the
// +8 (poolNonce, absolute 138) and +12 (workerNonce, absolute 142)
// writes this fix performs.
const (
	xnpFixtureRawTemplateBlob = "0e0ed286da8006ecdc1aab3033cf1716c52f13f9d8ae0051615a2453643de94643b550d543becd0000000002abc78b0101ffefc68b0101fcfcf0d4b422025014bb4a1eade6622fd781cb1063381cad396efa69719b41aa28b4fce8c7ad4b5f019ce1dc670456b24a5e03c2d9058a2df10fec779e2579753b1847b74ee644f16b023c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000051399a1bc46a846474f5b33db24eae173a26393b976054ee14f9feefe99925233802867097564c9db7a36af5bb5ed33ab46e63092bd8d32cef121608c3258edd55562812e21cc7e3ac73045745a72f7d74581d9a0849d6f30e8b2923171253e864f4e9ddea3acb5bc755f1c4a878130a70c26297540bc0b7a57affb6b35c1f03d8dbd54ece8457531f8cba15bb74516779c01193e212050423020e45aa2c15dcb"
	xnpFixtureReservedOffset  = 130
	xnpFixtureHashingBlobLen  = 76
)

// TestPatchMoneroXNPReservedOffsets_LandsAtCorrectByteOffsets is
// required test (a): confirms the real offset math
// (reservedOffset+8/reservedOffset+12) actually lands the two
// big-endian uint32 values at the right byte positions in a
// synthetic buffer -- asserting on the raw bytes directly, not just
// "no error".
func TestPatchMoneroXNPReservedOffsets_LandsAtCorrectByteOffsets(t *testing.T) {
	const reservedOffset = 10
	raw := bytes.Repeat([]byte{0xEE}, reservedOffset+16+4) // headroom past the +12+4 write
	orig := append([]byte(nil), raw...)

	const workerNonce = 0xAABBCCDD
	const poolNonce = 0x11223344

	got, err := patchMoneroXNPReservedOffsets(raw, reservedOffset, workerNonce, poolNonce)
	if err != nil {
		t.Fatalf("patchMoneroXNPReservedOffsets: %v", err)
	}

	wantPool := make([]byte, 4)
	binary.BigEndian.PutUint32(wantPool, poolNonce)
	if !bytes.Equal(got[reservedOffset+8:reservedOffset+12], wantPool) {
		t.Errorf("poolNonce bytes at [reservedOffset+8:reservedOffset+12] = %x, want %x (big-endian %d)", got[reservedOffset+8:reservedOffset+12], wantPool, poolNonce)
	}
	wantWorker := make([]byte, 4)
	binary.BigEndian.PutUint32(wantWorker, workerNonce)
	if !bytes.Equal(got[reservedOffset+12:reservedOffset+16], wantWorker) {
		t.Errorf("workerNonce bytes at [reservedOffset+12:reservedOffset+16] = %x, want %x (big-endian %d)", got[reservedOffset+12:reservedOffset+16], wantWorker, workerNonce)
	}

	// Everything outside the two patched 4-byte windows must be
	// untouched.
	if !bytes.Equal(got[:reservedOffset+8], orig[:reservedOffset+8]) {
		t.Errorf("bytes before the patched region were modified")
	}
	if !bytes.Equal(got[reservedOffset+16:], orig[reservedOffset+16:]) {
		t.Errorf("bytes after the patched region were modified")
	}

	// raw itself must be untouched -- patchMoneroXNPReservedOffsets
	// must return a copy, never mutate its input.
	if !bytes.Equal(raw, orig) {
		t.Fatalf("patchMoneroXNPReservedOffsets mutated its input raw buffer -- must operate on a copy")
	}
}

// TestPatchMoneroXNPReservedOffsets_TooShortReturnsError is part of
// required test (b): a buffer too short for reservedOffset+16 must
// return a clear error, not panic.
func TestPatchMoneroXNPReservedOffsets_TooShortReturnsError(t *testing.T) {
	const reservedOffset = 10
	raw := make([]byte, reservedOffset+15) // one byte short of the required +16

	if _, err := patchMoneroXNPReservedOffsets(raw, reservedOffset, 1, 2); err == nil {
		t.Fatal("expected an error for a too-short buffer, got nil")
	}
}

// TestMoneroHashingBlobForXNPSubmit_NilJob confirms the nil-job guard
// mirrors MoneroHashingBlobForSubmit's own.
func TestMoneroHashingBlobForXNPSubmit_NilJob(t *testing.T) {
	if _, err := MoneroHashingBlobForXNPSubmit(nil, 0, 1, 2); err == nil {
		t.Fatal("expected an error for a nil job, got nil")
	}
}

// TestMoneroHashingBlobForXNPSubmit_EmptyRawTemplateBlob is required
// test (c) (first half): a job with an empty RawTemplateBlob must
// return a clear error, not panic, even with a plausible
// ReservedOffset.
func TestMoneroHashingBlobForXNPSubmit_EmptyRawTemplateBlob(t *testing.T) {
	job := &Job{Algo: poolpb.Algo_ALGO_RXM, ReservedOffset: 130, RawTemplateBlob: nil}
	_, err := MoneroHashingBlobForXNPSubmit(job, 0, 1, 2)
	if err == nil {
		t.Fatal("expected an error for an empty RawTemplateBlob, got nil")
	}
	if !strings.Contains(err.Error(), "RawTemplateBlob is empty") {
		t.Errorf("error = %v, want it to mention the empty RawTemplateBlob", err)
	}
}

// TestMoneroHashingBlobForXNPSubmit_ZeroReservedOffset is required
// test (c) (second half): a job with ReservedOffset == 0 (job.go's
// documented "not populated"/zero-value convention) must return a
// clear error, not panic, even with a real, non-empty
// RawTemplateBlob.
func TestMoneroHashingBlobForXNPSubmit_ZeroReservedOffset(t *testing.T) {
	rawBlob, err := hex.DecodeString(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("decoding fixture hex: %v", err)
	}
	job := &Job{Algo: poolpb.Algo_ALGO_RXM, ReservedOffset: 0, RawTemplateBlob: rawBlob}
	_, err = MoneroHashingBlobForXNPSubmit(job, 0, 1, 2)
	if err == nil {
		t.Fatal("expected an error for ReservedOffset == 0, got nil")
	}
	if !strings.Contains(err.Error(), "ReservedOffset") {
		t.Errorf("error = %v, want it to mention ReservedOffset", err)
	}
}

// TestMoneroHashingBlobForXNPSubmit_TooShortRawTemplateBlob is
// required test (b) (second half): a job whose RawTemplateBlob is too
// short for ReservedOffset+16 must return a clear error, not panic.
func TestMoneroHashingBlobForXNPSubmit_TooShortRawTemplateBlob(t *testing.T) {
	job := &Job{
		Algo:            poolpb.Algo_ALGO_RXM,
		ReservedOffset:  70,
		RawTemplateBlob: make([]byte, 76), // real production repro shape: offset=179 blob_len=76 (see job.go's ReservedOffsetUsable doc comment) -- 70+16=86 > 76
	}
	if _, err := MoneroHashingBlobForXNPSubmit(job, 0, 1, 2); err == nil {
		t.Fatal("expected an error for a too-short RawTemplateBlob, got nil")
	}
}

// TestMoneroHashingBlobForXNPSubmit_RoundTripsWithRealFixture is
// required test (d): patches a real, go-xmr-lib-verified raw
// blocktemplate_blob's real reserved-offset region via
// MoneroHashingBlobForXNPSubmit, confirms it succeeds and produces a
// hashing blob of the expected real length, AND independently
// confirms (by separately patching a copy the exact same way and
// re-parsing it with go-xmr-lib/support's own real
// ParseBlockFromTemplateBlob) that the two values actually landed at
// the expected coinbase tx_extra locations -- go-xmr-lib's
// serialization.Transaction.Extra.Nonce is a real, inspectable public
// field (confirmed via that library's own API), so this checks it
// directly rather than merely trusting no error occurred.
func TestMoneroHashingBlobForXNPSubmit_RoundTripsWithRealFixture(t *testing.T) {
	rawBlob, err := hex.DecodeString(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("decoding fixture hex: %v", err)
	}

	const workerNonce = 0xDEADBEEF
	const poolNonce = 0xC0FFEE01

	job := &Job{
		Algo:            poolpb.Algo_ALGO_RXM,
		ReservedOffset:  xnpFixtureReservedOffset,
		RawTemplateBlob: rawBlob,
		VmKey:           []byte("test-monero-seed-hash-32-bytes!"),
	}

	hashingBlob, err := MoneroHashingBlobForXNPSubmit(job, 0x818d1a00, workerNonce, poolNonce)
	if err != nil {
		t.Fatalf("MoneroHashingBlobForXNPSubmit: %v", err)
	}
	if len(hashingBlob) != xnpFixtureHashingBlobLen {
		t.Errorf("len(hashingBlob) = %d, want %d (the real, correctly-sized RandomX hashing blob for this fixture)", len(hashingBlob), xnpFixtureHashingBlobLen)
	}

	// job.RawTemplateBlob itself must be untouched.
	rawBlobAfter, err := hex.DecodeString(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("decoding fixture hex: %v", err)
	}
	if !bytes.Equal(job.RawTemplateBlob, rawBlobAfter) {
		t.Fatalf("MoneroHashingBlobForXNPSubmit mutated job.RawTemplateBlob -- must operate on a copy")
	}

	// Independent round-trip: patch a separate copy the exact same
	// way and re-parse it directly with go-xmr-lib/support, then
	// inspect the parsed coinbase's real tx_extra nonce field to
	// confirm the two values genuinely landed where expected --
	// not just that MoneroHashingBlobForXNPSubmit claimed success.
	patched, err := patchMoneroXNPReservedOffsets(rawBlob, xnpFixtureReservedOffset, workerNonce, poolNonce)
	if err != nil {
		t.Fatalf("patchMoneroXNPReservedOffsets: %v", err)
	}
	parsedBlock, err := support.ParseBlockFromTemplateBlob(hex.EncodeToString(patched))
	if err != nil {
		t.Fatalf("support.ParseBlockFromTemplateBlob on the independently-patched blob: %v", err)
	}
	extraNonce := parsedBlock.MinerTxn.Extra.Nonce
	if len(extraNonce) < 16 {
		t.Fatalf("parsed coinbase tx_extra nonce region is only %d bytes, want at least 16", len(extraNonce))
	}
	// poolNonce lives at absolute reservedOffset+8, i.e. relative
	// byte 8 within Extra.Nonce (which itself starts at
	// reservedOffset); workerNonce at relative byte 12.
	if got := binary.BigEndian.Uint32(extraNonce[8:12]); got != poolNonce {
		t.Errorf("parsed coinbase tx_extra poolNonce = %#x, want %#x", got, poolNonce)
	}
	if got := binary.BigEndian.Uint32(extraNonce[12:16]); got != workerNonce {
		t.Errorf("parsed coinbase tx_extra workerNonce = %#x, want %#x", got, workerNonce)
	}

	parsedHashingBlob, err := support.GetBlockHashingBlob(parsedBlock)
	if err != nil {
		t.Fatalf("support.GetBlockHashingBlob on the independently-patched blob: %v", err)
	}
	if len(parsedHashingBlob) != xnpFixtureHashingBlobLen {
		t.Errorf("independently-derived hashing blob length = %d, want %d", len(parsedHashingBlob), xnpFixtureHashingBlobLen)
	}

	// The plain miner nonce (0x818d1a00, little-endian, matching this
	// package's own real xmrig production capture -- see
	// session_test.go's xmrigCaptureNonce) must also have been
	// applied to the FINAL returned hashing blob, at whatever offset
	// parseMoneroBlockHeaderNonceOffset finds for it.
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(hashingBlob)
	if err != nil {
		t.Fatalf("parseMoneroBlockHeaderNonceOffset on the returned hashing blob: %v", err)
	}
	wantNonce := make([]byte, 4)
	binary.LittleEndian.PutUint32(wantNonce, 0x818d1a00)
	if !bytes.Equal(hashingBlob[nonceOffset:nonceOffset+4], wantNonce) {
		t.Errorf("plain nonce bytes at the header nonce offset = %x, want %x (little-endian 0x818d1a00)", hashingBlob[nonceOffset:nonceOffset+4], wantNonce)
	}
}
