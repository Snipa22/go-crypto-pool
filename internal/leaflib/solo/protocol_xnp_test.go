// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// legacyJobPayload captures the EXACT JobPayload wire shape as it
// existed immediately BEFORE this XNP-proxy-detection fix (i.e.
// protocol.go's JobPayload with no BlocktemplateBlob/ReservedOffset/
// ClientNonceOffset/ClientPoolOffset fields at all) — used below as an
// independent, byte-for-byte non-regression oracle: for any
// non-proxy-detected session, marshaling the SAME real field values
// through this frozen pre-change shape and through the real
// (post-change) JobPayload must produce byte-identical JSON. If the
// fix ever leaked one of the four new fields onto a non-proxy job's
// wire output, this comparison would fail (the real JobPayload's JSON
// would carry an extra key the legacy shape never could).
type legacyJobPayload struct {
	Algo     string `json:"algo"`
	Blob     string `json:"blob"`
	Height   uint64 `json:"height"`
	JobID    string `json:"job_id"`
	Target   string `json:"target"`
	XN       string `json:"xn,omitempty"`
	SeedHash string `json:"seed_hash,omitempty"`
}

// asLegacy projects a real JobPayload's already-existing (pre-fix)
// fields onto legacyJobPayload, deliberately dropping the four new
// pointer fields — the point of the comparison is exactly that
// dropping them changes nothing for a non-proxy job.
func asLegacy(p JobPayload) legacyJobPayload {
	return legacyJobPayload{
		Algo:     p.Algo,
		Blob:     p.Blob,
		Height:   p.Height,
		JobID:    p.JobID,
		Target:   p.Target,
		XN:       p.XN,
		SeedHash: p.SeedHash,
	}
}

// newXNPTestSession builds a minimal, directly-constructed *Session
// sufficient to exercise jobPayload in isolation (no real
// ManagedConnection/Server/net.Pipe harness needed — jobPayload itself
// only touches s.recordJob's own bookkeeping fields, s.xn, and
// s.agent). agent mirrors what handleLogin already stores via
// s.agent.Store(login.Agent) at real login time.
func newXNPTestSession(agent string, xn string) *Session {
	s := &Session{xn: xn, jobLog: make(map[string]*Job)}
	s.agent.Store(agent)
	return s
}

// newXNPTestJobRXM builds a directly-constructed ALGO_RXM *Job with a
// real, non-zero ReservedOffset and RawTemplateBlob — mirroring what
// monero_node.go's GetBlockTemplate now populates for a real monerod
// get_block_template response, without needing a real/fake monerod
// round-trip for this test.
func newXNPTestJobRXM(reservedOffset int, rawTemplateBlob []byte) *Job {
	return &Job{
		ID:               "abcdef0123456789",
		Algo:             poolpb.Algo_ALGO_RXM,
		Height:           123456,
		Header:           []byte("test-monero-hashing-blob-32byte!"),
		StaticDifficulty: 1000,
		VmKey:            []byte("test-monero-seed-hash-32-bytes!"),
		ReservedOffset:   reservedOffset,
		// ReservedOffsetUsable: true -- this fixture represents a
		// normal, healthy job whose real GetBlockTemplate bounds
		// check (monero_node.go) passed. See
		// TestJobPayloadXNPReservationUnavailableRXM below for the
		// degraded (false) case, constructed directly rather than
		// through this helper.
		ReservedOffsetUsable: true,
		RawTemplateBlob:      rawTemplateBlob,
	}
}

// newXNPTestJobRXT builds a directly-constructed ALGO_RXT *Job. RXT
// jobs never carry ReservedOffset/RawTemplateBlob (see job.go's doc
// comments on those fields — they are ALGO_RXM-only), so this
// deliberately leaves both at their zero value, matching real
// production RXT jobs.
func newXNPTestJobRXT() *Job {
	return &Job{
		ID:               "fedcba9876543210",
		Algo:             poolpb.Algo_ALGO_RXT,
		Height:           654321,
		Header:           []byte("test-tari-merge-mining-hash-32b"),
		StaticDifficulty: 1000,
		VmKey:            []byte("test-tari-vm-key-32-bytes-long!"),
	}
}

// TestJobPayloadXNPNonRegressionRXM is the required non-regression
// test for RXM: a login with a normal agent ("XMRig/6.21.0") must
// produce a JobPayload whose marshaled JSON is byte-identical to the
// frozen pre-change (legacyJobPayload) shape — i.e. the four new
// pointer fields are provably absent from the wire, not merely nil in
// Go.
func TestJobPayloadXNPNonRegressionRXM(t *testing.T) {
	s := newXNPTestSession("XMRig/6.21.0", "ab12")
	job := newXNPTestJobRXM(171, []byte("this is a fake raw monero blocktemplate_blob used only as a test fixture"))

	got := s.jobPayload(job)

	if got.BlocktemplateBlob != nil || got.ReservedOffset != nil || got.ClientNonceOffset != nil || got.ClientPoolOffset != nil {
		t.Fatalf("non-proxy RXM job payload has a non-nil XNP field, want all four nil: %+v", got)
	}

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal actual JobPayload: %v", err)
	}
	legacyJSON, err := json.Marshal(asLegacy(got))
	if err != nil {
		t.Fatalf("marshal legacy projection: %v", err)
	}
	if !bytes.Equal(gotJSON, legacyJSON) {
		t.Fatalf("RXM non-regression FAILED:\n  before (legacy shape): %s\n  after  (actual JobPayload): %s", legacyJSON, gotJSON)
	}
	t.Logf("RXM non-regression OK — before: %s\n                 after:  %s", legacyJSON, gotJSON)
}

// TestJobPayloadXNPNonRegressionRXT mirrors
// TestJobPayloadXNPNonRegressionRXM for ALGO_RXT.
func TestJobPayloadXNPNonRegressionRXT(t *testing.T) {
	s := newXNPTestSession("XMRig/6.21.0", "cd34")
	job := newXNPTestJobRXT()

	got := s.jobPayload(job)

	if got.BlocktemplateBlob != nil || got.ReservedOffset != nil || got.ClientNonceOffset != nil || got.ClientPoolOffset != nil {
		t.Fatalf("non-proxy RXT job payload has a non-nil XNP field, want all four nil: %+v", got)
	}

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal actual JobPayload: %v", err)
	}
	legacyJSON, err := json.Marshal(asLegacy(got))
	if err != nil {
		t.Fatalf("marshal legacy projection: %v", err)
	}
	if !bytes.Equal(gotJSON, legacyJSON) {
		t.Fatalf("RXT non-regression FAILED:\n  before (legacy shape): %s\n  after  (actual JobPayload): %s", legacyJSON, gotJSON)
	}
	t.Logf("RXT non-regression OK — before: %s\n                 after:  %s", legacyJSON, gotJSON)
}

// TestJobPayloadXNPNonRegressionNoAgent covers the "no agent at all"
// case the task explicitly calls out alongside "XMRig/6.21.0".
func TestJobPayloadXNPNonRegressionNoAgent(t *testing.T) {
	s := newXNPTestSession("", "ef56")
	job := newXNPTestJobRXM(171, []byte("fixture"))

	got := s.jobPayload(job)
	if got.BlocktemplateBlob != nil || got.ReservedOffset != nil || got.ClientNonceOffset != nil || got.ClientPoolOffset != nil {
		t.Fatalf("empty-agent RXM job payload has a non-nil XNP field, want all four nil: %+v", got)
	}
	gotJSON, _ := json.Marshal(got)
	legacyJSON, _ := json.Marshal(asLegacy(got))
	if !bytes.Equal(gotJSON, legacyJSON) {
		t.Fatalf("empty-agent non-regression FAILED:\n  before: %s\n  after:  %s", legacyJSON, gotJSON)
	}
}

// TestJobPayloadXNPProxyShapeRXM is the required proxy-detection+shape
// test for RXM: a login whose agent contains "xmr-node-proxy" for an
// RXM job with a realistic ReservedOffset (171, matching the real
// supportxmr example in the task brief) must produce
// ClientNonceOffset == ReservedOffset+12, ClientPoolOffset ==
// ReservedOffset+8, and a non-nil BlocktemplateBlob that decodes as
// valid hex matching the raw template bytes.
func TestJobPayloadXNPProxyShapeRXM(t *testing.T) {
	const reservedOffset = 171
	rawTemplate := []byte("this is a fake raw monero blocktemplate_blob used only as a test fixture, deliberately longer than 32 bytes")

	s := newXNPTestSession("xmr-node-proxy/0.0.3", "ab12")
	job := newXNPTestJobRXM(reservedOffset, rawTemplate)

	got := s.jobPayload(job)

	if got.ReservedOffset == nil {
		t.Fatalf("ReservedOffset is nil, want a pointer to %d", reservedOffset)
	}
	if *got.ReservedOffset != reservedOffset {
		t.Errorf("ReservedOffset = %d, want %d", *got.ReservedOffset, reservedOffset)
	}
	if got.ClientNonceOffset == nil {
		t.Fatalf("ClientNonceOffset is nil, want a pointer to %d", reservedOffset+12)
	}
	if *got.ClientNonceOffset != reservedOffset+12 {
		t.Errorf("ClientNonceOffset = %d, want %d (ReservedOffset+12 = %d+12)", *got.ClientNonceOffset, reservedOffset+12, reservedOffset)
	}
	if got.ClientPoolOffset == nil {
		t.Fatalf("ClientPoolOffset is nil, want a pointer to %d", reservedOffset+8)
	}
	if *got.ClientPoolOffset != reservedOffset+8 {
		t.Errorf("ClientPoolOffset = %d, want %d (ReservedOffset+8 = %d+8)", *got.ClientPoolOffset, reservedOffset+8, reservedOffset)
	}
	if got.BlocktemplateBlob == nil {
		t.Fatalf("BlocktemplateBlob is nil, want a non-nil hex string")
	}
	decoded, err := hex.DecodeString(*got.BlocktemplateBlob)
	if err != nil {
		t.Fatalf("BlocktemplateBlob is not valid hex: %v", err)
	}
	if !bytes.Equal(decoded, rawTemplate) {
		t.Fatalf("BlocktemplateBlob decodes to %q, want the raw template bytes %q", decoded, rawTemplate)
	}

	// Every other field the reference sends (job_id/height/seed_hash/
	// blob/target) must STILL be populated exactly as for an ordinary
	// job — see protocol.go's JobPayload doc comment: proxy fields are
	// ADDITIONAL, not a replacement.
	if got.JobID != job.ID {
		t.Errorf("JobID = %q, want %q (proxy shape must not remove existing fields)", got.JobID, job.ID)
	}
	if got.Blob != hex.EncodeToString(job.Header) {
		t.Errorf("Blob = %q, want %q", got.Blob, hex.EncodeToString(job.Header))
	}
	if got.SeedHash != hex.EncodeToString(job.VmKey) {
		t.Errorf("SeedHash = %q, want %q", got.SeedHash, hex.EncodeToString(job.VmKey))
	}

	t.Logf("RXM proxy-shape OK — reserved_offset=%d client_nonce_offset=%d (want %d) client_pool_offset=%d (want %d) blocktemplate_blob_len=%d",
		*got.ReservedOffset, *got.ClientNonceOffset, reservedOffset+12, *got.ClientPoolOffset, reservedOffset+8, len(*got.BlocktemplateBlob))
}

// TestJobPayloadXNPProxyShapeRXT is the required proxy-detection+shape
// test for RXT: ClientNonceOffset must be exactly 39
// (rxtXmrigNonceOffset), ReservedOffset/ClientPoolOffset must stay
// nil (Tari has no real reserved-coinbase-area concept), and
// BlocktemplateBlob must equal Blob exactly (RXT has no
// raw-template/hashing-blob distinction).
func TestJobPayloadXNPProxyShapeRXT(t *testing.T) {
	s := newXNPTestSession("xmr-node-proxy/0.0.3", "cd34")
	job := newXNPTestJobRXT()

	got := s.jobPayload(job)

	if got.ReservedOffset != nil {
		t.Errorf("ReservedOffset = %v, want nil (RXT has no real reserved-coinbase-area concept)", *got.ReservedOffset)
	}
	if got.ClientPoolOffset != nil {
		t.Errorf("ClientPoolOffset = %v, want nil (RXT has no real reserved-coinbase-area concept)", *got.ClientPoolOffset)
	}
	if got.ClientNonceOffset == nil {
		t.Fatalf("ClientNonceOffset is nil, want a pointer to %d (rxtXmrigNonceOffset)", rxtXmrigNonceOffset)
	}
	if *got.ClientNonceOffset != rxtXmrigNonceOffset {
		t.Errorf("ClientNonceOffset = %d, want %d (rxtXmrigNonceOffset)", *got.ClientNonceOffset, rxtXmrigNonceOffset)
	}
	if got.BlocktemplateBlob == nil {
		t.Fatalf("BlocktemplateBlob is nil, want a non-nil hex string equal to Blob")
	}
	if *got.BlocktemplateBlob != got.Blob {
		t.Errorf("BlocktemplateBlob = %q, want it identical to Blob %q (RXT has no raw-template/hashing-blob distinction)", *got.BlocktemplateBlob, got.Blob)
	}

	t.Logf("RXT proxy-shape OK — client_nonce_offset=%d (want %d), reserved_offset=nil, client_pool_offset=nil, blocktemplate_blob==blob (%d hex chars)",
		*got.ClientNonceOffset, rxtXmrigNonceOffset, len(*got.BlocktemplateBlob))
}

// TestJobPayloadXNPCaseSensitivity is the required case-sensitivity
// test: an agent containing "XMR-NODE-PROXY" (wrong case) must NOT
// trigger proxy detection — this repo's IsXNPProxyAgent uses
// strings.Contains (case-sensitive), matching JavaScript's
// String.prototype.includes exactly, NOT an EqualFold-style
// case-insensitive comparison.
func TestJobPayloadXNPCaseSensitivity(t *testing.T) {
	if IsXNPProxyAgent("XMR-NODE-PROXY/1.0.0") {
		t.Fatalf("IsXNPProxyAgent(%q) = true, want false — case must matter (real reference uses case-sensitive JS .includes())", "XMR-NODE-PROXY/1.0.0")
	}
	if !IsXNPProxyAgent("xmr-node-proxy/1.0.0") {
		t.Fatalf("IsXNPProxyAgent(%q) = false, want true", "xmr-node-proxy/1.0.0")
	}
	if !IsXNPProxyAgent("some-wrapper/xmr-node-proxy/2.0.0") {
		t.Fatalf("IsXNPProxyAgent with the substring anywhere in the agent should still match")
	}

	s := newXNPTestSession("XMR-NODE-PROXY/1.0.0", "ab12")
	job := newXNPTestJobRXM(171, []byte("fixture"))
	got := s.jobPayload(job)
	if got.BlocktemplateBlob != nil || got.ReservedOffset != nil || got.ClientNonceOffset != nil || got.ClientPoolOffset != nil {
		t.Fatalf("wrong-case agent must not trigger proxy shape, got: %+v", got)
	}
}

// TestJobPayloadXNPReservationUnavailableRXM is the real regression
// test for the confirmed production bug this pass fixed: a real live
// leaf-proxy rejection ("proxy: worker-nonce offset is out of range
// for this template's blob: offset=179 blob_len=76") against a
// genuine low-tx-volume testnet block, root-caused to
// monero_node.go's GetBlockTemplate never validating that
// ReservedOffset+12 actually fits within the real returned
// blocktemplate_blob length. Constructs a Job with
// ReservedOffsetUsable: false (exactly what GetBlockTemplate now sets
// for such a job — see monero_node_test.go's
// TestMoneroNodeClient_GetBlockTemplate_ReservationDoesNotFitDegradesGracefully
// for the end-to-end proof of THAT half) and confirms jobPayload
// degrades this one job to omit all four XNP-proxy-shape fields —
// exactly the existing "nil means not offered" convention already
// used for RXT's ReservedOffset/ClientPoolOffset — via a real
// marshaled-JSON byte-diff, not just Go struct field assertions,
// even for a real XNP-proxy-detected agent that would otherwise
// receive the full shape.
func TestJobPayloadXNPReservationUnavailableRXM(t *testing.T) {
	s := newXNPTestSession("xmr-node-proxy/0.0.3", "ab12")
	job := &Job{
		ID:               "0011223344556677",
		Algo:             poolpb.Algo_ALGO_RXM,
		Height:           999999,
		Header:           []byte("test-monero-hashing-blob-32byte!"),
		StaticDifficulty: 1000,
		VmKey:            []byte("test-monero-seed-hash-32-bytes!"),
		ReservedOffset:   179,
		// ReservedOffsetUsable: false -- the exact degraded state
		// GetBlockTemplate sets when ReservedOffset+12 does not fit
		// within the real returned blocktemplate_blob (real
		// production repro: offset=179 blob_len=76).
		ReservedOffsetUsable: false,
		RawTemplateBlob:      make([]byte, 76),
	}

	got := s.jobPayload(job)

	if got.BlocktemplateBlob != nil || got.ReservedOffset != nil || got.ClientNonceOffset != nil || got.ClientPoolOffset != nil {
		t.Fatalf("ReservedOffsetUsable=false must omit all four XNP-proxy-shape fields even for a detected XNP-proxy agent, got: %+v", got)
	}

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal actual JobPayload: %v", err)
	}
	legacyJSON, err := json.Marshal(asLegacy(got))
	if err != nil {
		t.Fatalf("marshal legacy projection: %v", err)
	}
	if !bytes.Equal(gotJSON, legacyJSON) {
		t.Fatalf("ReservedOffsetUsable=false non-regression FAILED (a real byte-diff, not just struct fields):\n  before (legacy shape): %s\n  after  (actual JobPayload): %s", legacyJSON, gotJSON)
	}
	t.Logf("ReservedOffsetUsable=false degrades correctly, real byte-diff proof — before: %s\n                                                    after:  %s", legacyJSON, gotJSON)
}

// TestSubmitRequestWorkerNoncePoolNonceRoundTrip is the required
// table-driven test for SubmitRequest's WorkerNonce/PoolNonce wire
// shape: the exact real wire capture from this fix's task brief
// ({"job_id":"x","nonce":"...","result":"...","workerNonce":9,
// "poolNonce":9,"id":"..."}) must round-trip through json.Unmarshal
// with both fields non-nil and equal to 9, AND an ordinary submit
// WITHOUT those fields (every real xmrig-class RXM/RXT submit) must
// decode with both nil -- NOT zero-valued non-nil pointers -- since
// that pointer-vs-zero distinction is the entire reason these fields
// are pointer-typed (see protocol.go's doc comment).
func TestSubmitRequestWorkerNoncePoolNonceRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		wireJSON   string
		wantWorker *uint32
		wantPool   *uint32
		wantJobID  string
		wantNonce  string
		wantResult string
		wantID     string
	}{
		{
			name:       "XNP-class proxy submit carries both fields",
			wireJSON:   `{"job_id":"x","nonce":"59280000","result":"deadbeef","workerNonce":9,"poolNonce":9,"id":"session-1"}`,
			wantWorker: uint32Ptr(9),
			wantPool:   uint32Ptr(9),
			wantJobID:  "x",
			wantNonce:  "59280000",
			wantResult: "deadbeef",
			wantID:     "session-1",
		},
		{
			name:       "ordinary xmrig-class submit omits both fields",
			wireJSON:   `{"job_id":"y","nonce":"818d1a00","result":"cafebabe","id":"session-2"}`,
			wantWorker: nil,
			wantPool:   nil,
			wantJobID:  "y",
			wantNonce:  "818d1a00",
			wantResult: "cafebabe",
			wantID:     "session-2",
		},
		{
			name:       "explicit zero values are distinguishable from absent",
			wireJSON:   `{"job_id":"z","nonce":"00000000","result":"","workerNonce":0,"poolNonce":0,"id":"session-3"}`,
			wantWorker: uint32Ptr(0),
			wantPool:   uint32Ptr(0),
			wantJobID:  "z",
			wantNonce:  "00000000",
			wantResult: "",
			wantID:     "session-3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got SubmitRequest
			if err := json.Unmarshal([]byte(tc.wireJSON), &got); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if got.JobID != tc.wantJobID {
				t.Errorf("JobID = %q, want %q", got.JobID, tc.wantJobID)
			}
			if got.Nonce != tc.wantNonce {
				t.Errorf("Nonce = %q, want %q", got.Nonce, tc.wantNonce)
			}
			if got.Result != tc.wantResult {
				t.Errorf("Result = %q, want %q", got.Result, tc.wantResult)
			}
			if got.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", got.ID, tc.wantID)
			}
			assertUint32PtrEqual(t, "WorkerNonce", got.WorkerNonce, tc.wantWorker)
			assertUint32PtrEqual(t, "PoolNonce", got.PoolNonce, tc.wantPool)
		})
	}
}

func uint32Ptr(v uint32) *uint32 { return &v }

func assertUint32PtrEqual(t *testing.T, field string, got, want *uint32) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("%s: nil-ness mismatch (got nil=%v, want nil=%v) -- this is exactly the pointer-vs-zero distinction these fields exist to preserve", field, got == nil, want == nil)
	}
	if got != nil && *got != *want {
		t.Fatalf("%s = %d, want %d", field, *got, *want)
	}
}
