// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// legacyJobPayload mirrors solo package's own identical type exactly
// (protocol_xnp_test.go) — see that type's doc comment for the full
// rationale. Duplicated here (rather than imported) because it is
// itself test-only fixture data, matching this package's existing
// convention of mirroring solo's small test helpers locally.
type legacyJobPayload struct {
	Algo     string `json:"algo"`
	Blob     string `json:"blob"`
	Height   uint64 `json:"height"`
	JobID    string `json:"job_id"`
	Target   string `json:"target"`
	XN       string `json:"xn,omitempty"`
	SeedHash string `json:"seed_hash,omitempty"`
}

func asLegacy(p solo.JobPayload) legacyJobPayload {
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
// sufficient to exercise jobPayload in isolation — mirrors
// solo package's own identical helper (protocol_xnp_test.go).
func newXNPTestSession(agent string, xn string) *Session {
	s := &Session{xn: xn, jobLog: make(map[string]*solo.Job)}
	s.agent.Store(agent)
	return s
}

func newXNPTestJobRXM(reservedOffset int, rawTemplateBlob []byte) *solo.Job {
	return &solo.Job{
		ID:               "abcdef0123456789",
		Algo:             poolpb.Algo_ALGO_RXM,
		Height:           123456,
		Header:           []byte("test-monero-hashing-blob-32byte!"),
		StaticDifficulty: 1000,
		VmKey:            []byte("test-monero-seed-hash-32-bytes!"),
		ReservedOffset:   reservedOffset,
		RawTemplateBlob:  rawTemplateBlob,
	}
}

func newXNPTestJobRXT() *solo.Job {
	return &solo.Job{
		ID:               "fedcba9876543210",
		Algo:             poolpb.Algo_ALGO_RXT,
		Height:           654321,
		Header:           []byte("test-tari-merge-mining-hash-32b"),
		StaticDifficulty: 1000,
		VmKey:            []byte("test-tari-vm-key-32-bytes-long!"),
	}
}

// TestDirectJobPayloadXNPNonRegressionRXM mirrors solo package's
// TestJobPayloadXNPNonRegressionRXM exactly, for leaf-direct's own
// jobPayload implementation.
func TestDirectJobPayloadXNPNonRegressionRXM(t *testing.T) {
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
		t.Fatalf("leaf-direct RXM non-regression FAILED:\n  before (legacy shape): %s\n  after  (actual JobPayload): %s", legacyJSON, gotJSON)
	}
	t.Logf("leaf-direct RXM non-regression OK — before: %s\n                              after:  %s", legacyJSON, gotJSON)
}

// TestDirectJobPayloadXNPNonRegressionRXT mirrors solo's
// TestJobPayloadXNPNonRegressionRXT exactly.
func TestDirectJobPayloadXNPNonRegressionRXT(t *testing.T) {
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
		t.Fatalf("leaf-direct RXT non-regression FAILED:\n  before (legacy shape): %s\n  after  (actual JobPayload): %s", legacyJSON, gotJSON)
	}
	t.Logf("leaf-direct RXT non-regression OK — before: %s\n                              after:  %s", legacyJSON, gotJSON)
}

// TestDirectJobPayloadXNPNonRegressionNoAgent covers "no agent at
// all" for leaf-direct.
func TestDirectJobPayloadXNPNonRegressionNoAgent(t *testing.T) {
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

// TestDirectJobPayloadXNPProxyShapeRXM mirrors solo's
// TestJobPayloadXNPProxyShapeRXM exactly, for leaf-direct.
func TestDirectJobPayloadXNPProxyShapeRXM(t *testing.T) {
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

	t.Logf("leaf-direct RXM proxy-shape OK — reserved_offset=%d client_nonce_offset=%d (want %d) client_pool_offset=%d (want %d) blocktemplate_blob_len=%d",
		*got.ReservedOffset, *got.ClientNonceOffset, reservedOffset+12, *got.ClientPoolOffset, reservedOffset+8, len(*got.BlocktemplateBlob))
}

// TestDirectJobPayloadXNPProxyShapeRXT mirrors solo's
// TestJobPayloadXNPProxyShapeRXT exactly, for leaf-direct.
func TestDirectJobPayloadXNPProxyShapeRXT(t *testing.T) {
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

	t.Logf("leaf-direct RXT proxy-shape OK — client_nonce_offset=%d (want %d), reserved_offset=nil, client_pool_offset=nil, blocktemplate_blob==blob (%d hex chars)",
		*got.ClientNonceOffset, rxtXmrigNonceOffset, len(*got.BlocktemplateBlob))
}

// TestDirectJobPayloadXNPCaseSensitivity mirrors solo's
// TestJobPayloadXNPCaseSensitivity exactly, for leaf-direct.
func TestDirectJobPayloadXNPCaseSensitivity(t *testing.T) {
	if solo.IsXNPProxyAgent("XMR-NODE-PROXY/1.0.0") {
		t.Fatalf("IsXNPProxyAgent(%q) = true, want false — case must matter", "XMR-NODE-PROXY/1.0.0")
	}

	s := newXNPTestSession("XMR-NODE-PROXY/1.0.0", "ab12")
	job := newXNPTestJobRXM(171, []byte("fixture"))
	got := s.jobPayload(job)
	if got.BlocktemplateBlob != nil || got.ReservedOffset != nil || got.ClientNonceOffset != nil || got.ClientPoolOffset != nil {
		t.Fatalf("wrong-case agent must not trigger proxy shape, got: %+v", got)
	}
}
