// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
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

// legacyJobPayloadWithDifficulty / asLegacyWithDifficulty mirror
// solo's identical helpers (protocol_xnp_test.go) — see that type's
// doc comment: they keep only the three difficulty keys this pass
// added, so the ReservedOffsetUsable=false test below still proves,
// via a real byte-diff, that the FOUR OFFSET fields are absent from
// the wire, while acknowledging that the difficulty half is
// deliberately not gated on that bounds check.
type legacyJobPayloadWithDifficulty struct {
	Algo          string  `json:"algo"`
	Blob          string  `json:"blob"`
	Height        uint64  `json:"height"`
	JobID         string  `json:"job_id"`
	Target        string  `json:"target"`
	XN            string  `json:"xn,omitempty"`
	SeedHash      string  `json:"seed_hash,omitempty"`
	Difficulty    *uint64 `json:"difficulty,omitempty"`
	TargetDiff    *uint64 `json:"target_diff,omitempty"`
	TargetDiffHex *string `json:"target_diff_hex,omitempty"`
}

func asLegacyWithDifficulty(p solo.JobPayload) legacyJobPayloadWithDifficulty {
	return legacyJobPayloadWithDifficulty{
		Algo:          p.Algo,
		Blob:          p.Blob,
		Height:        p.Height,
		JobID:         p.JobID,
		Target:        p.Target,
		XN:            p.XN,
		SeedHash:      p.SeedHash,
		Difficulty:    p.Difficulty,
		TargetDiff:    p.TargetDiff,
		TargetDiffHex: p.TargetDiffHex,
	}
}

// assertNoDifficultyKeysOnWire mirrors solo's identical helper — see
// its doc comment (protocol_xnp_test.go).
func assertNoDifficultyKeysOnWire(t *testing.T, payload solo.JobPayload) {
	t.Helper()
	if payload.Difficulty != nil || payload.TargetDiff != nil || payload.TargetDiffHex != nil {
		t.Fatalf("non-proxy job payload has a non-nil XNP difficulty field, want all three nil: difficulty=%v target_diff=%v target_diff_hex=%v",
			payload.Difficulty, payload.TargetDiff, payload.TargetDiffHex)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal JobPayload: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal marshaled JobPayload into a key map: %v", err)
	}
	for _, key := range []string{"difficulty", "target_diff", "target_diff_hex"} {
		if _, present := keys[key]; present {
			t.Errorf("marshaled non-proxy job JSON carries key %q, want it absent (omitempty): %s", key, raw)
		}
	}
}

// assertXNPDifficultyFields mirrors solo's identical helper — see its
// doc comment (protocol_xnp_test.go).
func assertXNPDifficultyFields(t *testing.T, got solo.JobPayload, wantDifficulty uint64) {
	t.Helper()
	if got.Difficulty == nil {
		t.Fatalf("Difficulty is nil, want a pointer to %d -- this is the exact field whose absence made a real MoneroOcean-fork xmr-node-proxy fall back to difficulty 1", wantDifficulty)
	}
	if *got.Difficulty != wantDifficulty {
		t.Errorf("Difficulty = %d, want %d (job.StaticDifficulty)", *got.Difficulty, wantDifficulty)
	}
	if got.TargetDiff == nil {
		t.Fatalf("TargetDiff is nil, want a pointer to %d (legacy: `target_diff: this.difficulty`)", wantDifficulty)
	}
	if *got.TargetDiff != wantDifficulty {
		t.Errorf("TargetDiff = %d, want %d (the SAME plain numeric value as Difficulty)", *got.TargetDiff, wantDifficulty)
	}
	if *got.TargetDiff != *got.Difficulty {
		t.Errorf("TargetDiff (%d) != Difficulty (%d): legacy sends one plain numeric difficulty under both keys", *got.TargetDiff, *got.Difficulty)
	}
	if got.TargetDiffHex == nil {
		t.Fatalf("TargetDiffHex is nil, want the SAME hex string as Target (%q)", got.Target)
	}
	if *got.TargetDiffHex != got.Target {
		t.Errorf("TargetDiffHex = %q, want it byte-identical to Target %q (legacy's this.diffHex IS what its `target` carries)", *got.TargetDiffHex, got.Target)
	}
}

// newXNPTestSession builds a minimal, directly-constructed *Session
// sufficient to exercise jobPayload in isolation — mirrors
// solo package's own identical helper (protocol_xnp_test.go).
func newXNPTestSession(agent string, xn string) *Session {
	s := &Session{jobs: leaflib.NewJobHistory[*solo.Job](0)}
	s.xn.Store(xn)
	s.identity.Store(&leaflib.MinerIdentity{Agent: agent})
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
		// ReservedOffsetUsable: true -- this fixture represents a
		// normal, healthy job whose real GetBlockTemplate bounds
		// check (monero_node.go) passed, i.e. reservedOffset+12 fits
		// within rawTemplateBlob for every existing/non-regression
		// test that calls this helper. TestDirectJobPayloadXNP
		// ReservationUnavailableRXM below constructs its own
		// ReservedOffsetUsable:false job directly, rather than
		// through this helper, to exercise the degraded path.
		ReservedOffsetUsable: true,
		RawTemplateBlob:      rawTemplateBlob,
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
	assertNoDifficultyKeysOnWire(t, got)

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
	assertNoDifficultyKeysOnWire(t, got)

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
	assertNoDifficultyKeysOnWire(t, got)
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

	// DIFFICULTY HALF of the same real proxy-class job shape (the
	// "difficulty 1" incident fix) -- mirrors solo's identical
	// assertion.
	assertXNPDifficultyFields(t, got, job.StaticDifficulty)

	t.Logf("leaf-direct RXM proxy-shape OK — reserved_offset=%d client_nonce_offset=%d (want %d) client_pool_offset=%d (want %d) blocktemplate_blob_len=%d difficulty=%d target_diff=%d target_diff_hex=%s",
		*got.ReservedOffset, *got.ClientNonceOffset, reservedOffset+12, *got.ClientPoolOffset, reservedOffset+8, len(*got.BlocktemplateBlob),
		*got.Difficulty, *got.TargetDiff, *got.TargetDiffHex)
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
		t.Fatalf("ClientNonceOffset is nil, want a pointer to %d (leaflib.RXTXmrigNonceOffset)", leaflib.RXTXmrigNonceOffset)
	}
	if *got.ClientNonceOffset != leaflib.RXTXmrigNonceOffset {
		t.Errorf("ClientNonceOffset = %d, want %d (leaflib.RXTXmrigNonceOffset)", *got.ClientNonceOffset, leaflib.RXTXmrigNonceOffset)
	}
	if got.BlocktemplateBlob == nil {
		t.Fatalf("BlocktemplateBlob is nil, want a non-nil hex string equal to Blob")
	}
	if *got.BlocktemplateBlob != got.Blob {
		t.Errorf("BlocktemplateBlob = %q, want it identical to Blob %q (RXT has no raw-template/hashing-blob distinction)", *got.BlocktemplateBlob, got.Blob)
	}

	assertXNPDifficultyFields(t, got, job.StaticDifficulty)

	t.Logf("leaf-direct RXT proxy-shape OK — client_nonce_offset=%d (want %d), reserved_offset=nil, client_pool_offset=nil, blocktemplate_blob==blob (%d hex chars), difficulty=%d target_diff=%d target_diff_hex=%s",
		*got.ClientNonceOffset, leaflib.RXTXmrigNonceOffset, len(*got.BlocktemplateBlob), *got.Difficulty, *got.TargetDiff, *got.TargetDiffHex)
}

// TestDirectJobPayloadXNPCaseInsensitivity mirrors solo's
// TestJobPayloadXNPCaseInsensitivity exactly, for leaf-direct (renamed
// from TestDirectJobPayloadXNPCaseSensitivity -- case sensitivity was
// intentionally removed per product-owner direction, see
// solo.IsXNPProxyAgent's doc comment).
func TestDirectJobPayloadXNPCaseInsensitivity(t *testing.T) {
	if !solo.IsXNPProxyAgent("XMR-NODE-PROXY/1.0.0") {
		t.Fatalf("IsXNPProxyAgent(%q) = false, want true — case must NOT matter", "XMR-NODE-PROXY/1.0.0")
	}

	s := newXNPTestSession("XMR-NODE-PROXY/1.0.0", "ab12")
	job := newXNPTestJobRXM(171, []byte("this is a fake raw monero blocktemplate_blob used only as a test fixture, deliberately longer than 32 bytes"))
	got := s.jobPayload(job)
	if got.BlocktemplateBlob == nil || got.ReservedOffset == nil || got.ClientNonceOffset == nil || got.ClientPoolOffset == nil {
		t.Fatalf("wrong-case (but now-matching) XNP agent must trigger the proxy shape, got: %+v", got)
	}
}

// TestDirectJobPayloadXNPReservationUnavailableRXM mirrors solo's
// TestJobPayloadXNPReservationUnavailableRXM exactly, for leaf-direct's
// own jobPayload -- both leaf-solo and leaf-direct share the SAME
// solo.MoneroNodeClient.GetBlockTemplate implementation, so the same
// real production bug (a real live leaf-proxy rejection, "offset=179
// blob_len=76") and fix (ReservedOffsetUsable-gated degradation to
// omitted proxy-shape fields) apply identically here.
func TestDirectJobPayloadXNPReservationUnavailableRXM(t *testing.T) {
	s := newXNPTestSession("xmr-node-proxy/0.0.3", "ab12")
	job := &solo.Job{
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

	// The DIFFICULTY half of the XNP-proxy shape is deliberately NOT
	// gated on this bounds check (see session.go's jobPayload): an
	// XNP-proxy client whose template fails it still must not be told
	// its difficulty is 1. So the byte-diff below runs against a
	// projection that keeps those three keys and drops only the four
	// offset fields whose absence is this test's actual subject.
	assertXNPDifficultyFields(t, got, job.StaticDifficulty)

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal actual JobPayload: %v", err)
	}
	legacyJSON, err := json.Marshal(asLegacyWithDifficulty(got))
	if err != nil {
		t.Fatalf("marshal legacy projection: %v", err)
	}
	if !bytes.Equal(gotJSON, legacyJSON) {
		t.Fatalf("leaf-direct ReservedOffsetUsable=false non-regression FAILED (real byte-diff):\n  before (legacy shape): %s\n  after  (actual JobPayload): %s", legacyJSON, gotJSON)
	}
	t.Logf("leaf-direct ReservedOffsetUsable=false degrades correctly, real byte-diff proof — before: %s\n                                                               after:  %s", legacyJSON, gotJSON)
}

// TestDirectJobPayloadXNPDifficultyAllMoneroFamilyAlgos mirrors solo's
// TestJobPayloadXNPDifficultyAllMoneroFamilyAlgos exactly, for
// leaf-direct's own jobPayload: every algo the existing proxy-shape
// switch already handles as monerod-family, proxy and non-proxy.
func TestDirectJobPayloadXNPDifficultyAllMoneroFamilyAlgos(t *testing.T) {
	algos := []poolpb.Algo{
		poolpb.Algo_ALGO_RXM,
		poolpb.Algo_ALGO_XMR,
		poolpb.Algo_ALGO_ARQ,
		poolpb.Algo_ALGO_XEQ,
		poolpb.Algo_ALGO_GRFT,
		poolpb.Algo_ALGO_SFX,
		poolpb.Algo_ALGO_ZEPH,
		poolpb.Algo_ALGO_SAL,
	}
	const difficulty = 50000

	for _, algo := range algos {
		t.Run(algo.String(), func(t *testing.T) {
			newJob := func() *solo.Job {
				job := newXNPTestJobRXM(171, []byte("this is a fake raw monero blocktemplate_blob used only as a test fixture, deliberately longer than 32 bytes"))
				job.Algo = algo
				job.StaticDifficulty = difficulty
				return job
			}

			proxySession := newXNPTestSession("xmr-node-proxy/0.0.3", "ab12")
			proxyJob := proxySession.jobPayload(newJob())
			assertXNPDifficultyFields(t, proxyJob, difficulty)

			ordinarySession := newXNPTestSession("XMRig/6.21.0", "ab12")
			ordinaryJob := ordinarySession.jobPayload(newJob())
			assertNoDifficultyKeysOnWire(t, ordinaryJob)

			if proxyJob.Target != ordinaryJob.Target {
				t.Errorf("Target differs between proxy (%q) and ordinary (%q) sessions on the same job; the fix must be purely additive", proxyJob.Target, ordinaryJob.Target)
			}
		})
	}
}

// TestDirectJobPayloadXNPTargetDiffLiveIncidentRXM mirrors solo's
// TestJobPayloadXNPTargetDiffLiveIncidentRXM exactly, for
// leaf-direct's own jobPayload: the real, live-shaped end-to-end
// regression test for the reported incident (a MoneroOcean-fork
// xmr-node-proxy "getting a job difficulty of 1"), asserted on the
// MARSHALED WIRE JSON decoded the way a JS client reads it, at 50000
// -- today's real production min-difficulty.
func TestDirectJobPayloadXNPTargetDiffLiveIncidentRXM(t *testing.T) {
	const liveMinDifficulty = 50000
	const reservedOffset = 171

	s := newXNPTestSession("xmr-node-proxy/0.0.3", "ab12")
	job := newXNPTestJobRXM(reservedOffset, []byte("this is a fake raw monero blocktemplate_blob used only as a test fixture, deliberately longer than 32 bytes"))
	job.StaticDifficulty = liveMinDifficulty

	wireJSON, err := json.Marshal(s.jobPayload(job))
	if err != nil {
		t.Fatalf("marshal XNP-proxy-shape JobPayload: %v", err)
	}
	t.Logf("leaf-direct live-shaped XNP-proxy job wire JSON: %s", wireJSON)

	decoder := json.NewDecoder(bytes.NewReader(wireJSON))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil {
		t.Fatalf("decode marshaled wire JSON: %v", err)
	}

	for _, key := range []string{"difficulty", "target_diff", "target_diff_hex"} {
		if _, present := wire[key]; !present {
			t.Fatalf("marshaled XNP-proxy job JSON is MISSING key %q -- this is the exact, confirmed cause of the reported 'job difficulty of 1' incident: %s", key, wireJSON)
		}
	}

	for _, key := range []string{"target_diff", "difficulty"} {
		num, ok := wire[key].(json.Number)
		if !ok {
			t.Fatalf("wire key %q is %T, want a JSON number (a JS client calls Number() on it directly)", key, wire[key])
		}
		got, err := num.Int64()
		if err != nil {
			t.Fatalf("wire key %q = %q, which does not decode as an integer: %v", key, num, err)
		}
		if got != liveMinDifficulty {
			t.Fatalf("wire key %q decodes to %d, want %d -- a downstream Number(json.%s) must NOT fall through to the hardcoded fallback of 1", key, got, liveMinDifficulty, key)
		}
	}

	poolDifficulty := normalizeDifficultyLikeMoneroOceanFork(wire["difficulty"], nil)
	if poolDifficulty != liveMinDifficulty {
		t.Fatalf("normalizeDifficulty(template.difficulty) = %d, want %d", poolDifficulty, liveMinDifficulty)
	}
	effective := normalizeDifficultyLikeMoneroOceanFork(wire["target_diff"], json.Number(strconv.FormatInt(poolDifficulty, 10)))
	if effective != liveMinDifficulty {
		t.Fatalf("normalizeDifficulty(template.target_diff, this.difficulty) = %d, want %d (1 would be the exact reported incident)", effective, liveMinDifficulty)
	}

	target, ok := wire["target"].(string)
	if !ok {
		t.Fatalf("wire key \"target\" is %T, want a string still present and unchanged for ordinary clients: %s", wire["target"], wireJSON)
	}
	targetDiffHex, ok := wire["target_diff_hex"].(string)
	if !ok {
		t.Fatalf("wire key \"target_diff_hex\" is %T, want a string", wire["target_diff_hex"])
	}
	if targetDiffHex != target {
		t.Fatalf("target_diff_hex = %q, want it byte-identical to target %q", targetDiffHex, target)
	}
	if want := leaflib.DiffToTargetHex(liveMinDifficulty); target != want {
		t.Fatalf("target = %q, want %q (leaflib.DiffToTargetHex(%d)) -- the existing Target field must be left completely unchanged by this fix", target, want, liveMinDifficulty)
	}
}

// normalizeDifficultyLikeMoneroOceanFork/jsNumber/max64 mirror solo's
// identical test-only helpers (protocol_xnp_test.go) -- a faithful Go
// port of the affected user's MoneroOcean/xmr-node-proxy fork's own
// coins/template.js helper, whose final `return 1` was the reported
// incident. Duplicated here rather than exported from solo, matching
// this file's existing convention of mirroring solo's small test
// helpers locally.
func normalizeDifficultyLikeMoneroOceanFork(value, fallback any) int64 {
	if v, ok := jsNumber(value); ok && v > 0 {
		return max64(1, v)
	}
	if v, ok := jsNumber(fallback); ok && v > 0 {
		return max64(1, v)
	}
	return 1
}

func jsNumber(value any) (int64, bool) {
	num, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := num.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return int64(math.Floor(f)), true
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
