// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// legacyJobPayload captures the EXACT JobPayload wire shape as it
// existed immediately BEFORE this XNP-proxy-detection fix (i.e.
// protocol.go's JobPayload with no BlocktemplateBlob/ReservedOffset/
// ClientNonceOffset/ClientPoolOffset fields at all — nor the later
// Difficulty/TargetDiff/TargetDiffHex difficulty half of the same
// shape) — used below as an independent, byte-for-byte non-regression
// oracle: for any non-proxy-detected session, marshaling the SAME real
// field values through this frozen pre-change shape and through the
// real (post-change) JobPayload must produce byte-identical JSON. If
// the fix ever leaked one of the seven new fields onto a non-proxy
// job's wire output, this comparison would fail (the real
// JobPayload's JSON would carry an extra key the legacy shape never
// could).
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
// fields onto legacyJobPayload, deliberately dropping the seven new
// pointer fields (four offset + three difficulty) — the point of the
// comparison is exactly that dropping them changes nothing for a
// non-proxy job.
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

// legacyJobPayloadWithDifficulty is legacyJobPayload PLUS only the
// three difficulty fields this pass added (difficulty/target_diff/
// target_diff_hex), in the same relative order the real JobPayload
// declares them. It exists for exactly one test —
// TestJobPayloadXNPReservationUnavailableRXM — whose property under
// test is that a ReservedOffsetUsable=false job omits the FOUR OFFSET
// fields from the wire even for a detected XNP-proxy agent. That test
// proves it the same way it always has (a real marshaled-JSON
// byte-diff against a projection that drops the fields in question),
// just with the difficulty half retained, because the difficulty half
// is deliberately NOT gated on the reserved-offset bounds check — see
// session.go's jobPayload and protocol.go's Difficulty doc comment: an
// XNP-proxy client whose template fails that bounds check still must
// not be told its difficulty is 1.
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

func asLegacyWithDifficulty(p JobPayload) legacyJobPayloadWithDifficulty {
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

// assertNoDifficultyKeysOnWire asserts that NONE of the three
// difficulty keys this pass added appears in payload's marshaled JSON
// — the required "absent from the wire, not merely nil in Go"
// assertion for every non-XNP-proxy session (see the task brief).
// Checked against the real decoded key set rather than by substring
// search, so it cannot be fooled by a key name appearing inside a hex
// blob value.
func assertNoDifficultyKeysOnWire(t *testing.T, payload JobPayload) {
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

// assertXNPDifficultyFields asserts the required post-fix invariants
// for an XNP-proxy-detected session's job payload: all three
// difficulty fields non-nil, Difficulty == TargetDiff ==
// job.StaticDifficulty, and TargetDiffHex byte-identical to the job's
// own Target field (legacy's `target_diff_hex: this.diffHex` is the
// SAME value its `target` would carry — see protocol.go's doc
// comment; not a different width/endianness encoding).
func assertXNPDifficultyFields(t *testing.T, got JobPayload, wantDifficulty uint64) {
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
// sufficient to exercise jobPayload in isolation (no real
// ManagedConnection/Server/net.Pipe harness needed — jobPayload itself
// only touches s.recordJob's own bookkeeping fields, s.xn, and
// s.Identity().Agent). agent mirrors what handleLogin already stores
// via s.identity.Store(...) at real login time.
func newXNPTestSession(agent string, xn string) *Session {
	s := &Session{jobs: leaflib.NewJobHistory[*Job](0)}
	s.xn.Store(xn)
	s.identity.Store(&leaflib.MinerIdentity{Agent: agent})
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
	assertNoDifficultyKeysOnWire(t, got)
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

	// DIFFICULTY HALF of the same real proxy-class job shape (the
	// "difficulty 1" incident fix): difficulty/target_diff/
	// target_diff_hex must all be present, with both numeric keys
	// carrying job.StaticDifficulty and target_diff_hex byte-identical
	// to target.
	assertXNPDifficultyFields(t, got, job.StaticDifficulty)

	t.Logf("RXM proxy-shape OK — reserved_offset=%d client_nonce_offset=%d (want %d) client_pool_offset=%d (want %d) blocktemplate_blob_len=%d difficulty=%d target_diff=%d target_diff_hex=%s",
		*got.ReservedOffset, *got.ClientNonceOffset, reservedOffset+12, *got.ClientPoolOffset, reservedOffset+8, len(*got.BlocktemplateBlob),
		*got.Difficulty, *got.TargetDiff, *got.TargetDiffHex)
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
	assertXNPDifficultyFields(t, got, job.StaticDifficulty)

	t.Logf("RXT proxy-shape OK — client_nonce_offset=%d (want %d), reserved_offset=nil, client_pool_offset=nil, blocktemplate_blob==blob (%d hex chars), difficulty=%d target_diff=%d target_diff_hex=%s",
		*got.ClientNonceOffset, rxtXmrigNonceOffset, len(*got.BlocktemplateBlob), *got.Difficulty, *got.TargetDiff, *got.TargetDiffHex)
}

// TestJobPayloadXNPCaseInsensitivity is the required
// case-INsensitivity test (renamed from
// TestJobPayloadXNPCaseSensitivity — case sensitivity was intentionally
// removed per product-owner direction, see IsXNPProxyAgent's doc
// comment in protocol.go): an agent containing "XMR-NODE-PROXY" (wrong
// case relative to the legacy JS reference) MUST now trigger proxy
// detection, exactly like the canonical lowercase substring.
func TestJobPayloadXNPCaseInsensitivity(t *testing.T) {
	if !IsXNPProxyAgent("XMR-NODE-PROXY/1.0.0") {
		t.Fatalf("IsXNPProxyAgent(%q) = false, want true — case must NOT matter (product-owner direction: broaden past the legacy case-sensitive JS .includes())", "XMR-NODE-PROXY/1.0.0")
	}
	if !IsXNPProxyAgent("xmr-node-proxy/1.0.0") {
		t.Fatalf("IsXNPProxyAgent(%q) = false, want true", "xmr-node-proxy/1.0.0")
	}
	if !IsXNPProxyAgent("some-wrapper/xmr-node-proxy/2.0.0") {
		t.Fatalf("IsXNPProxyAgent with the substring anywhere in the agent should still match")
	}

	s := newXNPTestSession("XMR-NODE-PROXY/1.0.0", "ab12")
	job := newXNPTestJobRXM(171, []byte("this is a fake raw monero blocktemplate_blob used only as a test fixture, deliberately longer than 32 bytes"))
	got := s.jobPayload(job)
	if got.BlocktemplateBlob == nil || got.ReservedOffset == nil || got.ClientNonceOffset == nil || got.ClientPoolOffset == nil {
		t.Fatalf("wrong-case (but now-matching) XNP agent must trigger the proxy shape, got: %+v", got)
	}
}

// TestIsXNPProxyAgentCaseInsensitiveTable is the required table-driven
// test proving IsXNPProxyAgent matches the "xmr-node-proxy" substring
// regardless of case, and still correctly rejects unrelated/empty
// agents.
func TestIsXNPProxyAgentCaseInsensitiveTable(t *testing.T) {
	cases := []struct {
		name  string
		agent string
		want  bool
	}{
		{name: "lowercase", agent: "xmr-node-proxy", want: true},
		{name: "uppercase", agent: "XMR-NODE-PROXY", want: true},
		{name: "mixed-case", agent: "Xmr-Node-Proxy", want: true},
		{
			name:  "full-agent-string-mixed-case-substring",
			agent: "SomeClient/XMR-Node-Proxy/1.2.3",
			want:  true,
		},
		{name: "unrelated-agent", agent: "XMRig/6.21.0", want: false},
		{name: "empty-string", agent: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsXNPProxyAgent(tc.agent); got != tc.want {
				t.Errorf("IsXNPProxyAgent(%q) = %v, want %v", tc.agent, got, tc.want)
			}
		})
	}
}

// TestJobPayloadXNPDifficultyAllMoneroFamilyAlgos covers the
// difficulty half of the XNP-proxy shape across EVERY algo the
// existing proxy-shape switch already handles as monerod-family
// (session.go's jobPayload: RXM/XMR/ARQ/XEQ/GRFT/SFX/ZEPH/SAL),
// paired with the matching non-proxy (ordinary agent) case on the
// SAME algo — proving both halves of the required behavior on all of
// them, not just RXM.
func TestJobPayloadXNPDifficultyAllMoneroFamilyAlgos(t *testing.T) {
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
			newJob := func() *Job {
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

			// And the ordinary client's own Target is identical either
			// way: this fix is strictly additive (see protocol.go's
			// "ADDITIONAL, not a replacement" convention).
			if proxyJob.Target != ordinaryJob.Target {
				t.Errorf("Target differs between proxy (%q) and ordinary (%q) sessions on the same job; the fix must be purely additive", proxyJob.Target, ordinaryJob.Target)
			}
		})
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
		t.Fatalf("ReservedOffsetUsable=false non-regression FAILED (a real byte-diff, not just struct fields):\n  before (legacy shape): %s\n  after  (actual JobPayload): %s", legacyJSON, gotJSON)
	}
	t.Logf("ReservedOffsetUsable=false degrades correctly, real byte-diff proof — before: %s\n                                                    after:  %s", legacyJSON, gotJSON)
}

// TestJobPayloadXNPTargetDiffLiveIncidentRXM is the real,
// live-shaped end-to-end regression test for the reported incident: a
// MoneroOcean-fork xmr-node-proxy (agent "xmr-node-proxy/0.0.3")
// logging into this leaf and "getting a job difficulty of 1". The job
// is built at 50000 — today's real production min-difficulty — and
// the assertion is made on the MARSHALED WIRE JSON, decoded the way a
// JavaScript client actually reads it (Number(json.target_diff)), NOT
// on the Go struct: the whole failure mode was that the key never
// reached the wire at all, so the fork's own
//
//	normalizeDifficulty(template.target_diff, this.difficulty)
//
// chain (see protocol.go's Difficulty doc comment for its verbatim
// source) received undefined twice and fell through to its final
// hardcoded `return 1`.
func TestJobPayloadXNPTargetDiffLiveIncidentRXM(t *testing.T) {
	const liveMinDifficulty = 50000
	const reservedOffset = 171

	s := newXNPTestSession("xmr-node-proxy/0.0.3", "ab12")
	job := newXNPTestJobRXM(reservedOffset, []byte("this is a fake raw monero blocktemplate_blob used only as a test fixture, deliberately longer than 32 bytes"))
	job.StaticDifficulty = liveMinDifficulty

	wireJSON, err := json.Marshal(s.jobPayload(job))
	if err != nil {
		t.Fatalf("marshal XNP-proxy-shape JobPayload: %v", err)
	}
	t.Logf("live-shaped XNP-proxy job wire JSON: %s", wireJSON)

	// Decode exactly as a JS client does: the raw key set off the
	// wire, with numbers left as json.Number so this test observes
	// what Number(json.target_diff) would observe, not a
	// Go-struct-typed re-read of our own field.
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

	// And the full fallback chain the affected fork actually runs,
	// reproduced in Go over the REAL decoded wire values: with both
	// keys present and positive, neither normalizeDifficulty call can
	// reach `return 1`.
	poolDifficulty := normalizeDifficultyLikeMoneroOceanFork(wire["difficulty"], nil)
	if poolDifficulty != liveMinDifficulty {
		t.Fatalf("normalizeDifficulty(template.difficulty) = %d, want %d", poolDifficulty, liveMinDifficulty)
	}
	effective := normalizeDifficultyLikeMoneroOceanFork(wire["target_diff"], json.Number(strconv.FormatInt(poolDifficulty, 10)))
	if effective != liveMinDifficulty {
		t.Fatalf("normalizeDifficulty(template.target_diff, this.difficulty) = %d, want %d (1 would be the exact reported incident)", effective, liveMinDifficulty)
	}
	if effective == 1 {
		t.Fatalf("the reported incident reproduced: an XNP-proxy client still resolves difficulty 1 from %s", wireJSON)
	}

	// target_diff_hex must be the SAME string the ordinary "target"
	// key carries, byte-for-byte (legacy: `target_diff_hex:
	// this.diffHex`) -- and "target" itself must still be present and
	// unchanged for ordinary xmrig-class consumers.
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
	if want := diffToTargetHex(liveMinDifficulty); target != want {
		t.Fatalf("target = %q, want %q (diffToTargetHex(%d)) -- the existing Target field must be left completely unchanged by this fix", target, want, liveMinDifficulty)
	}
}

// normalizeDifficultyLikeMoneroOceanFork is a faithful Go port of the
// affected user's MoneroOcean/xmr-node-proxy fork's own helper
// (coins/template.js), used above to prove the real client-side
// fallback chain no longer bottoms out at 1 against this leaf's real
// marshaled wire JSON:
//
//	function normalizeDifficulty(value, fallback = 1) {
//	    const numericValue = Number(value);
//	    if (Number.isFinite(numericValue) && numericValue > 0) return Math.max(1, Math.floor(numericValue));
//	    const fallbackValue = Number(fallback);
//	    if (Number.isFinite(fallbackValue) && fallbackValue > 0) return Math.max(1, Math.floor(fallbackValue));
//	    return 1;
//	}
//
// A nil argument models JS `undefined` (an absent JSON key), which is
// exactly what this leaf used to send.
func normalizeDifficultyLikeMoneroOceanFork(value, fallback any) int64 {
	if v, ok := jsNumber(value); ok && v > 0 {
		return max64(1, v)
	}
	if v, ok := jsNumber(fallback); ok && v > 0 {
		return max64(1, v)
	}
	return 1
}

// jsNumber models JS Number(x) + Number.isFinite(x) for the only two
// inputs that can reach it here: a decoded JSON number, or
// nil/undefined (an absent key).
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
