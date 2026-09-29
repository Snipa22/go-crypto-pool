// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// --- leaf-proxy's XNP-proxy-shape job payload ---------------------
//
// Parity coverage for the port of commit f5c9b6a (the "job difficulty
// of 1" incident fix) into leaf-proxy's OWN downstream-serving
// jobPayload, PLUS the explicit, deliberate NON-port of that shape's
// other half (the four reserved-region offset fields) -- see
// Session.jobPayload's own "RESERVED-OFFSET DECISION" doc comment for
// the full reasoning these tests pin.
//
// proxy.JobPayload is a type ALIAS for solo.JobPayload
// (protocol.go:23), so all seven of those fields have existed on this
// exact struct since f5c9b6a; the bug being fixed here is that
// leaf-proxy never POPULATED any of them, leaving a nested
// XNP-proxy-class downstream client to hit the identical
// fallback-to-difficulty-1 path.

// legacyProxyJobPayload captures the EXACT wire shape leaf-proxy's
// jobPayload produced BEFORE this pass -- i.e. only the fields it
// actually sets, with none of the seven XNP-proxy-shape pointer fields
// -- used below as an independent, byte-for-byte non-regression
// oracle. For any non-proxy-detected session, marshaling the SAME real
// field values through this frozen pre-change shape and through the
// real (post-change) JobPayload must produce byte-identical JSON. If
// this pass ever leaked one of the new keys onto an ordinary
// xmrig-class miner's job, this comparison would fail.
//
// Field order and JSON tags mirror solo.JobPayload's own first seven
// fields exactly so the marshaled key ORDER matches too, not just the
// key set.
type legacyProxyJobPayload struct {
	Algo     string `json:"algo"`
	Blob     string `json:"blob"`
	Height   uint64 `json:"height"`
	JobID    string `json:"job_id"`
	Target   string `json:"target"`
	XN       string `json:"xn,omitempty"`
	SeedHash string `json:"seed_hash,omitempty"`
}

func asLegacyProxy(p JobPayload) legacyProxyJobPayload {
	return legacyProxyJobPayload{
		Algo:     p.Algo,
		Blob:     p.Blob,
		Height:   p.Height,
		JobID:    p.JobID,
		Target:   p.Target,
		XN:       p.XN,
		SeedHash: p.SeedHash,
	}
}

// newProxyXNPTestSession builds a minimal, directly-constructed
// *Session sufficient to exercise jobPayload in isolation -- mirrors
// solo's and direct's own identical helpers (protocol_xnp_test.go /
// session_xnp_test.go). jobPayload itself only touches
// s.Identity().Agent/s.jobs/s.lastDelivered*, none of which need a
// real connection.
func newProxyXNPTestSession(agent string) *Session {
	s := &Session{
		jobs: leaflib.NewJobHistory[*Job](defaultProxySessionJobHistorySize),
	}
	s.identity.Store(&leaflib.MinerIdentity{Agent: agent})
	return s
}

// newProxyXNPTestJob builds a real leaf-proxy Job at a caller-chosen
// difficulty, shaped exactly as JobManager.NextJob produces one (a
// CONVERTED, fixed-size RandomX hashing blob -- see
// Session.jobPayload's RESERVED-OFFSET note, point 3).
func newProxyXNPTestJob(difficulty uint64) *Job {
	return &Job{
		ID:                 "proxy-xnp-test-job",
		Blob:               fakeBlob(76, 50),
		WorkerNonce:        7,
		PoolNonce:          9,
		UpstreamJobID:      "upstream-job-1",
		Route:              RoutePrimary,
		TemplateGeneration: 1,
		SeedHash:           []byte("test-seed-hash-32-bytes-exactly!"),
		Height:             123,
		StaticDifficulty:   difficulty,
		UpstreamShareDiff:  1_000_000,
		CreatedAt:          time.Now(),
	}
}

// assertProxyXNPDifficultyFields asserts the required post-fix
// invariants for an XNP-proxy-detected session's job payload -- mirrors
// solo's and direct's identically-named helper: all three difficulty
// fields non-nil, Difficulty == TargetDiff == job.StaticDifficulty,
// and TargetDiffHex byte-identical to Target (legacy's
// `target_diff_hex: this.diffHex` is the SAME value its `target`
// carries -- two wire key names, one encoding, NOT two different
// width/endianness encodings).
func assertProxyXNPDifficultyFields(t *testing.T, got JobPayload, wantDifficulty uint64) {
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

// assertNoProxyDifficultyKeysOnWire asserts that NONE of the three
// difficulty keys appears in payload's marshaled JSON -- the required
// "absent from the wire, not merely nil in Go" assertion for every
// non-XNP-proxy session. Checked against the real decoded key set
// rather than by substring search, so it cannot be fooled by a key
// name appearing inside a hex blob value.
func assertNoProxyDifficultyKeysOnWire(t *testing.T, payload JobPayload) {
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

// --- The difficulty half: PORTED ----------------------------------

// TestProxyJobPayloadXNPProxyShapeDifficultyFields is the core test
// for the ported half: an XNP-proxy-detected leaf-proxy session's job
// payload carries difficulty/target_diff/target_diff_hex, derived from
// this leaf's OWN job.StaticDifficulty and its OWN existing
// `Target: leaflib.DiffToTargetHex(job.StaticDifficulty)` line.
func TestProxyJobPayloadXNPProxyShapeDifficultyFields(t *testing.T) {
	const difficulty = 50_000

	s := newProxyXNPTestSession(xnpProxyDownstreamTestAgent)
	job := newProxyXNPTestJob(difficulty)
	got := s.jobPayload(job)

	assertProxyXNPDifficultyFields(t, got, job.StaticDifficulty)

	// And the values really are derived from this leaf's own existing
	// Target computation, not an independently-recomputed encoding.
	if want := leaflib.DiffToTargetHex(difficulty); got.Target != want {
		t.Errorf("Target = %q, want %q (leaflib.DiffToTargetHex(%d)) -- the existing Target field must be left completely unchanged", got.Target, want, difficulty)
	}
	t.Logf("leaf-proxy XNP-proxy-shape OK -- difficulty=%d target_diff=%d target_diff_hex=%s target=%s",
		*got.Difficulty, *got.TargetDiff, *got.TargetDiffHex, got.Target)
}

// TestProxyJobPayloadXNPDifficultyUsesStaticDifficultyNotUpstreamShareDiff
// pins a leaf-proxy-specific decision the other two leaf modes have no
// equivalent of: leaf-proxy's Job carries TWO difficulty values --
// StaticDifficulty (this session's own current vardiff share
// difficulty, what Target encodes and what this leaf actually grades
// submits against) and UpstreamShareDiff (the separate upstream-pool
// forwarding threshold). The client must be told the former; telling
// it the latter would report a difficulty this leaf does not grade it
// at.
func TestProxyJobPayloadXNPDifficultyUsesStaticDifficultyNotUpstreamShareDiff(t *testing.T) {
	const sessionDiff, upstreamShareDiff = uint64(50_000), uint64(1_000_000)

	s := newProxyXNPTestSession(xnpProxyDownstreamTestAgent)
	job := newProxyXNPTestJob(sessionDiff)
	job.UpstreamShareDiff = upstreamShareDiff

	got := s.jobPayload(job)
	assertProxyXNPDifficultyFields(t, got, sessionDiff)
	if *got.Difficulty == upstreamShareDiff {
		t.Fatalf("Difficulty = %d, the job's UpstreamShareDiff -- want this session's own StaticDifficulty %d, which is what Target encodes and what handleSubmit grades against", *got.Difficulty, sessionDiff)
	}
}

// TestProxyJobPayloadXNPNonRegressionOrdinaryAgent is the required
// byte-diff non-regression proof: an ordinary xmrig-class session's
// marshaled job JSON is byte-identical to the frozen pre-change shape
// -- all three new keys provably absent from the wire, not merely nil.
func TestProxyJobPayloadXNPNonRegressionOrdinaryAgent(t *testing.T) {
	for _, agent := range []string{
		"XMRig/6.21.0",
		"",
		// A near-miss substring that is genuinely not the real one,
		// AND does not contain "xmr-node-proxy" case-insensitively
		// either, so it correctly stays non-XNP.
		"xmr-node-proxie/0.0.3",
		// NOTE: "XMR-NODE-PROXY/0.0.3" (wrong-case XNP agent) is
		// deliberately NOT in this list -- solo.IsXNPProxyAgent is
		// now case-INsensitive (product-owner direction), so this
		// agent IS now directly matched by IsXNPProxyAgent and must
		// get the XNP proxy shape instead. See
		// TestProxyJobPayloadXNPWrongCaseAgentGetsProxyShape below,
		// which pins that exact, intended behavior.
	} {
		t.Run("agent="+agent, func(t *testing.T) {
			s := newProxyXNPTestSession(agent)
			got := s.jobPayload(newProxyXNPTestJob(50_000))

			assertNoProxyDifficultyKeysOnWire(t, got)

			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal actual JobPayload: %v", err)
			}
			legacyJSON, err := json.Marshal(asLegacyProxy(got))
			if err != nil {
				t.Fatalf("marshal legacy projection: %v", err)
			}
			if !bytes.Equal(gotJSON, legacyJSON) {
				t.Fatalf("non-proxy job JSON changed:\n pre-change shape: %s\n  post-change:     %s", legacyJSON, gotJSON)
			}
		})
	}
}

// TestProxyJobPayloadXNPWrongCaseAgentGetsProxyShape pins the NEW
// correct behavior at the exact boundary the case-insensitivity change
// moved for leaf-proxy: a downstream agent that near-misses the legacy
// JS reference's case-sensitive XNP literal is now matched DIRECTLY by
// solo.IsXNPProxyAgent (product-owner direction -- see that function's
// doc comment in protocol.go), and therefore gets the XNP proxy
// job-payload shape (difficulty/target_diff/target_diff_hex present),
// exactly like the canonical-case agent.
func TestProxyJobPayloadXNPWrongCaseAgentGetsProxyShape(t *testing.T) {
	const agent = "XMR-NODE-PROXY/0.0.3"
	if !solo.IsXNPProxyAgent(agent) {
		t.Fatalf("solo.IsXNPProxyAgent(%q) = false, want true -- this predicate is now case-INsensitive per product-owner direction", agent)
	}

	s := newProxyXNPTestSession(agent)
	job := newProxyXNPTestJob(50_000)
	got := s.jobPayload(job)

	assertProxyXNPDifficultyFields(t, got, job.StaticDifficulty)
}

// TestProxyJobPayloadXNPAdditiveOnly proves the fix is strictly
// additive: for the SAME job, a proxy session and an ordinary session
// receive the identical Target (and identical blob/height/seed_hash),
// differing ONLY by the three added keys.
func TestProxyJobPayloadXNPAdditiveOnly(t *testing.T) {
	const difficulty = 50_000

	proxyPayload := newProxyXNPTestSession(xnpProxyDownstreamTestAgent).jobPayload(newProxyXNPTestJob(difficulty))
	ordinaryPayload := newProxyXNPTestSession("XMRig/6.21.0").jobPayload(newProxyXNPTestJob(difficulty))

	if proxyPayload.Target != ordinaryPayload.Target {
		t.Errorf("Target differs between proxy (%q) and ordinary (%q) sessions on the same job; the fix must be purely additive", proxyPayload.Target, ordinaryPayload.Target)
	}
	if asLegacyProxy(proxyPayload) != asLegacyProxy(ordinaryPayload) {
		t.Errorf("the pre-existing wire fields differ between a proxy and an ordinary session on the same job:\n proxy:    %+v\n ordinary: %+v", asLegacyProxy(proxyPayload), asLegacyProxy(ordinaryPayload))
	}
}

// TestProxyJobPayloadXNPTargetDiffLiveIncident is the live-shaped
// end-to-end regression test for the real reported incident, asserted
// on the MARSHALED WIRE JSON decoded the way a JavaScript client reads
// it -- at 50000, today's real production min-difficulty. The whole
// failure mode was that the key never reached the wire at all, so the
// affected MoneroOcean xmr-node-proxy fork's
//
//	normalizeDifficulty(template.target_diff, this.difficulty)
//
// chain received undefined twice and fell through to its final
// hardcoded `return 1`. Mirrors solo's and direct's identical tests,
// through leaf-proxy's own jobPayload.
func TestProxyJobPayloadXNPTargetDiffLiveIncident(t *testing.T) {
	const liveMinDifficulty = 50_000

	s := newProxyXNPTestSession(xnpProxyDownstreamTestAgent)
	wireJSON, err := json.Marshal(s.jobPayload(newProxyXNPTestJob(liveMinDifficulty)))
	if err != nil {
		t.Fatalf("marshal XNP-proxy-shape JobPayload: %v", err)
	}
	t.Logf("leaf-proxy live-shaped XNP-proxy job wire JSON: %s", wireJSON)

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

	// The full fallback chain the affected fork actually runs,
	// reproduced over the REAL decoded wire values.
	poolDifficulty := normalizeDifficultyLikeMoneroOceanForkProxy(wire["difficulty"], nil)
	if poolDifficulty != liveMinDifficulty {
		t.Fatalf("normalizeDifficulty(template.difficulty) = %d, want %d", poolDifficulty, liveMinDifficulty)
	}
	effective := normalizeDifficultyLikeMoneroOceanForkProxy(wire["target_diff"], json.Number(strconv.FormatInt(poolDifficulty, 10)))
	if effective == 1 {
		t.Fatalf("the reported incident reproduced: an XNP-proxy client still resolves difficulty 1 from %s", wireJSON)
	}
	if effective != liveMinDifficulty {
		t.Fatalf("normalizeDifficulty(template.target_diff, this.difficulty) = %d, want %d", effective, liveMinDifficulty)
	}

	// "target" itself must still be present and unchanged for
	// ordinary clients, and target_diff_hex byte-identical to it.
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
		t.Fatalf("target = %q, want %q (leaflib.DiffToTargetHex(%d))", target, want, liveMinDifficulty)
	}
}

// TestProxyJobPayloadXNPDifficultyReachesTheRealWireOnLoginAndPush is
// the end-to-end half: the three keys must reach a real downstream
// client through the REAL handleLogin/pushJob path, not just through a
// directly-constructed Session. This is what proves s.agent is
// actually populated by handleLogin (before this pass leaf-proxy
// dropped the downstream agent string entirely, so no
// solo.IsXNPProxyAgent gate could ever have fired here).
func TestProxyJobPayloadXNPDifficultyReachesTheRealWireOnLoginAndPush(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}, 0)
	h.source.setTemplate(poolTemplateWithTargetDiff(1_000_000))

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress+"+50000", "rig1", "", xnpProxyDownstreamTestAgent)
	if resp.Result.Status != "OK" {
		t.Fatalf("XNP-proxy login was rejected: %#v", resp)
	}

	// The job delivered in the LOGIN RESPONSE already carries them,
	// at the requested starting difficulty.
	assertProxyXNPDifficultyFields(t, resp.Result.Job, 50_000)

	sess := h.onlySession()
	if got := sess.Identity().Agent; got != xnpProxyDownstreamTestAgent {
		t.Fatalf("session agent = %q, want %q -- handleLogin must store the downstream agent string for the XNP gate to work at all", got, xnpProxyDownstreamTestAgent)
	}

	// And so does a genuine vardiff-pushed job afterward, at the new
	// retargeted difficulty. BRIEF.md "proxy-aware vardiff target
	// time" forces this XNP-agent-detected session's target time to
	// proxyForcedTargetTimeSeconds (10), unconditionally overriding
	// the harness's configured cfg.TargetTime (30):
	// (600000/90)*10 = 66660, which does not hit the 1.5x step
	// clamp (50000*1.5 = 75000) at all.
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	push := c.recvJobPush()
	<-done

	assertProxyXNPDifficultyFields(t, push.Params, 66_660)
}

// TestProxyJobPayloadXNPOrdinaryMinerWireIsUnchangedEndToEnd is the
// end-to-end counterpart: an ordinary xmrig-class miner's real login
// job, off the real wire, must carry none of the three keys.
func TestProxyJobPayloadXNPOrdinaryMinerWireIsUnchangedEndToEnd(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	c, _ := h.connectAtDifficulty(1000)
	resp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("ordinary login was rejected: %#v", resp)
	}
	assertNoProxyDifficultyKeysOnWire(t, resp.Result.Job)
}

// --- The reserved-offset half: DELIBERATELY NOT PORTED ------------

// TestProxyJobPayloadReservedOffsetFieldsAreAbsentByDesign is the
// required proof of this pass's explicit reserved-offset DECISION: the
// four reserved-region fields leaf-direct's/leaf-solo's XNP-proxy shape
// surfaces (blocktemplate_blob/reserved_offset/client_nonce_offset/
// client_pool_offset) are NOT emitted by leaf-proxy, for ANY session,
// including a fully XNP-proxy-detected one -- and that is correct by
// design, not an oversight.
//
// The reasoning, with citations, is stated in full on
// Session.jobPayload's own "RESERVED-OFFSET DECISION" doc comment.
// Summarized, all from this package's real code:
//
//  1. leaf-proxy ALREADY partitions worker-nonce and pool-nonce
//     itself, centrally, per issued job, baking both into Job.Blob
//     before it is ever sent (JobManager.NextJob ->
//     WorkerTemplate.NextBlobForWorkerAndPool, job.go). A reserved
//     region exists for a downstream client to partition FOR ITSELF;
//     there is nothing left here for it to partition.
//  2. proxy.Job has no ReservedOffset and no raw-template field of any
//     kind (contrast solo.Job, which carries RawTemplateBlob precisely
//     so its client can do reserved-region work). The offsets exist in
//     this package only on WorkerTemplate, as internal inputs to (1).
//  3. The blob sent downstream is the CONVERTED, fixed-size RandomX
//     hashing blob, not a raw blocktemplate_blob -- so a
//     reserved_offset would be an out-of-bounds index against it. Not
//     speculative: NextJob's own doc comment cites the real live
//     failure, "worker-nonce offset is out of range for this
//     template's blob: offset=179 blob_len=76".
//  4. Emitting them would be actively HARMFUL. handleSubmit forwards
//     job.WorkerNonce/job.PoolNonce -- THIS leaf's own centrally
//     allocated pair -- upstream, ignoring whatever a downstream
//     client claims. A client that partitioned its own sub-miners
//     inside an advertised reserved region would hash against nonces
//     that disagree with what this leaf reports upstream, so genuinely
//     valid shares would be rejected by the pool.
//
// Points 1, 2 and 4 are additionally asserted as live invariants below,
// so this decision cannot silently rot if the architecture changes.
func TestProxyJobPayloadReservedOffsetFieldsAreAbsentByDesign(t *testing.T) {
	const difficulty = 50_000

	s := newProxyXNPTestSession(xnpProxyDownstreamTestAgent)
	job := newProxyXNPTestJob(difficulty)
	got := s.jobPayload(job)

	// The four offset fields: nil in Go...
	if got.BlocktemplateBlob != nil || got.ReservedOffset != nil || got.ClientNonceOffset != nil || got.ClientPoolOffset != nil {
		t.Fatalf("leaf-proxy must not emit the reserved-region XNP fields -- want all four nil, got blocktemplate_blob=%v reserved_offset=%v client_nonce_offset=%v client_pool_offset=%v",
			got.BlocktemplateBlob, got.ReservedOffset, got.ClientNonceOffset, got.ClientPoolOffset)
	}

	// ...and provably absent from the real marshaled wire JSON, which
	// is what a nested client actually reads.
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal JobPayload: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal marshaled JobPayload into a key map: %v", err)
	}
	for _, key := range []string{"blocktemplate_blob", "reserved_offset", "client_nonce_offset", "client_pool_offset"} {
		if _, present := keys[key]; present {
			t.Errorf("marshaled XNP-proxy job JSON carries key %q, want it absent by design (see Session.jobPayload's RESERVED-OFFSET DECISION): %s", key, raw)
		}
	}

	// A byte-diff proof that the ONLY difference from the pre-change
	// shape is the three difficulty keys -- i.e. this pass added
	// exactly those and nothing else, even for a proxy session.
	legacyJSON, err := json.Marshal(asLegacyProxy(got))
	if err != nil {
		t.Fatalf("marshal legacy projection: %v", err)
	}
	withDifficulty, err := json.Marshal(struct {
		legacyProxyJobPayload
		Difficulty    *uint64 `json:"difficulty,omitempty"`
		TargetDiff    *uint64 `json:"target_diff,omitempty"`
		TargetDiffHex *string `json:"target_diff_hex,omitempty"`
	}{asLegacyProxy(got), got.Difficulty, got.TargetDiff, got.TargetDiffHex})
	if err != nil {
		t.Fatalf("marshal legacy+difficulty projection: %v", err)
	}
	if !bytes.Equal(raw, withDifficulty) {
		t.Fatalf("an XNP-proxy job's wire JSON carries MORE than the pre-change shape plus the three difficulty keys:\n want: %s\n got:  %s", withDifficulty, raw)
	}
	t.Logf("leaf-proxy XNP-proxy job shape, real byte-diff proof --\n  pre-change:           %s\n  post-change (actual): %s", legacyJSON, raw)

	// INVARIANT behind decision point 2: proxy.Job genuinely has no
	// reserved-offset/raw-template field for jobPayload to even read.
	// Asserted structurally so this cannot silently rot: if someone
	// later adds one, the reasoning above must be revisited.
	assertProxyJobHasNoReservedRegionField(t)
}

// assertProxyJobHasNoReservedRegionField pins decision point 2 as a
// live, structural invariant: proxy.Job must carry no reserved-region
// or raw-template field. If one is ever added, leaf-proxy's downstream
// architecture has changed and the reserved-offset decision documented
// on Session.jobPayload must be re-evaluated rather than left stale.
// Checked by reflection over the real struct so it cannot go stale
// silently.
func assertProxyJobHasNoReservedRegionField(t *testing.T) {
	t.Helper()

	jobType := reflect.TypeOf(Job{})
	have := make(map[string]bool, jobType.NumField())
	names := make([]string, 0, jobType.NumField())
	for i := 0; i < jobType.NumField(); i++ {
		name := jobType.Field(i).Name
		have[name] = true
		names = append(names, name)
	}

	// The reasoning was built on the ABSENCE of these.
	for _, forbidden := range []string{"ReservedOffset", "RawTemplateBlob", "ClientNonceOffset", "ClientPoolOffset", "BlocktemplateBlob"} {
		if have[forbidden] {
			t.Fatalf("proxy.Job now has a %q field. leaf-proxy's reserved-offset DECISION (see Session.jobPayload's RESERVED-OFFSET doc comment) was reasoned on its ABSENCE -- re-evaluate that decision rather than leaving this test passing vacuously. Job fields: %v", forbidden, names)
		}
	}

	// Positive control: the fields the reasoning DEPENDS on existing
	// must actually exist -- leaf-proxy's own central per-job
	// worker-/pool-nonce partitioning, baked into Blob.
	for _, required := range []string{"WorkerNonce", "PoolNonce", "Blob"} {
		if !have[required] {
			t.Fatalf("proxy.Job no longer has a %q field -- leaf-proxy's central per-job nonce partitioning (the whole basis of the reserved-offset decision) has changed. Job fields: %v", required, names)
		}
	}
}

// TestProxyHandleSubmitIgnoresDownstreamClaimedNonces pins decision
// point 4 -- the reason emitting a reserved region would be actively
// HARMFUL rather than merely useless, not just a documentation claim.
//
// A nested XNP-proxy client handed a reserved region partitions its own
// sub-miners inside it and reports the workerNonce/poolNonce it chose
// on submit (the downstream SubmitRequest wire type carries exactly
// those fields). leaf-proxy's handleSubmit ignores them completely and
// forwards job.WorkerNonce/job.PoolNonce -- THIS leaf's own centrally
// allocated pair, the only pair actually baked into the blob it issued
// -- so such a client's genuinely-valid shares would be rejected
// upstream for describing nonces nobody hashed.
//
// Asserted against the REAL upstream forward: the fake upstream records
// what it was handed, and it must be the job's values, never the
// client's claimed ones.
func TestProxyHandleSubmitIgnoresDownstreamClaimedNonces(t *testing.T) {
	// Pointer-typed on the wire (solo.SubmitRequest.WorkerNonce/
	// PoolNonce are *uint32) -- addressable locals are needed.
	claimedWorkerNonceVal, claimedPoolNonceVal := uint32(4242), uint32(9999)
	const claimedWorkerNonce, claimedPoolNonce = uint32(4242), uint32(9999)

	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.loginWithFields(t, realProxyTestXMRAddress, "rig1", "", xnpProxyDownstreamTestAgent)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login rejected: %#v", loginResp)
	}

	sess := h.onlySession()
	job, ok := sess.ownJob(loginResp.Result.Job.JobID)
	if !ok {
		t.Fatalf("could not find the issued job %q in the session's own history", loginResp.Result.Job.JobID)
	}
	if job.WorkerNonce == claimedWorkerNonce || job.PoolNonce == claimedPoolNonce {
		t.Fatalf("test fixture collision: the job's own nonces (%d/%d) must differ from the client's claimed ones (%d/%d) for this assertion to mean anything",
			job.WorkerNonce, job.PoolNonce, claimedWorkerNonce, claimedPoolNonce)
	}

	// Decision point 3's premise, asserted on the real issued job: the
	// blob sent downstream is the CONVERTED, fixed-size RandomX
	// hashing blob, which has no reserved coinbase region at all.
	if len(job.Blob) != 76 {
		t.Fatalf("issued job blob length = %d, want the converted fixed-size RandomX hashing blob (76) -- a reserved_offset would be an out-of-bounds index against it", len(job.Blob))
	}

	// A genuine block-level find (above the template's 1,000,000
	// UpstreamShareDiff) so the submit really is forwarded upstream,
	// carrying DELIBERATELY WRONG client-claimed nonces.
	submitParams, err := json.Marshal(SubmitRequest{
		ID:          loginResp.Result.ID,
		JobID:       loginResp.Result.Job.JobID,
		Nonce:       nonceHexAt(3),
		Result:      hashForDifficulty(2_000_000),
		WorkerNonce: &claimedWorkerNonceVal,
		PoolNonce:   &claimedPoolNonceVal,
	})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	if resp := c.recvShareResponse(); resp.Result == nil {
		t.Fatalf("expected the block-level find to be accepted, got error=%v", resp.Error)
	}

	if h.upstream.callCount() != 1 {
		t.Fatalf("expected exactly one upstream submit, got %d", h.upstream.callCount())
	}
	gotWorker, gotPool := h.upstream.lastNonces()
	if gotWorker != job.WorkerNonce || gotPool != job.PoolNonce {
		t.Fatalf("upstream received workerNonce=%d poolNonce=%d, want the JOB's own %d/%d", gotWorker, gotPool, job.WorkerNonce, job.PoolNonce)
	}
	if gotWorker == claimedWorkerNonce || gotPool == claimedPoolNonce {
		t.Fatalf("leaf-proxy forwarded a DOWNSTREAM-CLAIMED nonce upstream (workerNonce=%d poolNonce=%d) -- if that were the behavior, advertising a reserved region might be coherent; it is not, which is exactly why those fields must stay absent", gotWorker, gotPool)
	}
}

// --- test-only helpers --------------------------------------------

// normalizeDifficultyLikeMoneroOceanForkProxy is a faithful Go port of
// the affected user's MoneroOcean/xmr-node-proxy fork's own helper
// (coins/template.js), whose final `return 1` was the reported
// incident:
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
// exactly what leaf-proxy used to send. Duplicated here rather than
// exported from solo, matching this repo's existing convention of
// mirroring solo's small test helpers locally (direct's own
// session_xnp_test.go does the same).
func normalizeDifficultyLikeMoneroOceanForkProxy(value, fallback any) int64 {
	if v, ok := jsNumberProxy(value); ok && v > 0 {
		return maxInt64Proxy(1, v)
	}
	if v, ok := jsNumberProxy(fallback); ok && v > 0 {
		return maxInt64Proxy(1, v)
	}
	return 1
}

func jsNumberProxy(value any) (int64, bool) {
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

func maxInt64Proxy(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// compile-time assertion that proxy.JobPayload really is
// solo.JobPayload (protocol.go's alias) -- the premise for this whole
// file: the seven XNP-proxy-shape fields already existed here and were
// simply never populated.
var _ solo.JobPayload = JobPayload{}
