// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
)

// TestSession_RealPureGoRandomXValidator_BlockLevelFind_ForwardedUpstream
// is a real, non-mocked integration test: unlike every other test in
// this package (which uses fakeValidator to control PoW validity
// deterministically without paying real hashing cost), this test wires
// the actual internal/leaflib/validator.PureGoRandomXValidator -- the
// same type cmd/leaf-proxy/main.go constructs at real startup -- into a
// real Server/Session, computes the REAL RandomX hash of the exact
// bytes handleSubmit would hash (the worker-nonce-partitioned blob,
// under the job's real seed hash), and confirms:
//
//  1. A genuinely-correct RandomX proof that also meets the upstream
//     block target is ACCEPTED and forwarded upstream for real (through
//     the real validator's real ValidateBlobSeedResult call, not a
//     mock).
//  2. A wrong claimed result for the same job/nonce is REJECTED and
//     never forwarded upstream.
//
// This closes the exact gap fakeValidator-based tests leave open: they
// prove the accept/forward CONTROL FLOW is correct assuming Validate
// says yes/no, but never actually exercise a real validator's real
// hash computation end-to-end through Session.handleSubmit. This is
// slow (a real pure-Go RandomX hash is ~hundreds of ms) by design --
// see PureGoRandomXValidator's own doc comment.
//
// Read deadline note: this is the ONLY test in this package that
// exercises a real, non-mocked RandomX hash -- every other test uses
// the instant fakeValidator, which is why testClient.recvRaw()'s
// shared default read deadline is (and should stay) 5 seconds. That
// 5s default is not enough headroom here: this test computes a real
// RandomX hash TWICE (once directly in the test body above to build a
// genuinely-correct claimed result, and once again for real inside
// Session.handleSubmit's own async-dispatched ValidateBlobSeedResult
// call when the submit below is processed), and on CI's slower/shared
// -race runner that pushes wall-clock time for the submit round-trip
// over the 5s ceiling. This was confirmed against real CI logs: this
// test failed on every one of 7 consecutive recent CI runs with
// "read response: read pipe: i/o timeout" at ~10s wall-clock (i.e. it
// burned through two successive 5s reads before failing), while
// passing reliably locally in ~4s. Rather than widen the shared 5s
// default (which would mask genuine hangs/deadlocks in every other,
// fast, fakeValidator-based test in this package), the two submit
// round-trips below that must wait on a real RandomX validation use
// recvShareResponseWithTimeout with a generous, still-bounded 30s
// deadline instead.
func TestSession_RealPureGoRandomXValidator_BlockLevelFind_ForwardedUpstream(t *testing.T) {
	blob := fakeBlob(76, 50)
	seedHash := []byte("test-seed-hash-32-bytes-exactly!")
	const nonce = uint32(42)

	// Compute the REAL RandomX hash of the exact bytes handleSubmit
	// will hash, using the exact same validator type main.go
	// constructs at real startup -- no mocking of the hash itself.
	rxValidator := validator.NewPureGoRandomXValidator()

	tmpl := &WorkerTemplate{
		Blob:              blob,
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1, // this fake upstream never publishes client_pool_offset
		SeedHash:          seedHash,
		Height:            123,
		JobID:             "upstream-job-real-rx",
		// TargetDiff deliberately very low so the real hash above --
		// whatever its real difficulty happens to be -- genuinely
		// meets the upstream block target, exercising the real
		// "forward upstream" path rather than requiring us to also
		// grind for a real hash meeting some specific target.
		TargetDiff: 1,
		Difficulty: 1,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	upstream := &fakeUpstream{accept: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, rxValidator, upstream, log.New(nil2Writer{}, "", 0), leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	h := &harness{t: t, server: server, source: source, upstream: upstream, cancel: cancel}
	c, _ := h.connectAtDifficulty(1)
	loginResp := c.login(t, "addr-real-rx")

	// The job's OWN worker-nonce-partitioned blob (as actually issued
	// to this session -- decoded from the real hex the server sent),
	// NOT the raw template blob: WorkerTemplate.BlobForWorker writes
	// this job's worker nonce at ReservedOffset when ClientNonceOffset
	// is unset (see template.go's workerNonceOffset), so job.Blob is
	// NOT byte-identical to tmpl.Blob. Using the real issued blob here
	// (exactly what handleSubmit itself starts from) is what makes this
	// hash computation genuinely match the real path end-to-end.
	issuedBlob, err := hex.DecodeString(loginResp.Result.Job.Blob)
	if err != nil {
		t.Fatalf("decode issued job blob: %v", err)
	}
	fullBlob, err := writeMinerNonce(issuedBlob, nonce)
	if err != nil {
		t.Fatalf("writeMinerNonce: %v", err)
	}
	start := time.Now()
	realHash := rxValidator.Hash(seedHash, fullBlob)
	if time.Since(start) < 10*time.Millisecond {
		t.Fatalf("real RandomX hash computation returned suspiciously fast (%s) -- may have been short-circuited", time.Since(start))
	}
	realResultHex := hex.EncodeToString(realHash)

	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(nonce), Result: realResultHex})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	// This waits on a real, non-mocked RandomX validation round-trip
	// inside Session.handleSubmit -- use the longer, test-specific
	// deadline (see doc comment above), not the package's 5s default.
	resp := c.recvShareResponseWithTimeout(30 * time.Second)
	if resp.Result == nil {
		t.Fatalf("expected the real, correct RandomX proof to be accepted, got error=%v", resp.Error)
	}
	if upstream.callCount() != 1 {
		t.Fatalf("expected exactly one real upstream submit call for a genuine block-level find, got %d", upstream.callCount())
	}

	// Negative case: a WRONG claimed result for the exact same job/nonce
	// must be rejected by the real validator, not accepted.
	c2, _ := h.connectAtDifficulty(1)
	loginResp2 := c2.login(t, "addr-real-rx-wrong")
	wrongHex := hex.EncodeToString(make([]byte, 32)) // all-zero, definitely not the real hash
	submitParams2, err := json.Marshal(SubmitRequest{ID: loginResp2.Result.ID, JobID: loginResp2.Result.Job.JobID, Nonce: nonceHexAt(nonce + 1), Result: wrongHex})
	if err != nil {
		t.Fatalf("marshal submit params (wrong hash): %v", err)
	}
	c2.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams2})
	// Also a real, non-mocked RandomX validation round-trip -- same
	// longer deadline rationale as the positive case above.
	resp2 := c2.recvShareResponseWithTimeout(30 * time.Second)
	if resp2.Result != nil {
		t.Fatal("expected a wrong claimed RandomX result to be rejected by the real pure-Go validator, not accepted")
	}
	if upstream.callCount() != 1 {
		t.Fatalf("a rejected wrong-hash submit must never reach the upstream pool; call count changed to %d", upstream.callCount())
	}
}
