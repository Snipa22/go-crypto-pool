// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// gatedValidator is a ShareValidator whose ValidateBlobSeedResult
// blocks until release is closed, then returns (accept, nil) -- lets
// a test deterministically control exactly when a dispatched
// finishSubmit closure (session.go) is still "in flight" inside the
// async pool (queued or actively validating) vs. has genuinely
// reached its post-validation upstream-forward call, without racing
// against real RandomX/goroutine-scheduling timing.
type gatedValidator struct {
	release chan struct{}
	accept  bool
}

func (g *gatedValidator) ValidateBlobSeedResult(_ context.Context, _, _ []byte, _ string) (bool, error) {
	<-g.release
	return g.accept, nil
}

// TestHandleSubmit_GenerationAdvancesWhileQueued_ForwardSkipped is the
// required Fix 10 test (DISPATCH_BRIEF.md 2026-09-10): the
// PRE-dispatch CurrentGeneration() check (session.go's handleSubmit,
// before the async randomxPool.Submit call -- f2bfa0b's original
// fix) only catches a generation that had ALREADY advanced at the
// moment a submit was first read. This test proves the SEPARATE,
// deeper gap Fix 10 closes: if the upstream connection reconnects
// WHILE a candidate is still in flight inside the async pool (queued,
// or actively running real RandomX validation) -- i.e. AFTER the
// pre-dispatch check already passed -- the dispatched closure must
// re-check CurrentGeneration() again immediately before actually
// calling SubmitShare, and skip the forward (reject locally) if the
// generation has since advanced, rather than wasting a real
// round-trip against a dead/superseded upstream session.
//
// Mechanism: a gatedValidator blocks the dispatched closure's real
// validation call until this test explicitly releases it -- while
// blocked, the closure has ALREADY passed the pre-dispatch generation
// check (it wouldn't have been dispatched otherwise) but has NOT yet
// reached the post-validation SubmitShare call. Bumping the fake
// upstream's generation during that window, then releasing the
// validator, deterministically reproduces the exact TOCTOU gap Fix
// 10 closes.
func TestHandleSubmit_GenerationAdvancesWhileQueued_ForwardSkipped(t *testing.T) {
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
		Generation:        1,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	validator := &gatedValidator{release: make(chan struct{}), accept: true}
	upstream := &fakeUpstreamWithGeneration{}
	upstream.accept = true
	upstream.generation.Store(1)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, upstream, log.New(nil2Writer{}, "", 0), leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, 1000, "")
	t.Cleanup(func() { _ = clientConn.Close() })
	c := &testClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}

	loginResp := c.login(t, "addr-generation-race-while-queued")

	claimedHash := hashForDifficulty(2_000_000) // above the 1,000,000 upstream block target
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	// This submit passes handleSubmit's own synchronous, pre-dispatch
	// checks (including the pre-dispatch generation check -- the
	// upstream's generation is still 1, matching job.TemplateGeneration)
	// and gets dispatched onto the async pool, where it now blocks
	// inside gatedValidator.ValidateBlobSeedResult.
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})

	// While the dispatched closure sits blocked in validation (i.e.
	// genuinely "queued for validation" per the brief's own
	// wording), simulate a real reconnect completing: the upstream's
	// OWN live generation advances, exactly reproducing the race Fix
	// 10 closes.
	upstream.generation.Store(2)
	close(validator.release)

	resp := c.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected the forward to be skipped (rejected locally) once the generation advanced while queued, got accepted")
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatal("expected a non-empty rejection message explaining the generation staleness")
	}
	if got := upstream.callCount(); got != 0 {
		t.Fatalf("SubmitShare must NEVER be called once the generation advanced while this candidate was queued/validating -- expected 0 calls, got %d", got)
	}
}

// TestHandleSubmit_GenerationUnchangedWhileQueued_ForwardStillHappens
// is the non-regression complement: if the generation does NOT
// change while a candidate is queued/validating, the real upstream
// forward must still happen exactly as before this fix.
func TestHandleSubmit_GenerationUnchangedWhileQueued_ForwardStillHappens(t *testing.T) {
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
		Generation:        1,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	validator := &gatedValidator{release: make(chan struct{}), accept: true}
	upstream := &fakeUpstreamWithGeneration{}
	upstream.accept = true
	upstream.generation.Store(1)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, upstream, log.New(nil2Writer{}, "", 0), leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, 1000, "")
	t.Cleanup(func() { _ = clientConn.Close() })
	c := &testClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}

	loginResp := c.login(t, "addr-generation-unchanged-while-queued")

	claimedHash := hashForDifficulty(2_000_000)
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})

	// No generation change this time -- release immediately.
	close(validator.release)

	resp := c.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("expected the forward to still happen when the generation never changed, got error=%v", resp.Error)
	}
	if got := upstream.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 upstream submit call, got %d", got)
	}
}
