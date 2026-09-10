// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/hex"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestDirectSessionRXTBelowStaticDifficultyFloorIsRejected is
// DISPATCH_BRIEF.md's (2026-09-10, Fix 1 [CRITICAL — Finding 1])
// direct regression guard for leaf-direct's own difficulty floor:
// Alex's exact framing is "as long as the difficulty of the hash is
// OVER the difficulty of the job, it's fine, because we send the job
// diff back upstream" -- a REAL, validated share whose derived
// difficulty is below this job's own StaticDifficulty must be
// rejected/not-forwarded, never credited at StaticDifficulty weight.
//
// Uses fakeDelayedDirectRandomXValidator (delay=0, always returns
// valid=true) so the real, daemon-backed hash-EQUALITY check is
// deterministically bypassed -- this test is specifically about the
// floor check that runs AFTER validation succeeds, not about
// validation itself (see session_async_randomx_test.go's identical
// fake for the concurrency-focused tests that established this
// pattern first).
func TestDirectSessionRXTBelowStaticDifficultyFloorIsRejected(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1000), uint64(1) << 62
	h, tr := newDirectHardeningTestHarness(t, staticDiff, networkTargetDiff, &fakeDelayedDirectRandomXValidator{})

	_, xn := directLogin(t, h, realTariTestAddress("addr-rxt-floor-below"))
	jobID := directCurrentJobIDForXN(t, h, xn)

	nonce := make([]byte, 4)
	nonce[0] = 0xaa
	h.send(solo.Request{ID: 50, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID, Nonce: hex.EncodeToString(nonce),
		Result: hex.EncodeToString(directLargeResultHash(0)), // derived difficulty ~= 1, well below staticDiff=1000
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatalf("expected a below-static-difficulty-floor RXT claim to be rejected, got accepted: %#v", resp)
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatal("expected a clear rejection error for a below-floor claim")
	}
	if tr.shareCount() != 0 {
		t.Errorf("forwardShare must never be called for a below-floor claim, got %d calls", tr.shareCount())
	}
}

// TestDirectSessionRXTAtStaticDifficultyFloorIsAccepted is this fix's
// own sanity control -- mirrors solo's identical control test exactly
// (see internal/leaflib/solo/hardening_test.go): a claim whose real
// derived difficulty exactly meets this job's own StaticDifficulty
// must still be credited and forwarded normally.
func TestDirectSessionRXTAtStaticDifficultyFloorIsAccepted(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	h, tr := newDirectHardeningTestHarness(t, staticDiff, networkTargetDiff, &fakeDelayedDirectRandomXValidator{})

	_, xn := directLogin(t, h, realTariTestAddress("addr-rxt-floor-at"))
	jobID := directCurrentJobIDForXN(t, h, xn)

	nonce := make([]byte, 4)
	nonce[0] = 0xbb
	h.send(solo.Request{ID: 51, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID, Nonce: hex.EncodeToString(nonce),
		Result: hex.EncodeToString(directLargeResultHash(0)), // derived difficulty == 1 == staticDiff
	})})
	resp := h.recvShareResponse()

	if resp.Error != nil {
		t.Fatalf("expected a claim exactly meeting the static difficulty floor to be accepted, got error: %v", resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatal("expected a claim exactly meeting the static difficulty floor to be accepted")
	}
	if tr.shareCount() != 1 {
		t.Errorf("forwardShare should have been called exactly once, got %d calls", tr.shareCount())
	}
}

// TestDirectSessionRXTRepeatedFabricatedClaimsGetDisconnected is the
// real, end-to-end proof (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b
// [HIGH — Finding 2]) that leaf-direct disconnects a session that
// repeatedly submits claims failing REAL validation, exactly
// mirroring solo's own identical proof
// (TestSessionRXTRepeatedFabricatedBlockFindClaimsGetDisconnected) --
// unlike solo, leaf-direct dispatches EVERY RXT/RXM submit through
// s.server.randomxPool (not just genuine block-find candidates), so
// this is an even more directly-hit call site for the same DoS vector.
func TestDirectSessionRXTRepeatedFabricatedClaimsGetDisconnected(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	const threshold = 3

	// Always fails real validation.
	fakeValidator := &fakeDelayedDirectRandomXValidator{alwaysReject: true}
	h, _ := newDirectHardeningTestHarnessWithGuard(t, staticDiff, networkTargetDiff, fakeValidator,
		leaflib.InvalidShareGuardConfig{Enabled: true, Threshold: threshold})

	_, xn := directLogin(t, h, realTariTestAddress("addr-rxt-dos"))
	jobID := directCurrentJobIDForXN(t, h, xn)

	for i := 0; i < threshold; i++ {
		nonce := make([]byte, 4)
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		h.send(solo.Request{ID: i + 200, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(directLargeResultHash(i)),
		})})
		resp := h.recvShareResponse()
		if resp.Result != nil {
			t.Fatalf("attempt %d: expected fabricated claim to be rejected, got accepted: %#v", i, resp)
		}
	}

	_ = h.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if n, err := h.client.Read(buf); err == nil {
		t.Fatalf("expected the connection to be closed after %d consecutive invalid shares, but Read succeeded (n=%d)", threshold, n)
	}
}

// newDirectHardeningTestHarness builds a *directTestHarness wired to
// v (an already-constructed validator.AlgoValidator, typically a
// fake) -- mirrors session_async_randomx_test.go's own inline
// harness construction (needed here, rather than reusing
// newDirectRXTTestHarness, because that helper always constructs a
// REAL, network-backed validator.RandomXValidator, and this file's
// tests specifically need deterministic control over the
// validation outcome).
func newDirectHardeningTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64, v validator.AlgoValidator) (*directTestHarness, *fakeShareTransport) {
	t.Helper()
	return newDirectHardeningTestHarnessWithGuard(t, staticDiff, networkTargetDiff, v, leaflib.InvalidShareGuardConfig{})
}

// newDirectHardeningTestHarnessWithGuard is
// newDirectHardeningTestHarness's variant that also overrides the
// Server's invalidShareGuardConfig BEFORE Server.handleConn's
// goroutine starts -- required (exactly like
// trust_integration_test.go's own EnableTrust-before-handleConn
// requirement, and for the identical reason: go test -race correctly
// flags a real data race otherwise) for tests that need a non-default
// InvalidShareGuardConfig. A zero-value guardCfg (Enabled: false)
// leaves the guard disabled, matching newDirectHardeningTestHarness's
// own behavior exactly (it delegates here with a zero-value guardCfg).
func newDirectHardeningTestHarnessWithGuard(t *testing.T, staticDiff, networkTargetDiff uint64, v validator.AlgoValidator, guardCfg leaflib.InvalidShareGuardConfig) (*directTestHarness, *fakeShareTransport) {
	t.Helper()
	node := &fakeDirectNodeClient{
		height:          42,
		mergeMiningHash: []byte("direct-test-merge-mining-hash-3"),
		vmKey:           []byte("test key 000"),
	}
	node.targetDifficulty = networkTargetDiff
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXT,
	})
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: v}
	tr := &fakeShareTransport{}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET, Transport: tr, MultiSubmit: multi,
		Algo: poolpb.Algo_ALGO_RXT, PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
	})
	t.Cleanup(func() {
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
	})
	if guardCfg.Enabled {
		server.SetInvalidShareGuardConfig(guardCfg)
	}

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr, submit: sub,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	return h, tr
}
