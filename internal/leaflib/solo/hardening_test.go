// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestSessionRXTOrdinaryShareBelowStaticDifficultyFloorIsRejected is
// DISPATCH_BRIEF.md's (2026-09-10, Fix 1 [CRITICAL — Finding 1])
// direct regression guard for solo's own ordinary-share (sub-block)
// RXT/RXM difficulty floor: Alex's exact framing is "as long as the
// difficulty of the hash is OVER the difficulty of the job, it's
// fine, because we send the job diff back upstream" -- i.e. a
// claimed difficulty BELOW this job's own StaticDifficulty must be
// rejected outright, not credited as a full StaticDifficulty-weighted
// accepted share.
//
// staticDiff is set well above largeResultHash's own derived
// difficulty (~1 -- see that helper's doc comment in
// session_async_randomx_test.go) so this exercises the floor
// specifically, while networkTargetDiff stays enormous so this
// submit still takes the cheap ORDINARY-share code path (no real
// validator call, no async dispatch -- this floor check must reject
// it WITHOUT ever needing a reachable randomx-service daemon, which
// is why newRXTTestHarness is pointed at an unreachable address
// here: a submit that reached the validator despite being an
// ordinary sub-block claim would be a test-harness bug, not
// something this test should tolerate).
func TestSessionRXTOrdinaryShareBelowStaticDifficultyFloorIsRejected(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1000), uint64(1) << 62
	h := newRXTTestHarness(t, staticDiff, networkTargetDiff, "http://127.0.0.1:1") // deliberately unreachable
	sessionID, xn := login(t, h, "addr-rxt-floor-below")
	jobID := currentJobIDForXN(t, h, xn)

	h.send(Request{ID: 40, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  xnPrefixedNonceHex(xn, 0xaaaaaaaa),
		Result: hex.EncodeToString(largeResultHash(0)), // derived difficulty ~= 1, well below staticDiff=1000
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatalf("expected a below-static-difficulty-floor RXT claim to be rejected, got accepted: %#v", resp)
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatal("expected a clear rejection error for a below-floor claim")
	}

	stats := h.server.Stats()
	if stats.TotalShares != 0 {
		t.Errorf("TotalShares = %d, want 0: a below-floor claim must never be credited", stats.TotalShares)
	}
}

// TestSessionRXTOrdinaryShareAtStaticDifficultyFloorIsAccepted is
// this fix's own sanity control: a claimed difficulty that DOES meet
// (here, exactly equals) this job's own StaticDifficulty must still
// be credited normally -- proving Fix 1's floor check is a genuine
// `>=` floor, not an overly-aggressive rejection that breaks ordinary
// legitimate shares.
func TestSessionRXTOrdinaryShareAtStaticDifficultyFloorIsAccepted(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	h := newRXTTestHarness(t, staticDiff, networkTargetDiff, "http://127.0.0.1:1") // deliberately unreachable
	sessionID, xn := login(t, h, "addr-rxt-floor-at")
	jobID := currentJobIDForXN(t, h, xn)

	h.send(Request{ID: 41, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  xnPrefixedNonceHex(xn, 0xbbbbbbbb),
		Result: hex.EncodeToString(largeResultHash(0)), // derived difficulty == 1 == staticDiff
	})})
	resp := h.recvShareResponse()

	if resp.Error != nil {
		t.Fatalf("expected a claim exactly meeting the static difficulty floor to be accepted, got error: %v", resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatal("expected a claim exactly meeting the static difficulty floor to be accepted")
	}

	stats := h.server.Stats()
	if stats.TotalShares != 1 {
		t.Errorf("TotalShares = %d, want 1", stats.TotalShares)
	}
}

// TestInvalidShareGuardDisconnectsAfterConsecutiveFailures is
// DISPATCH_BRIEF.md's (2026-09-10, Fix 2b [HIGH — Finding 2]) direct
// regression guard for the consecutive-invalid-share disconnect
// mechanism, tested at the leaflib.InvalidShareGuard unit level (the
// shared, package-agnostic implementation solo/direct/proxy all
// wire in identically) -- see session_hardening_test.go's own
// TestSessionRXTRepeatedFabricatedBlockFindClaimsGetDisconnected for
// the full, real end-to-end proof through solo's actual Session/
// finishSubmit call site using a fake, always-failing validator.
func TestInvalidShareGuardDisconnectsAfterConsecutiveFailures(t *testing.T) {
	g := leaflib.NewInvalidShareGuard(leaflib.InvalidShareGuardConfig{Enabled: true, Threshold: 3})

	for i := 0; i < 2; i++ {
		if disconnect := g.RecordOutcome(false); disconnect {
			t.Fatalf("disconnect signaled after only %d consecutive failures, want threshold=3", i+1)
		}
	}
	if disconnect := g.RecordOutcome(false); !disconnect {
		t.Fatal("expected disconnect to be signaled on the 3rd consecutive failure")
	}
}

// TestInvalidShareGuardResetsOnAcceptedOutcome confirms a single
// accepted outcome resets the running consecutive-invalid count --
// this mechanism targets a SUSTAINED run of fabricated claims, not a
// lifetime tally that would eventually disconnect even a
// mostly-honest session that occasionally loses a real block race.
func TestInvalidShareGuardResetsOnAcceptedOutcome(t *testing.T) {
	g := leaflib.NewInvalidShareGuard(leaflib.InvalidShareGuardConfig{Enabled: true, Threshold: 3})

	g.RecordOutcome(false)
	g.RecordOutcome(false)
	g.RecordOutcome(true) // resets the count
	for i := 0; i < 2; i++ {
		if disconnect := g.RecordOutcome(false); disconnect {
			t.Fatalf("disconnect signaled after only %d consecutive failures post-reset, want threshold=3", i+1)
		}
	}
	if disconnect := g.RecordOutcome(false); !disconnect {
		t.Fatal("expected disconnect to be signaled on the 3rd consecutive failure post-reset")
	}
}

// TestSessionRXTRepeatedFabricatedBlockFindClaimsGetDisconnected is
// the real, end-to-end proof (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b
// [HIGH — Finding 2]) that a session repeatedly submitting fabricated
// above-target claims that fail REAL validation gets disconnected
// once it crosses the configured consecutive-invalid-share threshold
// — the actual DoS vector Finding 2 identified: each such claim
// numerically crosses job.NetworkTargetDifficulty (a genuine
// block-find candidate, per solo's own block-find-only validation
// model — see session.go's handleSubmit doc comment), so it IS
// dispatched through s.server.randomxPool and DOES pay a real
// validator call, unlike an ordinary sub-block claim. A fake,
// always-failing validator.AlgoValidator stands in for a real
// randomx-service daemon here (deterministic, no real network I/O,
// no daemon dependency), per the brief's own explicit instruction not
// to require one for this test.
//
// This builds its own harness (rather than reusing
// newRXTTestHarnessWithValidator) for the same reason
// trust_integration_test.go's own (now-removed, per Fix 5)
// analogous test did: SetInvalidShareGuardConfig must be called
// BEFORE Server.handleConn's goroutine starts, so the session this
// test's login creates captures the overridden config, not
// NewServer's own default.
func TestSessionRXTRepeatedFabricatedBlockFindClaimsGetDisconnected(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	const threshold = 3

	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: networkTargetDiff,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
		vmKey:            []byte("test key 000"),
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXT,
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})
	// Always fails real validation -- every one of this test's
	// submits is a genuine block-find CANDIDATE (blockFindResultHash)
	// whose claim is nonetheless never cryptographically genuine.
	fakeValidator := &fakeDelayedRandomXValidator{validFunc: func(string) bool { return false }}
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: fakeValidator}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})
	t.Cleanup(func() {
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
	})

	// Override BEFORE handleConn's goroutine starts -- see this
	// test's own doc comment.
	server.SetInvalidShareGuardConfig(leaflib.InvalidShareGuardConfig{Enabled: true, Threshold: threshold})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &testHarness{
		t: t, server: server, cm: cm, jm: jm, node: node,
		client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}

	_, xn := login(t, h, "addr-rxt-dos")
	jobID := currentJobIDForXN(t, h, xn)

	for i := 0; i < threshold; i++ {
		nonce := make([]byte, 4)
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		result := blockFindResultHash(i)
		h.send(Request{ID: i + 200, Method: "submit", Params: mustJSON(t, SubmitRequest{
			JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
		resp := h.recvShareResponse()
		if resp.Result != nil {
			t.Fatalf("attempt %d: expected fabricated block-find claim to be rejected, got accepted: %#v", i, resp)
		}
	}

	// The threshold-th rejection's response was already delivered
	// above (finishSubmit writes the rejection BEFORE closing the
	// connection -- see its own doc comment); the connection itself
	// should now be closing/closed. Confirm by attempting one more
	// read: it must fail (EOF/closed-pipe), never block indefinitely
	// or succeed with a real response to a submit this session never
	// even got to send.
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if n, err := h.client.Read(buf); err == nil {
		t.Fatalf("expected the connection to be closed after %d consecutive invalid shares, but Read succeeded (n=%d)", threshold, n)
	}
}
