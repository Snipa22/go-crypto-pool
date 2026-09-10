// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestSessionRXTTrustedShareSkipsRealRandomXValidation is the real,
// end-to-end proof that Server.EnableTrust's wiring in handleSubmit
// genuinely skips the real RandomXValidator.Validate call (not just
// that MinerTrust's own isolated state machine works in unit tests):
// this harness deliberately points -randomx-service-url at an
// unreachable address. A normal (untrusted) RXT submit against this
// harness MUST fail (confirmed by the sibling test
// TestSessionRXTSubmitWithoutXNPrefixIsNotRejectedByXNCheck, which
// uses the identical unreachable-daemon harness and explicitly
// expects failure) since Validate cannot reach a real daemon. Once
// trust is pre-ramped in (both gates cleared, probability floored),
// the IDENTICAL submit must instead succeed -- the only way that is
// possible is if the real daemon call was genuinely never made.
//
// This test builds its OWN harness (rather than reusing
// newRXTTestHarness) because EnableTrust genuinely MUST be called
// BEFORE Server.handleConn's goroutine starts (its own doc comment
// says so, and go test -race confirms it with a real, would-be
// production data race if called after) -- newRXTTestHarness starts
// that goroutine internally with no seam to call EnableTrust in
// between.
func TestSessionRXTTrustedShareSkipsRealRandomXValidation(t *testing.T) {
	const staticDiff, networkTargetDiff = 1, uint64(1) << 62
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
	rx := validator.NewRandomXValidator("http://127.0.0.1:1") // deliberately unreachable
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: rx}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	// EnableTrust BEFORE handleConn's goroutine starts -- this is the
	// real fix for the real data race go test -race caught when this
	// test previously called EnableTrust after harness construction.
	server.EnableTrust(TrustConfig{Enabled: true, Threshold: 1, Penalty: 1, Change: 300, Min: 1})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &testHarness{
		t: t, server: server, cm: cm, jm: jm, node: node,
		client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}

	sessionID, xn := login(t, h, "addr-rxt-trust")
	jobID := currentJobIDForXN(t, h, xn)

	// Find the real session this login created and pre-ramp its
	// trust state directly (bypassing the need to actually submit
	// Threshold real, successfully-validated shares first, which
	// would themselves require a reachable daemon -- exactly the
	// dependency this test needs to avoid to prove the SKIP path
	// specifically, not the ramp-in path, which trust_test.go already
	// covers in isolation).
	h.server.mu.RLock()
	var sess *Session
	for _, s := range h.server.sessions {
		if s.sessionID == sessionID {
			sess = s
			break
		}
	}
	h.server.mu.RUnlock()
	if sess == nil {
		t.Fatalf("could not find session %q on server after login", sessionID)
	}
	if sess.trust == nil {
		t.Fatal("session.trust is nil despite EnableTrust having been called before this session was created")
	}
	// Force both gates open and probability floored so the very next
	// ShouldSkipValidation call is virtually certain to return true
	// (Min=1 means only a random byte of exactly 0 or 1 would NOT
	// exceed it -- 254/256 odds of skipping on any single attempt).
	// Loop the actual real submit attempt (not the isolated
	// ShouldSkipValidation check) a bounded number of times so a
	// single unlucky coin flip can't flake this real end-to-end test.
	forceTrustReady(sess.trust)

	badNonce := xnPrefixedNonceHex(xn, 0xdeadbeef)
	// DISPATCH_BRIEF (2026-09-10) UPDATE: solo now only ever consults
	// s.trust / calls the real validator for an RXT/RXM submit whose
	// CLAIMED result already crosses job.NetworkTargetDifficulty (a
	// genuine block-find candidate) -- see session.go's handleSubmit
	// doc comment. An "ab"-repeated claimed hash (this test's previous
	// fixture) derives to a claimed difficulty of essentially 1 (see
	// rxt_test.go's own "all 0xFF hash -> very LOW difficulty" vector;
	// 0xAB-repeated is in the same "hash is numerically large, so
	// derived difficulty is tiny" regime), which is an ORDINARY
	// sub-block share under the new model and would never reach
	// finishSubmit/s.trust at all, defeating this test's whole point.
	// This fixture instead encodes a claimed hash that is numerically
	// TINY when read little-endian (mostly zero, with a single low
	// nonzero byte so it is not the literal, degenerate all-zero value
	// claimedRandomXFamilyDifficulty correctly treats as an error) --
	// its derived difficulty is astronomically larger than
	// networkTargetDiff (1<<62), making this submit a genuine
	// block-find candidate that DOES reach finishSubmit and DOES
	// consult s.trust, exactly what this test needs to prove trust-skip
	// genuinely avoids the real daemon round-trip at the one call site
	// that still makes one.
	fakeResult := "01" + strings.Repeat("00", 31)
	submitAndExpectSkip := func() (accepted bool, errMsg string) {
		h.send(Request{ID: 70, Method: "submit", Params: mustJSON(t, SubmitRequest{
			ID:     sessionID,
			JobID:  jobID,
			Nonce:  badNonce,
			Result: fakeResult,
		})})
		resp := h.recvShareResponse()
		errMsg = ""
		if resp.Error != nil {
			errMsg = resp.Error.Message
		}
		return resp.Result != nil, errMsg
	}

	var accepted bool
	var lastErr string
	for attempt := 0; attempt < 20; attempt++ {
		accepted, lastErr = submitAndExpectSkip()
		if accepted {
			break
		}
		// A real, genuine daemon-unreachable failure (not a
		// probabilistic near-miss) would report the real connection
		// error, not "duplicate nonce" -- if we see that specific
		// error, the coin flip landed on "fully validate" this time;
		// forceTrustReady again (a rejection would have reset trust,
		// but this path never reaches RecordOutcome(false) since
		// Validate's own real connection error returns early before
		// any RecordOutcome call -- confirm this doesn't corrupt
		// state by re-forcing before retrying with a fresh nonce).
		if !strings.Contains(lastErr, "randomx-service") && !strings.Contains(lastErr, "connect") {
			t.Fatalf("unexpected non-connectivity failure on attempt %d: %q", attempt, lastErr)
		}
		forceTrustReady(sess.trust)
		badNonce = xnPrefixedNonceHex(xn, uint64(0xdeadbeef+attempt+1))
	}
	if !accepted {
		t.Fatalf("expected at least one trusted-share skip to succeed within 20 attempts against an unreachable daemon; last error: %q", lastErr)
	}
}

// forceTrustReady directly manipulates a MinerTrust's internal state
// (via its own exported Snapshot/RecordOutcome API is insufficient
// for this -- RecordOutcome only ever moves state in the real
// reference's own directions, it cannot jump straight to "ready").
// This test-only helper lives in the same package specifically so it
// can reach into MinerTrust's unexported fields directly, exactly
// mirroring how trust_test.go's own tests already do this via
// Snapshot() for reads; this is the write-side equivalent, used only
// to avoid needing a reachable daemon to naturally ramp trust in via
// real successful submits.
func forceTrustReady(trust *MinerTrust) {
	trust.mu.Lock()
	trust.threshold = -1
	trust.penalty = -1
	trust.probability = 1
	trust.mu.Unlock()
}
