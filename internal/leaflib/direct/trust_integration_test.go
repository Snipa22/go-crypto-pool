// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestDirectSessionRXTTrustedShareSkipsRealRandomXValidation mirrors
// solo's own identical test exactly (see
// internal/leaflib/solo/trust_integration_test.go's doc comment for
// the full real reasoning) -- the real, end-to-end proof that
// Server.EnableTrust's wiring in handleSubmit genuinely skips the
// real RandomXValidator.Validate call for leaf-direct too, not just
// leaf-solo.
//
// This test builds its OWN harness (rather than reusing
// newDirectRXTTestHarness) for the identical real reason solo's own
// test does: EnableTrust MUST be called BEFORE Server.handleConn's
// goroutine starts, or go test -race correctly reports a real data
// race on trustConfig -- newDirectRXTTestHarness starts that
// goroutine internally with no seam to call EnableTrust in between.
func TestDirectSessionRXTTrustedShareSkipsRealRandomXValidation(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
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
	rx := validator.NewRandomXValidator("http://127.0.0.1:1") // deliberately unreachable
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: rx}
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

	// EnableTrust BEFORE handleConn's goroutine starts -- the real
	// fix for the real data race go test -race caught when this
	// test previously called EnableTrust after harness construction.
	server.EnableTrust(solo.TrustConfig{Enabled: true, Threshold: 1, Penalty: 1, Change: 300, Min: 1})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr, submit: sub,
		client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}

	sessionID, xn := directLogin(t, h, realTariTestAddress("addr-rxt-trust"))
	jobID := directCurrentJobIDForXN(t, h, xn)

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
	forceDirectTrustReady(sess.trust)

	// BUG FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 6): use the
	// BIG-ENDIAN nonce-hex helper, not the little-endian one, for this
	// retry loop's nonce generation. directXNPrefixedNonceHex (LE)
	// packs n little-endian and then overwrites the LEADING hex
	// characters with xn -- for a little-endian encoding, those
	// leading characters are n's LOW-order bytes, exactly the bytes a
	// small per-attempt increment (n+1, n+2, ...) changes. Every
	// "retry" below therefore ended up submitting the byte-identical
	// final nonce post-xn-overwrite, which (since job.MarkNonceUsed
	// already ran on attempt 0, unconditionally, before any
	// validation/skip decision) made every subsequent attempt hit a
	// spurious "duplicate nonce" rejection instead of the real
	// randomx-service-unreachable connectivity error this loop
	// actually expects and checks for -- an intermittent flake
	// whenever attempt 0's trust coin-flip happened to land on "run
	// real validation" instead of "skip". directXNPrefixedNonceHexBigEndian
	// puts n's low-order bytes at the END of the hex string, outside
	// xn's overwritten prefix, so each attempt's increment always
	// produces a genuinely distinct nonce.
	badNonce := directXNPrefixedNonceHexBigEndian(xn, 0xdeadbeef)
	fakeResult := strings.Repeat("ab", 32)

	var accepted bool
	var lastErr string
	for attempt := 0; attempt < 20; attempt++ {
		h.send(solo.Request{ID: 70, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			ID:     sessionID,
			JobID:  jobID,
			Nonce:  badNonce,
			Result: fakeResult,
		})})
		resp := h.recvShareResponse()
		accepted = resp.Result != nil
		lastErr = ""
		if resp.Error != nil {
			lastErr = resp.Error.Message
		}
		if accepted {
			break
		}
		if !strings.Contains(lastErr, "randomx-service") && !strings.Contains(lastErr, "connect") {
			t.Fatalf("unexpected non-connectivity failure on attempt %d: %q", attempt, lastErr)
		}
		forceDirectTrustReady(sess.trust)
		badNonce = directXNPrefixedNonceHexBigEndian(xn, uint64(0xdeadbeef+attempt+1))
	}
	if !accepted {
		t.Fatalf("expected at least one trusted-share skip to succeed within 20 attempts against an unreachable daemon; last error: %q", lastErr)
	}
}

// forceDirectTrustReady is direct's copy of solo's own identical
// test-only helper (see solo/trust_integration_test.go's doc
// comment) -- MinerTrust's unexported fields aren't reachable from
// this package, so this operates via MinerTrust's real exported API
// (RecordOutcome), using the SAME cfg this test's EnableTrust call
// already configured (Threshold=1, Penalty=1, Change=300, Min=1 --
// one accept is enough to floor probability at 1 and clear threshold
// to 0; penalty starts at 0 already per the real reference
// semantics, so it's already clear too).
func forceDirectTrustReady(trust *solo.MinerTrust) {
	trust.RecordOutcome(true)
	trust.RecordOutcome(true)
}
