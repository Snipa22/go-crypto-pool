// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"log"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// newDirectFoundBlockRXTHarness builds a leaf-direct ALGO_RXT test
// harness wired with the real, legacy-ported trusted-miner
// validation skip (solo.TrustConfig) forced into its "ready to skip"
// state before any connection is served -- this lets these regression
// tests drive a genuine RXT block-find submission through
// handleSubmit end-to-end (real BuildCandidateBlock difficulty
// derivation, real forwardShare dispatch, real MultiSubmit block
// acceptance) without requiring a real reachable randomx-service
// daemon, mirroring trust_integration_test.go's own established
// pattern exactly (EnableTrust must be called before
// Server.handleConn's goroutine starts, or go test -race correctly
// reports a real data race on trustConfig).
func newDirectFoundBlockRXTHarness(t *testing.T, staticDiff, networkTargetDiff uint64) (h *directTestHarness, sess *Session, sessionID, xn string) {
	t.Helper()
	node := &fakeDirectNodeClient{
		height:          42,
		mergeMiningHash: []byte("direct-test-merge-mining-hash-found-block"),
		vmKey:           []byte("test key 000"),
	}
	node.targetDifficulty = networkTargetDiff
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXT,
	})
	// Deliberately unreachable -- trust-skip must mean this is never
	// actually dialed for the accepted submit below.
	rx := validator.NewRandomXValidator("http://127.0.0.1:1")
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
		Algo: poolpb.Algo_ALGO_RXT, PoolType: poolpb.PoolType_POOL_TYPE_SOLO, PoolID: 42,
	})
	server.EnableTrust(solo.TrustConfig{Enabled: true, Threshold: 1, Penalty: 1, Change: 300, Min: 1})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)
	t.Cleanup(func() { _ = clientConn.Close() })

	h = &directTestHarness{
		t: t, server: server, jm: jm, transport: tr, submit: sub,
		client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}

	sessionID, xn = directLogin(t, h, realTariTestAddress("addr-found-block-rxt"))

	server.mu.RLock()
	for _, s := range server.sessions {
		if s.sessionID == sessionID {
			sess = s
			break
		}
	}
	server.mu.RUnlock()
	if sess == nil {
		t.Fatalf("could not find session %q on server after login", sessionID)
	}
	if sess.trust == nil {
		t.Fatal("session.trust is nil despite EnableTrust having been called before this session was created")
	}
	forceDirectTrustReady(sess.trust)
	return h, sess, sessionID, xn
}

// submitTrustedRXTShare drives one RXT submit through the given
// harness, retrying with a fresh nonce and re-forcing trust readiness
// whenever the coin-flip (MinerTrust.ShouldSkipValidation) lands on
// "run real validation against the deliberately unreachable
// randomx-service daemon" instead of "skip" -- mirrors
// trust_integration_test.go's own identical retry-loop pattern
// exactly (see that test's doc comment on
// directXNPrefixedNonceHexBigEndian's specific big-endian-vs-little-
// endian rationale for why retries need distinct nonces that don't
// collide with job.MarkNonceUsed's already-unconditional dedup on
// attempt 0).
func submitTrustedRXTShare(t *testing.T, h *directTestHarness, sess *Session, sessionID, xn, jobID string, reqID int, startNonce uint32) (accepted bool, lastErr string) {
	t.Helper()
	fakeResult := strings.Repeat("ab", 32)
	nonce := startNonce
	for attempt := 0; attempt < 20; attempt++ {
		h.send(solo.Request{ID: reqID, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			ID:     sessionID,
			JobID:  jobID,
			Nonce:  directXNPrefixedNonceHexBigEndian(xn, uint64(nonce)),
			Result: fakeResult,
		})})
		resp := h.recvShareResponse()
		accepted = resp.Result != nil
		lastErr = ""
		if resp.Error != nil {
			lastErr = resp.Error.Message
		}
		if accepted {
			return true, ""
		}
		if !strings.Contains(lastErr, "randomx-service") && !strings.Contains(lastErr, "connect") {
			t.Fatalf("unexpected non-connectivity failure on attempt %d: %q", attempt, lastErr)
		}
		forceDirectTrustReady(sess.trust)
		nonce++
	}
	return false, lastErr
}

// TestDirectSessionRXTBlockFindSetsFoundBlockTrue is the confirmed,
// live-bug regression test: a genuine RXT block-find submission
// (real BuildCandidateBlock-derived difficulty clearing
// job.NetworkTargetDifficulty, real MultiSubmit acceptance) must
// produce a forwarded poolpb.Share with FoundBlock == true --
// previously it was ALWAYS false regardless of a real block find,
// because the poolpb.Share{} struct literal for every algo branch
// was built and dispatched to forwardShare BEFORE handleSubmit ever
// checked whether the submit cleared network difficulty at all (see
// session.go's handleSubmit doc comment on the fix). Downstream, this
// is exactly the bug that made internal/backend/db/repository.go's
// SoloShare(...) query (`WHERE ... AND found_block IS TRUE`) never
// find the real winning miner for a solo-pool_type payout.
func TestDirectSessionRXTBlockFindSetsFoundBlockTrue(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1)
	h, sess, sessionID, xn := newDirectFoundBlockRXTHarness(t, staticDiff, networkTargetDiff)
	jobID := directCurrentJobIDForXN(t, h, xn)

	accepted, lastErr := submitTrustedRXTShare(t, h, sess, sessionID, xn, jobID, 501, 0xdeadbeef)
	if !accepted {
		t.Fatalf("expected the trust-skipped RXT block-finding submit to be accepted within 20 attempts; last error: %q", lastErr)
	}

	waitForShareCount(t, h.transport, 1)
	share := h.transport.shareAt(0)
	if !share.GetFoundBlock() {
		t.Fatalf("BUG REGRESSION: a genuine RXT block-find submission forwarded a Share with FoundBlock=false; SoloShare's DB lookup (found_block IS TRUE) would never find this real winning miner, so solo payout would silently pay them zero")
	}
	if got := share.GetAlgo(); got != poolpb.Algo_ALGO_RXT {
		t.Errorf("sanity: forwarded share algo = %v, want ALGO_RXT", got)
	}
}

// TestDirectSessionRXTOrdinarySubmitLeavesFoundBlockFalse is the
// non-regression counterpart: an RXT submit that clears its job's
// StaticDifficulty but NOT the (deliberately huge)
// NetworkTargetDifficulty is an ordinary share, not a block find, and
// must still forward with FoundBlock left at its correct false zero
// value.
func TestDirectSessionRXTOrdinarySubmitLeavesFoundBlockFalse(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	h, sess, sessionID, xn := newDirectFoundBlockRXTHarness(t, staticDiff, networkTargetDiff)
	jobID := directCurrentJobIDForXN(t, h, xn)

	accepted, lastErr := submitTrustedRXTShare(t, h, sess, sessionID, xn, jobID, 502, 0x1000)
	if !accepted {
		t.Fatalf("expected the trust-skipped RXT ordinary submit to be accepted within 20 attempts; last error: %q", lastErr)
	}

	waitForShareCount(t, h.transport, 1)
	share := h.transport.shareAt(0)
	if share.GetFoundBlock() {
		t.Fatalf("an ordinary (below-network-difficulty) RXT share was forwarded with FoundBlock=true, want false")
	}
	if h.transport.blockCount() != 0 {
		t.Errorf("an ordinary share must not also trigger a forwarded block, got blockCount=%d", h.transport.blockCount())
	}
}

// rxmDifficultyOneResultHex is a claimed RXM RandomX result hash
// whose little-endian whole-buffer value is the max 256-bit value
// (every byte 0xff) -- per monero_node.go's moneroDifficultyFromHash
// (moneroMax256 / hashVal), this is the SMALLEST difficulty a claimed
// result can carry (== 1), letting a test construct a genuine
// ordinary (non-block-finding) RXM share against a daemon-reported
// network difficulty set comfortably higher.
var rxmDifficultyOneResultHex = strings.Repeat("ff", 32)

// TestDirectSessionRXMBlockFindSetsFoundBlockTrue is
// TestDirectSessionRXTBlockFindSetsFoundBlockTrue's ALGO_RXM
// (Monero-family) counterpart, reusing this package's own
// session_rxm_blockhash_test.go harness (a REAL solo.MoneroNodeClient
// against a mock monerod, exercising the exact real
// GetBlockTemplate -> BuildCandidateBlock -> SubmitBlock pipeline) --
// this proves the fix in session.go's handleSubmit (shared, common
// post-switch logic for every algo branch) is not accidentally
// RXT-specific.
func TestDirectSessionRXMBlockFindSetsFoundBlockTrue(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	daemon.setHeaderHash("d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d3")
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectRXMBlockFindHarness(t, srv, 1)
	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

	h.send(solo.Request{ID: 503, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  "01000000",
		Result: moneroDirectClaimedTinyResult,
	})})
	resp := h.recvShareResponse()
	if resp.Error != nil {
		t.Fatalf("unexpected share rejection: %+v", resp.Error)
	}
	if resp.Result == nil || resp.Result.Status != "OK" {
		t.Fatalf("expected an accepted block-finding share, got %#v", resp)
	}

	waitForShareCount(t, h.transport, 1)
	share := h.transport.shareAt(0)
	if !share.GetFoundBlock() {
		t.Fatalf("BUG REGRESSION: a genuine RXM (Monero-family) block-find submission forwarded a Share with FoundBlock=false")
	}
	if got := share.GetAlgo(); got != poolpb.Algo_ALGO_RXM {
		t.Errorf("sanity: forwarded share algo = %v, want ALGO_RXM", got)
	}
	waitForBlockCount(t, h.transport, 1)
}

// TestDirectSessionRXMOrdinarySubmitLeavesFoundBlockFalse is the RXM
// non-regression counterpart of the RXT ordinary-submit test above:
// a claimed result whose real derived difficulty (1, see
// rxmDifficultyOneResultHex's doc comment) clears the job's
// StaticDifficulty (1) but NOT the daemon's much higher reported
// network difficulty (1000) is an ordinary share, and must forward
// with FoundBlock left false.
func TestDirectSessionRXMOrdinarySubmitLeavesFoundBlockFalse(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectRXMBlockFindHarness(t, srv, 1)
	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

	h.send(solo.Request{ID: 504, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  "02000000",
		Result: rxmDifficultyOneResultHex,
	})})
	resp := h.recvShareResponse()
	if resp.Error != nil {
		t.Fatalf("unexpected share rejection: %+v", resp.Error)
	}
	if resp.Result == nil || resp.Result.Status != "OK" {
		t.Fatalf("expected an accepted ordinary share, got %#v", resp)
	}

	waitForShareCount(t, h.transport, 1)
	share := h.transport.shareAt(0)
	if share.GetFoundBlock() {
		t.Fatalf("an ordinary (below-network-difficulty) RXM share was forwarded with FoundBlock=true, want false")
	}
	if h.transport.blockCount() != 0 {
		t.Errorf("an ordinary share must not also trigger a forwarded block, got blockCount=%d", h.transport.blockCount())
	}
	if daemon.submitCalls.Load() != 0 {
		t.Errorf("an ordinary (non-block-finding) share must never call submit_block, got %d calls", daemon.submitCalls.Load())
	}
}
