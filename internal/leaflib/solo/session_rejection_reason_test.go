// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// rejectionReasonHarness wraps testHarness with the real
// *metrics.Metrics EnableMetrics returns, wired BEFORE
// Server.handleConn's goroutine starts -- mirrors
// session_async_randomx_test.go's own newRXTTestHarnessWithValidator
// construction order exactly, and (per direct/session_classification_
// test.go's own doc comment on this exact same ordering requirement)
// avoids a real `go test -race` data race between this test's own
// EnableMetrics call and the session goroutine's own field reads.
type rejectionReasonHarness struct {
	*testHarness
	metrics *metrics.Metrics
}

// newRejectionReasonHarness builds a real Server/JobManager for algo,
// with metrics enabled and wired to the returned harness -- node may
// be nil (a default fakeNodeClient, shaped like session_test.go's own
// newTestHarness/newRXTTestHarness fixtures, is constructed), or a
// caller-supplied *fakeNodeClient (e.g. one with submitBlockErr set)
// for tests that need to control the node's own behavior.
func newRejectionReasonHarness(t *testing.T, algo poolpb.Algo, staticDiff, networkTargetDiff uint64, jobMaxAge time.Duration, registry validator.Registry, node *fakeNodeClient) *rejectionReasonHarness {
	t.Helper()
	if node == nil {
		node = &fakeNodeClient{
			height:          42,
			mergeMiningHash: []byte("test-merge-mining-hash-32bytes!"),
			blockHashSeed:   []byte("test-block-hash-seed-32-bytes!!"),
			vmKey:           []byte("test key 000"),
		}
	}
	node.targetDifficulty = networkTargetDiff

	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
		Algo:             algo,
		JobMaxAge:        jobMaxAge,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})
	m := server.EnableMetrics("test", 0)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &testHarness{
		t: t, server: server, cm: cm, jm: jm, node: node,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	t.Cleanup(func() {
		cancel()
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
		_ = clientConn.Close()
	})
	return &rejectionReasonHarness{testHarness: h, metrics: m}
}

// assertOnlyRejectionReason confirms exactly one
// leaf_share_rejection_reason_total{reason=want} sample equals 1 and
// every OTHER reason in the full, closed metrics.AllRejectionReasons
// enumeration is still 0 -- the "no other category's counter moved"
// half of this feature's required test coverage.
func assertOnlyRejectionReason(t *testing.T, m *metrics.Metrics, want string) {
	t.Helper()
	for _, reason := range metrics.AllRejectionReasons {
		got := testutil.ToFloat64(m.ShareRejectionReasonTotal.WithLabelValues(reason))
		if reason == want {
			if got != 1 {
				t.Errorf("reason=%s counter = %v, want 1", reason, got)
			}
		} else if got != 0 {
			t.Errorf("reason=%s counter = %v, want 0 (only reason=%s should have incremented)", reason, got, want)
		}
	}
}

// assertSharesRejectedTotal confirms the pre-existing
// leaf_shares_total{result="rejected"} counter is still incremented
// exactly as before this feature -- proving the new per-reason
// breakdown is purely additive, never a replacement for the existing
// accept/reject bookkeeping writeShareResponse already does.
func assertSharesRejectedTotal(t *testing.T, m *metrics.Metrics, want float64) {
	t.Helper()
	if got := testutil.ToFloat64(m.SharesTotal.WithLabelValues(metrics.ResultRejected)); got != want {
		t.Errorf("leaf_shares_total{result=\"rejected\"} = %v, want %v", got, want)
	}
}

// TestSessionRejectionReason_StaleOrUnknownJob covers handleSubmit's
// s.ownJob(submit.JobID) failure call site.
func TestSessionRejectionReason_StaleOrUnknownJob(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-stale-job")

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonStaleOrUnknownJob)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_JobExpired covers handleSubmit's real
// per-job JobMaxAge expiry call site, independent of job ownership.
func TestSessionRejectionReason_JobExpired(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 30*time.Millisecond, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-job-expired")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	time.Sleep(60 * time.Millisecond)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonJobExpired)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_BannedAddress covers handleSubmit's
// submit-time address-flags re-check (independent of the login-time
// check, which never reaches writeShareResponse at all) -- mirrors
// addressflags_enforcement_test.go's own
// TestSessionSubmit_RejectsAddressBannedMidSession exactly, plus this
// feature's own rejection-reason assertions.
func TestSessionRejectionReason_BannedAddress(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)

	addr := realTariTestAddress("rr-banned-mid-session")
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)
	h.server.EnableAddressFlags(cache)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	loginResp := h.recvLoginResponse()
	if loginResp.Result.Status != "OK" {
		t.Fatalf("setup: expected login to succeed while unbanned, got status=%q", loginResp.Result.Status)
	}
	sessionID, xn := loginResp.Result.ID, loginResp.Result.Job.XN
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	src.set(addr, addressflags.Flags{Banned: true})
	waitForCachePoll(t, cache, addr, true)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatal("expected a submit from a now-mid-session-banned address to be rejected, got accepted")
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonBannedAddress)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_InvalidXNonce covers handleSubmit's
// SHA3X/C29 xn-prefix check.
func TestSessionRejectionReason_InvalidXNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-invalid-xnonce")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	badNonce := flipFirstHexNibble(xnPrefixedNonceHex(xn, 1))
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: badNonce,
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonInvalidXNonce)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_MalformedNonce covers handleSubmit's
// algo-conditional nonce hex-decode/length gate.
func TestSessionRejectionReason_MalformedNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-malformed-nonce")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	// SHA3X requires a full 8-byte (16 hex char) nonce; this is only
	// 2 bytes, still correctly xn-prefixed, so the xn-prefix check
	// (checked first) passes and the length gate is what rejects it.
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xn,
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonMalformedNonce)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_InvalidPowShape covers handleSubmit's
// C29-only cycle-length check.
func TestSessionRejectionReason_InvalidPowShape(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_C29, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_C29: validator.NewC29Validator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-invalid-pow-shape")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xnPrefixedNonceHexBigEndianForTest(xn, 1),
		POW: make([]uint64, 41), // c29SubmitCycleSize is 42
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonInvalidPowShape)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// xnPrefixedNonceHexBigEndianForTest is xnPrefixedNonceHex's
// big-endian counterpart, needed for a C29 nonce (C29 decodes its
// nonce big-endian -- see handleSubmit) -- this file's own minimal
// local helper rather than reusing session_test.go's big-endian
// helper (which is direct-package-only), matching xnPrefixedNonceHex's
// own byte-layout convention (xn overwrites the START of the hex
// string, matching THIS package's xnPrefixedNonceHex, not
// direct's END-anchored equivalent).
func xnPrefixedNonceHexBigEndianForTest(xn string, n uint64) string {
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		buf[i] = byte(n >> (8 * (7 - i)))
	}
	full := hex.EncodeToString(buf)
	return xn + full[len(xn):]
}

// TestSessionRejectionReason_DuplicateNonce covers handleSubmit's
// job.MarkNonceUsed replay-detection call site.
func TestSessionRejectionReason_DuplicateNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-duplicate-nonce")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	nonce := xnPrefixedNonceHex(xn, 42)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	first := h.recvLegacyShareResponse()
	if !first.Result {
		t.Fatalf("expected the first submission of a nonce to be accepted, got %#v", first)
	}

	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	second := h.recvLegacyShareResponse()
	if second.Result {
		t.Fatal("expected a replayed nonce to be rejected")
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonDuplicateNonce)
	// One accepted + one rejected submit -- confirm exactly 1 reject,
	// not 2 (the accept must not also count as a reject).
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_MissingClaimedResult covers handleSubmit's
// ALGO_RXM "requires a claimed result hash" check.
func TestSessionRejectionReason_MissingClaimedResult(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXM, 1, 1<<62, 0, validator.Registry{}, nil)
	sessionID, xn := loginRXM(t, h.testHarness)
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: "00000001",
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonMissingClaimedResult)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_DifficultyFloorMiss covers handleSubmit's
// cheap pre-dispatch claimed-difficulty-vs-StaticDifficulty floor
// check for RXT/RXM.
func TestSessionRejectionReason_DifficultyFloorMiss(t *testing.T) {
	const staticDiff = 1000 // deliberately high -- largeResultHash's own claimed difficulty is tiny (~1).
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, staticDiff, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)
	jobID := rxtLoginAndGetJobID(t, h.testHarness, "rr-difficulty-floor-miss")

	result := largeResultHash(1)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: "00000001", Result: hex.EncodeToString(result),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonDifficultyFloorMiss)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_ClaimedDifficultyOrCryptoInvalid covers
// handleSubmit's cheap pre-dispatch ClaimedRandomXFamilyDifficulty
// error path (a degenerate, all-zero claimed result hash -- division
// by zero has no sound difficulty).
func TestSessionRejectionReason_ClaimedDifficultyOrCryptoInvalid(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)
	jobID := rxtLoginAndGetJobID(t, h.testHarness, "rr-claimed-diff-invalid")

	zeroHash := make([]byte, 32)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: "00000001", Result: hex.EncodeToString(zeroHash),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonClaimedDifficultyOrCryptoInvalid)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_MalformedSubmitRequest_MissingParams
// covers handleSubmit's "submit requires params" call site (empty
// req.Params).
func TestSessionRejectionReason_MalformedSubmitRequest_MissingParams(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	_, _ = login(t, h.testHarness, "rr-missing-params")

	h.send(Request{ID: 2, Method: "submit"}) // Params deliberately omitted
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonMalformedSubmitRequest)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_MalformedSubmitRequest_InvalidJSON
// covers handleSubmit's "invalid submit params" JSON-unmarshal-error
// call site -- the SECOND, distinct real call site mapped to the same
// RejectionReasonMalformedSubmitRequest category.
func TestSessionRejectionReason_MalformedSubmitRequest_InvalidJSON(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)
	_, _ = login(t, h.testHarness, "rr-invalid-json-params")

	h.send(Request{ID: 2, Method: "submit", Params: json.RawMessage(`"not-an-object"`)})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonMalformedSubmitRequest)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_BlockSubmitFailed covers handleSubmit's
// "invalid block" call site (the node's real SubmitBlock call
// errored on a genuine, cryptographically-valid block-find).
func TestSessionRejectionReason_BlockSubmitFailed(t *testing.T) {
	node := &fakeNodeClient{
		height:          42,
		mergeMiningHash: []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:   []byte("test-block-hash-seed-32-bytes!!"),
		submitBlockErr:  errors.New("rr-test: real node rejected this block"),
	}
	// staticDiff=1/networkTargetDiff=1: real SHA3XValidator.Validate
	// trivially accepts any hash against a difficulty=1 target, and
	// diff=1 also trivially clears networkTargetDiff=1, guaranteeing
	// a genuine block-find candidate reaches SubmitBlock.
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, node)
	sessionID, xn := login(t, h.testHarness, "rr-block-submit-failed")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection (node SubmitBlock error), got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonBlockSubmitFailed)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestSessionRejectionReason_PoolSaturated covers handleSubmit's
// primary randomxPool TrySubmit dispatch failure -- the shared,
// bounded async-validation pool's queue was full (and its sole
// worker busy) at the exact instant a genuine RXT block-find
// candidate submit tried to dispatch.
func TestSessionRejectionReason_PoolSaturated(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)
	jobID := rxtLoginAndGetJobID(t, h.testHarness, "rr-pool-saturated")

	// A single-worker pool with queue capacity exactly 1 -- passing 0
	// falls back to AsyncValidationQueueSize's own generous default
	// (256, see NewAsyncValidationPool's <=0 fallback), so a genuinely
	// saturated queue needs an explicit small positive capacity
	// instead. Occupy the sole worker with a blocking closure, THEN
	// fill the queue's one remaining slot with a second (eventually
	// no-op) closure, so a THIRD dispatch attempt -- the real submit
	// below -- has nowhere to go: worker busy AND queue full.
	h.server.SetRandomXWorkerPoolSize(1, 1)

	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	if ok := h.server.randomxPool.Submit(func() {
		close(started)
		<-release
	}); !ok {
		t.Fatal("setup: failed to occupy the pool's sole worker")
	}
	<-started
	if ok := h.server.randomxPool.Submit(func() {}); !ok {
		t.Fatal("setup: failed to fill the pool's one-slot queue")
	}

	// A genuine block-find candidate (blockFindResultHash) is required
	// so handleSubmit actually reaches the randomxPool.TrySubmit
	// dispatch call site at all (an ordinary sub-block RXT/RXM share
	// never touches the pool -- see handleSubmit's own doc comment).
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: "00000001", Result: hex.EncodeToString(blockFindResultHash(1)),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection (pool saturated), got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonPoolSaturated)
	assertSharesRejectedTotal(t, h.metrics, 1)
}

// TestServer_SetRandomXWorkerPoolSize_QueueSizeReachesPool is the
// required RandomX-validation-queue-size-fix test: cmd/leaf-solo's new
// -randomx-queue-size flag (and its LEAF_SOLO_RANDOMX_QUEUE_SIZE env
// var, and randomx_queue_size toml key) all flow straight into main's
// server.SetRandomXWorkerPoolSize(cfg.randomxWorkers,
// cfg.randomxQueueSize) call site -- this confirms THAT call site's
// queueSize argument, when positive, genuinely reaches the constructed
// pool's real QueueCapacity(), mirroring
// TestSessionRejectionReason_PoolSaturated's own harness/introspection
// pattern above (real Server, direct field access to randomxPool from
// within this same package).
func TestServer_SetRandomXWorkerPoolSize_QueueSizeReachesPool(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)

	const explicitWorkers = 2
	const explicitQueueSize = 777
	h.server.SetRandomXWorkerPoolSize(explicitWorkers, explicitQueueSize)

	if got := h.server.randomxPool.QueueCapacity(); got != explicitQueueSize {
		t.Fatalf("randomxPool.QueueCapacity() = %d, want %d (the explicit queueSize passed to SetRandomXWorkerPoolSize)", got, explicitQueueSize)
	}
	if got := h.server.randomxPool.Workers(); got != explicitWorkers {
		t.Fatalf("randomxPool.Workers() = %d, want %d (the explicit workers passed to SetRandomXWorkerPoolSize)", got, explicitWorkers)
	}
}

// TestSessionRejectionReason_InternalError covers handleSubmit's
// "no validator configured for this leaf's algo" call site --
// finishSubmit's own first check, reached for EVERY submit regardless
// of its actual cryptographic shape/validity.
func TestSessionRejectionReason_InternalError(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 0, validator.Registry{}, nil)
	sessionID, xn := login(t, h.testHarness, "rr-internal-error")
	jobID := currentJobIDForSession(t, h.testHarness, xn)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection (no validator configured), got accepted: %#v", resp)
	}

	assertOnlyRejectionReason(t, h.metrics, metrics.RejectionReasonInternalError)
	assertSharesRejectedTotal(t, h.metrics, 1)
}
