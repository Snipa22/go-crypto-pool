// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// newRejectionReasonHarness builds a real leaf-direct Server/Session
// with metrics enabled and wired BEFORE Server.handleConn's goroutine
// starts -- mirrors session_classification_test.go's own
// newClassificationTestHarness construction order exactly (see that
// file's doc comment for the full "why before handleConn starts"
// rationale). node may be nil (a default fakeDirectNodeClient is
// constructed) or a caller-supplied one for tests that need to
// control the node's own behavior (e.g. a real MultiSubmit failure).
func newRejectionReasonHarness(t *testing.T, algo poolpb.Algo, staticDiff, networkTargetDiff uint64, registry validator.Registry, node *fakeDirectNodeClient, submitClient blockSubmitClient) *classificationTestHarness {
	t.Helper()
	if node == nil {
		node = &fakeDirectNodeClient{
			height:          42,
			mergeMiningHash: []byte("direct-test-merge-mining-hash-3"),
			vmKey:           []byte("test key 000"),
		}
	}
	node.targetDifficulty = networkTargetDiff

	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
		Algo:             algo,
	})

	tr := &fakeShareTransport{}
	if submitClient == nil {
		submitClient = &fakeAcceptingBlockClient{}
	}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": submitClient}, log.Default())

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET, Transport: tr, MultiSubmit: multi,
		Algo: algo, PoolType: poolpb.PoolType_POOL_TYPE_SOLO, PoolID: 42,
	})

	m := server.EnableMetrics("test", 0)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	return &classificationTestHarness{directTestHarness: h, metrics: m}
}

// newRejectionReasonHarnessWithJobMaxAge is newRejectionReasonHarness
// plus an explicit JobManagerConfig.JobMaxAge override -- used only by
// the real per-job expiry test below (mirrors solo package's own
// newTestHarnessWithJobMaxAge/newRejectionReasonHarness split).
func newRejectionReasonHarnessWithJobMaxAge(t *testing.T, algo poolpb.Algo, staticDiff, networkTargetDiff uint64, jobMaxAge time.Duration, registry validator.Registry) *classificationTestHarness {
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
		Algo:             algo,
		JobMaxAge:        jobMaxAge,
	})

	tr := &fakeShareTransport{}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET, Transport: tr, MultiSubmit: multi,
		Algo: algo, PoolType: poolpb.PoolType_POOL_TYPE_SOLO, PoolID: 42,
	})

	m := server.EnableMetrics("test", 0)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	return &classificationTestHarness{directTestHarness: h, metrics: m}
}

// assertOnlyDirectRejectionReason mirrors solo package's identical
// assertOnlyRejectionReason exactly -- see that function's doc
// comment.
func assertOnlyDirectRejectionReason(t *testing.T, m *directmetrics.Metrics, want string) {
	t.Helper()
	for _, reason := range directmetrics.AllRejectionReasons {
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

// assertDirectSharesRejectedTotal mirrors solo package's identical
// assertSharesRejectedTotal exactly.
func assertDirectSharesRejectedTotal(t *testing.T, m *directmetrics.Metrics, want float64) {
	t.Helper()
	if got := testutil.ToFloat64(m.SharesTotal.WithLabelValues(directmetrics.ResultRejected)); got != want {
		t.Errorf("leaf_direct_shares_total{result=\"rejected\"} = %v, want %v", got, want)
	}
}

func TestDirectSessionRejectionReason_StaleOrUnknownJob(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-stale-job"))

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: "0000000000000000", Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonStaleOrUnknownJob)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

// TestDirectSessionRejectionReason_JobExpired covers handleSubmit's
// real per-job JobMaxAge expiry call site, independent of job
// ownership.
func TestDirectSessionRejectionReason_JobExpired(t *testing.T) {
	h := newRejectionReasonHarnessWithJobMaxAge(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, 30*time.Millisecond, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()})
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-job-expired"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	time.Sleep(60 * time.Millisecond)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonJobExpired)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_InvalidXNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-invalid-xnonce"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	badNonce := flipFirstHexNibble(directXNPrefixedNonceHex(xn, 1))
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: badNonce,
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonInvalidXNonce)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_MalformedNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-malformed-nonce"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: xn, // too short: SHA3X needs a full 8-byte nonce
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonMalformedNonce)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_InvalidPowShape(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_C29, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_C29: validator.NewC29Validator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-invalid-pow-shape"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHexBigEndian(xn, 1),
		POW: make([]uint64, 41), // c29SubmitCycleSize is 42
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonInvalidPowShape)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_DuplicateNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-duplicate-nonce"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	nonce := directXNPrefixedNonceHex(xn, 42)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	first := h.recvLegacyShareResponse()
	if !first.Result {
		t.Fatalf("expected the first submission of a nonce to be accepted, got %#v", first)
	}
	waitForShareCount(t, h.transport, 1)

	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce,
	})})
	second := h.recvLegacyShareResponse()
	if second.Result {
		t.Fatal("expected a replayed nonce to be rejected")
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonDuplicateNonce)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_MissingClaimedResult(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXM, 1, 1<<62, validator.Registry{}, nil, nil)
	sessionID, xn := directLoginRXM(t, h.directTestHarness)
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: "00000001",
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonMissingClaimedResult)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

// TestDirectSessionRejectionReason_DifficultyFloorMiss covers
// handleSubmit's cheap pre-dispatch claimed-difficulty-vs-
// StaticDifficulty floor check (the same call site solo's own
// identical test exercises -- see that package's own doc comment on
// why the SEPARATE, direct-only post-validate real-derived-difficulty
// floor check (handleSubmit's "GENUINE DIFFERENCE FROM leaf-solo"
// branch) is structurally unreachable for RXT: both the claimed and
// the real derived difficulty are computed from the exact same
// submit.Result via the exact same formula, so they can never
// diverge -- confirmed by this repo's own pre-existing
// session_classification_test.go doc comment on
// TestDirectSessionRXTClassification_Invalid).
func TestDirectSessionRejectionReason_DifficultyFloorMiss(t *testing.T) {
	const staticDiff = 1000
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, staticDiff, 1<<62, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-difficulty-floor-miss"))
	_ = xn
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: classificationRXTNonceHex(1),
		Result: hex.EncodeToString(directLargeResultHash(1)),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonDifficultyFloorMiss)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_ClaimedDifficultyOrCryptoInvalid(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-claimed-diff-invalid"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	zeroHash := make([]byte, 32)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: classificationRXTNonceHex(1),
		Result: hex.EncodeToString(zeroHash),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonClaimedDifficultyOrCryptoInvalid)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_MalformedSubmitRequest_MissingParams(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	_, _ = directLogin(t, h.directTestHarness, realTariTestAddress("drr-missing-params"))

	h.send(solo.Request{ID: 2, Method: "submit"}) // Params deliberately omitted
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonMalformedSubmitRequest)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

func TestDirectSessionRejectionReason_MalformedSubmitRequest_InvalidJSON(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)
	_, _ = directLogin(t, h.directTestHarness, realTariTestAddress("drr-invalid-json-params"))

	h.send(solo.Request{ID: 2, Method: "submit", Params: json.RawMessage(`"not-an-object"`)})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection, got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonMalformedSubmitRequest)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

// TestDirectSessionRejectionReason_BlockSubmitFailed covers
// handleSubmit's "invalid block: rejected/failed at every configured
// node" call site: a genuine, cryptographically-valid block-find
// candidate whose real MultiSubmit attempt is rejected by every
// configured node.
func TestDirectSessionRejectionReason_BlockSubmitFailed(t *testing.T) {
	rejecting := &fakeRejectingBlockClient{}
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, rejecting)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-block-submit-failed"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection (every node rejected the block), got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonBlockSubmitFailed)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

// fakeRejectingBlockClient is a blockSubmitClient test double that
// always reports rejection -- the inverse of session_test.go's own
// fakeAcceptingBlockClient, used to exercise handleSubmit's
// every-node-rejected block-submit-failure path.
type fakeRejectingBlockClient struct{}

func (f *fakeRejectingBlockClient) SubmitBlock(_ *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	return nil, errors.New("drr-test: node rejected block")
}

func (f *fakeRejectingBlockClient) Close() error { return nil }

// TestDirectSessionRejectionReason_PoolSaturated mirrors solo
// package's identical test exactly -- see that test's own doc
// comment for the full setup rationale (a genuinely saturated
// randomxPool: sole worker busy AND its one-slot queue full).
func TestDirectSessionRejectionReason_PoolSaturated(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-pool-saturated"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

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

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: classificationRXTNonceHex(1),
		Result: classificationRXTResultHex, // real-shaped, block-find-crossing claimed hash
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatalf("expected rejection (pool saturated), got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonPoolSaturated)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

// TestServer_SetRandomXWorkerPoolSize_QueueSizeReachesPool mirrors
// solo package's identical test exactly -- see that test's own doc
// comment for the full rationale: this confirms
// cmd/leaf-direct's new -randomx-queue-size flag's plumbing target
// (server.SetRandomXWorkerPoolSize(cfg.randomxWorkers,
// cfg.randomxQueueSize)) genuinely reaches the constructed pool's
// real QueueCapacity(), not just Workers().
func TestServer_SetRandomXWorkerPoolSize_QueueSizeReachesPool(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)

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

// TestDirectSessionRejectionReason_InternalError covers handleSubmit's
// "no validator configured for this leaf's algo" call site --
// finishSubmit's own first check, reached for EVERY submit regardless
// of its actual cryptographic shape/validity (and, for SHA3X/C29,
// reached inline without any block-find/async-dispatch requirement).
func TestDirectSessionRejectionReason_InternalError(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62, validator.Registry{}, nil, nil)
	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("drr-internal-error"))
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatalf("expected rejection (no validator configured), got accepted: %#v", resp)
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonInternalError)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

// TestDirectSessionRejectionReason_BannedAddress covers handleSubmit's
// submit-time address-flags re-check.
func TestDirectSessionRejectionReason_BannedAddress(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	addr := realTariTestAddress("drr-banned-mid-session")
	src := &fakeAddressFlagsSourceForRejectionTest{flags: map[string]addressflags.Flags{}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)
	h.server.EnableAddressFlags(cache)

	sessionID, xn := directLogin(t, h.directTestHarness, addr)
	jobID := directCurrentJobIDForSession(t, h.directTestHarness, xn)

	src.set(addr, addressflags.Flags{Banned: true})
	waitForDirectRejectionCachePoll(t, cache, addr, true)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatal("expected a submit from a now-mid-session-banned address to be rejected, got accepted")
	}

	assertOnlyDirectRejectionReason(t, h.metrics, directmetrics.RejectionReasonBannedAddress)
	assertDirectSharesRejectedTotal(t, h.metrics, 1)
}

// fakeAddressFlagsSourceForRejectionTest mirrors
// addressflags_enforcement_test.go's own fakeAddressFlagsSource
// exactly (this package's own copy, to avoid depending on that
// solo-package-only test helper from the direct package).
type fakeAddressFlagsSourceForRejectionTest struct {
	mu    sync.Mutex
	flags map[string]addressflags.Flags
}

func (s *fakeAddressFlagsSourceForRejectionTest) Fetch(_ context.Context) (map[string]addressflags.Flags, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]addressflags.Flags, len(s.flags))
	for k, v := range s.flags {
		out[k] = v
	}
	return out, nil
}

func (s *fakeAddressFlagsSourceForRejectionTest) set(addr string, f addressflags.Flags) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flags[addr] = f
}

// waitForDirectRejectionCachePoll mirrors
// addressflags_enforcement_test.go's own waitForCachePoll exactly.
func waitForDirectRejectionCachePoll(t *testing.T, cache *addressflags.Cache, addr string, wantBanned bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if cache.Get(addr).Banned == wantBanned {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("address-flags cache poll never converged to Banned=%v for %q", wantBanned, addr)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// fakeControllableValidator mirrors session_classification_test.go's
// own controllableValidator exactly, but with a fixed (not runtime-
// mutable) valid value -- sufficient for this file's tests, which
// each only ever need one fixed accept/reject behavior per harness.
type fakeControllableValidator struct {
	valid bool
}

func (c *fakeControllableValidator) Validate(_ context.Context, _ *poolpb.Share) (bool, error) {
	return c.valid, nil
}

var _ validator.AlgoValidator = (*fakeControllableValidator)(nil)
