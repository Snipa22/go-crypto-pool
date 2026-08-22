// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// fakeDirectNodeClient is a solo.NodeClient test double for
// leaf-direct's own Server/Session wiring — deliberately mirrors
// solo/job_test.go's own fakeNodeClient shape (same real
// GetBlockTemplate/GetTipInfo/SubmitBlock contract) since JobManager
// (reused as-is from solo) drives leaf-direct's job templates through
// the exact same interface.
type fakeDirectNodeClient struct {
	mu sync.Mutex

	height           uint64
	targetDifficulty uint64
	mergeMiningHash  []byte
	blockHashSeed    []byte

	templateCalls atomic.Int64
	submitCalls   atomic.Int64
}

func (f *fakeDirectNodeClient) GetBlockTemplate(_ context.Context, _ string, _ poolpb.Algo) (*tari_generated.GetNewBlockResult, error) {
	call := f.templateCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	seed := f.blockHashSeed
	if len(seed) == 0 {
		seed = []byte("default-direct-test-block-hash!")
	}
	hash := make([]byte, len(seed))
	copy(hash, seed)
	if len(hash) < 8 {
		padded := make([]byte, 8)
		copy(padded, hash)
		hash = padded
	}
	binary.BigEndian.PutUint64(hash[:8], uint64(call))
	return &tari_generated.GetNewBlockResult{
		BlockHash:       hash,
		MergeMiningHash: f.mergeMiningHash,
		Block: &tari_generated.Block{
			Header: &tari_generated.BlockHeader{Height: f.height},
		},
		MinerData: &tari_generated.MinerData{TargetDifficulty: f.targetDifficulty},
	}, nil
}

func (f *fakeDirectNodeClient) GetTipInfo(_ context.Context) (*tari_generated.TipInfoResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &tari_generated.TipInfoResponse{Metadata: &tari_generated.MetaData{BestBlockHeight: f.height}}, nil
}

func (f *fakeDirectNodeClient) SubmitBlock(_ context.Context, _ *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	f.submitCalls.Add(1)
	return &tari_generated.SubmitBlockResponse{}, nil
}

var _ solo.NodeClient = (*fakeDirectNodeClient)(nil)

// fakeShareTransport is a transport.ShareTransport test double
// recording every forwarded share/block so tests can assert
// leaf-direct's genuinely new behavior vs. leaf-solo: every validated
// share (not just block finds) reaches the "backend".
type fakeShareTransport struct {
	mu     sync.Mutex
	shares []*poolpb.Share
	blocks []*poolpb.Block
}

func (f *fakeShareTransport) SubmitShare(_ context.Context, share *poolpb.Share) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shares = append(f.shares, share)
	return nil
}

func (f *fakeShareTransport) SubmitBlock(_ context.Context, block *poolpb.Block) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocks = append(f.blocks, block)
	return nil
}

func (f *fakeShareTransport) shareCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.shares)
}

func (f *fakeShareTransport) blockCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.blocks)
}

func (f *fakeShareTransport) Close() error { return nil }

// fakeAcceptingBlockClient is a blockSubmitClient test double that
// always accepts, for wiring the Server's MultiSubmit path in tests
// that need a genuine block-find to succeed end-to-end.
type fakeAcceptingBlockClient struct {
	calls atomic.Int64
}

func (f *fakeAcceptingBlockClient) SubmitBlock(_ *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	f.calls.Add(1)
	return &tari_generated.SubmitBlockResponse{}, nil
}

func (f *fakeAcceptingBlockClient) Close() error { return nil }

// directTestHarness mirrors solo/session_test.go's own testHarness
// exactly in spirit: a real Server (real ConnectionManager, real
// SHA3XValidator, fake NodeClient/transport/multi-submit) driven over
// an in-process net.Pipe connection pair, speaking the exact same real
// wire dialect leaf-solo's own tests exercise.
type directTestHarness struct {
	t         *testing.T
	server    *Server
	jm        *solo.JobManager
	node      *fakeDirectNodeClient
	transport *fakeShareTransport
	submit    *fakeAcceptingBlockClient
	client    net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	cancel    context.CancelFunc
}

func newDirectTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64) *directTestHarness {
	t.Helper()
	node := &fakeDirectNodeClient{
		height:          42,
		mergeMiningHash: []byte("direct-test-merge-mining-hash-3"),
	}
	node.targetDifficulty = networkTargetDiff
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
	})

	v := validator.NewSHA3XValidator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v}

	tr := &fakeShareTransport{}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm,
		JobManager:        jm,
		Validators:        registry,
		Network:           poolpb.Network_NETWORK_TESTNET,
		Transport:         tr,
		MultiSubmit:       multi,
		Algo:              poolpb.Algo_ALGO_SHA3X,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
	})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr, submit: sub,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
	})
	return h
}

func (h *directTestHarness) send(req solo.Request) {
	h.t.Helper()
	req.JsonRPC = "2.0"
	buf, err := json.Marshal(req)
	if err != nil {
		h.t.Fatalf("marshal request: %v", err)
	}
	buf = append(buf, '\n')
	if _, err := h.writer.Write(buf); err != nil {
		h.t.Fatalf("write request: %v", err)
	}
	if err := h.writer.Flush(); err != nil {
		h.t.Fatalf("flush request: %v", err)
	}
}

func (h *directTestHarness) recvRaw() []byte {
	h.t.Helper()
	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := h.reader.ReadBytes('\n')
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	return line
}

func (h *directTestHarness) recvLoginResponse() solo.LoginResponse {
	h.t.Helper()
	var resp solo.LoginResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal login response: %v", err)
	}
	return resp
}

func (h *directTestHarness) recvShareResponse() solo.ShareResponse {
	h.t.Helper()
	var resp solo.ShareResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal share response: %v", err)
	}
	return resp
}

func (h *directTestHarness) recvErrorResponse() solo.ErrorResponse {
	h.t.Helper()
	var resp solo.ErrorResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal error response: %v", err)
	}
	return resp
}

func directLogin(t *testing.T, h *directTestHarness, address string) (sessionID, xn string) {
	t.Helper()
	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: address, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.ID, resp.Result.Job.XN
}

func directCurrentJobIDForXN(t *testing.T, h *directTestHarness, xn string) string {
	t.Helper()
	job, err := h.jm.JobForXN(context.Background(), xn)
	if err != nil {
		t.Fatalf("JobForXN(%q): %v", xn, err)
	}
	return job.ID
}

func directXNPrefixedNonceHex(xn string, n uint64) string {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, n)
	full := hex.EncodeToString(buf)
	return xn + full[len(xn):]
}

func mustDirectJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	buf, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return buf
}

// TestDirectSessionLoginPushesInitialJob is the basic real wire-level
// login/getjob smoke test for leaf-direct's own Session/Server (reused
// solo wire types, leaf-direct's own handler logic).
func TestDirectSessionLoginPushesInitialJob(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: "some-tari-address", Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()

	if resp.Result.Status != "OK" {
		t.Errorf("result status = %q, want OK", resp.Result.Status)
	}
	if resp.Result.ID == "" {
		t.Error("expected a non-empty session id in the login response")
	}
	if resp.Result.Job.JobID == "" {
		t.Error("expected a non-empty job_id in the login-pushed job")
	}
	if resp.Result.Job.XN == "" || len(resp.Result.Job.XN) != 4 {
		t.Errorf("expected a 4-hex-char xn, got %q", resp.Result.Job.XN)
	}
}

func TestDirectSessionGetJobWithoutLoginIsRejected(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)

	h.send(solo.Request{ID: 5, Method: "getjob"})
	resp := h.recvErrorResponse()

	if resp.Error == "" {
		t.Error("expected getjob before login to be rejected with an error")
	}
}

// TestDirectSessionSubmitValidBelowBlockDifficulty is leaf-direct's own
// version of solo's equivalent test, but ALSO asserts the genuinely
// new behavior: every validated share (not just block finds) is
// forwarded to the backend transport, and MultiSubmit is NOT invoked
// since this share does not meet block difficulty.
func TestDirectSessionSubmitValidBelowBlockDifficulty(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1<<62)
	sessionID, xn := directLogin(t, h, "addr-1")

	jobID := directCurrentJobIDForXN(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 12345),
	})})
	resp := h.recvShareResponse()

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if !resp.Result {
		t.Fatalf("expected result=true for an accepted share, got %#v", resp)
	}
	if h.submit.calls.Load() != 0 {
		t.Errorf("MultiSubmit.SubmitBlock should not have been called, got %d calls", h.submit.calls.Load())
	}
	if h.transport.shareCount() != 1 {
		t.Errorf("expected exactly 1 share forwarded to the backend transport, got %d", h.transport.shareCount())
	}
	if h.transport.blockCount() != 0 {
		t.Errorf("expected 0 blocks forwarded to the backend transport, got %d", h.transport.blockCount())
	}
	if got := h.transport.shares[0].GetPoolType(); got != poolpb.PoolType_POOL_TYPE_SOLO {
		t.Errorf("forwarded share must carry the server's configured PoolType (SOLO), got %v", got)
	}
}

// TestDirectSessionSubmitMeetingBlockDifficulty exercises the full
// genuine-block-find path: staticDiff=1/networkTargetDiff=1 both
// virtually guaranteed to be met, exercising real parallel multi-node
// GRPC submission (via the injected fakeAcceptingBlockClient) AND the
// real backend block-report forward, both of which are leaf-direct's
// own genuinely new wiring vs. leaf-solo.
func TestDirectSessionSubmitMeetingBlockDifficulty(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1)
	sessionID, xn := directLogin(t, h, "addr-2")

	jobID := directCurrentJobIDForXN(t, h, xn)
	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 999),
	})})
	resp := h.recvShareResponse()

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if !resp.Result {
		t.Fatalf("expected result=true for a block-finding share, got %#v", resp)
	}
	if h.submit.calls.Load() != 1 {
		t.Errorf("expected exactly 1 MultiSubmit.SubmitBlock call, got %d", h.submit.calls.Load())
	}
	if h.transport.shareCount() != 1 {
		t.Errorf("expected the block-finding submit to ALSO forward a share, got %d", h.transport.shareCount())
	}
	// forwardBlock runs on the session's handling goroutine AFTER the
	// wire response has already been flushed (see handleSubmit's own
	// ordering), so the test's own read of the response can race the
	// session goroutine's subsequent forwardBlock call — poll briefly
	// rather than asserting immediately.
	deadline := time.Now().Add(2 * time.Second)
	for h.transport.blockCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.transport.blockCount() != 1 {
		t.Errorf("expected exactly 1 block forwarded to the backend transport, got %d", h.transport.blockCount())
	}
	if got := h.transport.shares[0].GetPoolType(); got != poolpb.PoolType_POOL_TYPE_SOLO {
		t.Errorf("forwarded block-finding share must carry the server's configured PoolType (SOLO), got %v", got)
	}
	h.transport.mu.Lock()
	blocksLen := len(h.transport.blocks)
	var blockPoolType poolpb.PoolType
	if blocksLen > 0 {
		blockPoolType = h.transport.blocks[0].GetPoolType()
	}
	h.transport.mu.Unlock()
	if blocksLen > 0 && blockPoolType != poolpb.PoolType_POOL_TYPE_SOLO {
		t.Errorf("forwarded block must carry the server's configured PoolType (SOLO), got %v", blockPoolType)
	}
}

func TestDirectSessionSubmitCryptographicallyInvalid(t *testing.T) {
	h := newDirectTestHarness(t, 1<<63, 1<<63)
	sessionID, xn := directLogin(t, h, "addr-3")

	jobID := directCurrentJobIDForXN(t, h, xn)
	h.send(solo.Request{ID: 4, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvShareResponse()

	if resp.Error == "" {
		t.Fatal("expected an error for a share that fails PoW validation")
	}
	if resp.Result {
		t.Fatalf("expected result=false for an invalid share, got %#v", resp)
	}
	if h.submit.calls.Load() != 0 {
		t.Errorf("MultiSubmit.SubmitBlock must not be called for an invalid share, got %d calls", h.submit.calls.Load())
	}
	if h.transport.shareCount() != 0 {
		t.Errorf("an invalid share must not be forwarded to the backend, got %d forwards", h.transport.shareCount())
	}
}

func TestDirectSessionSubmitUnknownJobIDIsRejected(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)
	sessionID, xn := directLogin(t, h, "addr-4")

	h.send(solo.Request{ID: 6, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:    sessionID,
		JobID: "0000000000000000",
		Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvShareResponse()

	if resp.Error == "" {
		t.Fatal("expected an error for an unknown job_id")
	}
	if resp.Result {
		t.Error("expected result=false for an unknown job_id")
	}
}

func TestDirectSessionSubmitDuplicateNonceIsRejected(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1<<62)
	sessionID, xn := directLogin(t, h, "addr-6")

	jobID := directCurrentJobIDForXN(t, h, xn)
	submit := func() solo.ShareResponse {
		h.send(solo.Request{ID: 7, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			ID:    sessionID,
			JobID: jobID,
			Nonce: directXNPrefixedNonceHex(xn, 42424242),
		})})
		return h.recvShareResponse()
	}

	first := submit()
	if !first.Result {
		t.Fatalf("expected the first submission of a nonce to be accepted, got %#v", first)
	}
	second := submit()
	if second.Result {
		t.Fatal("expected a replayed nonce to be rejected")
	}
	if second.Error == "" {
		t.Error("expected an error message on a replayed-nonce rejection")
	}
}

// TestDirectSessionSubmitAgainstAnotherSessionsJobIsRejected is the
// required real job-ownership security test: confirms leaf-direct's
// own Session.ownJob (session.go, ported verbatim from solo's own
// SECURITY FIX for PR #14) genuinely rejects a submit against another
// session's job_id — session B submits against session A's job_id,
// using session A's sessionID and a nonce prefixed with session A's
// OWN xn (so the xn-prefix check alone would NOT catch this), proving
// the rejection can only be explained by the real per-session
// jobLog/ownJob boundary, not some other incidental check.
func TestDirectSessionSubmitAgainstAnotherSessionsJobIsRejected(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1)

	serverConnA, clientA := net.Pipe()
	serverConnB, clientB := net.Pipe()
	ctx := context.Background()
	go h.server.handleConn(ctx, serverConnA, 1)
	go h.server.handleConn(ctx, serverConnB, 1)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	hA := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientA, reader: bufio.NewReader(clientA), writer: bufio.NewWriter(clientA)}
	hB := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientB, reader: bufio.NewReader(clientB), writer: bufio.NewWriter(clientB)}

	sessionIDA, xnA := directLogin(t, hA, "addr-owner-a")
	_, xnB := directLogin(t, hB, "addr-attacker-b")
	if xnA == xnB {
		t.Fatalf("expected sessions A and B to get different xn values, both got %q", xnA)
	}

	jobIDA := directCurrentJobIDForXN(t, hA, xnA)

	hB.send(solo.Request{ID: 20, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:    sessionIDA,
		JobID: jobIDA,
		Nonce: directXNPrefixedNonceHex(xnA, 999),
	})})
	resp := hB.recvShareResponse()

	if resp.Result {
		t.Fatal("SECURITY REGRESSION: session B's submit against session A's real job was ACCEPTED — cross-session job submission must be structurally impossible in leaf-direct")
	}
	if resp.Error == "" {
		t.Fatal("expected a clear rejection error for a cross-session job submission")
	}
	if !strings.Contains(resp.Error, "unknown or stale job_id") {
		t.Errorf("expected rejection to be classed as \"unknown or stale job_id\" (the session-ownership boundary), got %q", resp.Error)
	}
	if h.submit.calls.Load() != 0 {
		t.Errorf("MultiSubmit.SubmitBlock must NOT be called for a cross-session job submission, got %d calls", h.submit.calls.Load())
	}
	if h.transport.shareCount() != 0 {
		t.Errorf("a cross-session-rejected submit must not be forwarded to the backend, got %d forwards", h.transport.shareCount())
	}
}
