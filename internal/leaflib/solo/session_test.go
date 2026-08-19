// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// testHarness wires a real Server (real ConnectionManager, real
// SHA3XValidator, fake NodeClient) around an in-process net.Pipe
// connection pair, so miner-protocol handling can be exercised without
// a real TCP socket or a real Tari base node.
type testHarness struct {
	t      *testing.T
	server *Server
	cm     *leaflib.ConnectionManager
	jm     *JobManager
	node   *fakeNodeClient
	client net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	cancel context.CancelFunc
}

func newTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64) *testHarness {
	t.Helper()
	node := &fakeNodeClient{height: 42, targetDifficulty: networkTargetDiff, mergeMiningHash: []byte("test-merge-mining-hash-32bytes!")}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
	})
	if _, err := jm.Refresh(context.Background()); err != nil {
		t.Fatalf("initial job refresh: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	v := validator.NewSHA3XValidator()
	server := NewServer(cm, jm, node, v, poolpb.Network_NETWORK_TESTNET, nil)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn)

	h := &testHarness{
		t:      t,
		server: server,
		cm:     cm,
		jm:     jm,
		node:   node,
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

func (h *testHarness) send(req Request) {
	h.t.Helper()
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

func (h *testHarness) recv() Response {
	h.t.Helper()
	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := h.reader.ReadBytes('\n')
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		h.t.Fatalf("unmarshal response %q: %v", line, err)
	}
	return resp
}

func TestSessionLoginPushesInitialJob(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginParams{Address: "some-tari-address", Worker: "rig1"})})
	resp := h.recv()

	if resp.ID != 1 {
		t.Errorf("response ID = %d, want 1", resp.ID)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error in login response: %s", resp.Error)
	}

	resultMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("login result has unexpected shape: %#v", resp.Result)
	}
	if resultMap["status"] != "ok" {
		t.Errorf("login status = %v, want ok", resultMap["status"])
	}
	job, ok := resultMap["job"].(map[string]any)
	if !ok {
		t.Fatalf("login result missing job payload: %#v", resultMap)
	}
	if job["job_id"] == "" || job["job_id"] == nil {
		t.Error("expected a non-empty job_id in the login-pushed job")
	}
}

func TestSessionGetJobWithoutLoginIsRejected(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	h.send(Request{ID: 5, Method: "getjob"})
	resp := h.recv()

	if resp.Error == "" {
		t.Error("expected getjob before login to be rejected with an error")
	}
}

// TestSessionSubmitValidBelowBlockDifficulty exercises the "valid,
// doesn't meet block difficulty" path: staticDiff is set low enough that
// SHA3XValidator.Validate accepts virtually any nonce, but
// networkTargetDiff is set to (near) the maximum uint64, which no real
// hash-derived difficulty will realistically reach — so the share is
// counted locally but never submitted as a block.
func TestSessionSubmitValidBelowBlockDifficulty(t *testing.T) {
	h := newTestHarness(t, 1, math.MaxUint64)
	login(t, h, "addr-1")

	jobID := currentJobID(t, h)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitParams{
		JobID: jobID,
		Nonce: nonceHex(12345),
	})})
	resp := h.recv()

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["status"] != StatusOK {
		t.Fatalf("expected status %q, got %#v", StatusOK, resp.Result)
	}
	if h.node.submitCalls.Load() != 0 {
		t.Errorf("SubmitBlock should not have been called, got %d calls", h.node.submitCalls.Load())
	}
	stats := h.server.Stats()
	if stats.TotalShares != 1 {
		t.Errorf("TotalShares = %d, want 1", stats.TotalShares)
	}
	if stats.TotalBlocks != 0 {
		t.Errorf("TotalBlocks = %d, want 0", stats.TotalBlocks)
	}
}

// TestSessionSubmitMeetingBlockDifficulty exercises the full "valid AND
// meets block difficulty -> real SubmitBlock call" path. staticDiff=1
// and networkTargetDiff=1 are both satisfied by virtually any
// hash-derived difficulty (see validator/sha3x.go's algorithm — the
// derived difficulty is essentially never below 1 for a real 32-byte
// hash output), making this deterministic without brute-forcing a
// nonce.
func TestSessionSubmitMeetingBlockDifficulty(t *testing.T) {
	h := newTestHarness(t, 1, 1)
	login(t, h, "addr-2")

	jobID := currentJobID(t, h)
	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitParams{
		JobID: jobID,
		Nonce: nonceHex(999),
	})})
	resp := h.recv()

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["status"] != StatusBlockFound {
		t.Fatalf("expected status %q, got %#v", StatusBlockFound, resp.Result)
	}
	if h.node.submitCalls.Load() != 1 {
		t.Errorf("expected exactly 1 SubmitBlock call, got %d", h.node.submitCalls.Load())
	}
	stats := h.server.Stats()
	if stats.TotalBlocks != 1 {
		t.Errorf("TotalBlocks = %d, want 1", stats.TotalBlocks)
	}
}

// TestSessionSubmitCryptographicallyInvalid exercises the rejection
// path: staticDiff is set to (near) the maximum uint64, which no
// real hash-derived difficulty will realistically reach, so
// SHA3XValidator.Validate reports the share invalid.
func TestSessionSubmitCryptographicallyInvalid(t *testing.T) {
	h := newTestHarness(t, math.MaxUint64, math.MaxUint64)
	login(t, h, "addr-3")

	jobID := currentJobID(t, h)
	h.send(Request{ID: 4, Method: "submit", Params: mustJSON(t, SubmitParams{
		JobID: jobID,
		Nonce: nonceHex(1),
	})})
	resp := h.recv()

	if resp.Error == "" {
		t.Fatal("expected an error for a share that fails PoW validation")
	}
	result, ok := resp.Result.(map[string]any)
	if !ok || result["status"] != StatusRejected {
		t.Fatalf("expected status %q, got %#v", StatusRejected, resp.Result)
	}
	if h.node.submitCalls.Load() != 0 {
		t.Errorf("SubmitBlock must not be called for an invalid share, got %d calls", h.node.submitCalls.Load())
	}
	stats := h.server.Stats()
	if stats.TotalShares != 0 {
		t.Errorf("TotalShares = %d, want 0 for a rejected share", stats.TotalShares)
	}
}

func TestSessionSubmitUnknownJobIDIsRejected(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)
	login(t, h, "addr-4")

	h.send(Request{ID: 6, Method: "submit", Params: mustJSON(t, SubmitParams{
		JobID: "not-a-real-job-id",
		Nonce: nonceHex(1),
	})})
	resp := h.recv()

	if resp.Error == "" {
		t.Fatal("expected an error for an unknown job_id")
	}
}

// TestManagedConnectionLifecycleUsedNotBypassed confirms the session is
// riding on ManagedConnection's real lifecycle guarantees: closing the
// underlying pipe from the client side should eventually cause the
// server-side ManagedConnection to be torn down and deregistered from
// the ConnectionManager, without the session's read loop needing to
// implement its own cleanup.
func TestManagedConnectionLifecycleUsedNotBypassed(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)
	login(t, h, "addr-5")

	if h.cm.Count() != 1 {
		t.Fatalf("expected 1 registered connection after login, got %d", h.cm.Count())
	}

	_ = h.client.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.cm.Count() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected ConnectionManager to deregister the connection after client close, still has %d", h.cm.Count())
}

func login(t *testing.T, h *testHarness, address string) {
	t.Helper()
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginParams{Address: address, Worker: "rig1"})})
	resp := h.recv()
	if resp.Error != "" {
		t.Fatalf("login failed: %s", resp.Error)
	}
}

func currentJobID(t *testing.T, h *testHarness) string {
	t.Helper()
	job := h.jm.Current()
	if job == nil {
		t.Fatal("no current job")
	}
	return job.ID
}

func nonceHex(n uint64) string {
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		buf[i] = byte(n >> (8 * i))
	}
	return hex.EncodeToString(buf)
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	buf, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return buf
}
