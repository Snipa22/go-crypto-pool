// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// testHarness wires a real Server (real ConnectionManager, real
// SHA3XValidator, fake NodeClient) around an in-process net.Pipe
// connection pair, so miner-protocol handling can be exercised without
// a real TCP socket or a real Tari base node. It speaks the real
// Monero-style JSON-RPC 2.0 stratum dialect (protocol.go) over that
// pipe, not the legacy custom JSON-line protocol.
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
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: networkTargetDiff,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
	})

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

// recvRaw reads one raw newline-delimited wire line, for assertions
// that need the literal JSON bytes (real wire-shape verification), not
// just a decoded Go value.
func (h *testHarness) recvRaw() []byte {
	h.t.Helper()
	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := h.reader.ReadBytes('\n')
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	return line
}

func (h *testHarness) recvLoginResponse() LoginResponse {
	h.t.Helper()
	var resp LoginResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal login response: %v", err)
	}
	return resp
}

func (h *testHarness) recvShareResponse() ShareResponse {
	h.t.Helper()
	var resp ShareResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal share response: %v", err)
	}
	return resp
}

func (h *testHarness) recvErrorResponse() ErrorResponse {
	h.t.Helper()
	var resp ErrorResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal error response: %v", err)
	}
	return resp
}

func TestSessionLoginPushesInitialJob(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: "some-tari-address", Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()

	if resp.ID != 1 {
		t.Errorf("response ID = %d, want 1", resp.ID)
	}
	if resp.JsonRPC != "2.0" {
		t.Errorf("response jsonrpc = %q, want 2.0", resp.JsonRPC)
	}
	if resp.Status != "OK" {
		t.Errorf("response status = %q, want OK", resp.Status)
	}
	if resp.Result.Status != "OK" {
		t.Errorf("result status = %q, want OK", resp.Result.Status)
	}
	if resp.Result.ID == "" {
		t.Error("expected a non-empty session id in the login response")
	}
	if resp.Result.Job.JobID == "" {
		t.Error("expected a non-empty job_id in the login-pushed job")
	}
	if resp.Result.Job.Algo != "sha3x" {
		t.Errorf("job algo = %q, want sha3x", resp.Result.Job.Algo)
	}
	if resp.Result.Job.Blob == "" {
		t.Error("expected a non-empty blob in the login-pushed job")
	}
	if resp.Result.Job.Target == "" {
		t.Error("expected a non-empty target in the login-pushed job")
	}
	// Real per-session extranonce (xn) requirement: graxil and other
	// real miner software hard-requires this field to be present — see
	// job.go/protocol.go doc comments for the production crash this
	// fixes. Must be exactly 4 hex characters (2 bytes), matching
	// go-tari-sha3x-solo-stratum's xn sizing exactly.
	if resp.Result.Job.XN == "" {
		t.Fatal("expected a non-empty xn in the login-pushed job")
	}
	if len(resp.Result.Job.XN) != 4 {
		t.Errorf("xn length = %d, want 4 hex characters (2 bytes)", len(resp.Result.Job.XN))
	}
	if _, err := hex.DecodeString(resp.Result.Job.XN); err != nil {
		t.Errorf("xn %q is not valid hex: %v", resp.Result.Job.XN, err)
	}
	// Real wire encoding check: target must decode to exactly 8 raw
	// bytes (a little-endian uint64), matching
	// go-tari-sha3x-solo-stratum's diffToTarget encoding exactly.
	targetBytes, err := hex.DecodeString(resp.Result.Job.Target)
	if err != nil || len(targetBytes) != 8 {
		t.Fatalf("target %q must be 8 hex-encoded bytes, got %d bytes, err=%v", resp.Result.Job.Target, len(targetBytes), err)
	}
	gotTarget := binary.LittleEndian.Uint64(targetBytes)
	wantTarget := uint64(math.MaxUint64) / 1000
	if gotTarget != wantTarget {
		t.Errorf("decoded target = %d, want %d (2^64-1 / difficulty=1000)", gotTarget, wantTarget)
	}
	// job_id must be exactly 16 hex characters (first 16 hex chars of
	// the block hash), matching go-tari-sha3x-solo-stratum exactly.
	if len(resp.Result.Job.JobID) != 16 {
		t.Errorf("job_id length = %d, want 16", len(resp.Result.Job.JobID))
	}
}

func TestSessionGetJobWithoutLoginIsRejected(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	h.send(Request{ID: 5, Method: "getjob"})
	resp := h.recvErrorResponse()

	if resp.Error == "" {
		t.Error("expected getjob before login to be rejected with an error")
	}
	if resp.Result != "" {
		t.Errorf("error response result must be the empty string, got %q", resp.Result)
	}
}

// TestSessionSubmitValidBelowBlockDifficulty exercises the "valid,
// doesn't meet block difficulty" path: staticDiff is set low enough that
// SHA3XValidator.Validate accepts virtually any nonce, but
// networkTargetDiff is set to (near) the maximum uint64, which no real
// hash-derived difficulty will realistically reach — so the share is
// counted locally but never submitted as a block. On the real wire,
// this is indistinguishable from any other accepted share: a bare
// {"result":true}.
func TestSessionSubmitValidBelowBlockDifficulty(t *testing.T) {
	h := newTestHarness(t, 1, math.MaxUint64)
	sessionID, xn := login(t, h, "addr-1")

	jobID := currentJobIDForXN(t, h, xn)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 12345),
	})})
	resp := h.recvShareResponse()

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if !resp.Result {
		t.Fatalf("expected result=true for an accepted share, got %#v", resp)
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
// nonce. On the real wire, a block-find and an ordinary accepted share
// both surface identically as {"result":true} — there is no separate
// "block found" wire status in the real dialect.
//
// This is also the REGRESSION GUARD that the existing accept path still
// works correctly with the new xn-prefix check added in front of it:
// the nonce here is correctly xn-prefixed AND cryptographically valid,
// so it must still be accepted exactly as before xn support was added.
func TestSessionSubmitMeetingBlockDifficulty(t *testing.T) {
	h := newTestHarness(t, 1, 1)
	sessionID, xn := login(t, h, "addr-2")

	jobID := currentJobIDForXN(t, h, xn)
	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 999),
	})})
	resp := h.recvShareResponse()

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if !resp.Result {
		t.Fatalf("expected result=true for a block-finding share, got %#v", resp)
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
	sessionID, xn := login(t, h, "addr-3")

	jobID := currentJobIDForXN(t, h, xn)
	h.send(Request{ID: 4, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvShareResponse()

	if resp.Error == "" {
		t.Fatal("expected an error for a share that fails PoW validation")
	}
	if resp.Result {
		t.Fatalf("expected result=false for an invalid share, got %#v", resp)
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
	sessionID, xn := login(t, h, "addr-4")

	h.send(Request{ID: 6, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: "0000000000000000",
		Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvShareResponse()

	if resp.Error == "" {
		t.Fatal("expected an error for an unknown job_id")
	}
	if resp.Result {
		t.Error("expected result=false for an unknown job_id")
	}
}

// TestSessionSubmitDuplicateNonceIsRejected exercises the per-job
// used-nonce tracking that is REQUIRED to carry over from the legacy
// reference (UsedNonces/NonceMutex in minerTracking/structs.go) even
// though the wire format changed: resubmitting the same nonce against
// the same job must be rejected the second time, without being
// credited twice.
func TestSessionSubmitDuplicateNonceIsRejected(t *testing.T) {
	h := newTestHarness(t, 1, math.MaxUint64)
	sessionID, xn := login(t, h, "addr-6")

	jobID := currentJobIDForXN(t, h, xn)
	submit := func() ShareResponse {
		h.send(Request{ID: 7, Method: "submit", Params: mustJSON(t, SubmitRequest{
			ID:    sessionID,
			JobID: jobID,
			Nonce: xnPrefixedNonceHex(xn, 42424242),
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

	stats := h.server.Stats()
	if stats.TotalShares != 1 {
		t.Errorf("TotalShares = %d, want 1 (replay must not be credited again)", stats.TotalShares)
	}
}

// TestSessionSubmitWithWrongXNPrefixIsRejectedBeforeValidation is the
// core new requirement: a submit whose nonce does NOT carry the
// session's own assigned xn as a hex prefix must be rejected outright
// — BEFORE any PoW validation work happens — ported from
// go-tari-sha3x-solo-stratum's miner.go SubmitJob
// (`strings.HasPrefix(strings.ToLower(submittedWork.Nonce), m.xn)`).
// staticDiff/networkTargetDiff are both set to 1 (i.e. this nonce WOULD
// have been cryptographically valid and even block-finding, were it not
// for the xn mismatch) specifically so a false accept can only be
// explained by the xn check being skipped, not by the nonce
// coincidentally failing PoW too.
func TestSessionSubmitWithWrongXNPrefixIsRejectedBeforeValidation(t *testing.T) {
	h := newTestHarness(t, 1, 1)
	sessionID, xn := login(t, h, "addr-8")

	wrongXN := "ffff"
	if wrongXN == xn {
		wrongXN = "0000"
	}

	jobID := currentJobIDForXN(t, h, xn)
	h.send(Request{ID: 9, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(wrongXN, 999),
	})})
	resp := h.recvShareResponse()

	if resp.Result {
		t.Fatal("expected a submit with a nonce not prefixed by the session's own xn to be rejected")
	}
	if resp.Error == "" {
		t.Error("expected a clear rejection error for an xn-prefix mismatch")
	}
	if !strings.Contains(strings.ToLower(resp.Error), "xnonce") {
		t.Errorf("expected the rejection error to mention XNonce, got %q", resp.Error)
	}
	// Nothing downstream of the xn check must have run: no share
	// credited, no SubmitBlock call, even though this nonce/job would
	// otherwise have been both a valid share AND a block find.
	if h.node.submitCalls.Load() != 0 {
		t.Errorf("SubmitBlock must not be called when the xn-prefix check fails, got %d calls", h.node.submitCalls.Load())
	}
	stats := h.server.Stats()
	if stats.TotalShares != 0 {
		t.Errorf("TotalShares = %d, want 0 for an xn-prefix-rejected submit", stats.TotalShares)
	}
	if stats.TotalBlocks != 0 {
		t.Errorf("TotalBlocks = %d, want 0 for an xn-prefix-rejected submit", stats.TotalBlocks)
	}
}

// TestTwoSessionsGetDifferentXNsAndDifferentJobs is the multi-session
// requirement at the protocol/session layer (job_test.go covers the
// same guarantee at the JobManager layer directly): two independently
// logged-in sessions against the same server, at the same height, must
// be handed different xn values and different job_ids/blobs — a real
// miner pointed at go-crypto-pool's solo leaf must not collide with
// another miner's search space.
func TestTwoSessionsGetDifferentXNsAndDifferentJobs(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	serverConnA, clientA := net.Pipe()
	serverConnB, clientB := net.Pipe()
	ctx := context.Background()
	go h.server.handleConn(ctx, serverConnA)
	go h.server.handleConn(ctx, serverConnB)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	hA := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientA, reader: bufio.NewReader(clientA), writer: bufio.NewWriter(clientA)}
	hB := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientB, reader: bufio.NewReader(clientB), writer: bufio.NewWriter(clientB)}

	_, xnA := login(t, hA, "addr-multi-a")
	_, xnB := login(t, hB, "addr-multi-b")

	if xnA == xnB {
		t.Fatalf("expected two independently-connected sessions to get different xn values, both got %q (collision probability is 1/65536 per pair — if this genuinely flakes, widen the assertion, but treat a repeat failure as a real bug)", xnA)
	}

	jobIDA := currentJobIDForXN(t, hA, xnA)
	jobIDB := currentJobIDForXN(t, hB, xnB)
	if jobIDA == jobIDB {
		t.Fatalf("expected two different xns to be served two different job_ids at the same height, both got %q", jobIDA)
	}
}

// login performs a real login handshake and returns the session id the
// server handed back (LoginResult.ID) and the session's own assigned
// xn (LoginResult.Job.XN), which real submits must echo/prefix
// respectively.
func login(t *testing.T, h *testHarness, address string) (sessionID, xn string) {
	t.Helper()
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: address, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.ID, resp.Result.Job.XN
}

// currentJobIDForXN looks up the current job for a given already-issued
// xn directly from the shared JobManager (mirroring what the session
// itself would resolve via JobForXN).
func currentJobIDForXN(t *testing.T, h *testHarness, xn string) string {
	t.Helper()
	job, err := h.jm.JobForXN(context.Background(), xn)
	if err != nil {
		t.Fatalf("JobForXN(%q): %v", xn, err)
	}
	return job.ID
}

// xnPrefixedNonceHex builds an 8-byte, hex-encoded nonce whose leading
// hex characters are exactly xn, matching the real wire convention
// go-tari-sha3x-solo-stratum's miners are expected to follow
// (session.go's handleSubmit checks strings.HasPrefix on the hex
// string, not on the decoded bytes' numeric value).
func xnPrefixedNonceHex(xn string, n uint64) string {
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		buf[i] = byte(n >> (8 * i))
	}
	full := hex.EncodeToString(buf)
	return xn + full[len(xn):]
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	buf, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return buf
}
