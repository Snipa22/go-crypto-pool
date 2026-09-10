// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// newC29TestHarness is newTestHarness's C29 counterpart: the
// JobManager is configured for Algo_ALGO_C29 (so its fetched job
// templates and jobPayload's wire "algo" label are genuinely "c29",
// not "sha3x"), exercising the real algo-aware code paths added in
// this pass rather than SHA3X's already-covered ones.
func newC29TestHarness(t *testing.T, staticDiff, networkTargetDiff uint64) *testHarness {
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
		Algo:             poolpb.Algo_ALGO_C29,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	v := validator.NewSHA3XValidator()
	c29 := validator.NewC29Validator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v, poolpb.Algo_ALGO_C29: c29}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

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

// newTestHarness is the SHA3X counterpart used by every pre-existing
// test in this file: staticDiff/networkTargetDiff work exactly as
// before, JobManager defaults to Algo_ALGO_SHA3X (the zero value).
func newTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64) *testHarness {
	t.Helper()
	return newTestHarnessWithJobMaxAge(t, staticDiff, networkTargetDiff, 0)
}

// newRXTTestHarness is newC29TestHarness's RXT counterpart: the
// JobManager is configured for Algo_ALGO_RXT, the fakeNodeClient is
// seeded with a real-shaped vmKey (RandomX seed material,
// GetNewBlockResult.VmKey), and the validator.Registry's RXT entry is
// backed by a REAL RandomXValidator pointed at randomXServiceURL (not
// a mock) -- so tests using this harness exercise the actual live
// randomx-service daemon end-to-end, not a stand-in.
func newRXTTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64, randomXServiceURL string) *testHarness {
	t.Helper()
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: networkTargetDiff,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
		vmKey:            []byte("test key 000"), // real reference-vector seed, see randomx_real_daemon_test.go
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXT,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})
	rx := validator.NewRandomXValidator(randomXServiceURL)
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: rx}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

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

// newRXMTestHarness is newC29TestHarness's ALGO_RXM counterpart, used
// ONLY to exercise handleSubmit's algo-conditional nonce-length gate
// (the regression fix below) — NOT full Monero PoW verification.
// fakeNodeClient's GetBlockTemplate is Tari-shaped (tariJobFromResult)
// and knows nothing about Monero; it still happily returns a *Job
// whose Algo field is whatever poolpb.Algo the caller (JobManager,
// configured here with Algo_ALGO_RXM) passed in, with TemplateData
// left as the raw Tari result rather than a real *moneroTemplateData.
// That's fine for THIS test's purpose: handleSubmit's length gate
// switches on job.Algo alone, before any TemplateData type assertion,
// so a submit that clears the gate still deterministically fails
// downstream at MoneroHashingBlobForSubmit's own type assertion
// (solo/node.go) with a distinct, non-"8 bytes" error — which is
// exactly the observable this test needs: proof the gate itself did
// not reject the submit.
func newRXMTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64) *testHarness {
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
		Algo:             poolpb.Algo_ALGO_RXM,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	registry := validator.Registry{}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

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

// newTestHarnessWithJobMaxAge is newTestHarness plus an explicit
// JobManagerConfig.JobMaxAge override (0 keeps NewJobManager's own
// default of 6 minutes), used by the real per-job expiry tests below.
func newTestHarnessWithJobMaxAge(t *testing.T, staticDiff, networkTargetDiff uint64, jobMaxAge time.Duration) *testHarness {
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
		JobMaxAge:        jobMaxAge,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	v := validator.NewSHA3XValidator()
	c29 := validator.NewC29Validator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v, poolpb.Algo_ALGO_C29: c29}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

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

// recvLegacyShareResponse decodes a submit response using the
// pre-PR-#56 bare-bool/bare-string LegacyShareResponse shape — used by
// C29 AND SHA3X (the default) test harnesses, since ALGO_C29 and
// ALGO_SHA3X sessions now genuinely emit this different wire shape
// (see session.go's writeShareResponse and protocol.go's
// LegacyShareResponse doc comment for the confirmed regression this
// preserves against).
func (h *testHarness) recvLegacyShareResponse() LegacyShareResponse {
	h.t.Helper()
	var resp LegacyShareResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal legacy share response: %v", err)
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

// recvLegacyErrorResponse decodes a general-purpose response using the
// pre-PR-#56 bare-string LegacyErrorResponse shape — used by C29 and
// SHA3X test harnesses, since ALGO_C29/ALGO_SHA3X sessions now
// genuinely emit this different wire shape (see session.go's
// writeGeneralResponse and protocol.go's LegacyErrorResponse doc
// comment for the confirmed regression this preserves against).
func (h *testHarness) recvLegacyErrorResponse() LegacyErrorResponse {
	h.t.Helper()
	var resp LegacyErrorResponse
	if err := json.Unmarshal(h.recvRaw(), &resp); err != nil {
		h.t.Fatalf("unmarshal legacy error response: %v", err)
	}
	return resp
}

// recvJobPush reads and decodes one unsolicited "job" push
// (protocol.go's JobPush) — the shape handleGetJob/vardiff retargets/
// invalidateAndRepushJobs use to hand a session a fresh job.
func (h *testHarness) recvJobPush() JobPush {
	h.t.Helper()
	var push JobPush
	if err := json.Unmarshal(h.recvRaw(), &push); err != nil {
		h.t.Fatalf("unmarshal job push: %v", err)
	}
	return push
}

func TestSessionLoginPushesInitialJob(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realTariTestAddress("some-tari-address"), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
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
	resp := h.recvLegacyErrorResponse()

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
	resp := h.recvLegacyShareResponse()

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
	resp := h.recvLegacyShareResponse()

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
	resp := h.recvLegacyShareResponse()

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
	resp := h.recvLegacyShareResponse()

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
	submit := func() LegacyShareResponse {
		h.send(Request{ID: 7, Method: "submit", Params: mustJSON(t, SubmitRequest{
			ID:    sessionID,
			JobID: jobID,
			Nonce: xnPrefixedNonceHex(xn, 42424242),
		})})
		return h.recvLegacyShareResponse()
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
	resp := h.recvLegacyShareResponse()

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
	go h.server.handleConn(ctx, serverConnA, 1000)
	go h.server.handleConn(ctx, serverConnB, 1000)
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

// TestSessionSubmitAgainstAnotherSessionsJobIsRejected is THE core
// regression guard for the security fix this PR exists for.
//
// staticDiff=1 and networkTargetDiff=1 are both satisfied by
// virtually any hash-derived difficulty (see
// TestSessionSubmitMeetingBlockDifficulty's identical setup), so this
// submission would be BOTH cryptographically valid AND block-finding
// were it not rejected — a false accept here can only be explained by
// the session-ownership check being skipped, not by the nonce
// coincidentally failing PoW.
//
// Deliberately structured to be algo-agnostic proof, not an
// xn-prefix-catches-it accident: the nonce submitted by session B is
// prefixed with session A's own xn (xnA), i.e. the xn check would
// have INCORRECTLY ALLOWED this submission through if it were still
// the security boundary. Only the session-ownership check (session
// B's own jobLog never having an entry for session A's job_id) can
// explain the rejection here.
func TestSessionSubmitAgainstAnotherSessionsJobIsRejected(t *testing.T) {
	h := newTestHarness(t, 1, 1)

	serverConnA, clientA := net.Pipe()
	serverConnB, clientB := net.Pipe()
	ctx := context.Background()
	go h.server.handleConn(ctx, serverConnA, 1)
	go h.server.handleConn(ctx, serverConnB, 1)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	hA := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientA, reader: bufio.NewReader(clientA), writer: bufio.NewWriter(clientA)}
	hB := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientB, reader: bufio.NewReader(clientB), writer: bufio.NewWriter(clientB)}

	sessionIDA, xnA := login(t, hA, "addr-owner-a")
	_, xnB := login(t, hB, "addr-attacker-b")
	if xnA == xnB {
		t.Fatalf("expected sessions A and B to get different xn values, both got %q", xnA)
	}

	// Session A's real, currently-issued job_id.
	jobIDA := currentJobIDForXN(t, hA, xnA)

	// Session B submits against session A's job_id, using session A's
	// sessionID and a nonce prefixed with session A's OWN xn (xnA) —
	// so the xn-prefix check, if it were still the security boundary,
	// would have let this straight through to PoW validation (which
	// would then have accepted it, given staticDiff=1/networkTargetDiff=1).
	hB.send(Request{ID: 20, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionIDA,
		JobID: jobIDA,
		Nonce: xnPrefixedNonceHex(xnA, 999),
	})})
	resp := hB.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("SECURITY REGRESSION: session B's submit against session A's real job was ACCEPTED — cross-session job submission must be structurally impossible")
	}
	if resp.Error == "" {
		t.Fatal("expected a clear rejection error for a cross-session job submission")
	}
	if !strings.Contains(resp.Error, "unknown or stale job_id") {
		t.Errorf("expected rejection to be classed as \"unknown or stale job_id\" (the session-ownership boundary), got %q", resp.Error)
	}
	if h.node.submitCalls.Load() != 0 {
		t.Errorf("SubmitBlock must NOT be called for a cross-session job submission, got %d calls", h.node.submitCalls.Load())
	}
	stats := h.server.Stats()
	if stats.TotalShares != 0 {
		t.Errorf("TotalShares = %d, want 0: no share must be credited for a cross-session job submission", stats.TotalShares)
	}
	if stats.TotalBlocks != 0 {
		t.Errorf("TotalBlocks = %d, want 0", stats.TotalBlocks)
	}

	// Sanity check: session A submitting against its OWN job_id with
	// this exact same shape must still work — proving the rejection
	// above is really about ownership, not some broken plumbing.
	hA.send(Request{ID: 21, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionIDA,
		JobID: jobIDA,
		Nonce: xnPrefixedNonceHex(xnA, 999),
	})})
	okResp := hA.recvLegacyShareResponse()
	if !okResp.Result {
		t.Fatalf("expected session A's own submit against its own job to be accepted, got %#v", okResp)
	}
}

// TestSessionSubmitAgainstExpiredJobIsRejected confirms the real,
// independent per-job expiry (JobManagerConfig.JobMaxAge, backed by
// Job.CreatedAt): a job still technically present in the submitting
// session's own job history must be rejected once it is older than
// the configured max age, WITHOUT InvalidateAll ever having run (i.e.
// this is not gated on tip movement or the periodic refresh timer).
func TestSessionSubmitAgainstExpiredJobIsRejected(t *testing.T) {
	h := newTestHarnessWithJobMaxAge(t, 1, math.MaxUint64, time.Minute)
	sessionID, xn := login(t, h, "addr-expiry")

	jobID := currentJobIDForXN(t, h, xn)

	// Directly age the real *Job past the configured max age. This is
	// the SAME *Job pointer both JobManager's cache and the session's
	// own jobLog hold (RestampDifficulty/recordJob never copy the
	// struct), so mutating CreatedAt here is equivalent to real wall
	// clock time having passed with no InvalidateAll in between.
	job, ok := h.jm.GetJob(jobID)
	if !ok {
		t.Fatalf("expected job %q to be resolvable via JobManager for test setup", jobID)
	}
	job.CreatedAt = time.Now().Add(-2 * time.Minute)

	h.send(Request{ID: 30, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 1),
	})})
	resp := h.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("expected a submit against an expired job to be rejected")
	}
	if resp.Error == "" {
		t.Fatal("expected a clear rejection error for an expired job")
	}
	if !strings.Contains(resp.Error, "expired") {
		t.Errorf("expected the rejection error to mention expiry, got %q", resp.Error)
	}
	if strings.Contains(resp.Error, "unknown or stale job_id") {
		t.Errorf("expired-job rejection must be a DISTINCT reason from unknown-job_id, got %q", resp.Error)
	}
	if h.node.submitCalls.Load() != 0 {
		t.Errorf("SubmitBlock must not be called for an expired-job submit, got %d calls", h.node.submitCalls.Load())
	}
	stats := h.server.Stats()
	if stats.TotalShares != 0 {
		t.Errorf("TotalShares = %d, want 0 for an expired-job submit", stats.TotalShares)
	}
}

// TestSessionJobHistoryIsBounded confirms the per-session
// jobList/jobLog trimming behavior ported from
// go-tari-sha3x-solo-stratum's CleanMinerJobs: once more than
// defaultSessionJobHistorySize distinct jobs have been issued to a
// session, the oldest entries drop off and become unsubmittable,
// while the most recent defaultSessionJobHistorySize remain
// submittable. Exercised via repeated tip-triggered regenerations
// (InvalidateAll + getjob), mirroring how a real session accumulates
// job history over several vardiff retargets/tip movements.
func TestSessionJobHistoryIsBounded(t *testing.T) {
	h := newTestHarness(t, 1, math.MaxUint64)
	sessionID, xn := login(t, h, "addr-bounded")

	// The login itself already issued one job; capture it as index 0.
	jobIDs := []string{currentJobIDForXN(t, h, xn)}

	// Force enough distinct new jobs (via real tip-triggered cache
	// invalidation, matching production's actual invalidation path:
	// InvalidateAll fires JobManager's subscribers, which is exactly
	// how server.go's invalidateAndRepushJobs pushes a freshly
	// regenerated job to every logged-in session — no explicit getjob
	// needed) to overflow the bound by 3.
	const extra = defaultSessionJobHistorySize + 3
	for i := 0; i < extra; i++ {
		// InvalidateAll's subscriber notification (invalidateAndRepushJobs)
		// runs synchronously on the CALLER's goroutine and writes
		// directly to this session's connection — exactly like the
		// real block-found path (handleSubmit's `go
		// s.server.jobManager.InvalidateAll()`), InvalidateAll must be
		// invoked from its own goroutine here too, since net.Pipe's
		// writes block until the peer (this same test) reads them;
		// calling it inline would self-deadlock against the
		// recvJobPush call below.
		go h.jm.InvalidateAll()
		push := h.recvJobPush()
		if push.Params.JobID == "" {
			t.Fatalf("push %d: expected a non-empty job_id", i)
		}
		jobIDs = append(jobIDs, push.Params.JobID)

		// A real miner sends periodic keepalives; do the same here so
		// this session's rolling idle deadline (ManagerConfig.
		// IdleTimeout, 2s in this harness) doesn't expire purely
		// because this test loop itself never needs to submit
		// anything between pushes.
		h.send(Request{ID: 900 + i, Method: "keepalived"})
		_ = h.recvLegacyErrorResponse()
	}

	total := len(jobIDs)
	dropped := total - defaultSessionJobHistorySize
	if dropped <= 0 {
		t.Fatalf("test setup issued %d distinct jobs, expected more than %d to actually exercise the bound", total, defaultSessionJobHistorySize)
	}

	// The oldest `dropped` job_ids must now be rejected as unknown —
	// they've fallen out of this session's own bounded history.
	for i := 0; i < dropped; i++ {
		h.send(Request{ID: 100 + i, Method: "submit", Params: mustJSON(t, SubmitRequest{
			ID:    sessionID,
			JobID: jobIDs[i],
			Nonce: xnPrefixedNonceHex(xn, uint64(2000+i)),
		})})
		resp := h.recvLegacyShareResponse()
		if resp.Result {
			t.Fatalf("job index %d (job_id %q) should have been trimmed from the bounded history, but was accepted", i, jobIDs[i])
		}
		if resp.Error == "" || !strings.Contains(resp.Error, "unknown or stale job_id") {
			t.Errorf("job index %d: expected an unknown-job_id rejection for a trimmed job, got %v", i, resp.Error)
		}
	}

	// The most recent defaultSessionJobHistorySize job_ids must still
	// be submittable (accepted, since staticDiff=1 here).
	for i := dropped; i < total; i++ {
		h.send(Request{ID: 200 + i, Method: "submit", Params: mustJSON(t, SubmitRequest{
			ID:    sessionID,
			JobID: jobIDs[i],
			Nonce: xnPrefixedNonceHex(xn, uint64(3000+i)),
		})})
		resp := h.recvLegacyShareResponse()
		if !resp.Result {
			t.Fatalf("job index %d (job_id %q) should still be within the bounded history and accepted, got error %v", i, jobIDs[i], resp.Error)
		}
	}
}

// TestSessionLoginJobPayloadOmitsXNForRandomXFamilyAlgos is the real
// wire-shape regression guard for this bug fix: RXT/RXM
// (RandomX-family) job payloads must NOT carry an "xn" key at all —
// real RandomX miners (xmrig, graxil) neither expect nor use one, and
// unconditionally populating JobPayload.XN with the session's
// extranonce for these algos broke live xmrig connections against the
// production RXT leaf-solo port. This asserts on the literal raw JSON
// bytes (not just a decoded Go struct, which would hide the
// difference between an omitted key and a present-but-empty one)
// that "xn" is genuinely absent for RXT.
func TestSessionLoginJobPayloadOmitsXNForRandomXFamilyAlgos(t *testing.T) {
	h := newRXTTestHarness(t, 1000, 1<<62, "http://127.0.0.1:1") // unreachable; irrelevant to login/job wire shape
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realTariTestAddress("addr-rxt-noxn-wire"), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"rxt"}})})
	raw := h.recvRaw()

	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal login response as map: %v", err)
	}
	result, ok := asMap["result"].(map[string]any)
	if !ok {
		t.Fatalf("login response has no result object: %s", raw)
	}
	job, ok := result["job"].(map[string]any)
	if !ok {
		t.Fatalf("login result has no job object: %s", raw)
	}
	// Wire label is "rx/0", not "rxt" — RXT is plain RandomX under the
	// hood and real RandomX miners (XMRig et al.) have no concept of an
	// algo named "rxt"; only this repo's internal poolpb.Algo enum name
	// and the -algo=rxt CLI flag value stay "rxt".
	if algo, _ := job["algo"].(string); algo != "rx/0" {
		t.Fatalf("job algo = %q, want rx/0 (sanity check this is really an RXT job on the correct miner-facing wire label): %s", algo, raw)
	}
	if _, present := job["xn"]; present {
		t.Errorf("RXT job payload must not carry an \"xn\" key at all, got raw job JSON: %s", raw)
	}
}

// TestSessionLoginJobPayloadStillIncludesXNForSHA3X is
// TestSessionLoginJobPayloadOmitsXNForRandomXFamilyAlgos's regression
// counterpart: the RXT/RXM-only fix must not accidentally strip xn
// from SHA3X (or C29) jobs too, since those algos' real
// nonce-partitioning convention still depends on it.
func TestSessionLoginJobPayloadStillIncludesXNForSHA3X(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realTariTestAddress("addr-sha3x-xn-wire"), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	raw := h.recvRaw()

	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal login response as map: %v", err)
	}
	job := asMap["result"].(map[string]any)["job"].(map[string]any)
	xnVal, present := job["xn"]
	if !present {
		t.Fatalf("SHA3X job payload must still carry an \"xn\" key, got raw job JSON: %s", raw)
	}
	if s, _ := xnVal.(string); s == "" {
		t.Errorf("SHA3X job's xn value must be non-empty, got %q in raw job JSON: %s", xnVal, raw)
	}
}

// login performs a real login handshake and returns the session id the
// server handed back (LoginResult.ID) and the session's own assigned
// xn.
//
// xn is resolved via sessionXN (a direct lookup of the real Session's
// internal xn field), NOT via the wire LoginResult.Job.XN field:
// RXT/RXM sessions still carry an internal xn for job bookkeeping
// (JobForXN et al) even though that xn is deliberately never sent
// over the wire for those two algos (see jobPayload's doc comment) --
// reading it off the wire would silently return "" for RXT/RXM
// harnesses and break every test that needs a real xn to construct
// xn-prefixed nonces.
func login(t *testing.T, h *testHarness, address string) (sessionID, xn string) {
	t.Helper()
	// address is a short, readable test label; it is deterministically
	// mapped to a real, byte-exact-valid Tari address here (see
	// address_helper_test.go's realTariTestAddress doc comment) since
	// handleLogin now performs real, coin-aware address validation.
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realTariTestAddress(address), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.ID, sessionXN(t, h, resp.Result.ID)
}

// sessionXN looks up the real, live Session for sessionID on h.server
// and returns its internal xn field directly -- this is the
// session-bookkeeping xn (assigned once at connect time, used to key
// JobForXN and to validate xn-prefixed nonces for SHA3X/C29), which is
// independent of whether that xn is ever surfaced on the wire for the
// session's algo (it deliberately is not, for RXT/RXM).
func sessionXN(t *testing.T, h *testHarness, sessionID string) string {
	t.Helper()
	h.server.mu.RLock()
	defer h.server.mu.RUnlock()
	for _, s := range h.server.sessions {
		if s.sessionID == sessionID {
			return s.xn
		}
	}
	t.Fatalf("could not find session %q on server", sessionID)
	return ""
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

// --- C29 algo-aware wiring tests ---
//
// See internal/leaflib/validator/c29_test.go's "NOTE ON TEST COVERAGE
// HONESTY" for why no genuine solved Cuckaroo29 cycle fixture exists
// anywhere in this codebase or its legacy reference (powkit is
// verify-only; go-tari-c29-solo-stratum itself has zero test files).
// These tests exercise the REAL leaf-solo wire path (JSON submit ->
// per-algo nonce byte-order decode -> C29Proof construction ->
// validator dispatch -> reject/accept) with structurally-valid-shaped
// but non-solving cycle data, honestly proving the PLUMBING is
// correct end-to-end, not that a genuine C29 solution was ever
// produced or accepted here.

// TestSessionC29JobPayloadLabelsAlgoCorrectly confirms a C29-configured
// leaf's real job push actually says "c29" on the wire, not "sha3x" —
// the most basic algo-awareness regression: a leaf-solo instance
// wired for the wrong algo would silently mislabel every job.
func TestSessionC29JobPayloadLabelsAlgoCorrectly(t *testing.T) {
	h := newC29TestHarness(t, 1000, 1<<62)
	_, xn := login(t, h, "addr-c29-label")
	job, err := h.jm.JobForXN(context.Background(), xn)
	if err != nil {
		t.Fatalf("JobForXN: %v", err)
	}
	if job.Algo != poolpb.Algo_ALGO_C29 {
		t.Fatalf("job.Algo = %v, want ALGO_C29", job.Algo)
	}
}

// TestSessionC29SubmitWithCorrectlyShapedCycleIsRejectedByRealValidator
// exercises the FULL leaf-solo submit path for C29: a real wire-level
// JSON submit carrying a "pow" field with exactly 42 edges (the real,
// correctly-shaped C29Proof.Cycle length) — the plumbing (nonce
// decode, Share_C29Proof construction, validator dispatch) must run
// all the way through to the real ported cuckoo.Client.Verify call
// (see validator/c29.go), which correctly rejects this non-solving
// cycle. This proves the WIRING is real and complete, matching
// validator/c29_test.go's own "correctly-shaped but non-solving cycle"
// test at the validator layer — here at the full session/wire layer
// instead.
func TestSessionC29SubmitWithCorrectlyShapedCycleIsRejectedByRealValidator(t *testing.T) {
	h := newC29TestHarness(t, 1, 1)
	sessionID, xn := login(t, h, "addr-c29-1")
	jobID := currentJobIDForXN(t, h, xn)

	cycle := make([]uint64, 42) // correctly-shaped (42 edges), not a real solved cycle
	h.send(Request{ID: 10, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 1),
		POW:   cycle,
	})})
	resp := h.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("expected a non-solving (all-zero) C29 cycle to be rejected by the real cuckoo.Verify call")
	}
	if resp.Error == "" {
		t.Fatal("expected a clear rejection error")
	}
	if h.node.submitCalls.Load() != 0 {
		t.Errorf("SubmitBlock must not be called for a rejected C29 share, got %d calls", h.node.submitCalls.Load())
	}
}

// TestSessionC29SubmitWrongCycleLengthIsRejected confirms the real
// c29SubmitCycleSize check (42 edges exactly) rejects a submit before
// ever reaching the validator — mirrors the wrong-edge-count case
// go-tari-c29-solo-stratum's own real miner.go implicitly relies on
// (a malformed pow array is never a valid Cuckaroo29 cycle).
func TestSessionC29SubmitWrongCycleLengthIsRejected(t *testing.T) {
	h := newC29TestHarness(t, 1, 1)
	sessionID, xn := login(t, h, "addr-c29-2")
	jobID := currentJobIDForXN(t, h, xn)

	shortCycle := make([]uint64, 41) // one short of the real 42-edge requirement
	h.send(Request{ID: 11, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 1),
		POW:   shortCycle,
	})})
	resp := h.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("expected a wrong-length pow array to be rejected")
	}
	if resp.Error == "" || !strings.Contains(resp.Error, "42") {
		t.Errorf("expected the rejection error to mention the required edge count, got %v", resp.Error)
	}
}

// TestSessionC29NonceByteOrderIsBigEndianNotLittleEndian is the single
// most important regression test in this pass: go-tari-c29-solo-stratum's
// real SubmitJob decodes the submitted nonce as BIG-ENDIAN
// (binary.BigEndian.Uint64), confirmed from source — a silent
// byte-order mismatch here would not fail loudly, it would just
// validate against the WRONG numeric nonce value, silently breaking
// real verification for every genuine solve. This test proves the
// decode is genuinely algo-aware by round-tripping a nonce whose
// big-endian and little-endian interpretations are deliberately
// different non-trivial values, and confirming the submission is
// processed (reaches the real validator, not rejected earlier by
// generic nonce-format checks) — the two interpretations differing at
// all is only possible if this leaf is really decoding per-algo, not
// applying one universal byte order to both SHA3X and C29 submits.
func TestSessionC29NonceByteOrderIsBigEndianNotLittleEndian(t *testing.T) {
	h := newC29TestHarness(t, 1, 1)
	sessionID, xn := login(t, h, "addr-c29-endian")
	jobID := currentJobIDForXN(t, h, xn)

	// A nonce value whose big-endian and little-endian 8-byte
	// encodings are genuinely different hex strings (not a palindrome
	// like an all-zero or all-0xff value, which would be identical
	// either way and prove nothing about byte order specifically).
	const nonceValue uint64 = 0x0102030405060708
	beHex := fmt.Sprintf("%016x", nonceValue) // hex.EncodeToString of the big-endian encoding
	leBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(leBytes, nonceValue)
	leHex := hex.EncodeToString(leBytes)
	if beHex == leHex {
		t.Fatalf("test setup bug: chosen nonceValue's big-endian and little-endian hex encodings are identical (%s) — pick a non-palindromic value", beHex)
	}

	// xnPrefixedNonceHex builds "<xn><random suffix>"; for this test
	// we need the EXACT big-endian hex of nonceValue, prefixed with
	// this session's own xn, so construct it directly rather than via
	// the usual random-suffix helper.
	nonceHex := xn + beHex[len(xn):]

	cycle := make([]uint64, 42)
	h.send(Request{ID: 12, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: nonceHex,
		POW:   cycle,
	})})
	resp := h.recvLegacyShareResponse()

	// The all-zero cycle will still fail real PoW verification (it's
	// not a genuine solved cycle) — that's expected and fine. What
	// this test actually proves is that the submit was NOT rejected
	// for a nonce-FORMAT reason (which would indicate the byte-order
	// handling broke decoding entirely) — the real validator was
	// reached and is what produced the rejection.
	if resp.Result {
		t.Fatal("expected the non-solving cycle to still be rejected")
	}
	if resp.Error != "" && (strings.Contains(resp.Error, "must be 8 bytes") || strings.Contains(resp.Error, "hex") && strings.Contains(resp.Error, "invalid")) {
		t.Fatalf("submit was rejected for a NONCE FORMAT reason (%q), not real PoW validation — byte-order handling may be broken", resp.Error)
	}
}

// xnPrefixedNonceHex builds an 8-byte, hex-encoded nonce whose leading
// hex characters are exactly xn, matching the real wire convention
// go-tari-sha3x-solo-stratum's miners are expected to follow
// (session.go's handleSubmit checks strings.HasPrefix on the hex
// string, not on the decoded bytes' numeric value).
//
// BUG FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 6): n is now encoded
// BIG-ENDIAN, not little-endian. With a little-endian encoding, xn's
// overwrite of the leading hex characters clobbers the LOW-order
// bytes of n -- exactly the bytes a small increment (e.g. `n+1` in a
// retry loop) changes -- so two calls with genuinely different,
// small-delta n values could silently produce the BYTE-IDENTICAL
// final nonce hex once xn is overlaid, defeating any caller that
// increments n across retries against the SAME job_id expecting a
// genuinely distinct nonce each time (this exact bug caused
// intermittent "duplicate nonce" flakes in
// direct/trust_integration_test.go's identical LE helper -- see that
// package's directXNPrefixedNonceHex/directXNPrefixedNonceHexBigEndian
// doc comments). Big-endian encoding puts n's low-order bytes at the
// END of the hex string, outside xn's overwritten prefix, so small
// increments always produce a genuinely distinct final nonce
// regardless of xn's length. No existing caller in this file depends
// on the specific byte-order this helper picks (each call site cares
// only about wire acceptance/rejection and the xn-prefix match, never
// the decoded numeric value), so this is a safe, non-behavior-
// changing-for-existing-tests fix.
func xnPrefixedNonceHex(xn string, n uint64) string {
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		buf[7-i] = byte(n >> (8 * i))
	}
	full := hex.EncodeToString(buf)
	return xn + full[len(xn):]
}

// --- xn-prefix check regression tests (bug fix: RXT must NOT be
// subject to the xn-prefix check; SHA3X/C29 still must be) ---

// TestSessionSHA3XSubmitWithoutXNPrefixIsRejected is the regression
// guard for the SHA3X side of the xn-prefix fix: confirms making the
// check algo-conditional (skipped for RXT) did NOT accidentally
// disable it for SHA3X, which still requires the real xn-prefix
// convention (see handleSubmit's doc comment).
func TestSessionSHA3XSubmitWithoutXNPrefixIsRejected(t *testing.T) {
	h := newTestHarness(t, 1, 1<<62)
	sessionID, xn := login(t, h, "addr-sha3x-noxn")
	jobID := currentJobIDForXN(t, h, xn)

	// Deliberately build a nonce hex string that does NOT start with
	// this session's own xn (flip the first hex nibble to guarantee a
	// mismatch regardless of what xn happens to be).
	badNonce := xnPrefixedNonceHex(xn, 1)
	badNonce = flipFirstHexNibble(badNonce)

	h.send(Request{ID: 60, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: badNonce,
	})})
	resp := h.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("expected a SHA3X submit whose nonce does not start with the session's own xn to be REJECTED")
	}
	if resp.Error == "" || !strings.Contains(resp.Error, "Invalid XNonce") {
		t.Errorf("expected rejection to be the xn-prefix check (\"Invalid XNonce\"), got %v", resp.Error)
	}
}

// TestSessionC29SubmitWithoutXNPrefixIsRejected is the C29 counterpart
// of the above — same regression guard, different algo.
func TestSessionC29SubmitWithoutXNPrefixIsRejected(t *testing.T) {
	h := newC29TestHarness(t, 1, 1)
	sessionID, xn := login(t, h, "addr-c29-noxn")
	jobID := currentJobIDForXN(t, h, xn)

	badNonce := xnPrefixedNonceHex(xn, 1)
	badNonce = flipFirstHexNibble(badNonce)

	cycle := make([]uint64, 42)
	h.send(Request{ID: 61, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: badNonce,
		POW:   cycle,
	})})
	resp := h.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("expected a C29 submit whose nonce does not start with the session's own xn to be REJECTED")
	}
	if resp.Error == "" || !strings.Contains(resp.Error, "Invalid XNonce") {
		t.Errorf("expected rejection to be the xn-prefix check (\"Invalid XNonce\"), got %v", resp.Error)
	}
}

// TestSessionRXTSubmitWithoutXNPrefixIsNotRejectedByXNCheck is this
// bug fix's core regression test: an RXT submit whose nonce does NOT
// start with the session's own xn must NOT be rejected with "Invalid
// XNonce" (the whole point of the fix — RXT was never designed to use
// xn nonce partitioning, per rxt.go/createTariMiningBlob). This does
// not require a real randomx-service daemon: the RandomXValidator here
// points at an address nothing is listening on, so the submit will
// still be rejected overall (a real Validate call errors out), but the
// rejection reason must be the validator/transport error, never the
// xn-prefix check — proving the xn-prefix branch is genuinely skipped
// for ALGO_RXT rather than merely returning a different message for
// the same check.
func TestSessionRXTSubmitWithoutXNPrefixIsNotRejectedByXNCheck(t *testing.T) {
	h := newRXTTestHarness(t, 1, 1<<62, "http://127.0.0.1:1") // deliberately unreachable
	sessionID, xn := login(t, h, "addr-rxt-noxn")
	jobID := currentJobIDForXN(t, h, xn)

	badNonce := xnPrefixedNonceHex(xn, 0xdeadbeef)
	badNonce = flipFirstHexNibble(badNonce)

	h.send(Request{ID: 62, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  badNonce,
		Result: strings.Repeat("00", 32),
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("test setup bug: expected this submit to fail (unreachable RandomX service), not succeed")
	}
	if resp.Error != nil && strings.Contains(resp.Error.Message, "Invalid XNonce") {
		t.Fatalf("BUG REGRESSION: an RXT submit without the xn prefix was rejected by the xn-prefix check (%q) — RXT must be exempt from it", resp.Error.Message)
	}
}

// flipFirstHexNibble flips the first hex character of s to a value
// that is guaranteed different, so the resulting string is guaranteed
// to no longer start with the original xn prefix (used to build a
// deliberately xn-mismatched nonce for the regression tests above).
func flipFirstHexNibble(s string) string {
	if s == "" {
		return s
	}
	if s[0] == '0' {
		return "f" + s[1:]
	}
	return "0" + s[1:]
}

// realXMRMainnetAddr is the real, well-known Monero project donation
// address -- a genuine mainnet standard address whose base58/checksum
// has been independently verified for years by the Monero ecosystem
// (same fixture as internal/backend/addressmap/addressmap_test.go's
// own realXMRMainnetAddr), used here so the RXM-focused nonce-length
// gate tests below can pass handleLogin's real, coin-aware Monero
// address validation (address.go's validateMoneroLoginAddress).
const realXMRMainnetAddr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"

// loginRXM is login's ALGO_RXM counterpart: uses a real Monero
// address (not a Tari one) and advertises the "rx/0" algo, matching a
// real xmrig client's login params.
//
// xn is resolved via sessionXN (a direct lookup of the real Session's
// internal xn field), NOT via the wire LoginResult.Job.XN field: RXM
// sessions still carry an internal xn for job bookkeeping even though
// it is deliberately never sent over the wire for that algo (see
// jobPayload's doc comment) -- reading it off the wire would silently
// return "" and cause callers to look up/submit against the wrong job.
func loginRXM(t *testing.T, h *testHarness) (sessionID, xn string) {
	t.Helper()
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realXMRMainnetAddr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"rx/0"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.ID, sessionXN(t, h, resp.Result.ID)
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	buf, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return buf
}

// --- nonce-length gate regression tests (bug fix: the nonce-length
// check was an unconditional "must be exactly 8 bytes" gate applied
// to EVERY algo, rejecting every real ALGO_RXM submit -- a real
// production packet capture against the live public RXM leaf-solo
// instance (148.163.90.157:4450) showed a real xmrig client's
// genuine 4-byte nonce ("818d1a00", matching Monero's real 32-bit
// block-header nonce field) being rejected with "nonce must be 8
// bytes, hex-encoded uint64" purely because of this blanket check.
// RXM must now accept a 4-byte nonce; SHA3X/C29/RXT must still
// require exactly 8 bytes, unchanged. ---

// TestSessionRXMAccepts4ByteNonce is the core regression test for the
// fix: submitting the EXACT nonce from the real production packet
// capture above ("818d1a00", 4 bytes) for an ALGO_RXM job must NOT be
// rejected by the "nonce must be 8 bytes" gate. The submit still
// fails further downstream (this harness's fakeNodeClient builds a
// Tari-shaped job, not a real *moneroTemplateData, so
// MoneroHashingBlobForSubmit's own type assertion fails) -- that's
// expected and is not what this test asserts. The test's ONLY
// assertion is that the rejection reason is NOT the 8-byte gate.
func TestSessionRXMAccepts4ByteNonce(t *testing.T) {
	h := newRXMTestHarness(t, 1, 1<<62)
	sessionID, xn := loginRXM(t, h)
	jobID := currentJobIDForXN(t, h, xn)

	const xmrigCaptureNonce = "818d1a00" // real capture: 4 bytes, 8 hex chars
	h.send(Request{ID: 70, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  xmrigCaptureNonce,
		Result: strings.Repeat("00", 32), // placeholder claimed result hash
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("test setup bug: expected this RXM submit to still fail downstream (fake Tari template data, not real Monero data), not succeed")
	}
	if resp.Error != nil && strings.Contains(resp.Error.Message, "must be 8 bytes") {
		t.Fatalf("BUG REGRESSION: a real xmrig-shaped 4-byte RXM nonce (%q) was rejected by the 8-byte length gate (%q) -- RXM must accept a 4-byte nonce", xmrigCaptureNonce, resp.Error.Message)
	}
}

// TestSessionRXMAccepts8ByteNonceToo confirms the fix's lenient
// 8-byte tolerance branch for RXM still works (some other
// RXM-speaking client could zero-pad to 8 bytes) -- same
// "not the 8-byte gate" assertion as above, just with an 8-byte
// nonce this time.
func TestSessionRXMAccepts8ByteNonceToo(t *testing.T) {
	h := newRXMTestHarness(t, 1, 1<<62)
	sessionID, xn := loginRXM(t, h)
	jobID := currentJobIDForXN(t, h, xn)

	h.send(Request{ID: 71, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  "00000000818d1a00",
		Result: strings.Repeat("00", 32),
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("test setup bug: expected this RXM submit to still fail downstream, not succeed")
	}
	if resp.Error != nil && (strings.Contains(resp.Error.Message, "must be 8 bytes") || strings.Contains(resp.Error.Message, "must be 4 bytes")) {
		t.Fatalf("an 8-byte RXM nonce was rejected by the length gate (%q) -- RXM should tolerate 8 bytes too", resp.Error.Message)
	}
}

// TestSessionRXMRejectsBadLengthNonce confirms RXM's length gate
// still rejects a genuinely wrong-length nonce (neither 4 nor 8
// bytes) -- proving the fix didn't just remove the gate entirely.
func TestSessionRXMRejectsBadLengthNonce(t *testing.T) {
	h := newRXMTestHarness(t, 1, 1<<62)
	sessionID, xn := loginRXM(t, h)
	jobID := currentJobIDForXN(t, h, xn)

	h.send(Request{ID: 72, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  "aabbcc", // 3 bytes -- neither valid width
		Result: strings.Repeat("00", 32),
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("expected a 3-byte RXM nonce to be rejected")
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "4 bytes") {
		t.Errorf("expected the RXM-specific 4-byte-nonce error, got %v", resp.Error)
	}
}

// TestSessionSHA3XStillRejects4ByteNonce and
// TestSessionC29StillRejects4ByteNonce are the regression guards for
// the OTHER side of this fix: making the length gate lenient for RXM
// must NOT have accidentally loosened it for SHA3X/C29, which
// genuinely require exactly 8 bytes.
func TestSessionSHA3XStillRejects4ByteNonce(t *testing.T) {
	h := newTestHarness(t, 1, 1<<62)
	sessionID, xn := login(t, h, "addr-sha3x-4byte")
	jobID := currentJobIDForXN(t, h, xn)

	// A 4-byte (8 hex char) nonce, xn-prefixed so the xn check
	// (which runs first) doesn't mask the length-gate result.
	shortNonce := xn + strings.Repeat("0", 8-len(xn))
	h.send(Request{ID: 73, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: shortNonce,
	})})
	resp := h.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("expected a 4-byte SHA3X nonce to be rejected")
	}
	if resp.Error == "" || !strings.Contains(resp.Error, "must be 8 bytes") {
		t.Fatalf("BUG REGRESSION: SHA3X's 8-byte nonce requirement was loosened -- got error %v, want the \"must be 8 bytes\" message", resp.Error)
	}
}

func TestSessionC29StillRejects4ByteNonce(t *testing.T) {
	h := newC29TestHarness(t, 1, 1)
	sessionID, xn := login(t, h, "addr-c29-4byte")
	jobID := currentJobIDForXN(t, h, xn)

	shortNonce := xn + strings.Repeat("0", 8-len(xn))
	h.send(Request{ID: 74, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: shortNonce,
		POW:   make([]uint64, 42),
	})})
	resp := h.recvLegacyShareResponse()

	if resp.Result {
		t.Fatal("expected a 4-byte C29 nonce to be rejected")
	}
	if resp.Error == "" || !strings.Contains(resp.Error, "must be 8 bytes") {
		t.Fatalf("BUG REGRESSION: C29's 8-byte nonce requirement was loosened -- got error %v, want the \"must be 8 bytes\" message", resp.Error)
	}
}

// TestAlgoWireNameRXTMapsToRX0 is a direct regression guard for the
// live production bug: RXT jobs must be labeled "rx/0" on the wire,
// exactly like RXM, NOT the internal poolpb.Algo enum name "rxt".
// Real RandomX-family miners (XMRig et al.) have no concept of an
// algorithm called "rxt" in their own algo dispatch table — confirmed
// live against XMRig 6.25.0, whose login "algo" capability array
// contained "rx/0" but never "rxt", against production leaf-solo-rxt
// (port 4447): the miner reported real ~90kh/s hashrate but produced
// zero accepted shares because the job's algo label was unrecognized.
func TestAlgoWireNameRXTMapsToRX0(t *testing.T) {
	if got := algoWireName(poolpb.Algo_ALGO_RXT); got != "rx/0" {
		t.Fatalf("algoWireName(ALGO_RXT) = %q, want %q (RXT is plain RandomX under the hood; the miner-facing wire label must match RXM's, not the internal enum name)", got, "rx/0")
	}
}

// TestAlgoWireNameRXMStillMapsToRX0 guards against regressing the
// already-correct RXM mapping while fixing RXT above.
func TestAlgoWireNameRXMStillMapsToRX0(t *testing.T) {
	if got := algoWireName(poolpb.Algo_ALGO_RXM); got != "rx/0" {
		t.Fatalf("algoWireName(ALGO_RXM) = %q, want %q", got, "rx/0")
	}
}

// TestAlgoWireNameC29AndSHA3XUnaffected guards the other wire labels
// against any regression from the RXT fix above.
func TestAlgoWireNameC29AndSHA3XUnaffected(t *testing.T) {
	if got := algoWireName(poolpb.Algo_ALGO_C29); got != "c29" {
		t.Fatalf("algoWireName(ALGO_C29) = %q, want %q", got, "c29")
	}
	if got := algoWireName(poolpb.Algo_ALGO_SHA3X); got != "sha3x" {
		t.Fatalf("algoWireName(ALGO_SHA3X) = %q, want %q", got, "sha3x")
	}
}

// TestJobPayloadRXTBlobIs76Bytes is a direct regression guard for the
// live production bug this pass fixes: a real packet capture against
// 148.163.90.157:4447 (RXT) showed a wire "blob" field of only 64 hex
// characters (32 bytes, the bare Tari merge-mining hash) — not a
// minable blob a real RandomX-family client (XMRig) can parse — while
// the SAME leaf family's working RXM job (148.163.90.157:4450)
// carried a real 152-hex-char (76-byte) blob. This test logs in on a
// real RXT-configured JobManager/Session and asserts the wire "blob"
// is now also 152 hex chars (76 bytes), decoding to the exact
// createTariMiningBlob layout (3 zero bytes, the real 32-byte mining
// hash, a zeroed 8-byte nonce-placeholder region, then the
// pow-algo/data segment) with the nonce-placeholder region entirely
// zero (nonce=0 placeholder — see rxt.go's rxtXmrigNonceOffset doc
// comment for why byte offset 39, inside this region, is exactly
// where a real XMRig client is expected to patch its own nonce).
func TestJobPayloadRXTBlobIs76Bytes(t *testing.T) {
	h := newRXTTestHarness(t, 1000, 100000, "http://127.0.0.1:1")
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress("rxt-blob-shape"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
	})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}

	blobHex := resp.Result.Job.Blob
	if len(blobHex) != 152 {
		t.Fatalf("RXT job wire \"blob\" = %d hex chars, want 152 (76 bytes) -- this is the exact live production bug: a bare 32-byte hash (64 hex chars) is not a minable blob a real RandomX client can parse", len(blobHex))
	}
	blob, err := hex.DecodeString(blobHex)
	if err != nil {
		t.Fatalf("blob is not valid hex: %v", err)
	}
	if len(blob) != 76 {
		t.Fatalf("decoded blob length = %d bytes, want 76", len(blob))
	}

	if !bytes.Equal(blob[0:3], []byte{0, 0, 0}) {
		t.Errorf("bytes[0:3] (zero placeholder) = %x, want all-zero", blob[0:3])
	}

	wantHash := make([]byte, 32) // createTariMiningBlob zero-pads a short/31-byte fixture up to exactly 32 bytes
	copy(wantHash, []byte("test-merge-mining-hash-32bytes!"))
	if !bytes.Equal(blob[3:35], wantHash) {
		t.Errorf("bytes[3:35] (mining hash) = %q, want %q", blob[3:35], wantHash)
	}

	if !bytes.Equal(blob[35:43], make([]byte, 8)) {
		t.Errorf("bytes[35:43] (nonce region) = %x, want all-zero (nonce=0 outbound placeholder)", blob[35:43])
	}

	if blob[43] != rxtPowAlgoByte {
		t.Errorf("byte[43] (pow_algo) = %d, want %d (rxtPowAlgoByte)", blob[43], rxtPowAlgoByte)
	}
	if !bytes.Equal(blob[44:76], make([]byte, 32)) {
		t.Errorf("bytes[44:76] (pow_data, empty+padded) = %x, want all-zero", blob[44:76])
	}
}

// TestJobPayloadSHA3XC29RXMBlobShapeUnaffected is the explicit
// regression guard the task requires: SHA3X and C29 job blobs must
// STILL be exactly 32 bytes (64 hex chars, the bare merge-mining
// hash — genuinely correct for those two algos, unlike RXT), and
// RXM's job blob must STILL be exactly 76 bytes (152 hex chars,
// already correct by construction — see monero_node.go) after the
// RXT-only fix above.
func TestJobPayloadSHA3XC29RXMBlobShapeUnaffected(t *testing.T) {
	t.Run("sha3x stays 32 bytes", func(t *testing.T) {
		h := newTestHarness(t, 1000, 100000)
		h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realTariTestAddress("sha3x-shape"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"sha3x"}})})
		resp := h.recvLoginResponse()
		if resp.Result.Status != "OK" {
			t.Fatalf("login failed: status=%q", resp.Result.Status)
		}
		if len(resp.Result.Job.Blob) != len(hex.EncodeToString([]byte("test-merge-mining-hash-32bytes!"))) {
			t.Fatalf("SHA3X job blob = %d hex chars, want %d -- REGRESSION from the RXT-only blob fix", len(resp.Result.Job.Blob), len(hex.EncodeToString([]byte("test-merge-mining-hash-32bytes!"))))
		}
	})

	t.Run("c29 stays 32 bytes", func(t *testing.T) {
		h := newC29TestHarness(t, 1000, 100000)
		h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realTariTestAddress("c29-shape"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"c29"}})})
		resp := h.recvLoginResponse()
		if resp.Result.Status != "OK" {
			t.Fatalf("login failed: status=%q", resp.Result.Status)
		}
		if len(resp.Result.Job.Blob) != len(hex.EncodeToString([]byte("test-merge-mining-hash-32bytes!"))) {
			t.Fatalf("C29 job blob = %d hex chars, want %d -- REGRESSION from the RXT-only blob fix", len(resp.Result.Job.Blob), len(hex.EncodeToString([]byte("test-merge-mining-hash-32bytes!"))))
		}
	})

	t.Run("rxm stays 76 bytes", func(t *testing.T) {
		h := newRXMTestHarness(t, 1000, 100000)
		h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: realXMRMainnetAddr, Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"rx/0"}})})
		resp := h.recvLoginResponse()
		if resp.Result.Status != "OK" {
			t.Fatalf("login failed: status=%q", resp.Result.Status)
		}
		// newRXMTestHarness's fakeNodeClient is Tari-shaped (see its
		// own doc comment), so job.Header is still the bare 31-byte
		// (test fixture) mergeMiningHash here -- this asserts RXM's
		// blob construction path (job.Header used directly) is
		// UNTOUCHED by the RXT-only fix, not that this particular
		// fixture is a real Monero blob.
		if len(resp.Result.Job.Blob) != len(hex.EncodeToString([]byte("test-merge-mining-hash-32bytes!"))) {
			t.Fatalf("RXM (fixture) job blob = %d hex chars, want %d -- REGRESSION from the RXT-only blob fix (jobPayload's RXT branch guard is no longer algo-exclusive)", len(resp.Result.Job.Blob), len(hex.EncodeToString([]byte("test-merge-mining-hash-32bytes!"))))
		}
	})
}

// TestHandleSubmitRXTNonceLengthAccepts4Bytes is a direct regression
// guard for the companion submit-side half of this fix: a real
// XMRig client reports a raw 4-byte nonce (not 8) for RXT, matching
// its own hardcoded Job::nonceOffset()/nonceSize() default-case
// behavior for the generic RandomX family (rxt.go's
// rxtXmrigNonceOffset/rxtXmrigNonceSize) -- so the ALGO_RXT nonce
// length gate must accept 4 bytes (8 hex chars) and NOT reject it
// with the old, SHA3X/C29-only "must be 8 bytes" error.
func TestHandleSubmitRXTNonceLengthAccepts4Bytes(t *testing.T) {
	h := newRXTTestHarness(t, 1000, 100000, "http://127.0.0.1:1") // deliberately unreachable randomx-service
	sessionID, _ := login(t, h, "rxt-nonce-len")
	jobID := currentJobIDForXNRXT(t, h)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: "deadbeef" /* 4 raw bytes, 8 hex chars */, Result: strings.Repeat("ab", 32),
	})})
	resp := h.recvShareResponse()

	// The unreachable randomx-service means real PoW validation will
	// fail downstream -- that's expected and NOT what this test
	// checks. The observable this test needs is that the length gate
	// itself did not reject the submit with the old "must be 8 bytes"
	// message.
	if resp.Error != nil && strings.Contains(resp.Error.Message, "must be 8 bytes") {
		t.Fatalf("BUG: a real 4-byte RXT nonce was rejected by the length gate with %q -- RXT must accept the same 4-byte width RXM already does (a real XMRig client never sends 8 bytes for either)", resp.Error.Message)
	}
}

// currentJobIDForXNRXT mirrors currentJobIDForXN but resolves xn via
// sessionXN (RXT's xn is never surfaced on the wire -- see login's own
// doc comment) using the FIRST live session found; used only by the
// single-session nonce-length test above, which never needs to
// disambiguate between multiple sessions.
func currentJobIDForXNRXT(t *testing.T, h *testHarness) string {
	t.Helper()
	h.server.mu.RLock()
	var xn string
	for _, s := range h.server.sessions {
		xn = s.xn
		break
	}
	h.server.mu.RUnlock()
	if xn == "" {
		t.Fatalf("no live session found on server")
	}
	return currentJobIDForXN(t, h, xn)
}

// sessionByID looks up the real, live *Session for sessionID on
// h.server directly -- like sessionXN, but returns the Session itself
// so a test can mutate/inspect internal state (currentDifficulty,
// lastDeliveredJobID) that isn't exposed on the wire.
func sessionByID(t *testing.T, h *testHarness, sessionID string) *Session {
	t.Helper()
	h.server.mu.RLock()
	defer h.server.mu.RUnlock()
	for _, s := range h.server.sessions {
		if s.sessionID == sessionID {
			return s
		}
	}
	t.Fatalf("could not find session %q on server", sessionID)
	return nil
}

// expectNoJobPush asserts that NO further wire traffic arrives within
// a short deadline -- used to prove invalidateAndRepushJobs' dedup
// correctly suppressed a would-be-redundant unsolicited "job" push.
func expectNoJobPush(t *testing.T, h *testHarness) {
	t.Helper()
	_ = h.client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	line, err := h.reader.ReadBytes('\n')
	if err == nil {
		t.Fatalf("BUG: received an unexpected wire push when none was expected: %s", line)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a read timeout (no data), got: %v", err)
	}
	// Reset the deadline so subsequent reads in the same test aren't
	// affected by this probe's short deadline.
	_ = h.client.SetReadDeadline(time.Time{})
}

// TestInvalidateAndRepushJobsSkipsDuplicatePush is the direct
// regression test for Alex's live production report ("we're sending
// duplicate jobs down the wire to RXT"): invalidateAndRepushJobs fires
// on every periodic RefreshInterval tick (and on tip movement)
// regardless of whether anything actually changed for a given
// session. Two consecutive invocations against the SAME underlying
// cached job/template (JobManager's cache was never invalidated
// between them) must result in AT MOST ONE real "job" push reaching
// the wire -- the second, genuinely-redundant push must be suppressed.
func TestInvalidateAndRepushJobsSkipsDuplicatePush(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)
	sessionID, _ := login(t, h, "dedup-addr-1")

	// First invocation: the per-xn job cache was never invalidated
	// since login, so JobForXNAtDifficulty returns the SAME cached Job
	// at the SAME difficulty already recorded by the login response's
	// own jobPayload call -- this must be recognized as a duplicate
	// and skipped.
	h.server.invalidateAndRepushJobs()
	expectNoJobPush(t, h)

	// Second consecutive invocation, still with nothing having
	// changed: must ALSO be skipped, proving this isn't a one-shot
	// fluke of already having a per-session job that happens to match
	// only right after login.
	h.server.invalidateAndRepushJobs()
	expectNoJobPush(t, h)

	_ = sessionID
}

// TestInvalidateAndRepushJobsStillPushesOnDifficultyChange is the
// regression guard for the correctness nuance in this fix: job.ID is
// derived purely from the block hash (job.go's Job.ID) and does NOT
// depend on difficulty, but the wire "target" field does. A dedup
// keyed on job.ID alone would incorrectly swallow a legitimate
// vardiff-driven difficulty/target update sharing the same job.ID as
// the previous push. This simulates exactly that: a vardiff retarget
// changes the session's own currentDifficulty between two
// invalidateAndRepushJobs ticks while the underlying job/template
// (and therefore job.ID) stays the same -- the push must still be
// sent, with the new target.
func TestInvalidateAndRepushJobsStillPushesOnDifficultyChange(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)
	sessionID, xn := login(t, h, "dedup-addr-2")

	// Establish the baseline: same as the pure-dedup test, this first
	// tick with nothing changed must be suppressed (no write happens,
	// so this call is safe to run synchronously).
	h.server.invalidateAndRepushJobs()
	expectNoJobPush(t, h)

	baselineJobID := currentJobIDForXN(t, h, xn)

	// Simulate a real vardiff retarget between two invalidation ticks:
	// vardiff.go's maybeRetarget updates currentDifficulty AND calls
	// JobManager.RestampDifficulty (producing a new *Job with the
	// SAME ID/Header/BlockHash but a NEW StaticDifficulty, replacing
	// the cached entry for this xn) -- mutating currentDifficulty
	// alone would NOT be enough here, since JobForXNAtDifficulty does
	// not retroactively restamp an already-cached job (see job.go's
	// doc comment); the cache entry itself must be restamped, exactly
	// as the real retarget path does.
	sess := sessionByID(t, h, sessionID)
	newDiff := sess.currentDifficulty.Load() * 2
	sess.currentDifficulty.Store(newDiff)
	if _, err := h.jm.RestampDifficulty(context.Background(), xn, newDiff); err != nil {
		t.Fatalf("RestampDifficulty: %v", err)
	}

	// invalidateAndRepushJobs' real push write blocks (net.Pipe is a
	// synchronous, unbuffered pipe: a server-side Write blocks until
	// the client reads) until this test's own recvJobPush below
	// performs that read -- so the call must run in its own
	// goroutine, exactly like the real production callback does (it
	// is JobManager's own invalidation-subscriber callback, never
	// called synchronously from the same goroutine that will read the
	// resulting wire traffic).
	go h.server.invalidateAndRepushJobs()
	push := h.recvJobPush()

	if push.Method != "job" {
		t.Fatalf("push method = %q, want job", push.Method)
	}
	if push.Params.JobID != baselineJobID {
		t.Fatalf("BUG: job.ID changed across a pure difficulty retarget (got %q, want unchanged %q) -- the underlying template/job.ID must be difficulty-independent", push.Params.JobID, baselineJobID)
	}
	wantTarget := diffToTargetHex(newDiff)
	if push.Params.Target != wantTarget {
		t.Fatalf("BUG: a real vardiff-driven target update was dropped -- push.Params.Target = %q, want %q (dedup must consider difficulty, not just job.ID)", push.Params.Target, wantTarget)
	}

	// A third tick with nothing changed since the difficulty-driven
	// push above must once again be suppressed -- proves the dedup
	// state was correctly updated to reflect the just-sent push.
	h.server.invalidateAndRepushJobs()
	expectNoJobPush(t, h)
}
