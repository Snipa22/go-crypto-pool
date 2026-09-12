// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// newDebugTestHarness mirrors newTestHarness exactly, except it lets
// the caller supply the *log.Logger every real Printf/Debugf call
// writes to (so a test can capture and assert on it) and whether
// debug mode is enabled (via Server.SetDebugLogger), covering the
// SAME real Server/Session/JobManager wiring every other session_test.go
// test exercises -- nothing about the actual submit-handling logic is
// mocked or bypassed differently from newTestHarness.
func newDebugTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64, logger *log.Logger, debugEnabled bool) *testHarness {
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
		Logger:           logger,
		Debug:            leaflib.NewDebugLogger(logger, debugEnabled),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	v := validator.NewSHA3XValidator()
	c29 := validator.NewC29Validator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v, poolpb.Algo_ALGO_C29: c29}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, logger, VardiffConfig{})
	server.SetDebugLogger(leaflib.NewDebugLogger(logger, debugEnabled))

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

// TestSessionSubmitDebugDisabledProducesNoDebugOutput confirms the
// hard requirement from the -debug feature brief: with debug OFF (the
// default), a normal login+submit produces byte-identical log output
// to before the feature existed -- i.e. no "[DEBUG]"-tagged line
// appears anywhere in the captured log output.
func TestSessionSubmitDebugDisabledProducesNoDebugOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "leaf-solo-test: ", 0)

	h := newDebugTestHarness(t, 1, math.MaxUint64, logger, false)
	sessionID, xn := login(t, h, "addr-debug-off")

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

	got := buf.String()
	if strings.Contains(got, "[DEBUG]") {
		t.Fatalf("expected NO [DEBUG]-tagged output with debug disabled, got:\n%s", got)
	}
}

// TestSessionSubmitDebugEnabledProducesDebugOutput is the companion
// case: with debug ON, the exact same login+submit sequence produces
// real, expected [DEBUG]-tagged lines covering the submit-received,
// validation-attempt, and submit-result checkpoints wired into
// session.go's handleSubmit/writeShareResponse/finishSubmit.
func TestSessionSubmitDebugEnabledProducesDebugOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "leaf-solo-test: ", 0)

	h := newDebugTestHarness(t, 1, math.MaxUint64, logger, true)
	sessionID, xn := login(t, h, "addr-debug-on")

	jobID := currentJobIDForXN(t, h, xn)
	nonceHex := xnPrefixedNonceHex(xn, 54321)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: nonceHex,
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if !resp.Result {
		t.Fatalf("expected result=true for an accepted share, got %#v", resp)
	}

	got := buf.String()
	if !strings.Contains(got, "[DEBUG]") {
		t.Fatalf("expected [DEBUG]-tagged output with debug enabled, got:\n%s", got)
	}
	if !strings.Contains(got, "submit received") {
		t.Errorf("expected a \"submit received\" debug line, got:\n%s", got)
	}
	if !strings.Contains(got, jobID) {
		t.Errorf("expected the debug output to mention job_id=%s, got:\n%s", jobID, got)
	}
	if !strings.Contains(got, "submit result") {
		t.Errorf("expected a \"submit result\" debug line, got:\n%s", got)
	}
	if !strings.Contains(got, "accepted=true") {
		t.Errorf("expected the submit result debug line to report accepted=true, got:\n%s", got)
	}

	debugLines := strings.Count(got, "[DEBUG]")
	if debugLines == 0 {
		t.Fatalf("expected at least one [DEBUG] line, got 0")
	}
}
