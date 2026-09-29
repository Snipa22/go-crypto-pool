// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// realDirectARQMainnetAddr is a real, primary-source-cited ArQmA
// mainnet address (see internal/coinprofile/address_test.go for the
// exact provenance) -- used so this test's real login/handleSubmit
// path exercises real, byte-exact address validation for the NEW
// ALGO_ARQ coin, not a placeholder string.
const realDirectARQMainnetAddr = "ar2dJ21SCuNiJndoQBf5ojhbdA7K8B3sREpnWSg4pHedXcwMbvUkYREAapZJMn3cVRj6VqDqDkj9bFoXLJViCmFs2qWkdufHt"

// alwaysValidARQValidator mirrors alwaysValidRXMValidator (see
// session_rxm_blockhash_test.go) exactly, for ALGO_ARQ.
type alwaysValidARQValidator struct{}

func (alwaysValidARQValidator) Validate(_ context.Context, _ *poolpb.Share) (bool, error) {
	return true, nil
}

var _ validator.AlgoValidator = alwaysValidARQValidator{}

// newDirectNewCoinBlockFindHarness mirrors newDirectRXMBlockFindHarness
// (session_rxm_blockhash_test.go) EXACTLY, parameterized on algo --
// proving this repo's session.go generalization for the new
// standalone monerod-family coin algos (ALGO_XMR and below) reuses
// the SAME real GetBlockTemplate -> BuildCandidateBlock -> SubmitBlock
// pipeline as ALGO_RXM, end-to-end, against the same mock monerod
// daemon shape (this is MOCK-SHAPE-ONLY verification, per the PR
// description -- no real ArQmA daemon was available to test against
// in this pass; the mock daemon's JSON-RPC responses match the real,
// documented monerod get_block_template/submit_block wire shape, the
// SAME shape every confirmed coin in internal/coinprofile.Registry
// speaks).
func newDirectNewCoinBlockFindHarness(t *testing.T, srv *httptest.Server, staticDiff uint64, algo poolpb.Algo, payoutAddress string) *directTestHarness {
	t.Helper()
	node := solo.NewMoneroNodeClient(srv.URL)

	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    payoutAddress,
		StaticDifficulty: staticDiff,
		Algo:             algo,
	})

	registry := validator.Registry{algo: alwaysValidARQValidator{}}

	tr := &fakeShareTransport{}

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm,
		JobManager:        jm,
		Node:              node,
		Validators:        registry,
		Network:           poolpb.Network_NETWORK_TESTNET,
		Transport:         tr,
		Algo:              algo,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            42,
		MonerodURL:        srv.URL,
	})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &directTestHarness{
		t: t, server: server, jm: jm, transport: tr,
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

// directLoginNewCoin mirrors directLoginRXM exactly, parameterized on
// login address -- see that function's doc comment for why xn must be
// read via directSessionXN, not the wire LoginResult.Job.XN field.
func directLoginNewCoin(t *testing.T, h *directTestHarness, address string) (sessionID, xn string) {
	t.Helper()
	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: address, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"rx/0"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.ID, directSessionXN(t, h, resp.Result.ID)
}

// TestDirectSessionNewCoinAlgoBlockFind proves a genuinely NEW
// standalone coin algo (ALGO_ARQ, one of the confirmed
// internal/coinprofile.Registry entries) works end-to-end through
// leaf-direct's REAL session code, via the exact same real
// solo.MoneroNodeClient pipeline ALGO_RXM already uses -- login with
// a real ARQ address (rejected if algo dispatch/address validation
// weren't genuinely generalized), submit a block-finding share, and
// confirm it is accepted and forwarded with the real submit_block
// block_id, exactly mirroring
// TestDirectSessionRXMBlockFindUsesRealSubmitBlockID's own assertions.
func TestDirectSessionNewCoinAlgoBlockFind(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectNewCoinBlockFindHarness(t, srv, 1, poolpb.Algo_ALGO_ARQ, realDirectARQMainnetAddr)

	sessionID, xn := directLoginNewCoin(t, h, realDirectARQMainnetAddr)
	jobID := directCurrentJobIDForSession(t, h, xn)

	h.send(solo.Request{ID: 50, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
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

	if daemon.submitCalls.Load() != 1 {
		t.Errorf("expected exactly 1 real submit_block call, got %d", daemon.submitCalls.Load())
	}

	waitForBlockCount(t, h.transport, 1)
	forwardedBlock := h.transport.blockAt(0)
	if forwardedBlock.GetAlgo() != poolpb.Algo_ALGO_ARQ {
		t.Errorf("forwarded block Algo = %v, want %v -- the new coin's own dedicated algo must be stamped on the Share/Block, not silently folded into ALGO_RXM", forwardedBlock.GetAlgo(), poolpb.Algo_ALGO_ARQ)
	}
	if forwardedBlock.GetHash() != moneroDirectDefaultBlockID {
		t.Fatalf("forwarded block hash = %q, want the real block_id from submit_block's own response %q", forwardedBlock.GetHash(), moneroDirectDefaultBlockID)
	}
}

// TestDirectSessionNewCoinAlgoRejectsWrongCoinAddress proves login
// address validation is genuinely coin-specific: a real Monero
// address must be REJECTED when logging in against an ALGO_ARQ job
// (different network bytes), proving this leaf did not silently fall
// back to Monero's own validator for the new algo.
func TestDirectSessionNewCoinAlgoRejectsWrongCoinAddress(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectNewCoinBlockFindHarness(t, srv, 1, poolpb.Algo_ALGO_ARQ, realDirectARQMainnetAddr)

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: realDirectXMRMainnetAddr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"rx/0"},
	})})
	resp := h.recvErrorResponse()
	if resp.Error == nil {
		t.Fatal("expected login to be rejected (real Monero address against an ALGO_ARQ job), got success")
	}
}
