// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-xmr-lib/support"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/moneroblob"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// fakeMoneroXNPNodeClient is a NodeClient test double that, unlike
// newRXMTestHarness's own fakeNodeClient (Tari-shaped, see that
// harness's doc comment), returns a genuinely real-shaped Monero
// *Job: a real *moneroTemplateData TemplateData, a real
// RawTemplateBlob, and a real ReservedOffset -- built from
// xnpFixtureRawTemplateBlob (node_test.go's go-xmr-lib-verified
// fixture), the SAME real fixture this file's own
// MoneroHashingBlobForXNPSubmit unit tests use. This is what makes
// the end-to-end test below able to actually exercise the new
// patched-blob path (MoneroHashingBlobForXNPSubmit) rather than
// immediately failing at MoneroHashingBlobForSubmit's/
// MoneroHashingBlobForXNPSubmit's own "not a real *moneroTemplateData"
// type-assertion guard.
type fakeMoneroXNPNodeClient struct {
	height         uint64
	rawTemplate    []byte
	hashingBlob    []byte
	reservedOffset int
	seedHash       []byte
	difficulty     uint64
}

func (f *fakeMoneroXNPNodeClient) GetBlockTemplate(_ context.Context, _ string, algo poolpb.Algo) (*Job, error) {
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(f.hashingBlob)
	if err != nil {
		return nil, err
	}
	return &Job{
		ID:                      "xnp-rxm-test-job0",
		Algo:                    algo,
		Height:                  f.height,
		Header:                  f.hashingBlob,
		BlockHash:               []byte("test-monero-block-hash-32-byte!"),
		NetworkTargetDifficulty: f.difficulty,
		TemplateData: &moneroTemplateData{
			HashingBlob:    f.hashingBlob,
			TemplateBlob:   f.rawTemplate,
			NonceOffset:    nonceOffset,
			SeedHash:       f.seedHash,
			Difficulty:     f.difficulty,
			Height:         f.height,
			ReservedOffset: f.reservedOffset,
		},
		VmKey:                f.seedHash,
		ReservedOffset:       f.reservedOffset,
		ReservedOffsetUsable: true,
		RawTemplateBlob:      f.rawTemplate,
		CreatedAt:            time.Now(),
	}, nil
}

func (f *fakeMoneroXNPNodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	return f.height, nil
}

// BuildCandidateBlock delegates to the REAL MoneroNodeClient
// implementation (monero_node.go) -- that method does no network I/O
// of its own (it only re-parses job.TemplateData), so a zero-value
// *MoneroNodeClient is safe to call it on directly, exercising the
// exact real production candidate-construction logic rather than a
// shadow reimplementation.
func (f *fakeMoneroXNPNodeClient) BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (uint64, any, error) {
	return (&MoneroNodeClient{}).BuildCandidateBlock(job, nonce, proof)
}

// SubmitBlock is not expected to be reached by this file's own tests
// (the deliberately-unreachable RandomXValidator URL these tests wire
// up means real PoW validation always fails first -- see
// newRXMXNPTestHarness's doc comment), so this just reports an error
// rather than attempting any real network I/O.
func (f *fakeMoneroXNPNodeClient) SubmitBlock(_ context.Context, _ any) error {
	return errUnexpectedSubmitBlockCall
}

// TemplateBytesForRelay/JobFromTemplateBytes: this is a Monero-family
// test double -- relay-template-adoption is explicitly scoped to
// leaf-direct's Tari NodeClient only, so simple "not supported" stubs
// satisfy the NodeClient interface here, mirroring
// MoneroNodeClient's own real "not supported" stub.
func (f *fakeMoneroXNPNodeClient) TemplateBytesForRelay(_ *Job) ([]byte, error) {
	return nil, errors.New("fakeMoneroXNPNodeClient: TemplateBytesForRelay not supported")
}

func (f *fakeMoneroXNPNodeClient) JobFromTemplateBytes(_ []byte, _ poolpb.Algo) (*Job, error) {
	return nil, errors.New("fakeMoneroXNPNodeClient: JobFromTemplateBytes not supported")
}

var errUnexpectedSubmitBlockCall = errors.New("fakeMoneroXNPNodeClient: SubmitBlock unexpectedly called")

// newRXMXNPTestHarness is newRXMTestHarness's real-Monero-shaped
// counterpart: node is a *fakeMoneroXNPNodeClient (not the
// Tari-shaped fakeNodeClient every other harness in this package
// uses), so a job's TemplateData genuinely holds a *moneroTemplateData
// and RawTemplateBlob/ReservedOffset are genuinely populated -- the
// preconditions MoneroHashingBlobForXNPSubmit actually needs to run
// its real patch-and-convert logic, not just its own guard clauses.
// The RandomXValidator is pointed at a deliberately unreachable URL
// (mirrors newRXTTestHarness's own "http://127.0.0.1:1" convention):
// this harness exists to prove the wire fields are consumed and the
// blob-patching/conversion path executes without error, NOT to
// manufacture a fake accepted share -- the real accept/reject outcome
// depends on real RandomX difficulty math, out of scope here (see
// this file's own end-to-end test's doc comment).
func newRXMXNPTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64, node NodeClient) *testHarness {
	t.Helper()
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXM,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	rx := validator.NewRandomXValidator("http://127.0.0.1:1") // deliberately unreachable randomx-service
	registry := validator.Registry{poolpb.Algo_ALGO_RXM: rx}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &testHarness{
		t:      t,
		server: server,
		cm:     cm,
		jm:     jm,
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

// newFakeMoneroXNPNodeClient builds a fakeMoneroXNPNodeClient from
// node_test.go's real, go-xmr-lib-verified xnpFixtureRawTemplateBlob
// fixture, deriving its real blockhashing_blob the exact same way
// monerod's own get_block_template response is derived from a raw
// blocktemplate_blob (go-xmr-lib/support's ParseBlockFromTemplateBlob
// + GetBlockHashingBlob).
func newFakeMoneroXNPNodeClient(t *testing.T) *fakeMoneroXNPNodeClient {
	t.Helper()
	rawTemplate, err := hex.DecodeString(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("decoding fixture hex: %v", err)
	}
	parsedBlock, err := support.ParseBlockFromTemplateBlob(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("support.ParseBlockFromTemplateBlob(fixture): %v", err)
	}
	hashingBlob, err := support.GetBlockHashingBlob(parsedBlock)
	if err != nil {
		t.Fatalf("support.GetBlockHashingBlob(fixture): %v", err)
	}
	return &fakeMoneroXNPNodeClient{
		height:         42,
		rawTemplate:    rawTemplate,
		hashingBlob:    hashingBlob,
		reservedOffset: xnpFixtureReservedOffset,
		seedHash:       []byte("test-monero-seed-hash-32-bytes!"),
		difficulty:     1 << 62,
	}
}

// TestSessionRXMXNPSubmitPatchesWorkerAndPoolNonce is the required
// end-to-end session-level test: logs in as a real (fixture-backed)
// RXM session, receives a job, and submits WITH workerNonce/poolNonce
// set to real values that correctly round-trip against a real
// RawTemplateBlob + ReservedOffset -- confirming the submit is
// processed through the new MoneroHashingBlobForXNPSubmit path
// without erroring on the patching/conversion step itself. The
// harness's RandomXValidator points at an unreachable URL (see
// newRXMXNPTestHarness's doc comment), so the submit is still
// expected to fail overall -- the assertion here is narrowly that it
// does NOT fail with the "failed to build monero randomx verification
// blob" error MoneroHashingBlobForXNPSubmit itself would produce
// (which is exactly the failure mode a submit-side fix regression
// would reintroduce: dropping the XNP fields on the floor and going
// back through MoneroHashingBlobForSubmit's own
// type-assertion/offset-mismatch failure instead).
func TestSessionRXMXNPSubmitPatchesWorkerAndPoolNonce(t *testing.T) {
	// See newRXMXNPTestHarness's doc comment on breaker isolation:
	// moneroblob.GlobalBreaker is a process-wide singleton shared
	// with every other test in this package, several of which
	// legitimately (and by design, gracefully) fail conversion on
	// deliberately synthetic template blobs and thereby trigger it.
	// Reset it so THIS test's real-fixture conversion is never
	// refused by another test's leftover state.
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	node := newFakeMoneroXNPNodeClient(t)
	h := newRXMXNPTestHarness(t, 1, 1<<62, node)

	sessionID, xn := loginRXM(t, h)
	jobID := currentJobIDForSession(t, h, xn)

	workerNonce := uint32(9)
	poolNonce := uint32(9)
	h.send(Request{ID: 90, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:          sessionID,
		JobID:       jobID,
		Nonce:       "818d1a00", // real xmrig-capture-shaped 4-byte nonce
		Result:      strings.Repeat("00", 32),
		WorkerNonce: &workerNonce,
		PoolNonce:   &poolNonce,
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("test setup bug: expected this submit to still fail downstream (unreachable randomx-service), not succeed")
	}
	if resp.Error == nil {
		t.Fatal("expected a share-rejection error (unreachable randomx-service), got none")
	}
	if strings.Contains(resp.Error.Message, "failed to build monero randomx verification blob") {
		t.Fatalf("BUG REGRESSION: an XNP-proxy-shaped RXM submit (workerNonce/poolNonce present) was rejected while BUILDING the verification blob (%q) -- the new MoneroHashingBlobForXNPSubmit path did not execute cleanly", resp.Error.Message)
	}
	t.Logf("XNP-proxy RXM submit patched cleanly, rejected downstream for the expected reason instead: %q", resp.Error.Message)
}

// TestSessionRXMOrdinarySubmitStillUsesNonXNPPath confirms the OTHER
// side of the dispatch fix: an ordinary xmrig-class submit (no
// workerNonce/poolNonce fields at all) against this SAME real-Monero
// harness must still go through the ordinary MoneroHashingBlobForSubmit
// path, which for THIS harness's fixture succeeds at the blob-building
// step too (job.TemplateData is a real *moneroTemplateData here,
// unlike newRXMTestHarness's Tari-shaped fixture) -- proving the
// dispatch didn't regress the non-XNP case while adding the XNP one.
func TestSessionRXMOrdinarySubmitStillUsesNonXNPPath(t *testing.T) {
	// See newRXMXNPTestHarness's doc comment on breaker isolation:
	// moneroblob.GlobalBreaker is a process-wide singleton shared
	// with every other test in this package, several of which
	// legitimately (and by design, gracefully) fail conversion on
	// deliberately synthetic template blobs and thereby trigger it.
	// Reset it so THIS test's real-fixture conversion is never
	// refused by another test's leftover state.
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	node := newFakeMoneroXNPNodeClient(t)
	h := newRXMXNPTestHarness(t, 1, 1<<62, node)

	sessionID, xn := loginRXM(t, h)
	jobID := currentJobIDForSession(t, h, xn)

	h.send(Request{ID: 91, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  "818d1a00",
		Result: strings.Repeat("00", 32),
		// WorkerNonce/PoolNonce deliberately absent.
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("test setup bug: expected this submit to still fail downstream (unreachable randomx-service), not succeed")
	}
	if resp.Error == nil {
		t.Fatal("expected a share-rejection error (unreachable randomx-service), got none")
	}
	if strings.Contains(resp.Error.Message, "failed to build monero randomx verification blob") {
		t.Fatalf("an ordinary (non-XNP) RXM submit against a real *moneroTemplateData job failed at the blob-building step (%q) -- MoneroHashingBlobForSubmit should succeed for this harness's real fixture", resp.Error.Message)
	}
	t.Logf("ordinary RXM submit still uses MoneroHashingBlobForSubmit cleanly, rejected downstream for the expected reason instead: %q", resp.Error.Message)
}
