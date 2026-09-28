// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-xmr-lib/support"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/moneroblob"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// xnpDirectFixtureRawTemplateBlob/xnpDirectFixtureReservedOffset are
// the SAME real, go-xmr-lib-verified fixture used by
// internal/leaflib/solo's node_test.go (xnpFixtureRawTemplateBlob/
// xnpFixtureReservedOffset) -- duplicated here per this repo's own
// established convention of duplicating small real fixtures/helpers
// across packages rather than exporting test-only data (see
// solo/node.go's tariJobFromResult doc comment for a description of
// that same convention).
const (
	xnpDirectFixtureRawTemplateBlob = "0e0ed286da8006ecdc1aab3033cf1716c52f13f9d8ae0051615a2453643de94643b550d543becd0000000002abc78b0101ffefc68b0101fcfcf0d4b422025014bb4a1eade6622fd781cb1063381cad396efa69719b41aa28b4fce8c7ad4b5f019ce1dc670456b24a5e03c2d9058a2df10fec779e2579753b1847b74ee644f16b023c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000051399a1bc46a846474f5b33db24eae173a26393b976054ee14f9feefe99925233802867097564c9db7a36af5bb5ed33ab46e63092bd8d32cef121608c3258edd55562812e21cc7e3ac73045745a72f7d74581d9a0849d6f30e8b2923171253e864f4e9ddea3acb5bc755f1c4a878130a70c26297540bc0b7a57affb6b35c1f03d8dbd54ece8457531f8cba15bb74516779c01193e212050423020e45aa2c15dcb"
	xnpDirectFixtureReservedOffset  = 130
)

// fakeDirectMoneroXNPNodeClient is a solo.NodeClient test double,
// analogous to solo package's own fakeMoneroXNPNodeClient
// (solo/session_xnp_rxm_submit_test.go): unlike this file's sibling
// fakeDirectNodeClient (Tari-shaped), it returns a *solo.Job with a
// genuinely real RawTemplateBlob and ReservedOffset -- the two
// EXPORTED Job fields solo.MoneroHashingBlobForXNPSubmit actually
// needs (that function does not type-assert job.TemplateData at all
// -- see solo/node.go's doc comment -- so, unlike the ordinary
// solo.MoneroHashingBlobForSubmit path, this test double does not
// need to construct solo's own unexported *moneroTemplateData type,
// which is not reachable from this package anyway).
type fakeDirectMoneroXNPNodeClient struct {
	height         uint64
	rawTemplate    []byte
	hashingBlob    []byte
	reservedOffset int
	seedHash       []byte
	difficulty     uint64
}

func (f *fakeDirectMoneroXNPNodeClient) GetBlockTemplate(_ context.Context, _ string, algo poolpb.Algo) (*solo.Job, error) {
	return &solo.Job{
		ID:                      "xnp-rxm-direct-test-job0",
		Algo:                    algo,
		Height:                  f.height,
		Header:                  f.hashingBlob,
		BlockHash:               []byte("direct-test-monero-block-hash-3"),
		NetworkTargetDifficulty: f.difficulty,
		VmKey:                   f.seedHash,
		ReservedOffset:          f.reservedOffset,
		ReservedOffsetUsable:    true,
		RawTemplateBlob:         f.rawTemplate,
		CreatedAt:               time.Now(),
	}, nil
}

func (f *fakeDirectMoneroXNPNodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	return f.height, nil
}

func (f *fakeDirectMoneroXNPNodeClient) BuildCandidateBlock(_ *solo.Job, _ uint64, _ solo.SubmitProof) (uint64, any, error) {
	return 0, nil, errUnexpectedDirectXNPCandidateCall
}

func (f *fakeDirectMoneroXNPNodeClient) SubmitBlock(_ context.Context, _ any) error {
	return errUnexpectedDirectXNPSubmitBlockCall
}

// TemplateBytesForRelay/JobFromTemplateBytes: this is a Monero-family
// test double -- relay-template-adoption is explicitly scoped to
// leaf-direct's Tari NodeClient only (see node.go's real
// implementation), so simple "not supported" stubs satisfy
// solo.NodeClient here.
func (f *fakeDirectMoneroXNPNodeClient) TemplateBytesForRelay(_ *solo.Job) ([]byte, error) {
	return nil, errors.New("fakeDirectMoneroXNPNodeClient: TemplateBytesForRelay not supported")
}

func (f *fakeDirectMoneroXNPNodeClient) JobFromTemplateBytes(_ []byte, _ poolpb.Algo) (*solo.Job, error) {
	return nil, errors.New("fakeDirectMoneroXNPNodeClient: JobFromTemplateBytes not supported")
}

var (
	errUnexpectedDirectXNPCandidateCall   = errors.New("fakeDirectMoneroXNPNodeClient: BuildCandidateBlock unexpectedly called")
	errUnexpectedDirectXNPSubmitBlockCall = errors.New("fakeDirectMoneroXNPNodeClient: SubmitBlock unexpectedly called")
)

// newFakeDirectMoneroXNPNodeClient builds a fakeDirectMoneroXNPNodeClient
// from the real, go-xmr-lib-verified xnpDirectFixtureRawTemplateBlob
// fixture, deriving its real blockhashing_blob the same way monerod's
// own get_block_template response is derived from a raw
// blocktemplate_blob.
func newFakeDirectMoneroXNPNodeClient(t *testing.T) *fakeDirectMoneroXNPNodeClient {
	t.Helper()
	rawTemplate, err := hex.DecodeString(xnpDirectFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("decoding fixture hex: %v", err)
	}
	parsedBlock, err := support.ParseBlockFromTemplateBlob(xnpDirectFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("support.ParseBlockFromTemplateBlob(fixture): %v", err)
	}
	hashingBlob, err := support.GetBlockHashingBlob(parsedBlock)
	if err != nil {
		t.Fatalf("support.GetBlockHashingBlob(fixture): %v", err)
	}
	return &fakeDirectMoneroXNPNodeClient{
		height:         42,
		rawTemplate:    rawTemplate,
		hashingBlob:    hashingBlob,
		reservedOffset: xnpDirectFixtureReservedOffset,
		seedHash:       []byte("direct-test-monero-seed-hash-32"),
		difficulty:     1 << 62,
	}
}

// newDirectRXMXNPTestHarness is newDirectRXMTestHarness's
// real-Monero-shaped counterpart -- mirrors solo package's own
// newRXMXNPTestHarness (see that function's doc comment for the full
// rationale): node is a *fakeDirectMoneroXNPNodeClient so
// RawTemplateBlob/ReservedOffset are genuinely populated, and the
// RandomXValidator points at a deliberately unreachable URL, so this
// harness proves the XNP wire fields are consumed and the
// blob-patching/conversion path executes without error, not that a
// share is actually accepted.
func newDirectRXMXNPTestHarness(t *testing.T, staticDiff, networkTargetDiff uint64, node solo.NodeClient) *directTestHarness {
	t.Helper()
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXM,
	})

	rx := validator.NewRandomXValidator("http://127.0.0.1:1") // deliberately unreachable randomx-service
	registry := validator.Registry{poolpb.Algo_ALGO_RXM: rx}

	tr := &fakeShareTransport{}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm,
		JobManager:        jm,
		Node:              node,
		Validators:        registry,
		Network:           poolpb.Network_NETWORK_TESTNET,
		Transport:         tr,
		MultiSubmit:       multi,
		Algo:              poolpb.Algo_ALGO_RXM,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            42,
	})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &directTestHarness{
		t: t, server: server, jm: jm, transport: tr, submit: sub,
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

// TestDirectSessionRXMXNPSubmitPatchesWorkerAndPoolNonce is
// leaf-direct's counterpart of solo package's own
// TestSessionRXMXNPSubmitPatchesWorkerAndPoolNonce -- see that test's
// doc comment for the full rationale. Logs in as a real
// (fixture-backed) RXM session and submits WITH workerNonce/poolNonce
// set, confirming the submit goes through
// solo.MoneroHashingBlobForXNPSubmit's real patch-and-convert logic
// without erroring there (the harness's unreachable RandomXValidator
// still fails the submit overall -- that part is expected and out of
// scope).
func TestDirectSessionRXMXNPSubmitPatchesWorkerAndPoolNonce(t *testing.T) {
	// moneroblob.GlobalBreaker is a genuinely process-wide singleton
	// (see that package's doc comment for why), so it is shared with
	// every OTHER test in this package -- including the many
	// Monero-shaped test doubles whose deliberately small, synthetic
	// template blobs are NOT real, go-xmr-lib-parseable Monero
	// blocks. Those doubles now reach a real conversion attempt via
	// solo.JobManager's own per-job extraNonce stamp (which degrades
	// gracefully, exactly as designed -- but each degradation is a
	// genuine breaker trigger), and enough of them in sequence trip
	// the breaker OPEN, which would then refuse THIS test's own,
	// entirely legitimate conversion of a real fixture. Resetting
	// the singleton here (and restoring it afterward) is the same
	// test-isolation discipline internal/leaflib/proxy's own
	// breaker-wiring test already uses; it does not weaken the
	// breaker itself, which moneroblob's own unit tests cover
	// directly against isolated instances.
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	node := newFakeDirectMoneroXNPNodeClient(t)
	h := newDirectRXMXNPTestHarness(t, 1, 1<<62, node)

	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

	workerNonce := uint32(9)
	poolNonce := uint32(9)
	h.send(solo.Request{ID: 90, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:          sessionID,
		JobID:       jobID,
		Nonce:       "818d1a00",
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
		t.Fatalf("BUG REGRESSION: an XNP-proxy-shaped RXM submit (workerNonce/poolNonce present) was rejected while BUILDING the verification blob (%q) -- the new solo.MoneroHashingBlobForXNPSubmit path did not execute cleanly", resp.Error.Message)
	}
	t.Logf("XNP-proxy RXM submit (leaf-direct) patched cleanly, rejected downstream for the expected reason instead: %q", resp.Error.Message)
}
