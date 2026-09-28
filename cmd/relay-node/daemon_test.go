// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// startEmbeddedNATSServer starts a real, in-process, embedded NATS
// server (github.com/nats-io/nats-server/v2's own public server.New/
// Start/ReadyForConnections API), bound to an OS-assigned free port.
// Deliberately duplicated from internal/leaflib/relay/relay_test.go's
// identical helper -- this repo's own established convention (see
// solo/node.go's convertRawTemplateBlobToHashingBlob doc comment) is
// to duplicate small, single-package test helpers like this rather
// than export a test-only symbol across a package boundary.
func startEmbeddedNATSServer(t *testing.T) (url string, shutdown func()) {
	t.Helper()
	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1,
		NoLog:          true,
		NoSigs:         true,
		MaxControlLine: 4096,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("starting embedded NATS server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("embedded NATS server did not become ready within 5s")
	}
	t.Cleanup(func() {
		srv.Shutdown()
		srv.WaitForShutdown()
	})
	return srv.ClientURL(), srv.Shutdown
}

// realMoneroFixtureBlobHex/syntheticMoneroTestnetAddress/
// mockMoneroGetBlockTemplateServer are deliberately duplicated from
// internal/leaflib/solo/monero_node_test.go's identical
// realFixtureBlobHex/syntheticTestnetAddress/
// mockGetBlockTemplateServer helpers -- this repo's own established
// convention (see solo/node.go's convertRawTemplateBlobToHashingBlob
// doc comment) is to duplicate small, single-package test helpers
// like this rather than export a test-only symbol across a package
// boundary (and the originals are themselves unexported _test.go
// symbols in a different package, so they are not reachable from
// here at all). A real, go-xmr-lib-verified monerod get_block_template
// blob (both blockhashing_blob and blocktemplate_blob are the SAME
// fixture bytes, which trivially satisfies GetBlockTemplate's own
// header-prefix-match check): 76 bytes, real nonce offset 39.
const realMoneroFixtureBlobHex = "1010c3f4a4d4062d5456c2d3d54707336bc352fc9910c8adbd586603439b548fca04de64c1973d00000000936c23078acfd28dc0b307b8a2e63eb4eef27681ebb63f9ec67f09b8e3b59cef01"

// syntheticMoneroTestnetAddress is a syntactically-valid (correct
// base58 length/prefix) but NOT real Monero testnet address --
// GetBlockTemplate only needs a well-formed payout address to build
// its own outbound RPC request; monerod's response is fully
// controlled by mockMoneroGetBlockTemplateServer below regardless of
// what address was sent.
const syntheticMoneroTestnetAddress = "9tvbsnp9XjUNeDkhsC9JQ7Eh8naZeS6YNFsMbi1oaym83M1FhSjoyToiy2T1F7fSE6MXws1Wypo4XfECHuzqKw7XBMMwQ5e"

// mockMoneroGetBlockTemplateServer starts a real local httptest server
// whose /json_rpc get_block_template response carries a real,
// well-formed fixture template (realMoneroFixtureBlobHex, a fixed
// reserved_offset of 10 which fits within the fixture's 76-byte
// length) -- enough for a real *solo.MoneroNodeClient.GetBlockTemplate
// call to succeed end to end.
func mockMoneroGetBlockTemplateServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/json_rpc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{
			"blockhashing_blob":"%s",
			"blocktemplate_blob":"%s",
			"difficulty":1000,
			"height":123,
			"prev_hash":"%s",
			"reserved_offset":10,
			"seed_hash":"%s",
			"seed_height":100,
			"status":"OK"
		}}`, realMoneroFixtureBlobHex, realMoneroFixtureBlobHex, hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32)), hex.EncodeToString(bytes.Repeat([]byte{0xCD}, 32)))
	})
	return httptest.NewServer(mux)
}

// mockNodeClient is a solo.NodeClient test double -- no real GRPC/RPC
// connection, deterministic behavior, real call counters so tests can
// assert exactly how many times each method was invoked. Mirrors
// internal/leaflib/solo/job_test.go's own fakeNodeClient convention
// (a mocked NodeClient injected via the interface, never a real
// network call) at a level of simplicity relay-node's own tests need.
type mockNodeClient struct {
	mu sync.Mutex

	height    uint64
	heightErr error

	job    *solo.Job
	jobErr error

	// relayTemplateData/relayTemplateErr control TemplateBytesForRelay's
	// return value -- as of this fix, templateDataForJob's
	// Monero-family branch genuinely calls this (delegating to
	// d.Node.TemplateBytesForRelay(job), exactly like leaf-direct's
	// own solo/job.go), so this mock double needs a real, controllable
	// implementation rather than the old always-error stub. Both zero
	// values (nil, nil) mirror solo.NodeClient.TemplateBytesForRelay's
	// own documented "cannot serialize for a benign reason" contract.
	relayTemplateData []byte
	relayTemplateErr  error

	getTipInfoCalls       int
	getBlockTemplateCalls int
	submitBlockCalls      int
	lastSubmitCandidate   any
	submitErr             error
}

func (m *mockNodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getTipInfoCalls++
	return m.height, m.heightErr
}

func (m *mockNodeClient) setHeight(h uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.height = h
}

func (m *mockNodeClient) GetBlockTemplate(_ context.Context, _ string, _ poolpb.Algo) (*solo.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getBlockTemplateCalls++
	if m.jobErr != nil {
		return nil, m.jobErr
	}
	return m.job, nil
}

func (m *mockNodeClient) BuildCandidateBlock(_ *solo.Job, _ uint64, _ solo.SubmitProof) (uint64, any, error) {
	return 0, nil, errors.New("mockNodeClient: BuildCandidateBlock not used by relay-node")
}

func (m *mockNodeClient) SubmitBlock(_ context.Context, candidate any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.submitBlockCalls++
	m.lastSubmitCandidate = candidate
	return m.submitErr
}

// JobFromTemplateBytes implements solo.NodeClient -- relay-node itself
// never calls this (it only PUBLISHES template bytes, it never ADOPTS
// a relayed template the way leaf-direct's JobManager does), so this
// is a simple, clearly-unused stub, mirroring solo.GRPCNodeClient's
// own "not supported" stub convention.
func (m *mockNodeClient) JobFromTemplateBytes(_ []byte, _ poolpb.Algo) (*solo.Job, error) {
	return nil, errors.New("mockNodeClient: JobFromTemplateBytes not used by relay-node")
}

// TemplateBytesForRelay implements solo.NodeClient -- as of this fix,
// templateDataForJob's Monero-family branch genuinely calls this (see
// daemon.go), so, unlike JobFromTemplateBytes above, this is a real,
// test-controllable double, not an unused stub. See
// relayTemplateData/relayTemplateErr's own doc comment above.
func (m *mockNodeClient) TemplateBytesForRelay(_ *solo.Job) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relayTemplateErr != nil {
		return nil, m.relayTemplateErr
	}
	return m.relayTemplateData, nil
}

func (m *mockNodeClient) callCounts() (tip, template, submit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getTipInfoCalls, m.getBlockTemplateCalls, m.submitBlockCalls
}

// newTariJob builds a minimal-but-real solo.Job for a Tari algo,
// carrying a real (if sparsely populated) *tari_generated.GetNewBlockResult
// as TemplateData -- exactly the shape solo.GRPCNodeClient's own
// tariJobFromResult produces (node.go), which is what
// templateDataForJob's Tari branch type-asserts for.
func newTariJob(height uint64) *solo.Job {
	return &solo.Job{
		Height:    height,
		Algo:      poolpb.Algo_ALGO_SHA3X,
		BlockHash: []byte{0xaa, 0xbb},
		TemplateData: &tari_generated.GetNewBlockResult{
			BlockHash: []byte{0xaa, 0xbb},
			Block: &tari_generated.Block{
				Header: &tari_generated.BlockHeader{Height: height},
			},
		},
		CreatedAt: time.Now(),
	}
}

// newMoneroJob builds a minimal-but-real solo.Job for a Monero-family
// algo, carrying a real, non-empty RawTemplateBlob -- exactly the
// exported field solo.MoneroNodeClient.GetBlockTemplate populates
// (monero_node.go). Used only by tests that don't care about the
// EXACT bytes templateDataForJob's Monero branch publishes (that
// branch now delegates entirely to node.TemplateBytesForRelay(job) --
// see TestTemplateDataForJob_Monero* below, and
// TestTemplateDataForJob_MoneroRealNodeClientRoundTrip for the real,
// cross-component wire-compatibility regression test).
func newMoneroJob(height uint64) *solo.Job {
	return &solo.Job{
		Height:          height,
		Algo:            poolpb.Algo_ALGO_XMR,
		BlockHash:       []byte{0xcc, 0xdd},
		RawTemplateBlob: []byte{0x01, 0x02, 0x03, 0x04},
		CreatedAt:       time.Now(),
	}
}

// TestTemplateDataForJob_Tari confirms the Tari branch produces a
// real proto.Marshal of the job's own GetNewBlockResult, decodable
// back into an equivalent message. This is deliberately NOT delegated
// to node.TemplateBytesForRelay -- passing a node whose
// TemplateBytesForRelay would fail/panic if called proves the Tari
// branch never calls it (see daemon.go's templateDataForJob doc
// comment for why: -coin=tari's real NodeClient,
// *solo.GRPCNodeClient, hard-errors on that call).
func TestTemplateDataForJob_Tari(t *testing.T) {
	job := newTariJob(100)
	node := &mockNodeClient{relayTemplateErr: errors.New("TestTemplateDataForJob_Tari: TemplateBytesForRelay must not be called for a Tari job")}
	data, err := templateDataForJob(coinTari, node, job)
	if err != nil {
		t.Fatalf("templateDataForJob: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty TemplateData for a Tari job")
	}
	var decoded tari_generated.GetNewBlockResult
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding TemplateData back into GetNewBlockResult: %v", err)
	}
	if decoded.GetBlock().GetHeader().GetHeight() != 100 {
		t.Errorf("decoded height = %d, want 100", decoded.GetBlock().GetHeader().GetHeight())
	}
}

// TestTemplateDataForJob_Monero is this fix's core unit-level proof:
// the Monero-family branch no longer hand-rolls its own encoding of
// job.RawTemplateBlob -- it delegates entirely to
// node.TemplateBytesForRelay(job) and returns exactly what that call
// returns, byte for byte. Real end-to-end wire compatibility with
// solo.MoneroNodeClient.JobFromTemplateBytes is separately covered by
// TestTemplateDataForJob_MoneroRealNodeClientRoundTrip below.
func TestTemplateDataForJob_Monero(t *testing.T) {
	job := newMoneroJob(200)
	want := []byte(`{"hashing_blob":"aabb","template_blob":"aabb","seed_hash":null,"prev_hash":null,"difficulty":42,"height":200,"reserved_offset":0}`)
	node := &mockNodeClient{relayTemplateData: want}
	data, err := templateDataForJob(coinMonero, node, job)
	if err != nil {
		t.Fatalf("templateDataForJob: %v", err)
	}
	if string(data) != string(want) {
		t.Errorf("TemplateData = %s, want %s (node.TemplateBytesForRelay's own return value, verbatim)", data, want)
	}
}

// TestTemplateDataForJob_MoneroPropagatesError confirms a genuine
// node.TemplateBytesForRelay error is surfaced (never silently
// swallowed into empty-but-"successful" TemplateData).
func TestTemplateDataForJob_MoneroPropagatesError(t *testing.T) {
	job := newMoneroJob(1)
	node := &mockNodeClient{relayTemplateErr: errors.New("boom")}
	if _, err := templateDataForJob(coinMonero, node, job); err == nil {
		t.Fatal("expected an error when node.TemplateBytesForRelay errors, got nil")
	}
}

// TestTemplateDataForJob_MoneroEmptyData confirms node.
// TemplateBytesForRelay's documented (nil, nil) "cannot serialize for
// a benign reason" contract is still surfaced as a real, reported
// error from templateDataForJob itself (never silently produces
// empty-but-"successful" TemplateData) -- matching this function's
// pre-existing contract for the analogous Tari failure case.
func TestTemplateDataForJob_MoneroEmptyData(t *testing.T) {
	job := newMoneroJob(1)
	node := &mockNodeClient{} // relayTemplateData/relayTemplateErr both zero-value.
	if _, err := templateDataForJob(coinMonero, node, job); err == nil {
		t.Fatal("expected an error when node.TemplateBytesForRelay returns (nil, nil), got nil")
	}
}

// TestTemplateDataForJob_MoneroRealNodeClientRoundTrip is the real,
// cross-component wire-compatibility regression test this bug
// represents (see BRIEF.md): a real *solo.Job produced by a real
// *solo.MoneroNodeClient.GetBlockTemplate call (against a mocked
// monerod, via mockMoneroGetBlockTemplateServer) is encoded through
// templateDataForJob's Monero-family branch -- the EXACT function
// relay-node's own publishTemplateForHeight calls -- and the
// resulting bytes are fed straight into a DIFFERENT
// *solo.MoneroNodeClient's JobFromTemplateBytes, simulating a
// genuinely separate leaf-direct-Monero process receiving this
// relay-node instance's published template over the shared NATS
// subject. Before this fix, templateDataForJob published
// job.RawTemplateBlob's raw bytes directly, which
// JobFromTemplateBytes's JSON unmarshal would reject outright (the
// real production symptom this whole fix exists for -- see BRIEF.md's
// root-cause section for the exact log line).
func TestTemplateDataForJob_MoneroRealNodeClientRoundTrip(t *testing.T) {
	srv := mockMoneroGetBlockTemplateServer(t)
	defer srv.Close()

	// Both clients pinned to the SAME instanceID: JobFromTemplateBytes
	// stamps the RECEIVING instance's own instanceID into the
	// reserved region on every call (see monero_node.go's
	// stampInstanceID doc comment) -- two genuinely different
	// instances would legitimately diverge there, which is its own
	// separately-tested behavior (solo/monero_node_relay_test.go's
	// TestMoneroNodeClient_JobFromTemplateBytes_StampsDistinctInstanceIDs),
	// not what THIS test is proving. Pinning both keeps this test's
	// byte-equality assertions meaningful for every field other than
	// that stamp.
	sameInstanceID := [4]byte{0x11, 0x22, 0x33, 0x44}
	sendingNode := solo.NewMoneroNodeClient(srv.URL)
	sendingNode.SetInstanceID(sameInstanceID)
	originalJob, err := sendingNode.GetBlockTemplate(context.Background(), syntheticMoneroTestnetAddress, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("GetBlockTemplate (sending side): %v", err)
	}

	data, err := templateDataForJob(coinMonero, sendingNode, originalJob)
	if err != nil {
		t.Fatalf("templateDataForJob: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("templateDataForJob returned empty data for a real, populated Monero job")
	}

	// A genuinely different MoneroNodeClient instance -- no shared
	// state, no baseURL even configured -- simulating a sibling
	// leaf-direct-Monero process receiving this relay-node instance's
	// published bytes over NATS.
	receivingNode := solo.NewMoneroNodeClient("")
	receivingNode.SetInstanceID(sameInstanceID)
	reconstructedJob, err := receivingNode.JobFromTemplateBytes(data, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("JobFromTemplateBytes: %v (relay-node's published bytes must be decodable by solo.MoneroNodeClient.JobFromTemplateBytes -- this is the exact regression this fix addresses)", err)
	}
	if reconstructedJob == nil {
		t.Fatal("JobFromTemplateBytes returned a nil job with a nil error")
	}

	if reconstructedJob.Height != originalJob.Height {
		t.Errorf("reconstructed Height = %d, want %d", reconstructedJob.Height, originalJob.Height)
	}
	if !bytes.Equal(reconstructedJob.Header, originalJob.Header) {
		t.Errorf("reconstructed Header = %x, want %x", reconstructedJob.Header, originalJob.Header)
	}
	if !bytes.Equal(reconstructedJob.RawTemplateBlob, originalJob.RawTemplateBlob) {
		t.Errorf("reconstructed RawTemplateBlob = %x, want %x", reconstructedJob.RawTemplateBlob, originalJob.RawTemplateBlob)
	}
	if reconstructedJob.NetworkTargetDifficulty != originalJob.NetworkTargetDifficulty {
		t.Errorf("reconstructed NetworkTargetDifficulty = %d, want %d", reconstructedJob.NetworkTargetDifficulty, originalJob.NetworkTargetDifficulty)
	}
	if reconstructedJob.Algo != poolpb.Algo_ALGO_RXM {
		t.Errorf("reconstructed Algo = %v, want ALGO_RXM", reconstructedJob.Algo)
	}
}

// TestDaemonPollOnce_SeedsBaselineWithoutPublishing covers
// requirement (a)'s "NOT on an unchanged height" half for the very
// first observation: no relay traffic at all on the first PollOnce.
func TestDaemonPollOnce_SeedsBaselineWithoutPublishing(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	node := &mockNodeClient{height: 1000, job: newTariJob(1000)}
	pubRelay := relay.NewRelay(relay.Config{URL: url})
	defer pubRelay.Close()
	subRelay := relay.NewRelay(relay.Config{URL: url})
	defer subRelay.Close()

	received := make(chan relay.TemplateMessage, 4)
	unsub, err := subRelay.SubscribeTemplate(func(msg relay.TemplateMessage) { received <- msg })
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsub()
	time.Sleep(100 * time.Millisecond)

	d := NewDaemon(node, pubRelay, poolpb.Algo_ALGO_SHA3X, coinTari, "testnet", "payout", nil)
	if err := d.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}

	select {
	case msg := <-received:
		t.Fatalf("expected NO template publish on the first (baseline-seeding) PollOnce, got %+v", msg)
	case <-time.After(500 * time.Millisecond):
		// Expected: no message.
	}

	if _, templateCalls, _ := node.callCounts(); templateCalls != 0 {
		t.Errorf("expected GetBlockTemplate to NOT be called on baseline seed, got %d calls", templateCalls)
	}
}

// TestDaemonPollOnce_PublishesOnHeightChangeOnly is the required
// requirement-(a) proof: a genuine height increase triggers exactly
// one real PublishTemplate call with the correct Algo/Network/Height
// tags, and a repeated poll at the SAME height triggers none.
func TestDaemonPollOnce_PublishesOnHeightChangeOnly(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	node := &mockNodeClient{height: 1000, job: newTariJob(1000)}
	pubRelay := relay.NewRelay(relay.Config{URL: url})
	defer pubRelay.Close()
	subRelay := relay.NewRelay(relay.Config{URL: url})
	defer subRelay.Close()

	received := make(chan relay.TemplateMessage, 4)
	unsub, err := subRelay.SubscribeTemplate(func(msg relay.TemplateMessage) { received <- msg })
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsub()
	time.Sleep(100 * time.Millisecond)

	d := NewDaemon(node, pubRelay, poolpb.Algo_ALGO_SHA3X, coinTari, "testnet", "payout", nil)

	// First call: baseline seed, no publish (see previous test).
	if err := d.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce (seed): %v", err)
	}

	// Second call: same height, still no publish.
	if err := d.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce (unchanged): %v", err)
	}
	select {
	case msg := <-received:
		t.Fatalf("expected NO template publish for an unchanged height, got %+v", msg)
	case <-time.After(300 * time.Millisecond):
	}

	// Third call: genuine height increase -- expect exactly one
	// publish with the correct tags.
	node.setHeight(1001)
	node.mu.Lock()
	node.job = newTariJob(1001)
	node.mu.Unlock()
	if err := d.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce (increase): %v", err)
	}

	select {
	case msg := <-received:
		if msg.Height != 1001 {
			t.Errorf("published Height = %d, want 1001", msg.Height)
		}
		if msg.Algo != "sha3x" {
			t.Errorf("published Algo = %q, want %q", msg.Algo, "sha3x")
		}
		if msg.Network != "testnet" {
			t.Errorf("published Network = %q, want %q", msg.Network, "testnet")
		}
		if len(msg.TemplateData) == 0 {
			t.Error("expected non-empty TemplateData on a real height-change publish")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected a real template publish on genuine height increase, got none within 5s")
	}

	// No further, unexpected publish should follow.
	select {
	case msg := <-received:
		t.Fatalf("expected exactly one publish for the single height increase, got an extra one: %+v", msg)
	case <-time.After(300 * time.Millisecond):
	}

	if _, templateCalls, _ := node.callCounts(); templateCalls != 1 {
		t.Errorf("expected exactly 1 real GetBlockTemplate call (for the single height increase), got %d", templateCalls)
	}
}

// TestZMQOnBlockFunc_TriggersImmediateRePoll is requirement (b)'s
// proof: the real callback wired into monerozmq.NewClient triggers an
// immediate extra PollOnce (observable via the mock's GetTipInfo call
// counter) -- this exercises the exact function main.go wires as the
// ZMQ onBlock callback for -coin=monero, not a hand-rolled shadow of
// it.
func TestZMQOnBlockFunc_TriggersImmediateRePoll(t *testing.T) {
	node := &mockNodeClient{height: 500, job: newMoneroJob(500)}
	// Disabled relay (empty URL) -- this test only needs to prove the
	// re-poll happens, not exercise relay publish behavior.
	d := NewDaemon(node, relay.NewRelay(relay.Config{URL: ""}), poolpb.Algo_ALGO_XMR, coinMonero, "testnet", "payout", nil)

	onBlock := zmqOnBlockFunc(context.Background(), d, d.Logger)

	if tip, _, _ := node.callCounts(); tip != 0 {
		t.Fatalf("expected zero GetTipInfo calls before the ZMQ trigger fires, got %d", tip)
	}
	onBlock()
	if tip, _, _ := node.callCounts(); tip != 1 {
		t.Errorf("expected exactly 1 GetTipInfo call immediately after the ZMQ onBlock callback fires, got %d", tip)
	}
}

// TestHandleFoundBlock_MatchingTariAlgoNetworkSubmits is requirement
// (c)'s primary proof: a genuinely matching Algo+Network Tari
// BlockMessage results in exactly one real SubmitBlock call, decoding
// the SAME real *tari_generated.Block bytes a real leaf-direct
// producer would have marshaled (see
// internal/leaflib/direct/server.go's marshalBlockForRelay -- this
// test independently re-implements that exact marshal to prove the
// decode side really round-trips against it).
func TestHandleFoundBlock_MatchingTariAlgoNetworkSubmits(t *testing.T) {
	node := &mockNodeClient{}
	d := NewDaemon(node, relay.NewRelay(relay.Config{URL: ""}), poolpb.Algo_ALGO_SHA3X, coinTari, "testnet", "payout", nil)

	block := &tari_generated.Block{Header: &tari_generated.BlockHeader{Height: 42}}
	data, err := proto.Marshal(block)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	d.handleFoundBlock(relay.BlockMessage{
		Algo: "sha3x", Network: "testnet", Height: 42, Hash: "deadbeef", BlockData: data,
	})

	if _, _, submits := node.callCounts(); submits != 1 {
		t.Fatalf("expected exactly 1 SubmitBlock call for a matching Algo/Network message, got %d", submits)
	}
	got, ok := node.lastSubmitCandidate.(*tari_generated.Block)
	if !ok {
		t.Fatalf("SubmitBlock candidate type = %T, want *tari_generated.Block", node.lastSubmitCandidate)
	}
	if got.GetHeader().GetHeight() != 42 {
		t.Errorf("decoded candidate height = %d, want 42", got.GetHeader().GetHeight())
	}
}

// TestHandleFoundBlock_MismatchedAlgoSkips and
// TestHandleFoundBlock_MismatchedNetworkSkips are requirement (c)'s
// negative proof: SubmitBlock must NOT be called for either kind of
// mismatch.
func TestHandleFoundBlock_MismatchedAlgoSkips(t *testing.T) {
	node := &mockNodeClient{}
	d := NewDaemon(node, relay.NewRelay(relay.Config{URL: ""}), poolpb.Algo_ALGO_SHA3X, coinTari, "testnet", "payout", nil)

	block := &tari_generated.Block{Header: &tari_generated.BlockHeader{Height: 1}}
	data, _ := proto.Marshal(block)
	d.handleFoundBlock(relay.BlockMessage{Algo: "c29", Network: "testnet", BlockData: data})

	if _, _, submits := node.callCounts(); submits != 0 {
		t.Fatalf("expected 0 SubmitBlock calls for a mismatched algo, got %d", submits)
	}
}

func TestHandleFoundBlock_MismatchedNetworkSkips(t *testing.T) {
	node := &mockNodeClient{}
	d := NewDaemon(node, relay.NewRelay(relay.Config{URL: ""}), poolpb.Algo_ALGO_SHA3X, coinTari, "testnet", "payout", nil)

	block := &tari_generated.Block{Header: &tari_generated.BlockHeader{Height: 1}}
	data, _ := proto.Marshal(block)
	d.handleFoundBlock(relay.BlockMessage{Algo: "sha3x", Network: "mainnet", BlockData: data})

	if _, _, submits := node.callCounts(); submits != 0 {
		t.Fatalf("expected 0 SubmitBlock calls for a mismatched network, got %d", submits)
	}
}

// TestHandleFoundBlock_MatchingMoneroAlgoNetworkSubmits is this
// follow-up fix's own required regression test: a genuinely MATCHING
// Monero-family Algo/Network relay message now DOES trigger a real
// local resubmission, decoding BlockMessage.BlockData straight back
// into a *solo.MoneroCandidate (see handleFoundBlock's own doc
// comment -- this mirrors internal/leaflib/direct/session.go's
// producer side exactly: BlockData is the raw, already-nonce-patched
// TemplateBlob bytes, no proto marshal step involved).
func TestHandleFoundBlock_MatchingMoneroAlgoNetworkSubmits(t *testing.T) {
	node := &mockNodeClient{}
	d := NewDaemon(node, relay.NewRelay(relay.Config{URL: ""}), poolpb.Algo_ALGO_XMR, coinMonero, "testnet", "payout", nil)

	wantBlob := []byte{1, 2, 3, 4, 5}
	d.handleFoundBlock(relay.BlockMessage{
		Algo: leaflib.AlgoWireName(poolpb.Algo_ALGO_XMR), Network: "testnet", Height: 7, Hash: "abc", BlockData: wantBlob,
	})

	if _, _, submits := node.callCounts(); submits != 1 {
		t.Fatalf("expected exactly 1 SubmitBlock call for a matching Monero-family Algo/Network message, got %d", submits)
	}
	got, ok := node.lastSubmitCandidate.(*solo.MoneroCandidate)
	if !ok {
		t.Fatalf("SubmitBlock candidate type = %T, want *solo.MoneroCandidate", node.lastSubmitCandidate)
	}
	if !bytes.Equal(got.TemplateBlob, wantBlob) {
		t.Fatalf("decoded candidate TemplateBlob = %x, want %x", got.TemplateBlob, wantBlob)
	}
}

// TestHandleFoundBlock_MismatchedAlgoSkipsMonero and
// TestHandleFoundBlock_MismatchedNetworkSkipsMonero are the
// Monero-family counterpart of the Tari mismatch tests above: SubmitBlock
// must NOT be called for either kind of mismatch, even now that the
// Monero-family decode+resubmit path is real.
func TestHandleFoundBlock_MismatchedAlgoSkipsMonero(t *testing.T) {
	node := &mockNodeClient{}
	d := NewDaemon(node, relay.NewRelay(relay.Config{URL: ""}), poolpb.Algo_ALGO_XMR, coinMonero, "testnet", "payout", nil)

	// NOTE: leaflib.AlgoWireName maps EVERY RandomX-family algo
	// (ALGO_RXT, ALGO_RXM, and every internal/coinprofile.Registry
	// entry including ALGO_XMR) to the SAME "rx/0" wire label (real
	// miner software has no per-coin algo name -- see that function's
	// own doc comment), so ALGO_RXM would NOT actually exercise a
	// wire-level mismatch here. ALGO_C29 ("c29") is used instead to
	// prove a genuine wire-algo mismatch is still correctly filtered.
	d.handleFoundBlock(relay.BlockMessage{Algo: leaflib.AlgoWireName(poolpb.Algo_ALGO_C29), Network: "testnet", BlockData: []byte{1, 2, 3}})

	if _, _, submits := node.callCounts(); submits != 0 {
		t.Fatalf("expected 0 SubmitBlock calls for a mismatched Monero-family algo, got %d", submits)
	}
}

func TestHandleFoundBlock_MismatchedNetworkSkipsMonero(t *testing.T) {
	node := &mockNodeClient{}
	d := NewDaemon(node, relay.NewRelay(relay.Config{URL: ""}), poolpb.Algo_ALGO_XMR, coinMonero, "testnet", "payout", nil)

	d.handleFoundBlock(relay.BlockMessage{Algo: leaflib.AlgoWireName(poolpb.Algo_ALGO_XMR), Network: "mainnet", BlockData: []byte{1, 2, 3}})

	if _, _, submits := node.callCounts(); submits != 0 {
		t.Fatalf("expected 0 SubmitBlock calls for a mismatched network, got %d", submits)
	}
}

// TestDaemon_DisabledRelayRunsCleanly is requirement (d)'s proof:
// with an empty relay URL, PollOnce/SubscribeFoundBlocks/Run all
// behave as complete relay no-ops (matching relay.Relay's own
// documented no-op contract) while the underlying node poll loop
// keeps working correctly.
func TestDaemon_DisabledRelayRunsCleanly(t *testing.T) {
	node := &mockNodeClient{height: 1, job: newTariJob(1)}
	disabledRelay := relay.NewRelay(relay.Config{URL: ""})
	if disabledRelay.Enabled() {
		t.Fatal("expected a Relay constructed with an empty URL to be disabled")
	}

	d := NewDaemon(node, disabledRelay, poolpb.Algo_ALGO_SHA3X, coinTari, "testnet", "payout", nil)

	unsub, err := d.SubscribeFoundBlocks()
	if err != nil {
		t.Fatalf("SubscribeFoundBlocks on a disabled relay must be a no-op, got error: %v", err)
	}
	unsub()

	if err := d.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce (seed) with a disabled relay: %v", err)
	}
	node.setHeight(2)
	node.mu.Lock()
	node.job = newTariJob(2)
	node.mu.Unlock()
	if err := d.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce (increase) with a disabled relay must still succeed (PublishTemplate is a no-op): %v", err)
	}

	if _, templateCalls, _ := node.callCounts(); templateCalls != 1 {
		t.Errorf("expected the real node poll loop to keep working (1 GetBlockTemplate call) even with the relay disabled, got %d", templateCalls)
	}

	// Run must also start/stop cleanly with a disabled relay.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { d.Run(ctx, 10*time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Daemon.Run did not return promptly after ctx cancellation")
	}
}
