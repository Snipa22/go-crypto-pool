// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// startEmbeddedNATSServer starts a REAL, in-process, embedded NATS
// server, bound to an OS-assigned free port. Deliberately duplicated
// from internal/leaflib/relay/relay_test.go's identical helper -- this
// repo's own established convention (see solo/node.go's
// convertRawTemplateBlobToHashingBlob doc comment) is to duplicate
// small, single-package test helpers like this rather than export a
// test-only symbol across a package boundary.
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

// newDirectRXMBlockFindHarnessWithRelay mirrors
// newDirectRXMBlockFindHarness (session_rxm_blockhash_test.go) exactly,
// with one addition: ServerConfig.Relay is wired to r, so a genuine
// ALGO_RXM block find through this harness's real session code also
// exercises the relay-publish path this fix adds (session.go's
// handleSubmit ALGO_RXM branch).
func newDirectRXMBlockFindHarnessWithRelay(t *testing.T, srv *httptest.Server, staticDiff uint64, r *relay.Relay) *directTestHarness {
	t.Helper()
	node := solo.NewMoneroNodeClient(srv.URL)

	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-monero-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXM,
	})

	registry := validator.Registry{poolpb.Algo_ALGO_RXM: alwaysValidRXMValidator{}}

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
		Algo:              poolpb.Algo_ALGO_RXM,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            42,
		MonerodURL:        srv.URL,
		Relay:             r,
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

// waitForRelayBlockMessage blocks until ch delivers a relay.BlockMessage
// or the deadline elapses, failing the test on timeout -- mirrors
// session_test.go's waitForBlockCount polling-with-deadline convention,
// just channel-based since the assertion here is on a single
// subscribe-delivered message rather than a growing counter.
func waitForRelayBlockMessage(t *testing.T, ch <-chan relay.BlockMessage) relay.BlockMessage {
	t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a relay.BlockMessage to be published")
		return relay.BlockMessage{}
	}
}

// TestDirectSessionRXMBlockFindPublishesToRelay is this follow-up
// fix's own required regression test (producer side): a genuine
// ALGO_RXM block find through leaf-direct's real session code, with a
// real (embedded-NATS-backed) relay configured, must publish a
// relay.BlockMessage carrying the REAL daemon-confirmed block_id as
// Hash, this leaf's real Algo/Network labels, and the candidate's raw
// TemplateBlob bytes as BlockData -- mirroring
// Server.submitBlockDirect's own Tari relay-publish shape exactly (see
// session.go's handleSubmit ALGO_RXM branch, added by this fix).
func TestDirectSessionRXMBlockFindPublishesToRelay(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	natsURL, natsShutdown := startEmbeddedNATSServer(t)
	defer natsShutdown()

	publisherRelay := relay.NewRelay(relay.Config{URL: natsURL})
	defer publisherRelay.Close()

	subscriberRelay := relay.NewRelay(relay.Config{URL: natsURL})
	defer subscriberRelay.Close()

	received := make(chan relay.BlockMessage, 1)
	unsubscribe, err := subscriberRelay.Subscribe(func(msg relay.BlockMessage) {
		received <- msg
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsubscribe()

	h := newDirectRXMBlockFindHarnessWithRelay(t, srv, 1, publisherRelay)

	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

	h.send(solo.Request{ID: 60, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
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

	waitForBlockCount(t, h.transport, 1)

	msg := waitForRelayBlockMessage(t, received)
	if msg.Hash != moneroDirectDefaultBlockID {
		t.Fatalf("relay.BlockMessage.Hash = %q, want the REAL block_id from submit_block's own response %q", msg.Hash, moneroDirectDefaultBlockID)
	}
	if want := leaflib.AlgoWireName(poolpb.Algo_ALGO_RXM); msg.Algo != want {
		t.Fatalf("relay.BlockMessage.Algo = %q, want %q", msg.Algo, want)
	}
	if msg.Network != "testnet" {
		t.Fatalf("relay.BlockMessage.Network = %q, want %q", msg.Network, "testnet")
	}
	wantBlob, err := hex.DecodeString(moneroDirectFixtureBlobHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(moneroDirectFixtureBlobHex): %v", err)
	}
	// The published BlockData is the REAL nonce-patched TemplateBlob,
	// which differs from the raw fixture template only at the nonce
	// offset (39) -- see BuildCandidateBlock's own doc comment. Assert
	// the length matches exactly and everything OUTSIDE the 4-byte
	// nonce window is byte-identical to the fixture, which is enough
	// to prove this is genuinely the submitted TemplateBlob and not
	// some other payload, without over-specifying the exact patched
	// nonce bytes here (already covered by monero_node_test.go).
	if len(msg.BlockData) != len(wantBlob) {
		t.Fatalf("relay.BlockMessage.BlockData length = %d, want %d (moneroDirectFixtureBlobHex length)", len(msg.BlockData), len(wantBlob))
	}
	const nonceOffset = 39
	if !bytes.Equal(msg.BlockData[:nonceOffset], wantBlob[:nonceOffset]) || !bytes.Equal(msg.BlockData[nonceOffset+4:], wantBlob[nonceOffset+4:]) {
		t.Fatalf("relay.BlockMessage.BlockData outside the nonce window does not match the real fixture template blob")
	}
}

// TestDirectSessionRXMBlockFindMissingBlockIDDoesNotPublishToRelay is
// this follow-up fix's own required negative-proof regression test: a
// genuine ALGO_RXM block find whose real hash could not be resolved
// (submit_block's own response carries no block_id -- see
// skipBackendForward's doc comment in session.go) must NOT publish
// anything to the relay either, for the exact same reason backend
// forwarding is skipped: an unresolved hash is not safe to key relay
// dedup on.
func TestDirectSessionRXMBlockFindMissingBlockIDDoesNotPublishToRelay(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	daemon.setBlockID("") // simulate an older/incompatible daemon
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	natsURL, natsShutdown := startEmbeddedNATSServer(t)
	defer natsShutdown()

	publisherRelay := relay.NewRelay(relay.Config{URL: natsURL})
	defer publisherRelay.Close()

	subscriberRelay := relay.NewRelay(relay.Config{URL: natsURL})
	defer subscriberRelay.Close()

	received := make(chan relay.BlockMessage, 1)
	unsubscribe, err := subscriberRelay.Subscribe(func(msg relay.BlockMessage) {
		received <- msg
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsubscribe()

	h := newDirectRXMBlockFindHarnessWithRelay(t, srv, 1, publisherRelay)

	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

	h.send(solo.Request{ID: 61, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
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
		t.Fatalf("expected an accepted block-finding share (the NODE still accepted it) even though block_id was missing, got %#v", resp)
	}

	select {
	case msg := <-received:
		t.Fatalf("expected NO relay.BlockMessage to be published for an unresolved-hash block find, got %+v", msg)
	case <-time.After(300 * time.Millisecond):
		// Expected: no publish within the wait window.
	}
}
