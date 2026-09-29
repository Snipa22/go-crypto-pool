// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// mergeMineMockDaemon is moneroDirectMockDaemon's sibling, extended
// with a configurable submit_block response so these tests can
// exercise the full real handleSubmit ALGO_RXM path end-to-end for
// EACH of the three real-world outcomes this task exists to cover:
// clears Monero only (no aux_chain_data), clears both (aux_chain_data
// present), and submit_block itself erroring (see this file's own
// test doc comments for why "clears the merge-mined chain only" is
// instead covered at the pure matchMergeMineForwards level in
// merge_mine_forward_test.go -- today's leaf only ever calls
// submit_block once Monero's OWN target is already cleared, so a
// standalone "Tari-only" case cannot be produced through this
// end-to-end harness without changing that gating).
type mergeMineMockDaemon struct {
	height     uint64
	difficulty uint64

	submitCalls atomic.Int64
	headerCalls atomic.Int64

	mu             sync.Mutex
	headerHash     string
	auxChainDataJS string // raw JSON array literal, e.g. `[{"id":"xtr","block_hash":"aabb"}]`, or "" for none
	submitError    string // if set, submit_block fails with this real JSON-RPC error message instead of succeeding
}

func (d *mergeMineMockDaemon) setHeaderHash(hash string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.headerHash = hash
}

func (d *mergeMineMockDaemon) setAuxChainData(js string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.auxChainDataJS = js
}

func (d *mergeMineMockDaemon) setSubmitError(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.submitError = msg
}

func (d *mergeMineMockDaemon) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock daemon: reading request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("mock daemon: decoding request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "get_block_template":
			fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{
				"blockhashing_blob":"%s",
				"blocktemplate_blob":"%s",
				"difficulty":%d,
				"height":%d,
				"prev_hash":"%s",
				"reserved_offset":10,
				"seed_hash":"%s",
				"seed_height":100,
				"status":"OK"
			}}`, moneroDirectFixtureBlobHex, moneroDirectFixtureBlobHex, d.difficulty, d.height,
				hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32)), hex.EncodeToString(bytes.Repeat([]byte{0xCD}, 32)))
		case "submit_block":
			d.submitCalls.Add(1)
			d.mu.Lock()
			submitErr := d.submitError
			auxJS := d.auxChainDataJS
			d.mu.Unlock()
			if submitErr != "" {
				fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","error":{"code":-7,"message":%q}}`, submitErr)
				return
			}
			if auxJS != "" {
				fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","untrusted":false,"block_id":%q,"_aux":{"chains":%s}}}`, moneroDirectDefaultBlockID, auxJS)
				return
			}
			fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","untrusted":false,"block_id":%q}}`, moneroDirectDefaultBlockID)
		case "get_block_header_by_height":
			d.headerCalls.Add(1)
			d.mu.Lock()
			hash := d.headerHash
			d.mu.Unlock()
			fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","block_header":{"hash":%q}}}`, hash)
		default:
			t.Errorf("mock daemon: unexpected method %q", req.Method)
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}
}

// newMergeMineHarness mirrors newDirectRXMBlockFindHarness exactly,
// with one addition: ServerConfig.MergeMineChains is populated
// (TARI:xtr), exactly mirroring a real -coin=monero
// -merge-mine-chains=TARI:xtr deployment.
func newMergeMineHarness(t *testing.T, srv *httptest.Server, staticDiff uint64) *directTestHarness {
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
		MergeMineChains:   []MergeMineChainConfig{{Name: "TARI", AuxChainID: "xtr"}},
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

func submitRXMBlockFind(t *testing.T, h *directTestHarness, reqID int) {
	t.Helper()
	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForSession(t, h, xn)
	h.send(solo.Request{ID: reqID, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:     sessionID,
		JobID:  jobID,
		Nonce:  "01000000",
		Result: moneroDirectClaimedTinyResult,
	})})
	h.recvShareResponse() // consumed for its side effect only -- callers assert on forwarded blocks, not on this response (a rejected submit_block legitimately produces a rejection response here too)
}

// TestDirectRXM_MergeMine_MoneroOnly is the "one submission clears
// Monero only" scenario: submit_block succeeds with no "_aux" data at
// all (the merge-mined chain's own target was not cleared) --
// exactly ONE Block message should be forwarded, with
// MergeMineChain unset (nil).
func TestDirectRXM_MergeMine_MoneroOnly(t *testing.T) {
	daemon := &mergeMineMockDaemon{height: 500, difficulty: 1000}
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newMergeMineHarness(t, srv, 1)
	submitRXMBlockFind(t, h, 60)

	waitForBlockCount(t, h.transport, 1)
	time.Sleep(100 * time.Millisecond) // give any (wrongly) extra forward a chance to land
	if got := h.transport.blockCount(); got != 1 {
		t.Fatalf("Monero-only find: forwarded %d Block messages, want exactly 1", got)
	}
	b := h.transport.blockAt(0)
	if b.MergeMineChain != nil {
		t.Fatalf("Monero-only find: forwarded block has MergeMineChain=%q, want nil (primary leg)", b.GetMergeMineChain())
	}
	if b.GetAlgo() != poolpb.Algo_ALGO_RXM {
		t.Fatalf("forwarded block algo = %v, want ALGO_RXM", b.GetAlgo())
	}
	if got := daemon.headerCalls.Load(); got != 0 {
		t.Fatalf("get_block_header_by_height was called %d time(s) -- the hot path must never call it", got)
	}
	if want := moneroDirectDefaultBlockID; b.GetHash() != want {
		t.Fatalf("primary leg hash = %q, want the real block_id from submit_block's own response %q", b.GetHash(), want)
	}
}

// TestDirectRXM_MergeMine_Both is the "one submission clears both"
// scenario: submit_block succeeds AND its response carries a real
// "_aux.chains" acceptance entry for the configured "xtr" (TARI)
// chain -- exactly TWO Block messages must be forwarded: one primary
// leg (MergeMineChain nil, Monero's own real, locally-computed hash)
// and one secondary leg (MergeMineChain="TARI", the _aux.chains
// hash).
func TestDirectRXM_MergeMine_Both(t *testing.T) {
	const tariHash = "tarihashaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbcc"

	daemon := &mergeMineMockDaemon{height: 500, difficulty: 1000}
	daemon.setAuxChainData(fmt.Sprintf(`[{"id":"xtr","block_hash":"%s"}]`, tariHash))
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newMergeMineHarness(t, srv, 1)
	submitRXMBlockFind(t, h, 61)

	waitForBlockCount(t, h.transport, 2)
	if got := h.transport.blockCount(); got != 2 {
		t.Fatalf("both-cleared find: forwarded %d Block messages, want exactly 2", got)
	}

	wantMoneroHash := moneroDirectDefaultBlockID
	var sawPrimary, sawTari bool
	for i := 0; i < h.transport.blockCount(); i++ {
		b := h.transport.blockAt(i)
		if b.GetAlgo() != poolpb.Algo_ALGO_RXM {
			t.Fatalf("forwarded block %d algo = %v, want ALGO_RXM for BOTH legs (design decision: never RXT/other)", i, b.GetAlgo())
		}
		switch {
		case b.MergeMineChain == nil:
			sawPrimary = true
			if b.GetHash() != wantMoneroHash {
				t.Fatalf("primary leg hash = %q, want the real Monero block_id %q", b.GetHash(), wantMoneroHash)
			}
		case b.GetMergeMineChain() == "TARI":
			sawTari = true
			if b.GetHash() != tariHash {
				t.Fatalf("TARI leg hash = %q, want the real _aux.chains hash %q", b.GetHash(), tariHash)
			}
		default:
			t.Fatalf("forwarded block %d has unexpected merge_mine_chain %q", i, b.GetMergeMineChain())
		}
	}
	if !sawPrimary {
		t.Fatal("both-cleared find: never forwarded the primary (Monero) leg")
	}
	if !sawTari {
		t.Fatal("both-cleared find: never forwarded the TARI leg")
	}
}

// TestDirectRXM_MergeMine_SubmitBlockErrorForwardsNothing covers the
// documented, conservative behavior when submit_block itself errors
// (e.g. the real, live-confirmed CT132 Tari-base-node-rejection bug,
// or a genuinely stale/rejected Monero block): since this
// deployment's mmproxy (submit_to_origin=false) reports the WHOLE
// call's outcome, an error here is never attributed to one specific
// leg -- NEITHER the primary nor any merge-mine leg is forwarded,
// exactly mirroring skipBackendForward's own "never fabricate, when
// in doubt leave it out" convention. This documents a real,
// deliberately-out-of-scope limitation: a genuinely Monero-only-valid
// submission whose Tari leg happens to error will currently also
// lose its OWN valid Monero forward -- see this PR's summary.
func TestDirectRXM_MergeMine_SubmitBlockErrorForwardsNothing(t *testing.T) {
	daemon := &mergeMineMockDaemon{height: 500, difficulty: 1000}
	daemon.setSubmitError("Block not accepted")
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newMergeMineHarness(t, srv, 1)
	submitRXMBlockFind(t, h, 62)

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.transport.blockCount(); got != 0 {
		t.Fatalf("submit_block error: forwarded %d Block messages, want exactly 0 (never fabricate either leg on an ambiguous whole-call error)", got)
	}
	if daemon.submitCalls.Load() != 1 {
		t.Errorf("expected exactly 1 real submit_block call, got %d", daemon.submitCalls.Load())
	}
	if daemon.headerCalls.Load() != 0 {
		t.Errorf("expected get_block_header_by_height to never be called after a submit_block error, got %d calls", daemon.headerCalls.Load())
	}
}
