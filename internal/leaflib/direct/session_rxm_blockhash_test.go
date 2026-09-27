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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// moneroDirectFixtureBlobHex is the SAME real, live-daemon-captured
// blockhashing_blob/blocktemplate_blob fixture
// internal/leaflib/solo/monero_node_test.go's own realFixtureBlobHex
// uses (76 bytes, real nonce offset 39, independently confirmed by
// that package's own TestParseMoneroBlockHeaderNonceOffset_
// RealFixture) -- duplicated here per this repo's own established
// duplicate-small-fixtures-across-packages convention (see
// solo/node.go's tariJobFromResult doc comment) since it is
// unexported in the solo package.
const moneroDirectFixtureBlobHex = "1010c3f4a4d4062d5456c2d3d54707336bc352fc9910c8adbd586603439b548fca04de64c1973d00000000936c23078acfd28dc0b307b8a2e63eb4eef27681ebb63f9ec67f09b8e3b59cef01"

// moneroDirectDefaultBlockID is the real, top-level "block_id" this
// file's mock daemon's submit_block response carries by default (see
// moneroDirectMockDaemon.setBlockID) -- a realistic-looking 32-byte
// hex string, standing in for the REAL block ID a real monerod
// v0.18.0.0+246+ returns directly in its submit_block response (see
// solo.moneroSubmitBlockAuxResult.BlockID's own doc comment). This
// package's own tests assert THIS value is what gets forwarded to
// the backend, never a locally-computed or RPC-looked-up hash.
const moneroDirectDefaultBlockID = "a69b402d9c1122334455667788990011223344556677889900112233445566"

// moneroDirectMockDaemon is a minimal, real monerod JSON-RPC 2.0 mock
// (httptest-backed) implementing exactly the methods this leaf's
// ALGO_RXM block-find path needs: get_block_template and submit_block
// (solo.MoneroNodeClient's own template-fetch/submit methods, reused
// as-is) and get_block_header_by_height (MoneroBlockHeaderClient,
// monero_hash.go -- retained ONLY for
// TestDirectResolveMoneroBlockHash_NoResolverConfigured-style direct
// tests and to prove, via headerCalls staying at 0, that
// session.go's handleSubmit hot path genuinely never calls it -- see
// this file's own tests below).
type moneroDirectMockDaemon struct {
	height     uint64
	difficulty uint64

	submitCalls atomic.Int64
	headerCalls atomic.Int64

	mu                 sync.Mutex
	headerHash         string // "" (default) makes the header lookup fail with an empty hash
	headerErrorMessage string // if set, get_block_header_by_height fails with a real JSON-RPC error instead
	// blockID is the real top-level "block_id" submit_block's mocked
	// response carries (see moneroDirectDefaultBlockID's own doc
	// comment) -- defaults to moneroDirectDefaultBlockID until
	// setBlockID is called explicitly (including with "", to
	// simulate an older pre-e8cac61f monerod or a merge-mining proxy
	// that doesn't pass block_id through).
	blockID    string
	blockIDSet bool
}

func (d *moneroDirectMockDaemon) setHeaderHash(hash string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.headerHash = hash
	d.headerErrorMessage = ""
}

func (d *moneroDirectMockDaemon) setHeaderError(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.headerHash = ""
	d.headerErrorMessage = msg
}

// setBlockID overrides the real top-level "block_id" submit_block's
// mocked response carries -- pass "" to simulate an older,
// pre-e8cac61f monerod (or a merge-mining proxy that doesn't pass
// block_id through), which must be handled defensively (see
// TestDirectSessionRXMBlockFindMissingBlockIDSkipsBackendForward).
func (d *moneroDirectMockDaemon) setBlockID(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blockID = id
	d.blockIDSet = true
}

func (d *moneroDirectMockDaemon) handler(t *testing.T) http.HandlerFunc {
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
			blockID, blockIDSet := d.blockID, d.blockIDSet
			d.mu.Unlock()
			if !blockIDSet {
				blockID = moneroDirectDefaultBlockID
			}
			// Real monero-project/monero wire shape: "block_id" is a
			// top-level field, sibling of status/untrusted -- see
			// solo.moneroSubmitBlockAuxResult.BlockID's own doc
			// comment. Omitted entirely (not merely empty-stringed)
			// when blockID=="" to also cover the real
			// pre-e8cac61f monerod shape, which never emits this
			// field at all.
			if blockID == "" {
				fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","untrusted":false}}`)
			} else {
				fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","untrusted":false,"block_id":%q}}`, blockID)
			}
		case "get_block_header_by_height":
			d.headerCalls.Add(1)
			d.mu.Lock()
			hash := d.headerHash
			errMsg := d.headerErrorMessage
			d.mu.Unlock()
			if errMsg != "" {
				fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","error":{"code":-2,"message":%q}}`, errMsg)
				return
			}
			fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","block_header":{"hash":%q}}}`, hash)
		default:
			t.Errorf("mock daemon: unexpected method %q", req.Method)
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}
}

// alwaysValidRXMValidator is a validator.AlgoValidator test double
// that always reports a share as cryptographically valid without any
// real RandomX hashing. This file's own tests are about the REAL
// Monero block-hash SOURCING path (session.go's handleSubmit reading
// the real block_id off submit_block's own response) --
// RandomXValidator's own hash-equality logic is already covered
// elsewhere (validator/randomx_test.go,
// validator/randomx_real_daemon_test.go), so standing up a real
// randomx-service daemon here would add a real infra dependency for
// zero additional coverage of what this fix actually changes.
type alwaysValidRXMValidator struct{}

func (alwaysValidRXMValidator) Validate(_ context.Context, _ *poolpb.Share) (bool, error) {
	return true, nil
}

var _ validator.AlgoValidator = alwaysValidRXMValidator{}

// newDirectRXMBlockFindHarness wires a REAL solo.MoneroNodeClient
// (unmodified, reused exactly as production does) and this package's
// own ServerConfig.MonerodURL against the SAME mock monerod daemon,
// so a genuine ALGO_RXM block find exercises the real
// GetBlockTemplate -> BuildCandidateBlock -> SubmitBlock pipeline
// end-to-end, not a shortcut/stand-in.
func newDirectRXMBlockFindHarness(t *testing.T, srv *httptest.Server, staticDiff uint64) *directTestHarness {
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
		// Still wired (mirrors a real -coin=monero deployment) so
		// this test's mock daemon's get_block_header_by_height
		// handler is reachable -- but see this file's own tests
		// below: session.go's handleSubmit hot path must NEVER
		// actually call it anymore (daemon.headerCalls must stay 0).
		MonerodURL: srv.URL,
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

// moneroDirectClaimedTinyResult is a claimed RandomX result hash whose
// little-endian whole-buffer value is 1 (hash[0]=0x01, every other
// byte 0) -- see monero_node.go's moneroDifficultyFromHash doc
// comment for the exact byte-order convention. This satisfies ANY
// real target difficulty (moneroMax256/1, clamped to MaxUint64),
// which is what lets these tests reach the real block-find path
// (BuildCandidateBlock -> job.NetworkTargetDifficulty) using
// alwaysValidRXMValidator instead of a real randomx-service.
var moneroDirectClaimedTinyResult = "01" + strings.Repeat("00", 31)

// moneroDirectFixtureNonceUint32 is the little-endian uint32 value the
// wire nonce "01000000" this file's tests submit decodes to.
const moneroDirectFixtureNonceUint32 = 0x00000001

// TestDirectSessionRXMBlockFindUsesRealSubmitBlockID is this fix's own
// required regression test (as corrected): a fabricated RXM
// block-find through leaf-direct's REAL session code must forward
// the REAL block_id straight off submit_block's own JSON-RPC
// response, and must NEVER call get_block_header_by_height to obtain
// it -- see solo.moneroSubmitBlockAuxResult.BlockID's own doc comment
// for why no RPC round-trip (local computation OR a second RPC call)
// is needed at all.
func TestDirectSessionRXMBlockFindUsesRealSubmitBlockID(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	// Deliberately set to a hash that does NOT match the real
	// submit_block block_id -- if this ever got forwarded, it would
	// prove the old (buggy, race-prone) RPC-lookup path is still in
	// use.
	const staleUnusedHeaderHash = "d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d3"
	daemon.setHeaderHash(staleUnusedHeaderHash)
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectRXMBlockFindHarness(t, srv, 1)
	m := h.server.EnableMetrics("test", 0)

	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

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
	// THE FIX, directly asserted: the hot path must NEVER call
	// get_block_header_by_height anymore.
	if got := daemon.headerCalls.Load(); got != 0 {
		t.Fatalf("BUG REGRESSION: get_block_header_by_height was called %d time(s) from the block-find hot path -- this fix's whole point is to remove that RPC round-trip (and the tip-advancement race it caused) entirely", got)
	}

	waitForBlockCount(t, h.transport, 1)
	forwardedHash := h.transport.blockAt(0).GetHash()

	if forwardedHash != moneroDirectDefaultBlockID {
		t.Fatalf("forwarded block hash = %q, want the REAL block_id from submit_block's own response %q", forwardedHash, moneroDirectDefaultBlockID)
	}
	if forwardedHash == staleUnusedHeaderHash {
		t.Fatalf("BUG REGRESSION: forwarded hash equals the mock daemon's get_block_header_by_height response -- the old RPC-lookup path is still being used")
	}
	if strings.Contains(forwardedHash, "-") {
		t.Fatalf("forwarded block hash %q looks like a nonce-height placeholder (contains '-'), not a real hex Monero block hash", forwardedHash)
	}
	if got := testutil.ToFloat64(m.DirectBlockHashUnresolvedTotal); got != 0 {
		t.Fatalf("DirectBlockHashUnresolvedTotal = %v on the successful path, want 0", got)
	}
}

// TestDirectSessionRXMBlockFindSucceedsEvenWhenHeaderLookupWouldFail
// is this fix's own direct reproduction of the real production
// incident that originally motivated this whole fix (2026-09-12 live
// test against leaf-direct-monero-pplns.service/CT132: 302 "MONERO
// BLOCK HASH UNRESOLVED" log lines from a get_block_header_by_height
// call racing the local daemon's own tip advancement, rpc error -2
// "Requested block height: X greater than current top block height:
// X-1"): even when the mock daemon's get_block_header_by_height
// would fail exactly like that, the block find must STILL be
// forwarded with its real block_id -- because the hot path no longer
// calls that RPC method at all (headerCalls stays 0), and the real
// hash is already available directly from submit_block's own
// response regardless.
func TestDirectSessionRXMBlockFindSucceedsEvenWhenHeaderLookupWouldFail(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	daemon.setHeaderError("Requested block height: 501 greater than current top block height: 500")
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectRXMBlockFindHarness(t, srv, 1)
	m := h.server.EnableMetrics("test", 0)

	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

	h.send(solo.Request{ID: 51, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
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
	if got := daemon.headerCalls.Load(); got != 0 {
		t.Fatalf("BUG REGRESSION: get_block_header_by_height was called %d time(s) -- the hot path must never call it, so a failing/racing daemon response for THIS method can no longer affect a block find at all", got)
	}

	// THE FIX: this block find must be forwarded normally -- there is
	// no RPC lookup left to fail, and the real hash comes straight off
	// submit_block's own response.
	waitForBlockCount(t, h.transport, 1)
	forwardedHash := h.transport.blockAt(0).GetHash()
	if forwardedHash != moneroDirectDefaultBlockID {
		t.Fatalf("forwarded block hash = %q, want the REAL block_id from submit_block's own response %q", forwardedHash, moneroDirectDefaultBlockID)
	}

	if got := testutil.ToFloat64(m.DirectBlockHashUnresolvedTotal); got != 0 {
		t.Fatalf("DirectBlockHashUnresolvedTotal = %v, want 0 -- a get_block_header_by_height failure must have ZERO effect now that the hot path never calls it", got)
	}
}

// TestDirectSessionRXMBlockFindMissingBlockIDSkipsBackendForward is
// the REQUIRED defensive-handling regression test (item 7 of this
// fix): when submit_block's own response carries no "block_id" at
// all (an older, pre-e8cac61f monerod, or a merge-mining proxy that
// doesn't pass it through), this leaf must NEVER fabricate a hash --
// the block find is accepted (the node itself already confirmed it),
// but the backend forward is skipped and
// leaf_direct_block_hash_unresolved_total is bumped, exactly
// mirroring this leaf's former "hash unresolved" handling.
func TestDirectSessionRXMBlockFindMissingBlockIDSkipsBackendForward(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	daemon.setBlockID("") // simulate an older/incompatible daemon
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectRXMBlockFindHarness(t, srv, 1)
	m := h.server.EnableMetrics("test", 0)

	sessionID, xn := directLoginRXM(t, h)
	jobID := directCurrentJobIDForXN(t, h, xn)

	h.send(solo.Request{ID: 52, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
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

	if daemon.submitCalls.Load() != 1 {
		t.Errorf("expected exactly 1 real submit_block call, got %d", daemon.submitCalls.Load())
	}
	if got := daemon.headerCalls.Load(); got != 0 {
		t.Fatalf("get_block_header_by_height was called %d time(s) -- a missing block_id must never trigger a fallback RPC lookup", got)
	}

	// THE DEFENSIVE FIX: never forward a placeholder/empty hash.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.transport.blockCount(); got != 0 {
		t.Fatalf("blockCount = %d, want 0 -- a missing block_id must never be forwarded as a placeholder/empty hash", got)
	}
	if got := testutil.ToFloat64(m.DirectBlockHashUnresolvedTotal); got != 1 {
		t.Fatalf("DirectBlockHashUnresolvedTotal = %v, want 1 for a genuinely missing block_id", got)
	}
}

// TestDirectResolveMoneroBlockHash_NoResolverConfigured is a direct
// unit-level regression guard for resolveMoneroBlockHash's own
// documented contract: a -coin=monero misconfiguration (ServerConfig.
// MonerodURL left empty) must return a clear error, NEVER an empty
// string mistaken for a real (if oddly-empty) hash. resolveMoneroBlockHash
// itself is retained as an independent capability/test helper (see
// its own doc comment) even though it is no longer called from
// handleSubmit's hot path.
func TestDirectResolveMoneroBlockHash_NoResolverConfigured(t *testing.T) {
	s := NewServer(ServerConfig{})
	hash, err := s.resolveMoneroBlockHash(context.Background(), 123)
	if err == nil {
		t.Fatalf("expected an error with no moneroHeaderResolver configured, got hash=%q, nil error", hash)
	}
	if hash != "" {
		t.Fatalf("expected an empty hash alongside the error, got %q", hash)
	}
}
