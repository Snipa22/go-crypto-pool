// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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
// unexported in the read-only solo package this fix must not modify.
const moneroDirectFixtureBlobHex = "1010c3f4a4d4062d5456c2d3d54707336bc352fc9910c8adbd586603439b548fca04de64c1973d00000000936c23078acfd28dc0b307b8a2e63eb4eef27681ebb63f9ec67f09b8e3b59cef01"

// moneroDirectMockDaemon is a minimal, real monerod JSON-RPC 2.0 mock
// (httptest-backed) implementing exactly the three methods this fix's
// full leaf-direct RXM block-find path needs: get_block_template and
// submit_block (solo.MoneroNodeClient's own template-fetch/submit
// methods, reused as-is -- this fix does not touch that package) and
// get_block_header_by_height (this fix's own new
// MoneroBlockHeaderClient, monero_hash.go). All three are served from
// the SAME httptest server, exactly mirroring a real production
// deployment where leaf-direct's template-fetch/submit connection and
// its block-hash-resolution connection point at the identical monerod
// daemon (see ServerConfig.MonerodURL).
type moneroDirectMockDaemon struct {
	height     uint64
	difficulty uint64

	submitCalls atomic.Int64
	headerCalls atomic.Int64

	mu                 sync.Mutex
	headerHash         string // "" (default) makes the header lookup fail with an empty hash
	headerErrorMessage string // if set, get_block_header_by_height fails with a real JSON-RPC error instead
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
			fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK"}}`)
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
// real RandomX hashing. This fix's own tests are about the REAL
// Monero block-hash RESOLUTION path (session.go's handleSubmit +
// resolveMoneroBlockHash/MoneroBlockHeaderClient) -- RandomXValidator's
// own hash-equality logic is already covered elsewhere (validator/
// randomx_test.go, validator/randomx_real_daemon_test.go), so standing
// up a real randomx-service daemon here would add a real infra
// dependency for zero additional coverage of what this fix actually
// changes.
type alwaysValidRXMValidator struct{}

func (alwaysValidRXMValidator) Validate(_ context.Context, _ *poolpb.Share) (bool, error) {
	return true, nil
}

var _ validator.AlgoValidator = alwaysValidRXMValidator{}

// newDirectRXMBlockFindHarness wires a REAL solo.MoneroNodeClient
// (unmodified, reused exactly as production does) and this fix's own
// ServerConfig.MonerodURL against the SAME mock monerod daemon, so a
// genuine ALGO_RXM block find exercises the real
// GetBlockTemplate -> BuildCandidateBlock -> SubmitBlock ->
// resolveMoneroBlockHash pipeline end-to-end, not a shortcut/stand-in.
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
		// This fix's own new wiring: the SAME monerod baseURL as Node,
		// so Server constructs a real MoneroBlockHeaderClient pointed
		// at this test's mock daemon (see NewServer/monero_hash.go).
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

// TestDirectSessionRXMBlockFindUsesRealMoneroHeaderHashNotSHA256 is
// FIX_BRIEF.md's own required regression test: a fabricated RXM
// block-find through leaf-direct's REAL session code must forward
// the REAL Monero block hash (resolved via get_block_header_by_height
// against this test's mock daemon) to the backend -- NOT
// sha256(candidate blob), the confirmed-wrong placeholder this fix
// replaces.
func TestDirectSessionRXMBlockFindUsesRealMoneroHeaderHashNotSHA256(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	const realHeaderHash = "d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d34d3"
	daemon.setHeaderHash(realHeaderHash)
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
	if daemon.headerCalls.Load() == 0 {
		t.Fatal("expected at least 1 real get_block_header_by_height call to resolve the block hash -- the fix under test never ran")
	}

	waitForBlockCount(t, h.transport, 1)
	forwardedHash := h.transport.blockAt(0).GetHash()

	if forwardedHash != realHeaderHash {
		t.Fatalf("forwarded block hash = %q, want the REAL resolved monerod header hash %q", forwardedHash, realHeaderHash)
	}

	// Regression guard: confirm this is genuinely NOT the old
	// sha256(candidate blob) placeholder, for whatever candidate blob
	// this run actually produced.
	rawTemplate, err := hex.DecodeString(moneroDirectFixtureBlobHex)
	if err != nil {
		t.Fatalf("decoding fixture blob: %v", err)
	}
	sum := sha256.Sum256(rawTemplate) // unpatched blob's sha256 as a sanity floor
	placeholderHash := hex.EncodeToString(sum[:])
	if forwardedHash == placeholderHash {
		t.Fatalf("BUG REGRESSION: forwarded hash %q equals sha256(candidate blob) -- the old, confirmed-wrong placeholder is still being used instead of the real resolved monerod header hash", forwardedHash)
	}
	if strings.Contains(forwardedHash, "-") {
		t.Fatalf("forwarded block hash %q looks like a nonce-height placeholder (contains '-'), not a real hex Monero block hash", forwardedHash)
	}
	if got := testutil.ToFloat64(m.DirectBlockHashUnresolvedTotal); got != 0 {
		t.Fatalf("DirectBlockHashUnresolvedTotal = %v on the successful-resolution path, want 0", got)
	}
}

// TestDirectSessionRXMBlockFindHashUnresolvedIsNotForwardedAsPlaceholder
// is FIX_BRIEF.md item 3's own explicit fallback-hardening regression
// test: when the real monerod get_block_header_by_height call fails
// (simulated here as a real JSON-RPC error) AFTER submit_block has
// already accepted the block, this leaf must NOT silently forward a
// placeholder/empty hash to the backend -- it must fail loudly
// (leaf_direct_block_hash_unresolved_total bumped, a clear log line)
// and skip the backend report for that block entirely, rather than
// writing an unverifiable hash that would silently, permanently
// orphan a genuinely found block (exactly the bug this whole fix
// exists to eliminate).
func TestDirectSessionRXMBlockFindHashUnresolvedIsNotForwardedAsPlaceholder(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	daemon.setHeaderError("Requested height is bigger than the current top block height")
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
		t.Fatalf("expected the miner-facing response to still report acceptance (the node itself DID accept the block; only hash resolution failed), got %#v", resp)
	}

	if daemon.submitCalls.Load() != 1 {
		t.Errorf("expected exactly 1 real submit_block call, got %d", daemon.submitCalls.Load())
	}
	if daemon.headerCalls.Load() == 0 {
		t.Fatal("expected at least 1 real get_block_header_by_height call attempt")
	}

	// Give the (never-taken) forward path a moment to prove it really
	// never fires, rather than racing a synchronous assertion against
	// forwardPool's own async dispatch.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.transport.blockCount(); got != 0 {
		t.Fatalf("BUG REGRESSION: a block find whose real hash could not be resolved was still forwarded to the backend (count=%d) -- it must be skipped entirely, never forwarded with a placeholder/empty hash", got)
	}

	if got := testutil.ToFloat64(m.DirectBlockHashUnresolvedTotal); got != 1 {
		t.Fatalf("DirectBlockHashUnresolvedTotal = %v, want 1 (fail loudly, per FIX_BRIEF.md item 3)", got)
	}
}

// TestDirectResolveMoneroBlockHash_NoResolverConfigured is a direct
// unit-level regression guard for resolveMoneroBlockHash's own
// documented contract: a -coin=monero misconfiguration (ServerConfig.
// MonerodURL left empty) must return a clear error, NEVER an empty
// string mistaken for a real (if oddly-empty) hash.
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
