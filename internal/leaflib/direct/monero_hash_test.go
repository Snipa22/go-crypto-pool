// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockMoneroHeaderServer starts a real local httptest server whose
// /json_rpc get_block_header_by_height response is controlled by
// hash/errMessage: if errMessage is non-empty, it returns a real
// JSON-RPC error object; otherwise it returns a real
// {"status":"OK","block_header":{"hash":hash}} result.
func mockMoneroHeaderServer(t *testing.T, hash, errMessage string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/json_rpc", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req struct {
			Method string `json:"method"`
			Params struct {
				Height uint64 `json:"height"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decoding request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Method != "get_block_header_by_height" {
			t.Errorf("unexpected method %q", req.Method)
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if errMessage != "" {
			fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","error":{"code":-2,"message":%q}}`, errMessage)
			return
		}
		fmt.Fprintf(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","block_header":{"hash":%q}}}`, hash)
	})
	return httptest.NewServer(mux)
}

// TestMoneroBlockHeaderClient_GetBlockHeaderHashByHeight_Success
// confirms the real hex hash monerod's own get_block_header_by_height
// response carries flows through unchanged -- the exact real hash
// shape internal/backend/chain.MoneroVerifier.Verify ultimately
// compares a stored blocks.hash value against.
func TestMoneroBlockHeaderClient_GetBlockHeaderHashByHeight_Success(t *testing.T) {
	const wantHash = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff0011223"
	srv := mockMoneroHeaderServer(t, wantHash, "")
	defer srv.Close()

	client := NewMoneroBlockHeaderClient(srv.URL)
	got, err := client.GetBlockHeaderHashByHeight(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetBlockHeaderHashByHeight: %v", err)
	}
	if got != wantHash {
		t.Fatalf("hash = %q, want %q", got, wantHash)
	}
}

// TestMoneroBlockHeaderClient_GetBlockHeaderHashByHeight_RPCError
// confirms a real monerod JSON-RPC error (e.g. height not reached
// yet) surfaces as a real Go error, never as a silently-empty/
// placeholder hash.
func TestMoneroBlockHeaderClient_GetBlockHeaderHashByHeight_RPCError(t *testing.T) {
	srv := mockMoneroHeaderServer(t, "", "height is bigger than the current top block height")
	defer srv.Close()

	client := NewMoneroBlockHeaderClient(srv.URL)
	got, err := client.GetBlockHeaderHashByHeight(context.Background(), 999999)
	if err == nil {
		t.Fatalf("expected an error, got hash=%q, nil error", got)
	}
	if got != "" {
		t.Fatalf("expected an empty hash alongside the error, got %q", got)
	}
}

// TestMoneroBlockHeaderClient_GetBlockHeaderHashByHeight_EmptyHash
// confirms a real (if malformed/unexpected) response carrying an
// empty hash string is itself treated as an error, never returned as
// a valid-looking empty result.
func TestMoneroBlockHeaderClient_GetBlockHeaderHashByHeight_EmptyHash(t *testing.T) {
	srv := mockMoneroHeaderServer(t, "", "")
	defer srv.Close()

	client := NewMoneroBlockHeaderClient(srv.URL)
	got, err := client.GetBlockHeaderHashByHeight(context.Background(), 1)
	if err == nil {
		t.Fatalf("expected an error for an empty block_header.hash, got hash=%q, nil error", got)
	}
	if got != "" {
		t.Fatalf("expected an empty hash alongside the error, got %q", got)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected the error to mention the empty hash, got: %v", err)
	}
}

var _ moneroBlockHeaderResolver = (*MoneroBlockHeaderClient)(nil)
