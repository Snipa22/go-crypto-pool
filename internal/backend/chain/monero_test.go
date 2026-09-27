// Copyright and license: see repository LICENSE (MIT).
package chain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// moneroTestServer builds a minimal, real HTTP server implementing
// exactly the get_block_header_by_height JSON-RPC 2.0 method
// MoneroVerifier depends on, driven by a handler func so each test
// controls the response/error directly.
func moneroTestServer(t *testing.T, handler func(height float64) (any, *moneroVerifierRPCError)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if req.Method != "get_block_header_by_height" {
			t.Fatalf("unexpected method %q", req.Method)
		}
		height, _ := req.Params["height"].(float64)
		result, rpcErr := handler(height)

		resp := map[string]any{"jsonrpc": "2.0", "id": "0"}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestMoneroVerifier_CanonicalAndConfirmed(t *testing.T) {
	srv := moneroTestServer(t, func(height float64) (any, *moneroVerifierRPCError) {
		return map[string]any{
			"status": "OK",
			"block_header": map[string]any{
				"hash":   "deadbeef",
				"height": height,
				"depth":  60,
				"reward": 600000000000,
			},
		}, nil
	})
	defer srv.Close()

	v := NewMoneroVerifier(srv.URL)
	got, err := v.Verify(context.Background(), "deadbeef", 12345)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !got.Found || got.Orphaned {
		t.Fatalf("Verify: got Found=%v Orphaned=%v, want Found=true Orphaned=false", got.Found, got.Orphaned)
	}
	if got.Confirmations != 60 {
		t.Fatalf("Verify: got Confirmations=%d, want 60", got.Confirmations)
	}
	if got.Reward != 600000000000 {
		t.Fatalf("Verify: got Reward=%d, want 600000000000 (from the real get_block_header_by_height response's own \"reward\" field, the SAME real call already made for hash/confirmation checking -- no extra RPC)", got.Reward)
	}
}

func TestMoneroVerifier_Orphaned(t *testing.T) {
	srv := moneroTestServer(t, func(height float64) (any, *moneroVerifierRPCError) {
		return map[string]any{
			"status": "OK",
			"block_header": map[string]any{
				"hash":   "canonicalhash",
				"height": height,
				"depth":  5,
			},
		}, nil
	})
	defer srv.Close()

	v := NewMoneroVerifier(srv.URL)
	got, err := v.Verify(context.Background(), "submittedhash", 12345)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !got.Found || !got.Orphaned {
		t.Fatalf("Verify: got Found=%v Orphaned=%v, want Found=true Orphaned=true", got.Found, got.Orphaned)
	}
	if got.CanonicalHash != "canonicalhash" {
		t.Fatalf("Verify: got CanonicalHash=%s, want canonicalhash", got.CanonicalHash)
	}
}

func TestMoneroVerifier_HeightNotReachedYet(t *testing.T) {
	srv := moneroTestServer(t, func(height float64) (any, *moneroVerifierRPCError) {
		return nil, &moneroVerifierRPCError{Code: -2, Message: fmt.Sprintf("Requested height %d is bigger than the current top block height", int64(height))}
	})
	defer srv.Close()

	v := NewMoneroVerifier(srv.URL)
	got, err := v.Verify(context.Background(), "deadbeef", 999999999)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if got.Found {
		t.Fatalf("Verify: got Found=true, want false for a not-yet-reached height")
	}
}

func TestMoneroVerifier_OtherRPCErrorPropagates(t *testing.T) {
	srv := moneroTestServer(t, func(height float64) (any, *moneroVerifierRPCError) {
		return nil, &moneroVerifierRPCError{Code: -1, Message: "Internal error"}
	})
	defer srv.Close()

	v := NewMoneroVerifier(srv.URL)
	_, err := v.Verify(context.Background(), "deadbeef", 100)
	if err == nil {
		t.Fatal("Verify: expected an error for a non-height-related RPC failure, got nil")
	}
}

func TestMoneroVerifier_NegativeHeight(t *testing.T) {
	v := NewMoneroVerifier("http://unused.invalid")
	if _, err := v.Verify(context.Background(), "deadbeef", -1); err == nil {
		t.Fatal("Verify: expected an error for a negative height")
	}
}
