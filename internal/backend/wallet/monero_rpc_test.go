// Copyright and license: see repository LICENSE (MIT).
package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// walletTestServer builds a minimal, real HTTP server implementing
// exactly the "transfer"/"get_balance" JSON-RPC 2.0 methods
// MoneroWalletRPC depends on, driven by a handler func so each test
// controls the response/error directly — mirrors
// internal/backend/chain/monero_test.go's moneroTestServer.
func walletTestServer(t *testing.T, handler func(method string, params map[string]any) (any, *walletRPCError)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		result, rpcErr := handler(req.Method, req.Params)

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

func TestMoneroWalletRPC_Transfer(t *testing.T) {
	srv := walletTestServer(t, func(method string, params map[string]any) (any, *walletRPCError) {
		if method != "transfer" {
			t.Fatalf("unexpected method %q", method)
		}
		dests, _ := params["destinations"].([]any)
		if len(dests) != 2 {
			t.Fatalf("got %d destinations, want 2", len(dests))
		}
		if pid, _ := params["payment_id"].(string); pid != "cafef00d" {
			t.Fatalf("got payment_id %q, want cafef00d", pid)
		}
		return map[string]any{
			"amount":  1500,
			"fee":     123,
			"tx_hash": "abc123",
			"tx_key":  "deadbeef",
		}, nil
	})
	defer srv.Close()

	w := NewMoneroWalletRPC(srv.URL)
	result, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{
			{Address: "addr1", Amount: 1000},
			{Address: "addr2", Amount: 500},
		},
		PaymentID: "cafef00d",
		Priority:  1,
	})
	if err != nil {
		t.Fatalf("Transfer: unexpected error: %v", err)
	}
	if result.TxHash != "abc123" || result.Fee != 123 || result.Amount != 1500 {
		t.Fatalf("Transfer: got %+v, want TxHash=abc123 Fee=123 Amount=1500", result)
	}
}

func TestMoneroWalletRPC_TransferRejectsEmptyDestinations(t *testing.T) {
	w := NewMoneroWalletRPC("http://unused.invalid")
	if _, err := w.Transfer(context.Background(), TransferRequest{}); err == nil {
		t.Fatal("Transfer: expected an error for zero destinations")
	}
}

func TestMoneroWalletRPC_TransferRejectsNonPositiveAmount(t *testing.T) {
	w := NewMoneroWalletRPC("http://unused.invalid")
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr1", Amount: 0}},
	})
	if err == nil {
		t.Fatal("Transfer: expected an error for a non-positive amount")
	}
}

func TestMoneroWalletRPC_TransferRPCErrorPropagates(t *testing.T) {
	srv := walletTestServer(t, func(method string, params map[string]any) (any, *walletRPCError) {
		return nil, &walletRPCError{Code: -20, Message: "not enough unlocked money"}
	})
	defer srv.Close()

	w := NewMoneroWalletRPC(srv.URL)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr1", Amount: 1000}},
	})
	if err == nil {
		t.Fatal("Transfer: expected an error when the RPC reports one")
	}
}

func TestMoneroWalletRPC_GetBalance(t *testing.T) {
	srv := walletTestServer(t, func(method string, params map[string]any) (any, *walletRPCError) {
		if method != "get_balance" {
			t.Fatalf("unexpected method %q", method)
		}
		return map[string]any{"balance": 5000, "unlocked_balance": 3000}, nil
	})
	defer srv.Close()

	w := NewMoneroWalletRPC(srv.URL)
	got, err := w.GetBalance(context.Background())
	if err != nil {
		t.Fatalf("GetBalance: unexpected error: %v", err)
	}
	if got.Total != 5000 || got.Unlocked != 3000 {
		t.Fatalf("GetBalance: got %+v, want Total=5000 Unlocked=3000", got)
	}
}

func TestMoneroWalletRPC_DigestAuth(t *testing.T) {
	const user, pass = "pooluser", "poolpass"
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="monero-rpc", nonce="abc123nonce", qop="auth", algorithm=MD5`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// A real digest client sends a non-empty Authorization
		// header containing the configured username once it has
		// parsed the challenge; this test does not re-derive the
		// full RFC 2617 response hash server-side (that would just
		// duplicate digest.go's own logic) but does confirm the
		// header names the right user and that a request eventually
		// succeeds without ever needing a plaintext password on the
		// wire.
		if !contains(auth, user) {
			t.Fatalf("Authorization header missing username: %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": "0",
			"result": map[string]any{"balance": 1, "unlocked_balance": 1},
		})
	}))
	defer srv.Close()

	wc := NewMoneroWalletRPC(srv.URL, WithDigestAuth(user, pass))
	if _, err := wc.GetBalance(context.Background()); err != nil {
		t.Fatalf("GetBalance with digest auth: unexpected error: %v", err)
	}
	if attempts < 2 {
		t.Fatalf("expected at least 2 attempts (challenge + authenticated retry), got %d", attempts)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
