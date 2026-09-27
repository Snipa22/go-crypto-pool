// Copyright and license: see repository LICENSE (MIT).
package chain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MoneroVerifier is the production ChainVerifier for ALGO_RXM, backed
// by a real monerod JSON-RPC 2.0 connection ("/json_rpc" —
// get_block_header_by_height). It deliberately does not share any
// code with internal/leaflib/solo's MoneroNodeClient (monero_node.go)
// — that type is leaflib's block-template-fetch/submit client; this
// one is the backend's independent, read-only chain-verification
// client, and the two have no legitimate reason to share a
// connection, credentials, or even necessarily point at the same
// monerod instance. Duplicating the small JSON-RPC envelope types
// below (rather than importing leaflib/solo from the backend) also
// keeps internal/backend free of any dependency on internal/leaflib,
// which is deliberate — see internal/leaflib/direct/wireutil.go's doc
// comment for this codebase's established small-duplication-over-
// cross-layer-dependency convention.
type MoneroVerifier struct {
	baseURL string
	client  *http.Client
}

// NewMoneroVerifier returns a MoneroVerifier talking to the real
// monerod JSON-RPC endpoint at baseURL (e.g. "http://127.0.0.1:18081"
// — no trailing slash or "/json_rpc" suffix required).
func NewMoneroVerifier(baseURL string) *MoneroVerifier {
	return &MoneroVerifier{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

type moneroVerifierRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type moneroVerifierRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *moneroVerifierRPCError) Error() string {
	return fmt.Sprintf("monero daemon rpc error %d: %s", e.Code, e.Message)
}

type moneroVerifierRPCResponse struct {
	Result json.RawMessage         `json:"result"`
	Error  *moneroVerifierRPCError `json:"error"`
}

// moneroBlockHeaderByHeightResult is monerod's real
// get_block_header_by_height result shape (the "block_header" object
// documented in Monero's own daemon RPC reference: hash, height, depth
// (blocks mined on top, i.e. confirmations), orphan_status (always
// false for this particular RPC — get_block_header_by_height only ever
// resolves a height to whatever block IS currently on the main chain
// at that height, it cannot return an orphan by height — so this
// package uses hash comparison, not this field, to detect orphaning;
// see Verify's doc comment), plus status/untrusted for the RPC
// envelope itself.
type moneroBlockHeaderByHeightResult struct {
	BlockHeader struct {
		Hash         string `json:"hash"`
		Height       uint64 `json:"height"`
		Depth        uint64 `json:"depth"`
		OrphanStatus bool   `json:"orphan_status"`
		Reward       uint64 `json:"reward"`
	} `json:"block_header"`
	Status string `json:"status"`
}

// call performs one real JSON-RPC 2.0 request against
// baseURL+"/json_rpc".
func (v *MoneroVerifier) call(ctx context.Context, method string, params any, out any) error {
	reqBody, err := json.Marshal(moneroVerifierRPCRequest{
		JSONRPC: "2.0",
		ID:      "0",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("chain: monero: marshaling %s request: %w", method, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+"/json_rpc", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("chain: monero: building %s request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := v.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("chain: monero: %s request failed: %w", method, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("chain: monero: reading %s response body: %w", method, err)
	}

	var rpcResp moneroVerifierRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("chain: monero: decoding %s response (status %d): %w", method, httpResp.StatusCode, err)
	}
	if rpcResp.Error != nil {
		return rpcResp.Error
	}
	if out != nil {
		if err := json.Unmarshal(rpcResp.Result, out); err != nil {
			return fmt.Errorf("chain: monero: decoding %s result payload: %w", method, err)
		}
	}
	return nil
}

// Verify implements ChainVerifier for Monero via a real
// get_block_header_by_height call. Unlike Tari's two-call
// GetHeaderByHash+GetBlocks approach (tari.go), monerod's
// get_block_header_by_height already only ever answers with whatever
// block is currently on the MAIN chain at that height (or a "height X
// is bigger than the current top block height" style RPC error if the
// chain hasn't reached that height at all) — so a single call gives
// both confirmation count (via the depth field) and orphan detection
// (by comparing the returned canonical hash to hashHex) in one round
// trip.
func (v *MoneroVerifier) Verify(ctx context.Context, hashHex string, height int64) (VerifyResult, error) {
	if height < 0 {
		return VerifyResult{}, fmt.Errorf("chain: monero: height must be non-negative, got %d", height)
	}

	var result moneroBlockHeaderByHeightResult
	err := v.call(ctx, "get_block_header_by_height", map[string]any{"height": height}, &result)
	if err != nil {
		if isMoneroHeightNotReached(err) {
			return VerifyResult{Found: false}, nil
		}
		return VerifyResult{}, fmt.Errorf("chain: monero: get_block_header_by_height(height=%d): %w", height, err)
	}
	if result.Status != "OK" {
		return VerifyResult{}, fmt.Errorf("chain: monero: get_block_header_by_height(height=%d) returned non-OK status %q", height, result.Status)
	}

	canonicalHash := result.BlockHeader.Hash
	orphaned := !strings.EqualFold(canonicalHash, hashHex)

	return VerifyResult{
		Found:         true,
		Orphaned:      orphaned,
		Confirmations: int64(result.BlockHeader.Depth),
		CanonicalHash: canonicalHash,
		Reward:        int64(result.BlockHeader.Reward),
	}, nil
}

// isMoneroHeightNotReached reports whether err is monerod's real
// "requested height is beyond the current chain tip" RPC error (code
// -2 — confirmed via a real live daemon call this session; the exact
// message wording varies by monerod version/build — observed variants
// include "... greater than current top block height: N" and "...
// bigger than the current top block height" — so this checks the
// stable error CODE first and only falls back to a message substring
// match as a secondary signal) — the Monero-side equivalent of Tari's
// codes.NotFound (see tari.go's isTariNotFound): a height the chain
// simply hasn't reached yet is expected steady state for a
// just-submitted block, not an operational failure.
func isMoneroHeightNotReached(err error) bool {
	var rpcErr *moneroVerifierRPCError
	if e, ok := err.(*moneroVerifierRPCError); ok {
		rpcErr = e
	} else {
		return false
	}
	if rpcErr.Code == -2 {
		return true
	}
	msg := strings.ToLower(rpcErr.Message)
	return strings.Contains(msg, "bigger than the current top block height") ||
		strings.Contains(msg, "greater than current top block height")
}
