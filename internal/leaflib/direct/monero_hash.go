// Copyright and license: see repository LICENSE (MIT).
package direct

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

// moneroBlockHeaderResolver is the minimal real capability this
// package's Monero (ALGO_RXM) block-find handling needs from a real
// monerod JSON-RPC 2.0 daemon connection: resolving the REAL,
// canonical block hash at a given height via get_block_header_by_height
// -- the exact SAME RPC method/shape internal/backend/chain's own
// MoneroVerifier.Verify ultimately compares a stored blocks.hash
// value against (see that type's Verify doc comment,
// internal/backend/chain/monero.go). Defined as an interface purely
// so session_test.go/server_test.go can inject a fake without a real
// monerod connection.
//
// WHY A NEW, DUPLICATED TYPE HERE, RATHER THAN REUSING
// internal/leaflib/solo.MoneroNodeClient OR internal/backend/chain:
// this fix (FIX_BRIEF.md, "leaf-direct RXM block hash is not the real
// Monero block ID") is explicitly scoped to this leaf-direct package
// only -- it must not modify the read-only internal/leaflib/solo
// package (which today has no get_block_header_by_height method at
// all), and internal/backend is a separate deployable this package
// has no business importing. Duplicating this small, self-contained
// JSON-RPC helper is this codebase's own established convention for
// exactly this situation -- see node.go's tariJobFromResult doc
// comment and internal/backend/chain/monero.go's own doc comment on
// why IT duplicates leaflib/solo's small JSON-RPC envelope types
// rather than importing across that same boundary.
type moneroBlockHeaderResolver interface {
	// GetBlockHeaderHashByHeight returns the REAL, canonical
	// block_header.hash monerod reports for height right now (hex
	// encoded, exactly as the daemon returns it -- no case
	// normalization is applied here since
	// internal/backend/chain.MoneroVerifier.Verify itself compares
	// with strings.EqualFold, not exact byte/case equality). Returns
	// an error for any RPC failure, non-OK daemon status, or a
	// height the chain hasn't reached yet -- callers must never
	// substitute a placeholder hash on error (see FIX_BRIEF.md's
	// explicit fallback-hardening requirement).
	GetBlockHeaderHashByHeight(ctx context.Context, height uint64) (string, error)
}

// MoneroBlockHeaderClient is the production moneroBlockHeaderResolver,
// backed by a real monerod JSON-RPC 2.0 connection ("/json_rpc" --
// get_block_header_by_height). It is deliberately independent of
// solo.MoneroNodeClient (monero_node.go, this leaf's own
// block-template-fetch/submit client) and of
// internal/backend/chain.MoneroVerifier (the backend's own,
// completely separate read-only chain-verification client) -- see
// this file's package doc comment for why duplicating this small
// client is the correct choice here rather than importing either.
type MoneroBlockHeaderClient struct {
	baseURL string
	client  *http.Client
}

// NewMoneroBlockHeaderClient returns a MoneroBlockHeaderClient talking
// to the real monerod JSON-RPC endpoint at baseURL (e.g.
// "http://127.0.0.1:18081" -- no trailing slash or "/json_rpc" suffix
// required, this type appends it itself). In production this is
// always the SAME monerod baseURL this leaf's own
// solo.MoneroNodeClient is already configured against (see
// cmd/leaf-direct/main.go's -monerod-url/LEAF_DIRECT_MONEROD_URL and
// ServerConfig.MonerodURL) -- a genuinely independent HTTP client,
// not a shared connection, exactly mirroring
// internal/backend/chain.NewMoneroVerifier's own "independent client,
// same real daemon" pattern.
func NewMoneroBlockHeaderClient(baseURL string) *MoneroBlockHeaderClient {
	return &MoneroBlockHeaderClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// moneroHeaderRPCRequest is a real, minimal Monero daemon JSON-RPC 2.0
// envelope -- monerod's /json_rpc endpoint uses this exact shape (see
// solo.MoneroNodeClient's own moneroRPCRequest and
// chain.MoneroVerifier's own moneroVerifierRPCRequest for the same
// duplicated shape in this codebase's other two Monero JSON-RPC
// clients).
type moneroHeaderRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// moneroHeaderRPCError is monerod's real JSON-RPC error shape.
type moneroHeaderRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *moneroHeaderRPCError) Error() string {
	return fmt.Sprintf("direct: monero daemon rpc error %d: %s", e.Code, e.Message)
}

// moneroHeaderRPCResponse is the generic JSON-RPC 2.0 response
// envelope. Result is left as json.RawMessage so this file's own
// call site unmarshals into its own real result type below.
type moneroHeaderRPCResponse struct {
	Result json.RawMessage       `json:"result"`
	Error  *moneroHeaderRPCError `json:"error"`
}

// moneroBlockHeaderByHeightResult mirrors
// internal/backend/chain/monero.go's identical
// moneroBlockHeaderByHeightResult exactly (same real monerod
// get_block_header_by_height "block_header" result shape) --
// duplicated here rather than imported, per this file's package doc
// comment.
type moneroBlockHeaderByHeightResult struct {
	BlockHeader struct {
		Hash string `json:"hash"`
	} `json:"block_header"`
	Status string `json:"status"`
}

// call performs one real JSON-RPC 2.0 request against
// baseURL+"/json_rpc".
func (c *MoneroBlockHeaderClient) call(ctx context.Context, method string, params any, out any) error {
	reqBody, err := json.Marshal(moneroHeaderRPCRequest{
		JSONRPC: "2.0",
		ID:      "0",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("direct: monero: marshaling %s request: %w", method, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/json_rpc", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("direct: monero: building %s request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("direct: monero: %s request failed: %w", method, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("direct: monero: reading %s response body: %w", method, err)
	}

	var rpcResp moneroHeaderRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("direct: monero: decoding %s response (status %d): %w", method, httpResp.StatusCode, err)
	}
	if rpcResp.Error != nil {
		return rpcResp.Error
	}
	if out != nil {
		if err := json.Unmarshal(rpcResp.Result, out); err != nil {
			return fmt.Errorf("direct: monero: decoding %s result payload: %w", method, err)
		}
	}
	return nil
}

// GetBlockHeaderHashByHeight implements moneroBlockHeaderResolver via
// a real get_block_header_by_height call -- the exact same RPC
// internal/backend/chain.MoneroVerifier.Verify uses to independently
// confirm a block (see this file's package doc comment): monerod's
// get_block_header_by_height only ever answers with whatever block is
// currently on the MAIN chain at that height, so a non-error response
// here is already the real, canonical hash -- no separate orphan-
// detection step is needed at the point of ORIGINAL submission (this
// leaf isn't verifying maturity here, only capturing the real hash to
// forward -- internal/backend/unlocker owns ongoing maturity/orphan
// verification against this same hash later).
func (c *MoneroBlockHeaderClient) GetBlockHeaderHashByHeight(ctx context.Context, height uint64) (string, error) {
	var result moneroBlockHeaderByHeightResult
	if err := c.call(ctx, "get_block_header_by_height", map[string]any{"height": height}, &result); err != nil {
		return "", fmt.Errorf("direct: monero: get_block_header_by_height(height=%d): %w", height, err)
	}
	if result.Status != "OK" {
		return "", fmt.Errorf("direct: monero: get_block_header_by_height(height=%d) returned non-OK status %q", height, result.Status)
	}
	if strings.TrimSpace(result.BlockHeader.Hash) == "" {
		return "", fmt.Errorf("direct: monero: get_block_header_by_height(height=%d) returned an empty block_header.hash", height)
	}
	return result.BlockHeader.Hash, nil
}

// Compile-time assertion that MoneroBlockHeaderClient satisfies
// moneroBlockHeaderResolver.
var _ moneroBlockHeaderResolver = (*MoneroBlockHeaderClient)(nil)
