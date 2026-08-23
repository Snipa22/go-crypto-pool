// Copyright and license: see repository LICENSE (MIT).
package networkpoller

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

// MoneroNetworkSource is the production Source for ALGO_RXM, backed
// by a real monerod JSON-RPC 2.0 "get_info" call. Deliberately does
// not share code/connection with
// internal/backend/chain.MoneroVerifier (a separate, independent
// read-only client -- see that type's doc comment for this
// codebase's established small-duplication-over-cross-layer-
// dependency convention, which applies identically here) nor with
// internal/leaflib/solo's MoneroNodeClient.
type MoneroNetworkSource struct {
	baseURL string
	client  *http.Client
}

// NewMoneroNetworkSource returns a MoneroNetworkSource talking to the
// real monerod JSON-RPC endpoint at baseURL (e.g.
// "http://127.0.0.1:18081" -- no trailing slash or "/json_rpc"
// suffix required).
func NewMoneroNetworkSource(baseURL string) *MoneroNetworkSource {
	return &MoneroNetworkSource{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

type moneroSourceRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
}

type moneroSourceRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *moneroSourceRPCError) Error() string {
	return fmt.Sprintf("monero daemon rpc error %d: %s", e.Code, e.Message)
}

type moneroSourceRPCResponse struct {
	Result json.RawMessage       `json:"result"`
	Error  *moneroSourceRPCError `json:"error"`
}

// moneroGetInfoResult is the real, relevant subset of monerod's
// get_info RPC result (see Monero's own daemon RPC reference) --
// height (the real chain's current tip height), difficulty (the
// real, current network difficulty at that height, as a string
// because monerod represents it via "wide_difficulty" for values
// exceeding a uint64 on some networks -- difficulty is used here as
// the plain uint64 "difficulty" field, sufficient for every real
// deployment this codebase targets), target (the real target block
// time in seconds this network's difficulty is calibrated against --
// the standard input to the difficulty/target-seconds = hashrate
// estimate formula), and top_block_hash.
type moneroGetInfoResult struct {
	Height       uint64 `json:"height"`
	Difficulty   uint64 `json:"difficulty"`
	Target       uint64 `json:"target"`
	TopBlockHash string `json:"top_block_hash"`
	Status       string `json:"status"`
}

func (s *MoneroNetworkSource) call(ctx context.Context, method string, out any) error {
	reqBody, err := json.Marshal(moneroSourceRPCRequest{JSONRPC: "2.0", ID: "0", Method: method})
	if err != nil {
		return fmt.Errorf("networkpoller: monero: marshaling %s request: %w", method, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/json_rpc", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("networkpoller: monero: building %s request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("networkpoller: monero: %s request failed: %w", method, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("networkpoller: monero: reading %s response body: %w", method, err)
	}

	var rpcResp moneroSourceRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("networkpoller: monero: decoding %s response (status %d): %w", method, httpResp.StatusCode, err)
	}
	if rpcResp.Error != nil {
		return rpcResp.Error
	}
	if out != nil {
		if err := json.Unmarshal(rpcResp.Result, out); err != nil {
			return fmt.Errorf("networkpoller: monero: decoding %s result payload: %w", method, err)
		}
	}
	return nil
}

// FetchNetworkState implements Source for Monero via a real
// get_info call.
func (s *MoneroNetworkSource) FetchNetworkState(ctx context.Context) (State, error) {
	var result moneroGetInfoResult
	if err := s.call(ctx, "get_info", &result); err != nil {
		return State{}, fmt.Errorf("networkpoller: monero: get_info: %w", err)
	}
	if result.Status != "OK" {
		return State{}, fmt.Errorf("networkpoller: monero: get_info returned non-OK status %q", result.Status)
	}

	difficulty := float64(result.Difficulty)

	var hashrate *float64
	if result.Target > 0 {
		// The standard, real Monero network-hashrate estimate:
		// current network difficulty divided by the real, current
		// target block time in seconds -- the same formula every
		// public Monero network-stats page/explorer uses.
		hr := difficulty / float64(result.Target)
		hashrate = &hr
	}

	return State{
		Height:              int64(result.Height),
		Difficulty:          &difficulty,
		EstimatedHashrateHS: hashrate,
		BestBlockHash:       result.TopBlockHash,
	}, nil
}
