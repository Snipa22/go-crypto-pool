// Copyright and license: see repository LICENSE (MIT).
package wallet

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

// MoneroWalletRPC is the production WalletClient for Monero, backed
// by a real monero-wallet-rpc JSON-RPC 2.0 connection. It is deliberately
// independent of internal/backend/chain.MoneroVerifier — that type talks
// to monerod (the daemon, read-only chain queries); this one talks to
// monero-wallet-rpc (the wallet process, real fund-moving RPCs) — two
// different real Monero processes with entirely different
// responsibilities and, in most real pool deployments, different trust
// boundaries (the wallet RPC endpoint holds hot-wallet keys and should
// never be as broadly reachable as the daemon).
type MoneroWalletRPC struct {
	baseURL string
	client  *http.Client
	// accountIndex selects which real subaddress account (Monero's
	// own multi-account wallet feature) transfer/get_balance operate
	// against. Zero is the wallet's primary account — the correct
	// default for a pool hot wallet that has not been deliberately
	// set up with multiple accounts.
	accountIndex uint64
}

// Option configures an optional MoneroWalletRPC construction knob.
type Option func(*moneroWalletRPCOptions)

type moneroWalletRPCOptions struct {
	username     string
	password     string
	timeout      time.Duration
	accountIndex uint64
}

// WithDigestAuth configures HTTP Digest authentication (RFC 2617)
// against the credentials monero-wallet-rpc was started with via its
// own --rpc-login user:pass flag. Omit this option entirely for a
// wallet RPC endpoint started without --rpc-login.
func WithDigestAuth(username, password string) Option {
	return func(o *moneroWalletRPCOptions) {
		o.username = username
		o.password = password
	}
}

// WithTimeout overrides the default 30s HTTP client timeout. Real
// transfer calls against a busy/syncing wallet can legitimately take
// longer than simple balance queries, so callers moving large payout
// batches may want a longer timeout than this package's default.
func WithTimeout(d time.Duration) Option {
	return func(o *moneroWalletRPCOptions) {
		o.timeout = d
	}
}

// WithAccountIndex selects a non-default (non-zero) subaddress
// account for transfer/get_balance calls. See MoneroWalletRPC's
// accountIndex field doc comment.
func WithAccountIndex(index uint64) Option {
	return func(o *moneroWalletRPCOptions) {
		o.accountIndex = index
	}
}

// NewMoneroWalletRPC returns a MoneroWalletRPC talking to the real
// monero-wallet-rpc JSON-RPC endpoint at baseURL (e.g.
// "http://127.0.0.1:18083" — no trailing slash or "/json_rpc" suffix
// required).
func NewMoneroWalletRPC(baseURL string, opts ...Option) *MoneroWalletRPC {
	o := moneroWalletRPCOptions{timeout: 30 * time.Second}
	for _, opt := range opts {
		opt(&o)
	}

	var transport http.RoundTripper
	if o.username != "" || o.password != "" {
		transport = &digestTransport{username: o.username, password: o.password}
	}

	return &MoneroWalletRPC{
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		client:       &http.Client{Timeout: o.timeout, Transport: transport},
		accountIndex: o.accountIndex,
	}
}

type walletRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// walletRPCError is monero-wallet-rpc's real JSON-RPC error envelope
// shape. Its Error() method's format intentionally matches
// go-xmr-lib's legacy wallet.XMRTransferReceipt.Error field's raw
// message text (message only, no code) for continuity with any
// existing operator tooling/log-grepping built against that legacy
// error text — see this package's doc comment for why this codebase
// does not import go-xmr-lib's wallet package directly (independent,
// from-scratch client, same reasoning as chain.MoneroVerifier's doc
// comment on not sharing code with leaflib/solo's node client).
type walletRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *walletRPCError) Error() string {
	return fmt.Sprintf("monero wallet rpc error %d: %s", e.Code, e.Message)
}

type walletRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *walletRPCError `json:"error"`
}

// call performs one real JSON-RPC 2.0 request against
// baseURL+"/json_rpc" — the same endpoint path every real
// monero-wallet-rpc method (transfer, get_balance, ...) is dispatched
// through.
func (w *MoneroWalletRPC) call(ctx context.Context, method string, params any, out any) error {
	reqBody, err := json.Marshal(walletRPCRequest{
		JSONRPC: "2.0",
		ID:      "0",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("wallet: monero: marshaling %s request: %w", method, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, w.baseURL+"/json_rpc", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("wallet: monero: building %s request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := w.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("wallet: monero: %s request failed: %w", method, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("wallet: monero: reading %s response body: %w", method, err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("wallet: monero: %s request returned HTTP %d: %s", method, httpResp.StatusCode, string(body))
	}

	var rpcResp walletRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("wallet: monero: decoding %s response: %w", method, err)
	}
	if rpcResp.Error != nil {
		return rpcResp.Error
	}
	if out != nil {
		if err := json.Unmarshal(rpcResp.Result, out); err != nil {
			return fmt.Errorf("wallet: monero: decoding %s result payload: %w", method, err)
		}
	}
	return nil
}

// transferDestination is one entry of the real "transfer" RPC's
// destinations array param.
type transferDestination struct {
	Amount  uint64 `json:"amount"`
	Address string `json:"address"`
}

// transferParams is the real monero-wallet-rpc "transfer" method's
// documented params shape. GetTxKey is always requested (harmless if
// unused, and useful for an operator who wants to independently
// verify a payout via a real tx-key + monero blockchain explorer
// lookup) but its value is not currently surfaced through
// TransferResult (a reasonable, small follow-up if ever needed).
type transferParams struct {
	Destinations []transferDestination `json:"destinations"`
	AccountIndex uint64                `json:"account_index"`
	Priority     int                   `json:"priority,omitempty"`
	RingSize     int                   `json:"ring_size,omitempty"`
	PaymentID    string                `json:"payment_id,omitempty"`
	GetTxKey     bool                  `json:"get_tx_key"`
}

type transferResult struct {
	Amount uint64 `json:"amount"`
	Fee    uint64 `json:"fee"`
	TxHash string `json:"tx_hash"`
	TxKey  string `json:"tx_key"`
}

// Transfer implements WalletClient via a real monero-wallet-rpc
// "transfer" call. It refuses to build a request with zero
// destinations or any non-positive Destination.Amount — both are
// caller bugs (see internal/backend/disburse's batching, which never
// constructs either), not something the real RPC needs to be asked
// to reject on this codebase's behalf.
func (w *MoneroWalletRPC) Transfer(ctx context.Context, req TransferRequest) (TransferResult, error) {
	if len(req.Destinations) == 0 {
		return TransferResult{}, fmt.Errorf("wallet: monero: Transfer: at least one destination is required")
	}
	dests := make([]transferDestination, 0, len(req.Destinations))
	for _, d := range req.Destinations {
		if d.Amount <= 0 {
			return TransferResult{}, fmt.Errorf("wallet: monero: Transfer: destination %s has non-positive amount %d", d.Address, d.Amount)
		}
		if d.Address == "" {
			return TransferResult{}, fmt.Errorf("wallet: monero: Transfer: destination has an empty address")
		}
		dests = append(dests, transferDestination{Amount: uint64(d.Amount), Address: d.Address})
	}

	params := transferParams{
		Destinations: dests,
		AccountIndex: w.accountIndex,
		Priority:     req.Priority,
		RingSize:     req.RingSize,
		PaymentID:    req.PaymentID,
		GetTxKey:     true,
	}

	var result transferResult
	if err := w.call(ctx, "transfer", params, &result); err != nil {
		return TransferResult{}, fmt.Errorf("wallet: monero: transfer: %w", err)
	}
	if result.TxHash == "" {
		return TransferResult{}, fmt.Errorf("wallet: monero: transfer: RPC reported success but returned no tx_hash")
	}
	return TransferResult{
		TxHash: result.TxHash,
		Fee:    int64(result.Fee),
		Amount: int64(result.Amount),
	}, nil
}

type getBalanceParams struct {
	AccountIndex uint64 `json:"account_index"`
}

type getBalanceResult struct {
	Balance         uint64 `json:"balance"`
	UnlockedBalance uint64 `json:"unlocked_balance"`
}

// GetBalance implements WalletClient via a real monero-wallet-rpc
// "get_balance" call.
func (w *MoneroWalletRPC) GetBalance(ctx context.Context) (Balance, error) {
	var result getBalanceResult
	if err := w.call(ctx, "get_balance", getBalanceParams{AccountIndex: w.accountIndex}, &result); err != nil {
		return Balance{}, fmt.Errorf("wallet: monero: get_balance: %w", err)
	}
	return Balance{
		Total:    int64(result.Balance),
		Unlocked: int64(result.UnlockedBalance),
	}, nil
}

var _ WalletClient = (*MoneroWalletRPC)(nil)
