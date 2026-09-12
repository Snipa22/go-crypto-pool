// Package wallet defines the backend's coin-agnostic wallet-transfer
// surface (WalletClient) plus a real monero-wallet-rpc implementation
// (see monero_rpc.go). It is the disbursement-side counterpart of
// internal/backend/chain's ChainVerifier: chain.ChainVerifier answers
// "did this block really land on the real chain", WalletClient
// answers "actually move real coin out of the pool's hot wallet to a
// miner's address" — the two are deliberately separate interfaces
// (a deployment could, in principle, verify blocks against one daemon
// and pay out from a wallet talking to a different one).
//
// internal/backend/disburse is the only caller of WalletClient today
// (its Config.Wallet field) — mirroring how internal/backend/unlocker
// is chain.ChainVerifier's only caller.
package wallet

import (
	"context"
	"errors"
)

// ErrNotBroadcast marks a Transfer error as a DEFINITIVE
// pre-broadcast failure: the implementation can prove no transaction
// was created or relayed, so the caller's balances are safe to retry
// unchanged on a later cycle.
//
// This sentinel exists because the absence of it is what actually
// matters. internal/backend/disburse used to assume EVERY Transfer
// error meant "no coin moved" and marked the payout FAILED, which
// left the balance payable and re-sent the same coin next cycle. Two
// real code paths broke that assumption outright: a
// slow-but-successful monero-wallet-rpc `transfer` that still
// broadcasts after the HTTP client gives up (see monero_rpc.go), and
// Tari's transfer-succeeded-but-fee-lookup-failed path (see
// tari.go). So the contract is now inverted and fail-safe:
//
//	errors.Is(err, ErrNotBroadcast) == true   ->  provably nothing
//	                                              moved; safe to
//	                                              retry (FAILED).
//	errors.Is(err, ErrNotBroadcast) == false  ->  MAY have moved;
//	                                              treat as ambiguous,
//	                                              halt, require a
//	                                              human (AMBIGUOUS).
//
// Every implementation must therefore mark ONLY the errors it can
// genuinely prove happened before anything hit the wire (or that the
// wallet itself explicitly answered "I did not do it"), and leave
// everything else unmarked. An unmarked error is the safe default; a
// wrongly-marked one is a double payment. Use NotBroadcast to mark.
var ErrNotBroadcast = errors.New("wallet: transfer definitively not broadcast")

// NotBroadcast wraps err so errors.Is(err, ErrNotBroadcast) reports
// true, without altering its message. Returns nil for a nil err.
//
// Only use this where non-broadcast is PROVABLE — see
// ErrNotBroadcast's doc comment. "The call returned an error so
// probably nothing happened" is not proof and must not be marked.
func NotBroadcast(err error) error {
	if err == nil {
		return nil
	}
	return notBroadcastError{err: err}
}

// notBroadcastError is NotBroadcast's tiny wrapper type: transparent
// to Error()/Unwrap() (so existing error text and wrapped-error
// chains are unchanged) and matched by errors.Is against
// ErrNotBroadcast via its own Is method.
type notBroadcastError struct {
	err error
}

func (e notBroadcastError) Error() string { return e.err.Error() }

func (e notBroadcastError) Unwrap() error { return e.err }

func (e notBroadcastError) Is(target error) bool { return target == ErrNotBroadcast }

// Destination is one payee/amount pair for a single Transfer call —
// the wallet-side analog of internal/backend/payout.Payment, but
// carrying only what a real transfer RPC needs (no PoolType/
// accounting metadata).
type Destination struct {
	// Address is the destination wallet address (standard or
	// integrated). Required.
	Address string
	// Amount is the amount to send, in the coin's atomic unit
	// (piconero for Monero). Required, must be > 0 — a zero-amount
	// destination is a caller bug, not something any real transfer
	// RPC accepts.
	Amount int64
}

// TransferRequest is one real on-chain transfer: one or more
// Destinations, plus optional inputs a real monero-wallet-rpc
// transfer call accepts (see monero_rpc.go's Transfer for exactly how
// these map onto the "transfer" JSON-RPC method's params).
type TransferRequest struct {
	Destinations []Destination

	// PaymentID, if non-empty, is attached to the transfer.
	// monero-wallet-rpc's "transfer" method only accepts a single
	// payment_id per call (there is no per-destination payment ID
	// in the real RPC) — callers with per-destination payment IDs
	// must issue one TransferRequest per distinct payment ID, which
	// is exactly what internal/backend/disburse's batching does
	// (see disburse.go's doc comment on batch grouping).
	PaymentID string

	// Priority is the real monero-wallet-rpc fee-priority value
	// (0 = default, 1 = unimportant, 2 = normal, 3 = elevated,
	// 4 = priority — Monero's own documented enum). Zero means "let
	// the wallet pick its default", not "no fee" — Monero has no
	// concept of a free transaction.
	Priority int

	// RingSize is the real monero-wallet-rpc ring_size param. Zero
	// means "let the wallet apply its own default/protocol-mandated
	// ring size" — this codebase does not second-guess the wallet's
	// own ring-size policy by defaulting it to a hardcoded number.
	RingSize int
}

// TransferResult is what a real, successful on-chain transfer
// reports back — the fields internal/backend/disburse actually needs
// to record a payout: the real transaction hash (for the payouts
// audit table) and the real network fee actually paid (deducted from
// the hot wallet, not from any miner's balance — see disburse.go).
type TransferResult struct {
	TxHash string
	Fee    int64
	// Amount is the total amount actually transferred (sum of every
	// Destination.Amount in the request that produced this result),
	// echoed back from the real RPC response rather than
	// recalculated locally, so a caller can detect any RPC-side
	// discrepancy.
	Amount int64
}

// Balance is a real wallet's current balance, as reported by
// monero-wallet-rpc's "get_balance" method.
type Balance struct {
	// Total is the wallet's total balance, including unconfirmed/
	// locked change.
	Total int64
	// Unlocked is spendable right now — the figure
	// internal/backend/disburse actually checks a payout batch
	// against before calling Transfer (see disburse.go), since
	// Total can include just-received, still-locked coinbase/
	// change outputs that would make an otherwise-valid transfer
	// request fail with monero-wallet-rpc's real
	// "not enough unlocked money" error.
	Unlocked int64
}

// WalletClient is the narrow, coin-agnostic surface
// internal/backend/disburse depends on for actually moving real coin.
// *MoneroWalletRPC (monero_rpc.go) is the only production
// implementation today; tests use an in-memory fake exactly like
// every other narrow interface in this codebase
// (unlocker.Repository, payout.Repository, chain.ChainVerifier).
type WalletClient interface {
	// Transfer submits one real on-chain transaction paying every
	// Destination in req, returning the real transaction hash/fee
	// once the wallet has actually broadcast it.
	//
	// A non-nil error does NOT mean nothing happened. It means only
	// one of two things, which the caller MUST distinguish via
	// errors.Is(err, ErrNotBroadcast):
	//
	//   - marked ErrNotBroadcast: no transaction was created or
	//     relayed, provably. The caller may safely leave balances
	//     payable and retry.
	//   - NOT marked: the outcome is UNKNOWN — real coin may
	//     already have moved on-chain (a timed-out but successful
	//     RPC, a partially-applied multi-recipient call, a
	//     post-broadcast lookup failure, ...). The caller must NOT
	//     credit/debit anything AND must NOT make those balances
	//     payable again; it has to halt and escalate to a human.
	//     See internal/backend/disburse's runBatch and
	//     migrations/0010_payouts_ambiguous_status.up.sql.
	Transfer(ctx context.Context, req TransferRequest) (TransferResult, error)

	// GetBalance returns the wallet's current real balance.
	// internal/backend/disburse calls this before every batch to
	// confirm enough UNLOCKED balance exists, rather than
	// discovering insufficient funds only via a failed Transfer
	// call.
	GetBalance(ctx context.Context) (Balance, error)
}
