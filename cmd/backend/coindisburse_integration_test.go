package main

// coindisburse_integration_test.go is the real, end-to-end proof for
// payoutbrief.md dispatch #3: one *disburse.Engine built for a real
// standalone monerod-family coin (ARQ -- already covered by a real
// end-to-end leaf test from PR #128, per the brief's own suggestion),
// wired EXACTLY the way buildCoinDisburseEngines/run() wire it (via
// GCPOOL_ARQ_WALLET_RPC_ADDR and buildCoinDisburseEngines itself, not
// a hand-constructed disburse.Engine that would bypass the real
// wiring path), pointed at a fake wallet-rpc test server, run through
// one full RunOnce cycle against a REAL Postgres instance.
//
// Same GCPOOL_TEST_DSN opt-in convention as this package's other
// *_integration_test.go files: unset means skip, not fail.
//
// No real production wallet-rpc endpoint/credentials are used
// anywhere here -- see payoutTestServer below, a minimal, real HTTP
// server implementing exactly the "transfer"/"get_balance" JSON-RPC
// 2.0 methods wallet.MoneroWalletRPC depends on, mirroring
// internal/backend/wallet/monero_rpc_test.go's own walletTestServer
// pattern (that helper is private to package wallet, so this is an
// independent, minimal reimplementation, not a copy-paste of
// unexported code).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/backend/disburse"
	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
)

// coinDisburseTestServer builds a fake monero-wallet-rpc-compatible
// HTTP server driven by a handler func, exactly like
// internal/backend/wallet/monero_rpc_test.go's walletTestServer, so
// this test controls the real "transfer"/"get_balance" JSON-RPC
// responses directly without touching any real coin daemon/wallet.
func coinDisburseTestServer(t *testing.T, handler func(method string, params map[string]any) any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		result := handler(req.Method, req.Params)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": "0", "result": result})
	}))
}

// TestCoinDisburseEngineRunOnceCreditsAndPaysOutARQCurrency is the
// required real end-to-end test: it proves buildCoinDisburseEngines'
// real wiring (env var -> wallet.NewMoneroWalletRPC -> disburse.Engine)
// correctly reads ARQ-currency payable balances, calls Transfer
// against the fake wallet-rpc server, and records the payout as SENT
// with the real balance moved from pending to paid -- against a real
// Postgres instance, not a mocked repository.
func TestCoinDisburseEngineRunOnceCreditsAndPaysOutARQCurrency(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)

	const minerAddress = "arq-miner-1"
	const creditAmount = int64(500000)

	if err := repo.CreditBalance(ctx, "ARQ", "TESTNET", "ARQ", minerAddress, nil, creditAmount); err != nil {
		t.Fatalf("CreditBalance(ARQ): %v", err)
	}

	var transferCalled, getBalanceCalled bool
	srv := coinDisburseTestServer(t, func(method string, params map[string]any) any {
		switch method {
		case "get_balance":
			getBalanceCalled = true
			return map[string]any{"balance": creditAmount * 2, "unlocked_balance": creditAmount * 2}
		case "transfer":
			transferCalled = true
			dests, _ := params["destinations"].([]any)
			if len(dests) != 1 {
				t.Fatalf("transfer: got %d destinations, want 1", len(dests))
			}
			dest, _ := dests[0].(map[string]any)
			if addr, _ := dest["address"].(string); addr != minerAddress {
				t.Fatalf("transfer: destination address = %q, want %q", addr, minerAddress)
			}
			if amt, _ := dest["amount"].(float64); int64(amt) != creditAmount {
				t.Fatalf("transfer: destination amount = %v, want %d", dest["amount"], creditAmount)
			}
			return map[string]any{"amount": creditAmount, "fee": 100, "tx_hash": "arq-test-tx-hash", "tx_key": "deadbeef"}
		default:
			t.Fatalf("unexpected method %q", method)
			return nil
		}
	})
	defer srv.Close()

	// Wire this EXACTLY the way run() does: set the real env var
	// buildCoinDisburseEngines reads, then call that exact function
	// -- never a hand-built disburse.Engine that would bypass the
	// real wiring path this dispatch adds.
	t.Setenv("GCPOOL_ARQ_WALLET_RPC_ADDR", srv.URL)
	// Explicitly ensure no stray digest-auth env vars leak in from
	// the outer environment onto this test.
	os.Unsetenv("GCPOOL_ARQ_WALLET_RPC_USER")
	os.Unsetenv("GCPOOL_ARQ_WALLET_RPC_PASSWORD")

	cfg := config{
		disburseMaxDestinationsPerBatch: 15,
		disburseMinPayoutAtomic:         0,
		disbursePollInterval:            0, // RunOnce is called directly below, not RunLoop.
	}
	m := metrics.New("test")

	engines, clients := buildCoinDisburseEngines(cfg, repo, m, nil)
	engine, ok := engines["ARQ"]
	if !ok {
		t.Fatalf("buildCoinDisburseEngines: no engine built for ARQ (env var GCPOOL_ARQ_WALLET_RPC_ADDR was set to %q) -- got engines for: %v", srv.URL, keysOf(engines))
	}
	if _, ok := clients["ARQ"]; !ok {
		t.Fatalf("buildCoinDisburseEngines: no wallet client returned for ARQ")
	}

	// Confirm the startup safety check (the exact one run() calls
	// via startDisburseLoop) sees this target as safe BEFORE running
	// a cycle -- proving the halt-on-unresolved-payout gate is wired
	// through this loop-built engine too, not bypassed.
	target := disburse.Target{Algo: "ARQ", Network: "TESTNET", Currency: "ARQ"}
	safe, blocked, err := engine.CheckTargets(ctx, []disburse.Target{target})
	if err != nil {
		t.Fatalf("CheckTargets: %v", err)
	}
	if len(blocked) != 0 || len(safe) != 1 {
		t.Fatalf("CheckTargets: got safe=%v blocked=%v, want exactly the ARQ target to be safe (no unresolved payouts yet)", safe, blocked)
	}

	result, err := engine.RunOnce(ctx, "ARQ", "TESTNET", "ARQ")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !getBalanceCalled {
		t.Error("RunOnce: fake wallet-rpc server never received a get_balance call")
	}
	if !transferCalled {
		t.Error("RunOnce: fake wallet-rpc server never received a transfer call")
	}
	if result.Payable != 1 || result.BatchesSent != 1 || result.TotalSent != creditAmount {
		t.Fatalf("RunOnce: got %+v, want Payable=1 BatchesSent=1 TotalSent=%d", result, creditAmount)
	}

	pending, paid := arqBalanceState(t, repo, minerAddress)
	if pending != 0 || paid != creditAmount {
		t.Fatalf("balance after RunOnce: got pending=%d paid=%d, want 0/%d", pending, paid, creditAmount)
	}
}

// arqBalanceState is balanceState (payoutcli_integration_test.go)'s
// counterpart for algo="ARQ" -- that existing helper hardcodes
// algo="RXM", which is correct for its own RXM-focused tests but
// wrong here.
func arqBalanceState(t *testing.T, repo *db.Repository, address string) (pending, paid int64) {
	t.Helper()
	ctx := context.Background()
	rows, err := repo.MinerBalances(ctx, address, "ARQ", "TESTNET", nil)
	if err != nil {
		t.Fatalf("MinerBalances(%s): %v", address, err)
	}
	if len(rows) != 1 {
		t.Fatalf("MinerBalances(%s): got %d rows, want 1", address, len(rows))
	}
	return rows[0].PendingBalance, rows[0].PaidBalance
}

// TestCoinDisburseEngineInheritsUnresolvedPayoutHaltGate is the
// explicit, real-Postgres confirmation payoutbrief.md dispatch #3
// asks for: that the AMBIGUOUS-status halt-on-unresolved-payout gate
// is a property of disburse.Engine/disburse.Repository themselves,
// and therefore applies automatically to a coin engine built via
// buildCoinDisburseEngines' loop -- NOT accidentally bypassed by
// however that loop wires things up. It fabricates exactly the state
// a real ambiguous transfer outcome leaves behind for an ARQ target
// (mirroring fabricateAmbiguousPayout in payoutcli_integration_test.go,
// which is hardcoded to RXM/XMR) and confirms both CheckTargets and a
// direct RunOnce call refuse to move any coin for it.
func TestCoinDisburseEngineInheritsUnresolvedPayoutHaltGate(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)

	const minerAddress = "arq-ambiguous-miner"
	const amount = int64(999)

	if err := repo.CreditBalance(ctx, "ARQ", "TESTNET", "ARQ", minerAddress, nil, amount); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	payable, err := repo.PayableBalances(ctx, "ARQ", "TESTNET", "ARQ", 1)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	var balanceID int64
	for _, p := range payable {
		if p.PaymentAddress == minerAddress {
			balanceID = p.ID
		}
	}
	if balanceID == 0 {
		t.Fatalf("PayableBalances: no row for %s: %+v", minerAddress, payable)
	}
	payoutID, err := repo.RecordPendingPayout(ctx, "ARQ", "TESTNET", "ARQ",
		[]db.DisburseEntry{{BalanceID: balanceID, Amount: amount}}, amount)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}
	if err := repo.MarkPayoutAmbiguous(ctx, payoutID, "maybe-broadcast-tx", "transfer outcome ambiguous (test fixture)"); err != nil {
		t.Fatalf("MarkPayoutAmbiguous: %v", err)
	}

	// A fake wallet server that FAILS the test if the engine ever
	// calls it -- this cycle must refuse before touching the wallet
	// at all.
	srv := coinDisburseTestServer(t, func(method string, params map[string]any) any {
		t.Fatalf("halted cycle unexpectedly called the wallet (method=%s) -- the unresolved-payout gate did not stop it", method)
		return nil
	})
	defer srv.Close()

	t.Setenv("GCPOOL_ARQ_WALLET_RPC_ADDR", srv.URL)
	os.Unsetenv("GCPOOL_ARQ_WALLET_RPC_USER")
	os.Unsetenv("GCPOOL_ARQ_WALLET_RPC_PASSWORD")

	cfg := config{disburseMaxDestinationsPerBatch: 15}
	m := metrics.New("test-halt")
	engines, _ := buildCoinDisburseEngines(cfg, repo, m, nil)
	engine, ok := engines["ARQ"]
	if !ok {
		t.Fatalf("buildCoinDisburseEngines: no engine built for ARQ")
	}

	target := disburse.Target{Algo: "ARQ", Network: "TESTNET", Currency: "ARQ"}
	safe, blocked, err := engine.CheckTargets(ctx, []disburse.Target{target})
	if err != nil {
		t.Fatalf("CheckTargets: %v", err)
	}
	if len(safe) != 0 || len(blocked) != 1 {
		t.Fatalf("CheckTargets: got safe=%v blocked=%v, want the ARQ target BLOCKED by the AMBIGUOUS payout", safe, blocked)
	}
	if blocked[0].Target != target || len(blocked[0].Unresolved) != 1 || blocked[0].Unresolved[0].ID != payoutID {
		t.Fatalf("CheckTargets: got blocked=%+v, want it to name payout %d", blocked, payoutID)
	}

	if _, err := engine.RunOnce(ctx, "ARQ", "TESTNET", "ARQ"); err == nil {
		t.Fatal("RunOnce: succeeded despite an unresolved AMBIGUOUS payout, want it to refuse (disburse.ErrHalted)")
	}

	// And, critically, the balance was NOT touched by the halted
	// cycle -- still sitting exactly where MarkPayoutAmbiguous left
	// it (the full original credit, still pending, not paid), frozen.
	pending, paid := arqBalanceState(t, repo, minerAddress)
	if pending != amount || paid != 0 {
		t.Fatalf("balance after a halted cycle: got pending=%d paid=%d, want %d/0 (frozen by the unresolved AMBIGUOUS payout, RunOnce touched nothing)", pending, paid, amount)
	}
}

// keysOf is a small test helper for a readable failure message.
func keysOf(m map[string]*disburse.Engine) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestBuildCoinDisburseEnginesDisabledWithoutEnvVar confirms the
// "absent env var = disabled, never fatal" contract from
// payoutbrief.md dispatch #3 for a coin that has no
// GCPOOL_<TICKER>_WALLET_RPC_ADDR configured at all.
func TestBuildCoinDisburseEnginesDisabledWithoutEnvVar(t *testing.T) {
	for _, ticker := range []string{"ARQ", "XEQ", "GRFT", "SFX", "ZEPH", "SAL", "XMR"} {
		os.Unsetenv("GCPOOL_" + ticker + "_WALLET_RPC_ADDR")
	}
	cfg := config{disburseMaxDestinationsPerBatch: 15}
	m := metrics.New("test-disabled")
	engines, clients := buildCoinDisburseEngines(cfg, nil, m, nil)
	if len(engines) != 0 {
		t.Errorf("buildCoinDisburseEngines: got %d engine(s) with no wallet-rpc env vars set, want 0: %v", len(engines), keysOf(engines))
	}
	if len(clients) != 0 {
		t.Errorf("buildCoinDisburseEngines: got %d wallet client(s) with no wallet-rpc env vars set, want 0", len(clients))
	}
}
