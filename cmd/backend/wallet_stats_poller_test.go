// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/backend/wallet"
)

// walletStatsFakeMonero is a minimal wallet.WalletClient test double
// with NO DetailedBalanceClient capability -- mirrors
// *wallet.MoneroWalletRPC's real shape exactly (only Total/Unlocked,
// never a genuine 4-way split).
type walletStatsFakeMonero struct {
	balance wallet.Balance
	err     error
}

func (f *walletStatsFakeMonero) Transfer(_ context.Context, _ wallet.TransferRequest) (wallet.TransferResult, error) {
	return wallet.TransferResult{}, fmt.Errorf("walletStatsFakeMonero: Transfer not supported by this minimal test double")
}

func (f *walletStatsFakeMonero) GetBalance(_ context.Context) (wallet.Balance, error) {
	return f.balance, f.err
}

var _ wallet.WalletClient = (*walletStatsFakeMonero)(nil)

// walletStatsFakeTari is a minimal wallet.WalletClient test double
// that ALSO satisfies wallet.DetailedBalanceClient -- mirrors
// *wallet.TariWalletGRPC's real shape exactly (genuine independent
// available/pending_incoming/pending_outgoing/timelocked fields).
type walletStatsFakeTari struct {
	detailed wallet.DetailedBalance
	err      error
}

func (f *walletStatsFakeTari) Transfer(_ context.Context, _ wallet.TransferRequest) (wallet.TransferResult, error) {
	return wallet.TransferResult{}, fmt.Errorf("walletStatsFakeTari: Transfer not supported by this minimal test double")
}

func (f *walletStatsFakeTari) GetBalance(_ context.Context) (wallet.Balance, error) {
	return wallet.Balance{
		Total:    f.detailed.Available + f.detailed.PendingIncoming + f.detailed.Timelocked,
		Unlocked: f.detailed.Available,
	}, f.err
}

func (f *walletStatsFakeTari) GetDetailedBalance(_ context.Context) (wallet.DetailedBalance, error) {
	return f.detailed, f.err
}

var (
	_ wallet.WalletClient          = (*walletStatsFakeTari)(nil)
	_ wallet.DetailedBalanceClient = (*walletStatsFakeTari)(nil)
)

// scrapeBackendMetrics scrapes m's real promhttp handler and returns
// the full plain-text exposition body -- mirrors this codebase's
// established scrape()-helper convention used throughout the
// leaf-direct/leaf-solo metrics test suites.
func scrapeBackendMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /metrics body: %v", err)
	}
	return string(body)
}

// walletGaugeLine builds the exact wallet_balance_atomic exposition
// line for one (algo, network, currency, kind, value) combination --
// promhttp emits labels in alphabetical order by name (algo,
// currency, kind, network here), which this mirrors exactly.
func walletGaugeLine(algo, network, currency, kind string, value float64) string {
	return fmt.Sprintf(`wallet_balance_atomic{algo="%s",currency="%s",kind="%s",network="%s"} %v`, algo, currency, kind, network, value)
}

// pollOnceForTest drives runWalletStatsPoller for exactly one poll
// pass. runWalletStatsPoller calls pollOnce() synchronously BEFORE
// entering its ticker loop (see its own doc comment), so canceling
// the context immediately still observes that first real pass --
// avoids needing a sleep-based wait in the tests below.
func pollOnceForTest(m *metrics.Metrics, targets []walletStatsTarget) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		runWalletStatsPoller(ctx, m, targets, time.Hour)
		close(done)
	}()
	<-done
}

// TestRunWalletStatsPoller_TariReportsRealFourWayBreakdown is the
// required regression proof for this feature: a Tari-family target
// (satisfying wallet.DetailedBalanceClient) must report its REAL
// pending_incoming/timelocked values, not the permanent 0 the poller
// used to hardcode for every target regardless of coin.
func TestRunWalletStatsPoller_TariReportsRealFourWayBreakdown(t *testing.T) {
	m := metrics.New("test")
	tari := &walletStatsFakeTari{detailed: wallet.DetailedBalance{
		Available:       1000,
		Timelocked:      50,
		PendingIncoming: 25,
		PendingOutgoing: 10,
	}}
	targets := []walletStatsTarget{{algo: "RXT", network: "mainnet", currency: "XTM", client: tari}}

	pollOnceForTest(m, targets)
	body := scrapeBackendMetrics(t, m)

	for _, want := range []string{
		walletGaugeLine("RXT", "mainnet", "XTM", walletBalanceKindAvailable, 1000),
		walletGaugeLine("RXT", "mainnet", "XTM", walletBalanceKindTimelocked, 50),
		walletGaugeLine("RXT", "mainnet", "XTM", walletBalanceKindPendingIncoming, 25),
		walletGaugeLine("RXT", "mainnet", "XTM", walletBalanceKindPendingOutgoing, 10),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestRunWalletStatsPoller_MoneroFallsBackToTotalUnlockedSplit proves
// the pre-existing Monero-family behavior is completely unchanged: a
// target whose client does NOT satisfy DetailedBalanceClient still
// reports available=Unlocked, pending_outgoing=(Total-Unlocked), and
// pending_incoming/timelocked=0 (a genuine 0 for Monero, which truly
// cannot distinguish those from Total -- not a regression).
func TestRunWalletStatsPoller_MoneroFallsBackToTotalUnlockedSplit(t *testing.T) {
	m := metrics.New("test")
	monero := &walletStatsFakeMonero{balance: wallet.Balance{Total: 500, Unlocked: 400}}
	targets := []walletStatsTarget{{algo: "RXM", network: "mainnet", currency: "XMR", client: monero}}

	pollOnceForTest(m, targets)
	body := scrapeBackendMetrics(t, m)

	for _, want := range []string{
		walletGaugeLine("RXM", "mainnet", "XMR", walletBalanceKindAvailable, 400),
		walletGaugeLine("RXM", "mainnet", "XMR", walletBalanceKindPendingOutgoing, 100),
		walletGaugeLine("RXM", "mainnet", "XMR", walletBalanceKindPendingIncoming, 0),
		walletGaugeLine("RXM", "mainnet", "XMR", walletBalanceKindTimelocked, 0),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

// TestRunWalletStatsPoller_DetailedBalanceErrorIncrementsPollErrors
// proves a failing GetDetailedBalance call is counted on
// WalletBalancePollErrorsTotal exactly like a failing plain
// GetBalance call already was.
func TestRunWalletStatsPoller_DetailedBalanceErrorIncrementsPollErrors(t *testing.T) {
	m := metrics.New("test")
	tari := &walletStatsFakeTari{err: fmt.Errorf("fake: wallet grpc unreachable")}
	targets := []walletStatsTarget{{algo: "RXT", network: "mainnet", currency: "XTM", client: tari}}

	pollOnceForTest(m, targets)
	body := scrapeBackendMetrics(t, m)

	if !strings.Contains(body, `wallet_balance_poll_errors_total{algo="RXT",currency="XTM",network="mainnet"} 1`) {
		t.Errorf("expected wallet_balance_poll_errors_total to have incremented on a failed GetDetailedBalance call, got:\n%s", body)
	}
}
