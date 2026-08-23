package payout

import (
	"context"
	"errors"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeRepo is an in-memory Repository test double, mirroring
// internal/backend/unlocker's fakeRepo style.
type fakeRepo struct {
	// sharesByKey is keyed by "algo/poolType/height".
	sharesByKey map[string][]ShareRow
	soloByKey   map[string]ShareRow
	credits     []creditCall
	creditErr   error
}

type creditCall struct {
	algo, network, paymentAddress string
	paymentID                     *string
	amount                        int64
}

func key(algo, poolType string, height int64) string {
	return algo + "/" + poolType + "/" + itoa(height)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func (f *fakeRepo) SharesAtHeight(_ context.Context, algo, poolType string, height int64) ([]ShareRow, error) {
	return f.sharesByKey[key(algo, poolType, height)], nil
}

func (f *fakeRepo) SoloShare(_ context.Context, algo string, height int64) (ShareRow, bool, error) {
	row, ok := f.soloByKey[key(algo, "SOLO", height)]
	return row, ok, nil
}

func (f *fakeRepo) CreditBalance(_ context.Context, algo, network, paymentAddress string, paymentID *string, amount int64) error {
	if f.creditErr != nil {
		return f.creditErr
	}
	f.credits = append(f.credits, creditCall{algo, network, paymentAddress, paymentID, amount})
	return nil
}

func testConfig() Config {
	return Config{
		FeeAddress:             "fee-addr",
		CoinDevAddress:         "coindev-addr",
		PoolDevAddress:         "pooldev-addr",
		PPSFeePercent:          2,
		PPLNSFeePercent:        1,
		SoloFeePercent:         0.5,
		DevDonationPercent:     10,
		PoolDevDonationPercent: 5,
		PPLNSShareMulti:        2,
	}
}

// TestRunForMaturedBlock_DispatchesByPoolTypeAndApplies exercises the
// unlocker-facing entry point end to end for each supported pool_type
// — the same dispatch cmd/backend's payoutTrigger adapter relies on.
func TestRunForMaturedBlock_DispatchesByPoolTypeAndApplies(t *testing.T) {
	reward := int64(100000)
	repo := &fakeRepo{
		sharesByKey: map[string][]ShareRow{
			key("RXM", "PPS", 100): {{Shares: 1000, PaymentAddress: "alice"}},
		},
		soloByKey: map[string]ShareRow{
			key("RXM", "SOLO", 100): {Shares: 1, PaymentAddress: "solo-winner"},
		},
	}
	c := New(repo, testConfig())

	result, err := c.RunForMaturedBlock(context.Background(), "RXM", "TESTNET", "PPS", 100, 1000, &reward)
	if err != nil {
		t.Fatalf("RunForMaturedBlock(PPS): %v", err)
	}
	if result.Credited == 0 || result.TotalPaid == 0 {
		t.Fatalf("RunForMaturedBlock(PPS): got %+v, want a non-trivial credited result", result)
	}
	foundAlice := false
	for _, cc := range repo.credits {
		if cc.paymentAddress == "alice" {
			foundAlice = true
		}
	}
	if !foundAlice {
		t.Fatalf("RunForMaturedBlock(PPS): expected a CreditBalance call for alice, got %+v", repo.credits)
	}

	repo.credits = nil
	if _, err := c.RunForMaturedBlock(context.Background(), "RXM", "TESTNET", "SOLO", 100, 1000, &reward); err != nil {
		t.Fatalf("RunForMaturedBlock(SOLO): %v", err)
	}
	foundSolo := false
	for _, cc := range repo.credits {
		if cc.paymentAddress == "solo-winner" {
			foundSolo = true
		}
	}
	if !foundSolo {
		t.Fatalf("RunForMaturedBlock(SOLO): expected a CreditBalance call for solo-winner, got %+v", repo.credits)
	}
}

// TestRunForMaturedBlock_NilRewardIsAnError confirms a block whose
// blocks.value column hasn't been populated yet is refused rather
// than silently treated as a zero-reward payout cycle.
func TestRunForMaturedBlock_NilRewardIsAnError(t *testing.T) {
	c := New(&fakeRepo{}, testConfig())
	if _, err := c.RunForMaturedBlock(context.Background(), "RXM", "TESTNET", "PPS", 100, 1000, nil); err == nil {
		t.Fatal("RunForMaturedBlock: got nil error for a nil blockReward, want an error")
	}
}

// TestRunForMaturedBlock_UnsupportedPoolTypeIsAnError confirms PROP
// (a real pool_type value in this schema's enum, see migrations) is
// rejected cleanly rather than causing a panic, since this package
// has no calculatePropPayments equivalent.
func TestRunForMaturedBlock_UnsupportedPoolTypeIsAnError(t *testing.T) {
	reward := int64(1000)
	c := New(&fakeRepo{}, testConfig())
	if _, err := c.RunForMaturedBlock(context.Background(), "RXM", "TESTNET", "PROP", 100, 1000, &reward); err == nil {
		t.Fatal("RunForMaturedBlock: got nil error for pool_type PROP, want an error")
	}
}

// TestRunForMaturedBlock_RecordsMetrics confirms the real
// metrics.Metrics collectors (not a mock) are actually incremented/
// observed by a successful cycle.
func TestRunForMaturedBlock_RecordsMetrics(t *testing.T) {
	reward := int64(1000)
	repo := &fakeRepo{sharesByKey: map[string][]ShareRow{
		key("RXM", "PPS", 5): {{Shares: 10, PaymentAddress: "alice"}},
	}}
	m := metrics.New("test")
	cfg := testConfig()
	cfg.Metrics = m
	c := New(repo, cfg)

	if _, err := c.RunForMaturedBlock(context.Background(), "RXM", "TESTNET", "PPS", 5, 100, &reward); err != nil {
		t.Fatalf("RunForMaturedBlock: %v", err)
	}

	if got := testutil.ToFloat64(m.PayoutCyclesTotal.WithLabelValues("RXM", "PPS", metrics.PayoutResultSuccess)); got != 1 {
		t.Fatalf("PayoutCyclesTotal success = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.PayoutAmountCreditedTotal.WithLabelValues("RXM", "TESTNET")); got <= 0 {
		t.Fatalf("PayoutAmountCreditedTotal = %v, want > 0", got)
	}

	// A failing cycle (unsupported pool_type) must be counted as an
	// error, not a success, and must not add to amount credited.
	if _, err := c.RunForMaturedBlock(context.Background(), "RXM", "TESTNET", "PROP", 5, 100, &reward); err == nil {
		t.Fatal("expected an error for pool_type PROP")
	}
	if got := testutil.ToFloat64(m.PayoutCyclesTotal.WithLabelValues("RXM", "PROP", metrics.PayoutResultError)); got != 1 {
		t.Fatalf("PayoutCyclesTotal error = %v, want 1", got)
	}
}

func TestCalculatePPS_SplitsByShareWeightAndFee(t *testing.T) {
	cfg := testConfig()
	repo := &fakeRepo{sharesByKey: map[string][]ShareRow{
		key("RXM", "PPS", 100): {
			{Shares: 600, PaymentAddress: "alice"},
			{Shares: 400, PaymentAddress: "bob"},
		},
	}}
	c := New(repo, cfg)

	data, err := c.CalculatePPS(context.Background(), "RXM", 100, 1000, 100000)
	if err != nil {
		t.Fatalf("CalculatePPS: %v", err)
	}

	// alice: floor(600/1000*100000) = 60000; fee = floor(60000*0.02)=1200; net = 58800
	if got := data["alice"].Amount; got != 58800 {
		t.Fatalf("alice amount = %v, want 58800", got)
	}
	// bob: floor(400/1000*100000) = 40000; fee = floor(40000*0.02)=800; net = 39200
	if got := data["bob"].Amount; got != 39200 {
		t.Fatalf("bob amount = %v, want 39200", got)
	}
	// total fees = 1200+800 = 2000; devDonation (unfloored) = 2000*0.10=200 each op;
	// coindev gets 10% of each op's feesToPay individually: 1200*0.10=120, 800*0.10=80 -> 200
	if got := data["coindev-addr"].Amount; got != 200 {
		t.Fatalf("coindev amount = %v, want 200", got)
	}
	// pooldev: 1200*0.05=60, 800*0.05=40 -> 100
	if got := data["pooldev-addr"].Amount; got != 100 {
		t.Fatalf("pooldev amount = %v, want 100", got)
	}
	// feeAddress: (1200-120-60) + (800-80-40) = 1020+680 = 1700
	if got := data["fee-addr"].Amount; got != 1700 {
		t.Fatalf("fee-addr amount = %v, want 1700", got)
	}
}

func TestCalculatePPS_PaymentIDSplitsIdentity(t *testing.T) {
	cfg := testConfig()
	longID := "0123456789abcdef" // len > 10
	shortID := "abc"             // len <= 10, ignored per legacy rule
	repo := &fakeRepo{sharesByKey: map[string][]ShareRow{
		key("RXM", "PPS", 1): {
			{Shares: 100, PaymentAddress: "alice", PaymentID: &longID},
			{Shares: 100, PaymentAddress: "alice", PaymentID: &shortID},
		},
	}}
	c := New(repo, cfg)
	data, err := c.CalculatePPS(context.Background(), "RXM", 1, 1000, 1000)
	if err != nil {
		t.Fatalf("CalculatePPS: %v", err)
	}
	if _, ok := data["alice.0123456789abcdef"]; !ok {
		t.Fatalf("expected a distinct entry keyed by alice.<paymentID> for the long payment id, got keys: %v", keysOf(data))
	}
	if _, ok := data["alice"]; !ok {
		t.Fatalf("expected the short-payment-id share to fold into the bare address key, got keys: %v", keysOf(data))
	}
}

func keysOf(m map[string]*Payment) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCalculatePPLNS_CapsAtBlockRewardAndFloorsDonations(t *testing.T) {
	cfg := testConfig()
	repo := &fakeRepo{sharesByKey: map[string][]ShareRow{
		// height 100: huge share count that alone would exceed the
		// block reward once scaled — exercises the totalPaid cap.
		key("RXT", "PPLNS", 100): {
			{Shares: 5000, PaymentAddress: "alice"},
		},
		key("RXT", "PPLNS", 99): {
			{Shares: 5000, PaymentAddress: "bob"},
		},
	}}
	c := New(repo, cfg)

	// blockDifficulty=1000, shareMulti=2 => denominator 2000.
	// alice: floor(5000/2000*100000) = floor(250000) = 250000 > reward(100000) => capped to 100000.
	data, err := c.CalculatePPLNS(context.Background(), "RXT", 100, 1000, 100000)
	if err != nil {
		t.Fatalf("CalculatePPLNS: %v", err)
	}
	// totalPaid reaches reward after alice's row, so bob (height 99) is never even reached
	// because the loop breaks after height 100 once totalPaid>=rewardTotal.
	if _, ok := data["bob"]; ok {
		t.Fatalf("expected bob to receive nothing (loop should stop once reward is exhausted at height 100), got %+v", data["bob"])
	}
	// amountToPay capped to 100000; fee = floor(100000*0.01) = 1000; net = 99000
	if got := data["alice"].Amount; got != 99000 {
		t.Fatalf("alice amount = %v, want 99000", got)
	}
	// donation split is floored for PPLNS: dev = floor(1000*0.10) = 100, pooldev = floor(1000*0.05) = 50
	if got := data["coindev-addr"].Amount; got != 100 {
		t.Fatalf("coindev amount = %v, want 100", got)
	}
	if got := data["pooldev-addr"].Amount; got != 50 {
		t.Fatalf("pooldev amount = %v, want 50", got)
	}
	if got := data["fee-addr"].Amount; got != 850 {
		t.Fatalf("fee-addr amount = %v, want 850 (1000-100-50)", got)
	}
}

func TestCalculatePPLNS_WalksBackMultipleHeightsUntilRewardMet(t *testing.T) {
	cfg := testConfig()
	cfg.PPLNSFeePercent = 0
	cfg.DevDonationPercent = 0
	cfg.PoolDevDonationPercent = 0
	repo := &fakeRepo{sharesByKey: map[string][]ShareRow{
		// blockDifficulty=1000, shareMulti=1 => denominator 1000.
		// Each height contributes floor(500/1000*1000) = 500 toward a 1200 reward,
		// so 3 heights (100, 99, 98) are needed: 500+500+500=1500 -> capped to 1200 on the 3rd.
		key("RXT", "PPLNS", 100): {{Shares: 500, PaymentAddress: "alice"}},
		key("RXT", "PPLNS", 99):  {{Shares: 500, PaymentAddress: "alice"}},
		key("RXT", "PPLNS", 98):  {{Shares: 500, PaymentAddress: "alice"}},
		key("RXT", "PPLNS", 97):  {{Shares: 500, PaymentAddress: "alice"}}, // must never be reached
	}}
	cfg.PPLNSShareMulti = 1
	c := New(repo, cfg)

	data, err := c.CalculatePPLNS(context.Background(), "RXT", 100, 1000, 1200)
	if err != nil {
		t.Fatalf("CalculatePPLNS: %v", err)
	}
	if got := data["alice"].Amount; got != 1200 {
		t.Fatalf("alice amount = %v, want 1200 (500+500+200 capped)", got)
	}
}

func TestCalculatePPLNS_StopsAtHeightOneNeverQueriesZero(t *testing.T) {
	cfg := testConfig()
	cfg.PPLNSFeePercent = 0
	cfg.DevDonationPercent = 0
	cfg.PoolDevDonationPercent = 0
	cfg.PPLNSShareMulti = 1
	// Reward far larger than any amount of shares can cover across
	// heights 2..1, and a poison entry at height 0 that would blow up
	// the test (via a huge payout) if ever queried.
	repo := &fakeRepo{sharesByKey: map[string][]ShareRow{
		key("RXT", "PPLNS", 2): {{Shares: 10, PaymentAddress: "alice"}},
		key("RXT", "PPLNS", 1): {{Shares: 10, PaymentAddress: "alice"}},
		key("RXT", "PPLNS", 0): {{Shares: 999999, PaymentAddress: "poison"}},
	}}
	c := New(repo, cfg)

	data, err := c.CalculatePPLNS(context.Background(), "RXT", 2, 1000, 1_000_000)
	if err != nil {
		t.Fatalf("CalculatePPLNS: %v", err)
	}
	if _, ok := data["poison"]; ok {
		t.Fatalf("height 0 must never be queried by PPLNS (legacy doWhilst terminates before it), got poison entry: %+v", data["poison"])
	}
}

func TestCalculateSolo_PaysFullRewardMinusFeeToFinder(t *testing.T) {
	cfg := testConfig()
	repo := &fakeRepo{soloByKey: map[string]ShareRow{
		key("RXM", "SOLO", 100): {Shares: 1, PaymentAddress: "alice"},
	}}
	c := New(repo, cfg)

	data, err := c.CalculateSolo(context.Background(), "RXM", 100, 100000)
	if err != nil {
		t.Fatalf("CalculateSolo: %v", err)
	}
	// fee = floor(100000*0.005) = 500; reward after fee = 99500 (assigned, not accumulated)
	if got := data["alice"].Amount; got != 99500 {
		t.Fatalf("alice amount = %v, want 99500", got)
	}
	// donations are unfloored for solo: dev=500*0.10=50, pooldev=500*0.05=25
	if got := data["coindev-addr"].Amount; got != 50 {
		t.Fatalf("coindev amount = %v, want 50", got)
	}
	if got := data["pooldev-addr"].Amount; got != 25 {
		t.Fatalf("pooldev amount = %v, want 25", got)
	}
	// fee-addr is assigned (not accumulated): 500-50-25=425
	if got := data["fee-addr"].Amount; got != 425 {
		t.Fatalf("fee-addr amount = %v, want 425", got)
	}
}

func TestCalculateSolo_NoFinderYet_ReturnsSeedOnly(t *testing.T) {
	cfg := testConfig()
	repo := &fakeRepo{}
	c := New(repo, cfg)

	data, err := c.CalculateSolo(context.Background(), "RXM", 100, 100000)
	if err != nil {
		t.Fatalf("CalculateSolo: %v", err)
	}
	if len(data) != 3 {
		t.Fatalf("expected only the 3 seed entries (fee/coindev/pooldev) when no finder row exists, got %d: %v", len(data), keysOf(data))
	}
	for _, addr := range []string{"fee-addr", "coindev-addr", "pooldev-addr"} {
		if data[addr].Amount != 0 {
			t.Fatalf("seed entry %s should be untouched (amount 0), got %v", addr, data[addr].Amount)
		}
	}
}

func TestApply_CreditsEveryEntryIncludingZero(t *testing.T) {
	cfg := testConfig()
	repo := &fakeRepo{}
	c := New(repo, cfg)

	data := map[string]*Payment{
		"alice":    {PaymentAddress: "alice", Amount: 123.6}, // rounds to 124
		"fee-addr": {PaymentAddress: "fee-addr", Amount: 0},  // must still be credited (0)
	}
	result, err := c.Apply(context.Background(), "RXM", "MAINNET", data)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Credited != 2 {
		t.Fatalf("Credited = %d, want 2 (every entry, including zero-amount ones)", result.Credited)
	}
	if result.TotalPaid != 124 {
		t.Fatalf("TotalPaid = %d, want 124", result.TotalPaid)
	}
	if len(repo.credits) != 2 {
		t.Fatalf("expected 2 CreditBalance calls, got %d", len(repo.credits))
	}
}

func TestApply_PropagatesRepositoryError(t *testing.T) {
	cfg := testConfig()
	wantErr := errors.New("boom")
	repo := &fakeRepo{creditErr: wantErr}
	c := New(repo, cfg)

	_, err := c.Apply(context.Background(), "RXM", "MAINNET", map[string]*Payment{
		"alice": {PaymentAddress: "alice", Amount: 1},
	})
	if err == nil {
		t.Fatal("Apply: expected an error to propagate from CreditBalance, got nil")
	}
}

func TestCalculatePPS_ZeroBlockDifficultyIsRejected(t *testing.T) {
	c := New(&fakeRepo{}, testConfig())
	if _, err := c.CalculatePPS(context.Background(), "RXM", 1, 0, 1000); err == nil {
		t.Fatal("CalculatePPS: expected an error for blockDifficulty=0 (would divide by zero)")
	}
}

func TestCalculatePPLNS_ZeroShareMultiIsRejected(t *testing.T) {
	cfg := testConfig()
	cfg.PPLNSShareMulti = 0
	c := New(&fakeRepo{}, cfg)
	if _, err := c.CalculatePPLNS(context.Background(), "RXM", 1, 1000, 1000); err == nil {
		t.Fatal("CalculatePPLNS: expected an error for PPLNSShareMulti=0 (would divide by zero)")
	}
}
