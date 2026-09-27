package payout

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeRepo is an in-memory Repository test double, mirroring
// internal/backend/unlocker's fakeRepo style.
//
// ApplyBlockPayout below models the REAL db.Repository.ApplyBlockPayout
// contract rather than just recording calls: it keeps a per-block
// claim status and an itemised per-(block, payee) credit ledger, so
// these unit tests exercise the same APPLIED-is-a-no-op /
// PENDING-is-refused / all-or-nothing semantics the Postgres
// implementation enforces. The real thing is covered end to end
// against a live database in
// internal/backend/db/blockpayout_integration_test.go.
type fakeRepo struct {
	// sharesByKey is keyed by "algo/poolType/height".
	sharesByKey map[string][]ShareRow
	soloByKey   map[string]ShareRow

	// runs records every ApplyBlockPayout call, in order, including
	// ones that were refused or no-op'd.
	runs []BlockPayoutRun
	// applyErr, when non-nil, makes ApplyBlockPayout fail outright
	// (the whole run credits nothing, mirroring the real
	// single-transaction rollback).
	applyErr error

	// claims maps block id -> status ("PENDING"/"APPLIED"), and
	// ledger maps block id -> payee key -> credited amount. Together
	// they are this double's stand-in for the `block_payouts` /
	// `block_payout_credits` tables.
	claims  map[int64]string
	ledger  map[int64]map[string]int64
	applied map[int64]BlockPayoutOutcome
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

// errFakePending mirrors db.ErrBlockPayoutPending's role for this
// double (the payout package deliberately does not import
// internal/backend/db, so it cannot use the real sentinel).
var errFakePending = errors.New("fake: block payout is PENDING and requires manual resolution")

func (f *fakeRepo) ApplyBlockPayout(_ context.Context, run BlockPayoutRun) (BlockPayoutOutcome, error) {
	f.runs = append(f.runs, run)
	if f.applyErr != nil {
		return BlockPayoutOutcome{}, f.applyErr
	}
	if f.claims == nil {
		f.claims = map[int64]string{}
		f.ledger = map[int64]map[string]int64{}
		f.applied = map[int64]BlockPayoutOutcome{}
	}
	switch f.claims[run.BlockID] {
	case "APPLIED":
		out := f.applied[run.BlockID]
		out.AlreadyApplied = true
		return out, nil
	case "PENDING":
		return BlockPayoutOutcome{}, errFakePending
	}

	if f.ledger[run.BlockID] == nil {
		f.ledger[run.BlockID] = map[string]int64{}
	}
	var out BlockPayoutOutcome
	for _, c := range run.Credits {
		k := c.PaymentAddress + "|" + derefPaymentID(c.PaymentID)
		if _, already := f.ledger[run.BlockID][k]; already {
			continue
		}
		f.ledger[run.BlockID][k] = c.Amount
		out.TotalPaid += c.Amount
		out.Credited++
	}
	f.claims[run.BlockID] = "APPLIED"
	f.applied[run.BlockID] = out
	return out, nil
}

// creditedAddresses returns every payment address this double has
// credited for blockID, for assertions that used to inspect a
// per-CreditBalance call log.
func (f *fakeRepo) creditedAddresses(blockID int64) []string {
	out := make([]string, 0, len(f.ledger[blockID]))
	for k := range f.ledger[blockID] {
		out = append(out, strings.SplitN(k, "|", 2)[0])
	}
	return out
}

func (f *fakeRepo) creditedAddress(blockID int64, address string) bool {
	for _, a := range f.creditedAddresses(blockID) {
		if a == address {
			return true
		}
	}
	return false
}

// testMaturedBlock is the MaturedBlock shape most tests below use --
// only ID actually matters to the idempotency ledger, the rest is
// just the run's recorded context.
func testMaturedBlock(id int64, algo, network, poolType string, height, reward int64) MaturedBlock {
	return MaturedBlock{ID: id, Algo: algo, Network: network, PoolType: poolType, Height: height, Reward: reward}
}

func testConfig() Config {
	return Config{
		TariFeeAddress:        "tari-fee-addr",
		TariDonationAddress:   "tari-donation-addr",
		MoneroFeeAddress:      "monero-fee-addr",
		MoneroDonationAddress: "monero-donation-addr",
		PPSFeePercent:         2,
		PPLNSFeePercent:       1,
		SoloFeePercent:        0.5,
		DonationPercent:       15,
		PPLNSShareMulti:       2,
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

	result, err := c.RunForMaturedBlock(context.Background(), 11, "RXM", "TESTNET", "PPS", 100, 1000, &reward)
	if err != nil {
		t.Fatalf("RunForMaturedBlock(PPS): %v", err)
	}
	if result.Credited == 0 || result.TotalPaid == 0 {
		t.Fatalf("RunForMaturedBlock(PPS): got %+v, want a non-trivial credited result", result)
	}
	if result.AlreadyApplied {
		t.Fatalf("RunForMaturedBlock(PPS): got AlreadyApplied=true on a block's first run, want false")
	}
	if !repo.creditedAddress(11, "alice") {
		t.Fatalf("RunForMaturedBlock(PPS): expected alice to be credited, got %v", repo.creditedAddresses(11))
	}

	if _, err := c.RunForMaturedBlock(context.Background(), 12, "RXM", "TESTNET", "SOLO", 100, 1000, &reward); err != nil {
		t.Fatalf("RunForMaturedBlock(SOLO): %v", err)
	}
	if !repo.creditedAddress(12, "solo-winner") {
		t.Fatalf("RunForMaturedBlock(SOLO): expected solo-winner to be credited, got %v", repo.creditedAddresses(12))
	}
}

// TestRunForMaturedBlock_SecondRunForSameBlockIsANoOp is the unit-level
// regression test for finding #5's core money bug: re-running a
// matured block's payout (which the unlocker now does automatically on
// retry, and which `backend block relock` has always been able to
// trigger) must credit NOBODY a second time.
//
// The equivalent test against a real Postgres instance, asserting
// actual `balance` rows are unchanged, is
// TestIntegrationApplyBlockPayoutIsIdempotent in
// internal/backend/db.
func TestRunForMaturedBlock_SecondRunForSameBlockIsANoOp(t *testing.T) {
	reward := int64(100000)
	repo := &fakeRepo{sharesByKey: map[string][]ShareRow{
		key("RXM", "PPS", 100): {{Shares: 1000, PaymentAddress: "alice"}},
	}}
	c := New(repo, testConfig())

	first, err := c.RunForMaturedBlock(context.Background(), 42, "RXM", "TESTNET", "PPS", 100, 1000, &reward)
	if err != nil {
		t.Fatalf("RunForMaturedBlock (first): %v", err)
	}
	if first.AlreadyApplied || first.TotalPaid == 0 {
		t.Fatalf("RunForMaturedBlock (first): got %+v, want a real credited run", first)
	}

	second, err := c.RunForMaturedBlock(context.Background(), 42, "RXM", "TESTNET", "PPS", 100, 1000, &reward)
	if err != nil {
		t.Fatalf("RunForMaturedBlock (second): got an error, want a clean no-op: %v", err)
	}
	if !second.AlreadyApplied {
		t.Fatal("RunForMaturedBlock (second): got AlreadyApplied=false, want true — a second run for the same block must not credit anything")
	}
	// The ledger must still hold exactly the first run's credits, at
	// exactly the first run's amounts.
	if got := len(repo.ledger[42]); got != first.Credited {
		t.Fatalf("credit ledger for block 42 has %d entries after two runs, want %d (the first run's)", got, first.Credited)
	}
	var total int64
	for _, amount := range repo.ledger[42] {
		total += amount
	}
	if total != first.TotalPaid {
		t.Fatalf("credit ledger for block 42 totals %d after two runs, want %d (unchanged)", total, first.TotalPaid)
	}
}

// TestRunForMaturedBlock_PendingClaimIsRefusedNotRetried confirms a
// block left in a claimed-but-unresolved PENDING state is surfaced as
// an error rather than silently re-credited. Blindly re-running such
// a block IS the double-credit bug (an unknown subset of its miners
// may already hold the credit), so this must fail loud and reach a
// human — see db.ErrBlockPayoutPending and
// cmd/backend/blockpayoutcli.go.
func TestRunForMaturedBlock_PendingClaimIsRefusedNotRetried(t *testing.T) {
	reward := int64(100000)
	repo := &fakeRepo{
		sharesByKey: map[string][]ShareRow{
			key("RXM", "PPS", 100): {{Shares: 1000, PaymentAddress: "alice"}},
		},
		claims:  map[int64]string{7: "PENDING"},
		ledger:  map[int64]map[string]int64{},
		applied: map[int64]BlockPayoutOutcome{},
	}
	c := New(repo, testConfig())

	result, err := c.RunForMaturedBlock(context.Background(), 7, "RXM", "TESTNET", "PPS", 100, 1000, &reward)
	if !errors.Is(err, errFakePending) {
		t.Fatalf("RunForMaturedBlock: got err=%v result=%+v, want the PENDING refusal to propagate", err, result)
	}
	if len(repo.ledger[7]) != 0 {
		t.Fatalf("a refused PENDING block must credit nothing, got ledger %+v", repo.ledger[7])
	}
}

// TestRunForMaturedBlock_NilRewardIsAnError confirms a block whose
// blocks.value column hasn't been populated yet is refused rather
// than silently treated as a zero-reward payout cycle.
func TestRunForMaturedBlock_NilRewardIsAnError(t *testing.T) {
	c := New(&fakeRepo{}, testConfig())
	if _, err := c.RunForMaturedBlock(context.Background(), 1, "RXM", "TESTNET", "PPS", 100, 1000, nil); err == nil {
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
	if _, err := c.RunForMaturedBlock(context.Background(), 1, "RXM", "TESTNET", "PROP", 100, 1000, &reward); err == nil {
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

	if _, err := c.RunForMaturedBlock(context.Background(), 5, "RXM", "TESTNET", "PPS", 5, 100, &reward); err != nil {
		t.Fatalf("RunForMaturedBlock: %v", err)
	}

	if got := testutil.ToFloat64(m.PayoutCyclesTotal.WithLabelValues("RXM", "PPS", metrics.PayoutResultSuccess)); got != 1 {
		t.Fatalf("PayoutCyclesTotal success = %v, want 1", got)
	}
	credited := testutil.ToFloat64(m.PayoutAmountCreditedTotal.WithLabelValues("RXM", "TESTNET"))
	if credited <= 0 {
		t.Fatalf("PayoutAmountCreditedTotal = %v, want > 0", credited)
	}

	// A re-run of the SAME block credits nothing, so it must be
	// counted as already_applied (not success) and must NOT add to
	// payout_amount_credited_total again — otherwise every unlocker
	// retry would inflate the pool's credited total.
	if _, err := c.RunForMaturedBlock(context.Background(), 5, "RXM", "TESTNET", "PPS", 5, 100, &reward); err != nil {
		t.Fatalf("RunForMaturedBlock (re-run): %v", err)
	}
	if got := testutil.ToFloat64(m.PayoutCyclesTotal.WithLabelValues("RXM", "PPS", metrics.PayoutResultAlreadyApplied)); got != 1 {
		t.Fatalf("PayoutCyclesTotal already_applied = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.PayoutCyclesTotal.WithLabelValues("RXM", "PPS", metrics.PayoutResultSuccess)); got != 1 {
		t.Fatalf("PayoutCyclesTotal success = %v after a no-op re-run, want it still 1", got)
	}
	if got := testutil.ToFloat64(m.PayoutAmountCreditedTotal.WithLabelValues("RXM", "TESTNET")); got != credited {
		t.Fatalf("PayoutAmountCreditedTotal = %v after a no-op re-run, want it unchanged at %v", got, credited)
	}

	// A failing cycle (unsupported pool_type) must be counted as an
	// error, not a success, and must not add to amount credited.
	if _, err := c.RunForMaturedBlock(context.Background(), 6, "RXM", "TESTNET", "PROP", 5, 100, &reward); err == nil {
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
	// total fees = 1200+800 = 2000; donation (unfloored) is 15% of each
	// op's feesToPay individually: 1200*0.15=180, 800*0.15=120 -> 300
	if got := data["monero-donation-addr"].Amount; got != 300 {
		t.Fatalf("donation amount = %v, want 300", got)
	}
	// feeAddress: (1200-180) + (800-120) = 1020+680 = 1700
	if got := data["monero-fee-addr"].Amount; got != 1700 {
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
	// donation split is floored for PPLNS: 15% of 1000 = 150
	if got := data["tari-donation-addr"].Amount; got != 150 {
		t.Fatalf("donation amount = %v, want 150", got)
	}
	if got := data["tari-fee-addr"].Amount; got != 850 {
		t.Fatalf("fee-addr amount = %v, want 850 (1000-150)", got)
	}
}

func TestCalculatePPLNS_WalksBackMultipleHeightsUntilRewardMet(t *testing.T) {
	cfg := testConfig()
	cfg.PPLNSFeePercent = 0
	cfg.DonationPercent = 0
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
	cfg.DonationPercent = 0
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
	// donation is unfloored for solo: 500*0.15=75
	if got := data["monero-donation-addr"].Amount; got != 75 {
		t.Fatalf("donation amount = %v, want 75", got)
	}
	// fee-addr is assigned (not accumulated): 500-75=425
	if got := data["monero-fee-addr"].Amount; got != 425 {
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
	if len(data) != 2 {
		t.Fatalf("expected only the 2 seed entries (fee/donation) when no finder row exists, got %d: %v", len(data), keysOf(data))
	}
	for _, addr := range []string{"monero-fee-addr", "monero-donation-addr"} {
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
	result, err := c.Apply(context.Background(), testMaturedBlock(3, "RXM", "MAINNET", "PPS", 100, 1000), data)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Credited != 2 {
		t.Fatalf("Credited = %d, want 2 (every entry, including zero-amount ones)", result.Credited)
	}
	if result.TotalPaid != 124 {
		t.Fatalf("TotalPaid = %d, want 124", result.TotalPaid)
	}
	if len(repo.ledger[3]) != 2 {
		t.Fatalf("expected 2 itemised credits, got %d", len(repo.ledger[3]))
	}
}

// TestApply_SendsOneRunCarryingTheBlockIdentityAndSortedCredits pins
// the two properties Apply's contract with the repository depends on:
// the run is handed over as ONE call (never a credit-per-payee loop —
// that shape was the money bug, see Apply's doc comment), and its
// credits are in a deterministic global order so concurrent
// transactions take their balance row locks consistently.
func TestApply_SendsOneRunCarryingTheBlockIdentityAndSortedCredits(t *testing.T) {
	repo := &fakeRepo{}
	c := New(repo, testConfig())

	data := map[string]*Payment{
		"charlie": {PoolType: "pps", PaymentAddress: "charlie", Amount: 3},
		"alice":   {PoolType: "pps", PaymentAddress: "alice", Amount: 1},
		"bob":     {PoolType: "fees", PaymentAddress: "bob", Amount: 2},
	}
	if _, err := c.Apply(context.Background(), testMaturedBlock(9, "RXT", "TESTNET", "PPLNS", 777, 55555), data); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(repo.runs) != 1 {
		t.Fatalf("Apply made %d ApplyBlockPayout call(s), want exactly 1 (the whole run must be one atomic unit)", len(repo.runs))
	}
	run := repo.runs[0]
	if run.BlockID != 9 || run.Algo != "RXT" || run.Network != "TESTNET" || run.PoolType != "PPLNS" || run.Height != 777 || run.Reward != 55555 {
		t.Fatalf("Apply sent run %+v, want the MaturedBlock identity carried through verbatim", run)
	}
	var gotOrder []string
	for _, cr := range run.Credits {
		gotOrder = append(gotOrder, cr.PaymentAddress)
	}
	want := []string{"alice", "bob", "charlie"}
	if strings.Join(gotOrder, ",") != strings.Join(want, ",") {
		t.Fatalf("Apply sent credits in order %v, want them sorted %v (deterministic lock ordering)", gotOrder, want)
	}
	// The payout-calculation bucket tag must survive into the ledger
	// record — it is what tells an operator which calculation paid a
	// given miner during an incident.
	for _, cr := range run.Credits {
		if cr.PaymentAddress == "bob" && cr.PayoutBucket != "fees" {
			t.Fatalf("Apply sent PayoutBucket=%q for bob, want the Payment.PoolType tag \"fees\"", cr.PayoutBucket)
		}
	}
}

func TestApply_PropagatesRepositoryError(t *testing.T) {
	cfg := testConfig()
	wantErr := errors.New("boom")
	repo := &fakeRepo{applyErr: wantErr}
	c := New(repo, cfg)

	_, err := c.Apply(context.Background(), testMaturedBlock(4, "RXM", "MAINNET", "PPS", 100, 1000), map[string]*Payment{
		"alice": {PaymentAddress: "alice", Amount: 1},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Apply: got err=%v, want the repository error to propagate", err)
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

// TestAddressesForAlgo_ExtraCoinAddressesResolve confirms the new
// standalone monerod-family coin algos (ALGO_XMR and below) resolve
// via cfg.ExtraFeeAddresses/ExtraDonationAddresses -- each one is its
// own independent coin family, distinct from RXM's Monero address.
func TestAddressesForAlgo_ExtraCoinAddressesResolve(t *testing.T) {
	cfg := testConfig()
	cfg.ExtraFeeAddresses = map[string]string{"ARQ": "arq-fee-addr", "XEQ": "xeq-fee-addr"}
	cfg.ExtraDonationAddresses = map[string]string{"ARQ": "arq-donation-addr", "XEQ": "xeq-donation-addr"}

	fee, donation, err := addressesForAlgo(cfg, "ARQ")
	if err != nil {
		t.Fatalf("addressesForAlgo(ARQ): unexpected error: %v", err)
	}
	if fee != "arq-fee-addr" || donation != "arq-donation-addr" {
		t.Errorf("addressesForAlgo(ARQ) = (%q, %q), want (arq-fee-addr, arq-donation-addr)", fee, donation)
	}

	fee, donation, err = addressesForAlgo(cfg, "XEQ")
	if err != nil {
		t.Fatalf("addressesForAlgo(XEQ): unexpected error: %v", err)
	}
	if fee != "xeq-fee-addr" || donation != "xeq-donation-addr" {
		t.Errorf("addressesForAlgo(XEQ) = (%q, %q), want (xeq-fee-addr, xeq-donation-addr)", fee, donation)
	}

	// A registered-coin algo with NO entry in either map is still
	// refused -- ExtraFeeAddresses/ExtraDonationAddresses must be
	// explicitly configured per coin, never silently defaulted.
	if _, _, err := addressesForAlgo(cfg, "GRFT"); err == nil {
		t.Fatal("addressesForAlgo(GRFT): expected an error (no ExtraFeeAddresses/ExtraDonationAddresses entry), got nil")
	}

	// RXM's own Monero address must NOT leak into any of the new
	// coins, and vice versa.
	rxmFee, _, err := addressesForAlgo(cfg, "RXM")
	if err != nil {
		t.Fatalf("addressesForAlgo(RXM): unexpected error: %v", err)
	}
	if rxmFee == "arq-fee-addr" || rxmFee == "xeq-fee-addr" {
		t.Error("addressesForAlgo(RXM) leaked a new coin's fee address")
	}
}

// TestAddressesForAlgo_UnknownAlgoIsAnError confirms an unmapped algo
// string fails loudly rather than silently defaulting to either coin
// family's addresses -- the whole point of addressesForAlgo existing
// as a single, explicit lookup point.
func TestAddressesForAlgo_UnknownAlgoIsAnError(t *testing.T) {
	cfg := testConfig()
	if _, _, err := addressesForAlgo(cfg, "DOGE"); err == nil {
		t.Fatal("addressesForAlgo: expected an error for an unmapped algo, got nil")
	}
	// Every real algo literal used elsewhere in this codebase
	// (internal/backend/db.ValidAlgos) must resolve cleanly -- for
	// RXT/C29/SHA3X/RXM via the Tari/Monero switch cases, and for
	// every other registered coin via cfg.ExtraFeeAddresses (set
	// below so this loop can cover them too).
	cfg.ExtraFeeAddresses = map[string]string{
		"XMR": "xmr-fee", "ARQ": "arq-fee", "XEQ": "xeq-fee",
		"GRFT": "grft-fee", "SFX": "sfx-fee", "ZEPH": "zeph-fee", "SAL": "sal-fee",
	}
	cfg.ExtraDonationAddresses = map[string]string{
		"XMR": "xmr-don", "ARQ": "arq-don", "XEQ": "xeq-don",
		"GRFT": "grft-don", "SFX": "sfx-don", "ZEPH": "zeph-don", "SAL": "sal-don",
	}
	for _, algo := range []string{
		"RXT", "C29", "SHA3X", "RXM",
		"XMR", "ARQ", "XEQ", "GRFT", "SFX", "ZEPH", "SAL",
	} {
		if _, _, err := addressesForAlgo(cfg, algo); err != nil {
			t.Fatalf("addressesForAlgo(%q): unexpected error: %v", algo, err)
		}
	}
}

// TestCalculatePPS_UnknownAlgoPropagatesError confirms the error from
// addressesForAlgo actually surfaces through the public
// Calculate{PPS,PPLNS,Solo} entry points rather than being swallowed.
func TestCalculatePPS_UnknownAlgoPropagatesError(t *testing.T) {
	cfg := testConfig()
	c := New(&fakeRepo{}, cfg)
	if _, err := c.CalculatePPS(context.Background(), "DOGE", 1, 1000, 1000); err == nil {
		t.Fatal("CalculatePPS: expected an error for an unmapped algo, got nil")
	}
}

func TestCalculatePPLNS_UnknownAlgoPropagatesError(t *testing.T) {
	cfg := testConfig()
	c := New(&fakeRepo{}, cfg)
	if _, err := c.CalculatePPLNS(context.Background(), "DOGE", 1, 1000, 1000); err == nil {
		t.Fatal("CalculatePPLNS: expected an error for an unmapped algo, got nil")
	}
}

func TestCalculateSolo_UnknownAlgoPropagatesError(t *testing.T) {
	cfg := testConfig()
	c := New(&fakeRepo{}, cfg)
	if _, err := c.CalculateSolo(context.Background(), "DOGE", 1, 1000); err == nil {
		t.Fatal("CalculateSolo: expected an error for an unmapped algo, got nil")
	}
}

// TestPayout_NeverCreditsTheOtherCoinFamilysAddress is the core
// regression test for the multi-coin fee-routing bug: one backend
// process runs Tari-family (RXT/C29/SHA3X) and Monero (RXM) payout
// cycles side by side against a SHARED Config, and a Tari cycle must
// never touch cfg.Monero*Address (or vice versa) -- both for the fee
// address and the donation address, across all three calculation
// modes.
func TestPayout_NeverCreditsTheOtherCoinFamilysAddress(t *testing.T) {
	cfg := testConfig()
	repo := &fakeRepo{
		sharesByKey: map[string][]ShareRow{
			key("RXT", "PPS", 100):   {{Shares: 500, PaymentAddress: "tari-miner"}},
			key("RXM", "PPS", 100):   {{Shares: 500, PaymentAddress: "monero-miner"}},
			key("RXT", "PPLNS", 100): {{Shares: 500, PaymentAddress: "tari-miner"}},
			key("RXM", "PPLNS", 100): {{Shares: 500, PaymentAddress: "monero-miner"}},
		},
		soloByKey: map[string]ShareRow{
			key("RXT", "SOLO", 100): {Shares: 1, PaymentAddress: "tari-finder"},
			key("RXM", "SOLO", 100): {Shares: 1, PaymentAddress: "monero-finder"},
		},
	}
	c := New(repo, cfg)

	assertOnlyTariAddresses := func(t *testing.T, data map[string]*Payment) {
		t.Helper()
		if _, ok := data[cfg.MoneroFeeAddress]; ok {
			t.Fatalf("a Tari-family payout cycle credited the Monero fee address %q -- funds crossed coin families", cfg.MoneroFeeAddress)
		}
		if _, ok := data[cfg.MoneroDonationAddress]; ok {
			t.Fatalf("a Tari-family payout cycle credited the Monero donation address %q -- funds crossed coin families", cfg.MoneroDonationAddress)
		}
		if _, ok := data[cfg.TariFeeAddress]; !ok {
			t.Fatalf("a Tari-family payout cycle never credited its own fee address %q", cfg.TariFeeAddress)
		}
	}
	assertOnlyMoneroAddresses := func(t *testing.T, data map[string]*Payment) {
		t.Helper()
		if _, ok := data[cfg.TariFeeAddress]; ok {
			t.Fatalf("a Monero payout cycle credited the Tari fee address %q -- funds crossed coin families", cfg.TariFeeAddress)
		}
		if _, ok := data[cfg.TariDonationAddress]; ok {
			t.Fatalf("a Monero payout cycle credited the Tari donation address %q -- funds crossed coin families", cfg.TariDonationAddress)
		}
		if _, ok := data[cfg.MoneroFeeAddress]; !ok {
			t.Fatalf("a Monero payout cycle never credited its own fee address %q", cfg.MoneroFeeAddress)
		}
	}

	for _, algo := range []string{"RXT", "C29", "SHA3X"} {
		ppsData, err := c.CalculatePPS(context.Background(), algo, 100, 1000, 100000)
		if err != nil {
			t.Fatalf("CalculatePPS(%s): %v", algo, err)
		}
		assertOnlyTariAddresses(t, ppsData)
	}
	moneroPPS, err := c.CalculatePPS(context.Background(), "RXM", 100, 1000, 100000)
	if err != nil {
		t.Fatalf("CalculatePPS(RXM): %v", err)
	}
	assertOnlyMoneroAddresses(t, moneroPPS)

	tariPPLNS, err := c.CalculatePPLNS(context.Background(), "RXT", 100, 1000, 100000)
	if err != nil {
		t.Fatalf("CalculatePPLNS(RXT): %v", err)
	}
	assertOnlyTariAddresses(t, tariPPLNS)
	moneroPPLNS, err := c.CalculatePPLNS(context.Background(), "RXM", 100, 1000, 100000)
	if err != nil {
		t.Fatalf("CalculatePPLNS(RXM): %v", err)
	}
	assertOnlyMoneroAddresses(t, moneroPPLNS)

	tariSolo, err := c.CalculateSolo(context.Background(), "RXT", 100, 100000)
	if err != nil {
		t.Fatalf("CalculateSolo(RXT): %v", err)
	}
	assertOnlyTariAddresses(t, tariSolo)
	moneroSolo, err := c.CalculateSolo(context.Background(), "RXM", 100, 100000)
	if err != nil {
		t.Fatalf("CalculateSolo(RXM): %v", err)
	}
	assertOnlyMoneroAddresses(t, moneroSolo)
}
