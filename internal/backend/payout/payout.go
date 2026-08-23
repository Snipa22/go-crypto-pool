// Package payout implements the go-crypto-pool backend's PPS/PPLNS/Solo
// payout calculations. This is a faithful, line-for-line port of
// nodejs-pool-sxmr's lib/blockManager.js — specifically
// calculatePPSPayments, calculatePPLNSPayments and
// calculateSoloPayments (and the paymentData/handleIdentifier shape all
// three share) — onto this repo's schema (internal/backend/db/
// migrations/0001_initial_schema.up.sql) and Repository-interface style
// (see internal/backend/unlocker for the established pattern this
// package mirrors: a narrow Repository interface, a Config struct for
// the operator-tunable knobs, and pure calculation functions that take
// their inputs as parameters rather than reaching into globals the way
// the legacy JS did via `global.config`/`global.coinFuncs`).
//
// What changed vs. the legacy algorithm, and why:
//
//   - Legacy blockManager.js re-derives each share row's payment
//     address/payment_id/worker via a `miner_identifiers` join inside
//     handleIdentifier (`SELECT * FROM miner_identifiers where id =
//     $1`, cached in local_miner_identifier_cache). This schema's
//     `shares` table already carries payment_address/payment_id
//     directly on every row (see the migration) — there is no separate
//     identifier table to join, so that lookup (and its cache) is
//     simply gone. The rest of handleIdentifier's math is unchanged.
//   - Legacy pool_type filtering happens in Go/JS after a single
//     `SELECT * FROM shares WHERE block_height = ?` (comparing
//     `row.pool_type === global.protos.POOLTYPE.PPLNS` etc. per row).
//     This schema list-partitions `shares` by (algo, pool_type) first
//     (see migrations), so Repository.SharesAtHeight filters via the
//     WHERE clause / partition pruning instead of a per-row branch —
//     same effective selection, cheaper.
//   - Legacy's Bitcoin-payout-conversion fee (`row.bitcoin` /
//     `global.config.payout.btcFee`) has no equivalent anywhere in this
//     codebase (no BTC concept exists in internal/proto or the schema)
//     and is intentionally NOT ported — there is nothing to convert to.
//   - Legacy amounts are plain JS numbers (float64 semantics) flowing
//     straight into a MySQL balance column. This schema's `balance`
//     table is NUMERIC(38, 0) (see migrations) — an exact integer.
//     Amount accumulation here uses float64 throughout, exactly
//     mirroring the legacy arithmetic (including its one genuine
//     inconsistency: calculatePPSPayments/calculateSoloPayments never
//     Math.floor() their dev/pool-dev donation splits, while
//     calculatePPLNSPayments does — both are reproduced exactly, warts
//     included, per instruction to port the *exact* algorithm). Only
//     Apply, at the very end, rounds each payment to the nearest
//     integer atomic unit before writing it — a spot the legacy code
//     never needed because MySQL happily stored the float as-is.
//   - Legacy calculateSoloPayments silently indexes row.pool_type on a
//     possibly-undefined `row` (result.rows[0]) if no found_block=true
//     row exists for the height yet — a latent crash bug, not a
//     feature. CalculateSolo instead returns the (fee/dev/pooldev-only)
//     seed payment data unchanged when Repository.SoloShare reports
//     no row found, which is a strict improvement, not a behavior this
//     port needed to preserve.
package payout

import (
	"context"
	"fmt"
	"math"
)

// ShareRow is one row from the `shares` table, as needed for payout
// math: the share-weight/difficulty-equivalent column (`shares`, the
// direct analog of legacy's `hashes = ~~row.hashes`) plus the payee
// identity already carried on the row (see this package's doc comment
// on why no separate identifier-table join is needed here).
type ShareRow struct {
	Shares         int64
	PaymentAddress string
	PaymentID      *string
}

// Repository is the narrow persistence surface Calculator depends on.
// *db.Repository satisfies this (see internal/backend/db) via a small
// adapter in cmd/backend, mirroring unlocker.Repository's role.
type Repository interface {
	// SharesAtHeight returns every shares row for (algo, poolType,
	// height), in the same descending-time order the legacy `SELECT *
	// FROM shares WHERE block_height = ? order by time desc` query
	// used (order does not affect the sum, but is kept for parity).
	SharesAtHeight(ctx context.Context, algo, poolType string, height int64) ([]ShareRow, error)

	// SoloShare returns the single found_block=TRUE SOLO row for
	// (algo, height) — the legacy `SELECT * FROM shares WHERE
	// block_height = ? AND found_block IS TRUE LIMIT 1` query, scoped
	// to one algo's own shares (this schema also partitions by algo,
	// which legacy's single commingled table did not). found is false
	// when no such row exists yet (see this package's doc comment on
	// why that's handled explicitly here rather than left to crash).
	SoloShare(ctx context.Context, algo string, height int64) (row ShareRow, found bool, err error)

	// CreditBalance adds amount (may be zero — see Apply) to the
	// pending balance for (algo, network, paymentAddress, paymentID),
	// creating that balance row first if it does not exist yet. This
	// is the real-schema equivalent of legacy's
	// createBalanceQueue+balanceQueue pair (account-ensure, then
	// increment) collapsed into one upsert.
	CreditBalance(ctx context.Context, algo, network, paymentAddress string, paymentID *string, amount int64) error
}

// Config holds every payout-cycle knob the legacy code read from
// global.config.payout / global.config.pplns / global.coinFuncs.
// All *FeePercent/*DonationPercent fields are percentages in the same
// 0-100 range the legacy config used (legacy always divides by 100
// itself, e.g. `global.config.payout.ppsFee / 100`).
type Config struct {
	// FeeAddress is the pool operator's fee-collection payment
	// address — global.config.payout.feeAddress.
	FeeAddress string
	// CoinDevAddress is the coin developer donation address —
	// global.coinFuncs.coinDevAddress.
	CoinDevAddress string
	// PoolDevAddress is the pool software developer donation address
	// — global.coinFuncs.poolDevAddress.
	PoolDevAddress string

	// PPSFeePercent/PPLNSFeePercent/SoloFeePercent are each pool
	// type's operator fee cut — global.config.payout.{pps,pplns,solo}Fee.
	PPSFeePercent   float64
	PPLNSFeePercent float64
	SoloFeePercent  float64

	// DevDonationPercent/PoolDevDonationPercent are the share of each
	// fee cut redirected to CoinDevAddress/PoolDevAddress —
	// global.config.payout.devDonation / poolDevDonation. Zero means
	// no donation split (the legacy `if (...DevDonation > 0)` guard,
	// reproduced exactly).
	DevDonationPercent     float64
	PoolDevDonationPercent float64

	// PPLNSShareMulti is the PPLNS window multiplier —
	// global.config.pplns.shareMulti (the "N" in PPLNS: the payout
	// window is shareMulti * block-difficulty worth of shares).
	PPLNSShareMulti float64
}

// Payment is one accumulated payout-cycle entry — the Go analog of one
// `paymentData[key]` object in the legacy code.
type Payment struct {
	// PoolType records which calculation produced this entry: "fees",
	// "pps", "pplns", or "solo" — mirrors legacy's paymentData[...].pool_type.
	PoolType       string
	PaymentAddress string
	PaymentID      *string
	// Amount is the accumulated payout in atomic units, held as
	// float64 during calculation (see this package's doc comment) and
	// rounded to an integer only by Apply.
	Amount float64
}

// paymentKey reproduces legacy's userIdentifier construction exactly:
// `row.address`, or `row.address + "." + row.payment_id` when
// payment_id is set AND longer than 10 characters (legacy's literal
// `row.payment_id.length > 10` check — a real Monero/Tari integrated-
// address-style payment ID heuristic, not a typo, so it is kept as-is).
func paymentKey(address string, paymentID *string) string {
	if paymentID != nil && len(*paymentID) > 10 {
		return address + "." + *paymentID
	}
	return address
}

// seedPaymentData builds the fee/coin-dev/pool-dev seed entries every
// legacy calculate*Payments function pre-populates paymentData with
// before touching any share row. Exactly like the legacy object
// literal, if two of cfg.FeeAddress/CoinDevAddress/PoolDevAddress are
// equal (or empty), they collapse into the same map entry — that is
// legacy's own behavior (paymentData is a plain object keyed by
// address string), reproduced here rather than treated as a bug.
func seedPaymentData(cfg Config) map[string]*Payment {
	data := make(map[string]*Payment, 3)
	seed := func(addr string) {
		if _, ok := data[addr]; !ok {
			data[addr] = &Payment{PoolType: "fees", PaymentAddress: addr}
		}
	}
	seed(cfg.FeeAddress)
	seed(cfg.CoinDevAddress)
	seed(cfg.PoolDevAddress)
	return data
}

// applyDonations reproduces the identical 6-line block that appears at
// the tail of all three legacy handleIdentifier functions: split
// feesToPay into coin-dev/pool-dev donations (each optionally floored
// per doFloorDonations — see CalculatePPLNS vs CalculatePPS/CalculateSolo's
// callers) and credit the remainder to cfg.FeeAddress.
//
// assignFee controls whether the fee-address entry is incremented
// (PPS/PPLNS: `... = ... + (feesToPay - donations)`) or overwritten
// (Solo: `... = feesToPay - donations`) — reproducing that exact
// legacy asymmetry (CalculateSolo's handleIdentifier is a single,
// one-shot handler per block, so it overwrites rather than
// accumulates).
func applyDonations(cfg Config, data map[string]*Payment, feesToPay float64, floorDonations, assignFee bool) {
	donations := 0.0
	if cfg.DevDonationPercent > 0 {
		devDonation := feesToPay * (cfg.DevDonationPercent / 100)
		if floorDonations {
			devDonation = math.Floor(devDonation)
		}
		donations += devDonation
		data[cfg.CoinDevAddress].Amount += devDonation
	}
	if cfg.PoolDevDonationPercent > 0 {
		poolDevDonation := feesToPay * (cfg.PoolDevDonationPercent / 100)
		if floorDonations {
			poolDevDonation = math.Floor(poolDevDonation)
		}
		donations += poolDevDonation
		data[cfg.PoolDevAddress].Amount += poolDevDonation
	}
	if assignFee {
		data[cfg.FeeAddress].Amount = feesToPay - donations
	} else {
		data[cfg.FeeAddress].Amount += feesToPay - donations
	}
}

// Calculator runs payout calculations against a Repository using a
// fixed Config — the payout-side analog of unlocker.Unlocker.
type Calculator struct {
	repo Repository
	cfg  Config
}

// New constructs a Calculator.
func New(repo Repository, cfg Config) *Calculator {
	return &Calculator{repo: repo, cfg: cfg}
}

// CalculatePPS ports calculatePPSPayments exactly: every PPS share row
// at this single block height is paid `hashes/blockDifficulty *
// blockReward`, independent of any other height (Pay Per Share pays
// for work done regardless of which block it landed in) — hence, no
// looping over heights the way PPLNS does.
func (c *Calculator) CalculatePPS(ctx context.Context, algo string, height, blockDifficulty, blockReward int64) (map[string]*Payment, error) {
	if blockDifficulty == 0 {
		return nil, fmt.Errorf("payout: CalculatePPS: blockDifficulty must be non-zero")
	}
	rows, err := c.repo.SharesAtHeight(ctx, algo, "PPS", height)
	if err != nil {
		return nil, fmt.Errorf("payout: CalculatePPS: %w", err)
	}

	data := seedPaymentData(c.cfg)
	rewardTotal := float64(blockReward)
	blockDiff := float64(blockDifficulty)

	for _, row := range rows {
		key := paymentKey(row.PaymentAddress, row.PaymentID)
		if _, ok := data[key]; !ok {
			data[key] = &Payment{PoolType: "pps", PaymentAddress: row.PaymentAddress, PaymentID: row.PaymentID}
		}
		hashes := float64(row.Shares)
		amountToPay := math.Floor((hashes / blockDiff) * rewardTotal)
		feesToPay := math.Floor(amountToPay * (c.cfg.PPSFeePercent / 100))
		amountToPay -= feesToPay
		data[key].Amount += amountToPay
		// Legacy calculatePPSPayments never floors its donation split
		// (unlike PPLNS below) — reproduced exactly.
		applyDonations(c.cfg, data, feesToPay, false, false)
	}
	return data, nil
}

// CalculatePPLNS ports calculatePPLNSPayments exactly: starting at
// startHeight (the block just found) and walking backwards one block
// height at a time, every PPLNS share row at each height is paid
// `hashes/(blockDifficulty*shareMulti) * blockReward`, capped so the
// running total never exceeds blockReward, until either the running
// total reaches blockReward or height 1 has been processed (height 0
// is never queried — see this package's doc comment / the legacy
// doWhilst's exact termination condition, reproduced here).
func (c *Calculator) CalculatePPLNS(ctx context.Context, algo string, startHeight, blockDifficulty, blockReward int64) (map[string]*Payment, error) {
	if blockDifficulty == 0 {
		return nil, fmt.Errorf("payout: CalculatePPLNS: blockDifficulty must be non-zero")
	}
	if c.cfg.PPLNSShareMulti == 0 {
		return nil, fmt.Errorf("payout: CalculatePPLNS: Config.PPLNSShareMulti must be non-zero")
	}

	data := seedPaymentData(c.cfg)
	rewardTotal := float64(blockReward)
	blockDiff := float64(blockDifficulty)
	totalPaid := 0.0

	for h := startHeight; h >= 1; h-- {
		rows, err := c.repo.SharesAtHeight(ctx, algo, "PPLNS", h)
		if err != nil {
			return nil, fmt.Errorf("payout: CalculatePPLNS: height %d: %w", h, err)
		}
		for _, row := range rows {
			key := paymentKey(row.PaymentAddress, row.PaymentID)
			if _, ok := data[key]; !ok {
				data[key] = &Payment{PoolType: "pplns", PaymentAddress: row.PaymentAddress, PaymentID: row.PaymentID}
			}
			hashes := float64(row.Shares)
			amountToPay := math.Floor((hashes / (blockDiff * c.cfg.PPLNSShareMulti)) * rewardTotal)
			if totalPaid+amountToPay > rewardTotal {
				amountToPay = rewardTotal - totalPaid
			}
			totalPaid += amountToPay
			feesToPay := math.Floor(amountToPay * (c.cfg.PPLNSFeePercent / 100))
			amountToPay -= feesToPay
			data[key].Amount += amountToPay
			// Legacy calculatePPLNSPayments DOES floor its donation
			// split (unlike PPS/Solo above/below) — reproduced exactly.
			applyDonations(c.cfg, data, feesToPay, true, false)
		}
		if totalPaid >= rewardTotal {
			break
		}
		// Loop condition mirrors legacy's post-decrement test exactly:
		// height 0 is never queried (the `for` header's h >= 1 already
		// encodes this, this branch just documents the parity).
	}
	return data, nil
}

// CalculateSolo ports calculateSoloPayments exactly: the single miner
// who actually found this block (the one found_block=TRUE SOLO row at
// this height) receives the entire block reward minus the solo fee —
// no share-weighting at all, since solo mining pays only the finder.
// If no such row exists yet (block not yet attributed to a share),
// this returns the seeded fee/dev/pool-dev-only payment data unchanged
// — see this package's doc comment for why that's a deliberate
// improvement over legacy's crash-on-undefined-row behavior.
func (c *Calculator) CalculateSolo(ctx context.Context, algo string, height, blockReward int64) (map[string]*Payment, error) {
	row, found, err := c.repo.SoloShare(ctx, algo, height)
	if err != nil {
		return nil, fmt.Errorf("payout: CalculateSolo: %w", err)
	}
	data := seedPaymentData(c.cfg)
	if !found {
		return data, nil
	}

	key := paymentKey(row.PaymentAddress, row.PaymentID)
	if _, ok := data[key]; !ok {
		data[key] = &Payment{PoolType: "solo", PaymentAddress: row.PaymentAddress, PaymentID: row.PaymentID}
	}

	rewardTotal := float64(blockReward)
	feesToPay := math.Floor(rewardTotal * (c.cfg.SoloFeePercent / 100))
	rewardTotal -= feesToPay
	// Legacy assigns (not accumulates) here: `paymentData[userIdentifier].amount = rewardTotal`.
	data[key].Amount = rewardTotal
	// Legacy calculateSoloPayments never floors its donation split
	// (like PPS, unlike PPLNS) — reproduced exactly. The fee-address
	// entry is also assigned, not accumulated, matching legacy.
	applyDonations(c.cfg, data, feesToPay, false, true)
	return data, nil
}

// ApplyResult summarizes one Apply call, mirroring the
// "PPS/PPLNS/Solo payout cycle complete..." log line every legacy
// calculate*Payments function prints at the end of its run.
type ApplyResult struct {
	// TotalPaid is the sum of every credited payment, in atomic units
	// (legacy's `totalPayments`).
	TotalPaid int64
	// Credited is the number of payment-data entries credited
	// (including zero-amount fee/dev/pool-dev seed entries — legacy
	// pushes every paymentData key onto balanceQueue unconditionally).
	Credited int
}

// Apply credits every entry in data via Repository.CreditBalance —
// the real-schema equivalent of legacy's
// `Object.keys(paymentData).forEach(key => balanceQueue.push(...))`
// loop that closes out every calculate*Payments function. Every entry
// is credited, even ones whose Amount rounds to zero (matching
// legacy's unconditional push, which exists specifically to guarantee
// every payee's balance row is created/touched even in a zero-payout
// cycle).
func (c *Calculator) Apply(ctx context.Context, algo, network string, data map[string]*Payment) (ApplyResult, error) {
	var result ApplyResult
	for _, p := range data {
		amount := int64(math.Round(p.Amount))
		if err := c.repo.CreditBalance(ctx, algo, network, p.PaymentAddress, p.PaymentID, amount); err != nil {
			return result, fmt.Errorf("payout: Apply: crediting %s: %w", p.PaymentAddress, err)
		}
		result.TotalPaid += amount
		result.Credited++
	}
	return result, nil
}
