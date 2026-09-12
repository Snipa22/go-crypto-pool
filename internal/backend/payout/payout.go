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
//   - Legacy pushed each payment onto a fire-and-forget
//     createBalanceQueue/balanceQueue pair — one independent
//     upsert-increment per payee, with no record anywhere that a given
//     block's payout had run. Apply here does NOT reproduce that: it
//     hands the whole run to Repository.ApplyBlockPayout, which
//     claims a per-block idempotency ledger row and applies every
//     credit in ONE database transaction. See
//     migrations/0011_block_payouts.up.sql and
//     internal/backend/db/blockpayout.go for the full writeup of why
//     — the short version is that the legacy shape's partial failures
//     left an unknown subset of miners credited, and the only
//     available retry then credited all of them a second time.
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
	"sort"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
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

	// ApplyBlockPayout durably claims one matured block's payout run
	// and applies every credit in it, in a single database
	// transaction. It is the ONLY balance-writing method this package
	// depends on, deliberately: there is no plain "credit this one
	// address" call in this interface any more, because a per-payee
	// credit that is not part of a claimed, all-or-nothing block run
	// is exactly the money-critical bug
	// migrations/0011_block_payouts.up.sql exists to close. See
	// db.Repository.ApplyBlockPayout's doc comment for the full
	// contract (claim semantics, the APPLIED no-op, the PENDING hard
	// refusal, and the row-level idempotency backstop underneath).
	ApplyBlockPayout(ctx context.Context, run BlockPayoutRun) (BlockPayoutOutcome, error)
}

// BlockCredit is one payee's credit within a single block's payout
// run, as handed to Repository.ApplyBlockPayout. Mirrors
// db.BlockCredit field-for-field.
type BlockCredit struct {
	// PayoutBucket is the originating Payment.PoolType tag: "fees",
	// "pps", "pplns" or "solo".
	PayoutBucket   string
	PaymentAddress string
	PaymentID      *string
	// Amount is the credit in atomic units — Payment.Amount rounded
	// by Apply. May legitimately be zero (see Apply's doc comment).
	Amount int64
}

// MaturedBlock identifies the one just-matured `blocks` row a payout
// run belongs to. ID is the idempotency key the whole ledger hangs
// off (see Repository.ApplyBlockPayout), which is why it is carried
// explicitly through Apply/RunForMaturedBlock rather than derived
// from (algo, height) — two different blocks can share a height
// across networks/forks, and "which row did we pay out" must never be
// a guess.
type MaturedBlock struct {
	ID       int64
	Algo     string
	Network  string
	PoolType string
	Height   int64
	Reward   int64
}

// BlockPayoutRun is one complete payout run as
// Repository.ApplyBlockPayout should record and apply it. Mirrors
// db.BlockPayoutRun field-for-field.
type BlockPayoutRun struct {
	BlockID  int64
	Algo     string
	Network  string
	PoolType string
	Height   int64
	Reward   int64
	Credits  []BlockCredit
}

// BlockPayoutOutcome summarizes one Repository.ApplyBlockPayout call.
// Mirrors db.BlockPayoutOutcome field-for-field.
type BlockPayoutOutcome struct {
	// AlreadyApplied is true when this block's payout had already
	// been applied by an earlier, committed run — this call credited
	// nothing. TotalPaid/Credited then describe that original run.
	AlreadyApplied bool
	TotalPaid      int64
	Credited       int
}

// Config holds every payout-cycle knob the legacy code read from
// global.config.payout / global.config.pplns / global.coinFuncs.
// All *FeePercent/*DonationPercent fields are percentages in the same
// 0-100 range the legacy config used (legacy always divides by 100
// itself, e.g. `global.config.payout.ppsFee / 100`).
type Config struct {
	// TariFeeAddress/MoneroFeeAddress are the pool operator's
	// fee-collection payment addresses — global.config.payout.feeAddress
	// in legacy, split per coin family because a single backend
	// process pays out both Tari-family algos (RXT/C29/SHA3X) and
	// Monero (RXM) simultaneously, and each family's payout address
	// must be a valid address on that family's own chain. See
	// addressesForAlgo for the algo -> family mapping.
	TariFeeAddress   string
	MoneroFeeAddress string
	// TariDonationAddress/MoneroDonationAddress are the (single,
	// unified) donation addresses per coin family — the coin-dev and
	// pool-dev donation roles legacy kept separate
	// (global.coinFuncs.coinDevAddress/poolDevAddress) are collapsed
	// into one address and one percentage here, per operator
	// direction: the split is the same everywhere, so there is no
	// reason to route it through two addresses.
	TariDonationAddress   string
	MoneroDonationAddress string

	// PPSFeePercent/PPLNSFeePercent/SoloFeePercent are each pool
	// type's operator fee cut — global.config.payout.{pps,pplns,solo}Fee.
	PPSFeePercent   float64
	PPLNSFeePercent float64
	SoloFeePercent  float64

	// DonationPercent is the share of each fee cut redirected to
	// TariDonationAddress/MoneroDonationAddress — replaces legacy's
	// separate devDonation/poolDevDonation percentages with a single
	// shared split. Zero means no donation split (the legacy
	// `if (...Donation > 0)` guard, reproduced exactly).
	DonationPercent float64

	// PPLNSShareMulti is the PPLNS window multiplier —
	// global.config.pplns.shareMulti (the "N" in PPLNS: the payout
	// window is shareMulti * block-difficulty worth of shares).
	PPLNSShareMulti float64

	// Metrics, if non-nil, is the metrics.Metrics instance
	// RunForMaturedBlock increments/observes (payout_cycles_total,
	// payout_amount_credited_total, payout_cycle_duration_seconds).
	// If nil, metrics are simply not recorded. See
	// unlocker.Config.Metrics's doc comment for why cmd/backend
	// wires in one shared instance across packages.
	Metrics *metrics.Metrics
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

// addressesForAlgo maps an algo literal to the correct coin family's
// fee/donation addresses. RXT/C29/SHA3X (see
// internal/backend/db.ValidAlgos) are Tari-family and resolve to
// cfg.Tari*Address; RXM is Monero and resolves to cfg.Monero*Address.
// Any other algo string is refused with an error rather than
// silently falling back to either family's addresses — a single
// backend process pays out both families simultaneously, so a wrong
// or unmapped algo here would misroute real funds, not just misfile
// a log line.
func addressesForAlgo(cfg Config, algo string) (feeAddr, donationAddr string, err error) {
	switch algo {
	case "RXT", "C29", "SHA3X":
		return cfg.TariFeeAddress, cfg.TariDonationAddress, nil
	case "RXM":
		return cfg.MoneroFeeAddress, cfg.MoneroDonationAddress, nil
	default:
		return "", "", fmt.Errorf("payout: addressesForAlgo: unrecognized algo %q -- refusing to guess a coin family (expected one of RXT, C29, SHA3X, RXM)", algo)
	}
}

// seedPaymentData builds the fee/donation seed entries every legacy
// calculate*Payments function pre-populates paymentData with before
// touching any share row, using the addresses of algo's coin family
// (see addressesForAlgo). Exactly like the legacy object literal, if
// a family's fee and donation addresses are equal (or both empty),
// they collapse into the same map entry — that is legacy's own
// behavior (paymentData is a plain object keyed by address string),
// reproduced here rather than treated as a bug.
func seedPaymentData(cfg Config, algo string) (map[string]*Payment, error) {
	feeAddr, donationAddr, err := addressesForAlgo(cfg, algo)
	if err != nil {
		return nil, err
	}
	data := make(map[string]*Payment, 2)
	seed := func(addr string) {
		if _, ok := data[addr]; !ok {
			data[addr] = &Payment{PoolType: "fees", PaymentAddress: addr}
		}
	}
	seed(feeAddr)
	seed(donationAddr)
	return data, nil
}

// applyDonations reproduces the identical block that appears at the
// tail of all three legacy handleIdentifier functions: split
// feesToPay into a donation (optionally floored per doFloorDonations
// — see CalculatePPLNS vs CalculatePPS/CalculateSolo's callers) and
// credit the remainder to algo's coin family's fee address (see
// addressesForAlgo) — never another family's, even though a single
// backend process runs Tari-family and Monero payouts side by side.
//
// assignFee controls whether the fee-address entry is incremented
// (PPS/PPLNS: `... = ... + (feesToPay - donations)`) or overwritten
// (Solo: `... = feesToPay - donations`) — reproducing that exact
// legacy asymmetry (CalculateSolo's handleIdentifier is a single,
// one-shot handler per block, so it overwrites rather than
// accumulates).
func applyDonations(cfg Config, algo string, data map[string]*Payment, feesToPay float64, floorDonations, assignFee bool) error {
	feeAddr, donationAddr, err := addressesForAlgo(cfg, algo)
	if err != nil {
		return err
	}
	donations := 0.0
	if cfg.DonationPercent > 0 {
		donation := feesToPay * (cfg.DonationPercent / 100)
		if floorDonations {
			donation = math.Floor(donation)
		}
		donations += donation
		data[donationAddr].Amount += donation
	}
	if assignFee {
		data[feeAddr].Amount = feesToPay - donations
	} else {
		data[feeAddr].Amount += feesToPay - donations
	}
	return nil
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

	data, err := seedPaymentData(c.cfg, algo)
	if err != nil {
		return nil, fmt.Errorf("payout: CalculatePPS: %w", err)
	}
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
		if err := applyDonations(c.cfg, algo, data, feesToPay, false, false); err != nil {
			return nil, fmt.Errorf("payout: CalculatePPS: %w", err)
		}
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

	data, err := seedPaymentData(c.cfg, algo)
	if err != nil {
		return nil, fmt.Errorf("payout: CalculatePPLNS: %w", err)
	}
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
			if err := applyDonations(c.cfg, algo, data, feesToPay, true, false); err != nil {
				return nil, fmt.Errorf("payout: CalculatePPLNS: %w", err)
			}
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
	data, err := seedPaymentData(c.cfg, algo)
	if err != nil {
		return nil, fmt.Errorf("payout: CalculateSolo: %w", err)
	}
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
	if err := applyDonations(c.cfg, algo, data, feesToPay, false, true); err != nil {
		return nil, fmt.Errorf("payout: CalculateSolo: %w", err)
	}
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
	// AlreadyApplied is true when this block's payout had already
	// been applied by an earlier, committed run, so this call
	// credited NOTHING. TotalPaid/Credited then describe that
	// original run, not this (no-op) one. This is the normal, healthy
	// outcome of the unlocker retrying a block whose payout
	// succeeded but whose status write did not — see
	// unlocker.checkBlock.
	AlreadyApplied bool
}

// Apply durably applies every entry in data as one atomic,
// idempotent payout run for block b.
//
// This replaced a straight `for each payment { CreditBalance(...) }`
// loop — the faithful port of legacy's
// `Object.keys(paymentData).forEach(key => balanceQueue.push(...))`.
// That shape was a real money bug, not a stylistic one: each
// increment committed independently, so an error partway through left
// an UNKNOWN subset of miners credited with no record of which, and
// the only retry available (a manual `backend block relock`) then
// credited every already-paid miner a second time. See
// migrations/0011_block_payouts.up.sql for the full writeup.
//
// What happens instead: the payments are flattened into a
// deterministically ordered credit list and handed, whole, to
// Repository.ApplyBlockPayout, which claims a per-block
// `block_payouts` ledger row and applies all of the credits in ONE
// database transaction. So:
//
//   - Failure anywhere mid-run credits NOBODY (full rollback), and
//     the next attempt re-runs cleanly.
//   - A block whose run already committed is a safe no-op
//     (ApplyResult.AlreadyApplied), never a second credit.
//   - A block left in a claimed-but-unresolved PENDING state is
//     REFUSED with an error rather than silently retried (see
//     db.ErrBlockPayoutPending) — "an unknown subset of these miners
//     may already hold this credit" must reach a human, not a retry
//     loop.
//
// Every entry is still credited, even ones whose Amount rounds to
// zero — matching legacy's unconditional push, which exists
// specifically to guarantee every payee's balance row is
// created/touched even in a zero-payout cycle.
//
// The credit list is sorted by (payment address, payment id) rather
// than left in Go map order. That is not only for reproducible logs
// and tests: a fixed, global ordering means two transactions
// crediting overlapping payee sets always take their `balance` row
// locks in the same order, which is what keeps them from deadlocking
// each other.
func (c *Calculator) Apply(ctx context.Context, b MaturedBlock, data map[string]*Payment) (ApplyResult, error) {
	credits := make([]BlockCredit, 0, len(data))
	for _, p := range data {
		credits = append(credits, BlockCredit{
			PayoutBucket:   p.PoolType,
			PaymentAddress: p.PaymentAddress,
			PaymentID:      p.PaymentID,
			Amount:         int64(math.Round(p.Amount)),
		})
	}
	sort.Slice(credits, func(i, j int) bool {
		if credits[i].PaymentAddress != credits[j].PaymentAddress {
			return credits[i].PaymentAddress < credits[j].PaymentAddress
		}
		return derefPaymentID(credits[i].PaymentID) < derefPaymentID(credits[j].PaymentID)
	})

	outcome, err := c.repo.ApplyBlockPayout(ctx, BlockPayoutRun{
		BlockID:  b.ID,
		Algo:     b.Algo,
		Network:  b.Network,
		PoolType: b.PoolType,
		Height:   b.Height,
		Reward:   b.Reward,
		Credits:  credits,
	})
	if err != nil {
		return ApplyResult{}, fmt.Errorf("payout: Apply: block %d (%s/%s height %d): %w", b.ID, b.Algo, b.Network, b.Height, err)
	}
	return ApplyResult{
		TotalPaid:      outcome.TotalPaid,
		Credited:       outcome.Credited,
		AlreadyApplied: outcome.AlreadyApplied,
	}, nil
}

// derefPaymentID flattens a nullable payment_id for Apply's sort
// comparison only. NULL and "" sort together, which is correct here:
// they are the same `balance` row identity (uq_balance_identity keys
// on COALESCE(payment_id, ”)).
func derefPaymentID(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// RunForMaturedBlock is the single entry point unlocker.PayoutTrigger
// implementations call (see cmd/backend's adapter): given one
// just-matured block's id/algo/network/pool_type/height/difficulty/
// reward, it dispatches to the matching Calculate{PPS,PPLNS,Solo}
// function, Applies the result as one atomic idempotent run keyed on
// that block id, and instruments the whole cycle on cfg.Metrics (a
// no-op if cfg.Metrics is nil).
//
// blockID is the `blocks.id` of the matured row and is REQUIRED: it
// is the idempotency key the `block_payouts` ledger hangs off (see
// Apply and migrations/0011_block_payouts.up.sql). A run for a block
// whose payout already committed returns
// ApplyResult.AlreadyApplied = true with a nil error — a safe,
// expected no-op, counted separately on payout_cycles_total (see
// metrics.PayoutResultAlreadyApplied) so a dashboard can tell a real
// payout cycle from a retry that correctly did nothing.
//
// poolType "PROP" is not a caller error — PROP blocks exist in this
// schema's pool_type enum (see migrations) but this package has no
// calculatePropPayments equivalent ported from legacy yet (legacy's
// own blockManager.js never implemented one either) — so it returns a
// plain error here, counted same as any other failed cycle, rather
// than panicking on an unrecognized case.
//
// blockReward nil (blocks.value is a nullable column — see
// migrations) means this block's real reward hasn't been recorded
// yet; RunForMaturedBlock refuses to guess and returns an error
// rather than silently paying out zero.
func (c *Calculator) RunForMaturedBlock(ctx context.Context, blockID int64, algo, network, poolType string, height, blockDifficulty int64, blockReward *int64) (result ApplyResult, err error) {
	start := time.Now()
	defer func() {
		if c.cfg.Metrics == nil {
			return
		}
		c.cfg.Metrics.PayoutCycleDuration.WithLabelValues(algo, poolType).Observe(time.Since(start).Seconds())
		outcome := metrics.PayoutResultSuccess
		switch {
		case err != nil:
			outcome = metrics.PayoutResultError
		case result.AlreadyApplied:
			outcome = metrics.PayoutResultAlreadyApplied
		}
		c.cfg.Metrics.PayoutCyclesTotal.WithLabelValues(algo, poolType, outcome).Inc()
		// Only a run that actually credited balances adds to the
		// credited total — an AlreadyApplied no-op credited nothing,
		// and counting its (historical) total again would double the
		// metric on every unlocker retry.
		if err == nil && !result.AlreadyApplied {
			c.cfg.Metrics.PayoutAmountCreditedTotal.WithLabelValues(algo, network).Add(float64(result.TotalPaid))
		}
	}()

	if blockReward == nil {
		return ApplyResult{}, fmt.Errorf("payout: RunForMaturedBlock: block reward (blocks.value) is not set for %s height %d", algo, height)
	}
	reward := *blockReward

	var data map[string]*Payment
	switch poolType {
	case "PPS":
		data, err = c.CalculatePPS(ctx, algo, height, blockDifficulty, reward)
	case "PPLNS":
		data, err = c.CalculatePPLNS(ctx, algo, height, blockDifficulty, reward)
	case "SOLO":
		data, err = c.CalculateSolo(ctx, algo, height, reward)
	default:
		err = fmt.Errorf("payout: RunForMaturedBlock: unsupported pool_type %q", poolType)
	}
	if err != nil {
		return ApplyResult{}, err
	}

	result, err = c.Apply(ctx, MaturedBlock{
		ID:       blockID,
		Algo:     algo,
		Network:  network,
		PoolType: poolType,
		Height:   height,
		Reward:   reward,
	}, data)
	return result, err
}
