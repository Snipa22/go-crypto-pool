// Package disburse implements the go-crypto-pool backend's real
// payout-disbursement engine: periodically querying every payable
// `balance` row for a given (algo, network) and actually moving real
// coin out of the pool's hot wallet to each miner's payment address
// via internal/backend/wallet.WalletClient, then debiting the exact
// amount sent from pending_balance into paid_balance.
//
// This is the disbursement side of payout accounting;
// internal/backend/payout is the calculation side (deciding HOW MUCH
// each miner is owed and crediting pending_balance). The two
// packages are deliberately independent — payout.Calculator never
// touches a wallet, and Engine never re-derives payout amounts, it
// only pays out whatever pending_balance already holds. This mirrors
// this codebase's established split between unlocker (chain-maturity
// detection) and payout (reward calculation): each package owns one
// well-defined step of the pipeline and depends on the previous
// step's output via a narrow interface, never its internals.
//
// # Real-money safety properties this package establishes
//
//   - No balance is ever debited before a real Transfer RPC call has
//     actually returned success (a tx_hash). See Engine.runBatch.
//   - Every attempted transfer is recorded (Repository.RecordPendingPayout)
//     BEFORE the real Transfer RPC call is made, and resolved to
//     SENT/FAILED immediately after — so a crash mid-call leaves a
//     durable, queryable PENDING row rather than silently vanishing
//     (see migrations/0002_wallet_disbursements.up.sql's doc comment).
//   - A failed Transfer call debits nothing — the underlying balance
//     rows remain untouched and are simply retried on the next cycle
//     (RunOnce's next invocation re-queries PayableBalances fresh).
//   - Every cycle checks the wallet's real UNLOCKED balance before
//     attempting any batch for that cycle, and skips (does not
//     partially attempt) any batch whose total would exceed it — see
//     Engine.RunOnce's insufficient-funds handling.
package disburse

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/backend/wallet"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// PayableBalance is one payable `balance` row, as needed for
// disbursement — mirrors db.PayableBalance field-for-field, kept as
// this package's own type for the same dependency-direction reason
// payout.ShareRow/unlocker.Block exist (cmd/backend is the only place
// this package and internal/backend/db need to meet).
type PayableBalance struct {
	ID             int64
	PaymentAddress string
	PaymentID      *string
	PendingBalance int64

	// ForcePayout mirrors db.PayableBalance.ForcePayout — true if
	// this row was returned by Repository.PayableBalances via the
	// force_payout override (see that method's doc comment),
	// regardless of whether it would also have qualified normally
	// via the plain minPayout threshold. runBatch uses this to
	// decide whether Config.ForcePayoutFeeAtomic applies to this
	// row — per this fee's explicit design, it applies to every
	// force_payout row being paid this cycle, full stop.
	ForcePayout bool
}

// PayoutEntry is one balance row's contribution to a single real
// on-chain transfer batch — the in-memory analog of db.DisburseEntry,
// built by Engine.RunOnce's batching logic and handed to
// Repository.CompletePayoutSent once the batch's real Transfer call
// succeeds.
type PayoutEntry struct {
	BalanceID      int64
	PaymentAddress string
	PaymentID      *string
	Amount         int64
}

// Repository is the narrow persistence surface Engine depends on.
// *db.Repository satisfies this interface via a small adapter in
// cmd/backend, mirroring unlocker.Repository/payout.Repository's role.
type Repository interface {
	// PayableBalances returns every balance row for (algo, network)
	// with pending_balance >= minPayout — see db.Repository's
	// identically-named method's doc comment.
	PayableBalances(ctx context.Context, algo, network string, minPayout int64) ([]PayableBalance, error)

	// RecordPendingPayout durably records one about-to-be-attempted
	// transfer batch BEFORE the real Transfer RPC call is made,
	// returning an opaque payout-row id used by
	// CompletePayoutSent/FailPayout to resolve it afterward.
	RecordPendingPayout(ctx context.Context, algo, network string, balanceIDs []int64, amount int64) (int64, error)

	// CompletePayoutSent atomically debits every entry's amount from
	// pending_balance into paid_balance and marks payoutID SENT with
	// the real tx_hash/fee the Transfer call reported. Only called
	// after a real, successful Transfer RPC call.
	CompletePayoutSent(ctx context.Context, payoutID int64, entries []DebitEntry, txHash string, fee int64) error

	// FailPayout marks payoutID FAILED with errMsg. Never touches
	// any balance row (see this package's doc comment).
	FailPayout(ctx context.Context, payoutID int64, errMsg string) error
}

// DebitEntry is the (balanceID, amount) pair Repository.CompletePayoutSent
// needs — a narrower view of PayoutEntry that doesn't leak
// PaymentAddress/PaymentID into the debit step (the real Transfer
// call has already resolved those; the debit step only needs to know
// which balance rows to touch and by how much).
type DebitEntry struct {
	// BalanceID/Amount: mirrors db.DisburseEntry's identically-named
	// fields exactly — Amount is always the row's FULL original
	// PendingBalance, even for a force_payout row where the real
	// Transfer destination amount (see PayoutEntry.Amount) was less
	// than this due to ForcePayoutFeeAtomic below.
	BalanceID int64
	Amount    int64

	// ForcePayout mirrors the originating PayableBalance.ForcePayout
	// — see db.DisburseEntry's identically-named field for why
	// CompletePayoutSent needs this (resetting the force_payout
	// column once consumed).
	ForcePayout bool

	// ForcePayoutFeeAtomic is the fee actually collected from this
	// row's payout (see Config.ForcePayoutFeeAtomic and runBatch),
	// zero for any non-force_payout row. Mirrors
	// db.DisburseEntry.ForcePayoutFeeAtomic.
	ForcePayoutFeeAtomic int64
}

// Config configures an Engine.
type Config struct {
	// Wallet performs the real on-chain transfer. Required.
	Wallet wallet.WalletClient

	// MinPayoutAtomic is the minimum pending_balance (in atomic
	// units) a miner must have accrued before this engine will pay
	// them out at all — an operator-tunable dust/fee-amortization
	// threshold (paying out a handful of atomic units would cost
	// more in real network fees than the payout itself, on any real
	// coin). Zero means "pay out anything positive" and is a
	// legitimate, if unusual, operator choice, not rejected here.
	MinPayoutAtomic int64

	// ForcePayoutFeeAtomic is an operator-configured flat atomic-unit
	// fee (GCPOOL_FORCE_PAYOUT_FEE_ATOMIC / --force-payout-fee-atomic)
	// charged against every force_payout = TRUE row this engine pays
	// out this cycle — Alex's explicit "we charge extra fees for
	// manual payouts like that below the threshold for auto payout"
	// requirement. Applies uniformly to every force_payout row,
	// regardless of whether that row's PendingBalance would also
	// have cleared MinPayoutAtomic on its own (deliberately not
	// distinguished — simpler and correct per that requirement).
	// Deducted from the amount actually wired to the miner (see
	// runBatch), never from what gets debited from pending_balance,
	// and credited to pool revenue (db's payouts.force_payout_fee_atomic)
	// rather than reported as part of the real on-chain Transfer fee
	// (which remains exactly what the wallet RPC reported — this fee
	// is additive pool policy, not a real network cost). Zero (the
	// default) means no extra fee — same "zero means off" convention
	// as MinPayoutAtomic above.
	ForcePayoutFeeAtomic int64

	// MaxDestinationsPerBatch caps how many balance rows one single
	// real Transfer RPC call covers. Real monero-wallet-rpc has no
	// hard-coded destination-count limit, but very large transactions
	// risk hitting real per-transaction size/relay limits and make a
	// single RPC failure block an entire cycle's disbursement instead
	// of just one batch — so this is an operational safety knob, not
	// a protocol constant. Must be > 0; RunOnce treats <= 0 as a
	// configuration error (there is no sane "unlimited" fallback that
	// wouldn't risk exactly the problem this knob exists to avoid).
	MaxDestinationsPerBatch int

	// TransferPriority/TransferRingSize are passed straight through
	// to every wallet.TransferRequest this engine builds — see
	// wallet.TransferRequest's doc comment for their real
	// monero-wallet-rpc semantics. Zero means "let the wallet apply
	// its own default" for both.
	TransferPriority int
	TransferRingSize int

	// Logf receives one line per notable event, defaulting to
	// log.Printf if nil — same seam as unlocker.Config.Logf.
	Logf func(format string, args ...any)

	// Metrics, if non-nil, is the metrics.Metrics instance RunOnce
	// increments/observes (disbursement_batches_total,
	// disbursement_amount_sent_total, disbursement_fee_total,
	// disbursement_cycle_duration_seconds). If nil, metrics are
	// simply not recorded.
	Metrics *metrics.Metrics

	// Debug, if non-nil and enabled, adds verbose [DEBUG]-tagged
	// logging to every RunOnce cycle -- what was checked (payable
	// balance count) and what changed (batch decisions/outcomes) --
	// see internal/leaflib/debuglog.go's doc comment and
	// cmd/backend/main.go's -debug/GCPOOL_DEBUG wiring. nil (the
	// default for every pre-existing caller/test) is a complete
	// no-op.
	Debug *leaflib.DebugLogger
}

// Engine runs disbursement cycles against a Repository/WalletClient
// using a fixed Config — the disbursement-side analog of
// payout.Calculator/unlocker.Unlocker.
type Engine struct {
	repo Repository
	cfg  Config
	logf func(format string, args ...any)
}

// New constructs an Engine.
func New(repo Repository, cfg Config) *Engine {
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	return &Engine{repo: repo, cfg: cfg, logf: logf}
}

// Result summarizes the outcome of one RunOnce call.
type Result struct {
	// Payable is how many balance rows RunOnce found eligible for
	// payout this cycle (before batching).
	Payable int
	// Batches/BatchesSent/BatchesFailed count real Transfer attempts
	// and their outcomes.
	Batches       int
	BatchesSent   int
	BatchesFailed int
	// Skipped is 1 if the entire cycle was skipped for insufficient
	// unlocked wallet balance (see RunOnce), 0 otherwise. Not a count
	// of individual batches — insufficiency is evaluated once, for
	// the whole cycle's total, before any batching happens.
	Skipped int
	// TotalSent is the sum of every batch's PayoutEntry amounts that
	// was ACTUALLY sent this cycle (excludes failed/skipped batches).
	TotalSent int64
	// TotalFees is the sum of real on-chain fees paid across every
	// successfully sent batch this cycle.
	TotalFees int64
}

// RunOnce performs exactly one disbursement cycle for (algo,
// network): fetches every payable balance row, checks the real
// wallet's unlocked balance can cover the total, and — if so —
// batches the payable rows into groups of at most
// cfg.MaxDestinationsPerBatch, sending one real Transfer per batch
// and debiting balances only after that batch's Transfer call
// actually succeeds.
//
// Batches are grouped by payment ID: every row with a nil/empty
// PaymentID is packed together up to MaxDestinationsPerBatch per
// batch; every row with a non-empty PaymentID gets its OWN
// single-destination batch. This is not an arbitrary simplification
// — monero-wallet-rpc's real "transfer" method accepts at most one
// payment_id per call (see wallet.TransferRequest's doc comment), so
// mixing distinct payment IDs into one multi-destination transfer is
// not something the real RPC supports at all.
//
// If the wallet's real unlocked balance is less than the sum of all
// payable rows, the ENTIRE cycle is skipped (Result.Skipped = 1, no
// batches attempted) rather than partially paying out an arbitrary
// subset — a deliberate choice: partial payout order would otherwise
// depend on batching/iteration order, which is not a policy this
// engine should be silently making. The next cycle retries the full
// set once more funds are available.
func (e *Engine) RunOnce(ctx context.Context, algo, network string) (Result, error) {
	start := time.Now()
	var result Result
	defer func() {
		if e.cfg.Metrics == nil {
			return
		}
		e.cfg.Metrics.DisbursementCycleDuration.WithLabelValues(algo, network).Observe(time.Since(start).Seconds())
	}()

	if e.cfg.Wallet == nil {
		return result, fmt.Errorf("disburse: RunOnce: Config.Wallet is required")
	}
	if e.cfg.MaxDestinationsPerBatch <= 0 {
		return result, fmt.Errorf("disburse: RunOnce: Config.MaxDestinationsPerBatch must be > 0")
	}

	rows, err := e.repo.PayableBalances(ctx, algo, network, e.cfg.MinPayoutAtomic)
	if err != nil {
		return result, fmt.Errorf("disburse: RunOnce: listing payable balances: %w", err)
	}
	result.Payable = len(rows)
	e.cfg.Debug.Debugf("disburse: %s/%s: poll cycle checking %d payable balance row(s) (min payout atomic=%d)", algo, network, len(rows), e.cfg.MinPayoutAtomic)
	if len(rows) == 0 {
		return result, nil
	}

	var totalRequested int64
	for _, r := range rows {
		totalRequested += r.PendingBalance
	}

	bal, err := e.cfg.Wallet.GetBalance(ctx)
	if err != nil {
		return result, fmt.Errorf("disburse: RunOnce: checking wallet balance: %w", err)
	}
	if bal.Unlocked < totalRequested {
		e.logf("disburse: %s/%s: skipping cycle: wallet unlocked balance %d < required %d for %d payable balances",
			algo, network, bal.Unlocked, totalRequested, len(rows))
		result.Skipped = 1
		e.observeBatch(algo, network, metrics.DisbursementResultSkipped)
		return result, nil
	}

	batches := buildBatches(rows, e.cfg.MaxDestinationsPerBatch)
	for _, batch := range batches {
		result.Batches++
		sent, fee, err := e.runBatch(ctx, algo, network, batch)
		if err != nil {
			result.BatchesFailed++
			e.logf("disburse: %s/%s: batch of %d destinations failed: %v", algo, network, len(batch), err)
			e.observeBatch(algo, network, metrics.DisbursementResultFailed)
			continue
		}
		result.BatchesSent++
		result.TotalSent += sent
		result.TotalFees += fee
		e.observeBatch(algo, network, metrics.DisbursementResultSent)
		if e.cfg.Metrics != nil {
			e.cfg.Metrics.DisbursementAmountSentTotal.WithLabelValues(algo, network).Add(float64(sent))
			e.cfg.Metrics.DisbursementFeeTotal.WithLabelValues(algo, network).Add(float64(fee))
		}
	}
	return result, nil
}

func (e *Engine) observeBatch(algo, network, result string) {
	if e.cfg.Metrics == nil {
		return
	}
	e.cfg.Metrics.DisbursementBatchesTotal.WithLabelValues(algo, network, result).Inc()
}

// buildBatches groups payable rows into real-Transfer-call-sized
// batches per RunOnce's doc comment: rows with a non-empty PaymentID
// each get their own single-row batch; rows with no PaymentID are
// packed together up to maxPerBatch per batch, in the same order
// PayableBalances returned them (deterministic, oldest-balance-row-
// first — see db.Repository.PayableBalances's doc comment).
func buildBatches(rows []PayableBalance, maxPerBatch int) [][]PayableBalance {
	var batches [][]PayableBalance
	var current []PayableBalance
	for _, r := range rows {
		if r.PaymentID != nil && *r.PaymentID != "" {
			if len(current) > 0 {
				batches = append(batches, current)
				current = nil
			}
			batches = append(batches, []PayableBalance{r})
			continue
		}
		current = append(current, r)
		if len(current) >= maxPerBatch {
			batches = append(batches, current)
			current = nil
		}
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

// runBatch performs one real Transfer RPC call for batch and, only on
// success, debits every entry's balance. Returns the real amount
// actually sent to miners (after any per-row force_payout fee
// deduction, see below) and the real on-chain fee paid.
//
// For every row in batch with ForcePayout == true, e.cfg.ForcePayoutFeeAtomic
// (if > 0) is subtracted from that row's real Transfer destination
// amount — the extra fee Alex required for manual/forced payouts
// below the normal threshold (see Config.ForcePayoutFeeAtomic's doc
// comment: applies uniformly to every force_payout row this cycle,
// not just ones that were genuinely below minPayout on their own).
// Edge case: if a row's PendingBalance <= the configured fee, the fee
// is capped to PendingBalance-1 for that row instead — this engine
// always sends at least 1 atomic unit to a real wallet RPC rather
// than a zero/negative amount, logging the cap so an operator can see
// it happened (chosen over skipping the row entirely: skipping would
// mean silently NOT honoring a miner's explicit forced-payout request
// this cycle purely because of a configuration edge case, which is a
// worse outcome than the miner receiving a token amount instead of
// the full fee being collected).
func (e *Engine) runBatch(ctx context.Context, algo, network string, batch []PayableBalance) (sent, fee int64, err error) {
	destinations := make([]wallet.Destination, 0, len(batch))
	balanceIDs := make([]int64, 0, len(batch))
	forceFees := make([]int64, len(batch))
	var total int64
	var paymentID string
	if len(batch) == 1 && batch[0].PaymentID != nil {
		paymentID = *batch[0].PaymentID
	}
	for i, r := range batch {
		amount := r.PendingBalance
		var rowFee int64
		if r.ForcePayout && e.cfg.ForcePayoutFeeAtomic > 0 {
			rowFee = e.cfg.ForcePayoutFeeAtomic
			if rowFee >= r.PendingBalance {
				capped := r.PendingBalance - 1
				e.logf("disburse: %s/%s: balance %d: force_payout fee %d >= pending_balance %d, capping fee to %d so the miner still receives >= 1 atomic unit",
					algo, network, r.ID, e.cfg.ForcePayoutFeeAtomic, r.PendingBalance, capped)
				rowFee = capped
			}
			amount = r.PendingBalance - rowFee
		}
		forceFees[i] = rowFee
		destinations = append(destinations, wallet.Destination{Address: r.PaymentAddress, Amount: amount})
		balanceIDs = append(balanceIDs, r.ID)
		total += amount
	}

	payoutID, err := e.repo.RecordPendingPayout(ctx, algo, network, balanceIDs, total)
	if err != nil {
		return 0, 0, fmt.Errorf("recording pending payout: %w", err)
	}

	result, transferErr := e.cfg.Wallet.Transfer(ctx, wallet.TransferRequest{
		Destinations: destinations,
		PaymentID:    paymentID,
		Priority:     e.cfg.TransferPriority,
		RingSize:     e.cfg.TransferRingSize,
	})
	if transferErr != nil {
		if failErr := e.repo.FailPayout(ctx, payoutID, transferErr.Error()); failErr != nil {
			e.logf("disburse: %s/%s: payout %d: also failed to mark payout as FAILED: %v", algo, network, payoutID, failErr)
		}
		return 0, 0, fmt.Errorf("transfer: %w", transferErr)
	}

	entries := make([]DebitEntry, 0, len(batch))
	var totalForceFee int64
	for i, r := range batch {
		entries = append(entries, DebitEntry{
			BalanceID:            r.ID,
			Amount:               r.PendingBalance,
			ForcePayout:          r.ForcePayout,
			ForcePayoutFeeAtomic: forceFees[i],
		})
		totalForceFee += forceFees[i]
	}
	if err := e.repo.CompletePayoutSent(ctx, payoutID, entries, result.TxHash, result.Fee); err != nil {
		// The real transfer already happened on-chain at this point
		// — this error means the LOCAL bookkeeping failed to record
		// it, a serious but different failure mode than a failed
		// Transfer call (real coin DID move). Surfaced as an error
		// (so it's loud), but this batch is still reported via the
		// tx_hash in the error message for manual reconciliation.
		return 0, 0, fmt.Errorf("transfer succeeded (tx_hash=%s amount=%d fee=%d) but recording it failed: %w", result.TxHash, result.Amount, result.Fee, err)
	}

	if totalForceFee > 0 {
		e.logf("disburse: %s/%s: payout %d: collected %d atomic units in force_payout fees across %d destinations",
			algo, network, payoutID, totalForceFee, len(batch))
	}
	e.logf("disburse: %s/%s: payout %d: sent %d atomic units (fee %d) to %d destinations, tx_hash=%s",
		algo, network, payoutID, total, result.Fee, len(batch), result.TxHash)
	return total, result.Fee, nil
}

// RunLoop calls RunOnce for every (algo, network) pair in targets
// every interval, until ctx is canceled. Never returns an error
// itself — RunOnce's own errors (repository/wallet failures at the
// whole-cycle level, distinct from a single failed batch, which
// RunOnce already handles internally) are logged and swallowed so one
// bad cycle does not take down the whole poll loop, mirroring
// unlocker.Unlocker.RunLoop's contract exactly.
func (e *Engine) RunLoop(ctx context.Context, targets []Target, interval time.Duration) {
	if interval <= 0 {
		e.logf("disburse: RunLoop: interval <= 0, exiting without polling")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, t := range targets {
				if _, err := e.RunOnce(ctx, t.Algo, t.Network); err != nil {
					e.logf("disburse: %s/%s: cycle failed: %v", t.Algo, t.Network, err)
				}
			}
		}
	}
}

// Target is one (algo, network) pair RunLoop disburses for.
type Target struct {
	Algo    string
	Network string
}
