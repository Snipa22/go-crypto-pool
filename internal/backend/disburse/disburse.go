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
//     SENT/FAILED/AMBIGUOUS immediately after — so a crash mid-call
//     leaves a durable, queryable PENDING row rather than silently
//     vanishing (see migrations/0002_wallet_disbursements.up.sql's
//     doc comment).
//   - A Transfer failure that is PROVABLY pre-broadcast (marked
//     wallet.ErrNotBroadcast) debits nothing and is recorded FAILED —
//     the underlying balance rows remain untouched and are simply
//     retried on the next cycle (RunOnce's next invocation re-queries
//     PayableBalances fresh).
//   - Any OTHER Transfer failure, and any failure of the
//     CompletePayoutSent bookkeeping write that follows a successful
//     Transfer, is recorded AMBIGUOUS and HALTS disbursement for that
//     (algo, network) until a human resolves it. See the section
//     below — this is the single most important property in this
//     package.
//   - Every cycle checks the wallet's real UNLOCKED balance before
//     attempting any batch for that cycle, and skips (does not
//     partially attempt) any batch whose total would exceed it — see
//     Engine.RunOnce's insufficient-funds handling.
//   - A single *Engine instance never runs two disbursement cycles
//     for itself at once, even if RunOnce is somehow invoked twice
//     concurrently — see the OVERLAP GATE section below.
//
// # Ambiguous outcomes and why this package halts instead of retrying
//
// This package used to treat EVERY Transfer error as "definitely no
// coin moved": it called Repository.FailPayout, which leaves the
// underlying balances payable, and the very next cycle sent the same
// coin again. Two real, already-present code paths broke that
// assumption and caused genuine double payments:
//
//  1. monero-wallet-rpc's `transfer` can take longer than the wallet
//     RPC HTTP client's timeout and STILL broadcast for real. The
//     client sees a timeout; the coin is gone.
//  2. internal/backend/wallet/tari.go has an explicit path where the
//     recipient transfer SUCCEEDS (broadcast, real tx id) but the
//     follow-up GetTransactionInfo fee lookup fails — Transfer still
//     returns an error for the whole call.
//
// So the rule is now inverted and fail-safe. FAILED (retry) requires
// PROOF of non-broadcast, in the form of wallet.ErrNotBroadcast (see
// that sentinel's doc comment — only the wallet implementations can
// establish it, e.g. a local request-validation refusal or an
// explicit rejection the wallet itself answered with). Everything
// else — timeouts, transport failures, unparseable responses, a
// success response with no tx_hash, a post-broadcast lookup failure —
// is AMBIGUOUS, which:
//
//   - marks the payout row AMBIGUOUS rather than FAILED (a distinct
//     status, deliberately NOT reusing FAILED: FAILED asserts
//     "nothing happened", AMBIGUOUS asserts the opposite is possible
//     — see migrations/0010_payouts_ambiguous_status.up.sql);
//   - leaves the affected `balance` rows frozen: Repository.PayableBalances
//     excludes every row referenced by an unresolved (PENDING or
//     AMBIGUOUS) payout, so they cannot be re-paid even by accident;
//   - abandons the rest of the current cycle for that (algo, network)
//     instead of attempting the remaining batches;
//   - makes every subsequent cycle for that (algo, network) refuse to
//     pay anything out at all (RunOnce's up-front UnresolvedPayouts
//     check), and makes cmd/backend refuse to even START the loop for
//     that pair on the next process launch.
//
// Recovery is deliberately manual: an operator confirms on-chain
// whether the transfer really happened and runs `backend payout
// resolve-sent` (records it, debits balances, no re-payment) or
// `backend payout resolve-not-sent` (makes the balances payable
// again). There is no automatic reconciliation, by choice: neither
// wallet client exposes a transfer-history/listing RPC this package
// could diff against (Monero's client wraps only `transfer` and
// `get_balance`; Tari's only adds a by-transaction-id lookup, which
// is useless when the ambiguity is precisely that no id came back),
// so any "automatic" recovery would have to guess about real money.
//
// # OVERLAP GATE: in-process-only mutual exclusion on RunOnce
//
// RunOnce has no built-in reason to ever be called twice
// concurrently for the same *Engine instance today — the only caller
// is RunLoop's own ticker, one tick at a time. But nothing enforced
// that invariant, and a future caller (e.g. a manual "run now"
// trigger racing the ticker loop) or a test that happens to invoke
// RunOnce from two goroutines would otherwise both reach
// Repository.PayableBalances, see the SAME payable rows (nothing
// locks them), and both call the real wallet.Transfer RPC for the
// same balances — a genuine double-payment of real money, and a
// different bug from everything above.
//
// So every *Engine instance guards itself with an in-process
// sync.Mutex (Engine.runMu). RunOnce's very first action, before the
// HALT GATE, before any balance query, before any wallet or
// repository call of any kind, is an e.runMu.TryLock(). If that
// fails — another call on this SAME instance is already running —
// RunOnce returns immediately with Result.Overlapped set and an
// error wrapping ErrOverlapped, touching nothing else at all. If it
// succeeds, the lock is held (via defer) for the ENTIRE rest of the
// cycle, all the way through the final return, so it covers every
// balance query and every real Transfer call this cycle makes.
//
// This is deliberately IN-PROCESS-ONLY: it is a plain in-memory
// mutex on one *Engine value, not a cross-process/DB mechanism (no
// Postgres advisory lock, no `SELECT ... FOR UPDATE`/`SKIP LOCKED`).
// Two separate backend processes each running their own *Engine for
// the same (algo, network) are NOT protected against each other by
// this gate — that would be a different problem, and this codebase
// has no existing convention assuming or requiring a cross-process
// lock for this code path (repository.go's PayableBalances is a
// plain SELECT with no row locking). If multi-process disbursement
// ever becomes a real deployment shape, that is a separate, explicit
// design decision, not something this gate silently half-solves.
package disburse

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/backend/wallet"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// ErrHalted is returned by RunOnce when it refuses to run a
// disbursement cycle for an (algo, network) because that pair has at
// least one unresolved (PENDING or AMBIGUOUS) payout row — see this
// package's doc comment. Callers can use errors.Is to distinguish
// this deliberate, safety-driven refusal from a genuine
// repository/wallet failure; cmd/backend's startup check reports it
// distinctly, and RunLoop keeps logging it once per tick (loudly, on
// purpose: a halted payout pipeline must not fade into silence).
var ErrHalted = errors.New("disburse: disbursement halted: unresolved payout(s) require manual resolution")

// ErrOverlapped is returned by RunOnce when it refuses to run a
// disbursement cycle for a given *Engine instance because another
// call to RunOnce on that SAME instance is already in progress — see
// the OVERLAP GATE paragraph in this package's doc comment and
// RunOnce's own doc comment. This is purely an in-process guard (a
// sync.Mutex.TryLock on the Engine), not a cross-process/DB lock: it
// exists to make a same-instance double-invoke (e.g. a future manual
// "run now" trigger racing the RunLoop ticker) refuse cleanly instead
// of racing two real Transfer calls against the same balance rows.
// Callers can use errors.Is to distinguish this deliberate rejection
// from a genuine repository/wallet failure, mirroring ErrHalted's
// pattern exactly.
var ErrOverlapped = errors.New("disburse: disbursement cycle already running for this engine instance (in-process overlap)")

// errAmbiguous is the internal marker runBatch returns (wrapped)
// when a batch ended in an ambiguous state, so RunOnce can abandon
// the rest of the cycle rather than attempting further batches. Not
// exported: callers outside this package should look at
// Result.BatchesAmbiguous / the AMBIGUOUS payout rows themselves,
// not try to classify errors this package already classified.
var errAmbiguous = errors.New("ambiguous transfer outcome")

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
	// PayableBalances returns every balance row for (algo, network,
	// currency) with pending_balance >= minPayout, EXCLUDING any row
	// referenced by an unresolved (PENDING/AMBIGUOUS) payout — see
	// db.Repository's identically-named method's doc comment.
	//
	// currency is REQUIRED (see migrations/0014_balance_payouts_currency.up.sql)
	// — a disbursement cycle for one currency's wallet must never be
	// able to sweep up a balance row that only exists on a
	// DIFFERENT currency for the same (algo, network), e.g.
	// ALGO_RXM's independent XMR and XTM legs.
	PayableBalances(ctx context.Context, algo, network, currency string, minPayout int64) ([]PayableBalance, error)

	// UnresolvedPayouts returns every unresolved (PENDING or
	// AMBIGUOUS) payout row for (algo, network, currency). RunOnce
	// calls this FIRST, before touching a wallet or a balance row,
	// and refuses to run the cycle at all if the result is non-empty
	// — see this package's doc comment on why disbursement halts
	// rather than retrying. currency is REQUIRED for the same reason
	// PayableBalances' is: an unresolved payout on one of ALGO_RXM's
	// two independent currency legs must halt ONLY that leg.
	UnresolvedPayouts(ctx context.Context, algo, network, currency string) ([]UnresolvedPayout, error)

	// RecordPendingPayout durably records one about-to-be-attempted
	// transfer batch BEFORE the real Transfer RPC call is made,
	// returning an opaque payout-row id used by
	// CompletePayoutSent/FailPayout/MarkPayoutAmbiguous to resolve
	// it afterward. entries carries the exact per-balance-row debit
	// this attempt would apply, which must be persisted so an
	// ambiguous outcome can later be resolved to SENT by replaying
	// precisely that debit (see db.Repository's identically-named
	// method); amount is the real on-chain destination total.
	// currency is REQUIRED and recorded on the new `payouts` row —
	// see db.Repository.RecordPendingPayout's doc comment.
	RecordPendingPayout(ctx context.Context, algo, network, currency string, entries []DebitEntry, amount int64) (int64, error)

	// CompletePayoutSent atomically debits every entry's amount from
	// pending_balance into paid_balance and marks payoutID SENT with
	// the real tx_hash/fee the Transfer call reported. Only called
	// after a real, successful Transfer RPC call.
	CompletePayoutSent(ctx context.Context, payoutID int64, entries []DebitEntry, txHash string, fee int64) error

	// FailPayout marks payoutID FAILED with errMsg. Never touches
	// any balance row, leaving them payable next cycle — so it is
	// ONLY valid for a failure proven to be pre-broadcast (see
	// wallet.ErrNotBroadcast and this package's doc comment).
	FailPayout(ctx context.Context, payoutID int64, errMsg string) error

	// MarkPayoutAmbiguous marks payoutID AMBIGUOUS with errMsg and,
	// when non-empty, txHash. Touches no balance row and — unlike
	// FailPayout — does NOT make those balances payable again:
	// PayableBalances excludes rows referenced by an unresolved
	// payout, and RunOnce refuses to run at all while one exists.
	MarkPayoutAmbiguous(ctx context.Context, payoutID int64, txHash, errMsg string) error
}

// UnresolvedPayout is one unresolved (PENDING or AMBIGUOUS) payout
// row as this package needs to see it — mirrors the operationally
// relevant subset of db.UnresolvedPayout, kept as this package's own
// type for the same dependency-direction reason PayableBalance and
// DebitEntry are.
type UnresolvedPayout struct {
	ID     int64
	Status string
	Amount int64
	// BalanceIDs is which `balance` rows this unresolved payout
	// covers — i.e. exactly the rows frozen out of PayableBalances
	// while it stays unresolved. Logged verbatim by the halt/startup
	// messages so an operator can see whose balances are affected
	// without a second query.
	BalanceIDs []int64
	TxHash     string
	Error      string
	Created    time.Time
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

	// runMu is the OVERLAP GATE (see this package's doc comment): an
	// in-process-only mutex ensuring this SAME *Engine instance never
	// runs two RunOnce cycles at once. TryLock'd at the very top of
	// RunOnce, before any other work, and held for the entire cycle.
	runMu sync.Mutex
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
	// BatchesAmbiguous counts batches that ended in the AMBIGUOUS
	// state this cycle — real coin may have moved, the balances are
	// frozen, and a human must resolve it (see this package's doc
	// comment). At most 1, since the first ambiguous batch abandons
	// the rest of the cycle.
	BatchesAmbiguous int
	// Skipped is 1 if the entire cycle was skipped for insufficient
	// unlocked wallet balance (see RunOnce), 0 otherwise. Not a count
	// of individual batches — insufficiency is evaluated once, for
	// the whole cycle's total, before any batching happens.
	Skipped int
	// Halted is 1 if the cycle refused to pay anything out because
	// this (algo, network) already had unresolved payout row(s) when
	// it started (RunOnce also returns an error wrapping ErrHalted
	// in that case), 0 otherwise. Distinct from Skipped: Skipped is
	// a routine "not enough unlocked funds right now, try later",
	// Halted is "something is wrong with real money and a human has
	// to look".
	Halted int
	// Overlapped is 1 if RunOnce refused to run at all because
	// another call to RunOnce on this SAME *Engine instance was
	// already in progress (RunOnce also returns an error wrapping
	// ErrOverlapped in that case), 0 otherwise. See the OVERLAP GATE
	// section of this package's doc comment. Distinct from BOTH
	// Skipped and Halted: those describe a cycle that ran and made a
	// real decision about funds/unresolved payouts; Overlapped means
	// this call never got to run at all — no balance query, no
	// wallet call, no repository call of any kind was made.
	Overlapped int
	// Unresolved is how many unresolved (PENDING/AMBIGUOUS) payout
	// rows this cycle observed for this (algo, network) at its
	// start. Zero on a healthy cycle.
	Unresolved int
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
//
// HALT GATE: before any of the above, RunOnce asks the repository
// whether this (algo, network, currency) has any unresolved (PENDING
// or AMBIGUOUS) payout row. If it does, the cycle pays out NOTHING —
// Result.Halted = 1, and an error wrapping ErrHalted is returned —
// until an operator resolves those rows by hand. See this package's
// doc comment for why halting is the correct response and
// cmd/backend/payoutcli.go for the resolution path. Likewise, if a
// batch goes ambiguous partway through a cycle, the remaining batches
// are abandoned rather than attempted.
//
// OVERLAP GATE: before even the HALT GATE — the very first thing
// RunOnce does at all — it tries to take this *Engine instance's
// in-process runMu lock. If another call to RunOnce on this SAME
// instance is already running, this call returns IMMEDIATELY with
// Result.Overlapped = 1 and an error wrapping ErrOverlapped, having
// made no balance query, no wallet call, and no repository call of
// any kind. This guard is in-process-only — it protects one *Engine
// value against being re-entered concurrently (e.g. a future manual
// "run now" trigger racing RunLoop's ticker), NOT multiple processes
// running their own Engine against the same (algo, network); see the
// OVERLAP GATE section of this package's doc comment for why that
// broader problem is deliberately out of scope here. If the lock is
// acquired, it is held for the ENTIRE rest of this cycle (via defer),
// released on every exit path. Note the guard is scoped to the
// *Engine INSTANCE only, not to (algo, network, currency): two
// distinct *Engine instances (e.g. one per RXM currency leg, see
// cmd/backend/main.go) never contend with each other here at all.
//
// currency is REQUIRED (see migrations/0014_balance_payouts_currency.up.sql
// and db.ValidateCurrency) — for RXT/C29/SHA3X it is always "XTM";
// for ALGO_RXM it is "XMR" or "XTM" depending on which of that algo's
// two independent wallets/legs this call means. The halt gate, the
// payable-balance query, and every payout row this cycle creates are
// all scoped to this exact (algo, network, currency) triple, so an
// unresolved XMR-side RXM payout can never halt (or be confused with)
// XTM-side RXM disbursement, and vice versa — those are genuinely
// independent wallets with independent failure domains.
func (e *Engine) RunOnce(ctx context.Context, algo, network, currency string) (Result, error) {
	// OVERLAP GATE. See this function's doc comment and this
	// package's doc comment's "OVERLAP GATE" section. Deliberately
	// the ABSOLUTE first thing RunOnce does: no balance query, no
	// wallet call, no repository call of any kind happens while
	// another call on this same *Engine is still running.
	if !e.runMu.TryLock() {
		var result Result
		result.Overlapped = 1
		e.logf("disburse: %s/%s/%s: OVERLAPPED: another RunOnce call is already running on this engine instance — this call is refusing to run at all (no balance query, no wallet call) rather than race it. This is an in-process guard only; see disburse.go's OVERLAP GATE doc.",
			algo, network, currency)
		e.observeBatch(algo, network, metrics.DisbursementResultOverlapped)
		return result, fmt.Errorf("disburse: RunOnce: %s/%s/%s: %w", algo, network, currency, ErrOverlapped)
	}
	defer e.runMu.Unlock()

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

	// Halt gate. Deliberately the very first thing this cycle does:
	// no wallet call, no balance query, no payout row is created
	// while a previous attempt's outcome is still unknown.
	unresolved, err := e.repo.UnresolvedPayouts(ctx, algo, network, currency)
	if err != nil {
		return result, fmt.Errorf("disburse: RunOnce: checking for unresolved payouts: %w", err)
	}
	e.setUnresolvedGauge(algo, network, len(unresolved))
	if len(unresolved) > 0 {
		result.Halted = 1
		result.Unresolved = len(unresolved)
		for _, p := range unresolved {
			e.logf("disburse: %s/%s/%s: HALTED: payout %d is unresolved (status=%s amount=%d balance_ids=%v tx_hash=%q created=%s): %s",
				algo, network, currency, p.ID, p.Status, p.Amount, p.BalanceIDs, p.TxHash, p.Created.UTC().Format(time.RFC3339), p.Error)
		}
		e.logf("disburse: %s/%s/%s: HALTED: %d unresolved payout(s) — NOTHING will be paid out for this algo/network/currency until an operator resolves them. "+
			"Inspect with `backend payout list-unresolved -algo=%s -network=%s -currency=%s`, confirm on-chain whether each transfer really happened, then run "+
			"`backend payout resolve-sent` (it DID broadcast: records it, debits balances, no re-payment) or `backend payout resolve-not-sent` "+
			"(it did NOT broadcast: makes those balances payable again).",
			algo, network, currency, len(unresolved), algo, network, currency)
		e.observeHalt(algo, network, metrics.HaltReasonUnresolvedPayouts)
		return result, fmt.Errorf("disburse: RunOnce: %s/%s/%s: %d unresolved payout(s): %w", algo, network, currency, len(unresolved), ErrHalted)
	}

	rows, err := e.repo.PayableBalances(ctx, algo, network, currency, e.cfg.MinPayoutAtomic)
	if err != nil {
		return result, fmt.Errorf("disburse: RunOnce: listing payable balances: %w", err)
	}
	result.Payable = len(rows)
	e.cfg.Debug.Debugf("disburse: %s/%s/%s: poll cycle checking %d payable balance row(s) (min payout atomic=%d)", algo, network, currency, len(rows), e.cfg.MinPayoutAtomic)
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
		e.logf("disburse: %s/%s/%s: skipping cycle: wallet unlocked balance %d < required %d for %d payable balances",
			algo, network, currency, bal.Unlocked, totalRequested, len(rows))
		result.Skipped = 1
		e.observeBatch(algo, network, metrics.DisbursementResultSkipped)
		return result, nil
	}

	batches := buildBatches(rows, e.cfg.MaxDestinationsPerBatch)
	for i, batch := range batches {
		result.Batches++
		sent, fee, err := e.runBatch(ctx, algo, network, currency, batch)
		if err != nil {
			if errors.Is(err, errAmbiguous) {
				result.BatchesAmbiguous++
				e.observeBatch(algo, network, metrics.DisbursementResultAmbiguous)
				e.observeHalt(algo, network, metrics.HaltReasonAmbiguousBatch)
				e.logf("disburse: %s/%s/%s: HALTING this cycle after an ambiguous batch outcome: %v", algo, network, currency, err)
				if remaining := len(batches) - i - 1; remaining > 0 {
					e.logf("disburse: %s/%s/%s: abandoning the remaining %d batch(es) of this cycle — no further coin will be moved for this algo/network/currency until the ambiguous payout above is manually resolved",
						algo, network, currency, remaining)
				}
				// Return the error so RunLoop logs it loudly every
				// cycle. The engine will refuse outright at the halt
				// gate from the next cycle onward.
				return result, err
			}
			result.BatchesFailed++
			e.logf("disburse: %s/%s/%s: batch of %d destinations failed (provably not broadcast, balances stay payable): %v", algo, network, currency, len(batch), err)
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

func (e *Engine) observeHalt(algo, network, reason string) {
	if e.cfg.Metrics == nil {
		return
	}
	e.cfg.Metrics.DisbursementHaltsTotal.WithLabelValues(algo, network, reason).Inc()
}

func (e *Engine) observeAmbiguous(algo, network, cause string) {
	if e.cfg.Metrics == nil {
		return
	}
	e.cfg.Metrics.DisbursementAmbiguousPayoutsTotal.WithLabelValues(algo, network, cause).Inc()
	e.cfg.Metrics.DisbursementUnresolvedPayouts.WithLabelValues(algo, network).Inc()
}

func (e *Engine) setUnresolvedGauge(algo, network string, n int) {
	if e.cfg.Metrics == nil {
		return
	}
	e.cfg.Metrics.DisbursementUnresolvedPayouts.WithLabelValues(algo, network).Set(float64(n))
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
//
// FAILURE HANDLING (money-critical — see this package's doc comment):
// the returned error is wrapped with errAmbiguous whenever the
// outcome cannot rule out that real coin already moved, which is the
// default for anything other than a wallet.ErrNotBroadcast-marked
// Transfer error. In that case the payout row is marked AMBIGUOUS
// (never FAILED) so the balances stay frozen, and RunOnce abandons
// the remaining batches.
func (e *Engine) runBatch(ctx context.Context, algo, network, currency string, batch []PayableBalance) (sent, fee int64, err error) {
	destinations := make([]wallet.Destination, 0, len(batch))
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
		total += amount
	}

	// entries is built BEFORE the attempt and handed to
	// RecordPendingPayout so the exact per-row debit this batch would
	// apply is durably recorded up front — that record is what makes
	// an ambiguous outcome resolvable to SENT later without guessing
	// (see Repository.RecordPendingPayout and
	// db.Repository.ResolvePayoutSent). Deliberately the same slice
	// used for CompletePayoutSent on the success path, so the two can
	// never disagree.
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

	payoutID, err := e.repo.RecordPendingPayout(ctx, algo, network, currency, entries, total)
	if err != nil {
		// Nothing has been attempted yet and no payout row exists,
		// so this is safely retriable: not ambiguous.
		return 0, 0, fmt.Errorf("recording pending payout: %w", err)
	}

	result, transferErr := e.cfg.Wallet.Transfer(ctx, wallet.TransferRequest{
		Destinations: destinations,
		PaymentID:    paymentID,
		Priority:     e.cfg.TransferPriority,
		RingSize:     e.cfg.TransferRingSize,
	})
	if transferErr != nil {
		if errors.Is(transferErr, wallet.ErrNotBroadcast) {
			// PROVABLY pre-broadcast (see wallet.ErrNotBroadcast):
			// no transaction was created, so FAILED is correct and
			// the balances legitimately stay payable for next cycle.
			if failErr := e.repo.FailPayout(ctx, payoutID, transferErr.Error()); failErr != nil {
				e.logf("disburse: %s/%s/%s: payout %d: also failed to mark payout as FAILED: %v", algo, network, currency, payoutID, failErr)
			}
			return 0, 0, fmt.Errorf("transfer: %w", transferErr)
		}

		// NOT proven pre-broadcast: real coin MAY already have moved
		// (a timed-out but successful transfer, a transport failure
		// after the wallet accepted, Tari's succeeded-transfer-but-
		// failed-fee-lookup path, ...). Recording this FAILED is
		// exactly the bug this code exists to prevent — it would
		// leave the balance payable and re-send the same coin next
		// cycle. Mark AMBIGUOUS instead, which freezes those
		// balances out of PayableBalances and halts this (algo,
		// network, currency) until a human confirms on-chain.
		msg := fmt.Sprintf("transfer outcome AMBIGUOUS (may or may not have broadcast, balances frozen pending manual resolution): %v", transferErr)
		if markErr := e.repo.MarkPayoutAmbiguous(ctx, payoutID, "", msg); markErr != nil {
			// Worst case: we cannot even record the ambiguity. The
			// payout row is still PENDING, which is ALSO an
			// unresolved status and therefore still freezes these
			// balances and still halts the next cycle — the safety
			// property holds either way. Log both errors loudly.
			e.logf("disburse: %s/%s/%s: payout %d: CRITICAL: transfer outcome is ambiguous (%v) AND marking it AMBIGUOUS failed (%v) — the row stays PENDING, which still blocks disbursement for this algo/network/currency; resolve it manually",
				algo, network, currency, payoutID, transferErr, markErr)
		}
		e.observeAmbiguous(algo, network, metrics.AmbiguousCauseTransfer)
		e.logf("disburse: %s/%s/%s: payout %d: AMBIGUOUS: %d destination(s), %d atomic units: %v — balances for this payout are frozen and disbursement for %s/%s/%s is halted until `backend payout resolve-sent`/`resolve-not-sent` is run for payout %d",
			algo, network, currency, payoutID, len(batch), total, transferErr, algo, network, currency, payoutID)
		return 0, 0, fmt.Errorf("transfer (payout %d): %w: %w", payoutID, errAmbiguous, transferErr)
	}

	if err := e.repo.CompletePayoutSent(ctx, payoutID, entries, result.TxHash, result.Fee); err != nil {
		// The real transfer already happened on-chain at this point
		// — this error means the LOCAL bookkeeping failed to record
		// it. Coin DEFINITELY moved, so the balances must NOT become
		// payable again: mark the row AMBIGUOUS (carrying the real
		// tx_hash, which is exactly what an operator needs to
		// confirm and then resolve it via `backend payout
		// resolve-sent`) and halt.
		msg := fmt.Sprintf("transfer SUCCEEDED (tx_hash=%s amount=%d fee=%d) but recording it failed, balances NOT yet debited: %v",
			result.TxHash, result.Amount, result.Fee, err)
		if markErr := e.repo.MarkPayoutAmbiguous(ctx, payoutID, result.TxHash, msg); markErr != nil {
			e.logf("disburse: %s/%s/%s: payout %d: CRITICAL: transfer succeeded (tx_hash=%s) but BOTH recording it (%v) and marking it AMBIGUOUS (%v) failed — the row stays PENDING, which still blocks disbursement for this algo/network/currency; resolve it manually with tx_hash=%s",
				algo, network, currency, payoutID, result.TxHash, err, markErr, result.TxHash)
		}
		e.observeAmbiguous(algo, network, metrics.AmbiguousCauseBookkeeping)
		e.logf("disburse: %s/%s/%s: payout %d: AMBIGUOUS: real transfer tx_hash=%s SUCCEEDED but bookkeeping failed (%v) — coin has moved, balances are NOT debited and are frozen; resolve with `backend payout resolve-sent -id=%d -tx-hash=%s`",
			algo, network, currency, payoutID, result.TxHash, err, payoutID, result.TxHash)
		return 0, 0, fmt.Errorf("transfer succeeded (payout %d tx_hash=%s amount=%d fee=%d) but recording it failed: %w: %w",
			payoutID, result.TxHash, result.Amount, result.Fee, errAmbiguous, err)
	}

	if totalForceFee > 0 {
		e.logf("disburse: %s/%s/%s: payout %d: collected %d atomic units in force_payout fees across %d destinations",
			algo, network, currency, payoutID, totalForceFee, len(batch))
	}
	e.logf("disburse: %s/%s/%s: payout %d: sent %d atomic units (fee %d) to %d destinations, tx_hash=%s",
		algo, network, currency, payoutID, total, result.Fee, len(batch), result.TxHash)
	return total, result.Fee, nil
}

// CheckTargets partitions targets into those that are safe to
// disburse for and those that must not be started because they
// already have unresolved (PENDING or AMBIGUOUS) payout rows — the
// startup check cmd/backend runs before wiring RunLoop, so a process
// restart can never quietly resume paying out an (algo, network)
// whose previous attempt's outcome is still unknown.
//
// It is intentionally a method on Engine rather than free-standing
// logic in cmd/backend: the "what counts as unresolved" rule, the
// operator-facing remediation message, and the metrics emitted all
// live here next to RunOnce's own halt gate, so the two cannot drift
// apart. blocked is returned in targets' order, each with the
// unresolved rows found, so the caller can log specifics.
//
// A repository error is returned as-is and must be treated as fatal
// by the caller: being unable to determine whether a payout is
// unresolved is emphatically NOT the same as there being none, and
// starting disbursement on that basis is how money gets sent twice.
func (e *Engine) CheckTargets(ctx context.Context, targets []Target) (safe []Target, blocked []BlockedTarget, err error) {
	for _, t := range targets {
		unresolved, uErr := e.repo.UnresolvedPayouts(ctx, t.Algo, t.Network, t.Currency)
		if uErr != nil {
			return nil, nil, fmt.Errorf("disburse: CheckTargets: %s/%s/%s: checking for unresolved payouts: %w", t.Algo, t.Network, t.Currency, uErr)
		}
		e.setUnresolvedGauge(t.Algo, t.Network, len(unresolved))
		if len(unresolved) == 0 {
			safe = append(safe, t)
			continue
		}
		e.observeHalt(t.Algo, t.Network, metrics.HaltReasonUnresolvedPayouts)
		blocked = append(blocked, BlockedTarget{Target: t, Unresolved: unresolved})
	}
	return safe, blocked, nil
}

// BlockedTarget is one (algo, network) CheckTargets refused to clear
// for disbursement, together with the unresolved payout rows that
// caused the refusal.
type BlockedTarget struct {
	Target     Target
	Unresolved []UnresolvedPayout
}

// RunLoop calls RunOnce for every (algo, network) pair in targets
// every interval, until ctx is canceled. Never returns an error
// itself — RunOnce's own errors (repository/wallet failures at the
// whole-cycle level, distinct from a single failed batch, which
// RunOnce already handles internally) are logged and swallowed so one
// bad cycle does not take down the whole poll loop, mirroring
// unlocker.Unlocker.RunLoop's contract exactly.
//
// That includes ErrHalted: a halted (algo, network) is logged on
// every tick rather than silently dropped or allowed to stop the loop
// for the OTHER targets, which may be perfectly healthy. Callers
// should prefer not to pass a known-halted target at all (see
// CheckTargets), but RunOnce's own halt gate means doing so is safe —
// it simply pays out nothing for that pair.
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
				if _, err := e.RunOnce(ctx, t.Algo, t.Network, t.Currency); err != nil {
					e.logf("disburse: %s/%s/%s: cycle failed: %v", t.Algo, t.Network, t.Currency, err)
				}
			}
		}
	}
}

// Target is one (algo, network, currency) triple RunLoop disburses
// for. Currency is REQUIRED (see migrations/0014_balance_payouts_currency.up.sql
// and db.ValidateCurrency) — "XTM" for every RXT/C29/SHA3X target,
// and either "XMR" or "XTM" for an ALGO_RXM target depending on which
// of that algo's two independent wallets/legs it means. There is
// deliberately no default: cmd/backend's own Target literals must
// each state their currency explicitly, so a future third
// leg/algo/coin can never silently inherit the wrong one.
type Target struct {
	Algo     string
	Network  string
	Currency string
}
