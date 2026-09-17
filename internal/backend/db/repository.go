package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Share is the minimal set of columns the backend needs to persist for
// one accepted share. It intentionally mirrors internal/proto.Share's
// accounting-relevant fields; raw_proof is not persisted (the backend
// does not decode/validate it, per AGENTS.md's trust-boundary design).
type Share struct {
	Algo           string
	Network        string
	PoolType       string
	PoolID         int32
	BlockHeight    int64
	Shares         int64
	PaymentAddress string
	PaymentID      *string
	FoundBlock     bool
	BlockDiff      int64
	Timestamp      int64
	Identifier     string
	TrustedShare   bool
}

// Block is the minimal set of columns the backend needs to persist for
// one reported block. Mirrors internal/proto.Block.
type Block struct {
	Algo       string
	Network    string
	PoolType   string
	Hash       string
	Height     int64
	Difficulty int64
	Shares     int64
	Timestamp  int64
	Unlocked   bool
	Valid      bool
	Value      *int64
	PoolID     int32

	// MergeMineChain mirrors internal/proto.Block.merge_mine_chain
	// (see that field's doc comment) -- nil means this row is the
	// primary/Monero leg of an ALGO_RXM find; a non-nil value (e.g.
	// "TARI") names the secondary merge-mined chain leg. Always nil
	// for every non-RXM algo.
	MergeMineChain *string
}

// Repository provides minimal read/write access to the core schema. It is
// deliberately narrow (InsertShare/InsertBlock plus the partition
// helpers in partition.go) — this is schema + plumbing, not the full
// backend data-access surface.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository wraps an existing connection pool (see Open) in a
// Repository.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// InsertShare ensures the destination height-range partition exists (see
// EnsureHeightPartition) and inserts one share row. bucketSize should
// normally be HeightPartitionBucketSize; it is a parameter here (rather
// than implicit) for the same reason EnsureHeightPartition takes it
// explicitly.
//
// It also upserts the submitting miner's `miner_identifiers` row (see
// UpsertMinerIdentifier) in the same DB transaction as the shares
// insert, so every real, accepted share both (a) lands in `shares` and
// (b) keeps that miner's identifier row's last_share freshness marker
// current — this is the fix for the schema-exists-but-unpopulated gap
// `miner_identifiers` previously had: nothing wrote to it. Doing both
// writes in one transaction means a share can never be recorded without
// its identifier's last_share being bumped (or vice versa) even if the
// process crashes mid-call.
func (r *Repository) InsertShare(ctx context.Context, s Share, bucketSize int64) error {
	if err := ValidateAlgo(s.Algo); err != nil {
		return err
	}
	if err := ValidatePoolType(s.PoolType); err != nil {
		return err
	}
	if err := EnsureHeightPartition(ctx, r.pool, s.Algo, s.PoolType, s.BlockHeight, bucketSize); err != nil {
		return err
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: inserting share: beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const stmt = `
		INSERT INTO shares (
			algo, network, pool_type, pool_id, block_height, shares,
			payment_address, payment_id, found_block, block_diff,
			share_timestamp, identifier, trusted_share
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)`
	if _, err := tx.Exec(ctx, stmt,
		s.Algo, s.Network, s.PoolType, s.PoolID, s.BlockHeight, s.Shares,
		s.PaymentAddress, s.PaymentID, s.FoundBlock, s.BlockDiff,
		s.Timestamp, s.Identifier, s.TrustedShare,
	); err != nil {
		return fmt.Errorf("db: inserting share: %w", err)
	}

	lastShare := time.Unix(s.Timestamp, 0).UTC()
	if err := upsertMinerIdentifierTx(ctx, tx, s.Algo, s.Network, s.PaymentAddress, s.PaymentID, s.Identifier, lastShare); err != nil {
		return fmt.Errorf("db: inserting share: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: inserting share: committing transaction: %w", err)
	}
	return nil
}

// UpsertMinerIdentifier records that (algo, network, paymentAddress,
// paymentID, workerName) submitted a real share at lastShare,
// inserting a fresh `miner_identifiers` row if this exact identity
// (per uq_miner_identifiers_identity) has never been seen before, or
// advancing its last_share column otherwise. last_share only ever
// moves forward (GREATEST(miner_identifiers.last_share, EXCLUDED.last_share))
// so an out-of-order/delayed share submission can never regress a
// miner's freshness marker backwards.
//
// This is exported (in addition to being called from InsertShare on
// every real ingested share) so other real write paths — tests, and
// any future backfill/reconciliation tooling — can populate/advance
// the same row without duplicating the upsert SQL.
func (r *Repository) UpsertMinerIdentifier(ctx context.Context, algo, network, paymentAddress string, paymentID *string, workerName string, lastShare time.Time) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}
	if err := ValidateNetwork(network); err != nil {
		return err
	}
	if paymentAddress == "" {
		return fmt.Errorf("db: UpsertMinerIdentifier: payment_address is required")
	}
	return upsertMinerIdentifierTx(ctx, r.pool, algo, network, paymentAddress, paymentID, workerName, lastShare)
}

// minerIdentifierExecer is the subset of pgxpool.Pool/pgx.Tx that
// upsertMinerIdentifierTx needs, so the same SQL/logic runs
// identically whether called inside InsertShare's transaction (a
// pgx.Tx) or standalone via UpsertMinerIdentifier (the plain pool).
type minerIdentifierExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func upsertMinerIdentifierTx(ctx context.Context, exec minerIdentifierExecer, algo, network, paymentAddress string, paymentID *string, workerName string, lastShare time.Time) error {
	const stmt = `
		INSERT INTO miner_identifiers (algo, network, payment_address, payment_id, worker_name, last_share)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (algo, network, payment_address, (COALESCE(payment_id, '')), worker_name)
		DO UPDATE SET last_share = GREATEST(COALESCE(miner_identifiers.last_share, EXCLUDED.last_share), EXCLUDED.last_share)`
	if _, err := exec.Exec(ctx, stmt, algo, network, paymentAddress, paymentID, workerName, lastShare); err != nil {
		return fmt.Errorf("db: upserting miner identifier for %s: %w", paymentAddress, err)
	}
	return nil
}

// InsertBlock inserts one row into the plain, unpartitioned blocks table.
// No partition management is needed here — blocks are permanent and
// never cleaned up.
func (r *Repository) InsertBlock(ctx context.Context, b Block) error {
	if err := ValidateAlgo(b.Algo); err != nil {
		return err
	}
	if err := ValidatePoolType(b.PoolType); err != nil {
		return err
	}

	const stmt = `
		INSERT INTO blocks (
			algo, network, pool_type, hash, height, difficulty, shares,
			block_timestamp, unlocked, valid, value, pool_id, merge_mine_chain
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)`
	_, err := r.pool.Exec(ctx, stmt,
		b.Algo, b.Network, b.PoolType, b.Hash, b.Height, b.Difficulty, b.Shares,
		b.Timestamp, b.Unlocked, b.Valid, b.Value, b.PoolID, b.MergeMineChain,
	)
	if err != nil {
		return fmt.Errorf("db: inserting block: %w", err)
	}
	return nil
}

// PendingBlock is one row of `blocks` that the unlocker (see
// internal/backend/unlocker) still needs to independently verify
// against the real chain — i.e. valid = TRUE (never yet found
// invalid/orphaned) AND unlocked = FALSE (not yet confirmed mature).
// Carries pool_type/difficulty/value in addition to the columns the
// unlocker's ChainVerifier.Verify call itself needs, since the
// unlocker also uses this row to trigger a payout.Calculator run
// once a block resolves to matured (see unlocker.PayoutTrigger).
type PendingBlock struct {
	ID         int64
	Algo       string
	Network    string
	PoolType   string
	Hash       string
	Height     int64
	Difficulty int64
	Value      *int64

	// InsertedAt is this row's `blocks.inserted_at` (server-side
	// receipt time, NOT the leaf-supplied block_timestamp -- see that
	// column's own doc comment in the migration). Used by
	// internal/backend/unlocker's pending-blocks-age gauge (see
	// PROD_HARDENING_REVIEW.md finding #11) to report how long the
	// OLDEST still-pending block for an (algo, network) has been
	// stuck, which is deliberately based on when THIS backend first
	// saw the block, not on whatever clock-skewed timestamp a leaf
	// happened to attach to it.
	InsertedAt time.Time

	// MergeMineChain mirrors Block.MergeMineChain (see that field's
	// doc comment) -- nil for the primary/Monero leg, non-nil (e.g.
	// "TARI") for a secondary merge-mined chain leg. The unlocker
	// (internal/backend/unlocker) uses this to route each pending
	// block row to the correct ChainVerifier.
	MergeMineChain *string
}

// PendingBlocks returns every blocks row with valid = TRUE AND
// unlocked = FALSE for the given algo, oldest (lowest id) first — the
// unlocker's poll loop calls this once per configured algo on every
// tick. algo is validated the same way InsertBlock's is; an invalid
// algo is a caller bug, not a legitimate "no rows" outcome, so it is
// reported as an error rather than silently returning an empty slice.
func (r *Repository) PendingBlocks(ctx context.Context, algo string) ([]PendingBlock, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}

	const stmt = `
		SELECT id, algo, network, pool_type, hash, height, difficulty, value, inserted_at, merge_mine_chain
		FROM blocks
		WHERE algo = $1 AND valid = TRUE AND unlocked = FALSE
		ORDER BY id ASC`
	rows, err := r.pool.Query(ctx, stmt, algo)
	if err != nil {
		return nil, fmt.Errorf("db: querying pending blocks: %w", err)
	}
	defer rows.Close()

	var out []PendingBlock
	for rows.Next() {
		var pb PendingBlock
		if err := rows.Scan(&pb.ID, &pb.Algo, &pb.Network, &pb.PoolType, &pb.Hash, &pb.Height, &pb.Difficulty, &pb.Value, &pb.InsertedAt, &pb.MergeMineChain); err != nil {
			return nil, fmt.Errorf("db: scanning pending block row: %w", err)
		}
		out = append(out, pb)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating pending block rows: %w", err)
	}
	return out, nil
}

// SetBlockStatus updates one blocks row's valid/unlocked columns by
// id — the unlocker's own write path once ChainVerifier.Verify has
// resolved a pending block's real chain status (matured -> valid,
// unlocked; orphaned -> !valid, unlocked; the third, "still
// confirming" outcome does not call this at all and simply leaves the
// row pending for the next poll). Returns an error (rather than
// silently no-op'ing) if id does not match any row, since that
// indicates the unlocker and the blocks table have drifted out of
// sync with each other.
func (r *Repository) SetBlockStatus(ctx context.Context, id int64, valid, unlocked bool) error {
	const stmt = `UPDATE blocks SET valid = $2, unlocked = $3 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, stmt, id, valid, unlocked)
	if err != nil {
		return fmt.Errorf("db: updating block %d status: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: updating block %d status: no such block", id)
	}
	return nil
}

// GetBlockByID returns one full `blocks` row by primary key, or a
// wrapped pgx.ErrNoRows if id does not match any row. This exists
// purely for ops-facing read access (the manual block invalidate/
// re-lock CLI subcommands in cmd/backend use it to show the operator
// exactly what they are about to change, and what changed, on either
// side of a SetBlockStatus call) — nothing in the normal
// share/block-ingestion or unlocker write paths needs to fetch a
// single block by id, so this was not previously exposed.
func (r *Repository) GetBlockByID(ctx context.Context, id int64) (Block, error) {
	const stmt = `
		SELECT algo, network, pool_type, hash, height, difficulty, shares,
		       block_timestamp, unlocked, valid, value, pool_id, merge_mine_chain
		FROM blocks
		WHERE id = $1`
	var b Block
	err := r.pool.QueryRow(ctx, stmt, id).Scan(
		&b.Algo, &b.Network, &b.PoolType, &b.Hash, &b.Height, &b.Difficulty, &b.Shares,
		&b.Timestamp, &b.Unlocked, &b.Valid, &b.Value, &b.PoolID, &b.MergeMineChain,
	)
	if err != nil {
		return Block{}, fmt.Errorf("db: getting block %d: %w", id, err)
	}
	return b, nil
}

// PayoutShare is one `shares` row as needed by internal/backend/payout
// (payout.ShareRow's DB-facing counterpart — kept as its own type for
// the same dependency-direction reason unlocker.Block/db.PendingBlock
// are kept separate, see unlocker.Repository's doc comment).
type PayoutShare struct {
	Shares         int64
	PaymentAddress string
	PaymentID      *string
}

// SharesAtHeight returns every `shares` row for (algo, poolType,
// height), newest share_timestamp first — the real-schema equivalent
// of nodejs-pool-sxmr's `SELECT * FROM shares WHERE block_height = ?
// order by time desc`, scoped by this schema's algo/pool_type
// partition columns instead of a post-hoc pool_type filter (see
// internal/backend/payout's doc comment for why that's equivalent).
func (r *Repository) SharesAtHeight(ctx context.Context, algo, poolType string, height int64) ([]PayoutShare, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidatePoolType(poolType); err != nil {
		return nil, err
	}

	const stmt = `
		SELECT shares, payment_address, payment_id
		FROM shares
		WHERE algo = $1 AND pool_type = $2 AND block_height = $3
		ORDER BY share_timestamp DESC`
	rows, err := r.pool.Query(ctx, stmt, algo, poolType, height)
	if err != nil {
		return nil, fmt.Errorf("db: querying shares at height %d: %w", height, err)
	}
	defer rows.Close()

	var out []PayoutShare
	for rows.Next() {
		var s PayoutShare
		if err := rows.Scan(&s.Shares, &s.PaymentAddress, &s.PaymentID); err != nil {
			return nil, fmt.Errorf("db: scanning share row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating share rows: %w", err)
	}
	return out, nil
}

// SoloShare returns the single found_block=TRUE SOLO row for (algo,
// height) — the real-schema equivalent of nodejs-pool-sxmr's `SELECT *
// FROM shares WHERE block_height = ? AND found_block IS TRUE LIMIT 1`,
// additionally scoped to algo (see internal/backend/payout's doc
// comment: this schema partitions by algo, legacy's commingled table
// did not). found is false, with no error, when no such row exists yet
// — an expected state for a block that hasn't been fully processed,
// not a caller error.
func (r *Repository) SoloShare(ctx context.Context, algo string, height int64) (PayoutShare, bool, error) {
	if err := ValidateAlgo(algo); err != nil {
		return PayoutShare{}, false, err
	}

	const stmt = `
		SELECT shares, payment_address, payment_id
		FROM shares
		WHERE algo = $1 AND pool_type = 'SOLO' AND block_height = $2 AND found_block IS TRUE
		ORDER BY share_timestamp DESC
		LIMIT 1`
	var s PayoutShare
	err := r.pool.QueryRow(ctx, stmt, algo, height).Scan(&s.Shares, &s.PaymentAddress, &s.PaymentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PayoutShare{}, false, nil
		}
		return PayoutShare{}, false, fmt.Errorf("db: querying solo share at height %d: %w", height, err)
	}
	return s, true, nil
}

// CreditBalance adds amount to the pending balance for (algo, network,
// paymentAddress, paymentID), inserting a new zero-balance row first
// if none exists yet — the real-schema equivalent of nodejs-pool-sxmr's
// createBalanceQueue (account-ensure) followed by balanceQueue
// (increment), collapsed into a single upsert against this schema's
// uq_balance_identity unique index (algo, network, payment_address,
// COALESCE(payment_id, ”)).
func (r *Repository) CreditBalance(ctx context.Context, algo, network, paymentAddress string, paymentID *string, amount int64) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}

	const stmt = `
		INSERT INTO balance (algo, network, payment_address, payment_id, pending_balance)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (algo, network, payment_address, (COALESCE(payment_id, '')))
		DO UPDATE SET pending_balance = balance.pending_balance + EXCLUDED.pending_balance,
		              updated_at = now()`
	_, err := r.pool.Exec(ctx, stmt, algo, network, paymentAddress, paymentID, amount)
	if err != nil {
		return fmt.Errorf("db: crediting balance for %s: %w", paymentAddress, err)
	}
	return nil
}

// PayableBalance is one `balance` row whose pending_balance meets or
// exceeds a disbursement cycle's minimum payout threshold (or was
// explicitly force_payout = TRUE flagged, see below) — the
// real-schema source internal/backend/disburse.Repository.PayableBalances
// draws from to decide who gets paid this cycle.
type PayableBalance struct {
	ID             int64
	PaymentAddress string
	PaymentID      *string
	PendingBalance int64

	// ForcePayout mirrors this row's `balance.force_payout` column
	// (see migrations/0008_balance_force_payout.up.sql) exactly as
	// PayableBalances read it. true means this row was included in
	// the result EITHER because it genuinely met minPayout on its
	// own OR solely because of the force_payout override below —
	// disburse.Engine uses this to decide whether
	// Config.ForcePayoutFeeAtomic applies to this row (see that
	// package's runBatch), per this fee's explicit design: it
	// applies to every force_payout row being paid, regardless of
	// whether that row would also have qualified normally.
	ForcePayout bool
}

// PayableBalances returns every `balance` row for (algo, network)
// with a positive pending_balance that is EITHER >= minPayout OR
// flagged force_payout = TRUE (see migrations/0008_balance_force_payout.up.sql
// and internal/backend/authapi's POST /user/forcePayment) — oldest
// (lowest id) first, deterministic ordering so repeated disbursement
// cycles process the same backlog in the same order rather than an
// unspecified one. minPayout <= 0 returns every balance row with a
// positive pending balance regardless of force_payout (a "no minimum"
// disbursement policy is a legitimate operator choice, not a caller
// error) — the force_payout override is purely additive on top of
// the normal minPayout check, never a replacement for it.
//
// IN-FLIGHT EXCLUSION (money-critical, see
// migrations/0010_payouts_ambiguous_status.up.sql): a balance row
// referenced by an UNRESOLVED `payouts` row for the same (algo,
// network) — status PENDING (attempted, outcome never recorded) or
// AMBIGUOUS (attempted, and the failure cannot rule out that real
// coin already moved) — is NEVER returned here, no matter how large
// its pending_balance or whether it is force_payout-flagged. This is
// the row-level half of the double-payment fix: before it existed,
// an errored Transfer flipped the payout row to FAILED and this query
// happily handed the exact same balance rows back to the very next
// disbursement cycle, which sent the same coin a second time. The
// engine additionally halts the whole (algo, network) cycle when any
// unresolved row exists (see internal/backend/disburse's RunOnce and
// Repository.UnresolvedPayouts) — this clause is the defense-in-depth
// layer underneath that, so even a caller that skipped the halt check
// cannot re-pay an in-flight balance.
//
// EMPTY-ADDRESS DEFENSE IN DEPTH (PROD_HARDENING_REVIEW.md finding
// #10): a balance row with payment_address = ” (or all-whitespace)
// is NEVER returned here either, no matter how large its
// pending_balance. Such a row cannot legitimately exist going
// forward (cmd/backend's validateDonationConfig now refuses to start
// with a donation percent configured against an empty donation
// address, the only known way one of these was ever created), but
// this clause protects any row that predates that validation from
// poisoning its entire disbursement batch forever (see
// wallet/monero_rpc.go's Transfer, which rejects an empty destination
// address and fails the WHOLE batch, silently blocking every other
// miner co-batched with it) — an operator still has to fix the
// underlying row by hand (it is simply excluded, not deleted), but it
// can no longer take other miners' payouts down with it.
func (r *Repository) PayableBalances(ctx context.Context, algo, network string, minPayout int64) ([]PayableBalance, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if minPayout < 0 {
		minPayout = 0
	}

	const stmt = `
		SELECT id, payment_address, payment_id, pending_balance, force_payout
		FROM balance
		WHERE algo = $1 AND network = $2 AND pending_balance > 0
		  AND trim(payment_address) <> ''
		  AND (pending_balance >= $3 OR force_payout = TRUE)
		  AND NOT EXISTS (
		      SELECT 1
		      FROM payouts p
		      WHERE p.algo = $1 AND p.network = $2
		        AND p.status IN ('PENDING', 'AMBIGUOUS')
		        AND balance.id = ANY (p.balance_ids)
		  )
		ORDER BY id ASC`
	rows, err := r.pool.Query(ctx, stmt, algo, network, minPayout)
	if err != nil {
		return nil, fmt.Errorf("db: querying payable balances: %w", err)
	}
	defer rows.Close()

	var out []PayableBalance
	for rows.Next() {
		var b PayableBalance
		if err := rows.Scan(&b.ID, &b.PaymentAddress, &b.PaymentID, &b.PendingBalance, &b.ForcePayout); err != nil {
			return nil, fmt.Errorf("db: scanning payable balance row: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating payable balance rows: %w", err)
	}
	return out, nil
}

// PendingBalanceTotal is one (algo, network)'s outstanding
// pending_balance total — the real-schema source for
// cmd/backend's pending-balance poller (see metrics.Metrics.
// PendingBalanceOutstanding's doc comment, PROD_HARDENING_REVIEW.md
// finding #19).
type PendingBalanceTotal struct {
	Algo    string
	Network string
	Total   int64
}

// PendingBalanceTotals returns the sum of every positive
// `balance.pending_balance` row, grouped by (algo, network) — an
// (algo, network) pair with no rows at all (or whose rows are all
// exactly zero) is simply absent from the result, not returned as a
// zero-value row; the caller (cmd/backend's poller) is responsible
// for deciding how to represent "no outstanding balance" on the
// corresponding Prometheus gauge.
func (r *Repository) PendingBalanceTotals(ctx context.Context) ([]PendingBalanceTotal, error) {
	const stmt = `
		SELECT algo, network, SUM(pending_balance)
		FROM balance
		WHERE pending_balance > 0
		GROUP BY algo, network`
	rows, err := r.pool.Query(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("db: querying pending balance totals: %w", err)
	}
	defer rows.Close()

	var out []PendingBalanceTotal
	for rows.Next() {
		var t PendingBalanceTotal
		if err := rows.Scan(&t.Algo, &t.Network, &t.Total); err != nil {
			return nil, fmt.Errorf("db: scanning pending balance total row: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating pending balance total rows: %w", err)
	}
	return out, nil
}

// disburse.PayoutEntry, kept as this package's own type for the same
// dependency-direction reason PayoutShare/ShareRow are kept separate
// (see internal/backend/payout's doc comment).
type DisburseEntry struct {
	// BalanceID/Amount: which `balance` row this entry debits, and
	// the FULL amount debited from its pending_balance — always the
	// row's entire original PendingBalance as PayableBalances
	// returned it, even for a force_payout row where the miner was
	// actually sent less than this due to ForcePayoutFeeAtomic below
	// (the miner's whole pending balance is resolved by this payout;
	// the fee is a deduction from what they receive, not from what
	// gets debited here — see disburse.go's runBatch).
	BalanceID int64
	Amount    int64

	// ForcePayout mirrors this entry's originating PayableBalance.ForcePayout.
	// When true, CompletePayoutSent resets this balance row's
	// force_payout column back to FALSE in the same transaction as
	// the debit — the flag requests exactly one early/manual payout
	// (see migrations/0008_balance_force_payout.up.sql's "priority
	// signal ... on its next cycle" framing), not a standing
	// instruction to keep force-paying (and re-charging the fee on)
	// every future accrual from this address forever.
	ForcePayout bool

	// ForcePayoutFeeAtomic is the pool-policy fee (see
	// migrations/0009_payouts_force_payout_fee.up.sql) actually
	// collected from THIS row's payout, in atomic units. Zero for
	// any non-force_payout row, or if the operator has not opted
	// into GCPOOL_FORCE_PAYOUT_FEE_ATOMIC at all. The sum of this
	// field across every entry in one CompletePayoutSent call is
	// what gets recorded in that call's `payouts` row.
	ForcePayoutFeeAtomic int64
}

// RecordPendingPayout inserts a PENDING `payouts` row for one about-
// to-be-attempted real Transfer RPC call, BEFORE that call is made.
// See migrations/0002_wallet_disbursements.up.sql's doc comment for
// why this ordering matters: it makes "the RPC call itself crashed
// this process" a recoverable/auditable state instead of a silently
// lost one (an operator can always find every attempted disbursement
// by querying this table, even ones that never got a further status
// update because the process died mid-call).
//
// entries is the exact per-`balance`-row debit detail this attempt
// WOULD apply on success — persisted verbatim into the row's
// pending_entries JSONB column alongside the derived balance_ids
// array. This is not bookkeeping nicety: it is the only durable
// record of the per-row amount/force_payout/force-payout-fee split,
// and resolving an AMBIGUOUS payout to SENT by hand has to replay
// precisely that split rather than re-deriving it from live `balance`
// rows (which may have accrued more since). See
// migrations/0010_payouts_ambiguous_status.up.sql's doc comment on
// pending_entries, and ResolvePayoutSent.
//
// amount is the batch's real on-chain destination total (i.e. after
// any per-row force-payout fee deduction), which is NOT necessarily
// the sum of entries' Amount fields (those are full pending_balance
// debits) — the two are deliberately distinct, see DisburseEntry.
func (r *Repository) RecordPendingPayout(ctx context.Context, algo, network string, entries []DisburseEntry, amount int64) (int64, error) {
	if err := ValidateAlgo(algo); err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, fmt.Errorf("db: recording pending payout: at least one entry is required")
	}

	balanceIDs := make([]int64, 0, len(entries))
	records := make([]PayoutEntryRecord, 0, len(entries))
	for _, e := range entries {
		balanceIDs = append(balanceIDs, e.BalanceID)
		records = append(records, PayoutEntryRecord{
			BalanceID:            e.BalanceID,
			Amount:               e.Amount,
			ForcePayout:          e.ForcePayout,
			ForcePayoutFeeAtomic: e.ForcePayoutFeeAtomic,
		})
	}
	entriesJSON, err := json.Marshal(records)
	if err != nil {
		return 0, fmt.Errorf("db: recording pending payout: encoding pending_entries: %w", err)
	}

	const stmt = `
		INSERT INTO payouts (algo, network, status, balance_ids, amount, pending_entries)
		VALUES ($1, $2, 'PENDING', $3, $4, $5)
		RETURNING id`
	var id int64
	if err := r.pool.QueryRow(ctx, stmt, algo, network, balanceIDs, amount, entriesJSON).Scan(&id); err != nil {
		return 0, fmt.Errorf("db: recording pending payout: %w", err)
	}
	return id, nil
}

// CompletePayoutSent atomically (single DB transaction) debits every
// entry's amount from pending_balance and credits it to paid_balance
// on the matching `balance` row, resets force_payout back to FALSE
// for any entry that carries ForcePayout = TRUE (see DisburseEntry's
// doc comment), sums every entry's ForcePayoutFeeAtomic into the
// `payouts` row's own force_payout_fee_atomic column, then flips the
// `payouts` row identified by payoutID to SENT with the real
// tx_hash/real on-chain fee the Transfer RPC call reported. All of
// this happens in the same transaction specifically so a crash
// between any of these writes can never leave a SENT payout with
// balances that were never actually debited/reset, or a fee that was
// collected from a miner's payout but never landed in the pool's own
// revenue ledger (or vice versa) — the real, irreversible on-chain
// transfer has already happened by the time this is called (see
// disburse.go), so this step is bookkeeping that must not itself
// introduce a new consistency gap.
//
// The `payouts` UPDATE is guarded on status IN ('PENDING',
// 'AMBIGUOUS') — the only two states a payout can legitimately be
// completed FROM. A row already SENT (or already resolved to FAILED
// by an operator) is refused with an error rather than debited a
// second time; this is what makes the debit half of this transaction
// idempotent-safe against a concurrent/duplicate completion attempt
// on the same payout id, which on real money is the difference
// between a retried bookkeeping write and double-debiting a miner.
func (r *Repository) CompletePayoutSent(ctx context.Context, payoutID int64, entries []DisburseEntry, txHash string, fee int64) error {
	return r.completePayoutSent(ctx, payoutID, entries, txHash, fee, nil, nil)
}

// completePayoutSent is CompletePayoutSent's implementation, shared
// with ResolvePayoutSent (which passes a non-nil resolvedBy/note so
// the same single transaction also records who manually resolved the
// row and why — see payoutreconcile.go).
func (r *Repository) completePayoutSent(ctx context.Context, payoutID int64, entries []DisburseEntry, txHash string, fee int64, resolvedBy, note *string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: completing payout %d: beginning transaction: %w", payoutID, err)
	}
	defer tx.Rollback(ctx)

	var totalForceFee int64
	for _, e := range entries {
		totalForceFee += e.ForcePayoutFeeAtomic

		const debitStmt = `
			UPDATE balance
			SET pending_balance = pending_balance - $2,
			    paid_balance = paid_balance + $2,
			    force_payout = CASE WHEN $3 THEN FALSE ELSE force_payout END,
			    updated_at = now()
			WHERE id = $1`
		tag, err := tx.Exec(ctx, debitStmt, e.BalanceID, e.Amount, e.ForcePayout)
		if err != nil {
			return fmt.Errorf("db: completing payout %d: debiting balance %d: %w", payoutID, e.BalanceID, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("db: completing payout %d: no such balance row %d", payoutID, e.BalanceID)
		}
	}

	const payoutStmt = `
		UPDATE payouts
		SET status = 'SENT', tx_hash = $2, fee = $3, force_payout_fee_atomic = $4,
		    resolved_by = COALESCE($5, resolved_by), resolution_note = COALESCE($6, resolution_note),
		    completed_at = now()
		WHERE id = $1 AND status IN ('PENDING', 'AMBIGUOUS')`
	tag, err := tx.Exec(ctx, payoutStmt, payoutID, txHash, fee, totalForceFee, resolvedBy, note)
	if err != nil {
		return fmt.Errorf("db: completing payout %d: updating payouts row: %w", payoutID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: completing payout %d: no payouts row in PENDING/AMBIGUOUS status (already resolved, or no such row) — refusing to debit balances a second time", payoutID)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: completing payout %d: committing transaction: %w", payoutID, err)
	}
	return nil
}

// FailPayout flips the `payouts` row identified by payoutID to
// FAILED with the given error message. Deliberately does NOT touch
// any `balance` row — FAILED means, specifically and only, that the
// real Transfer RPC call PROVABLY never broadcast anything (a
// locally-detected request-validation failure, or an explicit
// rejection the wallet itself answered with), so the underlying
// balances remain payable and are simply picked up again by the next
// disbursement cycle's PayableBalances call (see disburse.go).
//
// Callers must NOT use this for an error that merely might not have
// broadcast: that is what MarkPayoutAmbiguous is for. Getting this
// distinction wrong is precisely how the same coin gets sent twice —
// see migrations/0010_payouts_ambiguous_status.up.sql's doc comment
// and internal/backend/wallet.ErrNotBroadcast (the only sanctioned
// signal for "definitely not broadcast").
func (r *Repository) FailPayout(ctx context.Context, payoutID int64, errMsg string) error {
	const stmt = `
		UPDATE payouts
		SET status = 'FAILED', error = $2, completed_at = now()
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, stmt, payoutID, errMsg)
	if err != nil {
		return fmt.Errorf("db: failing payout %d: %w", payoutID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: failing payout %d: no such payouts row", payoutID)
	}
	return nil
}

// MarkPayoutAmbiguous flips the `payouts` row identified by payoutID
// to AMBIGUOUS — the "real coin MAY already have moved on-chain, a
// human must check before anything else is paid out for this (algo,
// network)" state introduced by
// migrations/0010_payouts_ambiguous_status.up.sql. Like FailPayout it
// touches no `balance` row, but unlike FailPayout the affected
// balances do NOT become payable again: PayableBalances excludes
// every row referenced by an unresolved payout, and disburse.Engine
// halts the whole (algo, network) while one exists.
//
// txHash, when non-empty, is recorded on the row — this matters for
// the CompletePayoutSent-failed-after-a-successful-broadcast case,
// where the real transaction hash IS known and is exactly what an
// operator needs to confirm the transfer on-chain before resolving.
// An empty txHash leaves any existing tx_hash untouched (the
// transfer-errored case genuinely has no hash to record).
//
// completed_at is deliberately left NULL: AMBIGUOUS is not a
// completed outcome, it is an open incident awaiting manual
// resolution (see cmd/backend/payoutcli.go's resolve-sent /
// resolve-not-sent subcommands, which are what finally set it).
func (r *Repository) MarkPayoutAmbiguous(ctx context.Context, payoutID int64, txHash, errMsg string) error {
	const stmt = `
		UPDATE payouts
		SET status = 'AMBIGUOUS',
		    error = $2,
		    tx_hash = COALESCE(NULLIF($3, ''), tx_hash)
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, stmt, payoutID, errMsg, txHash)
	if err != nil {
		return fmt.Errorf("db: marking payout %d ambiguous: %w", payoutID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: marking payout %d ambiguous: no such payouts row", payoutID)
	}
	return nil
}
