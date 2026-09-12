-- 0011_block_payouts.up.sql
--
-- Adds the matured-block payout IDEMPOTENCY LEDGER: `block_payouts`
-- (one row per block whose payout run has been claimed) and
-- `block_payout_credits` (one row per (block, balance row) that run
-- actually credited).
--
-- WHY THIS EXISTS (money-critical, read this before touching any of
-- it): up to this migration, the matured-block payout path had no
-- durable record that a block's payout had run at all, and credited
-- miners one non-transactional statement at a time. Two distinct real
-- bugs followed from that:
--
--   1. FIRE-AND-FORGET ORDERING. internal/backend/unlocker's
--      checkBlock marked a matured block `valid = TRUE, unlocked =
--      TRUE` FIRST and only then called PayoutTrigger. A trigger
--      failure was logged and dropped. Because Repository.PendingBlocks
--      selects `valid = TRUE AND unlocked = FALSE`, that block was
--      now permanently invisible to the unlocker's poll loop: the
--      payout was never retried, with no durable marker anywhere that
--      it was owed. A crash BETWEEN the two calls lost the payout the
--      same way, silently. The only recovery was an operator noticing
--      and running `backend block relock` by hand.
--
--   2. NON-IDEMPOTENT, NON-TRANSACTIONAL CREDITS.
--      internal/backend/payout's Apply looped over its payment data
--      calling Repository.CreditBalance (an upsert-increment) once per
--      payee, each in its own implicit transaction. An error partway
--      through left an UNKNOWN subset of miners already credited, with
--      no record of which. Re-running the payout for that block --
--      exactly what `backend block relock` causes -- then credited
--      every already-paid miner a SECOND time. That is a real,
--      unbounded overpayment of pool funds, and the pool had no way to
--      even determine after the fact which rows were affected.
--
-- Both halves are fixed by the same thing: Repository.ApplyBlockPayout
-- now performs the CLAIM, every balance credit, the per-credit ledger
-- rows, and the terminal status flip in ONE Postgres transaction (see
-- internal/backend/db/blockpayout.go). That makes the failure modes:
--
--   - crash/error anywhere mid-run -> the whole transaction rolls
--     back. No `block_payouts` row, no credit, no partial state. The
--     unlocker's next poll pass re-runs it cleanly. This is why the
--     partial-credit state that used to be possible simply cannot
--     arise from the engine any more.
--   - run committed -> status APPLIED. A second ApplyBlockPayout call
--     for that block is a safe no-op that credits nothing (this is
--     what makes the unlocker's automatic retry, and a manual
--     `backend block relock`, safe rather than a double-credit).
--
-- STATUS VALUES
--
--   PENDING -- a run has been claimed for this block but has no
--     recorded outcome. As of this migration the engine cannot leave
--     this behind (the claim and the outcome commit together), so a
--     PENDING row means something outside that transaction wrote it:
--     a hand-written row, or a future multi-transaction payout path.
--     It is treated as the block-payout analog of an AMBIGUOUS
--     `payouts` row (see migrations/0010_payouts_ambiguous_status.up.sql):
--     an UNRESOLVED state that BLOCKS any further automatic payout
--     for that block and requires a human, because "an unknown subset
--     of these miners may already hold this block's credit" is
--     precisely the state that must never be blindly retried.
--     Resolution is manual and explicitly logged -- `backend
--     block-payout resolve-credited` / `resolve-not-credited`, see
--     cmd/backend/blockpayoutcli.go.
--
--   APPLIED -- this block's payout ran to completion. Terminal.
--     Every credit it made is itemised in `block_payout_credits`.
--     ApplyBlockPayout is a no-op for such a block, forever.
--
--   FAILED -- an operator has established that this block's payout
--     credited nothing that still stands (either it never credited,
--     or they reversed the credits by hand). Deliberately RE-CLAIMABLE:
--     ApplyBlockPayout resets a FAILED row back to PENDING and runs
--     normally, so the block flows back into the automatic path. This
--     mirrors `payouts.FAILED`'s established meaning exactly --
--     "provably nothing landed, safe to retry" -- as opposed to
--     PENDING/AMBIGUOUS's "may have landed, human required". FAILED is
--     only ever written by `backend block-payout resolve-not-credited`;
--     the engine never writes it, because an engine-side failure rolls
--     the claim back instead of recording one.
--
-- block_payout_credits
--
-- One row per (block_id, balance_id) the run credited, with the exact
-- amount and the payout-calculation bucket it came from ("fees",
-- "pps", "pplns", "solo" -- payout.Payment.PoolType). This is not
-- bookkeeping nicety, it is what makes the two things above possible:
--
--   - The UNIQUE (block_id, balance_id) constraint is row-level
--     idempotency underneath the block-level claim: ApplyBlockPayout
--     inserts the ledger row FIRST (ON CONFLICT DO NOTHING) and only
--     increments `balance.pending_balance` if that insert actually
--     inserted. So even a caller that somehow got past the claim
--     cannot credit the same (block, payee) twice.
--   - It is the per-miner detail an operator needs to resolve a
--     PENDING row at all. Without it, "which miners already got this
--     block's credit?" is unanswerable and the only safe action is to
--     do nothing forever.
--
-- balance_id (not payment_address/payment_id) is the ledger's join
-- key because `balance` is the row real money is actually held on,
-- and its identity (uq_balance_identity) already collapses the
-- address/payment_id pair the same way the payout calculation does.
--
-- NOTE ON amount: NUMERIC(38, 0), matching `balance.pending_balance`
-- exactly rather than BIGINT, so a recorded credit can never be a
-- value the column it was applied to could hold but this ledger could
-- not.

BEGIN;

CREATE TABLE block_payouts (
    block_id        BIGINT      PRIMARY KEY REFERENCES blocks (id) ON DELETE CASCADE,
    algo            TEXT        NOT NULL CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM')),
    network         TEXT        NOT NULL CHECK (network IN ('MAINNET', 'TESTNET')),
    pool_type       TEXT        NOT NULL CHECK (pool_type IN ('SOLO', 'PPS', 'PPLNS', 'PROP')),
    height          BIGINT      NOT NULL,
    status          TEXT        NOT NULL CHECK (status IN ('PENDING', 'APPLIED', 'FAILED')),
    -- reward is the block reward (blocks.value / the real
    -- chain.VerifyResult.Reward the unlocker observed) this run paid
    -- out against, recorded so a later reconciliation can check the
    -- itemised credits against what was actually being divided up.
    reward          BIGINT      NOT NULL,
    -- credited/total_paid summarise a completed (APPLIED) run: how
    -- many payment entries were credited and their atomic-unit sum.
    -- NULL while PENDING -- a claimed-but-unresolved run has no
    -- trustworthy totals by definition.
    credited        INTEGER,
    total_paid      NUMERIC(38, 0),
    error           TEXT,
    -- resolved_by / resolution_note: who resolved an unresolved
    -- block payout by hand and why, mirroring `payouts`' identical
    -- audit columns (see migrations/0010_payouts_ambiguous_status.up.sql)
    -- and address_flags' banned_by/ban_reason convention before it.
    -- Always NULL for a run the engine completed on its own.
    resolved_by     TEXT,
    resolution_note TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at      TIMESTAMPTZ
);

CREATE INDEX idx_block_payouts_status ON block_payouts (status);

-- Partial index over exactly the unresolved-status predicate the new
-- read paths use (Repository.UnresolvedBlockPayouts, cmd/backend's
-- startup check, `backend block-payout list-unresolved`), so none of
-- them degrades into a full scan of what is a permanent, ever-growing
-- audit table. Mirrors idx_payouts_unresolved's shape.
CREATE INDEX idx_block_payouts_unresolved ON block_payouts (algo, network, block_id)
    WHERE status = 'PENDING';

CREATE TABLE block_payout_credits (
    id              BIGSERIAL   PRIMARY KEY,
    block_id        BIGINT      NOT NULL REFERENCES block_payouts (block_id) ON DELETE CASCADE,
    balance_id      BIGINT      NOT NULL REFERENCES balance (id) ON DELETE CASCADE,
    payment_address TEXT        NOT NULL,
    payment_id      TEXT,
    -- payout_bucket is payout.Payment.PoolType: which calculation
    -- produced this entry ("fees", "pps", "pplns", "solo"). Named
    -- payout_bucket rather than pool_type specifically so it is not
    -- mistaken for the SOLO/PPS/PPLNS/PROP pool_type enum every other
    -- table in this schema uses -- these are different vocabularies.
    payout_bucket   TEXT        NOT NULL,
    amount          NUMERIC(38, 0) NOT NULL,
    credited_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_block_payout_credits_identity
    ON block_payout_credits (block_id, balance_id);
CREATE INDEX idx_block_payout_credits_balance ON block_payout_credits (balance_id);

COMMIT;
