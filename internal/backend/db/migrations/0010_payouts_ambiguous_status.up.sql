-- 0010_payouts_ambiguous_status.up.sql
--
-- Adds the AMBIGUOUS payout status plus the durable per-entry detail
-- and operator-resolution audit columns needed to resolve one by hand.
--
-- WHY THIS EXISTS (money-critical, read this before touching any of
-- it): up to this migration, `payouts` had exactly three statuses (see
-- migrations/0002_wallet_disbursements.up.sql) and
-- internal/backend/disburse treated ANY error out of
-- wallet.WalletClient.Transfer as "definitely no coin moved" ->
-- Repository.FailPayout -> the underlying `balance` rows stay payable
-- -> the very next disbursement cycle sends the SAME coin again. That
-- assumption is false for at least two real, already-present code
-- paths:
--
--   1. monero-wallet-rpc's `transfer` call can legitimately take
--      longer than the wallet RPC HTTP client's timeout while still
--      broadcasting the transaction for real. The client sees a
--      timeout error; the coin is gone; FAILED said otherwise.
--   2. internal/backend/wallet/tari.go's Transfer has an explicit
--      path where the recipient transfer SUCCEEDS (broadcast) but the
--      follow-up GetTransactionInfo fee/amount lookup fails -- the
--      method still returns an error for the whole call.
--
-- Both of those produced a real double payment. So a third,
-- deliberately DISTINCT terminal-ish state is required:
--
--   AMBIGUOUS -> the real Transfer call (or the local bookkeeping
--                write that follows it) failed in a way that CANNOT
--                rule out that real coin already moved on-chain. This
--                is the exact OPPOSITE assumption to FAILED, which is
--                why it must not reuse FAILED: FAILED means "provably
--                nothing happened, safe to retry", AMBIGUOUS means
--                "may have happened, a human must check the chain
--                before anything else is paid for this (algo,
--                network)".
--
-- AMBIGUOUS (like PENDING) is an UNRESOLVED state. Both of them now
-- (a) exclude every `balance` row they reference from
-- Repository.PayableBalances for that (algo, network) (see
-- repository.go), and (b) halt disbursement for that (algo, network)
-- entirely -- both at cycle level inside disburse.Engine.RunOnce and
-- at process startup in cmd/backend (which refuses to even start the
-- disbursement loop for an affected pair). Resolution is a manual,
-- explicitly-logged operator action -- `backend payout resolve-sent`
-- / `backend payout resolve-not-sent`, see cmd/backend/payoutcli.go.
--
-- NEW COLUMNS
--
-- pending_entries JSONB -- the exact per-`balance`-row debit detail
--   for this payout, recorded by RecordPendingPayout BEFORE the real
--   Transfer call, as a JSON array of
--   {"balance_id","amount","force_payout","force_payout_fee_atomic"}
--   objects (mirrors db.DisburseEntry field-for-field). This is NOT
--   redundant with the existing `balance_ids` array or `amount`
--   total: resolving an AMBIGUOUS payout to SENT has to replay the
--   EXACT debit the failed CompletePayoutSent would have performed
--   (per-row full pending_balance, per-row force_payout flag to
--   consume, per-row force-payout fee to bank) and neither
--   balance_ids nor the batch total carries any of that. Re-deriving
--   it from the live `balance` rows at resolution time would be
--   wrong: pending_balance may have accrued MORE since the attempt,
--   and debiting that larger figure would silently overpay the pool
--   against a miner. One JSONB column rather than four parallel
--   arrays (balance_amounts[]/force_payout_flags[]/...) precisely
--   because parallel arrays have no structural guarantee of staying
--   the same length as each other, and a per-entry struct is exactly
--   what this is. Nullable: every historical row predating this
--   migration has no per-entry detail (and cannot be resolved via
--   `resolve-sent` for that reason -- the CLI says so explicitly
--   rather than guessing).
--
-- resolved_by / resolution_note TEXT -- who resolved an unresolved
--   payout by hand and why, mirroring address_flags' banned_by/
--   ban_reason audit convention (see migrations/
--   0004_address_flags.up.sql). Recorded by the `backend payout
--   resolve-*` subcommands; always NULL for a payout the engine
--   resolved on its own.
--
-- NEW INDEX
--
-- idx_payouts_unresolved -- partial index over exactly the
--   unresolved-status predicate the new hot paths use
--   (Repository.UnresolvedPayouts, and PayableBalances' NOT EXISTS
--   anti-join), so neither the startup check nor every disbursement
--   cycle's balance query degrades into a full scan of what is a
--   permanent, ever-growing audit table. The existing
--   idx_payouts_status is deliberately left alone: it covers status
--   alone, this one covers (algo, network) FOR unresolved rows only,
--   which is the actual shape of both new queries.

BEGIN;

ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_status_check;
ALTER TABLE payouts ADD CONSTRAINT payouts_status_check
    CHECK (status IN ('PENDING', 'SENT', 'FAILED', 'AMBIGUOUS'));

ALTER TABLE payouts ADD COLUMN pending_entries JSONB;
ALTER TABLE payouts ADD COLUMN resolved_by TEXT;
ALTER TABLE payouts ADD COLUMN resolution_note TEXT;

CREATE INDEX idx_payouts_unresolved ON payouts (algo, network, id)
    WHERE status IN ('PENDING', 'AMBIGUOUS');

COMMIT;
