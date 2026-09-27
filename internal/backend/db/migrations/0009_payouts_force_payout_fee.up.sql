-- 0009_payouts_force_payout_fee.up.sql
--
-- Adds `force_payout_fee_atomic` to `payouts`: durable, per-payout-row
-- tracking of how much of that payout's total was collected as the
-- operator-configured GCPOOL_FORCE_PAYOUT_FEE_ATOMIC pool-policy fee
-- (see internal/backend/disburse's doc comment and cmd/backend's
-- GCPOOL_FORCE_PAYOUT_FEE_ATOMIC / --force-payout-fee-atomic config
-- knob) -- this is this repository's chosen home for that fee's
-- durable ledger (a new column on the existing per-transfer `payouts`
-- audit log, see migrations/0002_wallet_disbursements.up.sql's doc
-- comment for that table's established rigor/conventions), rather
-- than a brand new table, since this fee is always collected as part
-- of an existing payouts row and never exists independently of one.
--
-- This column is DISTINCT from and ADDITIVE to `fee` (which already
-- means the real on-chain network fee actually paid to relayers/
-- miners for that transfer -- see disburse.go's runBatch): the
-- force-payout fee is a pool-policy fee charged on top of the real
-- network fee, deducted from the miner's payout amount and credited
-- to pool revenue, never conflated with the real on-chain cost of the
-- transfer itself.
--
-- One `payouts` row can cover several `balance` rows in a single real
-- Transfer batch (see 0002's doc comment), some of which may have
-- been included in that batch solely via force_payout = TRUE (see
-- migrations/0008_balance_force_payout.up.sql) while others in the
-- very same batch qualified normally via the ordinary minPayout
-- threshold -- this column is the SUM, across every row in that one
-- batch, of the per-row force-payout fee actually collected (0 for
-- any row not paid via the force_payout override, and always 0
-- across the board for any deployment that has not opted into this
-- fee at all).
--
-- Default 0 -- mirrors this fee's own "zero means off" convention
-- (GCPOOL_FORCE_PAYOUT_FEE_ATOMIC defaults to 0: no extra fee unless
-- an operator explicitly opts in), and every historical payouts row
-- predating this migration correctly reads back as having collected
-- no force-payout fee.

BEGIN;

ALTER TABLE payouts ADD COLUMN force_payout_fee_atomic NUMERIC(38, 0) NOT NULL DEFAULT 0;

COMMIT;
