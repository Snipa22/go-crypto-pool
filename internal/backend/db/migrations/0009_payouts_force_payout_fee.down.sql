-- 0009_payouts_force_payout_fee.down.sql
BEGIN;
ALTER TABLE payouts DROP COLUMN force_payout_fee_atomic;
COMMIT;
