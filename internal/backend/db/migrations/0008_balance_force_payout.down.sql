-- 0008_balance_force_payout.down.sql
BEGIN;
ALTER TABLE balance DROP COLUMN force_payout;
COMMIT;
