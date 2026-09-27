-- 0011_balance_nonnegative_check.down.sql
BEGIN;
ALTER TABLE balance DROP CONSTRAINT IF EXISTS balance_pending_balance_nonnegative;
COMMIT;
