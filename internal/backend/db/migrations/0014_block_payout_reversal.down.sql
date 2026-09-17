-- 0014_block_payout_reversal.down.sql
--
-- Reverts migration 0014: narrows block_payouts.status back to
-- PENDING/APPLIED/FAILED and drops block_payout_credits.reversed_at.
--
-- Deliberately REFUSES while any `block_payouts` row is REVERSED, for
-- the same class of reason migration 0013's down migration refuses
-- while any row is PENDING: narrowing the status CHECK constraint
-- back down would immediately fail anyway (a REVERSED row would
-- violate the narrower constraint the moment Postgres tries to
-- validate it), but this raises a clear, specific explanation instead
-- of a generic constraint-violation error, and does so BEFORE
-- touching `block_payout_credits.reversed_at` -- the itemised record
-- of exactly what a reversal debited back, which dropping that column
-- would destroy. Resolve this by first confirming no REVERSED block
-- payout still needs that column's detail (there is deliberately no
-- "un-reverse" operation -- a REVERSED block is not a real block, see
-- migration 0014's up-side doc comment), then re-run this migration.

BEGIN;

DO $$
DECLARE
    reversed_count BIGINT;
BEGIN
    SELECT count(*) INTO reversed_count FROM block_payouts WHERE status = 'REVERSED';
    IF reversed_count > 0 THEN
        RAISE EXCEPTION 'refusing to down-migrate 0014: % block_payouts row(s) are REVERSED; narrowing the status CHECK constraint back to PENDING/APPLIED/FAILED would corrupt those rows (a REVERSED block must never be representable as APPLIED/re-payable again), and dropping block_payout_credits.reversed_at would destroy the only itemised record of what each reversal actually debited', reversed_count;
    END IF;
END $$;

ALTER TABLE block_payouts DROP CONSTRAINT IF EXISTS block_payouts_status_check;
ALTER TABLE block_payouts ADD CONSTRAINT block_payouts_status_check
    CHECK (status IN ('PENDING', 'APPLIED', 'FAILED'));

ALTER TABLE block_payout_credits DROP COLUMN IF EXISTS reversed_at;

COMMIT;
