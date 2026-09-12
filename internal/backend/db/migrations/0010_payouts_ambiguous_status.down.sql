-- 0010_payouts_ambiguous_status.down.sql
--
-- Deliberately REFUSES to run while any AMBIGUOUS payout row is still
-- unresolved. Down-migrating such a row would have to either drop the
-- status (violating the restored CHECK constraint) or rewrite it to
-- FAILED -- and FAILED means "provably no coin moved, the balance is
-- safe to pay again next cycle", which is the exact opposite of what
-- AMBIGUOUS records. Silently doing that conversion would re-create
-- the double-payment bug this migration exists to fix, on real money,
-- with no trace. Resolve every AMBIGUOUS row first (`backend payout
-- list-unresolved`, then `backend payout resolve-sent` /
-- `backend payout resolve-not-sent` -- see cmd/backend/payoutcli.go),
-- then re-run this down migration.
--
-- PENDING rows are left alone: PENDING already existed before this
-- migration and its meaning is unchanged by it.

BEGIN;

DO $$
DECLARE
    stuck BIGINT;
BEGIN
    SELECT count(*) INTO stuck FROM payouts WHERE status = 'AMBIGUOUS';
    IF stuck > 0 THEN
        RAISE EXCEPTION 'refusing to down-migrate 0010: % unresolved AMBIGUOUS payout row(s) exist; resolve them via `backend payout resolve-sent` / `backend payout resolve-not-sent` first (rewriting them to FAILED here would make already-broadcast coin payable again -> real double payment)', stuck;
    END IF;
END $$;

DROP INDEX IF EXISTS idx_payouts_unresolved;

ALTER TABLE payouts DROP COLUMN resolution_note;
ALTER TABLE payouts DROP COLUMN resolved_by;
ALTER TABLE payouts DROP COLUMN pending_entries;

ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_status_check;
ALTER TABLE payouts ADD CONSTRAINT payouts_status_check
    CHECK (status IN ('PENDING', 'SENT', 'FAILED'));

COMMIT;
