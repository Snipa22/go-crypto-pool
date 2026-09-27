-- 0013_block_payouts.down.sql
--
-- Deliberately REFUSES to run while any PENDING block_payouts row is
-- still unresolved. A PENDING row means an unknown subset of that
-- block's miners may already hold its credit; dropping these tables
-- would destroy `block_payout_credits` -- the ONLY record of which
-- miners those are -- and simultaneously remove the claim that stops
-- the unlocker from re-running (and so double-crediting) that block's
-- payout on its very next poll pass. Resolve every PENDING row first
-- (`backend block-payout list-unresolved`, then `backend block-payout
-- resolve-credited` / `resolve-not-credited` -- see
-- cmd/backend/blockpayoutcli.go), then re-run this down migration.
--
-- APPLIED rows are allowed to go: dropping them loses the audit
-- itemisation but cannot cause a double credit on its own, because
-- down-migrating also removes every code path that reads the ledger.
-- Note, though, that re-applying 0013 afterwards starts from an empty
-- ledger, so any block still sitting at valid=TRUE/unlocked=FALSE
-- would be paid out again from scratch.

BEGIN;

DO $$
DECLARE
    stuck BIGINT;
BEGIN
    SELECT count(*) INTO stuck FROM block_payouts WHERE status = 'PENDING';
    IF stuck > 0 THEN
        RAISE EXCEPTION 'refusing to down-migrate 0013: % unresolved PENDING block_payouts row(s) exist; resolve them via `backend block-payout resolve-credited` / `resolve-not-credited` first (dropping these tables would destroy the only record of which miners already got credited AND un-block the automatic re-run -> real double credit)', stuck;
    END IF;
END $$;

DROP TABLE IF EXISTS block_payout_credits;
DROP TABLE IF EXISTS block_payouts;

COMMIT;
