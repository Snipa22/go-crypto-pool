-- 0017_multicoin_currencies.down.sql
--
-- Reverses 0017_multicoin_currencies.up.sql: narrows the `currency`
-- CHECK constraints on `balance`/`payouts`/`block_payout_credits`
-- back down to exactly ('XMR', 'XTM').
--
-- SAFETY: mirrors 0016_multicoin_algos.down.sql's own guard exactly
-- -- refuses to run while ANY row in any of the three affected tables
-- still uses one of the 6 newly-accepted currency values (ARQ, XEQ,
-- GRFT, SFX, ZEPH, SAL). Narrowing the CHECK constraint back down
-- while such a row exists would simply fail with a constraint
-- violation anyway, but failing loudly and explicitly here (rather
-- than via a bare, less legible ALTER TABLE error) tells an operator
-- exactly which table/currency still has real data blocking the
-- rollback.

BEGIN;

DO $$
DECLARE
    currency_val TEXT;
    cnt          BIGINT;
BEGIN
    FOREACH currency_val IN ARRAY ARRAY['ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL']
    LOOP
        EXECUTE format('SELECT count(*) FROM balance WHERE currency = %L', currency_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0017: % row(s) still exist in balance for currency=%; archive/migrate this data first', cnt, currency_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM payouts WHERE currency = %L', currency_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0017: % row(s) still exist in payouts for currency=%; archive/migrate this data first', cnt, currency_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM block_payout_credits WHERE currency = %L', currency_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0017: % row(s) still exist in block_payout_credits for currency=%; archive/migrate this data first', cnt, currency_val;
        END IF;
    END LOOP;
END $$;

ALTER TABLE balance DROP CONSTRAINT IF EXISTS balance_currency_check;
ALTER TABLE balance ADD CONSTRAINT balance_currency_check
    CHECK (currency IN ('XMR', 'XTM'));

ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_currency_check;
ALTER TABLE payouts ADD CONSTRAINT payouts_currency_check
    CHECK (currency IN ('XMR', 'XTM'));

ALTER TABLE block_payout_credits DROP CONSTRAINT IF EXISTS block_payout_credits_currency_check;
ALTER TABLE block_payout_credits ADD CONSTRAINT block_payout_credits_currency_check
    CHECK (currency IN ('XMR', 'XTM'));

COMMIT;
