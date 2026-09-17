-- 0016_multicoin_algos.down.sql
--
-- Reverses 0016_multicoin_algos.up.sql: drops the new algos' `shares`
-- partitions and narrows every algo CHECK constraint back to the
-- original fixed four (RXT, C29, SHA3X, RXM).
--
-- SAFETY: refuses to run while ANY row anywhere (shares/blocks/
-- miner_identifiers/balance/pools/payouts/block_payouts) still uses one
-- of the seven new algo values -- narrowing the CHECK constraint back
-- down while such a row exists would simply fail with a constraint
-- violation anyway, but dropping the `shares_<algo>` partitions FIRST
-- would silently destroy that algo's share history before the
-- constraint-narrowing step ever got a chance to fail loudly. Real
-- data for a newly-onboarded coin must be manually migrated/archived
-- (or the coin fully decommissioned) before this down migration can
-- run.

BEGIN;

DO $$
DECLARE
    algo_val TEXT;
    cnt      BIGINT;
BEGIN
    FOREACH algo_val IN ARRAY ARRAY['XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL']
    LOOP
        EXECUTE format('SELECT count(*) FROM shares WHERE algo = %L', algo_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0016: % row(s) still exist in shares for algo=%; archive/migrate this data first', cnt, algo_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM blocks WHERE algo = %L', algo_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0016: % row(s) still exist in blocks for algo=%; archive/migrate this data first', cnt, algo_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM miner_identifiers WHERE algo = %L', algo_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0016: % row(s) still exist in miner_identifiers for algo=%; archive/migrate this data first', cnt, algo_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM balance WHERE algo = %L', algo_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0016: % row(s) still exist in balance for algo=%; archive/migrate this data first', cnt, algo_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM pools WHERE algo = %L', algo_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0016: % row(s) still exist in pools for algo=%; archive/migrate this data first', cnt, algo_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM payouts WHERE algo = %L', algo_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0016: % row(s) still exist in payouts for algo=%; archive/migrate this data first', cnt, algo_val;
        END IF;

        EXECUTE format('SELECT count(*) FROM block_payouts WHERE algo = %L', algo_val) INTO cnt;
        IF cnt > 0 THEN
            RAISE EXCEPTION 'refusing to down-migrate 0016: % row(s) still exist in block_payouts for algo=%; archive/migrate this data first', cnt, algo_val;
        END IF;
    END LOOP;
END $$;

DO $$
DECLARE
    algo_val TEXT;
BEGIN
    FOREACH algo_val IN ARRAY ARRAY['XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL']
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %I CASCADE', 'shares_' || lower(algo_val));
    END LOOP;
END $$;

ALTER TABLE shares DROP CONSTRAINT IF EXISTS shares_algo_check;
ALTER TABLE shares ADD CONSTRAINT shares_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM'));

ALTER TABLE blocks DROP CONSTRAINT IF EXISTS blocks_algo_check;
ALTER TABLE blocks ADD CONSTRAINT blocks_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM'));

ALTER TABLE miner_identifiers DROP CONSTRAINT IF EXISTS miner_identifiers_algo_check;
ALTER TABLE miner_identifiers ADD CONSTRAINT miner_identifiers_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM'));

ALTER TABLE balance DROP CONSTRAINT IF EXISTS balance_algo_check;
ALTER TABLE balance ADD CONSTRAINT balance_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM'));

ALTER TABLE pools DROP CONSTRAINT IF EXISTS pools_algo_check;
ALTER TABLE pools ADD CONSTRAINT pools_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM'));

ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_algo_check;
ALTER TABLE payouts ADD CONSTRAINT payouts_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM'));

ALTER TABLE block_payouts DROP CONSTRAINT IF EXISTS block_payouts_algo_check;
ALTER TABLE block_payouts ADD CONSTRAINT block_payouts_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM'));

COMMIT;
