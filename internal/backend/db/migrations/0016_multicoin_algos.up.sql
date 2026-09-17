-- 0016_multicoin_algos.up.sql
--
-- Widens every algo CHECK (algo IN (...)) constraint from the original
-- fixed four (RXT, C29, SHA3X, RXM) to also accept the new standalone
-- monerod-family coin algos added via internal/coinprofile.Registry
-- (XMR, ARQ, XEQ, GRFT, SFX, ZEPH, SAL -- see internal/proto/share.proto's
-- Algo enum, values 5-11), and creates the corresponding `shares`
-- LIST-partition-by-algo leaf tables (with their own pool_type
-- sub-partitions and seed block_height bucket) those new algos need
-- before InsertShare can ever write a row for them -- LIST partitioning
-- has no implicit "any other value" fallback, so this was the one
-- genuinely non-generic gap in an otherwise fully-generic, algo-keyed
-- schema (EnsureHeightPartition, the `pools` table's
-- UNIQUE(algo, network, pool_type, name) constraint, and every index in
-- this schema already work for any algo string with zero changes).
--
-- This migration does NOT touch network/pool_type CHECK constraints
-- (unaffected by this dispatch) or RXM's own meaning/behavior in any
-- way -- RXM stays exactly as it always has been; XMR and the other six
-- are purely additive new values.
--
-- NUMBERED 0016 (not 0015): this branch previously carried this file
-- as 0015_multicoin_algos, cut before 0014_balance_payouts_currency.up.sql
-- (real, already-merged on origin/main -- see that migration's own doc
-- comment for what it does and why) had been rebased in here. Renumbered
-- to the next genuinely free slot after both pre-existing 0014_* files
-- (0014_balance_payouts_currency and 0014_block_payout_reversal -- a
-- real, separate duplicate-numbering situation on origin/main today,
-- intentionally left alone by this migration) and 0014_balance_payouts_currency's
-- own currency column/constraint additions to balance/payouts/
-- block_payout_credits, which this migration's algo CHECK widening is
-- layered on top of, not in place of.

BEGIN;

-- ---------------------------------------------------------------------
-- Widen every algo CHECK constraint.
-- ---------------------------------------------------------------------

ALTER TABLE shares DROP CONSTRAINT IF EXISTS shares_algo_check;
ALTER TABLE shares ADD CONSTRAINT shares_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM', 'XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE blocks DROP CONSTRAINT IF EXISTS blocks_algo_check;
ALTER TABLE blocks ADD CONSTRAINT blocks_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM', 'XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE miner_identifiers DROP CONSTRAINT IF EXISTS miner_identifiers_algo_check;
ALTER TABLE miner_identifiers ADD CONSTRAINT miner_identifiers_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM', 'XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE balance DROP CONSTRAINT IF EXISTS balance_algo_check;
ALTER TABLE balance ADD CONSTRAINT balance_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM', 'XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE pools DROP CONSTRAINT IF EXISTS pools_algo_check;
ALTER TABLE pools ADD CONSTRAINT pools_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM', 'XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_algo_check;
ALTER TABLE payouts ADD CONSTRAINT payouts_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM', 'XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE block_payouts DROP CONSTRAINT IF EXISTS block_payouts_algo_check;
ALTER TABLE block_payouts ADD CONSTRAINT block_payouts_algo_check
    CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM', 'XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

-- ---------------------------------------------------------------------
-- New `shares` algo/pool_type/seed-height-bucket leaf partitions for
-- the 7 new algos. Mirrors 0001_initial_schema.up.sql's own DO block
-- exactly (same bucket_size=100000, same naming convention), just
-- scoped to the new algo values only -- the original four already
-- have their partitions from 0001 and must not be touched again here.
-- ---------------------------------------------------------------------

DO $$
DECLARE
    algo_val      TEXT;
    pool_type_val TEXT;
    bucket_size   BIGINT := 100000; -- keep in sync with HeightPartitionBucketSize
    algo_tbl      TEXT;
    pt_tbl        TEXT;
    leaf_tbl      TEXT;
BEGIN
    FOREACH algo_val IN ARRAY ARRAY['XMR', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL']
    LOOP
        algo_tbl := 'shares_' || lower(algo_val);

        EXECUTE format(
            'CREATE TABLE %I PARTITION OF shares FOR VALUES IN (%L) PARTITION BY LIST (pool_type)',
            algo_tbl, algo_val
        );

        FOREACH pool_type_val IN ARRAY ARRAY['SOLO', 'PPS', 'PPLNS', 'PROP']
        LOOP
            pt_tbl := algo_tbl || '_' || lower(pool_type_val);

            EXECUTE format(
                'CREATE TABLE %I PARTITION OF %I FOR VALUES IN (%L) PARTITION BY RANGE (block_height)',
                pt_tbl, algo_tbl, pool_type_val
            );

            -- Seed leaf partition covering height bucket [0, bucket_size).
            leaf_tbl := pt_tbl || '_h' || lpad('0', 12, '0');

            EXECUTE format(
                'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (0) TO (%L)',
                leaf_tbl, pt_tbl, bucket_size
            );
        END LOOP;
    END LOOP;
END $$;

COMMIT;
