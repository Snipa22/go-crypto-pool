-- 0001_initial_schema.up.sql
--
-- Initial Postgres schema for the go-crypto-pool backend.
--
-- Design summary (see internal/backend/db/README.md for the full writeup):
--   - `shares` is a three-level DECLARATIVE PARTITION hierarchy:
--       algo (LIST) -> pool_type (LIST) -> block_height (RANGE)
--     The algo/pool_type levels are enumerated statically below (they mirror
--     the fixed Algo/PoolType enums in internal/proto/share.proto and don't
--     change without a proto change). The block_height RANGE leaf
--     partitions are intentionally NOT fully enumerated here — this
--     migration only creates the first bucket ([0, <bucket size>)) per
--     algo/pool_type so the schema is immediately usable. All subsequent
--     height-range partitions are created on demand by
--     internal/backend/db.EnsureHeightPartition, using the same bucket-size
--     constant (internal/backend/db.HeightPartitionBucketSize). This keeps
--     the bucket size a single tunable Go constant instead of baked-in SQL.
--   - `blocks` is a plain, unpartitioned, permanent table. No retention.
--   - Retention for `shares` is implemented as a partition-drop operation
--     (internal/backend/db.DropOldPartitions), never row-by-row DELETE. Not
--     wired into a scheduler yet — see README.
--
-- Bucket size used for the seed partitions below: 100000. This MUST match
-- internal/backend/db.HeightPartitionBucketSize. It is a placeholder
-- default only, not tuned against real testnet volume yet.

BEGIN;

-- ---------------------------------------------------------------------
-- shares: algo -> pool_type -> block_height range
-- ---------------------------------------------------------------------

CREATE TABLE shares (
    id              BIGINT GENERATED ALWAYS AS IDENTITY,
    algo            TEXT        NOT NULL CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM')),
    network         TEXT        NOT NULL CHECK (network IN ('MAINNET', 'TESTNET')),
    pool_type       TEXT        NOT NULL CHECK (pool_type IN ('SOLO', 'PPS', 'PPLNS', 'PROP')),
    pool_id         INTEGER     NOT NULL,
    block_height    BIGINT      NOT NULL,
    shares          BIGINT      NOT NULL,
    payment_address TEXT        NOT NULL,
    payment_id      TEXT,
    found_block     BOOLEAN     NOT NULL DEFAULT FALSE,
    block_diff      BIGINT      NOT NULL DEFAULT 0,
    share_timestamp BIGINT      NOT NULL, -- Share.timestamp from the wire proto (unix, leaf-assigned)
    identifier      TEXT        NOT NULL, -- worker/rig identifier
    trusted_share   BOOLEAN     NOT NULL DEFAULT FALSE,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, algo, pool_type, block_height)
) PARTITION BY LIST (algo);

CREATE INDEX idx_shares_payment_address ON shares (payment_address);
CREATE INDEX idx_shares_identifier ON shares (identifier);
CREATE INDEX idx_shares_share_timestamp ON shares (share_timestamp);
CREATE INDEX idx_shares_found_block ON shares (found_block) WHERE found_block;

-- Second level (pool_type) and third level (block_height range, seed
-- bucket only) are generated for every algo x pool_type combination so we
-- don't hand-write 16 near-identical DDL blocks. This is a one-time
-- migration-time loop, not a runtime code path.
DO $$
DECLARE
    algo_val      TEXT;
    pool_type_val TEXT;
    bucket_size   BIGINT := 100000; -- keep in sync with HeightPartitionBucketSize
    algo_tbl      TEXT;
    pt_tbl        TEXT;
    leaf_tbl      TEXT;
BEGIN
    FOREACH algo_val IN ARRAY ARRAY['RXT', 'C29', 'SHA3X', 'RXM']
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
            -- Naming convention: <parent>_h<bucket_start_padded>.
            -- EnsureHeightPartition (Go) follows the exact same convention
            -- for every subsequent bucket.
            leaf_tbl := pt_tbl || '_h' || lpad('0', 12, '0');

            EXECUTE format(
                'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (0) TO (%L)',
                leaf_tbl, pt_tbl, bucket_size
            );
        END LOOP;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- blocks: plain, unpartitioned, permanent table
-- ---------------------------------------------------------------------

CREATE TABLE blocks (
    id             BIGSERIAL PRIMARY KEY,
    algo           TEXT        NOT NULL CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM')),
    network        TEXT        NOT NULL CHECK (network IN ('MAINNET', 'TESTNET')),
    pool_type      TEXT        NOT NULL CHECK (pool_type IN ('SOLO', 'PPS', 'PPLNS', 'PROP')),
    hash           TEXT        NOT NULL,
    height         BIGINT      NOT NULL,
    difficulty     BIGINT      NOT NULL,
    shares         BIGINT      NOT NULL,
    block_timestamp BIGINT     NOT NULL, -- Block.timestamp from the wire proto
    unlocked       BOOLEAN     NOT NULL DEFAULT FALSE,
    valid          BOOLEAN     NOT NULL DEFAULT TRUE,
    value          BIGINT,
    inserted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_blocks_height ON blocks (height);
CREATE INDEX idx_blocks_algo ON blocks (algo);
CREATE INDEX idx_blocks_algo_pool_type ON blocks (algo, pool_type);
CREATE UNIQUE INDEX uq_blocks_algo_network_hash ON blocks (algo, network, hash);

-- ---------------------------------------------------------------------
-- miner_identifiers: coin-agnostic miner/worker registry
-- ---------------------------------------------------------------------

CREATE TABLE miner_identifiers (
    id              BIGSERIAL PRIMARY KEY,
    algo            TEXT        NOT NULL CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM')),
    network         TEXT        NOT NULL CHECK (network IN ('MAINNET', 'TESTNET')),
    payment_address TEXT        NOT NULL,
    payment_id      TEXT,
    worker_name     TEXT        NOT NULL DEFAULT '',
    last_share      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_miner_identifiers_identity ON miner_identifiers (
    algo, network, payment_address, COALESCE(payment_id, ''), worker_name
);
CREATE INDEX idx_miner_identifiers_address ON miner_identifiers (payment_address);

-- ---------------------------------------------------------------------
-- balance: per-miner balance, with an explicit algo/network discriminator
-- (the gap flagged in the SXMR legacy schema review)
-- ---------------------------------------------------------------------

CREATE TABLE balance (
    id              BIGSERIAL PRIMARY KEY,
    algo            TEXT        NOT NULL CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM')),
    network         TEXT        NOT NULL CHECK (network IN ('MAINNET', 'TESTNET')),
    payment_address TEXT        NOT NULL,
    payment_id      TEXT,
    pending_balance NUMERIC(38, 0) NOT NULL DEFAULT 0,
    paid_balance    NUMERIC(38, 0) NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_balance_identity ON balance (
    algo, network, payment_address, COALESCE(payment_id, '')
);

-- ---------------------------------------------------------------------
-- pools / ports: basic pool + listener configuration
-- ---------------------------------------------------------------------

CREATE TABLE pools (
    id         SERIAL PRIMARY KEY,
    algo       TEXT        NOT NULL CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM')),
    network    TEXT        NOT NULL CHECK (network IN ('MAINNET', 'TESTNET')),
    pool_type  TEXT        NOT NULL CHECK (pool_type IN ('SOLO', 'PPS', 'PPLNS', 'PROP')),
    name       TEXT        NOT NULL,
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (algo, network, pool_type, name)
);

CREATE TABLE ports (
    id             SERIAL PRIMARY KEY,
    pool_id        INTEGER     NOT NULL REFERENCES pools (id) ON DELETE CASCADE,
    port           INTEGER     NOT NULL,
    description    TEXT        NOT NULL DEFAULT '',
    min_difficulty BIGINT      NOT NULL DEFAULT 1,
    max_difficulty BIGINT,
    start_difficulty BIGINT    NOT NULL DEFAULT 1,
    variable_diff  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (pool_id, port)
);

COMMIT;
