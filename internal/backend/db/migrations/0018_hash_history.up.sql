-- 0018_hash_history.up.sql
--
-- Adds `hash_history`: a small, BOUNDED time series of periodic
-- hashrate/network-difficulty samples, replacing legacy worker.js's
-- hash-history feature (see DISPATCH_BRIEF.md for the full legacy
-- ground-truth writeup) with a design that has a real, enforced upper
-- bound on both row count (internal/backend/db.PruneHashHistory,
-- driven by cmd/backend's runHashHistoryPoller) and per-tick
-- cardinality (internal/backend/db.DefaultShareStatsCardinalityCap,
-- already introduced by commit 21df0fb for WorkerShareStatsSince/
-- PoolSourceShareStatsSince and reused as-is here for
-- ActiveMinerHashrates -- see hashhistory.go).
--
-- THIS IS THE ROOT-CAUSE FIX for today's real worker.js OOM: legacy
-- kept a snapshot for literally every miner+worker combination ever
-- seen since process start, in several never-evicted in-process JS
-- maps. This table intentionally has NO unbounded growth path:
-- every row this backend ever writes here is pruned once it ages
-- past the configured retention window (maxPoints * pollInterval,
-- default 480 * 60s = 8h, matching legacy's own real
-- `statsBufferLength` = 480 config value at its own 60s LPUSH
-- cadence), and the set of (payment_address, payment_id, worker)
-- tuples snapshotted on any one poll tick is capped at
-- DefaultShareStatsCardinalityCap (100) rows, not "every miner ever
-- seen."
--
-- One row per (algo, network, scope_type, ...) sample point,
-- scope_type distinguishing what this backend's hash-history poller
-- (cmd/backend's runHashHistoryPoller) is snapshotting:
--
--   'pool_type'          -- one of legacy's 5 pool-wide buckets:
--                         pool_type IN ('SOLO','PPS','PPLNS','PROP')
--                         (mirroring shares.pool_type's own CHECK
--                         values) or the literal 'GLOBAL' pseudo
--                         pool_type (legacy's whole-pool bucket,
--                         computed as its own independent SQL
--                         aggregate over ALL pool_types combined --
--                         see hashhistory.go's PoolTypeShareStatsSince
--                         doc comment -- NOT a Go-side re-addition of
--                         the other four numbers).
--   'miner'               -- one payment_address(+payment_id)'s
--                         hashrate, summed across every worker/rig
--                         that address has active in the sampling
--                         window (legacy's per-address bucket).
--   'worker'              -- one payment_address(+payment_id)+worker
--                         tuple's own hashrate (legacy's
--                         address_workername bucket).
--   'network_difficulty'  -- a snapshot of the REAL chain's own
--                         difficulty at sample time, read from the
--                         already-independently-polled
--                         `network_state` table (see
--                         migrations/0006_network_state.up.sql) --
--                         NOT a new upstream RPC call, just a cheap
--                         read of already-fresh data on the same
--                         60s-default cadence as everything else in
--                         this table.
--
-- pool_type/payment_address/payment_id/worker/hashrate_hs/
-- network_difficulty are all nullable at the column level (a single
-- table shared by 4 differently-shaped scopes has no single row
-- shape that needs every column) but the CHECK constraint below
-- pins down the EXACT non-null column set each scope_type requires,
-- so a caller can never end up with (e.g.) a 'pool_type' row that
-- also carries a payment_address, or a 'miner' row with no
-- hashrate_hs.

BEGIN;

CREATE TABLE hash_history (
    id                 BIGSERIAL PRIMARY KEY,
    algo               TEXT NOT NULL,
    network            TEXT NOT NULL,
    scope_type         TEXT NOT NULL CHECK (scope_type IN ('pool_type', 'miner', 'worker', 'network_difficulty')),

    -- Only set (and required) when scope_type = 'pool_type'. One of
    -- shares.pool_type's own CHECK values, or the literal 'GLOBAL'
    -- pseudo-bucket -- see this migration's own doc comment above.
    pool_type          TEXT,

    -- Only set (and required) when scope_type IN ('miner', 'worker').
    payment_address    TEXT,
    -- Optional even within scope_type IN ('miner', 'worker') --
    -- mirrors shares.payment_id/balance.payment_id's own nullable,
    -- "no payment_id variant" convention elsewhere in this schema.
    payment_id         TEXT,

    -- Only set (and required) when scope_type = 'worker' -- the same
    -- free-text worker/rig identifier as shares.identifier.
    worker             TEXT,

    -- Required for scope_type IN ('pool_type', 'miner', 'worker');
    -- NULL for scope_type = 'network_difficulty' (that scope has no
    -- hashrate figure of its own -- see network_difficulty below).
    hashrate_hs        DOUBLE PRECISION,

    -- Required for scope_type = 'network_difficulty' only; NULL for
    -- every other scope. NUMERIC (not DOUBLE PRECISION) to match
    -- network_state.difficulty's own column type exactly, since this
    -- is a direct point-in-time copy of that column's value (see
    -- internal/backend/db.CurrentNetworkDifficulty).
    network_difficulty NUMERIC,

    sample_time        TIMESTAMPTZ NOT NULL,
    inserted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_hash_history_scope_shape CHECK (
        CASE scope_type
            WHEN 'pool_type' THEN
                pool_type IS NOT NULL AND payment_address IS NULL AND payment_id IS NULL
                AND worker IS NULL AND hashrate_hs IS NOT NULL AND network_difficulty IS NULL
            WHEN 'miner' THEN
                pool_type IS NULL AND payment_address IS NOT NULL AND worker IS NULL
                AND hashrate_hs IS NOT NULL AND network_difficulty IS NULL
            WHEN 'worker' THEN
                pool_type IS NULL AND payment_address IS NOT NULL AND worker IS NOT NULL
                AND hashrate_hs IS NOT NULL AND network_difficulty IS NULL
            WHEN 'network_difficulty' THEN
                pool_type IS NULL AND payment_address IS NULL AND payment_id IS NULL
                AND worker IS NULL AND hashrate_hs IS NULL AND network_difficulty IS NOT NULL
            ELSE FALSE
        END
    )
);

-- Serves every read query in hashhistory.go (PoolTypeHashHistory/
-- MinerHashHistory/NetworkDifficultyHistory all filter on a prefix of
-- this exact column list, ordering by sample_time) -- one composite
-- index rather than one per scope_type, since every read query is
-- always scoped to exactly one scope_type value already (so Postgres
-- only ever has to descend into the matching scope_type's slice of
-- this index).
CREATE INDEX idx_hash_history_lookup ON hash_history (
    algo, network, scope_type, payment_address, payment_id, worker, sample_time DESC
);

-- Serves PruneHashHistory's bounded `DELETE ... WHERE sample_time <
-- $1` sweep -- see hashhistory.go's doc comment for why a plain
-- row-level DELETE (not internal/backend/retention's whole-partition
-- DROP TABLE approach) is the right mechanism for this table.
CREATE INDEX idx_hash_history_sample_time ON hash_history (sample_time);

COMMIT;
