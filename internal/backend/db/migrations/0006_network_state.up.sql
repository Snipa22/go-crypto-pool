-- 0006_network_state.up.sql
--
-- Adds `network_state`: the persistence layer for internal/backend/
-- networkpoller's real, live poll loop -- periodically querying the
-- REAL upstream node/daemon for each configured (algo, network) this
-- backend cares about (a real Tari base node GRPC GetTipInfo/
-- GetNetworkState call for RXT/C29/SHA3X, a real monerod JSON-RPC
-- get_info call for RXM) and recording the chain's OWN, actual
-- height/difficulty/estimated-network-hashrate here.
--
-- This is deliberately a SEPARATE, independent figure from
-- `shares`-derived pool-local hashrate (internal/backend/networkapi's
-- existing NetworkStatsSince aggregate): that number answers "how
-- much difficulty-weighted work has THIS POOL's own miners submitted
-- recently" -- it says nothing about the actual state of the real
-- network those miners are competing against. This table is the
-- other half: "what is the REAL chain doing right now" -- e.g. so a
-- public pool-stats page can render "this pool: 4.2 MH/s | network:
-- 850 MH/s" instead of implying the pool-local figure IS the network
-- figure (subsystem gap audit items 2+4).
--
-- Exactly one row per (algo, network) -- this table is a rolling
-- "latest known real state" snapshot, not a time series (that's what
-- a real external metrics/TSDB scraping GET /metrics would be for,
-- see internal/backend/metrics's NetworkPoller* gauges instead) --
-- so every poll pass UPSERTs (see db/network.go's
-- UpsertNetworkState), never INSERTs a new row.

BEGIN;

CREATE TABLE network_state (
    id                      BIGSERIAL PRIMARY KEY,
    algo                    TEXT             NOT NULL,
    network                 TEXT             NOT NULL,

    -- The real chain's own current tip height, as reported live by
    -- the queried node/daemon at poll time -- NOT this pool's last
    -- accepted/found block height.
    height                  BIGINT           NOT NULL,

    -- The real chain's own current difficulty, as reported live by
    -- the queried node/daemon. NULL when the queried protocol call
    -- for this algo does not cleanly resolve a single per-algo
    -- difficulty at poll time (see internal/backend/networkpoller's
    -- Tari source doc comment -- Tari's three merge-mined PoW algos
    -- do not all resolve to one clean per-algo figure from a single
    -- RPC call the way Monero's get_info does) rather than a
    -- fabricated/guessed value.
    difficulty              NUMERIC,

    -- The real chain-wide estimated network hashrate in H/s, as
    -- reported live by the queried node/daemon (Tari:
    -- GetNetworkState's real per-algo estimated_hash_rate field;
    -- Monero: derived from the real live get_info difficulty/
    -- target fields via the standard hashrate = difficulty / target
    -- -seconds formula). This is the number a pool-stats page should
    -- show as "network hashrate" -- see this table's own doc comment
    -- for why it is kept separate from any pool-local estimate.
    estimated_hashrate_hs   DOUBLE PRECISION,

    best_block_hash         TEXT,

    -- Free-text identifier of which live source produced this row
    -- (e.g. "tari_grpc", "monero_rpc") -- purely for operational
    -- diagnostics/debugging, never parsed by any reader.
    source                  TEXT             NOT NULL,

    polled_at               TIMESTAMPTZ      NOT NULL,
    updated_at              TIMESTAMPTZ      NOT NULL DEFAULT now(),

    CONSTRAINT chk_network_state_height_nonnegative CHECK (height >= 0)
);

CREATE UNIQUE INDEX uq_network_state_algo_network ON network_state (algo, network);

COMMIT;
