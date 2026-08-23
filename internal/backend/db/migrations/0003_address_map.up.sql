-- 0003_address_map.up.sql
--
-- Adds `address_map`: the persistence layer for the SXMR
-- merge-mining system's XMR-to-Tari address mapping. SXMR merge-mines
-- Monero (RXM) alongside a Tari-family algo; a miner submits shares
-- under a single Monero payment address, but any Tari-side payout
-- needs a real Tari wallet address to pay to. This table is the
-- durable, queryable mapping the backend consults at Tari-side payout
-- time to resolve "which Tari address does this XMR miner want paid".
--
-- One XMR address maps to exactly one Tari address at a time (see the
-- unique index below) -- a miner can update their mapping (the HTTP
-- endpoint in internal/backend/addressmap performs an upsert), but
-- there is never more than one live Tari destination per XMR address,
-- which is the property the payout path actually needs: an
-- unambiguous single destination per source address, not a history of
-- every value it was ever set to.
--
-- This table is deliberately NOT scoped by algo/network the way
-- shares/blocks/balance are: the XMR address itself (ALGO_RXM) is the
-- lookup key here, and it maps to a Tari destination on whichever
-- Tari-family network this deployment runs (this backend is already
-- constrained to a single network via GCPOOL_NETWORK, so there is no
-- real ambiguity to encode in an extra column).

BEGIN;

CREATE TABLE address_map (
    id           BIGSERIAL PRIMARY KEY,
    xmr_address  TEXT        NOT NULL,
    tari_address TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_address_map_xmr_address ON address_map (xmr_address);

COMMIT;
