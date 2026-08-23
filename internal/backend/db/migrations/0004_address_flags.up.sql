-- 0004_address_flags.up.sql
--
-- Adds `address_flags`: the persistence layer for two REAL,
-- operator-driven (manual, not automated-detection) miner-address
-- controls:
--
--   1. Ban -- an operator has independently determined (abuse report,
--      TOS violation, fraud investigation, chargeback, whatever the
--      real-world reason is) that a payment address should have every
--      further share it submits rejected outright. This is a hard
--      stop at ingestion time, enforced in Repository.InsertShare
--      (see repository.go) -- a banned address's shares never reach
--      the `shares` table at all, so they can never accrue balance,
--      count toward a block find, or otherwise affect payout.
--
--   2. Forced minimum difficulty -- an operator has independently
--      decided a payment address must submit shares at or above a
--      floor difficulty (e.g. a known low-diff-dust/DoS-shaped
--      submitter, or a large known miner who should be riding a
--      higher fixed floor regardless of what vardiff would otherwise
--      converge to). Enforced the same way: InsertShare rejects any
--      share whose block_diff is below the configured floor. This is
--      NOT the same mechanism as internal/leaflib's per-session
--      vardiff retargeting (which is automatic, client-side, and
--      algorithmic) -- this is a backend-enforced floor that exists
--      independently of whatever difficulty the leaf/miner session
--      itself negotiated, and it is set by a human operator via the
--      `backend address force-difficulty` CLI (see
--      cmd/backend/addresscli.go), never by any automated heuristic.
--
-- Both controls are keyed on payment_address alone (not scoped by
-- algo/network the way shares/miner_identifiers are) -- an operator
-- flagging a real-world bad actor's address wants that flag to apply
-- regardless of which algo/network stream they show up on next,
-- since the judgement call being encoded here is about the address
-- itself, not about one particular share stream.
--
-- Both are OFF by default for every address (no row = not banned, no
-- forced floor) -- this table only ever holds addresses an operator
-- has explicitly acted on.

BEGIN;

CREATE TABLE address_flags (
    id                     BIGSERIAL PRIMARY KEY,
    payment_address        TEXT        NOT NULL,

    banned                 BOOLEAN     NOT NULL DEFAULT FALSE,
    ban_reason             TEXT,
    banned_at              TIMESTAMPTZ,
    banned_by              TEXT,

    -- NULL = no forced floor. When set, must be > 0 -- a floor of 0
    -- (or negative) is not a real difficulty floor, it's a no-op, so
    -- the CLI/repository clear the row's floor back to NULL instead
    -- of ever writing a non-positive value here.
    forced_min_difficulty  BIGINT,
    difficulty_reason      TEXT,
    difficulty_set_at      TIMESTAMPTZ,
    difficulty_set_by      TEXT,

    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_address_flags_forced_min_difficulty_positive
        CHECK (forced_min_difficulty IS NULL OR forced_min_difficulty > 0)
);

CREATE UNIQUE INDEX uq_address_flags_payment_address ON address_flags (payment_address);

-- Ops-facing "show me everyone currently flagged" queries (the
-- `backend address list` CLI subcommand) filter on these two columns;
-- partial indexes keep that query cheap even once this table holds a
-- large number of historical (now-cleared) rows.
CREATE INDEX idx_address_flags_banned ON address_flags (payment_address) WHERE banned = TRUE;
CREATE INDEX idx_address_flags_forced_min_difficulty ON address_flags (payment_address) WHERE forced_min_difficulty IS NOT NULL;

COMMIT;
