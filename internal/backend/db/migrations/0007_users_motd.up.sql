-- 0007_users_motd.up.sql
--
-- Adds `users` and `motd`: the persistence layer for
-- internal/backend/authapi (SXMR-legacy /authenticate + /authed/* +
-- /user/* routes) and internal/backend/legacyconfig's GET /pool/motd,
-- ported from the legacy Node.js nodejs-pool-upgrade `lib/api.js`'s
-- MySQL `users`/`motd` tables (see brief-auth.md's ground-truth
-- transcription for the exact field names/behavior these mirror).
--
-- `users` is keyed on `username`, which -- per the legacy schema -- IS
-- the miner's payment address (there is no separate registration
-- flow; a miner's first authenticated action against this address
-- implicitly "creates" their account, see
-- Repository.UpsertUserThreshold). `pass` is nullable: a user with no
-- password set can never authenticate via POST /authenticate (see
-- authapi's package doc comment for the deliberate, stated deviation
-- from legacy's NULL/email-fallback quirk here).

BEGIN;

CREATE TABLE users (
    id                BIGSERIAL PRIMARY KEY,
    username          TEXT        NOT NULL,
    email             TEXT        NOT NULL DEFAULT '',
    pass              TEXT,
    admin             BOOLEAN     NOT NULL DEFAULT FALSE,
    enable_email      BOOLEAN     NOT NULL DEFAULT FALSE,
    payout_threshold  BIGINT      NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_users_username ON users (username);

-- `motd`: single-newest-row-wins message-of-the-day, matching legacy's
-- own query shape exactly (`select created, subject, body, type,
-- active from motd order by id desc limit 1`, see
-- legacyconfig.Handler.handleMotd). No caching layer here -- see that
-- handler's doc comment for why a plain per-request query is a
-- deliberate, stated simplification versus legacy's in-process TTL
-- cache.
CREATE TABLE motd (
    id      BIGSERIAL PRIMARY KEY,
    created TIMESTAMPTZ NOT NULL DEFAULT now(),
    subject TEXT        NOT NULL DEFAULT '',
    body    TEXT        NOT NULL DEFAULT '',
    type    TEXT        NOT NULL DEFAULT '',
    active  BOOLEAN     NOT NULL DEFAULT FALSE
);

COMMIT;
