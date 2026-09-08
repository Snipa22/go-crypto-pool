-- 0008_balance_force_payout.up.sql
--
-- Adds `force_payout` to `balance`: the real-schema replacement for
-- legacy's POST /user/forcePayment, which pushed an address onto a
-- Redis `earlyPayout` queue for a separate payout worker to consume.
-- There is no Redis in this stack (see brief-auth.md's resolved
-- ticket decision) -- this column is the reshaped equivalent: a
-- durable, per-balance-row boolean flag that
-- internal/backend/disburse's engine can pick up as a priority
-- signal on its next cycle.
--
-- NOTE: this migration only adds the column and the
-- internal/backend/authapi endpoint that sets it (see
-- Repository.SetForcePayout) -- internal/backend/disburse.Engine
-- itself is NOT modified in this change to actually treat
-- force_payout = TRUE as a priority signal ahead of the normal
-- PayableBalances threshold check. That consumption logic is a
-- separate, explicitly out-of-scope follow-up (see brief-auth.md).
--
-- Default FALSE for every existing row -- this is purely an opt-in
-- signal an operator/miner sets going forward, never inferred from
-- existing balance state.

BEGIN;

ALTER TABLE balance ADD COLUMN force_payout BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;
