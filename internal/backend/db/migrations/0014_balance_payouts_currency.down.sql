-- 0014_balance_payouts_currency.down.sql
--
-- Reverses 0014_balance_payouts_currency.up.sql: drops the `currency`
-- columns (and their CHECK constraints, dropped implicitly along with
-- the column) from `balance`/`payouts`/`block_payout_credits`, and
-- restores `uq_balance_identity` to its pre-migration definition
-- (without `currency`).
--
-- Not safe to run against a database that has ever stored more than
-- one currency for the same (algo, network, payment_address,
-- payment_id) identity: collapsing back to the old, currency-less
-- `uq_balance_identity` would then find two existing `balance` rows
-- claiming the same identity, and the CREATE UNIQUE INDEX below would
-- fail outright (which is the correct, loud failure -- there is no
-- safe automatic way to merge an XMR balance and an XTM balance into
-- one column, since they are not fungible).

BEGIN;

DROP INDEX uq_balance_identity;
CREATE UNIQUE INDEX uq_balance_identity ON balance (
    algo, network, payment_address, COALESCE(payment_id, '')
);

ALTER TABLE block_payout_credits DROP CONSTRAINT IF EXISTS block_payout_credits_currency_check;
ALTER TABLE block_payout_credits DROP COLUMN currency;

ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_currency_check;
ALTER TABLE payouts DROP COLUMN currency;

ALTER TABLE balance DROP CONSTRAINT IF EXISTS balance_currency_check;
ALTER TABLE balance DROP COLUMN currency;

COMMIT;
