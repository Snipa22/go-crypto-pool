-- 0017_multicoin_currencies.up.sql
--
-- Widens the `currency` CHECK (currency IN ('XMR', 'XTM')) constraints
-- added by migrations/0014_balance_payouts_currency.up.sql to
-- `balance`, `payouts`, and `block_payout_credits` -- to also accept
-- each of the 7 new standalone monerod-family coins' own tickers
-- (ARQ, XEQ, GRFT, SFX, ZEPH, SAL -- XMR is already accepted, see
-- below) added via internal/coinprofile.Registry and
-- migrations/0016_multicoin_algos.up.sql's algo CHECK widening.
--
-- WHY THIS EXISTS: db.blockPayoutCurrency (internal/backend/db/
-- blockpayout.go) previously hardcoded exactly two outcomes --
-- algo == "RXM" && merge_mine_chain IS NULL -> "XMR", everything else
-- -> "XTM" -- so a matured block on any of these 7 new algos fell
-- into the `else` branch and got silently mislabeled currency="XTM".
-- That code path is fixed by this same change-set to instead consult
-- internal/coinprofile.Registry and return that coin's own Ticker
-- (e.g. an ALGO_ARQ block's currency is "ARQ"). Without this
-- migration, that fix would simply trade a silent mislabeling bug for
-- a loud CHECK-constraint violation on every such CreditBalance/
-- ApplyBlockPayout call -- this migration is what makes the real
-- fix actually work end-to-end.
--
-- NOT a new column, NOT a new table, NOT a change to RXM's existing
-- dual-currency (XMR/XTM) behavior in any way -- purely additive
-- widening of three existing CHECK constraints, mirroring
-- 0016_multicoin_algos.up.sql's own "widen the CHECK, touch nothing
-- else" shape for the algo dimension.
--
-- "XMR" is listed again in each new constraint even though it was
-- already accepted by the 0014 constraint -- this is intentional and
-- harmless (Postgres CHECK (col IN (...)) does not care about
-- duplicate literals in the list), and mirrors db.ValidCurrencies'
-- own deliberate "XMR appears in both the fixed legacy set and
-- coinprofile.Registry" de-duplication note: ALGO_RXM's primary/XMR
-- leg and the new standalone ALGO_XMR coin are two genuinely separate
-- `balance`/`payouts`/`block_payout_credits` rows (disambiguated by
-- the `algo` column, "RXM" vs "XMR"), never merged, that simply share
-- the same currency string by design.
--
-- GREENFIELD, NO BACKFILL: same rationale as 0014_balance_payouts_currency
-- (no existing row anywhere has a currency value this migration would
-- ever need to reconcile) -- a plain DROP/ADD CONSTRAINT is used
-- rather than the NOT VALID / VALIDATE CONSTRAINT two-step 0011 uses
-- for a large, live table.

BEGIN;

ALTER TABLE balance DROP CONSTRAINT IF EXISTS balance_currency_check;
ALTER TABLE balance ADD CONSTRAINT balance_currency_check
    CHECK (currency IN ('XMR', 'XTM', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_currency_check;
ALTER TABLE payouts ADD CONSTRAINT payouts_currency_check
    CHECK (currency IN ('XMR', 'XTM', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

ALTER TABLE block_payout_credits DROP CONSTRAINT IF EXISTS block_payout_credits_currency_check;
ALTER TABLE block_payout_credits ADD CONSTRAINT block_payout_credits_currency_check
    CHECK (currency IN ('XMR', 'XTM', 'ARQ', 'XEQ', 'GRFT', 'SFX', 'ZEPH', 'SAL'));

COMMIT;
