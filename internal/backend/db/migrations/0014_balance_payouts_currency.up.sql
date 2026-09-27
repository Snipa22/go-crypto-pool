-- 0014_balance_payouts_currency.up.sql
--
-- Adds `currency TEXT NOT NULL CHECK (currency IN ('XMR', 'XTM'))` to
-- `balance`, `payouts`, and `block_payout_credits`.
--
-- WHY THIS EXISTS (money-critical, read this before touching any of
-- it): `balance`/`payouts`/`block_payout_credits` have never carried
-- a currency column, because for ALGO_RXT/ALGO_C29/ALGO_SHA3X that
-- was never ambiguous -- every one of those algos is mined solely
-- against the Tari base node and pays out in exactly one coin, XTM.
-- ALGO_RXM breaks that assumption for real: it is Monero, merge-mined
-- with Tari (see migrations/0012_blocks_merge_mine_chain.up.sql's own
-- doc comment for the full merge-mine mechanism). ONE PoW submission
-- from an RXM miner can independently clear the primary chain's
-- (Monero) real difficulty target, the merge-mined chain's (Tari)
-- real difficulty target, or both -- two independent,
-- independently-verifiable/maturable/payable events, tracked today as
-- two separate `blocks` rows distinguished by `merge_mine_chain`
-- (NULL = primary/Monero leg, `'TARI'` = secondary/Tari leg). A real
-- RXM miner therefore genuinely earns AND is owed a balance in BOTH
-- XMR and XTM simultaneously, and this schema had no way to represent
-- that: a single `balance` row per (algo, network, payment_address,
-- payment_id) could only ever hold one number, silently commingling
-- what are, on-chain, two completely independent wallets with
-- independent failure domains (internal/backend/wallet routes RXM to
-- moneroWalletClient only -- cmd/backend/main.go had no Tari-side
-- wallet target for RXM at all before this change).
--
-- Confirmed against real production data (SupportXMR's live DB,
-- read-only inspection 2026-09-16): that pool already tracks a
-- miner's XMR-side balance and Tari-side balance as two genuinely
-- separate numbers, in separate storage, today (MySQL for XMR, a
-- Postgres "added" layer for Tari). This migration brings this
-- schema's own `balance`/`payouts`/`block_payout_credits` up to that
-- same real requirement, cleanly, as a first-class column -- not a
-- migration-tool workaround bolted on beside the real schema.
--
-- SCOPE: deliberately NOT added to `block_payouts`. That table
-- already carries the real leg discriminator transitively, via its
-- `block_id` FK to `blocks` and that row's own `merge_mine_chain`
-- column -- adding a second, independently-settable currency column
-- to `block_payouts` would let the two disagree with nothing to stop
-- it, which is exactly the kind of redundant-and-driftable state this
-- codebase avoids elsewhere (see e.g. why `block_payout_credits`
-- below derives its own `currency` from the same source rather than
-- accepting one as a parameter). Likewise not added to `shares` or
-- `blocks` themselves -- `blocks.merge_mine_chain` already IS the
-- authoritative leg marker those tables need, and `shares` rows are
-- never currency-denominated (they are hash/difficulty-weighted work
-- units, converted to a currency amount only once payout.Calculator
-- runs).
--
-- GREENFIELD, NO BACKFILL: this schema has no production data yet
-- (no migrations/*.up.sql anywhere seeds a real row via INSERT --
-- confirmed by inspection), so there is no historical row whose real
-- currency needs to be inferred/backfilled. Each column below is
-- therefore added as NOT NULL with a temporary DEFAULT ('XTM' --
-- correct for every historical RXT/C29/SHA3X row, and for the RXM
-- primary/Monero leg once real traffic starts this will simply never
-- read the default at all, since every future INSERT states its own
-- currency explicitly -- see internal/backend/db.CreditBalance et
-- al.), immediately dropped by a follow-up ALTER COLUMN ... DROP
-- DEFAULT statement so no INSERT can ever again omit currency and
-- silently get XTM by accident. This is deliberately NOT the
-- NOT VALID / VALIDATE CONSTRAINT two-step migration 0011 uses for
-- `balance_pending_balance_nonnegative`: that pattern exists
-- specifically to avoid a long ACCESS EXCLUSIVE lock while validating
-- a CHECK constraint against a large, LIVE table's EXISTING rows.
-- With zero existing rows in any of these three tables, that concern
-- does not apply -- the ADD COLUMN/ADD CONSTRAINT statements below
-- are effectively instant regardless of locking strategy, so the
-- simpler single-pass approach is used instead.
--
-- uq_balance_identity: dropped and recreated to include `currency` in
-- the key, ordered right after `network` (mirroring `algo, network`
-- already being the coin/deployment-scoping prefix) and before
-- `payment_address`/`payment_id` (the payee-scoping suffix). This is
-- the whole point of the migration: it is what lets the SAME
-- (algo, network, payment_address, payment_id) identity legitimately
-- hold two rows -- one `currency='XMR'`, one `currency='XTM'` -- for
-- ALGO_RXM, while still refusing a genuine duplicate (same tuple,
-- same currency) exactly as before.
--
-- `payouts.currency`/`block_payout_credits.currency` do NOT get their
-- own uniqueness change -- neither table's existing uniqueness
-- constraints (`payouts` has none beyond its surrogate id;
-- `block_payout_credits` keys `uq_block_payout_credits_identity` on
-- (block_id, balance_id), and balance_id already fully disambiguates
-- currency via `balance`'s own identity) needs it. Both new columns
-- exist purely so a `payouts`/`block_payout_credits` row states,
-- durably and independently queryable, which currency's wallet/ledger
-- it belongs to -- see internal/backend/disburse's per-(algo,
-- network, currency) halt scoping and internal/backend/db/
-- blockpayout.go's derivation of `block_payout_credits.currency` from
-- the parent block's own `merge_mine_chain` for the money-critical
-- reasons this matters.

BEGIN;

ALTER TABLE balance ADD COLUMN currency TEXT NOT NULL DEFAULT 'XTM';
ALTER TABLE balance ALTER COLUMN currency DROP DEFAULT;
ALTER TABLE balance ADD CONSTRAINT balance_currency_check CHECK (currency IN ('XMR', 'XTM'));

ALTER TABLE payouts ADD COLUMN currency TEXT NOT NULL DEFAULT 'XTM';
ALTER TABLE payouts ALTER COLUMN currency DROP DEFAULT;
ALTER TABLE payouts ADD CONSTRAINT payouts_currency_check CHECK (currency IN ('XMR', 'XTM'));

ALTER TABLE block_payout_credits ADD COLUMN currency TEXT NOT NULL DEFAULT 'XTM';
ALTER TABLE block_payout_credits ALTER COLUMN currency DROP DEFAULT;
ALTER TABLE block_payout_credits ADD CONSTRAINT block_payout_credits_currency_check CHECK (currency IN ('XMR', 'XTM'));

DROP INDEX uq_balance_identity;
CREATE UNIQUE INDEX uq_balance_identity ON balance (
    algo, network, currency, payment_address, COALESCE(payment_id, '')
);

COMMIT;
