-- 0011_balance_nonnegative_check.up.sql
--
-- Adds `CHECK (pending_balance >= 0)` to `balance`. Per
-- PROD_HARDENING_REVIEW.md finding #20: there was previously no
-- database-level guard against a double-debit bug (or any other
-- application-level bug that computes a debit larger than a row's
-- current pending_balance) driving a miner's balance negative --
-- Repository.completePayoutSent's own
-- `SET pending_balance = pending_balance - $2` (see repository.go)
-- would happily write a negative value with nothing to stop it. A
-- real-money accounting invariant like this should fail LOUDLY at
-- the database level the moment it is violated, not silently
-- corrupt a balance row.
--
-- NOT VALID + a separate VALIDATE CONSTRAINT statement: adding a
-- CHECK constraint on a large, live table normally takes an
-- ACCESS EXCLUSIVE lock for the full duration of the initial
-- validation scan (checking every existing row). NOT VALID skips
-- that up-front scan (only a brief lock to add the constraint
-- definition itself, immediately enforced for every NEW write from
-- this point on), and the follow-up VALIDATE CONSTRAINT performs the
-- existing-row scan separately using a much weaker lock that does not
-- block concurrent reads/writes -- the standard safe-migration
-- pattern for adding a CHECK constraint to a table that must stay
-- online. If any existing row already violates this (which would
-- itself be evidence of the exact bug class this constraint exists
-- to catch), VALIDATE CONSTRAINT fails loudly and this migration
-- aborts rather than silently accepting corrupt data -- an operator
-- would need to manually investigate/fix that row before this
-- migration could complete, which is the correct outcome.
--
-- `paid_balance` deliberately gets NO such constraint here: unlike
-- pending_balance (debited on every real payout, so a bug here is
-- exactly the double-debit scenario this exists to catch),
-- paid_balance is only ever incremented (see completePayoutSent),
-- so there is no equivalent debit-bug risk to guard against, and
-- scope here is kept to the one column the audit finding actually
-- named.

BEGIN;

ALTER TABLE balance
    ADD CONSTRAINT balance_pending_balance_nonnegative
    CHECK (pending_balance >= 0) NOT VALID;

ALTER TABLE balance
    VALIDATE CONSTRAINT balance_pending_balance_nonnegative;

COMMIT;
