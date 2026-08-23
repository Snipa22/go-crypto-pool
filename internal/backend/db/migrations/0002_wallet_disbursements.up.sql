-- 0002_wallet_disbursements.up.sql
--
-- Adds the `payouts` table: a permanent, unpartitioned audit log of
-- every real on-chain disbursement attempt made by
-- internal/backend/disburse against internal/backend/wallet.WalletClient.
-- One row per Transfer RPC call, NOT one row per balance credited —
-- a single real transfer can (and normally does) pay multiple
-- balance rows in one transaction, so `balance_ids` records exactly
-- which balance rows this transfer's amount was drawn from.
--
-- Status lifecycle (see internal/backend/disburse's doc comment):
--   PENDING  -> row inserted immediately before the real Transfer RPC
--               call is made, so a crash between "RPC succeeded" and
--               "balances debited" is detectable/recoverable rather
--               than silently lost.
--   SENT     -> the real Transfer call returned a tx_hash; balances
--               have been debited in the SAME database transaction
--               that flipped this row to SENT (see
--               Repository.RecordDisbursement).
--   FAILED   -> the real Transfer call errored; balances were NEVER
--               touched for this row (see disburse.go), so this
--               status exists purely for audit/alerting, not as a
--               retry marker (the underlying balance rows simply
--               remain payable and get picked up again next cycle).

BEGIN;

CREATE TABLE payouts (
    id              BIGSERIAL PRIMARY KEY,
    algo            TEXT        NOT NULL CHECK (algo IN ('RXT', 'C29', 'SHA3X', 'RXM')),
    network         TEXT        NOT NULL CHECK (network IN ('MAINNET', 'TESTNET')),
    status          TEXT        NOT NULL CHECK (status IN ('PENDING', 'SENT', 'FAILED')),
    balance_ids     BIGINT[]    NOT NULL, -- balance.id rows this disbursement covers
    amount          NUMERIC(38, 0) NOT NULL, -- total atomic units requested for this transfer
    fee             NUMERIC(38, 0), -- real on-chain fee actually paid, set only once SENT
    tx_hash         TEXT, -- real transaction hash, set only once SENT
    error           TEXT, -- error message, set only if FAILED
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ -- set when this row transitions to SENT or FAILED
);

CREATE INDEX idx_payouts_algo_network ON payouts (algo, network);
CREATE INDEX idx_payouts_status ON payouts (status);
CREATE INDEX idx_payouts_tx_hash ON payouts (tx_hash) WHERE tx_hash IS NOT NULL;

COMMIT;
