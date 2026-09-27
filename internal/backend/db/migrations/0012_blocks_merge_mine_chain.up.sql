-- Adds blocks.merge_mine_chain: a nullable marker distinguishing which
-- leg of a merge-mined PoW submission one blocks row represents.
--
-- Background: ALGO_RXM (Monero) is merge-mined with a merge-mined
-- chain (today: Tari, via a minotari_merge_mining_proxy sitting
-- between leaf-direct-monero and real monerod). ONE PoW submission
-- from a miner can independently clear the primary chain's (Monero)
-- real difficulty target, the merge-mined chain's (Tari) real
-- difficulty target, or both -- these are two independent,
-- independently-verifiable/maturable/payable events, not one.
--
-- NULL (the default, and every historical row's implicit value) means
-- this row is the PRIMARY leg (Monero, for ALGO_RXM). A non-NULL value
-- (e.g. 'TARI') names the SECONDARY merge-mined chain this row's own
-- real, independently-resolved hash belongs to. algo stays 'RXM' for
-- BOTH legs -- this column, not algo, is what distinguishes them.
-- ALGO_RXT (a completely separate, standalone leaf/algo) is untouched
-- by this column and always has it NULL.
ALTER TABLE blocks ADD COLUMN merge_mine_chain TEXT NULL;

CREATE INDEX idx_blocks_merge_mine_chain ON blocks (merge_mine_chain);
