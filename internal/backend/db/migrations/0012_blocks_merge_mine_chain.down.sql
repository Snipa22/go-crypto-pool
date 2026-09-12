DROP INDEX IF EXISTS idx_blocks_merge_mine_chain;
ALTER TABLE blocks DROP COLUMN IF EXISTS merge_mine_chain;
