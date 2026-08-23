-- 0005_block_pool_id.down.sql
BEGIN;

ALTER TABLE blocks DROP COLUMN pool_id;

COMMIT;
