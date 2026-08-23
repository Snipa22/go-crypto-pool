-- 0005_block_pool_id.up.sql
--
-- Adds pool_id to `blocks`, mirroring the column `shares` has had since
-- 0001_initial_schema (which was never actually populated by any real
-- leaf -- see internal/proto/share.proto's Share.pool_id/Block.pool_id
-- doc comment for the full "scoped-down /poolInit" rationale). This
-- migration exists purely to give found-block reports the same
-- pool-server-source column shares already has; it does not change any
-- existing row's meaning.
--
-- Default 0 (matches poolpb's proto3 int32 zero value) so existing rows
-- inserted before this migration read as "source unknown" rather than
-- erroring or being backfilled with a guess.

BEGIN;

ALTER TABLE blocks ADD COLUMN pool_id INTEGER NOT NULL DEFAULT 0;

COMMIT;
