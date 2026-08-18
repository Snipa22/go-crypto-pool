-- 0001_initial_schema.down.sql
BEGIN;

DROP TABLE IF EXISTS ports;
DROP TABLE IF EXISTS pools;
DROP TABLE IF EXISTS balance;
DROP TABLE IF EXISTS miner_identifiers;
DROP TABLE IF EXISTS blocks;
DROP TABLE IF EXISTS shares; -- cascades to all partitions

COMMIT;
