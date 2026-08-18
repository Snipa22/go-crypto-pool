# internal/backend/db

Postgres schema and Go plumbing for the go-crypto-pool backend.

## Schema

See `migrations/0001_initial_schema.up.sql` for the full DDL. Summary:

- **`shares`** — three-level DECLARATIVE PARTITION hierarchy:
  `algo` (LIST) → `pool_type` (LIST) → `block_height` (RANGE). The algo
  and pool_type levels are enumerated statically (they mirror the fixed
  `Algo`/`PoolType` enums in `internal/proto/share.proto`: `RXT/C29/SHA3X/RXM`
  and `SOLO/PPS/PPLNS/PROP`). The `block_height` RANGE leaves are **not**
  fully enumerated in the migration — only a seed bucket
  (`[0, HeightPartitionBucketSize)`) is created per algo/pool_type combo.
  Every subsequent bucket is created on demand by
  `EnsureHeightPartition` (called from `Repository.InsertShare`).

  The bucket width is `HeightPartitionBucketSize` in `db.go` — a
  **placeholder default (100000), explicitly not tuned** against real
  testnet volume yet. It's a single Go constant precisely so it can be
  changed later without a schema redesign; `EnsureHeightPartition` and
  `DropOldPartitions` both take bucket size as a parameter rather than
  hardcoding it.

- **`blocks`** — plain, unpartitioned, permanent table. No retention/
  cleanup logic; blocks are never deleted.

- **`miner_identifiers`**, **`balance`**, **`pools`**, **`ports`** —
  minimal coin-agnostic supporting tables. `balance` carries an explicit
  `algo`/`network` discriminator column (a gap in the legacy SXMR schema
  that this project's architecture review flagged). `pools`/`ports`
  carry `network` (mainnet/testnet) as a hard requirement.

## Retention model for `shares`

Retention is "delete all shares of a given algo+pool_type below block
height X," implemented as **whole-partition drops**, never row-level
`DELETE`. `DropOldPartitions(ctx, pool, algo, poolType, belowHeight)`
finds every `block_height` leaf partition whose entire range already
falls below `belowHeight` and drops it.

This is a mechanism only — nothing in this package calls it on a
schedule. Wiring it into an actual periodic job (cron/ticker in
`cmd/backend`) is future work.

## Go package layout

- `db.go` — `Config`/`Open` (pgx pool setup), `HeightPartitionBucketSize`,
  `ValidAlgos`/`ValidPoolTypes`.
- `partition.go` — `EnsureHeightPartition`, `ListHeightPartitions`,
  `DropOldPartitions`, `BucketBounds`, algo/pool_type validation.
- `repository.go` — `Repository` with `InsertShare`/`InsertBlock`. This is
  intentionally minimal (not a full CRUD surface) — schema + plumbing
  only, per the task scope.
- `migrate.go` — `ApplyMigrations`, a tiny embedded-FS migration runner
  (no version-tracking table yet; only safe against a fresh database).
  Fine for bootstrap/tests today; a real migration tool (golang-migrate
  or similar) with version tracking is a reasonable follow-up once there
  are more than a couple of migration files.
- `migrations/*.sql` — hand-written migration files, `NNNN_name.up.sql` /
  `.down.sql` convention (golang-migrate-compatible naming, even though
  the current runner doesn't use golang-migrate itself).
- `integration_test.go` — Postgres-backed tests, gated on `GCPOOL_TEST_DSN`
  (skipped, not failed, when unset — see below).

## Running the integration tests

```sh
export GCPOOL_TEST_DSN="postgres://postgres@127.0.0.1:5544/gcpool_test?sslmode=disable"
go test ./internal/backend/db/... -run Integration -v
```

Verified against a local Postgres 17.5 instance during implementation.
Covers: partition-tree shape (`pg_partitioned_table`/`pg_inherits`
introspection), `InsertShare`/`InsertBlock` round-trips, partition
pruning via `EXPLAIN` (confirms irrelevant algo/pool_type/height
partitions never appear in the plan), and `DropOldPartitions` removing
exactly the intended rows/partitions and nothing else.

If `GCPOOL_TEST_DSN` isn't set, these tests are skipped (not failed) so
`go test ./...` stays green in environments with no Postgres available.

## Known follow-ups (not in scope for this pass)

- No migration version-tracking table — `ApplyMigrations` re-runs every
  file every time; fine for tests/bootstrap, not for a live database that
  already has migration 0001 applied.
- No scheduler/cron wiring for `DropOldPartitions` — mechanism exists,
  policy (when/how often to call it, what "live threshold" means per
  algo) is future work.
- `HeightPartitionBucketSize` is an unturned placeholder; revisit once
  real testnet share volume is observed.
- `pools`/`ports` config tables are intentionally minimal (no per-port
  vardiff curve, no pool-level fee config yet) — extend as needed.
