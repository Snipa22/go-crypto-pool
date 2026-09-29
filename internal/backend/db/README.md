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
  `miner_identifiers` is populated by `Repository.InsertShare` itself:
  every real, accepted share upserts its (algo, network,
  payment_address, payment_id, worker_name) identity row in the same
  DB transaction as the shares insert, advancing `last_share` to that
  share's own timestamp (never regressing it on an out-of-order/late
  submission — see `UpsertMinerIdentifier`'s doc comment). This closes
  what was previously a schema-exists-but-unused gap: nothing wrote to
  this table before.

- **`payouts`** (migration `0002_wallet_disbursements`) — a permanent,
  unpartitioned audit log of every real on-chain disbursement attempt
  made by `internal/backend/disburse.Engine` against
  `internal/backend/wallet.WalletClient`. One row per real Transfer RPC
  call (covering one or more `balance` rows via `balance_ids`), with a
  `PENDING -> SENT|FAILED` status lifecycle — see the migration file's
  own doc comment for exactly why the row is written *before* the real
  transfer call is attempted.

## Retention model for `shares`

Retention is "delete all shares of a given algo+pool_type below block
height X," implemented as **whole-partition drops**, never row-level
`DELETE`. `DropOldPartitions(ctx, pool, algo, poolType, belowHeight)`
finds every `block_height` leaf partition whose entire range already
falls below `belowHeight` and drops it.

This is a mechanism only — nothing in this package calls it on a
schedule. Wiring it into an actual periodic job (cron/ticker in
`cmd/backend`) is future work.

## Retention model for `hash_history`

`hash_history` (migration `0018_hash_history`) is the bounded,
Postgres-backed replacement for legacy `worker.js`'s hash-history
feature — periodic pool-wide/miner/worker hashrate and network-
difficulty samples, written by `cmd/backend`'s `runHashHistoryPoller`
(see `hashhistory.go`'s own package doc comment for the full design
writeup and `DISPATCH_BRIEF.md` for the legacy ground truth this
replaces).

Unlike `shares`' whole-partition-drop retention above, `hash_history`
retention (`Repository.PruneHashHistory`) is a **plain row-level
`DELETE ... WHERE sample_time < $1`**, backed by
`idx_hash_history_sample_time`. This is a deliberately different
mechanism from `shares`' partition-drop approach, not an oversight:
`hash_history` is small and low-cardinality by construction (at most a
few hundred `pool_type`/`network_difficulty` rows plus
`DefaultShareStatsCardinalityCap`-many (worker + miner-level) rows per
poll tick, retained for a bounded number of ticks — see
`ActiveMinerHashrates`' own cardinality cap), so a plain indexed
`DELETE` is fast enough that partition-drop's extra DDL-management
complexity buys nothing here, unlike `shares`, which is genuinely
large enough to need it.

The retention WINDOW itself is expressed as a **point count**
(`-hash-history-max-points` / `GCPOOL_HASH_HISTORY_MAX_POINTS`,
default 480 — mirroring legacy's own real `statsBufferLength=480`
config value), not a duration; `cmd/backend` computes the actual
duration passed to `PruneHashHistory` as
`maxPoints * -hash-history-interval` (480 * 60s = 8h at the defaults),
recomputed fresh on every poll tick rather than baked into the schema.

## Go package layout

- `db.go` — `Config`/`Open` (pgx pool setup), `HeightPartitionBucketSize`,
  `ValidAlgos`/`ValidPoolTypes`.
- `partition.go` — `EnsureHeightPartition`, `ListHeightPartitions`,
  `DropOldPartitions`, `BucketBounds`, algo/pool_type validation.
- `repository.go` — `Repository` with `InsertShare`/`InsertBlock`. This is
  intentionally minimal (not a full CRUD surface) — schema + plumbing
  only, per the task scope.
- `stats.go` — the read-only, miner-facing query surface backing
  `internal/backend/statsapi` (hashrate-right-now, not history).
- `hashhistory.go` — the bounded hash-history feature's own
  read+write surface (see "Retention model for `hash_history`" above)
  — `PoolTypeShareStatsSince`/`ActiveMinerHashrates` (reads over
  `shares`), `InsertPoolTypeHashSample`/`InsertNetworkDifficultySample`/
  `InsertMinerHashSamples`/`PruneHashHistory` (writes to
  `hash_history`), and `PoolTypeHashHistory`/`MinerHashHistory`/
  `NetworkDifficultyHistory` (reads over `hash_history`, backing
  `internal/backend/statsapi`'s history endpoints).
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
