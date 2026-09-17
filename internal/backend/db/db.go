// Package db implements the go-crypto-pool backend's Postgres schema
// plumbing: connection/pool setup, partition-management helpers for the
// `shares` height-range partitions, and a minimal repository surface
// (InsertShare/InsertBlock) over the schema defined in
// internal/backend/db/migrations.
//
// See migrations/0001_initial_schema.up.sql for the schema itself and
// README.md for the design rationale (partition hierarchy, retention
// model, open follow-ups).
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HeightPartitionBucketSize is the width, in block-height units, of each
// RANGE partition leaf under shares_<algo>_<pool_type>_*.
//
// This is a PLACEHOLDER DEFAULT (100000), not a tuned production value —
// real bucket sizing needs to be revisited once actual testnet share
// volume per algo is observed (rows/bucket, partition count, vacuum/
// planning overhead). It is deliberately expressed as a single Go
// constant (rather than hardcoded per-partition DDL) so it can be
// changed later without a schema redesign — see EnsureHeightPartition
// and DropOldPartitions, which are the only things that need to agree on
// its value, plus the seed buckets created in
// migrations/0001_initial_schema.up.sql (which must be kept in sync if
// this constant ever changes before that migration is amended/replaced).
const HeightPartitionBucketSize int64 = 100000

// ValidAlgos is the fixed set of algo partition-key values, matching the
// Algo enum in internal/proto/share.proto (string form, not the proto
// enum type itself, to keep this package independent of the wire schema).
//
// RXT/C29/SHA3X/RXM are the original four; the rest (XMR and below) are
// the standalone monerod-family coins added via
// internal/coinprofile.Registry -- see migrations/0016_multicoin_algos.up.sql,
// which is the migration that widened every affected CHECK (algo IN
// (...)) constraint to match this exact list (it was the one genuinely
// hardcoded, non-generic gap found in this schema; EnsureHeightPartition
// and the pools table's UNIQUE(algo, network, pool_type, name)
// constraint were already fully generic and needed no migration).
var ValidAlgos = []string{
	"RXT", "C29", "SHA3X", "RXM",
	"XMR", "ARQ", "XEQ", "GRFT", "SFX", "ZEPH", "SAL",
}

// ValidPoolTypes is the fixed set of pool_type partition-key values,
// matching the PoolType enum in internal/proto/share.proto.
var ValidPoolTypes = []string{"SOLO", "PPS", "PPLNS", "PROP"}

// ValidNetworks is the fixed set of network column values, matching
// the Network enum in internal/proto/share.proto (string form). Used
// by the read-only miner stats surface (stats.go) to validate an
// optional network filter the same way ValidateAlgo already validates
// algo everywhere else in this package.
var ValidNetworks = []string{"MAINNET", "TESTNET"}

// ValidCurrencies is the fixed set of `currency` column values added
// by migrations/0014_balance_payouts_currency.up.sql to `balance`,
// `payouts`, and `block_payout_credits` -- XTM (Tari, always used by
// RXT/C29/SHA3X, and by ALGO_RXM's secondary/merge-mined leg) and XMR
// (Monero, ALGO_RXM's primary leg). See that migration's doc comment
// for the full rationale.
var ValidCurrencies = []string{"XMR", "XTM"}

// Config holds the settings needed to establish the backend's Postgres
// connection pool.
type Config struct {
	// DSN is a standard libpq/pgx connection string, e.g.
	// "postgres://user:pass@host:5432/dbname?sslmode=disable".
	DSN string
}

// Open establishes a pgx connection pool and verifies connectivity with a
// ping. Callers own the returned pool's lifecycle and must call Close
// when done.
func Open(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("db: creating connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: pinging database: %w", err)
	}
	return pool, nil
}
