// Package leaflib is the shared internal library consumed by every leaf
// binary (leaf-direct, leaf-solo, leaf-proxy) across all four supported
// algos (RXT, C29, SHA3X, RXM). It owns connection-lifecycle management
// (see manager.go and connection.go), per-algo job/template caching, and
// vardiff.
//
// Connection lifecycle (ConnectionManager / ManagedConnection) is
// deliberately designed to avoid five bug classes found when reviewing
// the legacy Tari stratum servers (go-tari-c29-solo-stratum,
// go-tari-sha3x-solo-stratum):
//
//  1. Goroutine/fd/socket leak on invalid login — legacy code sent to an
//     unbuffered channel with no live receiver on validation failure,
//     deadlocking the goroutine and leaking the connection forever. Fixed
//     here via context.Context cancellation + a sync.Once-guarded cleanup
//     path that never blocks and can be invoked from any goroutine.
//  2. No read/write deadlines — legacy code never called
//     SetReadDeadline/SetWriteDeadline, relying on one-shot app timers
//     that never re-armed. Fixed here with a rolling idle-timeout that is
//     reset on every successful read/write, plus TCP keepalive.
//  3. No connection accounting/limiting — legacy code had literal
//     "TODO: add tracking" stubs. Fixed here with a live registry, an
//     atomic active-connection counter, and a pluggable ConnectionGate
//     interface checked before accepting new connections.
//  4. Unsynchronized concurrent writes to the same socket — legacy code
//     let the read loop and periodic/cron goroutines both call Write()
//     with no serialization. Fixed here with a single dedicated writer
//     goroutine per connection fed by a channel — no caller ever calls
//     net.Conn.Write directly.
//  5. Global shared cron.Cron scheduler for all connections' periodic
//     work — O(N) lock contention and goroutine churn per tick. Fixed
//     here by NOT centralizing per-connection periodic work in this
//     package at all: each ManagedConnection exposes its own lifetime
//     Context(), and owners are expected to run lightweight, per-
//     connection time.Timer/Ticker instances scoped to that goroutine,
//     trivially cancelled on disconnect.
package leaflib

// Algo identifies one of the supported mining algorithms/share streams.
type Algo string

const (
	AlgoRXT   Algo = "rxt"
	AlgoC29   Algo = "c29"
	AlgoSHA3X Algo = "sha3x"
	AlgoRXM   Algo = "rxm"
)

// JobCache is a placeholder for per-algo job/template caching. Its real
// design (eviction policy, cross-algo sharing) is a separate concern from
// connection lifecycle and is intentionally left unimplemented here.
type JobCache struct {
	Algo Algo
}

// VarDiff is a placeholder for the shared variable-difficulty logic. Its
// real design is a separate concern from connection lifecycle and is
// intentionally left unimplemented here.
type VarDiff struct{}
