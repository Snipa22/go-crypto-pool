// Package leaflib is the shared internal library consumed by every leaf
// binary (leaf-direct, leaf-solo, leaf-proxy) across all four supported
// algos (RXT, C29, SHA3X, RXM). It is intended to own pooling and
// connection-lifecycle logic, per-algo job/template caching, and vardiff.
//
// This is a scaffold-stage stub — no real logic yet.
package leaflib

// Algo identifies one of the supported mining algorithms/share streams.
type Algo string

const (
	AlgoRXT   Algo = "rxt"
	AlgoC29   Algo = "c29"
	AlgoSHA3X Algo = "sha3x"
	AlgoRXM   Algo = "rxm"
)

// ConnectionManager is a placeholder for the shared connection-lifecycle
// logic (deadlines, per-connection accounting/caps, deadlock-free
// shutdown) that all leaf modes need. Not yet implemented.
type ConnectionManager struct{}

// JobCache is a placeholder for per-algo job/template caching. Not yet
// implemented.
type JobCache struct {
	Algo Algo
}

// VarDiff is a placeholder for the shared variable-difficulty logic. Not
// yet implemented.
type VarDiff struct{}
