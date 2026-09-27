package leaflib

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionGate decides whether a newly-dialed-in connection should be
// accepted at all, before any bytes are read from it. It is the extension
// point for per-IP rate limiting / banning (bug class 3) without this
// package needing to own the full policy — a leaf binary can supply a
// custom ConnectionGate (e.g. backed by a sliding-window IP tracker) while
// DefaultGate below covers the common case of a simple global cap.
type ConnectionGate interface {
	// ShouldAccept is called synchronously from Accept before the
	// connection is registered. Returning false rejects the connection;
	// the caller (ConnectionManager) is responsible for closing the raw
	// net.Conn in that case.
	ShouldAccept(remoteAddr net.Addr) bool
}

// DefaultGate is the zero-config ConnectionGate: it accepts any
// connection as long as the manager's active-connection count is below
// MaxConnections. It does not implement per-IP limiting; construct a
// custom ConnectionGate for that.
type DefaultGate struct {
	manager *ConnectionManager
}

// ShouldAccept implements ConnectionGate.
func (g *DefaultGate) ShouldAccept(_ net.Addr) bool {
	if g.manager.maxConnections <= 0 {
		return true
	}
	return g.manager.Count() < g.manager.maxConnections
}

// DefaultLeafMaxConnections is Fix 13's (DISPATCH_BRIEF.md
// 2026-09-10) real, generous-but-bounded default for each leaf
// binary's own -max-connections/LEAF_*_MAX_CONNECTIONS flag --
// leaf-solo, leaf-direct, and leaf-proxy's own cmd/ packages all
// reference this single constant (rather than duplicating the
// literal three times) so the chosen default can never silently
// drift between them. This is purely a DEFAULT-value change: this
// package's own "0 or negative means unlimited" ManagerConfig.
// MaxConnections/DefaultGate contract (see both their doc comments
// above) is completely unchanged -- an operator who explicitly wants
// unlimited connections can still pass 0 via their leaf's own flag/
// env var exactly as before this fix.
//
// 10000 is chosen as a round, generous-but-bounded number for real
// production mining-pool connection volumes: this repo's own
// codebase has no other existing hint of an expected miner-count
// ceiling per leaf process (no prior default, no documented
// operational scale target), so this default is deliberately a
// simple, memorable round number well above what any single leaf
// process is realistically expected to serve on its own (a pool
// operator running enough miners to approach this on ONE leaf
// process would already be expected to run multiple leaf instances/
// ports for other operational reasons), while still being a REAL,
// finite bound -- the actual bug this fix closes (defaulting to
// unlimited, i.e. zero built-in protection against an unbounded
// connection flood, on all three binaries) is closed regardless of
// the exact number chosen, as long as it is finite and generous.
const DefaultLeafMaxConnections = 10000

// ManagerConfig configures a ConnectionManager.
type ManagerConfig struct {
	// MaxConnections caps the number of simultaneously-registered
	// connections. Zero or negative means unlimited (DefaultGate always
	// accepts). Ignored entirely if a custom Gate is supplied.
	MaxConnections int

	// IdleTimeout is the rolling read/write deadline applied to every
	// managed connection (bug class 2). Zero disables deadlines
	// (not recommended outside of tests).
	IdleTimeout time.Duration

	// Gate overrides the accept-admission policy (bug class 3). If nil, a
	// DefaultGate backed by MaxConnections is used.
	Gate ConnectionGate
}

// ConnectionManager owns the registry of active ManagedConnections, the
// accept-time admission policy (via ConnectionGate), and the shared
// lifetime context that all connections derive from so a manager-wide
// Shutdown cleanly tears down every connection without an O(N) global
// scheduler (bug class 5 is avoided by NOT centralizing per-connection
// periodic work here at all — each ManagedConnection's owner is expected
// to run its own lightweight timer(s) scoped to mc.Context()).
type ConnectionManager struct {
	cfg ManagerConfig

	maxConnections int
	gate           ConnectionGate

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.RWMutex
	conns  map[uint64]*ManagedConnection
	nextID atomic.Uint64
	count  atomic.Int64

	shutdownOnce sync.Once
}

// NewConnectionManager constructs a ConnectionManager bound to parentCtx.
// Cancelling parentCtx (or calling Shutdown) tears down every registered
// connection.
func NewConnectionManager(parentCtx context.Context, cfg ManagerConfig) *ConnectionManager {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(parentCtx)
	cm := &ConnectionManager{
		cfg:            cfg,
		maxConnections: cfg.MaxConnections,
		ctx:            ctx,
		cancel:         cancel,
		conns:          make(map[uint64]*ManagedConnection),
	}
	if cfg.Gate != nil {
		cm.gate = cfg.Gate
	} else {
		cm.gate = &DefaultGate{manager: cm}
	}
	return cm
}

// Count returns the number of currently-registered connections.
func (cm *ConnectionManager) Count() int {
	return int(cm.count.Load())
}

// ErrConnectionRejected is returned by Accept when the ConnectionGate
// declines to admit a connection (e.g. over the configured cap).
var ErrConnectionRejected = fmt.Errorf("leaflib: connection rejected by gate")

// Accept admits conn under the manager's ConnectionGate policy. On
// rejection, conn is closed for the caller and ErrConnectionRejected is
// returned — callers must not also close conn in that case. On success,
// a *ManagedConnection is registered and returned; the caller owns
// reading from it (typically via a per-connection goroutine calling
// Read) and is responsible for eventually calling Close, though the
// manager will also close it on Shutdown.
func (cm *ConnectionManager) Accept(_ context.Context, conn net.Conn) (*ManagedConnection, error) {
	if !cm.gate.ShouldAccept(conn.RemoteAddr()) {
		_ = conn.Close()
		return nil, ErrConnectionRejected
	}

	id := cm.nextID.Add(1)
	mc := newManagedConnection(cm.ctx, id, conn, cm.cfg.IdleTimeout, cm.remove)

	cm.mu.Lock()
	cm.conns[id] = mc
	cm.mu.Unlock()
	cm.count.Add(1)

	return mc, nil
}

// remove unregisters mc from the manager. It is the onClose hook invoked
// exactly once by ManagedConnection's own sync.Once-guarded teardown, so
// the registry stays consistent no matter which path (explicit Close,
// idle-timeout, remote EOF, manager Shutdown) triggered the close.
func (cm *ConnectionManager) remove(mc *ManagedConnection, _ string) {
	cm.mu.Lock()
	_, existed := cm.conns[mc.id]
	delete(cm.conns, mc.id)
	cm.mu.Unlock()
	if existed {
		cm.count.Add(-1)
	}
}

// Get returns the registered connection with the given id, if any.
func (cm *ConnectionManager) Get(id uint64) (*ManagedConnection, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	mc, ok := cm.conns[id]
	return mc, ok
}

// Snapshot returns a point-in-time copy of the active connection list.
// Safe for a batched-ticker-style caller to iterate without holding the
// manager's lock for the duration of its work.
func (cm *ConnectionManager) Snapshot() []*ManagedConnection {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	out := make([]*ManagedConnection, 0, len(cm.conns))
	for _, mc := range cm.conns {
		out = append(out, mc)
	}
	return out
}

// Shutdown cancels the manager's context (cascading cancellation to every
// registered connection's derived context, which triggers each one's
// idempotent Close path) and waits for the registry to drain.
func (cm *ConnectionManager) Shutdown() {
	cm.shutdownOnce.Do(func() {
		cm.cancel()
		for _, mc := range cm.Snapshot() {
			mc.Close("manager shutdown")
		}
	})
}
