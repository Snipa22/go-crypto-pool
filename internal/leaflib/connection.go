package leaflib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrConnectionClosed is returned by ManagedConnection operations once the
// connection has been closed (by either side, or by idle timeout).
var ErrConnectionClosed = errors.New("leaflib: connection closed")

// writeRequest is a single write job handed to a connection's dedicated
// writer goroutine. done receives the outcome so Write() can block for it
// (preserving a synchronous Write API for callers) while still ensuring
// all bytes going to the wire pass through exactly one goroutine.
type writeRequest struct {
	payload []byte
	done    chan error
}

// ManagedConnection wraps a net.Conn with:
//
//   - A single dedicated writer goroutine (fed by a channel) so that no
//     two goroutines ever call the underlying net.Conn.Write concurrently.
//     This is the fix for bug class 4 (unsynchronized concurrent writes).
//   - A rolling idle-timeout applied via SetDeadline around every I/O op,
//     reset on every successful op. This is the fix for bug class 2
//     (no deadlines).
//   - A context.Context + sync.Once-guarded Close path that is safe to
//     invoke exactly once no matter how many goroutines call it or how
//     many times, and that never blocks on an unbuffered handoff. This is
//     the fix for bug class 1 (goroutine/fd leak on bad login/teardown).
type ManagedConnection struct {
	id     uint64
	conn   net.Conn
	remote net.Addr

	idleTimeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce  sync.Once
	closeErr   error
	closeReasn string

	writeCh  chan writeRequest
	writerWG sync.WaitGroup
	closed   atomic.Bool

	onClose func(*ManagedConnection, string)
}

// newManagedConnection constructs a ManagedConnection and starts its
// writer goroutine. parentCtx is typically the ConnectionManager's own
// lifetime context; the connection gets a derived, independently
// cancellable context so a single bad connection can be torn down without
// affecting any other connection or the manager itself.
func newManagedConnection(parentCtx context.Context, id uint64, conn net.Conn, idleTimeout time.Duration, onClose func(*ManagedConnection, string)) *ManagedConnection {
	ctx, cancel := context.WithCancel(parentCtx)
	mc := &ManagedConnection{
		id:          id,
		conn:        conn,
		remote:      conn.RemoteAddr(),
		idleTimeout: idleTimeout,
		ctx:         ctx,
		cancel:      cancel,
		writeCh:     make(chan writeRequest, 64),
		onClose:     onClose,
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	mc.armDeadline()

	mc.writerWG.Add(1)
	go mc.writerLoop()

	// Idempotent teardown triggered by context cancellation from *any*
	// source (explicit Close, idle-timeout watchdog, manager shutdown).
	// This goroutine never blocks on a channel handoff — it only waits on
	// ctx.Done() and then runs the sync.Once-guarded cleanup.
	go func() {
		<-ctx.Done()
		mc.doClose("context cancelled")
	}()

	return mc
}

// ID returns the manager-assigned connection identifier.
func (mc *ManagedConnection) ID() uint64 { return mc.id }

// RemoteAddr returns the remote address captured at accept time.
func (mc *ManagedConnection) RemoteAddr() net.Addr { return mc.remote }

// Context returns the connection's lifetime context. It is cancelled the
// moment the connection starts closing (for any reason), so caller
// goroutines (e.g. a per-connection read loop or vardiff timer) can select
// on ctx.Done() instead of polling a closed flag. This is also the hook
// per-connection periodic work (bug class 5) should use: derive a
// time.Timer/Ticker scoped to this context instead of registering with
// any shared/global scheduler.
func (mc *ManagedConnection) Context() context.Context { return mc.ctx }

// armDeadline resets the rolling idle deadline on the underlying socket.
// Called after every successful read and write, plus once at connection
// setup. If idleTimeout is zero, deadlines are disabled (not recommended
// in production, but useful for tests that want manual control).
func (mc *ManagedConnection) armDeadline() {
	if mc.idleTimeout <= 0 {
		return
	}
	_ = mc.conn.SetDeadline(time.Now().Add(mc.idleTimeout))
}

// Read reads from the underlying connection, applying and re-arming the
// rolling idle deadline. Returns ErrConnectionClosed if the connection has
// already been torn down.
func (mc *ManagedConnection) Read(p []byte) (int, error) {
	if mc.closed.Load() {
		return 0, ErrConnectionClosed
	}
	n, err := mc.conn.Read(p)
	if err != nil {
		return n, err
	}
	mc.armDeadline()
	return n, nil
}

// Write enqueues payload to be written by this connection's single writer
// goroutine and blocks until that write completes (or the connection
// closes). This guarantees no interleaving between concurrent Write()
// callers and gives ordered, whole-message delivery — the fix for bug
// class 4.
func (mc *ManagedConnection) Write(payload []byte) error {
	if mc.closed.Load() {
		return ErrConnectionClosed
	}

	// Copy payload: the writer goroutine may send it asynchronously
	// relative to whatever the caller does with its buffer next, so we
	// need an immutable copy queued for later delivery.
	buf := make([]byte, len(payload))
	copy(buf, payload)

	req := writeRequest{payload: buf, done: make(chan error, 1)}

	select {
	case mc.writeCh <- req:
	case <-mc.ctx.Done():
		return ErrConnectionClosed
	}

	select {
	case err := <-req.done:
		return err
	case <-mc.ctx.Done():
		return ErrConnectionClosed
	}
}

// writerLoop is the single goroutine ever allowed to call mc.conn.Write.
// It drains writeCh in order until the connection's context is cancelled,
// then drains any remaining queued requests with ErrConnectionClosed so
// no caller blocked in Write() is left hanging.
func (mc *ManagedConnection) writerLoop() {
	defer mc.writerWG.Done()
	for {
		select {
		case req := <-mc.writeCh:
			mc.doWrite(req)
		case <-mc.ctx.Done():
			mc.drainPendingWrites()
			return
		}
	}
}

func (mc *ManagedConnection) doWrite(req writeRequest) {
	if mc.closed.Load() {
		req.done <- ErrConnectionClosed
		return
	}
	mc.armDeadline()
	_, err := mc.conn.Write(req.payload)
	if err == nil {
		mc.armDeadline()
	}
	req.done <- err
}

func (mc *ManagedConnection) drainPendingWrites() {
	for {
		select {
		case req := <-mc.writeCh:
			req.done <- ErrConnectionClosed
		default:
			return
		}
	}
}

// Close tears the connection down exactly once, regardless of how many
// goroutines call it or how many times. reason is recorded for
// diagnostics/logging and passed to the manager's onClose hook. This is
// the fix for bug class 1: cancelling ctx is always non-blocking (no
// unbuffered channel handoff with no receiver like the legacy code), and
// the actual socket teardown happens exactly once under sync.Once.
func (mc *ManagedConnection) Close(reason string) error {
	mc.cancel()
	mc.writerWG.Wait()
	mc.doClose(reason)
	return mc.closeErr
}

func (mc *ManagedConnection) doClose(reason string) {
	mc.closeOnce.Do(func() {
		mc.closed.Store(true)
		mc.closeReasn = reason
		mc.closeErr = mc.conn.Close()
		if mc.onClose != nil {
			mc.onClose(mc, reason)
		}
	})
}

// CloseReason returns why the connection was closed (empty if still open).
func (mc *ManagedConnection) CloseReason() string { return mc.closeReasn }

// IsClosed reports whether the connection has finished tearing down.
func (mc *ManagedConnection) IsClosed() bool { return mc.closed.Load() }

// String implements fmt.Stringer for logging convenience.
func (mc *ManagedConnection) String() string {
	return fmt.Sprintf("conn#%d(%s)", mc.id, mc.remote)
}
