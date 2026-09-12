package leaflib

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestIdleTimeoutClosesSilentConnection regression-guards bug class 2:
// the legacy stratum servers never applied read/write deadlines to the
// socket, so a silent/half-open connection (crashed miner, NAT drop)
// would sit in the registry forever. Here we configure a short
// IdleTimeout, accept a connection, and assert that the connection is
// closed automatically once neither side has done any read/write for
// longer than the timeout.
func TestIdleTimeoutClosesSilentConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	var serverRaw net.Conn
	select {
	case serverRaw = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted connection")
	}

	cm := NewConnectionManager(context.Background(), ManagerConfig{
		IdleTimeout: 150 * time.Millisecond,
	})
	defer cm.Shutdown()

	mc, err := cm.Accept(context.Background(), serverRaw)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// Kick off a read loop, mirroring what a real leaf accept-loop would
	// do. It must observe a deadline-exceeded error and close, rather
	// than blocking forever (the old bug: no deadline ever set means a
	// silent client hangs the read goroutine indefinitely).
	readErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := mc.Read(buf)
		readErrCh <- err
	}()

	// Client stays completely silent — no writes, no reads — simulating
	// a NAT drop / crashed client that never sends a FIN.

	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected a deadline/closed error from Read, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read never returned — idle timeout was not enforced (bug class 2 regression)")
	}

	// The connection's own idle-timeout enforcement is app-level in real
	// leaf binaries (they'd call Close on a deadline error observed from
	// Read/Write). Verify that a Close call following the deadline error
	// actually tears the connection down and deregisters it, and that a
	// second concurrent detection path doesn't double-free anything.
	mc.Close("idle timeout")
	if !mc.IsClosed() {
		t.Fatal("connection not closed after idle timeout")
	}
	if _, ok := cm.Get(mc.ID()); ok {
		t.Fatal("connection still registered after idle-timeout close")
	}
}

// TestWriteAlsoEnforcesDeadline exercises the write side of the rolling
// deadline: filling the peer's receive buffer without it ever reading
// should eventually make Write observe a deadline error rather than
// hanging forever.
func TestWriteAlsoEnforcesDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	var serverRaw net.Conn
	select {
	case serverRaw = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted connection")
	}

	cm := NewConnectionManager(context.Background(), ManagerConfig{
		IdleTimeout: 150 * time.Millisecond,
	})
	defer cm.Shutdown()

	mc, err := cm.Accept(context.Background(), serverRaw)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	writeErrCh := make(chan error, 1)
	go func() {
		payload := make([]byte, 1<<20) // 1MB, large enough to eventually block on a non-reading peer
		var lastErr error
		for i := 0; i < 64; i++ {
			if err := mc.Write(payload); err != nil {
				lastErr = err
				break
			}
		}
		writeErrCh <- lastErr
	}()

	select {
	case err := <-writeErrCh:
		if err == nil {
			t.Fatal("expected a deadline/closed error from Write, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write never returned an error — write deadline was not enforced (bug class 2 regression)")
	}
}

// TestIdleReadTimeoutNotExtendedByOutboundWrites regression-guards the
// production zombie-session defect (leaf-direct-rxm, session
// c4ef91306259e925, frozen 68+ hours): a connection whose local side
// keeps successfully WRITING (e.g. leaf-direct's periodic unsolicited
// job-push broadcasts) while genuinely receiving NOTHING back must still
// have its read-idle deadline fire. Before the read/write deadline split,
// every successful outbound write re-armed the single combined
// net.Conn.SetDeadline, which meant the inbound read deadline could never
// fire as long as writes kept succeeding — masking a genuinely dead
// peer.
func TestIdleReadTimeoutNotExtendedByOutboundWrites(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	var serverRaw net.Conn
	select {
	case serverRaw = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted connection")
	}

	cm := NewConnectionManager(context.Background(), ManagerConfig{
		IdleTimeout: 150 * time.Millisecond,
	})
	defer cm.Shutdown()

	mc, err := cm.Accept(context.Background(), serverRaw)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// The client keeps draining whatever the server writes to it (so the
	// server's writes keep succeeding rather than eventually blocking on
	// a full send buffer) but never itself writes a single byte back —
	// simulating a dead/half-open peer that a real TCP stack has not yet
	// surfaced a FIN/RST for.
	drainDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
		close(drainDone)
	}()

	// Kick off a read loop on the server side, exactly like
	// TestIdleTimeoutClosesSilentConnection does — this is what should
	// observe the idle-read-timeout error.
	readErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := mc.Read(buf)
		readErrCh <- err
	}()

	// Simulate leaf-direct's periodic unsolicited job-push broadcasts:
	// repeatedly write small payloads on an interval shorter than the
	// idle timeout, from a separate goroutine, while the client never
	// sends anything back. Crucially, these writes must keep going for
	// LONGER than the bounded wait below asserts on — otherwise a buggy,
	// coupled-deadline implementation would still "pass" simply because
	// the writes eventually stop and the read deadline lapses shortly
	// after, which wouldn't actually prove that the read deadline is
	// independent of ongoing writes. Here we keep writing every 50ms for
	// up to 2s, well beyond the bounded wait, so the pre-fix combined
	// SetDeadline would still be getting re-armed by every write
	// throughout that entire window.
	stopWrites := make(chan struct{})
	writesDone := make(chan struct{})
	go func() {
		defer close(writesDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		payload := []byte("job-push-broadcast")
		for i := 0; i < 40; i++ {
			select {
			case <-stopWrites:
				return
			case <-ticker.C:
				if err := mc.Write(payload); err != nil {
					return
				}
			}
		}
	}()
	defer func() {
		close(stopWrites)
		<-writesDone
	}()

	// Despite those ongoing successful outbound writes, the read-idle
	// timeout must still fire because the peer has never sent anything
	// back — within a bounded wait of a couple of idle-timeout periods
	// (150ms configured above), which is well BEFORE the write goroutine
	// above stops on its own. Against the pre-fix coupled-deadline code,
	// this wait deliberately expires (and the test fails) because the
	// ongoing writes keep re-arming the shared deadline throughout this
	// entire window; only the read/write deadline split lets Read fire
	// on schedule regardless of those writes.
	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected a deadline/closed error from Read, got nil")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Read never observed a deadline error while writes were still ongoing — outbound writes masked the read-idle timeout (zombie-session regression)")
	}

	mc.Close("idle timeout")
	clientConn.Close()
	<-drainDone
}
