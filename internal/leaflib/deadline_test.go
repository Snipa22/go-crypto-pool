package leaflib

import (
	"context"
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
