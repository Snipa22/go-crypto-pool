package leaflib

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestLoginFailureDoesNotLeakGoroutine regression-guards bug class 1: the
// legacy stratum servers sent a validation-failure signal to an unbuffered
// channel with no live receiver, deadlocking the per-connection goroutine
// and leaking the socket forever. Here we simulate a "bad login" handler
// that immediately calls ManagedConnection.Close on validation failure and
// assert no goroutine is left behind and the connection is actually
// closed.
func TestLoginFailureDoesNotLeakGoroutine(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"))

	cm := NewConnectionManager(context.Background(), ManagerConfig{})
	defer cm.Shutdown()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	mc, err := cm.Accept(context.Background(), serverConn)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	before := runtime.NumGoroutine()

	// Simulate the "bad login" path: the legacy code would try to signal
	// a goroutine via an unbuffered channel with nobody listening and
	// deadlock. Our fix: just call Close directly, from whichever
	// goroutine detected the failure, with no channel handoff required.
	loginFailed := make(chan struct{})
	go func() {
		// This goroutine represents the connection's read/handler loop.
		// On "bad login" it must be able to tear itself down without
		// blocking forever on a signal nobody receives.
		mc.Close("invalid login")
		close(loginFailed)
	}()

	select {
	case <-loginFailed:
	case <-time.After(2 * time.Second):
		t.Fatal("login-failure goroutine deadlocked (bug class 1 regression)")
	}

	if !mc.IsClosed() {
		t.Fatal("connection was not actually closed after login failure")
	}
	if _, ok := cm.Get(mc.ID()); ok {
		t.Fatal("connection still registered in manager after close")
	}

	// Give any residual goroutines a moment to actually exit before
	// comparing counts (writer loop / watcher goroutine exit
	// asynchronously relative to Close() returning... though Close()
	// itself waits for the writer; this covers the ctx-watcher too).
	deadline := time.Now().Add(2 * time.Second)
	for {
		after := runtime.NumGoroutine()
		if after <= before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak detected: before=%d after=%d", before, after)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestManyLoginFailuresDoNotAccumulate hammers the bad-login path many
// times to make the leak-detection more robust than a single sample.
func TestManyLoginFailuresDoNotAccumulate(t *testing.T) {
	cm := NewConnectionManager(context.Background(), ManagerConfig{})
	defer cm.Shutdown()

	before := runtime.NumGoroutine()

	const n = 50
	for i := 0; i < n; i++ {
		serverConn, clientConn := net.Pipe()
		mc, err := cm.Accept(context.Background(), serverConn)
		if err != nil {
			clientConn.Close()
			t.Fatalf("Accept: %v", err)
		}
		mc.Close("invalid login")
		clientConn.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		after := runtime.NumGoroutine()
		if after <= before+2 { // small slack for GC/runtime bookkeeping
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak after %d bad logins: before=%d after=%d", n, before, after)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
