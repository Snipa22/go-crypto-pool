package leaflib

import (
	"context"
	"net"
	"testing"
)

// TestConnectionCapRejectsOverflow regression-guards bug class 3: the
// legacy stratum servers had no connection accounting/limiting at all
// ("TODO: add tracking for connection counts" stubs that were never
// built). Configure a small MaxConnections, accept up to the cap, and
// assert the next Accept is rejected via the ConnectionGate — and that
// the manager closes the rejected raw connection itself.
func TestConnectionCapRejectsOverflow(t *testing.T) {
	cm := NewConnectionManager(context.Background(), ManagerConfig{MaxConnections: 2})
	defer cm.Shutdown()

	var serverConns, clientConns []net.Conn
	for i := 0; i < 2; i++ {
		s, c := net.Pipe()
		serverConns = append(serverConns, s)
		clientConns = append(clientConns, c)
		if _, err := cm.Accept(context.Background(), s); err != nil {
			t.Fatalf("Accept %d: unexpected rejection: %v", i, err)
		}
	}

	if got := cm.Count(); got != 2 {
		t.Fatalf("expected 2 active connections, got %d", got)
	}

	// Third connection must be rejected by the gate.
	s3, c3 := net.Pipe()
	defer c3.Close()
	mc3, err := cm.Accept(context.Background(), s3)
	if err != ErrConnectionRejected {
		t.Fatalf("expected ErrConnectionRejected, got %v (mc=%v)", err, mc3)
	}
	if mc3 != nil {
		t.Fatal("rejected Accept must not return a ManagedConnection")
	}

	// Manager must have closed the raw connection on rejection so no fd
	// is leaked even though it was never registered.
	buf := make([]byte, 1)
	if _, err := s3.Write(buf); err == nil {
		t.Fatal("expected write to rejected+closed connection to fail")
	}

	if got := cm.Count(); got != 2 {
		t.Fatalf("rejection must not affect active count, got %d", got)
	}

	// Freeing a slot allows a new connection in.
	clientConns[0].Close()
	serverConns[0].Close()
	cm.Get(0) // no-op touch; real detection happens via each conn's read loop in practice
	// Explicitly close via the manager's view to simulate detection.
	for _, id := range []uint64{1} {
		if mc, ok := cm.Get(id); ok {
			mc.Close("peer closed")
		}
	}

	if got := cm.Count(); got != 1 {
		t.Fatalf("expected 1 active connection after freeing a slot, got %d", got)
	}

	s4, c4 := net.Pipe()
	defer c4.Close()
	defer s4.Close()
	if _, err := cm.Accept(context.Background(), s4); err != nil {
		t.Fatalf("expected Accept to succeed after freeing a slot, got %v", err)
	}
	if got := cm.Count(); got != 2 {
		t.Fatalf("expected 2 active connections after re-filling slot, got %d", got)
	}

	for _, c := range clientConns[1:] {
		c.Close()
	}
}

// TestCustomGateOverridesDefault verifies the ConnectionGate extension
// point (the interface leaf binaries would use for per-IP rate limiting)
// is actually consulted instead of always falling back to the cap logic.
func TestCustomGateOverridesDefault(t *testing.T) {
	gate := &denyAllGate{}
	cm := NewConnectionManager(context.Background(), ManagerConfig{Gate: gate})
	defer cm.Shutdown()

	s, c := net.Pipe()
	defer c.Close()
	if _, err := cm.Accept(context.Background(), s); err != ErrConnectionRejected {
		t.Fatalf("expected custom gate to reject, got %v", err)
	}
	if !gate.called {
		t.Fatal("custom gate ShouldAccept was never invoked")
	}
}

type denyAllGate struct{ called bool }

func (g *denyAllGate) ShouldAccept(_ net.Addr) bool {
	g.called = true
	return false
}
