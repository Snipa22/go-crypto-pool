// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestConnectionPortCounter_CountsRealPerPortConnections spins up two
// real TCP listeners (simulating two configured port tiers), accepts
// a few connections on each via a real *leaflib.ConnectionManager, and
// confirms connectionPortCounter.PortMinerCounts reports the real
// per-port breakdown -- the exact data the legacy /poolCheckin
// heartbeat's `ports` field needs (see
// internal/leaflib/legacytransport/checkin.go).
func TestConnectionPortCounter_CountsRealPerPortConnections(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 1: %v", err)
	}
	defer ln1.Close()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 2: %v", err)
	}
	defer ln2.Close()

	port1 := ln1.Addr().(*net.TCPAddr).Port
	port2 := ln2.Addr().(*net.TCPAddr).Port

	cm := leaflib.NewConnectionManager(context.Background(), leaflib.ManagerConfig{})
	defer cm.Shutdown()

	acceptN := func(ln net.Listener, n int) {
		for i := 0; i < n; i++ {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				t.Errorf("accept: %v", acceptErr)
				return
			}
			if _, mcErr := cm.Accept(context.Background(), conn); mcErr != nil {
				t.Errorf("cm.Accept: %v", mcErr)
			}
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		acceptN(ln1, 2)
		acceptN(ln2, 1)
	}()

	// Dial in 2 clients to ln1 and 1 client to ln2, keeping the
	// connections open until the test is done.
	var dialed []net.Conn
	for i := 0; i < 2; i++ {
		c, dialErr := net.Dial("tcp", ln1.Addr().String())
		if dialErr != nil {
			t.Fatalf("dial ln1: %v", dialErr)
		}
		dialed = append(dialed, c)
	}
	c, dialErr := net.Dial("tcp", ln2.Addr().String())
	if dialErr != nil {
		t.Fatalf("dial ln2: %v", dialErr)
	}
	dialed = append(dialed, c)
	defer func() {
		for _, c := range dialed {
			_ = c.Close()
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop did not finish in time")
	}

	// Give ConnectionManager's internal registration a moment (Accept
	// registers synchronously, but this guards against any scheduling
	// flakiness in CI).
	time.Sleep(50 * time.Millisecond)

	counter := &connectionPortCounter{cm: cm, ports: []int{port1, port2}}
	counts := counter.PortMinerCounts()

	if counts[port1] != 2 {
		t.Errorf("counts[port1] = %d, want 2", counts[port1])
	}
	if counts[port2] != 1 {
		t.Errorf("counts[port2] = %d, want 1", counts[port2])
	}
}

// TestConnectionPortCounter_ZeroConnectionsReportsConfiguredPortsAtZero
// confirms every configured port is present in the returned map even
// with zero current connections -- matching the real legacy sender's
// own behavior of always reporting every configured port (see
// checkin.go's package doc comment).
func TestConnectionPortCounter_ZeroConnectionsReportsConfiguredPortsAtZero(t *testing.T) {
	cm := leaflib.NewConnectionManager(context.Background(), leaflib.ManagerConfig{})
	defer cm.Shutdown()

	counter := &connectionPortCounter{cm: cm, ports: []int{4444, 4443}}
	counts := counter.PortMinerCounts()

	if counts[4444] != 0 {
		t.Errorf("counts[4444] = %d, want 0", counts[4444])
	}
	if counts[4443] != 0 {
		t.Errorf("counts[4443] = %d, want 0", counts[4443])
	}
	if len(counts) != 2 {
		t.Errorf("len(counts) = %d, want 2 (every configured port present)", len(counts))
	}
}
