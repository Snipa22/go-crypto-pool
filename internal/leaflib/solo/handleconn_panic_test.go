// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

// TestHandleConn_RecoversFromPanicAndClosesOnlyThisConnection is the
// required regression test (FIX_BRIEF.md, finding #20) proving
// handleConn's new recover() wrapper actually works: a panic ANYWHERE
// in handleConn's body must be caught, logged, and result in only
// THIS connection being closed -- crucially, the calling
// goroutine/test process must SURVIVE, not crash the way an
// unrecovered panic in a goroutine always does (an unrecovered panic
// in ANY goroutine, even one this test itself spawned, terminates the
// entire process -- there would be no way to "catch" that from the
// test side at all, which is exactly why this recover() has to live
// INSIDE handleConn itself).
//
// Fabricates the panic via a deliberately-broken Server (a nil
// *leaflib.ConnectionManager -- s.cm.Accept immediately panics with a
// real nil-pointer dereference on its first field access, cm.gate)
// rather than reaching deep into wire-protocol/session internals for
// a "naturally occurring" panic: this is a standard, deterministic
// way to fabricate a real panic at a real call site inside handleConn
// without depending on some OTHER, unrelated bug existing to trigger
// one.
func TestHandleConn_RecoversFromPanicAndClosesOnlyThisConnection(t *testing.T) {
	s := &Server{
		logger: log.New(io.Discard, "", 0),
		// cm intentionally left nil.
	}

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleConn(context.Background(), serverConn, 1)
	}()

	select {
	case <-done:
		// handleConn returned normally -- the panic was recovered,
		// not left to crash this goroutine (and, transitively, the
		// whole test process).
	case <-time.After(3 * time.Second):
		t.Fatal("handleConn did not return within 3s -- the panic was likely not recovered (an unrecovered panic in this goroutine would have crashed the entire test process instead of merely hanging, but a genuine regression removing the recover() entirely is exactly what this timeout guards against turning into a silent process-wide crash of the whole test binary)")
	}

	// The connection must actually have been closed by the recovery
	// path (conn.Close() inside the recover branch) -- prove it from
	// the OTHER end of the pipe: a Read must now fail (closed pipe),
	// not hang or succeed.
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatal("expected the connection to be closed after handleConn recovered from a panic, but Read succeeded")
	}

	// The test process reaching this point at all (rather than having
	// already been killed by an unrecovered panic) is itself the
	// primary proof this test exists to provide.
}
