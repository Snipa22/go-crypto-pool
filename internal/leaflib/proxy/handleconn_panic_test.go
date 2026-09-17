// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

// TestHandleConn_RecoversFromPanicAndClosesOnlyThisConnection mirrors
// solo package's own identical test exactly -- see that test's doc
// comment (FIX_BRIEF.md, finding #20) for the full rationale.
func TestHandleConn_RecoversFromPanicAndClosesOnlyThisConnection(t *testing.T) {
	s := &Server{
		logger: log.New(io.Discard, "", 0),
		// cm intentionally left nil so s.cm.Accept panics immediately
		// with a real nil-pointer dereference (cm.gate field access).
	}

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleConn(context.Background(), serverConn, 1, "")
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleConn did not return within 3s -- the panic was likely not recovered")
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatal("expected the connection to be closed after handleConn recovered from a panic, but Read succeeded")
	}
}
