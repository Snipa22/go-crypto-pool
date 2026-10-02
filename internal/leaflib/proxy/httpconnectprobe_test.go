// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	proxymetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy/metrics"
)

// TestSession_HTTPConnectProbe_ClosesConnectionAndDropsFromTracking is
// the required end-to-end test for DISPATCH_BRIEF_HTTP_CONNECT_PROBE.md
// (through the real handleConn/net.Pipe()-based harness this package's
// other tests already use): sending a real
// "CONNECT example.com:443 HTTP/1.1\r\n" line causes the connection to
// close immediately (read from the client side returns EOF/closed, not
// a stratum-shaped response), and the session is dropped from
// s.server.sessions once handleConn's existing deferred cleanup runs.
func TestSession_HTTPConnectProbe_ClosesConnectionAndDropsFromTracking(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.EnableMetrics("test", 0)

	c, _ := h.connect()

	// handleConn registers the session into s.server.sessions on its
	// own goroutine before ever reaching Session.Run/handleLine --
	// poll briefly rather than asserting instantaneously, since this
	// test goroutine races that registration.
	deadline := time.Now().Add(5 * time.Second)
	for h.sessionCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("expected the session to be tracked immediately on connect (before any login), got sessionCount=%d", h.sessionCount())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Write a literal HTTP CONNECT probe line directly over the raw
	// connection -- deliberately NOT testClient.send's JSON-request
	// marshaling, since this is the whole point: a non-stratum
	// message hitting the listener.
	if _, err := c.writer.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write CONNECT probe line: %v", err)
	}
	if err := c.writer.Flush(); err != nil {
		t.Fatalf("flush CONNECT probe line: %v", err)
	}

	// The connection must close immediately: a read from the client
	// side must return an error (EOF/closed), never a stratum-shaped
	// response line.
	_ = c.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := c.client.Read(buf)
	if err == nil {
		t.Fatalf("expected the connection to be closed after an HTTP CONNECT probe, got %d bytes instead: %q", n, buf[:n])
	}

	// "Drop them from tracking": handleConn's EXISTING deferred
	// cleanup removes the session from s.server.sessions once
	// Session.Run's read loop exits -- that happens asynchronously
	// relative to this test goroutine, so poll briefly rather than
	// asserting instantaneously.
	deadline = time.Now().Add(5 * time.Second)
	for h.sessionCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("expected the session to be dropped from tracking after the HTTP CONNECT probe, got sessionCount=%d", h.sessionCount())
		}
		time.Sleep(10 * time.Millisecond)
	}

	body := scrapeMetrics(t, h.server)
	want := `leaf_connection_errors_total{category="` + proxymetrics.ConnErrorHTTPConnectProbe + `"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected %q in scraped metrics, got:\n%s", want, body)
	}
}

// TestSession_MalformedJSON_StillFallsThroughToUnparseableMessagePath
// is this feature's required regression check (DISPATCH_BRIEF_HTTP_CONNECT_PROBE.md
// "Required verification before you report done", item 2): an
// ordinary ill-formed-but-not-HTTP-CONNECT line must still fall
// through to the EXISTING "unparseable message" behavior unchanged --
// the connection stays open (a subsequent, well-formed login on the
// SAME connection still succeeds), proving the new CONNECT-probe check
// does not swallow the pre-existing malformed-JSON path.
func TestSession_MalformedJSON_StillFallsThroughToUnparseableMessagePath(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()

	if _, err := c.writer.Write([]byte("{not valid json\n")); err != nil {
		t.Fatalf("write malformed-json line: %v", err)
	}
	if err := c.writer.Flush(); err != nil {
		t.Fatalf("flush malformed-json line: %v", err)
	}

	// The connection must stay open -- a well-formed login sent
	// immediately afterward on the SAME connection must still
	// succeed normally.
	loginResp := c.login(t, "addr-after-malformed-json")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to still succeed after a malformed-JSON line (connection must not have been closed), got %+v", loginResp)
	}

	if h.sessionCount() != 1 {
		t.Fatalf("expected the session to remain tracked after a malformed-JSON line, got sessionCount=%d", h.sessionCount())
	}
}
