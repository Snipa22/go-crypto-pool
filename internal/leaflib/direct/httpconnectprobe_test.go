// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
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
	h := newDirectTestHarness(t, 1000, 1<<62)
	h.server.EnableMetrics("dev", 0)

	// handleConn registers the session into s.server.sessions on its
	// own goroutine before ever reaching Session.Run/handleLine --
	// poll briefly rather than asserting instantaneously, since this
	// test goroutine races that registration.
	waitForSessionCount(t, h.server, 1)

	if _, err := h.writer.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write CONNECT probe line: %v", err)
	}
	if err := h.writer.Flush(); err != nil {
		t.Fatalf("flush CONNECT probe line: %v", err)
	}

	// The connection must close immediately: a read from the client
	// side must return an error (EOF/closed), never a stratum-shaped
	// response line.
	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := h.client.Read(buf)
	if err == nil {
		t.Fatalf("expected the connection to be closed after an HTTP CONNECT probe, got %d bytes instead: %q", n, buf[:n])
	}

	// "Drop them from tracking": handleConn's EXISTING deferred
	// cleanup removes the session from s.server.sessions once
	// Session.Run's read loop exits.
	waitForSessionCount(t, h.server, 0)

	body := scrapeMetrics(t, h.server)
	want := `leaf_direct_connection_errors_total{category="` + connErrorHTTPConnectProbe + `"} 1`
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
	h := newDirectTestHarness(t, 1000, 1<<62)

	if _, err := h.writer.Write([]byte("{not valid json\n")); err != nil {
		t.Fatalf("write malformed-json line: %v", err)
	}
	if err := h.writer.Flush(); err != nil {
		t.Fatalf("flush malformed-json line: %v", err)
	}

	// The connection must stay open -- a well-formed login sent
	// immediately afterward on the SAME connection must still
	// succeed normally.
	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: realTariTestAddress("addr-after-malformed-json"), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("expected login to still succeed after a malformed-JSON line (connection must not have been closed), got status=%q", resp.Result.Status)
	}

	waitForSessionCount(t, h.server, 1)
}

// waitForSessionCount polls s.sessions until it reaches want, failing
// the test if that doesn't happen within a bounded deadline. Mirrors
// TestDirectInvalidateAndRepushJobsRecordsTemplateDistributionMetrics's
// own identical polling pattern (session_test.go) for the same
// reason: session registration/removal happens on handleConn's own
// goroutine, racing the test goroutine.
func waitForSessionCount(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.RLock()
		count := len(s.sessions)
		s.mu.RUnlock()
		if count == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected session count %d, got %d (timed out waiting)", want, count)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
