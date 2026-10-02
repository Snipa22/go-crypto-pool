// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// TestSession_HTTPRequestProbe_ClosesConnectionAndDropsFromTracking is
// the required end-to-end test for DISPATCH_BRIEF_HTTP_CONNECT_PROBE.md
// (originally CONNECT-only) generalized by
// DISPATCH_BRIEF_HTTP_PROBE_GENERALIZE.md to cover the full standard
// HTTP method set (through the real handleConn/net.Pipe()-based
// harness this package's other tests already use): sending a real
// HTTP request line for any of these methods causes the connection to
// close immediately (read from the client side returns EOF/closed,
// not a stratum-shaped response), and the session is dropped from
// s.server.sessions once handleConn's existing deferred cleanup runs.
func TestSession_HTTPRequestProbe_ClosesConnectionAndDropsFromTracking(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{name: "CONNECT", line: "CONNECT example.com:443 HTTP/1.1\r\n"},
		{name: "GET", line: "GET / HTTP/1.1\r\n"},
		{name: "HEAD", line: "HEAD /status HTTP/1.1\r\n"},
		{name: "POST", line: "POST /submit HTTP/1.1\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDirectTestHarness(t, 1000, 1<<62)
			h.server.EnableMetrics("dev", 0)

			// handleConn registers the session into s.server.sessions
			// on its own goroutine before ever reaching
			// Session.Run/handleLine -- poll briefly rather than
			// asserting instantaneously, since this test goroutine
			// races that registration.
			waitForSessionCount(t, h.server, 1)

			if _, err := h.writer.Write([]byte(tc.line)); err != nil {
				t.Fatalf("write %s probe line: %v", tc.name, err)
			}
			if err := h.writer.Flush(); err != nil {
				t.Fatalf("flush %s probe line: %v", tc.name, err)
			}

			// The connection must close immediately: a read from the
			// client side must return an error (EOF/closed), never a
			// stratum-shaped response line.
			_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 64)
			n, err := h.client.Read(buf)
			if err == nil {
				t.Fatalf("expected the connection to be closed after an HTTP %s probe, got %d bytes instead: %q", tc.name, n, buf[:n])
			}

			// "Drop them from tracking": handleConn's EXISTING
			// deferred cleanup removes the session from
			// s.server.sessions once Session.Run's read loop exits.
			waitForSessionCount(t, h.server, 0)

			body := scrapeMetrics(t, h.server)
			want := `leaf_direct_connection_errors_total{category="` + connErrorHTTPRequestProbe + `"} 1`
			if !strings.Contains(body, want) {
				t.Errorf("expected %q in scraped metrics, got:\n%s", want, body)
			}
		})
	}
}

// TestSession_HTTPRequestProbe_MultiLineRequestOnlyLogsOnce is the
// required reproduction of the EXACT real-world scenario from
// DISPATCH_BRIEF_HTTP_PROBE_GENERALIZE.md's production log evidence
// (session 8bcf5048aa6ed): a real HTTP GET request line followed by
// several headers, all arriving together. Before the generalization
// this brief implements, the pre-existing CONNECT-only guard did not
// catch GET at all, so the request fell through to the
// "sent unparseable message" path and logged ONE SEPARATE line per
// header (five lines in the real production evidence). This test
// proves two things at once through the real
// handleConn/net.Pipe()-based harness: (1) the generalized check now
// catches the GET request line just like CONNECT, and (2) only the
// FIRST line of the request is ever handled -- the connection closes
// immediately and exactly ONE probe-detected connection-error
// increment is recorded for the whole connection, not one per header
// line (proving Session.Run's ctx.Err() check, documented on that
// method, actually closes the no-gap it must close).
func TestSession_HTTPRequestProbe_MultiLineRequestOnlyLogsOnce(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)
	h.server.EnableMetrics("dev", 0)

	waitForSessionCount(t, h.server, 1)

	// The exact multi-line shape from the real production log
	// evidence cited in DISPATCH_BRIEF_HTTP_PROBE_GENERALIZE.md:
	// request line + four headers, written as a SINGLE Write call so
	// they arrive at the server side together (mirroring how a real
	// TCP segment carrying a full HTTP request behaves).
	request := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: curl/8.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: keep-alive\r\n\r\n"
	if _, err := h.writer.Write([]byte(request)); err != nil {
		t.Fatalf("write multi-line GET request: %v", err)
	}
	if err := h.writer.Flush(); err != nil {
		t.Fatalf("flush multi-line GET request: %v", err)
	}

	// The connection must close immediately after the FIRST line.
	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := h.client.Read(buf)
	if err == nil {
		t.Fatalf("expected the connection to be closed after the HTTP GET request's first line, got %d bytes instead: %q", n, buf[:n])
	}

	waitForSessionCount(t, h.server, 0)

	// The real fix: exactly ONE probe-detected increment for the
	// WHOLE connection, never one per header line.
	body := scrapeMetrics(t, h.server)
	want := `leaf_direct_connection_errors_total{category="` + connErrorHTTPRequestProbe + `"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected exactly one probe-detected increment (%q) in scraped metrics -- proving no per-header log/metric spam -- got:\n%s", want, body)
	}
}

// TestSession_MalformedJSON_StillFallsThroughToUnparseableMessagePath
// is this feature's required regression check (DISPATCH_BRIEF_HTTP_CONNECT_PROBE.md
// "Required verification before you report done", item 2, still
// applicable unchanged after DISPATCH_BRIEF_HTTP_PROBE_GENERALIZE.md's
// generalization): an ordinary ill-formed-but-not-HTTP-request line
// must still fall through to the EXISTING "unparseable message"
// behavior unchanged -- the connection stays open (a subsequent,
// well-formed login on the SAME connection still succeeds), proving
// the new HTTP-request-probe check does not swallow the pre-existing
// malformed-JSON path.
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
