// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// TestServerStats_TotalEstimatedHashrateEqualsSumOfSessions mirrors
// internal/leaflib/solo/hashrate_test.go's own test of the same name:
// drives real logins+submits through the direct test harness to
// produce non-zero hashesAccumulated for 2 simultaneously-connected
// sessions, then asserts Stats().TotalEstimatedHashrate is EXACTLY
// equal to the sum of each session's own EstimatedHashrate from
// Stats().Sessions (both come from the same accumulated values,
// summed once inline in Stats()'s own per-session loop, not
// independently recomputed).
func TestServerStats_TotalEstimatedHashrateEqualsSumOfSessions(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1<<62)
	_, xnA := directLogin(t, h, realTariTestAddress("hashrate-test-addr-a"))

	const sharesA = 5
	jobIDA := directCurrentJobIDForSession(t, h, xnA)
	for i := 0; i < sharesA; i++ {
		h.send(solo.Request{ID: 10 + i, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			JobID: jobIDA,
			Nonce: directXNPrefixedNonceHexBigEndian(xnA, uint64(9000+i)),
		})})
		resp := h.recvLegacyShareResponse()
		if !resp.Result {
			t.Fatalf("submit %d for session A: expected accepted, got %#v", i, resp)
		}
	}

	// A second, independently-connected session.
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	ctx := context.Background()
	go h.server.handleConn(ctx, serverConn, 1)
	hB := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
	_, xnB := directLogin(t, hB, realTariTestAddress("hashrate-test-addr-b"))

	const sharesB = 3
	jobIDB := directCurrentJobIDForSession(t, hB, xnB)
	for i := 0; i < sharesB; i++ {
		hB.send(solo.Request{ID: 20 + i, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			JobID: jobIDB,
			Nonce: directXNPrefixedNonceHexBigEndian(xnB, uint64(8000+i)),
		})})
		resp := hB.recvLegacyShareResponse()
		if !resp.Result {
			t.Fatalf("submit %d for session B: expected accepted, got %#v", i, resp)
		}
	}

	st := h.server.Stats()
	if len(st.Sessions) < 2 {
		t.Fatalf("expected at least 2 sessions in Stats(), got %d", len(st.Sessions))
	}

	var sum float64
	for _, sess := range st.Sessions {
		sum += sess.EstimatedHashrate
	}
	if sum != st.TotalEstimatedHashrate {
		t.Fatalf("sum of per-session EstimatedHashrate (%v) != TotalEstimatedHashrate (%v); these must be EXACTLY equal since both come from the same accumulated values summed once, not independently recomputed", sum, st.TotalEstimatedHashrate)
	}

	if st.TotalEstimatedHashrate <= 0 {
		t.Fatalf("expected TotalEstimatedHashrate > 0 after real accepted shares, got %v", st.TotalEstimatedHashrate)
	}
	if st.TotalEstimatedHashrate > 1e9 {
		t.Fatalf("TotalEstimatedHashrate = %v looks implausibly large for hashesAccumulated=8 over a sub-second test run -- possible scaling-constant regression", st.TotalEstimatedHashrate)
	}
}

// TestStatsHTMLHandler_RendersGlobalHashrateCard mirrors
// internal/leaflib/solo/hashrate_test.go's own test of the same name:
// a fixture session is given a known hashesAccumulated (1,000,000)
// and connectedAt (100 seconds ago), yielding exactly
// 1,000,000/100 = 10000 H/s = "10.00 KH/s" via
// leaflib.EstimateHashrateHz/formatHashrate -- this exact string must
// appear on the rendered page next to the "Global hashrate" label.
func TestStatsHTMLHandler_RendersGlobalHashrateCard(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1<<62)
	_, xn := directLogin(t, h, realTariTestAddress("global-hashrate-fixture-addr"))
	jobID := directCurrentJobIDForSession(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID,
		Nonce: directXNPrefixedNonceHexBigEndian(xn, 12345),
	})})
	if resp := h.recvLegacyShareResponse(); !resp.Result {
		t.Fatalf("expected the setup submit to be accepted, got %#v", resp)
	}

	h.server.mu.RLock()
	var sess *Session
	for _, s := range h.server.sessions {
		sess = s
		break
	}
	h.server.mu.RUnlock()
	if sess == nil {
		t.Fatal("expected exactly one connected session after login")
	}
	sess.hashesAccumulated.Store(1000000)
	sess.connectedAt = time.Now().Add(-100 * time.Second)

	expectedHz := leaflib.EstimateHashrateHz(sess.hashesAccumulated.Load(), sess.connectedAt)
	wantFormatted := formatHashrate(expectedHz)
	t.Logf("verification: EstimateHashrateHz(1000000, connectedAt=now-100s) = %v H/s; formatHashrate(...) = %q (expected ~10000 H/s / %q)", expectedHz, wantFormatted, "10.00 KH/s")

	srv := httptest.NewServer(h.server.StatsHTMLHandler())
	defer srv.Close()

	httpResp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET stats page: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", httpResp.StatusCode)
	}

	buf := make([]byte, 65536)
	n, _ := httpResp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "Global hashrate") {
		t.Errorf("expected the new 'Global hashrate' card label in the rendered page, got:\n%s", body)
	}
	if !strings.Contains(body, wantFormatted) {
		t.Errorf("expected the formatted hashrate %q (from EstimateHashrateHz(1000000, connectedAt=now-100s)=%v) in the rendered page, got:\n%s", wantFormatted, expectedHz, body)
	}
}
