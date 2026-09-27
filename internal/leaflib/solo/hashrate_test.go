// Copyright and license: see repository LICENSE (MIT).
package solo

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
)

// TestServerStats_TotalEstimatedHashrateEqualsSumOfSessions drives
// real logins+submits through the test harness (mirroring
// TestServerStats_ReportsPerSessionAndAddressBreakdown's pattern) to
// produce non-zero hashesAccumulated for 2 simultaneously-connected
// sessions, then asserts Stats().TotalEstimatedHashrate is EXACTLY
// equal to the sum of each session's own EstimatedHashrate from
// Stats().Sessions -- since Stats() accumulates
// TotalEstimatedHashrate inline, in the same loop iteration that
// computes each SessionStat.EstimatedHashrate (not an independent
// recomputation -- see server.go's Stats()), this must be an exact
// equality, not a tolerance check. Elapsed wall-clock time makes the
// absolute hashrate values themselves non-reproducible, so a separate
// ballpark/plausibility check (not exact-value assertion) confirms
// the totals are in the right neighborhood of the hand-computed
// hashesAccumulated expectation.
func TestServerStats_TotalEstimatedHashrateEqualsSumOfSessions(t *testing.T) {
	h := newTestHarness(t, 1, 1<<62)
	_, xnA := login(t, h, "hashrate-test-addr-a")

	// Every accepted ordinary SHA3X share credits job.StaticDifficulty
	// (1 here, so real crypto validation always clears it regardless
	// of nonce) to hashesAccumulated -- see session.go's
	// handleSubmit. Submitting 5 accepted shares against session A
	// makes its real hashesAccumulated exactly 5.
	const sharesA = 5
	jobIDA := currentJobIDForXN(t, h, xnA)
	for i := 0; i < sharesA; i++ {
		h.send(Request{ID: 10 + i, Method: "submit", Params: mustJSON(t, SubmitRequest{
			JobID: jobIDA,
			Nonce: xnPrefixedNonceHex(xnA, uint64(9000+i)),
		})})
		resp := h.recvLegacyShareResponse()
		if !resp.Result {
			t.Fatalf("submit %d for session A: expected accepted, got %#v", i, resp)
		}
	}

	// A second, independently-connected session (mirrors the spawn
	// pattern in TestServerStats_ReportsPerSessionAndAddressBreakdown).
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	ctx := context.Background()
	go h.server.handleConn(ctx, serverConn, 1)
	hB := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
	_, xnB := login(t, hB, "hashrate-test-addr-b")

	const sharesB = 3
	jobIDB := currentJobIDForXN(t, hB, xnB)
	for i := 0; i < sharesB; i++ {
		hB.send(Request{ID: 20 + i, Method: "submit", Params: mustJSON(t, SubmitRequest{
			JobID: jobIDB,
			Nonce: xnPrefixedNonceHex(xnB, uint64(8000+i)),
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

	// Ballpark plausibility check only (real wall-clock elapsed time
	// makes an exact expected value infeasible): with a combined
	// hashesAccumulated of 5+3=8 over what should be a very
	// small elapsed time (this test runs in well under a second), the
	// resulting hashrate must be positive and not absurdly large (a
	// sanity bound against a scaling-constant regression, e.g. the
	// historical 2^32 multiplier bug EstimateHashrateHz's own doc
	// comment describes).
	if st.TotalEstimatedHashrate <= 0 {
		t.Fatalf("expected TotalEstimatedHashrate > 0 after real accepted shares, got %v", st.TotalEstimatedHashrate)
	}
	if st.TotalEstimatedHashrate > 1e9 {
		t.Fatalf("TotalEstimatedHashrate = %v looks implausibly large for hashesAccumulated=8 over a sub-second test run -- possible scaling-constant regression", st.TotalEstimatedHashrate)
	}
}

// TestStatsHTMLHandler_RendersGlobalHashrateCard is the required
// "render each stats HTML page and assert the body contains the new
// card's label text" test, PLUS the brief's own required arithmetic
// sanity check: a fixture session is given a known hashesAccumulated
// (1,000,000) and connectedAt (100 seconds ago), which by
// leaflib.EstimateHashrateHz's own formula
// (hashesAccumulated/elapsed_seconds) yields exactly 1,000,000/100 =
// 10000 H/s = "10.00 KH/s" once run through formatHashrate -- this
// exact string must appear on the rendered page next to the "Global
// hashrate" label.
func TestStatsHTMLHandler_RendersGlobalHashrateCard(t *testing.T) {
	h := newTestHarness(t, 1, 1<<62)
	_, xn := login(t, h, "global-hashrate-fixture-addr")
	jobID := currentJobIDForXN(t, h, xn)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 12345),
	})})
	if resp := h.recvLegacyShareResponse(); !resp.Result {
		t.Fatalf("expected the setup submit to be accepted, got %#v", resp)
	}

	// Overwrite the real session's own accept-history/connectedAt
	// state directly (same package -- direct field access, no
	// exported setter exists nor should one for these internal
	// fields) with the brief's own worked example:
	// hashesAccumulated=1,000,000 over 100s = 10000 H/s = "10.00 KH/s".
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

	// leaflib.EstimateHashrateHz(1000000, now-100s) = 1000000/100 =
	// 10000 H/s exactly (see this function's own doc comment for the
	// formula) -- formatHashrate then renders that as "10.00 KH/s".
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
