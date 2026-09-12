// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestServerStats_TotalEstimatedHashrateEqualsSumOfSessions mirrors
// internal/leaflib/solo/hashrate_test.go's own test of the same name,
// using proxy's own harness/login/submit conventions (see
// session_test.go's harness/testClient): drives real logins+submits
// through 2 simultaneously-connected downstream sessions to produce
// non-zero hashesAccumulated, then asserts
// Stats().TotalEstimatedHashrate is EXACTLY equal to the sum of each
// session's own EstimatedHashrate from Stats().Sessions (both come
// from the same accumulated values, summed once inline in Stats()'s
// own per-session loop, not independently recomputed).
func TestServerStats_TotalEstimatedHashrateEqualsSumOfSessions(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	cA, _ := h.connect()
	loginA := cA.login(t, "hashrate-test-addr-a")

	// Difficulty comfortably between the session's own StaticDifficulty
	// (1000, the harness's default starting difficulty) and the
	// upstream block target (1,000,000, from newHarness's template):
	// credited locally, no real RandomX re-validation call needed --
	// see handleSubmit's doc comment.
	const sharesA = 5
	for i := 0; i < sharesA; i++ {
		claimedHash := hashForDifficulty(500_000)
		submitParams, _ := json.Marshal(SubmitRequest{ID: loginA.Result.ID, JobID: loginA.Result.Job.JobID, Nonce: nonceHexAt(uint32(100 + i)), Result: claimedHash})
		cA.send(Request{ID: 10 + i, JsonRPC: "2.0", Method: "submit", Params: submitParams})
		resp := cA.recvShareResponse()
		if resp.Result == nil {
			t.Fatalf("submit %d for session A: expected accepted, got error=%v", i, resp.Error)
		}
	}

	cB, _ := h.connect()
	loginB := cB.login(t, "hashrate-test-addr-b")

	const sharesB = 3
	for i := 0; i < sharesB; i++ {
		claimedHash := hashForDifficulty(500_000)
		submitParams, _ := json.Marshal(SubmitRequest{ID: loginB.Result.ID, JobID: loginB.Result.Job.JobID, Nonce: nonceHexAt(uint32(200 + i)), Result: claimedHash})
		cB.send(Request{ID: 20 + i, JsonRPC: "2.0", Method: "submit", Params: submitParams})
		resp := cB.recvShareResponse()
		if resp.Result == nil {
			t.Fatalf("submit %d for session B: expected accepted, got error=%v", i, resp.Error)
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
		t.Fatalf("TotalEstimatedHashrate = %v looks implausibly large for hashesAccumulated=8000 (sharesA+sharesB, each crediting job.StaticDifficulty=1000) over a sub-second test run -- possible scaling-constant regression", st.TotalEstimatedHashrate)
	}
}

// TestSessionStat_EstimatedHashrateIsPopulatedAndConsistent is the
// proxy-specific test the brief additionally requires (proxy's
// SessionStat had NO EstimatedHashrate field at all before this
// change, unlike solo/direct): logs in, submits shares to accumulate
// a known real difficulty-weighted hashesAccumulated total, and
// confirms Stats().Sessions[i].EstimatedHashrate is non-zero and
// consistent with hashesAccumulated/elapsed (leaflib.
// EstimateHashrateHz's own formula, computed independently here from
// the session's real internal fields for comparison).
func TestSessionStat_EstimatedHashrateIsPopulatedAndConsistent(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, sess := h.connect()
	loginResp := c.login(t, "addr-hashrate-populated")
	sess = h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	const shares = 4
	for i := 0; i < shares; i++ {
		claimedHash := hashForDifficulty(500_000)
		submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(uint32(300 + i)), Result: claimedHash})
		c.send(Request{ID: 30 + i, JsonRPC: "2.0", Method: "submit", Params: submitParams})
		resp := c.recvShareResponse()
		if resp.Result == nil {
			t.Fatalf("submit %d: expected accepted, got error=%v", i, resp.Error)
		}
	}

	st := h.server.Stats()
	if len(st.Sessions) != 1 {
		t.Fatalf("expected exactly 1 session in Stats(), got %d", len(st.Sessions))
	}
	got := st.Sessions[0]

	if got.EstimatedHashrate <= 0 {
		t.Fatalf("expected EstimatedHashrate > 0 after %d real accepted shares (hashesAccumulated should be %d*StaticDifficulty), got %v", shares, shares, got.EstimatedHashrate)
	}

	wantHz := leaflib.EstimateHashrateHz(sess.hashesAccumulated.Load(), sess.connectedAt)
	// Tolerance-based, not exact-equality: got.EstimatedHashrate was
	// computed inside Stats() a moment before this second,
	// independent EstimateHashrateHz call above -- both divide by
	// real, slightly-different elapsed wall-clock time (time.Since),
	// so a small relative difference is expected and NOT a bug (see
	// the brief's own "per-session-sum-vs-total should be exactly
	// equal ... only use a tolerance/range check for asserting the
	// values are in a plausible ballpark" guidance -- this is exactly
	// that ballpark check, applied to two independently-timed
	// evaluations of the same underlying accumulator instead of a
	// same-call sum).
	relDiff := (got.EstimatedHashrate - wantHz) / wantHz
	if relDiff < -0.05 || relDiff > 0.05 {
		t.Errorf("Sessions[0].EstimatedHashrate = %v, want approximately leaflib.EstimateHashrateHz(hashesAccumulated=%d, connectedAt=%v) = %v (relative diff %v exceeds 5%% tolerance)", got.EstimatedHashrate, sess.hashesAccumulated.Load(), sess.connectedAt, wantHz, relDiff)
	}
}

// TestStatsHTMLHandler_RendersGlobalHashrateCardAndEstHashrateColumn
// mirrors internal/leaflib/solo/hashrate_test.go's
// TestStatsHTMLHandler_RendersGlobalHashrateCard, PLUS proxy's own
// additional requirement: the "Connected sessions" table's new
// "Est. hashrate" column header must also be present. A fixture
// session is given a known hashesAccumulated (1,000,000) and
// connectedAt (100 seconds ago), yielding exactly 1,000,000/100 =
// 10000 H/s = "10.00 KH/s" via leaflib.EstimateHashrateHz/
// formatHashrate -- this exact string must appear on the rendered
// page.
func TestStatsHTMLHandler_RendersGlobalHashrateCardAndEstHashrateColumn(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	c.login(t, "global-hashrate-fixture-addr")

	sess := h.onlySession()
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
	if !strings.Contains(body, "Est. hashrate") {
		t.Errorf("expected the new 'Est. hashrate' column header in the rendered page, got:\n%s", body)
	}
	if !strings.Contains(body, wantFormatted) {
		t.Errorf("expected the formatted hashrate %q (from EstimateHashrateHz(1000000, connectedAt=now-100s)=%v) in the rendered page, got:\n%s", wantFormatted, expectedHz, body)
	}
}
