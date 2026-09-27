// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestSessionRepeatedFabricatedUpstreamForwardClaimsGetDisconnected
// is the real, end-to-end proof (DISPATCH_BRIEF.md, 2026-09-10, Fix
// 2b [HIGH — Finding 2]) that leaf-proxy disconnects a downstream
// session that repeatedly submits claims failing REAL re-validation
// -- the actual DoS vector Finding 2 identified: leaf-proxy had NO
// abuse-accounting mechanism of any kind before this fix (unlike
// solo/direct's pre-existing s.trust.RecordOutcome).
//
// SetInvalidShareGuardConfig is called BEFORE h.connect() spawns
// Server.handleConn's goroutine -- required for the same reason
// solo/direct's own equivalent tests require it (a session captures
// server.invalidShareGuardConfig once, at newSession time; calling
// the setter afterward would be a real, go-test -race-detectable
// data race).
func TestSessionRepeatedFabricatedUpstreamForwardClaimsGetDisconnected(t *testing.T) {
	const threshold = 3

	v := &fakeDelayedShareValidator{accept: false} // always fails real re-validation
	up := &fakeUpstream{accept: true}
	h := newAsyncHarness(t, v, up, 1_000_000)
	h.server.SetInvalidShareGuardConfig(leaflib.InvalidShareGuardConfig{Enabled: true, Threshold: threshold})

	c, _ := h.connect()
	loginResp := c.login(t, "randomx-dos")
	jobID := loginResp.Result.Job.JobID

	// Above BOTH the session's own StaticDifficulty (1000) and the
	// upstream target (1,000,000) -- every submit below is a genuine
	// upstream-forward candidate, i.e. every one pays (and fails) the
	// real re-validation this fix's guard is tracking.
	claimedHash := hashForDifficulty(2_000_000)

	for i := 0; i < threshold; i++ {
		submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobID, Nonce: nonceHexAt(uint32(i) + 1), Result: claimedHash})
		if err != nil {
			t.Fatalf("marshal submit params: %v", err)
		}
		c.send(Request{ID: i + 200, JsonRPC: "2.0", Method: "submit", Params: submitParams})
		resp := c.recvShareResponse()
		if resp.Result != nil {
			t.Fatalf("attempt %d: expected fabricated upstream-forward claim to be rejected, got accepted: %#v", i, resp)
		}
	}

	_ = c.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if n, err := c.client.Read(buf); err == nil {
		t.Fatalf("expected the connection to be closed after %d consecutive invalid shares, but Read succeeded (n=%d)", threshold, n)
	}
}
