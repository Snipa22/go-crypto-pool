// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestSessionLogin_RejectsOversizedLoginString is the required Fix 8
// test (DISPATCH_BRIEF.md 2026-09-10): a login string exceeding
// maxProxyLoginLen must be rejected cleanly (a normal error response,
// not a panic/dropped connection), and BEFORE it ever becomes this
// session's stored address.
func TestSessionLogin_RejectsOversizedLoginString(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	oversized := strings.Repeat("a", maxProxyLoginLen+1)

	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: oversized, Pass: "rig1", Agent: "XMRig/6.21.0"})})

	var resp ErrorResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		t.Fatalf("unmarshal oversized-login rejection response: %v", err)
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatal("expected an oversized login string to be rejected with a non-empty error message, got none")
	}

	sess := h.onlySession()
	if sess.loggedIn.Load() {
		t.Fatal("expected loggedIn to remain false after a rejected (oversized) login")
	}
	if addr, _ := sess.address.Load().(string); addr == oversized {
		t.Fatal("expected the oversized login string to never be stored as this session's address")
	}
}

// TestSessionLogin_AcceptsLoginStringAtExactlyTheLimit is the
// boundary non-regression check: a login string at EXACTLY
// maxProxyLoginLen bytes must still be accepted (only strictly-over
// is rejected) -- confirmed here using a syntactically-plausible
// (if not cryptographically valid) address-shaped string, since
// leaf-proxy imposes no format/charset check, only a length bound
// (see maxProxyLoginLen's own doc comment).
func TestSessionLogin_AcceptsLoginStringAtExactlyTheLimit(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	atLimit := strings.Repeat("a", maxProxyLoginLen)

	c, _ := h.connect()
	loginResp := c.login(t, atLimit)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected a login string at exactly the %d-byte limit to be accepted, got status=%q", maxProxyLoginLen, loginResp.Result.Status)
	}

	sess := h.onlySession()
	if !sess.loggedIn.Load() {
		t.Fatal("expected loggedIn to be true after an accepted login at exactly the limit")
	}
}
