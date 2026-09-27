// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
)

// fakeAddressFlagsSource mirrors
// internal/leaflib/solo/addressflags_enforcement_test.go's identical
// fixture exactly: an in-memory addressflags.Source that lets a test
// directly control what a Cache.Get call returns without any real
// file I/O, and lets a test flip a flag mid-session (simulating an
// operator banning an address while a downstream miner is already
// connected) via set + waitForCachePoll below.
type fakeAddressFlagsSource struct {
	mu    sync.Mutex
	flags map[string]addressflags.Flags
}

func (s *fakeAddressFlagsSource) Fetch(_ context.Context) (map[string]addressflags.Flags, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]addressflags.Flags, len(s.flags))
	for k, v := range s.flags {
		out[k] = v
	}
	return out, nil
}

func (s *fakeAddressFlagsSource) set(addr string, f addressflags.Flags) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flags[addr] = f
}

// waitForCachePoll mirrors solo's identical helper exactly -- polls
// cache.Get(addr) until it reports the real wantBanned state or the
// test times out, avoiding a fixed sleep racing against the Cache's
// own background poll goroutine.
func waitForCachePoll(t *testing.T, cache *addressflags.Cache, addr string, wantBanned bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if cache.Get(addr).Banned == wantBanned {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("address-flags cache never reflected Banned=%v for %s within the test deadline", wantBanned, addr)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSessionLogin_RejectsBannedAddress is leaf-proxy's real
// regression test for Gap 1 (DISPATCH_BRIEF.md): a downstream
// miner's login address that the address-flags Cache reports as
// Banned must be rejected at login, before loggedIn is ever flipped
// to true, and BEFORE any upstream job is fetched/handed out to it.
func TestSessionLogin_RejectsBannedAddress(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	addr := "banned-at-login"
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {Banned: true},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0"})})

	var resp ErrorResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		t.Fatalf("unmarshal login rejection response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected a banned address's login to be rejected with a non-nil error, got none")
	}
	if resp.Error.Message == "" {
		t.Error("expected a non-empty rejection error message")
	}

	if h.sessionCount() != 1 {
		t.Fatalf("expected the connection itself to still be registered (rejection is at the protocol level, not connection level), got %d sessions", h.sessionCount())
	}
	sess := h.onlySession()
	if sess.loggedIn.Load() {
		t.Fatal("expected loggedIn to remain false after a rejected (banned) login")
	}
}

// TestSessionSubmit_RejectsAddressBannedMidSession is the real
// regression test for the gap DISPATCH_BRIEF.md explicitly flags: a
// downstream session that logged in BEFORE its address was banned
// must have its SUBSEQUENT submits rejected too, not just future
// logins -- an already-connected botnet does not disconnect just
// because an operator banned it after the fact.
func TestSessionSubmit_RejectsAddressBannedMidSession(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	addr := "banned-mid-session"
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)
	h.server.EnableAddressFlags(cache)

	c, _ := h.connect()
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("setup: expected login to succeed while unbanned, got status=%q", loginResp.Result.Status)
	}
	jobID := loginResp.Result.Job.JobID

	// A real operator action bans this address while the session is
	// already connected -- the Cache's own background poll (20ms
	// interval, set above) will pick this up shortly, exactly as a
	// live leaf's real poll loop would after an operator's real CLI
	// action.
	src.set(addr, addressflags.Flags{Banned: true})
	waitForCachePoll(t, cache, addr, true)

	claimedHash := hashForDifficulty(50_000)
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected a submit from a now-mid-session-banned address to be rejected, got accepted")
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Error("expected a non-empty rejection error message for a mid-session-banned submit")
	}

	if h.upstream.callCount() != 0 {
		t.Errorf("a rejected (banned) submit must never reach the upstream pool, got %d calls", h.upstream.callCount())
	}
}

// TestSessionLogin_UnbannedAddress_StillSucceeds is a real
// non-regression check: EnableAddressFlags being called at all must
// not affect an address that is genuinely NOT flagged -- mirrors this
// package's other tests' baseline login flow, just with a Cache
// wired in (so a nil-vs-non-nil s.server.addressFlags codepath
// difference alone can never be the reason this passes).
func TestSessionLogin_UnbannedAddress_StillSucceeds(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		"some-other-banned-address": {Banned: true},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connect()
	loginResp := c.login(t, "genuinely-unbanned-address")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected an unflagged address's login to succeed, got status=%q", loginResp.Result.Status)
	}
}

// mustMarshal is a small json.Marshal-or-Fatal helper, local to this
// test file (session_test.go's testClient.login already builds its
// own params inline, but the banned-login test above needs to control
// the address independently of that helper's fixed param shape).
func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
