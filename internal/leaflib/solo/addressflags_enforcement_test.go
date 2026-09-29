package solo

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
)

// fakeAddressFlagsSource is an in-memory addressflags.Source for
// tests -- lets a test directly control what a Cache.Get call
// returns without any real HTTP/file I/O, and lets a test flip a
// flag mid-session (simulating an operator banning an address while
// a miner is already connected) by mutating flags and forcing a
// fresh poll via Cache.Start's own pollOnce path (exercised here via
// re-fetching, not by waiting out DefaultPollInterval).
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

// TestSessionLogin_RejectsBannedAddress is a real regression test for
// session.go's handleLogin ban check: a real, correctly-shaped Tari
// address that the address-flags Cache reports as Banned must be
// rejected at login, before loggedIn is ever flipped to true.
func TestSessionLogin_RejectsBannedAddress(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	addr := realTariTestAddress("banned-at-login")
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {Banned: true},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	raw := h.recvRaw()

	// newTestHarness defaults to ALGO_SHA3X, which now uses the
	// legacy bare-string LegacyErrorResponse wire shape for
	// writeGeneralResponse (see session.go's writeGeneralResponse
	// and protocol.go's LegacyErrorResponse doc comment) -- decode
	// with a bare string Error field, not the object/null *RPCError
	// shape.
	var generic struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected a banned address's login to be rejected, got status=OK (raw=%s)", raw)
	}
	if generic.Error == "" {
		t.Errorf("expected a non-empty rejection error message, got none (raw=%s)", raw)
	}
}

// TestSessionSubmit_RejectsAddressBannedMidSession is the real
// regression test for the gap Alex explicitly flagged: a session
// that logged in BEFORE its address was banned must have its
// SUBSEQUENT submits rejected too, not just future logins -- an
// already-connected botnet does not disconnect just because an
// operator banned it after the fact.
func TestSessionSubmit_RejectsAddressBannedMidSession(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	addr := realTariTestAddress("banned-mid-session")
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)
	h.server.EnableAddressFlags(cache)

	// Real login while genuinely unbanned -- must succeed.
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	loginResp := h.recvLoginResponse()
	if loginResp.Result.Status != "OK" {
		t.Fatalf("setup: expected login to succeed while unbanned, got status=%q", loginResp.Result.Status)
	}
	sessionID, xn := loginResp.Result.ID, loginResp.Result.Job.XN
	jobID := currentJobIDForSession(t, h, xn)

	// A real operator action bans this address while the session is
	// already connected -- update the fake source; the Cache's own
	// background poll (20ms interval, set above) will pick this up
	// shortly, exactly as a live leaf's real poll loop would after
	// an operator's real CLI action.
	src.set(addr, addressflags.Flags{Banned: true})
	waitForCachePoll(t, cache, addr, true)

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: xn + "00000000",
	})})
	resp := h.recvLegacyShareResponse()
	if resp.Result {
		t.Fatal("expected a submit from a now-mid-session-banned address to be rejected, got accepted")
	}
}

// waitForCachePoll polls cache.Get(addr) until it reports the real
// wantBanned state or the test times out -- avoids a fixed sleep
// racing against the Cache's own background poll goroutine.
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
