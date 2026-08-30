package direct

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// fakeAddressFlagsSource mirrors internal/leaflib/solo's own identical
// test helper exactly -- see that package's addressflags_enforcement_test.go
// for the full rationale.
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

// TestDirectSessionLogin_RejectsBannedAddress mirrors solo's own
// identical test -- leaf-direct's handleLogin must reject a banned
// address at login time too.
func TestDirectSessionLogin_RejectsBannedAddress(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1)

	addr := realTariTestAddress("direct-banned-at-login")
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {Banned: true},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	raw := h.recvRaw()

	var generic struct {
		Status string          `json:"status"`
		Error  *solo.RPCError  `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected a banned address's login to be rejected, got status=OK (raw=%s)", raw)
	}
}

// TestDirectSessionSubmit_RejectsAddressBannedMidSession mirrors
// solo's own identical test for the exact scenario Alex explicitly
// flagged: a session logged in before a ban took effect must still
// have its subsequent submits rejected.
func TestDirectSessionSubmit_RejectsAddressBannedMidSession(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1)

	addr := realTariTestAddress("direct-banned-mid-session")
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache.Start(ctx)
	h.server.EnableAddressFlags(cache)

	sessionID, xn := directLogin(t, h, addr)
	jobID := directCurrentJobIDForXN(t, h, xn)

	src.set(addr, addressflags.Flags{Banned: true})
	waitForDirectCachePoll(t, cache, addr, true)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID:    sessionID,
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 999),
	})})
	resp := h.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected a submit from a now-mid-session-banned address to be rejected, got accepted")
	}
}

func waitForDirectCachePoll(t *testing.T, cache *addressflags.Cache, addr string, wantBanned bool) {
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
