// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestMinersJSONHandler_ShapeAndOverview confirms GET /api/miners
// returns the documented JSON shape (generated_at/overview/miners)
// built from the same Stats() snapshot StatsHTMLHandler already uses.
func TestMinersJSONHandler_ShapeAndOverview(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "miners-api-test-addr")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	srv := httptest.NewServer(h.server.MinersJSONHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /api/miners: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}

	var body MinersAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.GeneratedAt == "" {
		t.Error("expected a non-empty generated_at")
	}
	if body.Overview.ActiveSessions != 1 {
		t.Errorf("overview.active_sessions = %d, want 1", body.Overview.ActiveSessions)
	}
	if len(body.Miners) != 1 {
		t.Fatalf("len(miners) = %d, want 1", len(body.Miners))
	}
	m := body.Miners[0]
	if m.Address != "miners-api-test-addr" {
		t.Errorf("miners[0].address = %q, want %q", m.Address, "miners-api-test-addr")
	}
	if m.SessionID == "" {
		t.Error("expected a non-empty session_id")
	}
	if m.RemoteAddr == "" {
		t.Error("expected a non-empty remote_addr when hideRemoteAddress is false (default)")
	}
}

// TestMinersJSONHandler_OmitsRemoteAddrWhenHidden confirms
// remote_addr is genuinely ABSENT from the marshaled JSON (not merely
// empty-stringed) once SetHideRemoteAddress(true) is set, mirroring
// StatsHTMLHandler's own "omit the column entirely" behavior.
func TestMinersJSONHandler_OmitsRemoteAddrWhenHidden(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "hide-remote-api-test")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	h.server.SetHideRemoteAddress(true)

	srv := httptest.NewServer(h.server.MinersJSONHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /api/miners: %v", err)
	}
	defer resp.Body.Close()

	// Decode into a raw map so we can assert the KEY is genuinely
	// absent, not merely an empty string.
	var raw struct {
		Miners []map[string]any `json:"miners"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(raw.Miners) != 1 {
		t.Fatalf("len(miners) = %d, want 1", len(raw.Miners))
	}
	if _, present := raw.Miners[0]["remote_addr"]; present {
		t.Errorf("expected remote_addr key to be ABSENT when hidden, got present with value %v", raw.Miners[0]["remote_addr"])
	}
}

// TestMinersJSONHandler_UncappedBeyondBothStatsPageAndAddressCaps is
// DISPATCH_BRIEF_HASHRATE_API_FOLLOWUP.md section 2's required
// regression test, proving /api/miners is PROVABLY, PERMANENTLY
// uncapped by construction, not just an accident of today's wiring.
//
// Connects more sessions (160) than DefaultStatsPageMaxSessions (150,
// the HTML stats page's "Connected sessions" table cap) across only
// 5 distinct login addresses, while deliberately configuring a tiny
// maxAddressLabels (3) -- fewer than those 5 distinct addresses, so
// CapAddressCounts' address-cardinality cap is genuinely exercised
// (it would fold 2 of the 5 addresses into an "other" bucket for
// StatsHTMLHandler's MinersByAddress breakdown) without needing 150+
// real distinct addresses.
//
// Asserts:
//   - len(response.Miners) == response.Overview.ActiveSessions (every
//     one of the 160 connected sessions shows up individually, no
//     silent truncation to 150 or any other cap), and
//   - every one of the 5 distinct addresses appears, by itself, as
//     the address of at least one entry in response.Miners (not
//     folded into an aggregated "other" bucket) -- confirmed by
//     construction (no entry's address is ever "other", and all 5
//     real addresses are present), not merely by a count that could
//     coincidentally match a capped-but-same-size response.
func TestMinersJSONHandler_UncappedBeyondBothStatsPageAndAddressCaps(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	// Tiny on purpose -- see doc comment above. EnableMetrics is also
	// how maxAddressLabels is actually wired into Stats()'s
	// MinersByAddress cap (server.go), so this is the real
	// production code path, not a test-only backdoor.
	const tinyMaxAddressLabels = 3
	h.server.EnableMetrics("test", tinyMaxAddressLabels)

	addresses := []string{
		"uncapped-addr-1",
		"uncapped-addr-2",
		"uncapped-addr-3",
		"uncapped-addr-4",
		"uncapped-addr-5",
	}
	const sessionsPerAddress = 32
	totalSessions := len(addresses) * sessionsPerAddress // 160 > DefaultStatsPageMaxSessions (150)

	for i := 0; i < totalSessions; i++ {
		addr := addresses[i%len(addresses)]
		c, _ := h.connect()
		loginResp := c.login(t, addr)
		if loginResp.Result.Status != "OK" {
			t.Fatalf("session %d (address %q): login failed: %+v", i, addr, loginResp)
		}
	}

	if got := h.server.SessionCount(); got != totalSessions {
		t.Fatalf("harness setup sanity check: SessionCount() = %d, want %d connected sessions before even hitting the handler", got, totalSessions)
	}

	srv := httptest.NewServer(h.server.MinersJSONHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /api/miners: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body MinersAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Overview.ActiveSessions != totalSessions {
		t.Fatalf("overview.active_sessions = %d, want %d", body.Overview.ActiveSessions, totalSessions)
	}
	if len(body.Miners) != body.Overview.ActiveSessions {
		t.Fatalf("len(miners) = %d, want it to EXACTLY equal overview.active_sessions (%d) -- every connected session must show up, with no silent truncation", len(body.Miners), body.Overview.ActiveSessions)
	}
	if len(body.Miners) <= DefaultStatsPageMaxSessions {
		t.Fatalf("test setup bug: len(miners) = %d must be > DefaultStatsPageMaxSessions (%d) for this test to actually exercise the uncapped guarantee", len(body.Miners), DefaultStatsPageMaxSessions)
	}

	seenAddresses := make(map[string]int, len(addresses))
	for _, m := range body.Miners {
		if m.Address == "other" {
			t.Errorf("found a miners[] entry with address %q -- /api/miners must never aggregate addresses into an \"other\" bucket (that is MinersByAddress's/CapAddressCounts' behavior, which this endpoint must never apply)", m.Address)
		}
		seenAddresses[m.Address]++
	}
	if len(seenAddresses) != len(addresses) {
		t.Fatalf("saw %d distinct addresses in miners[] (%v), want all %d of %v individually represented -- there must be no address-cardinality concept in this response at all", len(seenAddresses), seenAddresses, len(addresses), addresses)
	}
	for _, addr := range addresses {
		if seenAddresses[addr] != sessionsPerAddress {
			t.Errorf("address %q appears in %d miners[] entries, want exactly %d (one per connected session for that address)", addr, seenAddresses[addr], sessionsPerAddress)
		}
	}
}

// TestMinersJSONHandler_EmptyWhenNoSessions confirms an empty
// miners array (not null, and no error) when nothing is connected.
func TestMinersJSONHandler_EmptyWhenNoSessions(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	srv := httptest.NewServer(h.server.MinersJSONHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /api/miners: %v", err)
	}
	defer resp.Body.Close()

	var body MinersAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Overview.ActiveSessions != 0 {
		t.Errorf("overview.active_sessions = %d, want 0", body.Overview.ActiveSessions)
	}
	if len(body.Miners) != 0 {
		t.Errorf("len(miners) = %d, want 0", len(body.Miners))
	}
}
