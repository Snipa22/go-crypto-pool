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
