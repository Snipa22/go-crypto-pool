// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestStatsHTMLHandler_HidesRemoteAddressWhenConfigured mirrors
// internal/leaflib/solo/statsui_test.go's own test of the same name:
// SetHideRemoteAddress(true) removes the "Remote address" column
// (both header and per-session value) from the rendered stats page
// entirely; the default (unset) still shows it.
func TestStatsHTMLHandler_HidesRemoteAddressWhenConfigured(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{}, 6*time.Minute)
	c, _ := h.connect()
	c.login(t, "hide-remote-addr-test")

	fetch := func() string {
		srv := httptest.NewServer(h.server.StatsHTMLHandler())
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("GET stats page: %v", err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 65536)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}

	body := fetch()
	if !strings.Contains(body, "Remote address") {
		t.Errorf("expected 'Remote address' column by default, got:\n%s", body)
	}
	if !strings.Contains(body, "<html") {
		t.Errorf("expected a real HTML document, got:\n%s", body)
	}

	h.server.SetHideRemoteAddress(true)
	body = fetch()
	if strings.Contains(body, "Remote address") {
		t.Errorf("expected 'Remote address' column to be absent when hidden, got:\n%s", body)
	}
	if !strings.Contains(body, "<html") {
		t.Errorf("expected the rest of the page to still render normally, got:\n%s", body)
	}
}

// TestStatsHTMLHandler_DarkModeAndRefreshControls is the required
// (per DISPATCH_BRIEF_ADDENDUM_DARKMODE.md's "Testing" section) Go
// test asserting the rendered HTML still contains the expected
// structural pieces for the dark-mode toggle + adjustable
// auto-refresh feature: the old hardcoded <meta http-equiv="refresh">
// tag is gone, the new <select> refresh control and theme-toggle
// button are present, and the page still renders without error for
// both an empty and a populated Stats(). The interactive JS behavior
// itself (localStorage persistence, setTimeout scheduling) is not
// unit-testable from Go and was instead verified by manual/visual
// reading of the rendered template output per the addendum's
// "Required verification" section.
func TestStatsHTMLHandler_DarkModeAndRefreshControls(t *testing.T) {
	fetch := func(h *harness) string {
		srv := httptest.NewServer(h.server.StatsHTMLHandler())
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("GET stats page: %v", err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 65536)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}

	t.Run("empty Stats()", func(t *testing.T) {
		h := newHarness(t, leaflib.VardiffConfig{}, 6*time.Minute)
		body := fetch(h)

		if strings.Contains(body, `http-equiv="refresh"`) {
			t.Errorf("expected the old hardcoded <meta http-equiv=\"refresh\"> tag to be gone, got:\n%s", body)
		}
		if !strings.Contains(body, `id="refresh-select"`) {
			t.Errorf("expected the new auto-refresh <select> control, got:\n%s", body)
		}
		if !strings.Contains(body, `id="theme-toggle"`) {
			t.Errorf("expected the new dark-mode toggle button, got:\n%s", body)
		}
		if !strings.Contains(body, "leaf-proxy-stats-theme") {
			t.Errorf("expected the theme localStorage key to be referenced, got:\n%s", body)
		}
		if !strings.Contains(body, "leaf-proxy-stats-refresh-ms") {
			t.Errorf("expected the refresh-interval localStorage key to be referenced, got:\n%s", body)
		}
		if !strings.Contains(body, "<html") {
			t.Errorf("expected a real HTML document even with no sessions, got:\n%s", body)
		}
	})

	t.Run("populated Stats()", func(t *testing.T) {
		h := newHarness(t, leaflib.VardiffConfig{}, 6*time.Minute)
		c, _ := h.connect()
		c.login(t, "darkmode-refresh-test")
		body := fetch(h)

		if strings.Contains(body, `http-equiv="refresh"`) {
			t.Errorf("expected the old hardcoded <meta http-equiv=\"refresh\"> tag to be gone, got:\n%s", body)
		}
		if !strings.Contains(body, `id="refresh-select"`) {
			t.Errorf("expected the new auto-refresh <select> control, got:\n%s", body)
		}
		if !strings.Contains(body, `id="theme-toggle"`) {
			t.Errorf("expected the new dark-mode toggle button, got:\n%s", body)
		}
		if !strings.Contains(body, "darkmode-refresh-test") {
			t.Errorf("expected the connected session's address to still render normally, got:\n%s", body)
		}
	})
}

// TestCapSessionsForDisplay is the pure, table-driven unit test for
// the small helper StatsHTMLHandler uses to truncate the "Connected
// sessions" table -- see capSessionsForDisplay's own doc comment for
// the full contract (0/negative disables, first-N-of-existing-order
// otherwise).
func TestCapSessionsForDisplay(t *testing.T) {
	mk := func(n int) []SessionStat {
		base := time.Now()
		out := make([]SessionStat, n)
		for i := range out {
			out[i] = SessionStat{SessionID: fmt.Sprintf("sess-%d", i), ConnectedAt: base.Add(time.Duration(i) * time.Second)}
		}
		return out
	}

	t.Run("under cap: unchanged, not truncated", func(t *testing.T) {
		sessions := mk(3)
		shown, truncated := capSessionsForDisplay(sessions, 10)
		if truncated {
			t.Errorf("truncated = true, want false")
		}
		if len(shown) != 3 {
			t.Errorf("len(shown) = %d, want 3", len(shown))
		}
	})

	t.Run("exactly at cap: unchanged, not truncated", func(t *testing.T) {
		sessions := mk(5)
		shown, truncated := capSessionsForDisplay(sessions, 5)
		if truncated {
			t.Errorf("truncated = true, want false")
		}
		if len(shown) != 5 {
			t.Errorf("len(shown) = %d, want 5", len(shown))
		}
	})

	t.Run("over cap: truncated to first N of existing order", func(t *testing.T) {
		sessions := mk(5)
		shown, truncated := capSessionsForDisplay(sessions, 2)
		if !truncated {
			t.Errorf("truncated = false, want true")
		}
		if len(shown) != 2 {
			t.Fatalf("len(shown) = %d, want 2", len(shown))
		}
		if shown[0].SessionID != sessions[0].SessionID || shown[1].SessionID != sessions[1].SessionID {
			t.Errorf("shown = %#v, want the first 2 entries of the existing order unchanged", shown)
		}
	})

	t.Run("zero cap: no cap, render everything", func(t *testing.T) {
		sessions := mk(5)
		shown, truncated := capSessionsForDisplay(sessions, 0)
		if truncated {
			t.Errorf("truncated = true, want false")
		}
		if len(shown) != 5 {
			t.Errorf("len(shown) = %d, want 5", len(shown))
		}
	})

	t.Run("negative cap: no cap, render everything", func(t *testing.T) {
		sessions := mk(5)
		shown, truncated := capSessionsForDisplay(sessions, -1)
		if truncated {
			t.Errorf("truncated = true, want false")
		}
		if len(shown) != 5 {
			t.Errorf("len(shown) = %d, want 5", len(shown))
		}
	})
}

// TestServerStats_UnaffectedByStatsPageMaxSessions is the REQUIRED
// test proving Stats() itself is completely unchanged by the new
// -stats-page-max-sessions cap: it must keep returning the full,
// uncapped Sessions slice regardless of the configured value -- the
// cap is applied ONLY by StatsHTMLHandler, never inside Stats()
// itself.
func TestServerStats_UnaffectedByStatsPageMaxSessions(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{}, 6*time.Minute)
	h.server.SetStatsPageMaxSessions(1) // deliberately tiny

	const totalSessions = 5
	for i := 0; i < totalSessions; i++ {
		c, _ := h.connect()
		c.login(t, fmt.Sprintf("stats-page-cap-flood-%d", i))
	}

	st := h.server.Stats()
	if st.ActiveSessions != totalSessions {
		t.Fatalf("ActiveSessions = %d, want %d", st.ActiveSessions, totalSessions)
	}
	if len(st.Sessions) != totalSessions {
		t.Fatalf("len(Stats().Sessions) = %d, want %d (the full, uncapped list) even though statsPageMaxSessions=1", len(st.Sessions), totalSessions)
	}
}

// TestStatsHTMLHandler_CapsConnectedSessionsTable is the REQUIRED
// test: with more connected sessions than the configured cap, the
// rendered page must contain at most `cap` session rows plus the
// truncation-indicator text with the correct real total count.
func TestStatsHTMLHandler_CapsConnectedSessionsTable(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{}, 6*time.Minute)
	h.server.SetStatsPageMaxSessions(2)

	const totalSessions = 5
	for i := 0; i < totalSessions; i++ {
		c, _ := h.connect()
		c.login(t, fmt.Sprintf("stats-page-cap-flood-%d", i))
	}

	// Compute the real, actual-sort-order-derived expectation
	// directly from Stats() (the same ascending-by-ConnectedAt order
	// documented on Stats.Sessions) rather than assuming the connect
	// loop's iteration order matches connection-acceptance order
	// (goroutine scheduling makes no such guarantee).
	st := h.server.Stats()
	if len(st.Sessions) != totalSessions {
		t.Fatalf("Stats().Sessions length = %d, want %d", len(st.Sessions), totalSessions)
	}
	wantShown, wantTruncated := capSessionsForDisplay(st.Sessions, 2)
	if !wantTruncated || len(wantShown) != 2 {
		t.Fatalf("capSessionsForDisplay sanity check failed: truncated=%v len(shown)=%d", wantTruncated, len(wantShown))
	}

	srv := httptest.NewServer(h.server.StatsHTMLHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET stats page: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Addresses also legitimately appear in the separate "Miners by
	// address" table above (unaffected by this cap), so scope all
	// per-session presence/absence checks to just the "Connected
	// sessions" section of the page.
	idx := strings.Index(body, "<h2>Connected sessions")
	if idx < 0 {
		t.Fatalf("expected a \"Connected sessions\" section in the rendered page, got:\n%s", body)
	}
	sessionsSection := body[idx:]

	if !strings.Contains(sessionsSection, "showing 2 of 5") {
		t.Errorf("expected the truncation indicator to report \"showing 2 of 5\", got:\n%s", sessionsSection)
	}
	shownAddrs := map[string]bool{}
	for _, sess := range wantShown {
		shownAddrs[sess.Address] = true
		if !strings.Contains(sessionsSection, sess.Address) {
			t.Errorf("expected shown session address %s in the rendered sessions section, got:\n%s", sess.Address, sessionsSection)
		}
	}
	truncatedCount := 0
	for _, sess := range st.Sessions {
		if !shownAddrs[sess.Address] {
			truncatedCount++
			if strings.Contains(sessionsSection, sess.Address) {
				t.Errorf("expected truncated-away session address %s to be absent from the rendered sessions section, got:\n%s", sess.Address, sessionsSection)
			}
		}
	}
	if truncatedCount != totalSessions-2 {
		t.Fatalf("truncatedCount = %d, want %d", truncatedCount, totalSessions-2)
	}

	// Stats() itself must still report the real, uncapped total.
	st2 := h.server.Stats()
	if st2.ActiveSessions != totalSessions {
		t.Errorf("Stats().ActiveSessions = %d, want %d (uncapped total unaffected by the display cap)", st2.ActiveSessions, totalSessions)
	}
	if len(st2.Sessions) != totalSessions {
		t.Errorf("len(Stats().Sessions) = %d, want %d (uncapped, unaffected by the display cap)", len(st2.Sessions), totalSessions)
	}
}

// TestStatsHTMLHandler_NoTruncationIndicatorWhenUnderCap mirrors the
// existing AddressCapped bool's own "false when not actually capped"
// contract: fewer sessions than the configured cap renders no
// truncation indicator at all.
func TestStatsHTMLHandler_NoTruncationIndicatorWhenUnderCap(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{}, 6*time.Minute)
	h.server.SetStatsPageMaxSessions(10)
	c, _ := h.connect()
	c.login(t, "under-cap-test")

	srv := httptest.NewServer(h.server.StatsHTMLHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET stats page: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if strings.Contains(body, "capped to") && strings.Contains(body, "Connected sessions (") {
		t.Errorf("expected no session-table truncation indicator when under the cap, got:\n%s", body)
	}
	if !strings.Contains(body, "under-cap-test") {
		t.Errorf("expected the single connected session's address in the rendered page, got:\n%s", body)
	}
}

// TestStatsHTMLHandler_ZeroOrNegativeCapDisablesTruncation confirms
// -stats-page-max-sessions=0 (and negative) renders the full session
// list with no truncation indicator -- the explicit escape hatch for
// the old, uncapped behavior.
func TestStatsHTMLHandler_ZeroOrNegativeCapDisablesTruncation(t *testing.T) {
	for _, capVal := range []int{0, -1} {
		t.Run(fmt.Sprintf("cap=%d", capVal), func(t *testing.T) {
			h := newHarness(t, leaflib.VardiffConfig{}, 6*time.Minute)
			h.server.SetStatsPageMaxSessions(capVal)

			const totalSessions = 5
			addrs := make([]string, totalSessions)
			for i := 0; i < totalSessions; i++ {
				c, _ := h.connect()
				addrs[i] = fmt.Sprintf("stats-page-nocap-flood-%d", i)
				c.login(t, addrs[i])
			}

			srv := httptest.NewServer(h.server.StatsHTMLHandler())
			defer srv.Close()
			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Fatalf("GET stats page: %v", err)
			}
			defer resp.Body.Close()
			buf := make([]byte, 65536)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			for _, addr := range addrs {
				if !strings.Contains(body, addr) {
					t.Errorf("expected address %s to be rendered (no cap), got:\n%s", addr, body)
				}
			}
			if strings.Contains(body, "capped to") {
				t.Errorf("expected no truncation indicator with cap=%d, got:\n%s", capVal, body)
			}
		})
	}
}
