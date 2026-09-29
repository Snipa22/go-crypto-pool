// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStatsHTMLHandler_RendersRealConnectedSessionData is the required
// "renders without erroring and contains expected real data points"
// test: a real logged-in session's address must appear in the
// rendered HTML output, alongside real active-connection/share
// counts.
func TestStatsHTMLHandler_RendersRealConnectedSessionData(t *testing.T) {
	h := newTestHarness(t, 1, math.MaxUint64)
	_, xn := login(t, h, "stats-ui-test-address")

	jobID := currentJobIDForSession(t, h, xn)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 12345),
	})})
	resp := h.recvLegacyShareResponse()
	if !resp.Result {
		t.Fatalf("expected the setup submit to be accepted, got %#v", resp)
	}

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
	if ct := httpResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}

	buf := make([]byte, 65536)
	n, _ := httpResp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, realTariTestAddress("stats-ui-test-address")) {
		t.Errorf("expected the connected session's address in the rendered page, got:\n%s", body)
	}
	if !strings.Contains(body, "<html") {
		t.Errorf("expected a real HTML document, got:\n%s", body)
	}
	if !strings.Contains(body, "Active connections") {
		t.Errorf("expected the active-connections card label in the rendered page, got:\n%s", body)
	}
}

// TestStatsHTMLHandler_EmptyServerRendersWithoutError confirms the page
// renders cleanly (no panic, no 500) with zero connected sessions —
// the "no data yet" case a freshly-started leaf-solo would show.
func TestStatsHTMLHandler_EmptyServerRendersWithoutError(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	srv := httptest.NewServer(h.server.StatsHTMLHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET stats page: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestStatsHTMLHandler_HidesRemoteAddressWhenConfigured confirms
// SetHideRemoteAddress(true) removes both the "Remote address"
// column header and its per-session value from the rendered page —
// and that the default (unset) behavior still shows it.
func TestStatsHTMLHandler_HidesRemoteAddressWhenConfigured(t *testing.T) {
	h := newTestHarness(t, 1, math.MaxUint64)
	_, xn := login(t, h, "hide-remote-addr-test")
	jobID := currentJobIDForSession(t, h, xn)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 12345),
	})})
	if resp := h.recvLegacyShareResponse(); !resp.Result {
		t.Fatalf("expected the setup submit to be accepted, got %#v", resp)
	}

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

	// Default: shown.
	body := fetch()
	if !strings.Contains(body, "Remote address") {
		t.Errorf("expected 'Remote address' column by default, got:\n%s", body)
	}

	// Opted in: hidden.
	h.server.SetHideRemoteAddress(true)
	body = fetch()
	if strings.Contains(body, "Remote address") {
		t.Errorf("expected 'Remote address' column to be absent when hidden, got:\n%s", body)
	}
	if !strings.Contains(body, "<html") || !strings.Contains(body, "Active connections") {
		t.Errorf("expected the rest of the page to still render normally, got:\n%s", body)
	}
}

// TestServerStats_ReportsPerSessionAndAddressBreakdown exercises
// Server.Stats()'s extended shape directly: real per-session data
// (address, current difficulty) and the per-address breakdown for
// multiple simultaneously-connected sessions.
func TestServerStats_ReportsPerSessionAndAddressBreakdown(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)

	ctx := context.Background()
	spawn := func(address string) {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		login(t, hN, address)
	}
	spawn("addr-one")
	spawn("addr-two")

	st := h.server.Stats()
	if st.ActiveSessions < 3 { // h's own login below + the two spawned
		t.Errorf("ActiveSessions = %d, want >= 3", st.ActiveSessions)
	}
	login(t, h, "addr-one") // h itself becomes a 3rd connected session

	st = h.server.Stats()
	foundOne, foundTwo := false, false
	for _, ac := range st.MinersByAddress {
		if ac.Address == realTariTestAddress("addr-one") {
			foundOne = true
			if ac.Count < 1 {
				t.Errorf("addr-one count = %d, want >= 1", ac.Count)
			}
		}
		if ac.Address == realTariTestAddress("addr-two") {
			foundTwo = true
		}
	}
	if !foundOne || !foundTwo {
		t.Errorf("expected both addr-one and addr-two in MinersByAddress, got %#v", st.MinersByAddress)
	}
	if len(st.Sessions) < 3 {
		t.Errorf("Sessions snapshot length = %d, want >= 3", len(st.Sessions))
	}
}

// TestServerStats_MinersByAddressRespectsCap confirms Stats()'s
// MinersByAddress uses the same cardinality cap as
// leaf_miners_by_address (metrics.CapAddressCounts), via the server's
// EnableMetrics-configured maxAddressLabels.
func TestServerStats_MinersByAddressRespectsCap(t *testing.T) {
	h := newTestHarness(t, 1000, 1<<62)
	h.server.EnableMetrics("test", 2) // cap=2: 1 real address kept + "other"

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		login(t, hN, fmt.Sprintf("flood-addr-%d", i))
	}

	st := h.server.Stats()
	if len(st.MinersByAddress) > 2 {
		t.Fatalf("got %d MinersByAddress entries, want <= 2 (cap)", len(st.MinersByAddress))
	}
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
	h := newTestHarness(t, 1000, 1<<62)
	h.server.SetStatsPageMaxSessions(1) // deliberately tiny

	ctx := context.Background()
	const totalSessions = 5
	for i := 0; i < totalSessions-1; i++ {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		login(t, hN, fmt.Sprintf("stats-page-cap-flood-%d", i))
	}
	login(t, h, fmt.Sprintf("stats-page-cap-flood-%d", totalSessions-1))

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
	h := newTestHarness(t, 1000, 1<<62)
	h.server.SetStatsPageMaxSessions(2)

	ctx := context.Background()
	const totalSessions = 5
	for i := 0; i < totalSessions-1; i++ {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		login(t, hN, fmt.Sprintf("stats-page-cap-flood-%d", i))
	}
	login(t, h, fmt.Sprintf("stats-page-cap-flood-%d", totalSessions-1))

	// Compute the real, actual-sort-order-derived expectation
	// directly from Stats() (the same ascending-by-ConnectedAt order
	// documented on Stats.Sessions) rather than assuming the spawn
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
	h := newTestHarness(t, 1000, 1<<62)
	h.server.SetStatsPageMaxSessions(10)
	login(t, h, "under-cap-test")

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
	if !strings.Contains(body, realTariTestAddress("under-cap-test")) {
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
			h := newTestHarness(t, 1000, 1<<62)
			h.server.SetStatsPageMaxSessions(capVal)

			ctx := context.Background()
			const totalSessions = 5
			addrs := make([]string, totalSessions)
			for i := 0; i < totalSessions-1; i++ {
				serverConn, clientConn := net.Pipe()
				t.Cleanup(func() { _ = clientConn.Close() })
				go h.server.handleConn(ctx, serverConn, 1000)
				hN := &testHarness{t: t, server: h.server, jm: h.jm, node: h.node, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
				addrs[i] = fmt.Sprintf("stats-page-nocap-flood-%d", i)
				login(t, hN, addrs[i])
			}
			addrs[totalSessions-1] = fmt.Sprintf("stats-page-nocap-flood-%d", totalSessions-1)
			login(t, h, addrs[totalSessions-1])

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
				if !strings.Contains(body, realTariTestAddress(addr)) {
					t.Errorf("expected address %s to be rendered (no cap), got:\n%s", realTariTestAddress(addr), body)
				}
			}
			if strings.Contains(body, "capped to") {
				t.Errorf("expected no truncation indicator with cap=%d, got:\n%s", capVal, body)
			}
		})
	}
}
