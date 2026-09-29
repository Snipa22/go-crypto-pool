// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// TestStatsHTMLHandler_RendersRealConnectedSessionData is the required
// "renders without erroring and contains expected real data points"
// test: a real logged-in session's address must appear in the
// rendered HTML output, alongside real active-connection/share
// counts — mirrors internal/leaflib/solo/statsui_test.go's own test
// of the same name.
func TestStatsHTMLHandler_RendersRealConnectedSessionData(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1<<62)
	_, xn := directLogin(t, h, realTariTestAddress("stats-ui-test-address"))

	jobID := directCurrentJobIDForSession(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 12345),
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
	if !strings.Contains(body, "Backend transport") {
		t.Errorf("expected the backend-transport-health card label in the rendered page, got:\n%s", body)
	}
	if !strings.Contains(body, "UP") {
		t.Errorf("expected the backend transport to render as UP after a real successful forward, got:\n%s", body)
	}
}

// TestStatsHTMLHandler_HidesRemoteAddressWhenConfigured mirrors
// internal/leaflib/solo/statsui_test.go's own test of the same
// name: SetHideRemoteAddress(true) removes the "Remote address"
// column entirely; unset (default) still shows it.
func TestStatsHTMLHandler_HidesRemoteAddressWhenConfigured(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1<<62)
	_, xn := directLogin(t, h, realTariTestAddress("hide-remote-addr-test"))
	jobID := directCurrentJobIDForSession(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 12345),
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

	body := fetch()
	if !strings.Contains(body, "Remote address") {
		t.Errorf("expected 'Remote address' column by default, got:\n%s", body)
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

// TestStatsHTMLHandler_EmptyServerRendersWithoutError confirms the page
// renders cleanly (no panic, no 500) with zero connected sessions —
// the "no data yet" case a freshly-started leaf-direct would show.
func TestStatsHTMLHandler_EmptyServerRendersWithoutError(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)

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

// TestServerStats_ReportsPerSessionAndAddressBreakdown exercises
// Server.Stats()'s extended shape directly: real per-session data
// (address, current difficulty) and the per-address breakdown for
// multiple simultaneously-connected sessions.
func TestServerStats_ReportsPerSessionAndAddressBreakdown(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)

	ctx := context.Background()
	spawn := func(address string) {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		directLogin(t, hN, address)
	}
	spawn(realTariTestAddress("addr-one"))
	spawn(realTariTestAddress("addr-two"))

	st := h.server.Stats()
	if st.ActiveSessions < 2 {
		t.Errorf("ActiveSessions = %d, want >= 2", st.ActiveSessions)
	}
	directLogin(t, h, realTariTestAddress("addr-one")) // h itself becomes a 3rd connected session

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
// leaf_direct_miners_by_address (directmetrics.CapAddressCounts), via
// the server's EnableMetrics-configured maxAddressLabels.
func TestServerStats_MinersByAddressRespectsCap(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)
	h.server.EnableMetrics("test", 2) // cap=2: 1 real address kept + "other"

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		directLogin(t, hN, sprintfAddr(i))
	}

	st := h.server.Stats()
	if len(st.MinersByAddress) > 2 {
		t.Fatalf("got %d MinersByAddress entries, want <= 2 (cap)", len(st.MinersByAddress))
	}
}

// TestServerStats_ReflectsRealBackendTransportHealth is the
// backend-transport-health-specific test the other two leaves have no
// analogue for: a real successful share forward must report
// BackendHealthy=true, and a subsequent real transport failure must
// flip it to false while incrementing BackendErrorsTotal and
// recording the failing kind — exercised directly via
// recordTransportSuccess/recordTransportError (the exact real
// bookkeeping hooks session.go's forwardShare/forwardBlock call),
// not by faking a transport error injection path that doesn't exist
// on fakeShareTransport.
func TestServerStats_ReflectsRealBackendTransportHealth(t *testing.T) {
	h := newDirectTestHarness(t, 1, 1<<62)

	st := h.server.Stats()
	if !st.BackendHealthy {
		t.Fatalf("expected a freshly-started server (no backend calls yet) to report BackendHealthy=true, got false")
	}
	if st.BackendErrorsTotal != 0 {
		t.Errorf("expected BackendErrorsTotal=0 before any transport activity, got %d", st.BackendErrorsTotal)
	}

	// A real successful forward (via the actual session.go code path)
	// must keep/confirm the healthy state.
	_, xn := directLogin(t, h, realTariTestAddress("backend-health-test-address"))
	jobID := directCurrentJobIDForSession(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 555),
	})})
	resp := h.recvLegacyShareResponse()
	if !resp.Result {
		t.Fatalf("expected the setup submit to be accepted, got %#v", resp)
	}
	waitForShareCount(t, h.transport, 1)

	// forwardShare's recordTransportSuccess call (the actual bookkeeping
	// hook Stats().BackendHealthy/BackendLastErrorKind reflect) runs a
	// moment AFTER the mock transport's own SubmitShare append that
	// waitForShareCount just confirmed -- both on the same forwardPool
	// worker goroutine, but with no further synchronization the test
	// goroutine can observe directly, so poll briefly here too rather
	// than assuming it has already happened.
	deadline := time.Now().Add(2 * time.Second)
	for {
		st = h.server.Stats()
		if st.BackendLastErrorKind == "share" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("BackendLastErrorKind never became %q within the test deadline, got %q", "share", st.BackendLastErrorKind)
		}
		time.Sleep(time.Millisecond)
	}
	if !st.BackendHealthy {
		t.Errorf("expected BackendHealthy=true after a real successful forward, got false")
	}
	if st.BackendLastCheckedAt.IsZero() {
		t.Errorf("expected a non-zero BackendLastCheckedAt after a real forward")
	}

	// Now record a real transport failure using the exact same
	// bookkeeping hook a genuine backend outage would hit
	// (recordTransportError — see server.go/session.go's
	// forwardShare/forwardBlock).
	h.server.recordTransportError("block")

	st = h.server.Stats()
	if st.BackendHealthy {
		t.Errorf("expected BackendHealthy=false after a real recorded transport error, got true")
	}
	if st.BackendErrorsTotal != 1 {
		t.Errorf("BackendErrorsTotal = %d, want 1", st.BackendErrorsTotal)
	}
	if st.BackendLastErrorKind != "block" {
		t.Errorf("BackendLastErrorKind = %q, want %q", st.BackendLastErrorKind, "block")
	}
}

func sprintfAddr(i int) string {
	const letters = "0123456789"
	if i < len(letters) {
		return realTariTestAddress("flood-addr-" + string(letters[i]))
	}
	return realTariTestAddress("flood-addr-x")
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
			out[i] = SessionStat{SessionID: sprintfAddr(i), ConnectedAt: base.Add(time.Duration(i) * time.Second)}
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
// itself (see capSessionsForDisplay's own doc comment for the full
// rationale: Stats() is also used by tests and other internal
// callers that legitimately want the full list).
func TestServerStats_UnaffectedByStatsPageMaxSessions(t *testing.T) {
	h := newDirectTestHarness(t, 1000, 1<<62)
	h.server.SetStatsPageMaxSessions(1) // deliberately tiny

	ctx := context.Background()
	const totalSessions = 5
	for i := 0; i < totalSessions-1; i++ { // -1: h itself logs in as the last one below
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		directLogin(t, hN, sprintfAddr(i))
	}
	directLogin(t, h, sprintfAddr(totalSessions-1))

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
	h := newDirectTestHarness(t, 1000, 1<<62)
	h.server.SetStatsPageMaxSessions(2)

	ctx := context.Background()
	const totalSessions = 5
	for i := 0; i < totalSessions-1; i++ {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		go h.server.handleConn(ctx, serverConn, 1000)
		hN := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
		directLogin(t, hN, sprintfAddr(i))
	}
	directLogin(t, h, sprintfAddr(totalSessions-1))

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
	for _, sess := range wantShown {
		if !strings.Contains(sessionsSection, sess.Address) {
			t.Errorf("expected shown session address %s in the rendered sessions section, got:\n%s", sess.Address, sessionsSection)
		}
	}
	shownAddrs := map[string]bool{}
	for _, sess := range wantShown {
		shownAddrs[sess.Address] = true
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
	h := newDirectTestHarness(t, 1000, 1<<62)
	h.server.SetStatsPageMaxSessions(10)
	_, _ = directLogin(t, h, realTariTestAddress("under-cap-test"))

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
	for _, cap := range []int{0, -1} {
		t.Run(fmt.Sprintf("cap=%d", cap), func(t *testing.T) {
			h := newDirectTestHarness(t, 1000, 1<<62)
			h.server.SetStatsPageMaxSessions(cap)

			ctx := context.Background()
			const totalSessions = 5
			for i := 0; i < totalSessions-1; i++ {
				serverConn, clientConn := net.Pipe()
				t.Cleanup(func() { _ = clientConn.Close() })
				go h.server.handleConn(ctx, serverConn, 1000)
				hN := &directTestHarness{t: t, server: h.server, jm: h.jm, node: h.node, transport: h.transport, submit: h.submit, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
				directLogin(t, hN, sprintfAddr(i))
			}
			directLogin(t, h, sprintfAddr(totalSessions-1))

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

			for i := 0; i < totalSessions; i++ {
				if !strings.Contains(body, sprintfAddr(i)) {
					t.Errorf("expected session %d's address (%s) to be rendered (no cap), got:\n%s", i, sprintfAddr(i), body)
				}
			}
			if strings.Contains(body, "capped to") {
				t.Errorf("expected no truncation indicator with cap=%d, got:\n%s", cap, body)
			}
		})
	}
}
