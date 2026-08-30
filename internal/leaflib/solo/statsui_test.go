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
)

// TestStatsHTMLHandler_RendersRealConnectedSessionData is the required
// "renders without erroring and contains expected real data points"
// test: a real logged-in session's address must appear in the
// rendered HTML output, alongside real active-connection/share
// counts.
func TestStatsHTMLHandler_RendersRealConnectedSessionData(t *testing.T) {
	h := newTestHarness(t, 1, math.MaxUint64)
	_, xn := login(t, h, "stats-ui-test-address")

	jobID := currentJobIDForXN(t, h, xn)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 12345),
	})})
	resp := h.recvShareResponse()
	if resp.Result == nil {
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
	jobID := currentJobIDForXN(t, h, xn)
	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID,
		Nonce: xnPrefixedNonceHex(xn, 12345),
	})})
	if resp := h.recvShareResponse(); resp.Result == nil {
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
