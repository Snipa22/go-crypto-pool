// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	_, xn := directLogin(t, h, "stats-ui-test-address")

	jobID := directCurrentJobIDForXN(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 12345),
	})})
	resp := h.recvShareResponse()
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

	if !strings.Contains(body, "stats-ui-test-address") {
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
	spawn("addr-one")
	spawn("addr-two")

	st := h.server.Stats()
	if st.ActiveSessions < 2 {
		t.Errorf("ActiveSessions = %d, want >= 2", st.ActiveSessions)
	}
	directLogin(t, h, "addr-one") // h itself becomes a 3rd connected session

	st = h.server.Stats()
	foundOne, foundTwo := false, false
	for _, ac := range st.MinersByAddress {
		if ac.Address == "addr-one" {
			foundOne = true
			if ac.Count < 1 {
				t.Errorf("addr-one count = %d, want >= 1", ac.Count)
			}
		}
		if ac.Address == "addr-two" {
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
	_, xn := directLogin(t, h, "backend-health-test-address")
	jobID := directCurrentJobIDForXN(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		JobID: jobID,
		Nonce: directXNPrefixedNonceHex(xn, 555),
	})})
	resp := h.recvShareResponse()
	if !resp.Result {
		t.Fatalf("expected the setup submit to be accepted, got %#v", resp)
	}
	if h.transport.shareCount() != 1 {
		t.Fatalf("expected exactly 1 share forwarded, got %d", h.transport.shareCount())
	}

	st = h.server.Stats()
	if !st.BackendHealthy {
		t.Errorf("expected BackendHealthy=true after a real successful forward, got false")
	}
	if st.BackendLastErrorKind != "share" {
		t.Errorf("BackendLastErrorKind (last-activity kind) = %q, want %q", st.BackendLastErrorKind, "share")
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
		return "flood-addr-" + string(letters[i])
	}
	return "flood-addr-x"
}
