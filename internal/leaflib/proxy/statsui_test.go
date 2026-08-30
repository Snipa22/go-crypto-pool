// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
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
