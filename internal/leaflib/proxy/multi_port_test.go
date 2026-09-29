// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// sessionByAddress finds the currently-connected session logged in
// under addr, or nil if none is found -- used by
// TestMultiPortTiers_DifferentStartingDifficulties below, which (
// unlike h.onlySession(), used by every other test in this package)
// has more than one concurrently-connected session and needs to
// disambiguate between them by their real, distinct login addresses.
func (h *harness) sessionByAddress(addr string) *Session {
	h.server.mu.RLock()
	defer h.server.mu.RUnlock()
	for _, s := range h.server.sessions {
		if got := s.Identity().Address; got == addr {
			return s
		}
	}
	return nil
}

// TestMultiPortTiers_DifferentStartingDifficulties is the brief's
// required end-to-end proof that multiple port tiers with DIFFERENT
// starting difficulties produce sessions with different
// currentDifficulty, going through real net.Listener + Server.Serve
// plumbing (not just handleConn directly, unlike every other test in
// this package) -- mirroring cmd/leaf-direct's identical multi-port
// mechanism (see solo.PortConfig) now that
// internal/leaflib/proxy.Server.Serve also takes a solo.PortConfig
// instead of a bare uint64.
func TestMultiPortTiers_DifferentStartingDifficulties(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	tierDifficulties := []uint64{500, 20000, 75000}
	listeners := make([]net.Listener, 0, len(tierDifficulties))
	for i, diff := range tierDifficulties {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen for tier %d: %v", i, err)
		}
		listeners = append(listeners, ln)
		t.Cleanup(func() { _ = ln.Close() })
		go func(ln net.Listener, diff uint64) {
			_ = h.server.Serve(ctx, ln, solo.PortConfig{Difficulty: diff})
		}(ln, diff)
	}

	for i, diff := range tierDifficulties {
		addr := fmt.Sprintf("tier-address-%d", i)

		conn, err := net.Dial("tcp", listeners[i].Addr().String())
		if err != nil {
			t.Fatalf("dial tier %d (%s): %v", i, listeners[i].Addr(), err)
		}
		t.Cleanup(func() { _ = conn.Close() })

		c := &testClient{t: t, client: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn)}
		loginResp := c.login(t, addr)
		if loginResp.Result.Status != "OK" {
			t.Fatalf("tier %d login failed: %+v", i, loginResp)
		}

		sess := h.sessionByAddress(addr)
		if sess == nil {
			t.Fatalf("tier %d: no session found for login address %q", i, addr)
		}
		if got := sess.currentDifficulty.Load(); got != diff {
			t.Errorf("tier %d (listener %s): currentDifficulty = %d, want %d (this tier's configured starting difficulty)", i, listeners[i].Addr(), got, diff)
		}
	}
}
