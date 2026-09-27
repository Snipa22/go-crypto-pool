// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/goleak"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
)

// newNoShareTimeoutTestServer builds a minimal, real Server (no
// JobManager/Node wiring needed -- sweepNoShareSessions only ever
// touches s.mu/s.sessions/s.logger/s.metrics/s.noShareTimeout) plus a
// real *leaflib.ConnectionManager backing genuine ManagedConnections
// (via net.Pipe), mirroring direct package's own identical test
// helper.
func newNoShareTimeoutTestServer(t *testing.T, noShareTimeout time.Duration) (*Server, *leaflib.ConnectionManager, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 10 * time.Minute})
	s := &Server{
		logger:         log.New(io.Discard, "", 0),
		sessions:       make(map[uint64]*Session),
		noShareTimeout: noShareTimeout,
	}
	return s, cm, ctx
}

// newNoShareTimeoutTestSession registers one synthetic session,
// backed by a real ManagedConnection, directly into server.sessions
// with connectedAt backdated by connectedAgo and shareCount preset --
// this is the fake-clock-free way this feature's own tests avoid
// sleep-based-testing a real multi-minute window (mirrors
// hashrate_test.go's/vardiff_test.go's own existing "backdate
// connectedAt directly" convention for exactly this reason).
func newNoShareTimeoutTestSession(t *testing.T, cm *leaflib.ConnectionManager, ctx context.Context, server *Server, connectedAgo time.Duration, shareCount uint64) *Session {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	mc, err := cm.Accept(ctx, serverConn)
	if err != nil {
		t.Fatalf("cm.Accept: %v", err)
	}
	sess := newSession(mc, server, 1000)
	sess.connectedAt = time.Now().Add(-connectedAgo)
	sess.shareCount.Store(shareCount)

	server.mu.Lock()
	server.sessions[mc.ID()] = sess
	server.mu.Unlock()

	return sess
}

// TestSweepNoShareSessions_DisconnectsOnlyPastTimeoutWithZeroShares is
// this feature's core unit test (feature brief's "Tests" section,
// item 1): a mix of qualifying and non-qualifying sessions in ONE
// sweep pass -- past noShareTimeout with shareCount==0 gets
// disconnected; past noShareTimeout with shareCount>0 (even just 1)
// is NOT disconnected; still within the timeout window is NOT
// disconnected regardless of share count. Also covers item 2 (the
// sweep iterates ALL live sessions, not just the first/last one
// found).
func TestSweepNoShareSessions_DisconnectsOnlyPastTimeoutWithZeroShares(t *testing.T) {
	const noShareTimeout = 2 * time.Minute

	server, cm, ctx := newNoShareTimeoutTestServer(t, noShareTimeout)
	server.EnableMetrics("no-share-timeout-test", 0)

	stale := newNoShareTimeoutTestSession(t, cm, ctx, server, 3*time.Minute, 0)
	staleButShared := newNoShareTimeoutTestSession(t, cm, ctx, server, 3*time.Minute, 1)
	freshNoShare := newNoShareTimeoutTestSession(t, cm, ctx, server, 1*time.Minute, 0)
	freshShared := newNoShareTimeoutTestSession(t, cm, ctx, server, 1*time.Minute, 5)

	server.sweepNoShareSessions()

	if !stale.mc.IsClosed() {
		t.Fatal("stale session (past timeout, shareCount==0) should have been disconnected, but was not")
	}
	// NOTE: not asserting on mc.CloseReason() here -- ManagedConnection.Close
	// has a real, pre-existing (unrelated to this feature) race between its
	// own doClose(reason) call and the ctx-cancellation watcher goroutine's
	// doClose("context cancelled") (connection.go's newManagedConnection),
	// so which of the two reason strings wins closeOnce is not
	// deterministic. IsClosed() is the reliable, race-free signal that the
	// sweep genuinely disconnected this session via the real mc.Close(...)
	// mechanism.
	if staleButShared.mc.IsClosed() {
		t.Fatal("staleButShared session (past timeout, but shareCount==1) should NOT have been disconnected")
	}
	if freshNoShare.mc.IsClosed() {
		t.Fatal("freshNoShare session (still within timeout window, shareCount==0) should NOT have been disconnected")
	}
	if freshShared.mc.IsClosed() {
		t.Fatal("freshShared session (still within timeout window, shareCount>0) should NOT have been disconnected")
	}

	got := testutil.ToFloat64(server.metrics.ConnectionErrorsTotal.WithLabelValues(metrics.ConnErrorNoShareTimeout))
	if got != 1 {
		t.Fatalf("leaf_solo_connection_errors_total{category=%q} = %v, want 1 (exactly one qualifying session in this sweep pass)", metrics.ConnErrorNoShareTimeout, got)
	}
}

// TestSweepNoShareSessions_FirstShareIsPermanentExemption is the
// feature brief's explicit confirmation (item 5): a session that
// submits its first valid share is PERMANENTLY exempt from this
// specific disconnect for the rest of its life, even long after that
// first share, even though it is now well past noShareTimeout and has
// gone completely quiet since.
func TestSweepNoShareSessions_FirstShareIsPermanentExemption(t *testing.T) {
	const noShareTimeout = 2 * time.Minute

	server, cm, ctx := newNoShareTimeoutTestServer(t, noShareTimeout)

	// Connected long, long ago (well past noShareTimeout), submitted
	// exactly one share near the very start, then went completely
	// silent -- this must NEVER be disconnected by this sweep,
	// regardless of how long ago that one share was.
	sess := newNoShareTimeoutTestSession(t, cm, ctx, server, 10*time.Minute, 1)

	server.sweepNoShareSessions()

	if sess.mc.IsClosed() {
		t.Fatal("a session that has ever produced one accepted share must be permanently exempt from the no-share-timeout disconnect, but was disconnected")
	}
}

// TestSweepNoShareSessions_ZeroTimeoutIsFullNoOp is the feature
// brief's required test for item 3: -no-share-timeout=0 (mirrored
// here as noShareTimeout: 0) is a full, documented no-op. This
// codebase's zero-disables convention (ManagedConnection.
// armReadDeadline's own <=0 check) is mirrored here as "the sweep
// goroutine is never even started" (startNoShareSweep) -- confirmed
// below -- AND, defensively, sweepNoShareSessions itself never
// disconnects anyone even if called directly.
func TestSweepNoShareSessions_ZeroTimeoutIsFullNoOp(t *testing.T) {
	server, cm, ctx := newNoShareTimeoutTestServer(t, 0)

	sess := newNoShareTimeoutTestSession(t, cm, ctx, server, 10*time.Minute, 0)

	server.startNoShareSweep()
	if server.noShareSweepStop != nil {
		t.Fatal("startNoShareSweep should not have started a sweep goroutine at all for noShareTimeout<=0")
	}

	server.sweepNoShareSessions()
	if sess.mc.IsClosed() {
		t.Fatal("noShareTimeout<=0 must be a full no-op, but sweepNoShareSessions still disconnected a qualifying session")
	}
}

// TestSweepNoShareSessions_NegativeTimeoutIsFullNoOp mirrors the
// zero-timeout test above for a negative value -- the feature
// brief's own "0/negative disables" wording explicitly.
func TestSweepNoShareSessions_NegativeTimeoutIsFullNoOp(t *testing.T) {
	server, cm, ctx := newNoShareTimeoutTestServer(t, -1*time.Minute)

	sess := newNoShareTimeoutTestSession(t, cm, ctx, server, 10*time.Minute, 0)

	server.startNoShareSweep()
	if server.noShareSweepStop != nil {
		t.Fatal("startNoShareSweep should not have started a sweep goroutine at all for a negative noShareTimeout")
	}

	server.sweepNoShareSessions()
	if sess.mc.IsClosed() {
		t.Fatal("a negative noShareTimeout must be a full no-op, but sweepNoShareSessions still disconnected a qualifying session")
	}
}

// TestServerShutdown_StopsNoShareSweepGoroutine is the feature
// brief's required test for item 4: Server.Shutdown() actually stops
// this new sweep's goroutine. Uses this codebase's own established
// goleak convention (internal/leaflib/leak_test.go,
// internal/leaflib/metrics/ratetracker_test.go) rather than any
// weaker proxy signal.
func TestServerShutdown_StopsNoShareSweepGoroutine(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	s := &Server{
		logger:         log.New(io.Discard, "", 0),
		sessions:       make(map[uint64]*Session),
		noShareTimeout: time.Minute,
	}
	s.startNoShareSweep()
	if s.noShareSweepStop == nil {
		t.Fatal("expected startNoShareSweep to have started the sweep goroutine for a positive noShareTimeout")
	}

	s.Shutdown()
	// goleak.VerifyNone (deferred above) does the real assertion: if
	// runNoShareSweep were still running, its goroutine would show up
	// there.
}

// TestSetNoShareTimeout_StartsSweep confirms Server.SetNoShareTimeout
// (leaf-solo's own opt-in wiring point, unlike leaf-direct's
// ServerConfig.NoShareTimeout struct field) both stores the timeout
// and actually starts the sweep goroutine for a positive value.
func TestSetNoShareTimeout_StartsSweep(t *testing.T) {
	s := &Server{
		logger:   log.New(io.Discard, "", 0),
		sessions: make(map[uint64]*Session),
	}
	s.SetNoShareTimeout(90 * time.Second)
	t.Cleanup(s.Shutdown)

	if s.noShareTimeout != 90*time.Second {
		t.Fatalf("s.noShareTimeout = %v, want 90s", s.noShareTimeout)
	}
	if s.noShareSweepStop == nil {
		t.Fatal("SetNoShareTimeout(90s) should have started the sweep goroutine")
	}
}
