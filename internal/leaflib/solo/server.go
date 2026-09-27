// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Server ties together internal/leaflib.ConnectionManager (miner
// connection lifecycle), a JobManager (real Tari base-node GRPC job
// pipeline), and a validator.Registry (real per-algo PoW checking —
// SHA3XValidator and, as of this pass, C29Validator) — this is the
// entire leaf-solo vertical slice. There is deliberately no backend
// connection anywhere in this type.
type Server struct {
	cm         *leaflib.ConnectionManager
	jobManager *JobManager
	node       NodeClient

	// validators is looked up by a JOB's own stamped poolpb.Algo (see
	// job.go's Job.Algo) at submit time (session.go's handleSubmit),
	// not by any single server-wide algo assumption — this is what
	// makes validator dispatch algo-aware rather than SHA3X-hardcoded.
	// Callers that only ever serve SHA3X (the default/unconfigured
	// path — see cmd/leaf-solo/main.go) construct a Registry with only
	// poolpb.Algo_ALGO_SHA3X registered, which is exactly the
	// already-deployed CT132 behavior: any job somehow stamped with a
	// different algo would fail this lookup rather than being silently
	// mis-validated.
	validators validator.Registry
	network    poolpb.Network
	logger     *log.Logger

	// vardiff configures the per-session adaptive retargeting
	// algorithm (see vardiff.go's VardiffConfig/computeRetarget) that
	// every session's own runVardiffLoop goroutine uses. Normalized
	// (zero fields replaced by sane defaults) once, in NewServer.
	vardiff VardiffConfig

	// invalidShareGuardConfig configures the shared, per-session
	// consecutive-invalid-share disconnect mechanism (see
	// leaflib.InvalidShareGuard's doc comment for the full
	// DISPATCH_BRIEF.md 2026-09-10 Fix 2b rationale). Defaults to
	// leaflib.DefaultInvalidShareGuardConfig() (enabled) in NewServer
	// — unlike EnableTrust, this is a security-hardening default
	// that protects a deployment out of the box, not an opt-in
	// throughput tradeoff — but remains fully overridable (including
	// disabling it entirely) via SetInvalidShareGuardConfig before
	// Serve begins accepting connections.
	invalidShareGuardConfig leaflib.InvalidShareGuardConfig

	// addressFlags is nil unless EnableAddressFlags has been called
	// -- the real, manual ban/forced-minimum-difficulty enforcement
	// point (see internal/leaflib/addressflags's package doc comment
	// for the full rationale on why this belongs here, at the leaf,
	// rather than at the backend). nil means every login is accepted
	// regardless of what the backend's address_flags table (or a
	// leaf-solo operator's local flags file) says -- the same "opt-in,
	// no surprise behavior change for a caller that never wires this"
	// story EnableMetrics already has. Consulted by
	// session.go's handleLogin (ban rejection + starting-difficulty
	// floor) and vardiff.go's maybeRetarget (retarget floor).
	addressFlags *addressflags.Cache

	mu       sync.RWMutex
	sessions map[uint64]*Session

	unsubscribe func()

	// metrics is nil unless EnableMetrics has been called. Every
	// recordX helper below is a nil-safe no-op when it is nil, so
	// metrics wiring is entirely opt-in for callers/tests that don't
	// need it. Set exactly once, at startup, before Serve begins
	// accepting connections (see cmd/leaf-solo/main.go) — no
	// synchronization is applied around reads of this field for that
	// reason.
	metrics *metrics.Metrics

	// maxAddressLabels bounds the leaf_miners_by_address cardinality
	// AND the stats HTML page's per-address breakdown identically
	// (see metrics.CapAddressCounts) — both surfaces share exactly
	// the same cap so the UI and the exported metric never disagree
	// about how many distinct addresses are being tracked right now.
	// Defaults to metrics.DefaultMaxAddressLabels; overridden by
	// EnableMetrics when called with a positive value.
	maxAddressLabels int

	// statsPageMaxSessions caps how many SessionStat rows
	// StatsHTMLHandler actually renders in its "Connected sessions"
	// table -- NOT the same as ActiveSessions (which stays uncapped)
	// and NOT applied inside Stats() itself (see
	// capSessionsForDisplay's own doc comment in statsui.go).
	// Defaults to DefaultStatsPageMaxSessions. 0/negative disables
	// the cap entirely (render everything). Set via
	// SetStatsPageMaxSessions.
	statsPageMaxSessions int

	// hideRemoteAddress, when true, tells StatsHTMLHandler to omit
	// the "Remote address" column (both header and value) from the
	// rendered stats page entirely -- see SetHideRemoteAddress.
	// Defaults to false (existing behavior: remote addresses shown)
	// since this is an opt-in privacy control, not a security-fix
	// default change -- unlike the metrics-listen-address bind
	// default, which changed to localhost-only (see
	// cmd/leaf-solo/main.go), this flag intentionally still defaults
	// off so operators who want the existing page unchanged get
	// exactly that.
	//
	// HARDENING FIX (FIX_BRIEF.md, finding #20): atomic.Bool, not a
	// plain bool -- every real main.go calls SetHideRemoteAddress
	// exactly once before Serve begins accepting connections, so
	// this was benign in practice, but statsui.go's StatsHTMLHandler
	// reads it from within an http.HandlerFunc closure invoked on a
	// per-request goroutine, and a plain bool read there races (under
	// `go test -race`) against any write from a DIFFERENT goroutine
	// -- e.g. a future caller that (unlike today's main.go) invokes
	// SetHideRemoteAddress after Serve has already started. Matches
	// this codebase's existing atomic-heavy concurrency style
	// elsewhere (Session.loggedIn, UpstreamClient.connected, etc.).
	hideRemoteAddress atomic.Bool

	// randomxPool is the bounded, server-wide worker pool session.go's
	// handleSubmit dispatches RandomX-family (RXT/RXM) share validation
	// onto, so that a real, per-share synchronous randomx-service HTTP
	// round-trip never blocks Session.Run's read loop -- see
	// asyncvalidation.go's package doc comment for the full production
	// incident this fixes and the concurrency-bound justification.
	// Always non-nil (constructed in NewServer); SHA3X/C29 validation is
	// entirely unaffected and never touches this pool.
	randomxPool *AsyncValidationPool

	// debugLogger is nil unless SetDebugLogger has been called (see
	// cmd/leaf-solo/main.go) -- the real, opt-in -debug/LEAF_SOLO_DEBUG
	// verbose logging sink (internal/leaflib/debuglog.go). Every
	// Session created by this Server reads it through its own
	// server back-reference (session.go's s.server.debugLogger), so
	// there is exactly one DebugLogger per Server instance, never a
	// global/package-level singleton. nil is a complete no-op:
	// *leaflib.DebugLogger's own Debugf/Enabled methods are safe to
	// call on a nil receiver.
	debugLogger *leaflib.DebugLogger

	// noShareTimeout is set by SetNoShareTimeout (see that method's
	// doc comment): a connected session that has NEVER produced a
	// genuinely accepted share (shareCount.Load() == 0) within this
	// long of connecting gets disconnected by the periodic sweep
	// below (runNoShareSweep). Zero/negative (the default -- this
	// field is never set unless SetNoShareTimeout is called)
	// disables the feature entirely, mirroring
	// ManagedConnection.armReadDeadline's own <=0-disables
	// convention -- see SetNoShareTimeout/startNoShareSweep, which
	// never even starts the sweep goroutine in that case.
	noShareTimeout time.Duration

	// noShareSweepStop/noShareSweepDone are the sweep goroutine's own
	// stop signal/completion signal (started by startNoShareSweep,
	// closed/waited-on by stopNoShareSweep from Shutdown). Both stay
	// nil for a Server that never calls SetNoShareTimeout with a
	// positive value -- see startNoShareSweep's doc comment.
	noShareSweepStop chan struct{}
	noShareSweepDone chan struct{}

	// noShareSweepNow is a test-only clock seam (mirrors
	// MoneroNodeClient's own nowFunc convention exactly): nil in
	// production, so sweepNoShareSessions always calls time.Now();
	// overridden by this package's own no-share-timeout tests so
	// they never sleep-based-test a real multi-minute window.
	noShareSweepNow func() time.Time
}

// defaultNoShareSweepInterval is how often runNoShareSweep scans the
// live session map for sessions that have exceeded noShareTimeout
// without ever producing an accepted share -- see that method's own
// doc comment. Deliberately short relative to any realistic
// noShareTimeout (Alex's stated "2-3 minutes" -- see
// cmd/leaf-solo's -no-share-timeout flag doc comment) so the
// timeout is enforced within a few seconds of actually elapsing,
// without hot-looping a full session-map scan far more often than
// that. Not operator-configurable -- only noShareTimeout itself is.
const defaultNoShareSweepInterval = 15 * time.Second

// NewServer constructs a Server. cm must already be configured with the
// desired MaxConnections/IdleTimeout (ManagerConfig) by the caller —
// solo's Server does not own ConnectionManager construction so callers
// keep full control of that already-merged, already-correct lifecycle
// policy. There is no single "starting difficulty" on Server anymore —
// a Server now serves any number of simultaneous port tiers (see
// portconfig.go's PortConfig and Serve below), each of which supplies
// its OWN starting difficulty for sessions accepted on it. vardiff
// configures each session's own independent
// per-connection adaptive retargeting from that starting point (a
// zero-value VardiffConfig is normalized to sane defaults — see
// vardiff.go's defaultVardiffConfig).
func NewServer(cm *leaflib.ConnectionManager, jobManager *JobManager, node NodeClient, validators validator.Registry, network poolpb.Network, logger *log.Logger, vardiff VardiffConfig) *Server {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		cm:                      cm,
		jobManager:              jobManager,
		node:                    node,
		validators:              validators,
		network:                 network,
		logger:                  logger,
		vardiff:                 vardiff.Normalized(),
		sessions:                make(map[uint64]*Session),
		maxAddressLabels:        metrics.DefaultMaxAddressLabels,
		statsPageMaxSessions:    DefaultStatsPageMaxSessions,
		invalidShareGuardConfig: leaflib.DefaultInvalidShareGuardConfig(),
		// workers=0/queueSize=0 lets NewAsyncValidationPool apply its
		// own defaults (DefaultAsyncValidationWorkers() ==
		// runtime.NumCPU() for workers, NOT a hardcoded literal --
		// see asyncvalidation.go's doc comment and Alex's explicit
		// direction in DISPATCH_BRIEF.md, 2026-09-10; and
		// DefaultAsyncValidationQueueSize(workers) for queueSize --
		// max(AsyncValidationQueueSize, workers*
		// DefaultAsyncValidationQueueMultiplier), scaling with the
		// real worker count instead of staying the old flat 256
		// literal regardless of host size). An operator wanting a
		// different fixed worker count and/or queue size can override
		// via SetRandomXWorkerPoolSize (see cmd/leaf-solo's
		// -randomx-workers/-randomx-queue-size flags) before Serve
		// begins.
		randomxPool: NewAsyncValidationPool(0, 0),
	}
	// leaf-solo's own invalidateAndRepushJobs has no use for the
	// source label JobManager.Subscribe's callback now carries (see
	// job.go's Subscribe/InvalidateAll doc comments) -- only
	// leaf-direct's template-distribution metrics need it. Wrapped at
	// this call site rather than changing invalidateAndRepushJobs'
	// own signature.
	s.unsubscribe = jobManager.Subscribe(func(_ string) { s.invalidateAndRepushJobs() })
	return s
}

// SetRandomXWorkerPoolSize replaces this Server's randomxPool with a
// freshly constructed one sized to workers/queueSize -- see
// NewAsyncValidationPool's own doc comment for the <=0 fallback
// behavior (workers<=0 uses DefaultAsyncValidationWorkers(), i.e.
// runtime.NumCPU(), NOT a hardcoded literal -- DISPATCH_BRIEF.md,
// 2026-09-10, Fix 2a). Must be called before Serve begins accepting
// connections (mirrors EnableAddressFlags's identical "opt-in,
// pre-Serve" convention) -- the pool NewServer already
// constructed has never been given any work yet at this point in
// normal startup sequencing, so stopping it here is instant and
// drops nothing.
func (s *Server) SetRandomXWorkerPoolSize(workers, queueSize int) {
	s.randomxPool.Stop()
	s.randomxPool = NewAsyncValidationPool(workers, queueSize)
}

// SetInvalidShareGuardConfig overrides this Server's default
// leaflib.InvalidShareGuardConfig (see that field's own doc comment
// and leaflib.InvalidShareGuard's package-level doc comment for the
// full DISPATCH_BRIEF.md 2026-09-10 Fix 2b rationale). Must be called
// before Serve begins accepting connections -- sessions capture
// s.invalidShareGuardConfig once, at newSession time. Passing
// InvalidShareGuardConfig{Enabled: false} disables the mechanism
// entirely.
func (s *Server) SetInvalidShareGuardConfig(cfg leaflib.InvalidShareGuardConfig) {
	s.invalidShareGuardConfig = cfg.Normalized()
	s.invalidShareGuardConfig.Enabled = cfg.Enabled
}

// EnableMetrics constructs a *metrics.Metrics wired to this Server's
// live session state (via SetSnapshotSource(s.sessionSnapshots)) and
// stores it so handleSubmit/handleConn/session.Run's real event points
// (see recordShare/recordBlock/recordConnectionError below) start
// reporting into it. Must be called once, before Serve begins accepting
// connections. version is recorded on the leaf_solo_build_info gauge.
// maxAddressLabels <= 0 falls back to metrics.DefaultMaxAddressLabels
// and is also used to cap Stats()'s MinersByAddress breakdown, so the
// stats HTML page and the exported metric never disagree about the cap.
func (s *Server) EnableMetrics(version string, maxAddressLabels int) *metrics.Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = metrics.DefaultMaxAddressLabels
	}
	m := metrics.New(version, maxAddressLabels)
	m.SetSnapshotSource(s.sessionSnapshots)
	// Fix 9 (DISPATCH_BRIEF.md 2026-09-10): wire the shared
	// AsyncValidationPool's live stats into the new
	// leaf_async_validation_* metrics -- read s.randomxPool at CALL
	// time (not captured as a local variable here), since
	// SetRandomXWorkerPoolSize (below) may replace it with a freshly
	// constructed pool before Serve begins accepting connections;
	// reading the field fresh on every scrape keeps this correct
	// regardless of call order between EnableMetrics and
	// SetRandomXWorkerPoolSize.
	m.SetAsyncPoolSource(func() metrics.AsyncPoolStats {
		return metrics.AsyncPoolStats{
			QueueDepth:         s.randomxPool.QueueDepth(),
			InFlightWorkers:    s.randomxPool.InFlightWorkers(),
			SubmitBlockedTotal: s.randomxPool.SubmitBlockedTotal(),
		}
	})
	s.metrics = m
	s.maxAddressLabels = maxAddressLabels
	// Wire the real XNP-reservation-unavailable counter into this
	// server's own MoneroNodeClient, if that's what it's actually
	// running against (see monero_node.go's SetReservationUnavailableMetric
	// doc comment) -- a no-op for any other NodeClient implementation
	// (e.g. Tari's GRPCNodeClient), which never reads this metric.
	if mnc, ok := s.node.(*MoneroNodeClient); ok {
		mnc.SetReservationUnavailableMetric(m.XNPReservationUnavailableTotal)
	}
	return m
}

// SetHideRemoteAddress opts this server's stats HTML page into
// omitting the "Remote address" column entirely (both header and
// per-session value) — see the hideRemoteAddress field's doc comment.
// Safe to call at any point before or after Serve begins accepting
// connections; StatsHTMLHandler reads it fresh on every request.
func (s *Server) SetHideRemoteAddress(hide bool) {
	s.hideRemoteAddress.Store(hide)
}

// SetStatsPageMaxSessions sets the -stats-page-max-sessions/
// LEAF_SOLO_STATS_PAGE_MAX_SESSIONS cap StatsHTMLHandler enforces on
// its "Connected sessions" table row count -- see
// statsPageMaxSessions's own doc comment and capSessionsForDisplay
// in statsui.go for the full rationale. 0/negative disables the cap
// entirely (render everything).
func (s *Server) SetStatsPageMaxSessions(max int) {
	s.statsPageMaxSessions = max
}

// SetDebugLogger opts this Server (and every Session it creates) into
// verbose [DEBUG]-tagged logging -- see internal/leaflib/debuglog.go's
// doc comment and cmd/leaf-solo/main.go's -debug/LEAF_SOLO_DEBUG
// wiring. Passing a nil or disabled *leaflib.DebugLogger (or never
// calling this at all) is a complete no-op -- every debug call site
// this Server/Session touches is safe to call on a nil DebugLogger.
// Must be called before Serve begins accepting connections, mirroring
// every other opt-in Set*/Enable* method's convention on this type.
func (s *Server) SetDebugLogger(d *leaflib.DebugLogger) {
	s.debugLogger = d
}

// SetNoShareTimeout opts this Server into the connection-hygiene
// disconnect this feature's own brief describes: a session that
// connects and never produces a single genuinely accepted share
// (see Session.shareCount) within timeout of connecting gets
// disconnected by a periodic sweep (runNoShareSweep) -- a huge
// number of miners at real production scale connect and only ever
// send periodic keepalived messages, never a real submit, wasting a
// connection slot indefinitely without ever tripping the existing,
// generic "any contact resets the clock" idle timeout
// (ManagedConnection.armReadDeadline). This is a genuinely different
// condition from that idle timeout: the connection is NOT idle (it
// is actively sending non-share traffic) -- see
// metrics.ConnErrorIdleTimeout's own doc comment for that
// distinction and this feature's own metrics.ConnErrorNoShareTimeout
// category (recorded by sweepNoShareSessions).
//
// A non-positive timeout disables this feature entirely (mirrors
// armReadDeadline's own <=0-disables convention): the sweep
// goroutine is never even started in that case (see
// startNoShareSweep), so a Server that never calls this method (or
// calls it with a non-positive value) costs not even one extra
// goroutine. Set from cmd/leaf-solo's own -no-share-timeout/
// LEAF_SOLO_NO_SHARE_TIMEOUT flag (default 3m, matching Alex's
// stated "2-3 minutes" upper bound). Must be called before Serve
// begins accepting connections, mirroring every other opt-in
// Set*/Enable* method's convention on this type.
//
// A session that submits its first accepted share is PERMANENTLY
// exempt from this specific disconnect for the rest of its life
// (shareCount only ever increases, never resets) -- it never
// re-triggers later just because a session goes quiet AFTER its
// first share; that's what the existing, separate idle timeout
// already covers.
func (s *Server) SetNoShareTimeout(timeout time.Duration) {
	s.noShareTimeout = timeout
	s.startNoShareSweep()
}

// EnableAddressFlags opts this server into the real, manual ban/
// forced-minimum-difficulty enforcement described on the addressFlags
// field's own doc comment. cache should already have had Start called
// on it (see cmd/leaf-solo/main.go) so it is serving a real, already-
// polled snapshot by the time the first miner connection arrives;
// EnableAddressFlags itself does not start any polling -- it only
// wires an already-running Cache into this Server's enforcement path.
func (s *Server) EnableAddressFlags(cache *addressflags.Cache) {
	s.addressFlags = cache
}

// MetricsHandler returns the Prometheus /metrics HTTP handler if
// EnableMetrics has been called, or a handler that responds 404
// otherwise (rather than panicking a caller that wires it
// unconditionally).
func (s *Server) MetricsHandler() http.Handler {
	if s.metrics == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics not enabled", http.StatusNotFound)
		})
	}
	return s.metrics.Handler()
}

// sessionSnapshots implements metrics.SnapshotFunc against this
// Server's real, live session map — the same map Stats() below reads,
// so both the Prometheus scrape path and the stats HTML page are
// derived from identical live state, never two independently-drifting
// views.
func (s *Server) sessionSnapshots() []metrics.SessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]metrics.SessionSnapshot, 0, len(s.sessions))
	for _, sess := range s.sessions {
		addr, _ := sess.address.Load().(string)
		agent, _ := sess.agent.Load().(string)
		out = append(out, metrics.SessionSnapshot{
			Address:    addr,
			Agent:      agent,
			RemoteIP:   metrics.RemoteIPOf(sess.mc.RemoteAddr()),
			Difficulty: sess.currentDifficulty.Load(),
			Hashrate:   leaflib.EstimateHashrateHz(sess.hashesAccumulated.Load(), sess.connectedAt),
		})
	}
	return out
}

// recordShare/recordBlock/recordConnectionError are nil-safe hooks
// called from session.go's real branch points (writeShareResponse for
// every submit outcome, the blockCount.Add(1)/SubmitBlock-error sites
// for genuine block attempts) and handleConn's gate-rejection/close
// paths below. They never affect accept/reject decisions themselves —
// purely observability around the existing logic.
func (s *Server) recordShare(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncShareResult(resultLabel(accepted))
}

func (s *Server) recordBlock(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncBlockResult(resultLabel(accepted))
}

func (s *Server) recordConnectionError(category string) {
	if s.metrics == nil {
		return
	}
	s.metrics.ConnectionErrorsTotal.WithLabelValues(category).Inc()
}

// startNoShareSweep launches the single, Server-scoped periodic
// no-share-timeout sweep goroutine (runNoShareSweep) if
// s.noShareTimeout is positive -- deliberately ONE ticker for the
// whole Server, never one timer/goroutine per session. At the real
// production scale this feature exists for (13,500+ concurrent
// connections, per this feature's own brief), a per-session timer on
// top of everything else already running per-session would repeat
// the exact class of session-map-bloat production incidents this
// codebase's direct.Server (jobFetchPool/repushPool) doc comments
// describe fixing elsewhere. This sweep instead scans the SAME
// s.sessions map every other per-connection bookkeeping path on this
// Server already maintains (see sessionSnapshots/handleConn) -- no
// second, parallel registry.
//
// A non-positive s.noShareTimeout is this feature's documented
// no-op: no goroutine is started at all (the stronger guarantee,
// preferred here over "start it but have it never disconnect
// anyone" -- see this package's own no-share-timeout tests, which
// confirm a disabled Server leaks no extra goroutine). Called from
// SetNoShareTimeout.
func (s *Server) startNoShareSweep() {
	if s.noShareTimeout <= 0 {
		return
	}
	s.noShareSweepStop = make(chan struct{})
	s.noShareSweepDone = make(chan struct{})
	go s.runNoShareSweep()
}

func (s *Server) runNoShareSweep() {
	defer close(s.noShareSweepDone)
	ticker := time.NewTicker(defaultNoShareSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.noShareSweepStop:
			return
		case <-ticker.C:
			s.sweepNoShareSessions()
		}
	}
}

// sweepNoShareSessions is a single pass of the no-share-timeout
// sweep: it takes a real, complete snapshot of every currently-live
// session (RLock'd, mirroring sessionSnapshots' own convention
// exactly) and, for each one that has NEVER produced a genuinely
// accepted share (Session.shareCount.Load() == 0, incremented only
// in finishSubmit AFTER real validation passes -- never for a
// rejected/invalid submit) and has been connected longer than
// s.noShareTimeout, closes it via the exact same mc.Close(...)
// mechanism the existing invalid-share-guard disconnect uses (see
// finishSubmit's own disconnect call), with a clear, distinct reason
// string and connection-error category
// (metrics.ConnErrorNoShareTimeout) so it is never conflated with
// the generic metrics.ConnErrorIdleTimeout category -- that
// connection was NOT idle, it was actively sending non-share
// traffic.
//
// A session that has produced at least one accepted share is
// PERMANENTLY exempt from this specific disconnect for the rest of
// its life, even if it goes on to submit nothing else ever again --
// shareCount only ever increases, so this check can never re-trigger
// for a session once it has passed it once (that's what the
// existing, separate, generic idle timeout already covers).
func (s *Server) sweepNoShareSessions() {
	// Defensive no-op mirroring startNoShareSweep's own <=0-disables
	// convention: in normal operation this can never actually be
	// reached with a non-positive noShareTimeout (startNoShareSweep
	// never starts the goroutine that calls this in that case), but
	// keeping the same guard here too means a caller that invokes
	// this directly (e.g. this package's own tests) never has to
	// worry about it double-checking noShareTimeout itself.
	if s.noShareTimeout <= 0 {
		return
	}
	now := time.Now
	if s.noShareSweepNow != nil {
		now = s.noShareSweepNow
	}
	nowT := now()

	s.mu.RLock()
	var stale []*Session
	for _, sess := range s.sessions {
		if sess.shareCount.Load() == 0 && nowT.Sub(sess.connectedAt) > s.noShareTimeout {
			stale = append(stale, sess)
		}
	}
	s.mu.RUnlock()

	for _, sess := range stale {
		addr, _ := sess.address.Load().(string)
		s.logger.Printf("solo: disconnecting session %s (address %s): no share submitted within %s of connecting", sess.sessionID, addr, s.noShareTimeout)
		_ = sess.mc.Close(fmt.Sprintf("no share submitted within %s of connecting", s.noShareTimeout))
		s.recordConnectionError(metrics.ConnErrorNoShareTimeout)
	}
}

// stopNoShareSweep stops the sweep goroutine started by
// startNoShareSweep, if one was ever started -- a Server that never
// called SetNoShareTimeout with a positive value never started one
// (see that method's own doc comment), so this is a safe no-op there
// too. Called from Shutdown(), mirroring every other background
// worker's explicit stop-on-Shutdown convention on this type
// (randomxPool.Stop(), etc.).
func (s *Server) stopNoShareSweep() {
	if s.noShareSweepStop == nil {
		return
	}
	close(s.noShareSweepStop)
	<-s.noShareSweepDone
}

// recordShareRejectionReason bumps the real
// leaf_share_rejection_reason_total counter (see
// metrics.Metrics.ShareRejectionReasonTotal's doc comment) for reason
// (one of metrics.RejectionReason*) -- called from session.go's
// rejectShare helper at every real reject call site handleSubmit
// reaches, mirroring recordShare/recordBlock/recordConnectionError's
// identical nil-checked convention above. ADDITIVE to (never a
// replacement for) writeShareResponse's own existing recordShare(false)
// bookkeeping -- see rejectShare's own doc comment.
func (s *Server) recordShareRejectionReason(reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncShareRejectionReason(reason)
}

// recordLoginRejection bumps the real leaf_solo_login_rejections_total
// counter (see metrics.Metrics.LoginRejectionsTotal's doc comment) for
// reason (one of metrics.LoginRejectionReason*) -- called from
// session.go's handleLogin at every real rejection return point,
// mirroring recordShare/recordBlock/recordConnectionError/
// recordShareRejectionReason's identical nil-checked convention above
// (DISPATCH_BRIEF.md "login-rejection-reason metrics").
func (s *Server) recordLoginRejection(reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncLoginRejectionReason(reason)
}

func resultLabel(accepted bool) string {
	if accepted {
		return metrics.ResultAccepted
	}
	return metrics.ResultRejected
}

// invalidateAndRepushJobs is called whenever JobManager invalidates its
// per-xn job cache (tip movement or periodic refresh — see
// JobManager.Subscribe's doc comment). Since jobs are now per-xn (see
// job.go's doc comment), there is no single new Job to broadcast:
// instead, for every currently-connected, logged-in session, a fresh
// (or freshly-regenerated) job is fetched for THAT session's own xn,
// AT THAT SESSION'S OWN CURRENT VARDIFF DIFFICULTY (not any global
// static value — a tip-triggered regeneration must not silently reset
// a session's difficulty back to the starting value), and pushed to it
// individually.
func (s *Server) invalidateAndRepushJobs() {
	s.mu.RLock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.RUnlock()
	for _, sess := range sessions {
		if !sess.loggedIn.Load() {
			continue
		}
		job, err := s.jobManager.JobForXNAtDifficulty(context.Background(), sess.xn, sess.currentDifficulty.Load())
		if err != nil {
			s.logger.Printf("solo: failed to regenerate job for session %s (xn %s) after cache invalidation: %v", sess.sessionID, sess.xn, err)
			continue
		}
		// BUG FIX (Alex, live production report: "we're sending
		// duplicate jobs down the wire to RXT"): this callback fires
		// on EVERY periodic RefreshInterval tick (default 30s) AND on
		// tip movement, regardless of whether THIS session's own job
		// actually changed. Skip the unsolicited push when it would be
		// byte-for-byte identical (same job.ID AND same difficulty) to
		// what this session was already handed — see
		// Session.alreadyDelivered's doc comment for the real legacy
		// reference (go-tari-sha3x-solo-stratum's checkForNewWork/
		// SendNewJob, which only pushes when the tip has genuinely
		// advanced past the miner's current job) this ports.
		if sess.alreadyDelivered(job) {
			continue
		}
		sess.pushJob(job)
	}
}

// Serve accepts miner connections on ln until ctx is cancelled or ln is
// closed, stamping every session accepted on ln with port.Difficulty as
// its STARTING difficulty (see portconfig.go's PortConfig doc comment
// — from that point on, vardiff takes over exactly as before, per
// session, regardless of which port it came in on). It blocks; callers
// typically run it in its own goroutine, one call per configured port
// tier, all sharing this same Server (and therefore the same
// JobManager/ConnectionManager/NodeClient/validator) — see
// cmd/leaf-solo/main.go's startup sequence for the multi-listener
// fan-out.
func (s *Server) Serve(ctx context.Context, ln net.Listener, port PortConfig) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn, port.Difficulty)
	}
}

// handleConn accepts and runs one already-dialed connection through a
// new Session, seeded at startingDifficulty (the difficulty of the
// port tier this conn was accepted on — see Serve above). Test-only
// direct callers (session_test.go's testHarness) that don't go through
// a real net.Listener/Serve call this directly with whichever
// difficulty that test wants the session to start at.
func (s *Server) handleConn(ctx context.Context, conn net.Conn, startingDifficulty uint64) {
	// HARDENING FIX (FIX_BRIEF.md, finding #20): recover any panic
	// from this goroutine's own body (including Session.Run, called
	// synchronously below, which is where any future real-world
	// regression is most likely to actually panic) -- unlike the
	// backend's net/http (which recovers per-request automatically),
	// nothing in this leaf's own Serve/handleConn accept path ever
	// did, so a panic here used to take down this ENTIRE leaf
	// process, killing every other already-connected miner's session
	// too, not just this one connection. Registered FIRST (so it
	// runs LAST during panic unwinding, after the session-cleanup
	// defer below has already run normally) and unconditionally
	// closes conn directly (idempotent even if mc/session already
	// closed it) so this is safe regardless of how far handleConn got
	// before panicking.
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("solo: recovered from a panic in handleConn for remote=%s (closing only this connection; every other session and this leaf's own accept loop are unaffected): %v\n%s", conn.RemoteAddr(), r, debug.Stack())
			_ = conn.Close()
		}
	}()

	mc, err := s.cm.Accept(ctx, conn)
	if err != nil {
		// Accept already closed conn on rejection (see
		// leaflib.ConnectionManager.Accept's doc comment). This is a
		// real, observable connection-error category: the
		// ConnectionGate declined admission (e.g. over
		// MaxConnections) before a Session ever existed for it.
		if errors.Is(err, leaflib.ErrConnectionRejected) {
			s.recordConnectionError(metrics.ConnErrorRejectedByGate)
		}
		return
	}

	session := newSession(mc, s, startingDifficulty)
	s.mu.Lock()
	s.sessions[mc.ID()] = session
	s.mu.Unlock()

	s.debugLogger.Debugf("solo: connection accepted: session=%s remote=%s starting_difficulty=%d", session.sessionID, conn.RemoteAddr(), startingDifficulty)

	defer func() {
		s.mu.Lock()
		delete(s.sessions, mc.ID())
		s.mu.Unlock()
		s.debugLogger.Debugf("solo: connection closed: session=%s remote=%s", session.sessionID, conn.RemoteAddr())
		_ = mc.Close("session ended")
	}()

	// Per-session vardiff retarget timer, scoped to this connection's
	// own lifetime context (mc.Context() — see
	// internal/leaflib.ManagedConnection.Context's doc comment, the
	// exact hook it documents for per-connection periodic work like a
	// vardiff timer). This is NOT a shared/global scheduler: every
	// session gets its own goroutine and its own ticker, and this
	// goroutine exits on its own the moment mc.Context() is cancelled
	// (connection closes, for any reason) — no explicit cleanup needed
	// beyond that, and no other session's timer is affected.
	go session.runVardiffLoop(mc.Context())

	session.Run(mc.Context())
}

// Shutdown unsubscribes from job updates, stops this Server's
// RandomX-family async validation worker pool (asyncValidationPool.Stop --
// blocks until every in-flight validation finishes), the
// no-share-timeout sweep goroutine (see stopNoShareSweep, a no-op if
// it was never started), and -- if metrics are enabled -- the
// per-second rate trackers' background goroutines (see
// metrics.Metrics.Stop). It does not close the ConnectionManager or
// listener — callers own those lifecycles.
func (s *Server) Shutdown() {
	if s.unsubscribe != nil {
		s.unsubscribe()
	}
	s.stopNoShareSweep()
	if s.randomxPool != nil {
		s.randomxPool.Stop()
	}
	if s.metrics != nil {
		s.metrics.Stop()
	}
}

// SessionStat is one connected session's real, point-in-time
// diagnostic snapshot, used by both Stats() and the stats HTML page.
type SessionStat struct {
	SessionID string
	Address   string
	Worker    string
	// Agent is the real miner software/version string the miner
	// self-reported at login (LoginRequest.Agent) — see
	// session.go's Session.agent doc comment. Empty if not logged
	// in, or the miner sent no "agent" field.
	Agent             string
	RemoteAddr        string
	ConnectedAt       time.Time
	CurrentDifficulty uint64
	ShareCount        uint64
	BlockCount        uint64
	// EstimatedHashrate is this session's real, per-session
	// estimated hashrate in hashes/second, derived from its own
	// difficulty-weighted accept-history accumulator and connection
	// age — see leaflib.EstimateHashrateHz's doc comment for the
	// full formula (hashesAccumulated/elapsedSeconds; NO 2^32 or
	// other multiplier is applied — an earlier revision of this
	// comment incorrectly described a "difficulty*2^32/time"
	// formula, which was a real, since-fixed bug in a previous
	// version of EstimateHashrateHz itself, not the current, correct
	// behavior; see that function's own doc comment for the fix
	// history — FIX_BRIEF.md, finding #20).
	EstimatedHashrate float64
}

// AddressCount is one entry in Stats.MinersByAddress: a mining/payout
// address (or metrics.OtherAddressLabel for the overflow bucket) and
// the number of currently-connected sessions logged in under it.
type AddressCount struct {
	Address string
	Count   int
}

// Stats is a point-in-time diagnostic snapshot, backing both the
// /metrics-independent Stats() callers already had (logging, tests)
// and the stats HTML page. Solo mode has no share table, so this is
// the only visibility into share/block activity available locally.
type Stats struct {
	ActiveSessions   int
	TotalShares      uint64
	TotalBlocks      uint64
	UniqueRemoteIPs  int
	MinersByAddress  []AddressCount // capped/sorted desc by count, overflow aggregated into metrics.OtherAddressLabel
	MinDifficulty    uint64
	MaxDifficulty    uint64
	MedianDifficulty uint64
	Sessions         []SessionStat // per-session snapshot list, sorted by ConnectedAt

	// TotalEstimatedHashrate is the sum of EstimatedHashrate across
	// all sessions in this snapshot (hashes/second) — see
	// SessionStat.EstimatedHashrate's doc comment for the underlying
	// per-session formula.
	TotalEstimatedHashrate float64
}

// Stats returns a diagnostic snapshot across all currently-connected
// sessions: real per-session data (address, worker, remote address,
// current vardiff difficulty, share/block counts), real per-address
// connection counts (subject to the same cardinality cap as the
// leaf_miners_by_address metric — see metrics.CapAddressCounts), the
// real count of distinct remote IPs currently connected, and the
// real min/max/median of currently-connected sessions' vardiff
// difficulty.
func (s *Server) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := Stats{ActiveSessions: len(s.sessions)}
	ipSet := make(map[string]struct{}, len(s.sessions))
	addrCounts := make(map[string]int)
	diffs := make([]uint64, 0, len(s.sessions))
	st.Sessions = make([]SessionStat, 0, len(s.sessions))

	for _, sess := range s.sessions {
		st.TotalShares += sess.shareCount.Load()
		st.TotalBlocks += sess.blockCount.Load()

		addr, _ := sess.address.Load().(string)
		worker, _ := sess.worker.Load().(string)
		agent, _ := sess.agent.Load().(string)
		remoteIP := metrics.RemoteIPOf(sess.mc.RemoteAddr())
		diff := sess.currentDifficulty.Load()

		if remoteIP != "" {
			ipSet[remoteIP] = struct{}{}
		}
		if addr != "" {
			addrCounts[addr]++
		}
		diffs = append(diffs, diff)

		remoteAddr := ""
		if sess.mc.RemoteAddr() != nil {
			remoteAddr = sess.mc.RemoteAddr().String()
		}
		hashrate := leaflib.EstimateHashrateHz(sess.hashesAccumulated.Load(), sess.connectedAt)
		st.Sessions = append(st.Sessions, SessionStat{
			SessionID:         sess.sessionID,
			Address:           addr,
			Worker:            worker,
			Agent:             agent,
			RemoteAddr:        remoteAddr,
			ConnectedAt:       sess.connectedAt,
			CurrentDifficulty: diff,
			ShareCount:        sess.shareCount.Load(),
			BlockCount:        sess.blockCount.Load(),
			EstimatedHashrate: hashrate,
		})
		st.TotalEstimatedHashrate += hashrate
	}

	st.UniqueRemoteIPs = len(ipSet)

	kept, other := metrics.CapAddressCounts(addrCounts, s.maxAddressLabels)
	st.MinersByAddress = sortedAddressCounts(kept, other)

	st.MinDifficulty, st.MaxDifficulty, st.MedianDifficulty = minMaxMedian(diffs)

	sortSessionsByConnectedAt(st.Sessions)

	return st
}

// sortedAddressCounts renders kept+other into the deterministic,
// count-desc-then-address-asc order the stats HTML page and any
// future consumer expect, with the "other" overflow bucket (if any)
// always last.
func sortedAddressCounts(kept map[string]int, other int) []AddressCount {
	out := make([]AddressCount, 0, len(kept)+1)
	for addr, count := range kept {
		out = append(out, AddressCount{Address: addr, Count: count})
	}
	sortAddressCounts(out)
	if other > 0 {
		out = append(out, AddressCount{Address: metrics.OtherAddressLabel, Count: other})
	}
	return out
}

func sortAddressCounts(counts []AddressCount) {
	for i := 1; i < len(counts); i++ {
		for j := i; j > 0; j-- {
			a, b := counts[j-1], counts[j]
			if a.Count > b.Count || (a.Count == b.Count && a.Address <= b.Address) {
				break
			}
			counts[j-1], counts[j] = counts[j], counts[j-1]
		}
	}
}

func sortSessionsByConnectedAt(sessions []SessionStat) {
	for i := 1; i < len(sessions); i++ {
		for j := i; j > 0; j-- {
			if !sessions[j-1].ConnectedAt.After(sessions[j].ConnectedAt) {
				break
			}
			sessions[j-1], sessions[j] = sessions[j], sessions[j-1]
		}
	}
}

// minMaxMedian computes real min/max/median over vals without
// mutating the caller's slice (it copies before sorting). Returns
// zeros for an empty input.
func minMaxMedian(vals []uint64) (min, max, median uint64) {
	if len(vals) == 0 {
		return 0, 0, 0
	}
	sorted := make([]uint64, len(vals))
	copy(sorted, vals)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	min = sorted[0]
	max = sorted[len(sorted)-1]
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		median = sorted[mid]
	} else {
		median = (sorted[mid-1] + sorted[mid]) / 2
	}
	return min, max, median
}
