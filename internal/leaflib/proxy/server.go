// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// UpstreamHealth is an OPTIONAL capability a Server's real
// UpstreamSubmitter may additionally implement to expose real
// connection-health data for metrics — implemented by the real
// UpstreamClient in production. It is deliberately NOT folded into
// the UpstreamSubmitter interface itself (session_test.go's
// fakeUpstream only implements SubmitShare and must keep compiling
// unmodified): Server type-asserts for it at metrics-collection time
// and degrades gracefully (health metrics simply stay at their zero
// value) when the concrete upstream doesn't implement it, e.g. in
// tests.
type UpstreamHealth interface {
	// Connected reports whether the upstream pool connection is
	// currently established.
	Connected() bool
	// ReconnectCount reports the real, monotonically-increasing count
	// of successful reconnects since process start (NOT counting the
	// initial startup connect).
	ReconnectCount() uint64
}

// UpstreamGenerationSource is an OPTIONAL capability a Server's real
// UpstreamSubmitter may additionally implement to expose the real
// upstream-connection generation counter (see upstream.go's
// UpstreamClient.generation doc comment for the full root-cause/fix
// rationale) — implemented by the real UpstreamClient in production
// via CurrentGeneration(). Deliberately NOT folded into the
// UpstreamSubmitter interface itself, for the exact same reason
// UpstreamHealth above isn't: session_test.go's plain fakeUpstream
// only implements SubmitShare and must keep compiling unmodified.
// Session.handleSubmit type-asserts s.server.upstream against this
// interface at submit time and degrades gracefully — fails OPEN, not
// closed — when the concrete upstream doesn't implement it (e.g. in
// most existing tests): "no generation info available" is treated as
// "cannot check staleness, allow the submit through unchanged", never
// as a reason to reject a submit that would otherwise have been
// accepted before this capability existed.
type UpstreamGenerationSource interface {
	// CurrentGeneration reports the upstream-connection generation
	// number of the upstream client's CURRENTLY-live template. A
	// Job whose own TemplateGeneration (job.go) is less than this
	// value was minted against a template from a since-superseded
	// upstream connection generation (e.g. the upstream pool
	// connection dropped and reconnected since that Job was issued)
	// and should be rejected locally rather than forwarded upstream.
	CurrentGeneration() uint64
}

// UpstreamSeedHashStats is an OPTIONAL capability a Server's real
// UpstreamSubmitter may additionally implement to expose the real
// job.SeedHash-decode-error counter (FIX_BRIEF.md, finding #18) --
// implemented by the real UpstreamClient in production via
// SeedHashDecodeErrorsTotal(). Deliberately NOT folded into the
// UpstreamSubmitter interface itself, for the exact same reason
// UpstreamHealth/UpstreamGenerationSource above aren't. Server
// type-asserts for it in EnableMetrics and degrades gracefully (the
// metric simply stays at zero) when the concrete upstream doesn't
// implement it, e.g. in most existing tests.
type UpstreamSeedHashStats interface {
	// SeedHashDecodeErrorsTotal reports the real, monotonically-
	// increasing count of upstream jobs received with a non-empty
	// but unparseable seed_hash field.
	SeedHashDecodeErrorsTotal() uint64
}

// Server ties together internal/leaflib.ConnectionManager (downstream
// miner connection lifecycle — reused, not reimplemented), a
// JobManager (issuing per-session Jobs from the real upstream pool's
// current WorkerTemplate), a ShareValidator (real local RandomX
// re-validation — the already-merged, already-live-verified
// validator.RandomXValidator in production), and an UpstreamSubmitter
// (real forwarding of shares meeting the upstream pool's requested
// share difficulty — UpstreamClient in production). This is
// leaf-proxy's entire vertical slice: mode 3 of the unified
// leaf/proxy/solo/direct architecture, the XMR-Node-Proxy-style
// AGGREGATING pattern — many real downstream miner connections behind
// ONE real upstream pool connection.
type Server struct {
	cm        *leaflib.ConnectionManager
	jobs      *JobManager
	validator ShareValidator
	upstream  UpstreamSubmitter
	logger    *log.Logger

	vardiff   leaflib.VardiffConfig
	jobMaxAge time.Duration

	mu       sync.RWMutex
	sessions map[uint64]*Session

	unsubscribe func()

	// metrics is nil unless EnableMetrics has been called — every
	// recordX helper below is a nil-safe no-op when it is nil,
	// mirroring internal/leaflib/solo/server.go's identical
	// opt-in-metrics convention exactly.
	metrics *metrics.Metrics

	// maxAddressLabels bounds the leaf_proxy_miners_by_address
	// cardinality AND the stats HTML page's per-address breakdown
	// identically — same convention as leaf-solo's Server.
	maxAddressLabels int

	// lastReconnectCount tracks the most recent UpstreamHealth.
	// ReconnectCount() value observed at scrape time, so
	// sessionSnapshots can Add() the real delta onto the monotonic
	// UpstreamReconnectsTotal counter (prometheus.Counter has no
	// Set method).
	lastReconnectCount atomic.Uint64

	// hideRemoteAddress mirrors internal/leaflib/solo/server.go's
	// identical field exactly — see that doc comment (including its
	// FIX_BRIEF.md finding #20 atomic.Bool rationale). Defaults to
	// false; set via SetHideRemoteAddress.
	hideRemoteAddress atomic.Bool

	// addressFlags is nil unless EnableAddressFlags has been called --
	// mirrors internal/leaflib/solo/server.go's/
	// internal/leaflib/direct/server.go's identical field exactly (see
	// that field's doc comment for the full rationale). nil means
	// every login/submit is treated as unflagged, identical to this
	// feature not existing at all. leaf-proxy has no backend
	// connection of its own (same as leaf-solo -- see cmd/leaf-proxy's
	// doc comment: it emulates an advanced mining CLIENT to an
	// upstream pool, it does not have an upstream go-crypto-pool
	// backend), so cmd/leaf-proxy wires this via
	// addressflags.FileSource, mirroring cmd/leaf-solo's identical
	// wiring exactly. Consulted by session.go's handleLogin (ban
	// rejection) and handleSubmit (mid-session ban re-check).
	addressFlags *addressflags.Cache

	// randomxPool is the bounded, server-wide worker pool session.go's
	// handleSubmit dispatches the real, expensive local RandomX
	// re-validation (ShareValidator.ValidateBlobSeedResult) onto for a
	// genuine upstream-forward candidate, so that call never blocks
	// Session.Run's read loop -- mirrors
	// internal/leaflib/direct/server.go's identical field exactly
	// (leaf-direct also reuses solo's exported AsyncValidationPool
	// type directly rather than duplicating it -- see
	// internal/leaflib/solo/asyncvalidation.go's package doc comment
	// for the full production-incident rationale this class of fix
	// addresses). Always non-nil (constructed in NewServer).
	randomxPool *solo.AsyncValidationPool

	// invalidShareGuardConfig mirrors solo.Server's own identical
	// field exactly -- see leaflib.InvalidShareGuard's doc comment
	// for the full DISPATCH_BRIEF.md 2026-09-10 Fix 2b rationale.
	// Defaults to leaflib.DefaultInvalidShareGuardConfig() (enabled)
	// in NewServer; overridable via SetInvalidShareGuardConfig.
	invalidShareGuardConfig leaflib.InvalidShareGuardConfig

	// poolDiffCapEnabled gates the login-time pool-target-diff cap
	// added by commit 46a6e2c (see session.go's handleLogin doc
	// comment on that cap block for the full mechanism this toggles).
	// DISPATCH_BRIEF.md 2026-09-13 (Alex): "lets put this feature
	// behind a default-on flag to help protect against
	// mis-configuration, most proxy ops likely won't have this issue
	// because they'll have reasonable starting points." Defaults to
	// true (enabled) in NewServer, mirroring
	// invalidShareGuardConfig's own default-enabled convention above;
	// overridable via SetPoolDiffCapEnabled. When false, handleLogin
	// skips the entire cap block and falls through to exactly the
	// pre-flag (pre-46a6e2c) max()-of-floors behavior.
	poolDiffCapEnabled bool

	// debugLogger is nil unless SetDebugLogger has been called (see
	// cmd/leaf-proxy/main.go's -debug/LEAF_PROXY_DEBUG wiring) --
	// the real, opt-in verbose logging sink (internal/leaflib/
	// debuglog.go). Every Session created by this Server reads it
	// through its own server back-reference. nil is a complete
	// no-op.
	debugLogger *leaflib.DebugLogger

	// devFeeUpstream is nil unless EnableDevFeeUpstream has been
	// called (cmd/leaf-proxy/main.go only calls it when
	// -dev-fee-percent > 0 -- DISPATCH_BRIEF.md "leaf-proxy dev-fee
	// second-connection") -- the optional SECOND, independent
	// upstream connection a Job tagged Route == RouteDevFee (job.go)
	// must actually be forwarded/re-checked against instead of the
	// primary s.upstream. See upstreamForRoute below, the single
	// resolution choke point session.go's handleSubmit uses for
	// every route-dependent decision. nil is a complete no-op: every
	// route-dependent decision falls back to the primary s.upstream,
	// which is exactly the pre-dev-fee behavior.
	devFeeUpstream UpstreamSubmitter

	// lastDevFeeReconnectCount mirrors lastReconnectCount above but
	// for the optional dev-fee connection's own UpstreamHealth.
	// ReconnectCount() delta tracking at scrape time (sessionSnapshots)
	// -- see that field's doc comment for the exact rationale, which
	// applies identically here.
	lastDevFeeReconnectCount atomic.Uint64
}

// NewServer constructs a Server. cm must already be configured with
// the desired MaxConnections/IdleTimeout by the caller, exactly
// mirroring internal/leaflib/solo/server.go's NewServer contract —
// Server does not own ConnectionManager construction so callers keep
// full control of that already-merged, already-correct lifecycle
// policy for DOWNSTREAM connections. jobs must be backed by a
// TemplateSource whose Subscribe fires on every real upstream job
// update (login, getjob, or an unsolicited push) so every currently-
// connected downstream session gets a freshly-regenerated job at ITS
// OWN current vardiff difficulty — mirroring leaf-solo's
// invalidateAndRepushJobs exactly, just triggered by a real upstream
// pool event instead of Tari base-node tip movement.
func NewServer(cm *leaflib.ConnectionManager, jobs *JobManager, validator ShareValidator, upstream UpstreamSubmitter, logger *log.Logger, vardiff leaflib.VardiffConfig, jobMaxAge time.Duration) *Server {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		cm:                      cm,
		jobs:                    jobs,
		validator:               validator,
		upstream:                upstream,
		logger:                  logger,
		vardiff:                 vardiff.Normalized(),
		jobMaxAge:               jobMaxAge,
		sessions:                make(map[uint64]*Session),
		maxAddressLabels:        metrics.DefaultMaxAddressLabels,
		invalidShareGuardConfig: leaflib.DefaultInvalidShareGuardConfig(),
		poolDiffCapEnabled:      true,
		// workers=0 lets NewAsyncValidationPool apply its own default
		// (DefaultAsyncValidationWorkers() == runtime.NumCPU(), NOT a
		// hardcoded literal -- see solo/asyncvalidation.go's doc
		// comment and Alex's explicit direction in
		// DISPATCH_BRIEF.md, 2026-09-10). An operator wanting a
		// different fixed count can override via
		// SetRandomXWorkerPoolSize (see cmd/leaf-proxy's
		// -randomx-workers flag) before Serve begins.
		randomxPool: solo.NewAsyncValidationPool(0, solo.AsyncValidationQueueSize),
	}
	s.unsubscribe = jobs.Subscribe(s.repushAllSessions)
	return s
}

// EnableMetrics constructs a *metrics.Metrics wired to this Server's
// live session state (via SetSnapshotSource(s.sessionSnapshots)) and
// stores it so handleSubmit/handleConn/Session.Run's real event
// points (see recordShareDecision/recordConnectionError below) start
// reporting into it. Must be called once, before Serve begins
// accepting connections. version is recorded on the
// leaf_proxy_build_info gauge. maxAddressLabels <= 0 falls back to
// metrics.DefaultMaxAddressLabels and is also used to cap Stats()'s
// MinersByAddress breakdown.
func (s *Server) EnableMetrics(version string, maxAddressLabels int) *metrics.Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = metrics.DefaultMaxAddressLabels
	}
	m := metrics.New(version, maxAddressLabels)
	m.SetSnapshotSource(s.sessionSnapshots)
	// Fix 9 (DISPATCH_BRIEF.md 2026-09-10): mirrors solo/direct's
	// identical async-pool wiring exactly -- read s.randomxPool at
	// CALL time (not captured here), since SetRandomXWorkerPoolSize
	// may replace it before Serve begins.
	m.SetAsyncPoolSource(func() metrics.AsyncPoolStats {
		return metrics.AsyncPoolStats{
			QueueDepth:         s.randomxPool.QueueDepth(),
			InFlightWorkers:    s.randomxPool.InFlightWorkers(),
			SubmitBlockedTotal: s.randomxPool.SubmitBlockedTotal(),
		}
	})
	// FIX_BRIEF.md finding #18: real observability for both the
	// process-wide malformed-blob circuit breaker (upstream.go's
	// globalMalformedBlobBreaker -- a package-level singleton, not
	// per-Server, see that type's own doc comment for why) and the
	// per-UpstreamClient seed_hash-decode-error counter (via the
	// UpstreamSeedHashStats optional-capability type-assertion, same
	// pattern as UpstreamHealth/UpstreamGenerationSource above).
	m.SetMalformedBlobBreakerSource(func() metrics.MalformedBlobBreakerStats {
		return metrics.MalformedBlobBreakerStats{
			OpensTotal: globalMalformedBlobBreaker.OpensTotal(),
			Open:       globalMalformedBlobBreaker.IsOpen(),
		}
	})
	m.SetSeedHashStatsSource(func() metrics.SeedHashStats {
		if stats, ok := s.upstream.(UpstreamSeedHashStats); ok {
			return metrics.SeedHashStats{DecodeErrorsTotal: stats.SeedHashDecodeErrorsTotal()}
		}
		return metrics.SeedHashStats{}
	})
	s.metrics = m
	s.maxAddressLabels = maxAddressLabels
	return m
}

// SetHideRemoteAddress mirrors internal/leaflib/solo/server.go's
// identical method exactly — see that doc comment.
func (s *Server) SetHideRemoteAddress(hide bool) {
	s.hideRemoteAddress.Store(hide)
}

// SetDebugLogger opts this Server (and every Session it creates) into
// verbose [DEBUG]-tagged logging -- mirrors solo.Server.SetDebugLogger
// exactly (see that method's doc comment). nil/disabled is a complete
// no-op.
func (s *Server) SetDebugLogger(d *leaflib.DebugLogger) {
	s.debugLogger = d
}

// SetRandomXWorkerPoolSize mirrors solo.Server's own identical
// method exactly — see that method's doc comment.
func (s *Server) SetRandomXWorkerPoolSize(workers, queueSize int) {
	s.randomxPool.Stop()
	s.randomxPool = solo.NewAsyncValidationPool(workers, queueSize)
}

// SetInvalidShareGuardConfig mirrors solo.Server's own identical
// method exactly — see that method's doc comment and
// leaflib.InvalidShareGuard's package-level doc comment.
func (s *Server) SetInvalidShareGuardConfig(cfg leaflib.InvalidShareGuardConfig) {
	s.invalidShareGuardConfig = cfg.Normalized()
	s.invalidShareGuardConfig.Enabled = cfg.Enabled
}

// SetPoolDiffCapEnabled toggles the login-time pool-target-diff cap
// (see poolDiffCapEnabled's own doc comment above and session.go's
// handleLogin for the full mechanism). Defaults to true (enabled) via
// NewServer; cmd/leaf-proxy wires this from
// -pool-diff-cap-enabled/LEAF_PROXY_POOL_DIFF_CAP_ENABLED/
// pool_diff_cap_enabled before Serve begins.
func (s *Server) SetPoolDiffCapEnabled(enabled bool) {
	s.poolDiffCapEnabled = enabled
}

// EnableAddressFlags mirrors solo.Server's/direct.Server's own
// identical method exactly -- see that method's doc comment. cache
// should already have had Start called on it (see cmd/leaf-proxy's
// wiring) so it is serving a real, already-polled snapshot by the
// time the first downstream miner connection arrives.
func (s *Server) EnableAddressFlags(cache *addressflags.Cache) {
	s.addressFlags = cache
}

// EnableDevFeeUpstream opts this Server into the optional
// developer-fee mechanism's forwarding side (DISPATCH_BRIEF.md
// "leaf-proxy dev-fee second-connection"): from this call onward,
// upstreamForRoute resolves RouteDevFee (job.go's Job.Route) to
// upstream instead of falling back to the primary s.upstream. Intended
// caller: cmd/leaf-proxy/main.go, only when -dev-fee-percent > 0, in
// lockstep with the SAME UpstreamClient instance also passed to
// JobManager.EnableDevFee -- both must agree on which concrete
// connection RouteDevFee means, or a submit would be validated against
// one connection's template but forwarded to the other's socket.
// Never called at all when the mechanism is disabled, which is what
// makes "-dev-fee-percent=0 is a complete no-op" hold structurally at
// this layer too.
func (s *Server) EnableDevFeeUpstream(upstream UpstreamSubmitter) {
	s.devFeeUpstream = upstream
}

// upstreamForRoute is the single resolution choke point every
// route-dependent decision in session.go's handleSubmit goes through:
// given the UpstreamRoute a specific Job (job.go) was minted under, it
// returns the concrete UpstreamSubmitter that Job's eventual submit
// must be validated/forwarded against. RouteDevFee resolves to
// s.devFeeUpstream ONLY when EnableDevFeeUpstream has actually been
// called (s.devFeeUpstream != nil) -- falling back to the primary
// s.upstream otherwise, which should never actually happen in
// practice (JobManager.NextJob never tags a Job RouteDevFee unless its
// own devFeeSource was non-nil at mint time, and cmd/leaf-proxy always
// calls EnableDevFee/EnableDevFeeUpstream together -- see
// EnableDevFeeUpstream's own doc comment) but is the same
// fail-safe-toward-primary direction every other dev-fee fault-
// isolation fallback in this package takes, rather than a nil-pointer
// panic. RoutePrimary always resolves to s.upstream, unconditionally.
func (s *Server) upstreamForRoute(route UpstreamRoute) UpstreamSubmitter {
	if route == RouteDevFee && s.devFeeUpstream != nil {
		return s.devFeeUpstream
	}
	return s.upstream
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
// Server's real, live session map, AND (since this is called
// synchronously on every /metrics scrape — see metrics.SnapshotFunc's
// doc comment) is also where the single upstream connection's real
// health is refreshed into the UpstreamConnected/UpstreamReconnectsTotal
// collectors, via an UpstreamHealth type-assertion on s.upstream (see
// that interface's doc comment for why this is a graceful, optional
// capability check rather than a hard interface requirement).
func (s *Server) sessionSnapshots() []metrics.SessionSnapshot {
	if s.metrics != nil {
		if health, ok := s.upstream.(UpstreamHealth); ok {
			if health.Connected() {
				s.metrics.UpstreamConnected.Set(1)
			} else {
				s.metrics.UpstreamConnected.Set(0)
			}
			// UpstreamReconnectsTotal is a monotonic counter; Add the
			// delta since the last scrape rather than Set, since
			// prometheus.Counter has no Set.
			current := health.ReconnectCount()
			delta := current - s.lastReconnectCount.Swap(current)
			if delta > 0 && current >= delta {
				s.metrics.UpstreamReconnectsTotal.Add(float64(delta))
			}
		}
		// Dev-fee connection health mirrors the primary's exact same
		// pattern above, on its own gauge/counter pair -- see
		// EnableDevFeeUpstream's doc comment. s.devFeeUpstream is nil
		// (this whole block a no-op) unless the dev-fee mechanism was
		// actually enabled.
		if s.devFeeUpstream != nil {
			if health, ok := s.devFeeUpstream.(UpstreamHealth); ok {
				if health.Connected() {
					s.metrics.DevFeeUpstreamConnected.Set(1)
				} else {
					s.metrics.DevFeeUpstreamConnected.Set(0)
				}
				current := health.ReconnectCount()
				delta := current - s.lastDevFeeReconnectCount.Swap(current)
				if delta > 0 && current >= delta {
					s.metrics.DevFeeUpstreamReconnectsTotal.Add(float64(delta))
				}
			}
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]metrics.SessionSnapshot, 0, len(s.sessions))
	for _, sess := range s.sessions {
		addr, _ := sess.address.Load().(string)
		out = append(out, metrics.SessionSnapshot{
			Address:    addr,
			RemoteIP:   metrics.RemoteIPOf(sess.mc.RemoteAddr()),
			Difficulty: sess.currentDifficulty.Load(),
		})
	}
	return out
}

// recordShareDecision/recordConnectionError are nil-safe hooks called
// from session.go's real branch points (handleSubmit's real
// local-credit/upstream-forward decision, Session.Run's real close
// classification) and handleConn's gate-rejection path below. They
// never affect accept/reject decisions themselves — purely
// observability around the existing, unmodified logic.
func (s *Server) recordShareDecision(forwardedUpstream bool) {
	if s.metrics == nil {
		return
	}
	if forwardedUpstream {
		s.metrics.ShareDecisionsTotal.WithLabelValues(metrics.DecisionUpstreamForward).Inc()
	} else {
		s.metrics.ShareDecisionsTotal.WithLabelValues(metrics.DecisionLocalCredit).Inc()
	}
}

func (s *Server) recordConnectionError(category string) {
	if s.metrics == nil {
		return
	}
	s.metrics.ConnectionErrorsTotal.WithLabelValues(category).Inc()
}

// recordShare is the Fix 9 (DISPATCH_BRIEF.md 2026-09-10) real
// accept/reject counter hook, mirroring solo.Server.recordShare/
// direct.Server.recordShare exactly -- called from session.go's
// writeShareResponse for EVERY submit outcome (share or block,
// accepted or rejected), the single response-writing choke point
// every real branch in handleSubmit already flows through. Distinct
// from recordShareDecision above (local-credit vs upstream-forward);
// this tracks whether the submit was accepted at all.
func (s *Server) recordShare(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.SharesTotal.WithLabelValues(resultLabel(accepted)).Inc()
}

// recordBanRejection is the Fix 9 real counter hook for the two
// address-ban enforcement points (handleLogin's login-time check,
// handleSubmit's mid-session submit-time re-check) that were
// previously log-only -- see metrics.BanRejectionPhaseLogin/
// BanRejectionPhaseSubmit's doc comment.
func (s *Server) recordBanRejection(phase string) {
	if s.metrics == nil {
		return
	}
	s.metrics.BanRejectionsTotal.WithLabelValues(phase).Inc()
}

// resultLabel mirrors solo.Server's own identical helper exactly.
func resultLabel(accepted bool) string {
	if accepted {
		return metrics.ResultAccepted
	}
	return metrics.ResultRejected
}

// repushAllSessions regenerates and pushes a fresh job to every
// currently-connected, logged-in downstream session, AT THAT
// SESSION'S OWN CURRENT VARDIFF DIFFICULTY — mirrors
// internal/leaflib/solo/server.go's invalidateAndRepushJobs and
// internal/leaflib/direct/server.go's identically-named function.
//
// BUG FIX (Alex, live production report: "Proxy is having some job
// staleness issues, it's disabling as soon as a new job is sent, it
// needs to allow jobs 2-3 old, just like the -direct has to"): gated
// by sess.alreadyDelivered(job) exactly like leaf-direct's/leaf-solo's
// own invalidateAndRepushJobs already are.
//
// SECOND BUG FIX, one level deeper (third report of this same class of
// issue): this now calls sess.currentJob(difficulty) (session.go)
// instead of s.jobs.NextJob(difficulty) directly. Before
// Session.currentJob existed, JobManager.NextJob's unconditional
// "always allocate a brand-new random job_id plus fresh worker-/
// pool-nonces" behavior meant EVERY fire of jobs.Subscribe (which,
// prior to upstream.go's applyJob upstream-dupe guard, could itself
// fire on a genuine upstream no-op like a getjob poll response) handed
// every logged-in session a completely new, unrelated job_id --
// evicting that session's own in-flight job out of its bounded
// jobHistorySize (defaultProxySessionJobHistorySize) before it could
// even be submitted. alreadyDelivered already gated the SYMPTOM at
// this one unsolicited-push call site; currentJob now fixes the
// underlying ROOT CAUSE everywhere (this call site included): a
// redundant repush against an unchanged template/difficulty now
// returns the SAME cached *Job instead of minting a new one, so
// alreadyDelivered's gate below will, in the common case, now also
// see the SAME job.ID it already delivered (the two mechanisms are
// complementary, not redundant: currentJob avoids minting a wasted job
// in the first place; alreadyDelivered still avoids re-pushing an
// unchanged job down the wire at all). An explicit miner-initiated
// getjob/vardiff-retarget push is untouched by the alreadyDelivered
// gate -- it still always goes through pushJob/jobPayload
// unconditionally; that gate applies ONLY here, exactly mirroring
// direct/solo's own scoping.
func (s *Server) repushAllSessions() {
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
		job, err := sess.currentJob(sess.currentDifficulty.Load())
		if err != nil {
			s.logger.Printf("proxy: failed to regenerate job for session %s after upstream template update: %v", sess.sessionID, err)
			continue
		}
		if sess.alreadyDelivered(job) {
			continue
		}
		sess.pushJob(job)
	}
}

// recordBlock is the Fix 9 (DISPATCH_BRIEF.md 2026-09-10) real
// block-found counter hook, mirroring solo.Server.recordBlock/
// direct.Server.recordBlock exactly -- previously a no-op stub.
// Called from session.go's handleSubmit at its two real
// block-level-forward outcomes (upstream submit error/rejection vs.
// a real accepted result).
func (s *Server) recordBlock(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.BlocksTotal.WithLabelValues(resultLabel(accepted)).Inc()
}

// Serve accepts downstream miner connections on ln until ctx is
// cancelled or ln is closed, stamping every session accepted on ln
// with port.Difficulty as its starting difficulty -- mirroring
// internal/leaflib/direct/server.go's identical Serve(ctx, ln, port
// solo.PortConfig) signature exactly, so cmd/leaf-proxy's own
// multi-port-tier main() loop can be structurally identical to
// cmd/leaf-direct's (see solo.PortConfig's doc comment for the
// port-tier/starting-difficulty semantics this carries). handleConn
// itself stays a bare uint64 -- only Serve takes the full PortConfig.
// Blocks; callers typically run it in its own goroutine.
func (s *Server) Serve(ctx context.Context, ln net.Listener, port solo.PortConfig) error {
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

func (s *Server) handleConn(ctx context.Context, conn net.Conn, startingDifficulty uint64) {
	// HARDENING FIX (FIX_BRIEF.md, finding #20): mirrors
	// solo.Server's own identical handleConn recovery exactly -- see
	// that method's doc comment for the full rationale.
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("proxy: recovered from a panic in handleConn for remote=%s (closing only this connection; every other session and this leaf's own accept loop are unaffected): %v\n%s", conn.RemoteAddr(), r, debug.Stack())
			_ = conn.Close()
		}
	}()

	mc, err := s.cm.Accept(ctx, conn)
	if err != nil {
		if errors.Is(err, leaflib.ErrConnectionRejected) {
			s.recordConnectionError(metrics.ConnErrorRejectedByGate)
		} else {
			s.logger.Printf("proxy: failed to accept downstream connection: %v", err)
		}
		return
	}

	session := newSession(mc, s, startingDifficulty)
	s.mu.Lock()
	s.sessions[mc.ID()] = session
	s.mu.Unlock()

	s.debugLogger.Debugf("proxy: connection accepted: session=%s remote=%s starting_difficulty=%d", session.sessionID, conn.RemoteAddr(), startingDifficulty)

	defer func() {
		s.mu.Lock()
		delete(s.sessions, mc.ID())
		s.mu.Unlock()
		s.debugLogger.Debugf("proxy: connection closed: session=%s remote=%s", session.sessionID, conn.RemoteAddr())
		_ = mc.Close("session ended")
	}()

	go session.runVardiffLoop(mc.Context())

	session.Run(mc.Context())
}

// Shutdown unsubscribes from upstream job updates and stops this
// Server's RandomX re-validation async worker pool (see
// solo.AsyncValidationPool.Stop -- blocks until every in-flight
// re-validation finishes). It does not close the ConnectionManager or
// listener — callers own those lifecycles.
func (s *Server) Shutdown() {
	if s.unsubscribe != nil {
		s.unsubscribe()
	}
	if s.randomxPool != nil {
		s.randomxPool.Stop()
	}
}

// SessionCount returns the number of currently-connected downstream
// sessions — a small diagnostic used by cmd/leaf-proxy's startup
// logging and tests.
func (s *Server) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// SessionStat is one connected downstream session's real,
// point-in-time diagnostic snapshot, used by both Stats() and the
// stats HTML page — mirrors internal/leaflib/solo/server.go's
// SessionStat shape exactly, with BlockCount here meaning "shares
// forwarded upstream as a genuine block-level find" (leaf-proxy's
// own local-credit-vs-upstream-forward split — see
// internal/leaflib/proxy/metrics's doc comment), NOT a real found
// block the way leaf-solo's BlockCount is.
type SessionStat struct {
	SessionID         string
	Address           string
	Worker            string
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
	// version of EstimateHashrateHz itself, not the current,
	// correct behavior; see that function's own doc comment for the
	// fix history).
	//
	// SECURITY/TRUST CAVEAT (FIX_BRIEF.md, finding #16): this value
	// (and the aggregate Stats.TotalEstimatedHashrate/"Global
	// hashrate" card it feeds) is driven in part by
	// Session.hashesAccumulated, which for any LOCALLY-credited
	// share (below the real upstream pool's own requested share
	// difficulty — see metrics.DecisionLocalCredit) is incremented
	// from the miner's own SELF-CLAIMED result hash with ZERO
	// cryptographic validation. A hostile miner can inflate this
	// number arbitrarily with fabricated claims and no real work
	// behind them — see Session.hashesAccumulated's own doc comment
	// for the full rationale. Do not treat this as an authoritative,
	// tamper-proof measurement; an upstream_forward share (see
	// metrics.DecisionUpstreamForward) IS real-validated, but this
	// aggregate figure does not distinguish the two.
	EstimatedHashrate float64
}

// AddressCount is one entry in Stats.MinersByAddress: a mining/payout
// address (or metrics.OtherAddressLabel for the overflow bucket) and
// the number of currently-connected sessions logged in under it.
type AddressCount struct {
	Address string
	Count   int
}

// Stats is a point-in-time diagnostic snapshot across all currently-
// connected downstream sessions, backing both Stats() callers
// (logging, tests) and the stats HTML page — mirrors
// internal/leaflib/solo/server.go's Stats shape exactly, minus
// leaf-solo's non-applicable fields (no vardiff-median-over-blocks
// concept difference; the shape is otherwise identical since both
// leaves track the same per-session vardiff/share bookkeeping).
type Stats struct {
	ActiveSessions   int
	TotalShares      uint64
	TotalBlocks      uint64 // real upstream_forward decisions across connected sessions
	UniqueRemoteIPs  int
	MinersByAddress  []AddressCount // capped/sorted desc by count, overflow aggregated into metrics.OtherAddressLabel
	MinDifficulty    uint64
	MaxDifficulty    uint64
	MedianDifficulty uint64
	Sessions         []SessionStat // per-session snapshot list, sorted by ConnectedAt

	// TotalEstimatedHashrate is the sum of EstimatedHashrate across
	// all sessions in this snapshot (hashes/second) — see
	// SessionStat.EstimatedHashrate's doc comment for the underlying
	// per-session formula AND its miner-spoofability caveat
	// (FIX_BRIEF.md, finding #16) before treating this "Global
	// hashrate" headline figure as authoritative.
	TotalEstimatedHashrate float64

	UpstreamConnected  bool
	UpstreamReconnects uint64
}

// Stats returns a diagnostic snapshot across all currently-connected
// downstream sessions: real per-session data (address, worker,
// remote address, current vardiff difficulty, share/upstream-forward
// counts), real per-address connection counts (subject to the same
// cardinality cap as the leaf_proxy_miners_by_address metric — see
// metrics.CapAddressCounts), the real count of distinct remote IPs
// currently connected, the real min/max/median of currently-connected
// sessions' vardiff difficulty, and (when the concrete upstream
// implements UpstreamHealth) the real single-upstream-connection
// health — mirrors internal/leaflib/solo/server.go's Stats() exactly,
// plus the upstream-health fields solo mode has no analogue for.
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

	if health, ok := s.upstream.(UpstreamHealth); ok {
		st.UpstreamConnected = health.Connected()
		st.UpstreamReconnects = health.ReconnectCount()
	}

	return st
}

// sortedAddressCounts renders kept+other into the deterministic,
// count-desc-then-address-asc order the stats HTML page and any
// future consumer expect, with the "other" overflow bucket (if any)
// always last — mirrors internal/leaflib/solo/server.go's
// sortedAddressCounts exactly.
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
// zeros for an empty input — mirrors
// internal/leaflib/solo/server.go's minMaxMedian exactly.
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
