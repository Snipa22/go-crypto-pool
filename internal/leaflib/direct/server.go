// Copyright and license: see repository LICENSE (MIT).
//
// Package direct implements leaf-direct, go-crypto-pool's mode 1: the
// primary production ingest path. It speaks the exact same real
// Monero-family stratum wire protocol and validates shares/blocks with
// the exact same real per-algo validators as leaf-solo (mode 2), but
// forwards validated shares/blocks to the real backend via
// internal/leaflib/transport.ShareTransport instead of self-submitting
// to a single daemon.
//
// Two real capabilities exist here that neither leaf-solo nor the
// legacy nodejs-pool reference ever had (see Alex, 2026-08-22):
//
//  1. Direct parallel block submission to multiple configured GRPC
//     node addresses on a genuine block find, with "at least one
//     acceptance = success" semantics (multisubmit.go).
//  2. A generic, coin-agnostic NATS-based best-effort relay
//     broadcast/resubmit mechanism for found blocks
//     (internal/leaflib/relay), fully optional/no-op when
//     unconfigured and never blocking the primary path.
//
// What this package reuses AS-IS from the already-merged, read-only
// internal/leaflib/solo package (see AGENTS.md / this task's own
// explicit direction not to reinvent these): the wire protocol types
// (protocol.go: Request/LoginRequest/SubmitRequest/JobPush/
// ShareResponse/JobPayload), the JobManager/Job types and the
// NodeClient interface (this package supplies its OWN NodeClient
// implementation, node.go, backed by a real per-node-injectable GRPC
// client rather than the older package-level-singleton API — see that
// file's doc comment), internal/leaflib.ConnectionManager/
// ManagedConnection for miner connection lifecycle,
// internal/leaflib.VardiffConfig/ComputeRetarget for adaptive
// difficulty, and internal/leaflib/validator.Registry for real
// per-algo PoW validation.
package direct

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Server ties together internal/leaflib.ConnectionManager (miner
// connection lifecycle, reused as-is), a solo.JobManager (reused as-is
// — this package only supplies its own solo.NodeClient implementation,
// see node.go), a validator.Registry (reused as-is, real per-algo PoW
// checking), a transport.ShareTransport (the real, genuinely new
// wiring point vs. leaf-solo — every validated share/block goes here
// instead of a single self-submitted daemon), a MultiNodeSubmitter
// (real parallel multi-node GRPC block submission), and an optional
// *relay.Relay (best-effort NATS block broadcast/resubmit, no-op when
// unconfigured).
type Server struct {
	cm         *leaflib.ConnectionManager
	jobManager *solo.JobManager
	node       solo.NodeClient
	validators validator.Registry
	network    poolpb.Network
	logger     *log.Logger

	transport   transport.ShareTransport
	multiSubmit *MultiNodeSubmitter
	relay       *relay.Relay
	algo        poolpb.Algo
	poolType    poolpb.PoolType
	poolID      int32

	vardiff solo.VardiffConfig

	// trustConfig gates the real, legacy-ported probabilistic
	// RandomX-validation-skip mechanism for RXT/RXM shares (see
	// solo/trust.go). Zero-value TrustConfig{} (Enabled: false) is
	// the default — every share is always fully validated unless a
	// caller explicitly opts in via EnableTrust. UNLIKE solo (which
	// removed this mechanism entirely -- DISPATCH_BRIEF.md,
	// 2026-09-10, Fix 5 -- it was unreachable dead weight there post
	// solo's block-find-only validation change), leaf-direct still
	// validates EVERY RXT/RXM submit for real, so a ramped trust
	// state here is a genuinely live, real-money-relevant tradeoff:
	// see EnableTrust's own doc comment below for the explicit risk
	// framing an operator enabling this on leaf-direct should
	// understand before doing so.
	trustConfig solo.TrustConfig

	// invalidShareGuardConfig mirrors solo.Server's own identical
	// field exactly -- see leaflib.InvalidShareGuard's doc comment
	// for the full DISPATCH_BRIEF.md 2026-09-10 Fix 2b rationale.
	// Defaults to leaflib.DefaultInvalidShareGuardConfig() (enabled)
	// in NewServer; overridable via SetInvalidShareGuardConfig.
	invalidShareGuardConfig leaflib.InvalidShareGuardConfig

	// addressFlags mirrors solo.Server's own identical field exactly
	// -- see that field's doc comment. leaf-direct's Cache is fed by
	// a real backend poll (addressflags.HTTPSource) rather than
	// leaf-solo's local file (addressflags.FileSource) -- see
	// cmd/leaf-direct/main.go's wiring -- but the enforcement logic
	// in session.go's handleLogin/vardiff.go's maybeRetarget is
	// identical either way.
	addressFlags *addressflags.Cache

	mu       sync.RWMutex
	sessions map[uint64]*Session

	unsubscribe func()
	relayUnsub  func()

	metrics          *directmetrics.Metrics
	maxAddressLabels int

	// Backend-transport health tracking (statsui.go's Stats() reads
	// these) — leaf-direct's analogue of leaf-proxy's
	// UpstreamHealth: there is no persistent backend connection
	// object to type-assert against (transport.ShareTransport is a
	// stateless per-call interface, see internal/leaflib/transport),
	// so instead the last known real outcome (success or failure) of
	// forwardShare/forwardBlock is tracked directly here.
	transportOKSoFar    atomic.Bool // starts true: "no known failure yet"
	transportErrorTotal atomic.Uint64
	lastTransportKind   atomic.Value // string
	lastTransportAt     atomic.Value // time.Time

	// hideRemoteAddress mirrors internal/leaflib/solo/server.go's
	// identical field exactly — see that doc comment. Defaults to
	// false; set via SetHideRemoteAddress.
	hideRemoteAddress bool

	// randomxPool mirrors solo.Server's own identical field exactly —
	// see solo/asyncvalidation.go's package doc comment for the full
	// production incident/rationale. leaf-direct has the exact same
	// read-loop-blocking bug leaf-solo did (its own handleSubmit also
	// calls validator.RandomXValidator.Validate inline for RXT/RXM), so
	// it reuses solo's exported AsyncValidationPool rather than
	// duplicating the type.
	randomxPool *solo.AsyncValidationPool

	// forwardPool is Fix 12's (DISPATCH_BRIEF.md 2026-09-10) own
	// SEPARATE, dedicated worker pool for session.go's
	// forwardShare/forwardBlock backend-transport calls -- see those
	// methods' own doc comments and defaultForwardPoolWorkers' doc
	// comment for the full rationale. Deliberately NOT the same
	// randomxPool instance above: forwardShare/forwardBlock used to
	// run INSIDE finishSubmit, i.e. ON randomxPool's own worker
	// goroutines for RXT/RXM submits -- a slow-but-responding backend
	// (up to forwardShare's 5s/forwardBlock's 10s timeout) tied up
	// one of randomxPool's small, fixed number of workers for that
	// entire span, degrading process-wide RXT/RXM validation
	// throughput for every OTHER session's shares while it waited.
	// Dispatching these calls onto this leaf pool instead means a
	// slow backend can only ever saturate ITS OWN bounded pool, never
	// borrow capacity from (or block) real RandomX validation.
	// Reuses solo.AsyncValidationPool's exact same generic
	// closure-dispatching implementation (it has nothing
	// RandomX-specific in its actual mechanics, only in its doc
	// comments -- see that type's own doc comment) rather than
	// hand-rolling a second bounded-queue-plus-fixed-workers type for
	// what is structurally the identical shape.
	forwardPool *solo.AsyncValidationPool
}

// defaultForwardPoolWorkers/defaultForwardPoolQueueSize size Fix 12's
// forwardPool (DISPATCH_BRIEF.md 2026-09-10). Unlike randomxPool
// (CPU-bound RandomX hashing, sized to runtime.NumCPU() -- see
// solo/asyncvalidation.go), backend-forward calls are I/O-bound
// (a single outbound HTTP round-trip each, transport.ShareTransport),
// so scaling with host CPU count has no real justification here --
// what matters is bounding how many concurrent in-flight backend
// calls this leaf will ever make, independent of how many CPU cores
// happen to be available. 16 is a generous-but-bounded fixed
// concurrency limit for outbound HTTP calls to one backend (well
// beyond what a single backend endpoint needs to stay responsive
// under this leaf's own realistic accepted-share rate, while still
// bounding worst-case concurrent backend load to a small, fixed
// number regardless of miner count). AsyncValidationQueueSize (256)
// is reused unchanged for the queue bound, matching this codebase's
// existing "generous headroom for a burst, real backpressure once
// genuinely full" convention (see that constant's own doc comment).
const defaultForwardPoolWorkers = 16

// ServerConfig configures a Server.
type ServerConfig struct {
	ConnectionManager *leaflib.ConnectionManager
	JobManager        *solo.JobManager

	// Node is this leaf's coin-agnostic NodeClient, used by
	// session.go's handleSubmit to build the real, algo-appropriate
	// candidate block for a validated share (BuildCandidateBlock) —
	// see internal/leaflib/solo/node.go's NodeClient doc comment. This
	// is the SAME real NodeClient (this package's own node.go
	// implementation, backed by a real per-node-injectable GRPC
	// client) JobManager was constructed with as its own template
	// source — see cmd/leaf-direct/main.go's wiring. REQUIRED: a nil
	// Node means handleSubmit cannot construct a candidate block for
	// ANY submit, share or block-find alike.
	Node solo.NodeClient

	Validators validator.Registry
	Network    poolpb.Network
	Logger     *log.Logger
	Vardiff    solo.VardiffConfig

	// Transport is REQUIRED — this is leaf-direct's whole reason for
	// existing (forwarding validated shares/blocks to the real
	// backend). A nil Transport is accepted defensively (every
	// forward call is nil-safe — see session.go's forwardShare/
	// forwardBlock) but means shares/blocks are validated locally and
	// then silently dropped rather than reaching the backend at all;
	// callers should treat a nil Transport as a startup misconfiguration.
	Transport transport.ShareTransport

	// MultiSubmit is the real parallel-multi-node-GRPC-submit path for
	// a genuine block find (multisubmit.go). May be nil (a
	// misconfiguration — no configured submit nodes at all) in which
	// case every block find fails with success=false and an honest
	// "no configured submit nodes" result; construct via
	// NewMultiNodeSubmitter at startup with at least the primary node's
	// own address included (see cmd/leaf-direct/main.go).
	MultiSubmit *MultiNodeSubmitter

	// Relay is the optional best-effort NATS block-broadcast/resubmit
	// mechanism (internal/leaflib/relay). May be nil or a disabled
	// Relay (relay.NewRelay with an empty URL) — every call site is
	// nil/disabled-safe.
	Relay *relay.Relay

	// Algo is the single mining algorithm this Server's JobManager was
	// configured for (mirrors solo's own single-algo-per-process
	// model — see solo.JobManagerConfig.Algo's doc comment). Surfaced
	// on relay-published BlockMessage.Algo as a coin-agnostic string
	// label (see currentAlgoLabel).
	Algo poolpb.Algo

	// PoolType is the real, operator-configured pool payout model
	// (PPLNS/PPS/PROP/SOLO) stamped onto every real poolpb.Share/
	// poolpb.Block this leaf forwards to the backend (see
	// session.go's forwardShare/forwardBlock and handleSubmit's share
	// construction switch). REQUIRED and validated non-UNSPECIFIED by
	// the caller (cmd/leaf-direct/main.go) at startup -- the backend's
	// own real validation (internal/backend/api/api.go) correctly
	// rejects any Share/Block with PoolType left at its zero value
	// (poolpb.PoolType_POOL_TYPE_UNSPECIFIED) with a 400
	// "pool_type is required", since there is no safe silent default
	// for something that determines real payout accounting semantics.
	PoolType poolpb.PoolType

	// PoolID is the real, operator-assigned static integer identifying
	// this leaf-direct process's pool-server source (see
	// internal/proto/share.proto's Share.pool_id doc comment for the
	// full rationale/history). Stamped onto every real poolpb.Share/
	// poolpb.Block this leaf forwards to the backend (see session.go's
	// handleSubmit share-construction switch and forwardBlock),
	// unconditionally. Set at startup from cmd/leaf-direct's own
	// -pool-id/LEAF_DIRECT_POOL_ID flag.
	PoolID int32
}

// NewServer constructs a Server.
func NewServer(cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		cm: cfg.ConnectionManager, jobManager: cfg.JobManager, node: cfg.Node,
		vardiff:          cfg.Vardiff.Normalized(),
		sessions:         make(map[uint64]*Session),
		maxAddressLabels: directmetrics.DefaultMaxAddressLabels,
		validators:       cfg.Validators, network: cfg.Network, logger: logger,
		transport: cfg.Transport, multiSubmit: cfg.MultiSubmit, relay: cfg.Relay, algo: cfg.Algo,
		poolType: cfg.PoolType, poolID: cfg.PoolID,
		invalidShareGuardConfig: leaflib.DefaultInvalidShareGuardConfig(),
		// workers=0 lets NewAsyncValidationPool apply its own default
		// (DefaultAsyncValidationWorkers() == runtime.NumCPU(), NOT a
		// hardcoded literal -- see solo/asyncvalidation.go's doc
		// comment and Alex's explicit direction in
		// DISPATCH_BRIEF.md, 2026-09-10). An operator wanting a
		// different fixed count can override via
		// SetRandomXWorkerPoolSize (see cmd/leaf-direct's
		// -randomx-workers flag) before Serve begins.
		randomxPool: solo.NewAsyncValidationPool(0, solo.AsyncValidationQueueSize),
		// Fix 12 (DISPATCH_BRIEF.md 2026-09-10): a separate, dedicated
		// pool for forwardShare/forwardBlock -- see forwardPool's own
		// doc comment and defaultForwardPoolWorkers' doc comment for
		// the full rationale/sizing.
		forwardPool: solo.NewAsyncValidationPool(defaultForwardPoolWorkers, solo.AsyncValidationQueueSize),
	}
	s.transportOKSoFar.Store(true)
	if cfg.JobManager != nil {
		s.unsubscribe = cfg.JobManager.Subscribe(s.invalidateAndRepushJobs)
	}
	if s.relay != nil {
		unsub, err := s.relay.Subscribe(s.handleRelayedBlock)
		if err != nil {
			logger.Printf("direct: relay subscribe failed (relay resubmission disabled, primary path unaffected): %v", err)
		}
		s.relayUnsub = unsub
	}
	return s
}

// EnableMetrics constructs a *directmetrics.Metrics wired to this
// Server's live session state, mirroring solo.Server.EnableMetrics'
// exact conventions (private registry, cardinality-bounded per-address
// counts).
func (s *Server) EnableMetrics(version string, maxAddressLabels int) *directmetrics.Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = directmetrics.DefaultMaxAddressLabels
	}
	m := directmetrics.New(version, maxAddressLabels)
	m.SetSnapshotSource(s.sessionSnapshots)
	// Fix 9 (DISPATCH_BRIEF.md 2026-09-10): mirrors
	// solo.Server.EnableMetrics' identical async-pool wiring exactly
	// -- read s.randomxPool at CALL time (not captured here), since
	// SetRandomXWorkerPoolSize may replace it before Serve begins.
	m.SetAsyncPoolSource(func() directmetrics.AsyncPoolStats {
		return directmetrics.AsyncPoolStats{
			QueueDepth:         s.randomxPool.QueueDepth(),
			InFlightWorkers:    s.randomxPool.InFlightWorkers(),
			SubmitBlockedTotal: s.randomxPool.SubmitBlockedTotal(),
		}
	})
	s.metrics = m
	s.maxAddressLabels = maxAddressLabels
	// Wire the real XNP-reservation-unavailable counter into this
	// server's own MoneroNodeClient, if that's what it's actually
	// running against -- mirrors solo.Server.EnableMetrics' identical
	// wiring exactly (both leaf-solo and leaf-direct share the SAME
	// solo.MoneroNodeClient implementation for -coin=monero).
	if mnc, ok := s.node.(*solo.MoneroNodeClient); ok {
		mnc.SetReservationUnavailableMetric(m.XNPReservationUnavailableTotal)
	}
	return m
}

// SetHideRemoteAddress mirrors internal/leaflib/solo/server.go's
// identical method exactly — see that doc comment.
func (s *Server) SetHideRemoteAddress(hide bool) {
	s.hideRemoteAddress = hide
}

// SetRandomXWorkerPoolSize mirrors solo.Server's own identical
// method exactly — see that method's doc comment.
func (s *Server) SetRandomXWorkerPoolSize(workers, queueSize int) {
	s.randomxPool.Stop()
	s.randomxPool = solo.NewAsyncValidationPool(workers, queueSize)
}

// SetForwardPoolSize replaces this Server's forwardPool (Fix 12,
// DISPATCH_BRIEF.md 2026-09-10) with a freshly constructed one sized
// to workers/queueSize -- mirrors SetRandomXWorkerPoolSize's exact
// same "stop the old one, construct a fresh one" pattern and
// pre-Serve-only calling convention. workers<=0 falls back to
// solo.DefaultAsyncValidationWorkers() (runtime.NumCPU()) via
// NewAsyncValidationPool's own fallback -- an operator who wants
// forwardPool's own, genuinely different (I/O-bound, not CPU-bound)
// sizing rationale honored instead should pass a positive workers
// value explicitly (see defaultForwardPoolWorkers' doc comment).
func (s *Server) SetForwardPoolSize(workers, queueSize int) {
	s.forwardPool.Stop()
	s.forwardPool = solo.NewAsyncValidationPool(workers, queueSize)
}

// SetInvalidShareGuardConfig mirrors solo.Server's own identical
// method exactly — see that method's doc comment and
// leaflib.InvalidShareGuard's package-level doc comment.
func (s *Server) SetInvalidShareGuardConfig(cfg leaflib.InvalidShareGuardConfig) {
	s.invalidShareGuardConfig = cfg.Normalized()
	s.invalidShareGuardConfig.Enabled = cfg.Enabled
}

// EnableTrust opts this server into the real, legacy-ported
// probabilistic RandomX-validation-skip mechanism for RXT/RXM shares
// (see solo/trust.go's doc comment for the full reference algorithm
// and citation) — mirrors solo.Server's own identical EnableTrust
// exactly (solo's own copy has since been removed entirely — see
// solo.Session.handleSubmit's DISPATCH_BRIEF doc comment,
// 2026-09-10, Fix 5 — but leaf-direct's is NOT vestigial: unlike
// solo, which only validates an RXT/RXM share for real at the rare
// block-find level, leaf-direct's own handleSubmit runs v.Validate
// for EVERY RXT/RXM submit, so this mechanism is a genuinely live,
// frequently-consulted skip here).
//
// REAL-MONEY RISK, SPELLED OUT EXPLICITLY (DISPATCH_BRIEF.md,
// 2026-09-10, Fix 5 — documentation-only; no behavior change to this
// method or trustConfig's wiring): unlike solo (no share table, no
// backend, no payouts — see solo's own corrected comment, Fix 4), a
// leaf-direct share that skips real validation here still reaches
// s.transport.SubmitShare and the real backend's payout accounting,
// entirely on the miner's own claimed value, with NO cryptographic
// re-check on this leaf. Combined with Fix 1's difficulty-floor
// check (session.go's handleSubmit, post-validate/post-skip) this is
// a materially SAFER combination than before this dispatch (a
// trusted-but-fabricated claim can no longer also slip under this
// job's own StaticDifficulty floor uncaught), but it is still a
// deliberate trust-for-throughput tradeoff, not a free feature: a
// sufficiently ramped-in, then-compromised or malicious miner can
// still have some fraction of its claims credited (and forwarded to
// the backend) without ever being cryptographically re-checked by
// THIS leaf, bounded only by TrustConfig.Min/256 in the steady state
// (see solo/trust.go's own doc comment for that exact, known,
// intentionally-not-"fixed" tradeoff). An operator enabling
// -trust-enabled on leaf-direct (see cmd/leaf-direct's own flag help
// text) should understand this is trading a real, if bounded,
// authenticity gap for reduced randomx-service load — not assume it
// is a strictly free optimization the way it might appear to be on
// leaf-solo (where it no longer even exists). Must be called before
// serving any connections to take effect for them — sessions capture
// s.trustConfig once, at newSession time.
func (s *Server) EnableTrust(cfg solo.TrustConfig) {
	s.trustConfig = cfg.Normalized()
	s.trustConfig.Enabled = cfg.Enabled
}

// EnableAddressFlags mirrors solo.Server's own identical method
// exactly -- see that method's doc comment.
func (s *Server) EnableAddressFlags(cache *addressflags.Cache) {
	s.addressFlags = cache
}

// MetricsHandler returns the Prometheus /metrics HTTP handler if
// EnableMetrics has been called, or a 404 handler otherwise.
func (s *Server) MetricsHandler() http.Handler {
	if s.metrics == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics not enabled", http.StatusNotFound)
		})
	}
	return s.metrics.Handler()
}

func (s *Server) sessionSnapshots() []directmetrics.SessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]directmetrics.SessionSnapshot, 0, len(s.sessions))
	for _, sess := range s.sessions {
		addr, _ := sess.address.Load().(string)
		agent, _ := sess.agent.Load().(string)
		out = append(out, directmetrics.SessionSnapshot{
			Address: addr, RemoteIP: directmetrics.RemoteIPOf(sess.mc.RemoteAddr()),
			Difficulty: sess.currentDifficulty.Load(),
			Agent:      agent,
			Hashrate:   leaflib.EstimateHashrateHz(sess.hashesAccumulated.Load(), sess.connectedAt),
		})
	}
	return out
}

func (s *Server) recordShare(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.SharesTotal.WithLabelValues(directmetrics.ResultLabel(accepted)).Inc()
}

func (s *Server) recordBlock(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.BlocksTotal.WithLabelValues(directmetrics.ResultLabel(accepted)).Inc()
}

func (s *Server) recordConnectionError(category string) {
	if s.metrics == nil {
		return
	}
	s.metrics.ConnectionErrorsTotal.WithLabelValues(category).Inc()
}

// recordTransportError tracks backend-forwarding failures (share/
// block), a genuinely new observability axis leaf-solo has no
// equivalent of (it never forwards anything to a backend). It also
// updates the live "is the last known real backend call succeeding"
// health state statsui.go's Stats() surfaces (leaf-direct's analogue
// of leaf-proxy's UpstreamHealth.Connected()).
func (s *Server) recordTransportError(kind string) {
	s.transportOKSoFar.Store(false)
	s.transportErrorTotal.Add(1)
	s.lastTransportKind.Store(kind)
	s.lastTransportAt.Store(time.Now())
	if s.metrics == nil {
		return
	}
	s.metrics.TransportErrorsTotal.WithLabelValues(kind).Inc()
}

// recordTransportSuccess marks a real successful backend forward
// (share/block), flipping the transport health state back to
// healthy — mirrors recordTransportError's bookkeeping without a
// counterpart Prometheus metric (a running success total is not
// currently exported; only the stats page shows it).
func (s *Server) recordTransportSuccess(kind string) {
	s.transportOKSoFar.Store(true)
	s.lastTransportKind.Store(kind)
	s.lastTransportAt.Store(time.Now())
}

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
			s.logger.Printf("direct: failed to regenerate job for session %s (xn %s) after cache invalidation: %v", sess.sessionID, sess.xn, err)
			continue
		}
		// BUG FIX (Alex, live production report: "we're sending
		// duplicate jobs down the wire to RXT") -- mirrors
		// solo.Server.invalidateAndRepushJobs' identical fix exactly;
		// see that function's doc comment and Session.alreadyDelivered
		// for the real legacy reference this ports.
		if sess.alreadyDelivered(job) {
			continue
		}
		sess.pushJob(job)
	}
}

// Serve accepts miner connections on ln, structurally identical to
// solo.Server.Serve.
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
	mc, err := s.cm.Accept(ctx, conn)
	if err != nil {
		if errors.Is(err, leaflib.ErrConnectionRejected) {
			s.recordConnectionError("rejected-by-gate")
		}
		return
	}

	session := newSession(mc, s, startingDifficulty)
	s.mu.Lock()
	s.sessions[mc.ID()] = session
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, mc.ID())
		s.mu.Unlock()
		_ = mc.Close("session ended")
	}()

	go session.runVardiffLoop(mc.Context())
	session.Run(mc.Context())
}

// submitBlockDirect is the real block-submission choke point every
// genuine find goes through (session.go's handleSubmit): parallel
// multi-node GRPC submission (s.multiSubmit) is the primary,
// authoritative outcome (its own "at least one acceptance = success"
// return value IS this method's return value); the NATS relay publish
// is a purely-secondary, best-effort side effect that can never affect
// the returned outcome, per this feature's explicit design constraint
// (see internal/leaflib/relay's doc comment).
func (s *Server) submitBlockDirect(ctx context.Context, block *tari_generated.Block) ([]NodeSubmitResult, bool) {
	var (
		results []NodeSubmitResult
		ok      bool
	)
	if s.multiSubmit != nil {
		results, ok = s.multiSubmit.SubmitBlock(ctx, block)
	} else {
		s.logger.Printf("direct: no MultiNodeSubmitter configured; block find cannot be submitted to any node")
	}

	// Best-effort NATS relay publish — never allowed to affect ok/
	// results above, and never allowed to block this call meaningfully
	// (relay.Publish itself has no long-blocking network wait; it is
	// fire-and-forget at the NATS client level — see that method's doc
	// comment).
	if s.relay != nil {
		hash, _ := blockHash(block)
		algo := s.currentAlgoLabel()
		data, err := marshalBlockForRelay(block)
		if err != nil {
			s.logger.Printf("direct: failed to marshal block for relay publish (non-fatal, primary submit unaffected): %v", err)
		} else {
			msg := relay.BlockMessage{
				Algo: algo, Network: networkLabel(s.network),
				Height: block.GetHeader().GetHeight(), Hash: hash, BlockData: data,
			}
			if err := s.relay.Publish(ctx, msg); err != nil {
				s.logger.Printf("direct: relay publish failed (non-fatal, primary submit unaffected): %v", err)
			}
		}
	}

	return results, ok
}

// currentAlgoLabel returns the JobManager's configured algo as the
// wire-style string label the relay message carries (coin-agnostic —
// see relay.BlockMessage's doc comment on why this is a plain string,
// not a poolpb.Algo import).
func (s *Server) currentAlgoLabel() string {
	return leaflib.AlgoWireName(s.algo)
}

func networkLabel(n poolpb.Network) string {
	if n == poolpb.Network_NETWORK_MAINNET {
		return "mainnet"
	}
	return "testnet"
}

// handleRelayedBlock is invoked (see NewServer's Subscribe call) when
// this Server's relay receives a found-block message from ANOTHER
// leaf-direct instance (relay.Relay.Subscribe already filters out this
// instance's own published messages and duplicate deliveries — see
// that method's doc comment). It attempts a real local resubmission
// via this Server's OWN configured multi-node submitter, exactly
// mirroring the point of the relay (helping a block found by a
// geographically-distant pool instance propagate faster via every
// subscriber's own network position).
func (s *Server) handleRelayedBlock(msg relay.BlockMessage) {
	if s.multiSubmit == nil {
		s.logger.Printf("direct: received relayed block (height=%d hash=%s) but no local MultiNodeSubmitter is configured; cannot resubmit", msg.Height, msg.Hash)
		return
	}
	block, err := unmarshalBlockFromRelay(msg.BlockData)
	if err != nil {
		s.logger.Printf("direct: failed to unmarshal relayed block payload (height=%d hash=%s): %v", msg.Height, msg.Hash, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results, ok := s.multiSubmit.SubmitBlock(ctx, block)
	s.logger.Printf("direct: relay-triggered local resubmission (height=%d hash=%s publisher=%s): success=%v results=%v", msg.Height, msg.Hash, msg.PublisherID, ok, results)
}

// marshalBlockForRelay serializes block into the coin-agnostic
// relay.BlockMessage.BlockData payload. For Tari, this is simply a
// real protobuf marshal of the already-built candidate block (the
// SAME tari_generated.Block that was/will be submitted directly via
// MultiNodeSubmitter) — a receiving leaf-direct instance's own
// unmarshalBlockFromRelay reverses this exactly, so relay-triggered
// resubmission submits the literal same block bytes the finding
// instance itself submitted.
func marshalBlockForRelay(block *tari_generated.Block) ([]byte, error) {
	return proto.Marshal(block)
}

// unmarshalBlockFromRelay reverses marshalBlockForRelay.
func unmarshalBlockFromRelay(data []byte) (*tari_generated.Block, error) {
	var block tari_generated.Block
	if err := proto.Unmarshal(data, &block); err != nil {
		return nil, err
	}
	return &block, nil
}

// Shutdown unsubscribes from job updates and the relay, closes the
// multi-node submitter's connections, and stops this Server's RandomX-
// family async validation worker pool (see solo.AsyncValidationPool.Stop --
// blocks until every in-flight validation finishes). It does not close the
// ConnectionManager, listener, or transport — callers own those
// lifecycles.
func (s *Server) Shutdown() {
	if s.unsubscribe != nil {
		s.unsubscribe()
	}
	if s.relayUnsub != nil {
		s.relayUnsub()
	}
	if s.multiSubmit != nil {
		_ = s.multiSubmit.Close()
	}
	if s.randomxPool != nil {
		s.randomxPool.Stop()
	}
	if s.forwardPool != nil {
		s.forwardPool.Stop()
	}
}
