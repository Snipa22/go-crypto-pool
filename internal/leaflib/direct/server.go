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

	vardiff solo.VardiffConfig

	// trustConfig gates the real, legacy-ported probabilistic
	// RandomX-validation-skip mechanism for RXT/RXM shares (see
	// solo/trust.go). Zero-value TrustConfig{} (Enabled: false) is
	// the default — every share is always fully validated unless a
	// caller explicitly opts in via EnableTrust.
	trustConfig solo.TrustConfig

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
}

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
		poolType: cfg.PoolType,
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
	s.metrics = m
	s.maxAddressLabels = maxAddressLabels
	return m
}

// EnableTrust opts this server into the real, legacy-ported
// probabilistic RandomX-validation-skip mechanism for RXT/RXM shares
// (see solo/trust.go's doc comment for the full reference algorithm
// and citation) — mirrors solo.Server's own identical EnableTrust
// exactly. Must be called before serving any connections to take
// effect for them — sessions capture s.trustConfig once, at
// newSession time.
func (s *Server) EnableTrust(cfg solo.TrustConfig) {
	s.trustConfig = cfg.Normalized()
	s.trustConfig.Enabled = cfg.Enabled
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
	return algoWireName(s.algo)
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

// Shutdown unsubscribes from job updates and the relay, and closes the
// multi-node submitter's connections. It does not close the
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
}
