// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Server ties together internal/leaflib.ConnectionManager (miner
// connection lifecycle), a JobManager (real Tari base-node GRPC job
// pipeline), and a validator.AlgoValidator (real SHA3X PoW checking) —
// this is the entire leaf-solo vertical slice. There is deliberately no
// backend connection anywhere in this type.
type Server struct {
	cm         *leaflib.ConnectionManager
	jobManager *JobManager
	node       NodeClient
	validator  validator.AlgoValidator
	network    poolpb.Network
	logger     *log.Logger

	// startingDifficulty is the difficulty every newly-connected
	// session begins at (LEAF_SOLO_STARTING_DIFFICULTY). From that
	// point on, each session's own vardiff retarget loop (vardiff.go)
	// independently adjusts ITS difficulty based on its own accept
	// history — this field is never mutated after construction and is
	// only ever read once per new session (newSession, session.go).
	startingDifficulty uint64

	// vardiff configures the per-session adaptive retargeting
	// algorithm (see vardiff.go's VardiffConfig/computeRetarget) that
	// every session's own runVardiffLoop goroutine uses. Normalized
	// (zero fields replaced by sane defaults) once, in NewServer.
	vardiff VardiffConfig

	mu       sync.RWMutex
	sessions map[uint64]*Session

	unsubscribe func()
}

// NewServer constructs a Server. cm must already be configured with the
// desired MaxConnections/IdleTimeout (ManagerConfig) by the caller —
// solo's Server does not own ConnectionManager construction so callers
// keep full control of that already-merged, already-correct lifecycle
// policy. startingDifficulty is the difficulty every newly-connected
// session begins at; vardiff configures each session's own independent
// per-connection adaptive retargeting from that starting point (a
// zero-value VardiffConfig is normalized to sane defaults — see
// vardiff.go's defaultVardiffConfig).
func NewServer(cm *leaflib.ConnectionManager, jobManager *JobManager, node NodeClient, v validator.AlgoValidator, network poolpb.Network, logger *log.Logger, startingDifficulty uint64, vardiff VardiffConfig) *Server {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		cm:                 cm,
		jobManager:         jobManager,
		node:               node,
		validator:          v,
		network:            network,
		logger:             logger,
		startingDifficulty: startingDifficulty,
		vardiff:            vardiff.normalized(),
		sessions:           make(map[uint64]*Session),
	}
	s.unsubscribe = jobManager.Subscribe(s.invalidateAndRepushJobs)
	return s
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
		sess.pushJob(job)
	}
}

// Serve accepts miner connections on ln until ctx is cancelled or ln is
// closed. It blocks; callers typically run it in its own goroutine.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
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
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	mc, err := s.cm.Accept(ctx, conn)
	if err != nil {
		// Accept already closed conn on rejection (see
		// leaflib.ConnectionManager.Accept's doc comment).
		return
	}

	session := newSession(mc, s)
	s.mu.Lock()
	s.sessions[mc.ID()] = session
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, mc.ID())
		s.mu.Unlock()
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

// Shutdown unsubscribes from job updates. It does not close the
// ConnectionManager or listener — callers own those lifecycles.
func (s *Server) Shutdown() {
	if s.unsubscribe != nil {
		s.unsubscribe()
	}
}

// Stats is a point-in-time diagnostic snapshot, useful for logging /
// future metrics wiring. Solo mode has no share table, so this is the
// only visibility into share/block activity available locally.
type Stats struct {
	ActiveSessions int
	TotalShares    uint64
	TotalBlocks    uint64
}

// Stats returns a diagnostic snapshot across all currently-connected
// sessions.
func (s *Server) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{ActiveSessions: len(s.sessions)}
	for _, sess := range s.sessions {
		st.TotalShares += sess.shareCount.Load()
		st.TotalBlocks += sess.blockCount.Load()
	}
	return st
}
