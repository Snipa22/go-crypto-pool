// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// Server ties together internal/leaflib.ConnectionManager (downstream
// miner connection lifecycle — reused, not reimplemented), a
// JobManager (issuing per-session Jobs from the real upstream pool's
// current WorkerTemplate), a ShareValidator (real local RandomX
// re-validation — the already-merged, already-live-verified
// validator.RandomXValidator in production), and an UpstreamSubmitter
// (real forwarding of genuine block-level finds to the real upstream
// pool — UpstreamClient in production). This is leaf-proxy's entire
// vertical slice: mode 3 of the unified leaf/proxy/solo/direct
// architecture, the XMR-Node-Proxy-style AGGREGATING pattern — many
// real downstream miner connections behind ONE real upstream pool
// connection.
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
		cm:        cm,
		jobs:      jobs,
		validator: validator,
		upstream:  upstream,
		logger:    logger,
		vardiff:   vardiff.Normalized(),
		jobMaxAge: jobMaxAge,
		sessions:  make(map[uint64]*Session),
	}
	s.unsubscribe = jobs.Subscribe(s.repushAllSessions)
	return s
}

// repushAllSessions regenerates and pushes a fresh job to every
// currently-connected, logged-in downstream session, AT THAT
// SESSION'S OWN CURRENT VARDIFF DIFFICULTY — mirrors
// internal/leaflib/solo/server.go's invalidateAndRepushJobs exactly.
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
		job, err := s.jobs.NextJob(sess.currentDifficulty.Load())
		if err != nil {
			s.logger.Printf("proxy: failed to regenerate job for session %s after upstream template update: %v", sess.sessionID, err)
			continue
		}
		sess.pushJob(job)
	}
}

func (s *Server) recordShare(_ bool) {} // metrics hook placeholder — see cmd/leaf-proxy's doc comment on scope
func (s *Server) recordBlock(_ bool) {}

// Serve accepts downstream miner connections on ln until ctx is
// cancelled or ln is closed, stamping every session accepted on ln
// with startingDifficulty. Blocks; callers typically run it in its
// own goroutine.
func (s *Server) Serve(ctx context.Context, ln net.Listener, startingDifficulty uint64) error {
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
		go s.handleConn(ctx, conn, startingDifficulty)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn, startingDifficulty uint64) {
	mc, err := s.cm.Accept(ctx, conn)
	if err != nil {
		if !errors.Is(err, leaflib.ErrConnectionRejected) {
			s.logger.Printf("proxy: failed to accept downstream connection: %v", err)
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

// Shutdown unsubscribes from upstream job updates. It does not close
// the ConnectionManager or listener — callers own those lifecycles.
func (s *Server) Shutdown() {
	if s.unsubscribe != nil {
		s.unsubscribe()
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
