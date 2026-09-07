// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy/metrics"
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
	// identical field exactly — see that doc comment. Defaults to
	// false; set via SetHideRemoteAddress.
	hideRemoteAddress bool
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
		cm:               cm,
		jobs:             jobs,
		validator:        validator,
		upstream:         upstream,
		logger:           logger,
		vardiff:          vardiff.Normalized(),
		jobMaxAge:        jobMaxAge,
		sessions:         make(map[uint64]*Session),
		maxAddressLabels: metrics.DefaultMaxAddressLabels,
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
	s.metrics = m
	s.maxAddressLabels = maxAddressLabels
	return m
}

// SetHideRemoteAddress mirrors internal/leaflib/solo/server.go's
// identical method exactly — see that doc comment.
func (s *Server) SetHideRemoteAddress(hide bool) {
	s.hideRemoteAddress = hide
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
// own invalidateAndRepushJobs already are -- JobManager.NextJob always
// allocates a brand-new random job_id (newRandomHexID) plus fresh
// worker-/pool-nonces on EVERY call, so without this gate, every fire
// of jobs.Subscribe (which, prior to upstream.go's applyJob upstream-
// dupe guard, could itself fire on a genuine upstream no-op like a
// getjob poll response) handed every logged-in session a completely
// new, unrelated job_id -- evicting that session's own in-flight job
// out of its bounded jobHistorySize (defaultProxySessionJobHistorySize)
// before it could even be submitted. This is what produced the
// observed "unknown or stale job_id" rejections within tens of
// milliseconds of a job being issued. An explicit miner-initiated
// getjob/vardiff-retarget push is untouched by this gate -- it still
// always goes through pushJob/jobPayload unconditionally; the gate
// applies ONLY here, exactly mirroring direct/solo's own scoping.
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
		if sess.alreadyDelivered(job) {
			continue
		}
		sess.pushJob(job)
	}
}

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
		st.Sessions = append(st.Sessions, SessionStat{
			SessionID:         sess.sessionID,
			Address:           addr,
			Worker:            worker,
			RemoteAddr:        remoteAddr,
			ConnectedAt:       sess.connectedAt,
			CurrentDifficulty: diff,
			ShareCount:        sess.shareCount.Load(),
			BlockCount:        sess.blockCount.Load(),
		})
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
