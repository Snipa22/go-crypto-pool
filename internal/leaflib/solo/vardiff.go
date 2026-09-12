// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// VardiffConfig and computeRetarget/defaultVardiffConfig are now thin
// aliases/wrappers over internal/leaflib.VardiffConfig/ComputeRetarget/
// DefaultVardiffConfig (EXTRACTED there so leaf-proxy, mode 3, can
// reuse the exact same retarget algorithm for its own downstream
// sessions instead of duplicating it — see leaflib/vardiff.go's doc
// comment for the full rationale). VardiffConfig is a genuine type
// alias (not a new defined type), so every exported method on
// leaflib.VardiffConfig (Normalized) is directly callable on a solo
// VardiffConfig value with no forwarding boilerplate needed for that
// one. This is a clean, behavior-preserving move: every existing
// solo test (vardiff_test.go) keeps referencing computeRetarget and
// VardiffConfig by these exact same in-package names, unmodified.
type VardiffConfig = leaflib.VardiffConfig

// defaultVardiffConfig delegates to leaflib.DefaultVardiffConfig.
func defaultVardiffConfig() VardiffConfig {
	return leaflib.DefaultVardiffConfig()
}

// computeRetarget delegates to leaflib.ComputeRetarget — see that
// function's doc comment for the full, numbered behavior contract
// (unchanged by this move, just relocated).
func computeRetarget(curDiff, hashes uint64, connSeconds, targetTime int, minDiff, maxDiff uint64) (newDiff uint64, changed bool) {
	return leaflib.ComputeRetarget(curDiff, hashes, connSeconds, targetTime, minDiff, maxDiff)
}

// runVardiffLoop is this session's own per-connection retarget timer,
// ported from go-tari-sha3x-solo-stratum's cron registration
// (`config.SystemCrons.AddCronJob("*/60 * * * * *", m.NewDiff)`) —
// EXCEPT that timer is scoped to THIS session's own connection
// lifetime context (ctx, which is mc.Context() — see server.go's
// handleConn, the exact hook internal/leaflib.ManagedConnection.Context
// documents for "per-connection periodic work" like a vardiff timer),
// not registered with any shared/global cron/scheduler. When ctx is
// cancelled (connection closes, for any reason), this goroutine exits
// and the ticker is stopped — no leak, no per-session state surviving
// past disconnect, no other session's timer affected.
//
// s.connectedAt is written once in newSession, strictly before this
// goroutine is started (see server.go's handleConn: `go
// session.runVardiffLoop(...)` is issued after newSession returns),
// so reading it here from this goroutine is safe without further
// synchronization (Go's memory model guarantees a happens-before edge
// across goroutine creation).
func (s *Session) runVardiffLoop(ctx context.Context) {
	interval := s.server.vardiff.RetargetInterval
	if interval <= 0 {
		interval = defaultVardiffConfig().RetargetInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.maybeRetarget()
		}
	}
}

// maybeRetarget is the per-tick body of runVardiffLoop: it gates on
// connection age (legacy's `getConnSeconds() < 60` check, generalized
// to the configured RetargetInterval), runs computeRetarget against
// this session's OWN currentDifficulty/hashesAccumulated/connectedAt
// (never any other session's state — this is the key per-session
// isolation property), and — only if the difficulty actually changed —
// updates s.currentDifficulty and pushes a freshly-restamped job to
// THIS session alone via s.pushJob (mirroring the legacy NewDiff's
// closing `m.SendNewJob(false)` call), never broadcasting to any other
// connected session.
func (s *Session) maybeRetarget() {
	cfg := s.server.vardiff
	connSeconds := int(time.Since(s.connectedAt).Seconds())
	if connSeconds < int(cfg.RetargetInterval.Seconds()) {
		return
	}

	curDiff := s.currentDifficulty.Load()
	hashes := s.hashesAccumulated.Load()

	// An operator-forced minimum difficulty (see session.go's
	// handleLogin and internal/leaflib/addressflags's package doc
	// comment) must never be undercut by a vardiff retarget for the
	// lifetime of this connection -- raising the effective floor here
	// to at least s.forcedMinDifficulty (0 when unset, a complete
	// no-op) is the ONLY change from the server's own configured
	// cfg.MinDifficulty; the ceiling (cfg.MaxDifficulty) and every
	// other part of the retarget algorithm are untouched.
	minDiff := cfg.MinDifficulty
	if floor := s.forcedMinDifficulty.Load(); floor > minDiff {
		minDiff = floor
	}

	newDiff, changed := computeRetarget(curDiff, hashes, connSeconds, cfg.TargetTime, minDiff, cfg.MaxDifficulty)
	s.server.debugLogger.Debugf("solo: vardiff check: session=%s xn=%s cur_diff=%d hashes=%d conn_seconds=%d changed=%v", s.sessionID, s.xn, curDiff, hashes, connSeconds, changed)
	if !changed {
		return
	}

	s.currentDifficulty.Store(newDiff)

	job, err := s.server.jobManager.RestampDifficulty(context.Background(), s.xn, newDiff)
	if err != nil {
		s.server.logger.Printf("solo: vardiff retarget for session %s (xn %s) failed to restamp job: %v", s.sessionID, s.xn, err)
		return
	}
	s.server.logger.Printf("solo: vardiff retarget for session %s (xn %s): %d -> %d (hashes=%d, connSeconds=%d)", s.sessionID, s.xn, curDiff, newDiff, hashes, connSeconds)
	s.pushJob(job)
}
