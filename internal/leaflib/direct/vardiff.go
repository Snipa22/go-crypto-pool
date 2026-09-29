// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	mathrand "math/rand"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// proxyForcedTargetTimeSeconds mirrors solo.proxyForcedTargetTimeSeconds
// exactly -- see that constant's own doc comment (internal/leaflib/
// solo/vardiff.go) for the full BRIEF.md "Problem 2" rationale.
// Deliberately duplicated per-package, matching this repo's existing
// convention (see proxy/vardiff.go's identical constant/doc comment).
const proxyForcedTargetTimeSeconds = 10

// vardiffJitterFunc is a test-injectable seam over the one-time
// initial retarget-ticker jitter delay's random source below --
// mirrors this repo's existing test-injectable-randomness convention
// (see internal/backend/legacyapi's `nowUnix` package-level func-var
// seam) rather than inventing a new one. Production code always
// calls through this var; tests may substitute an instrumented/
// deterministic replacement.
//
// Uses math/rand, deliberately NOT crypto/rand: this jitter exists
// purely to desynchronize (load-shed) a thundering herd of
// simultaneous retargets, not to produce a security-sensitive value,
// so the faster, non-cryptographic PRNG is the correct tool here --
// do not "fix" this into an unnecessary crypto/rand dependency. Go
// 1.20+ auto-seeds math/rand's global source (this module's go.mod
// declares `go 1.25.0`, well past that threshold), so no explicit
// process-startup seeding call is required.
var vardiffJitterFunc = func(interval time.Duration) time.Duration {
	return time.Duration(mathrand.Int63n(int64(interval)))
}

// runVardiffLoop mirrors solo.Session's own runVardiffLoop exactly,
// reusing internal/leaflib.VardiffConfig/ComputeRetarget (the shared
// package extracted specifically so leaf-proxy and leaf-direct can
// both reuse the exact same retarget algorithm without duplicating
// it) via s.server.vardiff (a solo.VardiffConfig, itself a type alias
// for leaflib.VardiffConfig — see solo/vardiff.go).
//
// Before starting this session's ticker, it waits out a random
// ONE-TIME initial jitter delay uniformly distributed across the
// FULL interval window (vardiffJitterFunc above) -- this permanently
// desynchronizes this session's retarget PHASE from every other
// session that happened to start at the same instant (e.g. a
// mass-reconnect), fixing the thundering-herd retarget wave forever,
// not just for the first retarget: a time.Ticker's subsequent ticks
// stay offset by whatever phase its first tick landed on, so only
// this one-time delay is needed. Every SUBSEQUENT retarget still
// respects the exact configured interval unchanged (ticker.C fires
// every `interval`, exactly as before) -- only the ABSOLUTE
// WALL-CLOCK MOMENT this session's cycle lands on is randomized, not
// its real per-session cadence.
func (s *Session) runVardiffLoop(ctx context.Context) {
	interval := s.server.vardiff.RetargetInterval
	if interval <= 0 {
		interval = leaflib.DefaultVardiffConfig().RetargetInterval
	}

	jitter := vardiffJitterFunc(interval)
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
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

// maybeRetarget mirrors solo.Session's own maybeRetarget exactly,
// including its fixed-difficulty gate (Session.fixedDiff -- see
// solo.Session's own copy of that field for the verbatim legacy
// retargetMiners citation, and for the XNP-proxy escape hatch that
// keeps an aggregating proxy's "+<difficulty>"-suffixed session out of
// this gate entirely, applied at login time rather than here).
func (s *Session) maybeRetarget() {
	if s.fixedDiff.Load() {
		return
	}

	cfg := s.server.vardiff
	connSeconds := int(time.Since(s.connectedAt).Seconds())
	if connSeconds < int(cfg.RetargetInterval.Seconds()) {
		return
	}

	curDiff := s.currentDifficulty.Load()
	hashes := s.hashesAccumulated.Load()

	// Mirrors solo.Session's own maybeRetarget exactly -- see that
	// method's doc comment for the full rationale: an operator-forced
	// minimum difficulty must never be undercut by a vardiff
	// retarget.
	minDiff := cfg.MinDifficulty
	if floor := s.forcedMinDifficulty.Load(); floor > minDiff {
		minDiff = floor
	}

	// BRIEF.md "proxy-aware vardiff target time": mirrors
	// solo.Session.maybeRetarget's identical block exactly -- a
	// detected-proxy session's forcedTargetTime (0 when unset) always
	// wins over cfg.TargetTime, unconditionally.
	targetTime := cfg.TargetTime
	if forced := s.forcedTargetTime.Load(); forced != 0 {
		targetTime = int(forced)
	}

	newDiff, changed := leaflib.ComputeRetarget(curDiff, hashes, connSeconds, targetTime, minDiff, cfg.MaxDifficulty)
	s.server.debugLogger.Debugf("direct: vardiff check: session=%s xn=%s cur_diff=%d hashes=%d conn_seconds=%d changed=%v", s.sessionID, s.xn, curDiff, hashes, connSeconds, changed)
	if !changed {
		return
	}

	s.currentDifficulty.Store(newDiff)

	job, err := s.server.jobManager.RestampDifficulty(context.Background(), s.xn, newDiff)
	if err != nil {
		s.server.logger.Printf("direct: vardiff retarget for session %s (xn %s) failed to restamp job: %v", s.sessionID, s.xn, err)
		return
	}
	s.server.logger.Printf("direct: vardiff retarget for session %s (xn %s): %d -> %d (hashes=%d, connSeconds=%d)", s.sessionID, s.xn, curDiff, newDiff, hashes, connSeconds)
	s.pushJob(job)
}
