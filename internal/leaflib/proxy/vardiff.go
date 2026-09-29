// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	mathrand "math/rand"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// proxyForcedTargetTimeSeconds mirrors solo.proxyForcedTargetTimeSeconds
// exactly -- see that constant's own doc comment (internal/leaflib/
// solo/vardiff.go) for the full BRIEF.md "Problem 2" rationale.
// Deliberately duplicated per-package (not shared via leaflib),
// matching this repo's existing convention of small per-package
// constants that happen to share a value/name across all three leaf
// flavors (e.g. defaultSessionJobHistorySize/
// defaultProxySessionJobHistorySize) rather than always factoring
// every such constant into leaflib.
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

// runVardiffLoop/maybeRetarget are leaf-proxy's downstream-session
// counterpart to internal/leaflib/solo/vardiff.go's identically-named
// methods — REUSING the exact same shared algorithm
// (leaflib.ComputeRetarget, extracted from solo specifically so this
// package could reuse it — see leaflib/vardiff.go's doc comment)
// rather than re-implementing the retarget math. Scoped to this
// session's own connection lifetime context exactly like solo's
// version (no shared/global scheduler — bug class 5 from leaflib.go's
// doc comment, avoided here the same way).
//
// Before starting the ticker, this waits out a random ONE-TIME
// initial jitter delay uniformly distributed across the FULL interval
// window (vardiffJitterFunc above) -- this permanently desynchronizes
// this session's retarget PHASE from every other session that
// happened to start at the same instant (e.g. thousands of miners
// reconnecting within the same few seconds during a cutover), fixing
// the resulting thundering-herd retarget wave forever, not just for
// the first retarget: a time.Ticker's subsequent ticks stay offset by
// whatever phase its first tick landed on, so only this one-time
// delay is needed. Every SUBSEQUENT retarget still respects the exact
// configured interval unchanged -- only the ABSOLUTE WALL-CLOCK
// MOMENT this session's cycle lands on is randomized, not its real
// per-session cadence.
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

func (s *Session) maybeRetarget() {
	// A session that requested (or was assigned) a FIXED difficulty at
	// login is NEVER retargeted, for the lifetime of the connection --
	// mirrors solo.Session.maybeRetarget's/direct.Session.maybeRetarget's
	// identical gate exactly. See solo.Session.fixedDiff's doc comment
	// for the verbatim legacy retargetMiners citation
	// (nodejs-pool-sxmr lib/pool.js lines 227-236) this ports.
	// Checked first, before the connection-age gate and before any
	// ComputeRetarget work, so a fixed-difficulty session costs
	// nothing per tick.
	//
	// An XNP-proxy-detected session that requested a "+<difficulty>"
	// suffix deliberately never reaches this gate as "fixed": it is
	// exempted from the pin at login time instead (session.go's
	// handleLogin, via solo.LoginFields.XNPProxyExemptFromFixedDiffPin
	// -- legacy's own `proxyAddressList` clause of this very same
	// retargetMiners check), so it flows through the full retarget
	// below like any ordinary session. That matters more for THIS leaf
	// mode than for leaf-solo/leaf-direct: a nested proxy in front of
	// leaf-proxy is aggregating hashrate that genuinely moves.
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

	// Fix 7 (DISPATCH_BRIEF.md 2026-09-10): an operator-forced
	// minimum difficulty (see session.go's handleLogin and
	// internal/leaflib/addressflags's package doc comment) must
	// never be undercut by a vardiff retarget for the lifetime of
	// this connection -- mirrors solo.Session.maybeRetarget's
	// identical floor-raising logic exactly. 0 (the overwhelmingly
	// common case) is a complete no-op.
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
	s.server.debugLogger.Debugf("proxy: vardiff check: session=%s cur_diff=%d hashes=%d conn_seconds=%d changed=%v", s.sessionID, curDiff, hashes, connSeconds, changed)
	if !changed {
		return
	}

	s.currentDifficulty.Store(newDiff)

	// Routed through currentJob (session.go) rather than
	// s.server.jobs.NextJob directly -- see currentJob's own doc
	// comment. In practice this call will almost always mint a
	// genuinely fresh job anyway, since leaflib.ComputeRetarget only
	// reports changed=true when the difficulty genuinely changed
	// (matching XNP's own !miner.newDiff gate: a real retarget always
	// forces a new job) -- but going through currentJob here too
	// keeps a single, consistent code path across every production
	// job-issuance call site, at no cost.
	job, err := s.currentJob(newDiff)
	if err != nil {
		s.server.logger.Printf("proxy: vardiff retarget for session %s failed to build a new job: %v", s.sessionID, err)
		return
	}
	s.server.logger.Printf("proxy: vardiff retarget for session %s: %d -> %d (hashes=%d, connSeconds=%d)", s.sessionID, curDiff, newDiff, hashes, connSeconds)
	s.pushJob(job)
}
