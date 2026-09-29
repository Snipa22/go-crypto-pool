// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	mathrand "math/rand"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// proxyForcedTargetTimeSeconds is the hardcoded, UNCONDITIONAL vardiff
// share target time (seconds) forced onto any session detected as a
// proxy -- by agent string (IsXNPProxyAgent/IsGenericProxyAgent) or by
// the behavioral re-login signal (Session.reloginDetected) -- per
// BRIEF.md "Problem 2": a proxy aggregates many real miners' hashrate
// behind one session, so the server's ordinary single-miner-oriented
// default target time (VardiffConfig.TargetTime, default 30s) under-
// adjusts for it; 10s lets vardiff actually track a proxy's much
// larger, changing aggregate hashrate responsively. Deliberately NOT
// a config knob (Alex: "unconditionally") -- see session.go's
// handleLogin (the single call site that stores it onto
// Session.forcedTargetTime) and vardiff.go's maybeRetarget (the
// single call site that reads it in place of cfg.TargetTime).
const proxyForcedTargetTimeSeconds = 10

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
		interval = defaultVardiffConfig().RetargetInterval
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

// maybeRetarget is the per-tick body of runVardiffLoop: it returns
// immediately for a fixed-difficulty session (Session.fixedDiff -- see
// that field's doc comment), otherwise gates on
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
	// A session that requested (or was assigned) a FIXED difficulty at
	// login is NEVER retargeted, for the lifetime of the connection --
	// see Session.fixedDiff's own doc comment (session.go) for the
	// verbatim legacy retargetMiners citation (nodejs-pool-sxmr
	// lib/pool.js lines 227-236) this gate ports. Checked first,
	// before the connection-age gate and before any computeRetarget
	// work, so a fixed-difficulty session costs nothing per tick.
	//
	// An XNP-proxy-detected session that requested a "+<difficulty>"
	// suffix deliberately never reaches this gate as "fixed": it is
	// exempted from the pin at login time instead (handleLogin, via
	// LoginFields.XNPProxyExemptFromFixedDiffPin -- legacy's own
	// `proxyAddressList` clause of the very same retargetMiners
	// check), so it flows through the full retarget below like any
	// ordinary session.
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

	// BRIEF.md "proxy-aware vardiff target time": a detected-proxy
	// session's forcedTargetTime (session.go's handleLogin, 0 when
	// unset) always wins over the port tier's configured
	// cfg.TargetTime, unconditionally -- read BEFORE calling
	// computeRetarget so it feeds the SAME targetTime parameter
	// cfg.TargetTime would otherwise supply. This applies regardless
	// of cfg.MinDifficulty/cfg.MaxDifficulty/forcedMinDifficulty --
	// those clamps (immediately above/below) are completely
	// untouched; only the targetTime argument changes.
	targetTime := cfg.TargetTime
	if forced := s.forcedTargetTime.Load(); forced != 0 {
		targetTime = int(forced)
	}

	newDiff, changed := computeRetarget(curDiff, hashes, connSeconds, targetTime, minDiff, cfg.MaxDifficulty)
	s.server.debugLogger.Debugf("solo: vardiff check: session=%s xn=%s cur_diff=%d hashes=%d conn_seconds=%d changed=%v", s.sessionID, s.XN(), curDiff, hashes, connSeconds, changed)
	if !changed {
		return
	}

	s.currentDifficulty.Store(newDiff)

	job, err := s.server.jobManager.RestampDifficulty(context.Background(), s.XN(), newDiff)
	if err != nil {
		s.server.logger.Printf("solo: vardiff retarget for session %s (xn %s) failed to restamp job: %v", s.sessionID, s.XN(), err)
		return
	}
	s.server.logger.Printf("solo: vardiff retarget for session %s (xn %s): %d -> %d (hashes=%d, connSeconds=%d)", s.sessionID, s.XN(), curDiff, newDiff, hashes, connSeconds)
	s.pushJob(job)
}
