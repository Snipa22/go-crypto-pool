// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"math"
	"time"
)

// VardiffConfig configures per-session adaptive difficulty retargeting
// (vardiff), ported exactly from go-tari-sha3x-solo-stratum's
// subsystems/poolStratum/miner.go NewDiff() and the config it reads
// (subsystems/config/config.go's MinimumDifficulty/MaxDifficulty/
// TargetTime). Unlike the legacy code, RetargetInterval is a
// first-class, configurable field rather than a hardcoded cron string
// ("*/60 * * * * *") — see server.go/session.go for how it drives each
// session's own per-connection timer (runVardiffLoop below), not a
// shared/global scheduler.
type VardiffConfig struct {
	// MinDifficulty is the absolute floor a retarget will never clamp
	// below (go-tari-sha3x-solo-stratum's config.MinimumDifficulty).
	MinDifficulty uint64

	// MaxDifficulty is the absolute ceiling a retarget will never
	// clamp above (go-tari-sha3x-solo-stratum's config.MaxDifficulty).
	MaxDifficulty uint64

	// TargetTime is the number of seconds between shares the retarget
	// formula aims for (go-tari-sha3x-solo-stratum's
	// config.TargetTime, default 30).
	TargetTime int

	// RetargetInterval is how often each session's own retarget timer
	// fires (go-tari-sha3x-solo-stratum's hardcoded 60-second cron
	// cadence, made configurable here). It also doubles as the
	// minimum connection age before a session's first-ever retarget
	// runs (getConnSeconds() < 60 in the legacy code — here,
	// connSeconds < RetargetInterval.Seconds()).
	RetargetInterval time.Duration
}

// defaultVardiffConfig mirrors go-tari-sha3x-solo-stratum's real
// defaults (config.TargetTime=30, the hardcoded 60s cron cadence) plus
// sane absolute bounds for MinDifficulty/MaxDifficulty when the caller
// leaves them at the zero value.
func defaultVardiffConfig() VardiffConfig {
	return VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}
}

// normalized returns cfg with every zero-value field replaced by its
// default, so a caller that only cares about overriding e.g.
// RetargetInterval (as the smoke test does, for a fast demo) doesn't
// have to spell out every other field.
func (cfg VardiffConfig) normalized() VardiffConfig {
	out := cfg
	def := defaultVardiffConfig()
	if out.MinDifficulty == 0 {
		out.MinDifficulty = def.MinDifficulty
	}
	if out.MaxDifficulty == 0 {
		out.MaxDifficulty = def.MaxDifficulty
	}
	if out.TargetTime <= 0 {
		out.TargetTime = def.TargetTime
	}
	if out.RetargetInterval <= 0 {
		out.RetargetInterval = def.RetargetInterval
	}
	return out
}

// computeRetarget is a pure, directly-unit-testable port of
// go-tari-sha3x-solo-stratum's minerStruct.NewDiff (miner.go,
// ~line 287-326), minus the parts that are about I/O (mutex locking,
// SendNewJob, logging) rather than the actual math. Given:
//
//   - curDiff: the session's current share difficulty
//   - hashes: the session's difficulty-weighted accept-history
//     accumulator (minerStruct.hashes)
//   - connSeconds: seconds since the session connected
//     (minerStruct.getConnSeconds())
//   - targetTime: seconds between shares the formula aims for
//     (config.TargetTime)
//   - minDiff/maxDiff: absolute clamp bounds (config.MinimumDifficulty/
//     config.MaxDifficulty)
//
// it returns the new difficulty and whether it actually differs from
// curDiff (callers should treat changed=false as "do nothing", exactly
// like the legacy NewDiff's early `return` when the dead-zone check
// passes or the computed value collapses back to curDiff after
// clamping).
//
// Ported behavior, in order, exactly matching the legacy source:
//
//  1. Primary formula (at least one accepted share ever):
//     newDiff = (hashes / connSeconds) * targetTime
//     — integer division, exactly as the legacy Go code performs it
//     (uint64 / uint64), not floating point.
//  2. Fallback formula (zero accepted shares so far): a flat 10%
//     reduction from the current difficulty, to help a struggling/
//     slow miner settle in: newDiff = curDiff * 0.9.
//  3. Dead-zone: if newDiff is within ±5% of curDiff (strictly between
//     curDiff*0.95 and curDiff*1.05), no change — return curDiff,
//     false.
//  4. Step-size clamp: newDiff is clamped to [curDiff*0.5, curDiff*1.5]
//     — this happens even if step 1/2 wanted a bigger single-step
//     jump, and happens BEFORE the absolute clamp.
//  5. Absolute clamp: newDiff is floored to minDiff / ceilinged to
//     maxDiff.
//  6. If, after all of the above, newDiff == curDiff, report no
//     change (changed=false) rather than a no-op "change".
func computeRetarget(curDiff, hashes uint64, connSeconds, targetTime int, minDiff, maxDiff uint64) (newDiff uint64, changed bool) {
	if connSeconds <= 0 {
		// Guards against a division by zero; the caller (maybeRetarget)
		// already gates on connSeconds >= RetargetInterval before ever
		// calling this, so this only matters for direct unit tests
		// exercising the pure function with a degenerate input.
		return curDiff, false
	}

	var nd uint64
	if hashes > 0 {
		// Primary mechanism: average difficulty-weighted accept rate
		// per second, scaled to hit targetTime between shares.
		nd = (hashes / uint64(connSeconds)) * uint64(targetTime)
	} else {
		// Secondary mechanism: a 10% reduction from current to help a
		// miner that hasn't landed a single accepted share yet settle
		// into a workable difficulty.
		nd = uint64(float64(curDiff) * 0.9)
	}

	// Dead-zone: avoid needless job-churn for a negligible delta.
	if nd > uint64(float64(curDiff)*0.95) && nd < uint64(float64(curDiff)*1.05) {
		return curDiff, false
	}

	// Step-size clamp: never move more than 50% down or 50% up from
	// curDiff in a single retarget, regardless of how large the raw
	// computed value above was.
	if nd < uint64(float64(curDiff)*0.5) {
		nd = uint64(float64(curDiff) * 0.5)
	}
	if nd > uint64(float64(curDiff)*1.5) {
		nd = uint64(float64(curDiff) * 1.5)
	}

	// Absolute bounds clamp, applied AFTER the step-size clamp.
	if nd < minDiff {
		nd = minDiff
	} else if nd > maxDiff {
		nd = maxDiff
	}

	if nd == curDiff {
		return curDiff, false
	}
	return nd, true
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

	newDiff, changed := computeRetarget(curDiff, hashes, connSeconds, cfg.TargetTime, cfg.MinDifficulty, cfg.MaxDifficulty)
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
