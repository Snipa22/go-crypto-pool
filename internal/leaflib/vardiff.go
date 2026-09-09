// Copyright and license: see repository LICENSE (MIT).
package leaflib

import "math"
import "time"

// VardiffConfig and ComputeRetarget are the shared, algo/mode-agnostic
// per-session adaptive-difficulty-retargeting primitives, ported
// exactly from go-tari-sha3x-solo-stratum's subsystems/poolStratum/
// miner.go NewDiff() and the config it reads (subsystems/config/
// config.go's MinimumDifficulty/MaxDifficulty/TargetTime).
//
// EXTRACTED HERE (from internal/leaflib/solo/vardiff.go) so that
// leaf-proxy (mode 3, internal/leaflib/proxy) can reuse the exact same
// retarget algorithm for its downstream miner connections instead of
// duplicating it — per the architecture requirement that leaf-proxy
// reuse shared infra (ConnectionManager, protocol wire types, vardiff
// algorithm) rather than re-implementing it. internal/leaflib/solo's
// own VardiffConfig/computeRetarget are now thin aliases/wrappers over
// this package's exported versions (see solo/vardiff.go) so leaf-solo's
// own behavior and tests are completely unchanged by this move — this
// is a clean extraction, not a rewrite.
type VardiffConfig struct {
	// MinDifficulty is the absolute floor a retarget will never clamp
	// below.
	MinDifficulty uint64

	// MaxDifficulty is the absolute ceiling a retarget will never
	// clamp above.
	MaxDifficulty uint64

	// TargetTime is the number of seconds between shares the
	// retarget formula aims for (default 30).
	TargetTime int

	// RetargetInterval is how often each session's own retarget
	// timer fires. It also doubles as the minimum connection age
	// before a session's first-ever retarget runs.
	RetargetInterval time.Duration
}

// DefaultVardiffConfig mirrors go-tari-sha3x-solo-stratum's real
// defaults (config.TargetTime=30, the hardcoded 60s cron cadence) plus
// sane absolute bounds for MinDifficulty/MaxDifficulty when the caller
// leaves them at the zero value.
func DefaultVardiffConfig() VardiffConfig {
	return VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	}
}

// Normalized returns cfg with every zero-value field replaced by its
// default, so a caller that only cares about overriding e.g.
// RetargetInterval doesn't have to spell out every other field.
func (cfg VardiffConfig) Normalized() VardiffConfig {
	out := cfg
	def := DefaultVardiffConfig()
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

// ComputeRetarget is a pure, directly-unit-testable port of
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
// See the previous internal/leaflib/solo/vardiff.go (pre-extraction)
// for the full, numbered behavior contract this ports byte-for-byte;
// unchanged here, just relocated so leaf-proxy can call it too.
func ComputeRetarget(curDiff, hashes uint64, connSeconds, targetTime int, minDiff, maxDiff uint64) (newDiff uint64, changed bool) {
	if connSeconds <= 0 {
		return curDiff, false
	}

	var nd uint64
	if hashes > 0 {
		nd = (hashes / uint64(connSeconds)) * uint64(targetTime)
	} else {
		nd = uint64(float64(curDiff) * 0.9)
	}

	if nd > uint64(float64(curDiff)*0.95) && nd < uint64(float64(curDiff)*1.05) {
		return curDiff, false
	}

	if nd < uint64(float64(curDiff)*0.5) {
		nd = uint64(float64(curDiff) * 0.5)
	}
	if nd > uint64(float64(curDiff)*1.5) {
		nd = uint64(float64(curDiff) * 1.5)
	}

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

// EstimateHashrateHz estimates a session's real, per-session hashrate in
// hashes/second from its difficulty-weighted accept-history accumulator
// (hashesAccumulated — the same counter ComputeRetarget above consumes;
// see solo/session.go's Session.hashesAccumulated doc comment: the sum
// of job.StaticDifficulty over every share accepted so far, never reset
// for the life of the connection) and the connection's age (elapsed
// wall-clock time since connectedAt).
//
// hashesAccumulated is ALREADY a real, direct sum of per-share job
// difficulty values — it is not a raw hash-attempt count, and no
// further scaling (e.g. a 2^32-style difficulty-to-hash-attempts
// conversion) is applied here. This mirrors ComputeRetarget above,
// which treats hashesAccumulated/connSeconds as directly comparable to
// a difficulty value with no such multiplier; EstimateHashrateHz uses
// the exact same convention: hashesAccumulated/elapsed. A previous
// version of this function incorrectly multiplied by a 2^32 constant,
// producing wildly inflated (e+13-scale) hashrate figures — see the fix
// commit for the live diagnosis.
//
// Returns 0 for a session that has not yet been credited with any
// accepted-share difficulty, or whose connectedAt is in the future/now
// (guards a possible negative/zero elapsed duration rather than
// dividing by a non-positive number).
func EstimateHashrateHz(hashesAccumulated uint64, connectedAt time.Time) float64 {
	if hashesAccumulated == 0 {
		return 0
	}
	elapsed := time.Since(connectedAt).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(hashesAccumulated) / elapsed
}
