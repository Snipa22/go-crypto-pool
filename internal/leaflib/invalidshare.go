// Copyright and license: see repository LICENSE (MIT).
package leaflib

import "sync/atomic"

// InvalidShareGuard implements the shared, per-session consecutive-
// invalid-share disconnect mechanism required by this repo's
// DISPATCH_BRIEF.md (2026-09-10, Fix 2b [HIGH — Finding 2]).
//
// THE PROBLEM THIS FIXES: solo/direct/proxy's async RandomX-family
// validation dispatch (asyncvalidation.go's AsyncValidationPool) lets
// a session submit a claim that numerically crosses the pool's own
// block-level (solo/direct) or upstream-forward (proxy) target
// WITHOUT yet knowing whether that claim is genuine — the real,
// expensive daemon-backed validation only happens after dispatch.
// Before this fix, a hostile session could submit an unbounded stream
// of FABRICATED above-target claims: each one is cheap for the
// attacker to construct (just numbers), but each one costs this
// leaf's own randomx-service/upstream-pool a real, non-trivial
// validation round-trip, with ZERO consequence to the submitting
// session when that validation (correctly) fails. That is a real
// resource-exhaustion vector against the shared async validation pool
// (a small, bounded, server-wide resource — see asyncvalidation.go's
// own doc comment) — a single abusive session could keep it
// permanently saturated with garbage, starving every OTHER session's
// genuine block-find-level submits of a worker.
//
// THE FIX (deliberately simple, per DISPATCH_BRIEF.md's own explicit
// scoping): track a running count of CONSECUTIVE invalid outcomes
// from a single session's own real-validation call sites (the
// `!valid` branch of solo/direct's finishSubmit, and proxy's
// equivalent handleSubmit branch — i.e. specifically the outcome of
// the real, expensive, async-dispatched validation, NOT the cheap
// pre-dispatch difficulty-derivation checks that never touch the pool
// at all). Once that count reaches cfg.Threshold, RecordOutcome
// reports true and the caller is expected to close the session's
// connection (see solo.Session.finishSubmit's own `!valid` branch for
// the real call site). This is a LOCAL, in-process disconnect only —
// it does NOT populate the persistent addressflags ban list (a
// separate, bigger feature, explicitly out of scope for this fix per
// DISPATCH_BRIEF.md: "Do NOT also implement: persistent cross-session
// banning via the addressflags file").
//
// Deliberately NOT the full ratio-based nodejs-pool-sxmr banPercent/
// banThreshold mechanism (lib/pool.js's Miner.checkBan, which compares
// invalidShares/validShares against a percentage once
// validShares+invalidShares crosses banThreshold) — DISPATCH_BRIEF.md
// explicitly permits "a per-session sliding-window or simple counter
// of consecutive/recent invalid shares" as sufficient for this fix,
// and a simple consecutive-run counter is both simpler to reason about
// and directly targets the actual reported vector (a SUSTAINED RUN of
// fabricated claims), without needing to also track a valid-share
// counter that has nothing to do with the abuse being mitigated here.
type InvalidShareGuard struct {
	cfg         InvalidShareGuardConfig
	consecutive atomic.Uint64
}

// InvalidShareGuardConfig configures an InvalidShareGuard.
type InvalidShareGuardConfig struct {
	// Enabled is the master on/off switch. When false,
	// (*InvalidShareGuard).RecordOutcome always returns false (never
	// signals a disconnect) and never allocates any real state --
	// identical to this mechanism not existing at all, mirroring this
	// codebase's existing EnableTrust/EnableMetrics "opt-in feature,
	// zero effect when unused" convention.
	Enabled bool

	// Threshold is how many CONSECUTIVE invalid outcomes (see this
	// type's own doc comment for exactly which call sites count) a
	// single session may accumulate before RecordOutcome reports that
	// it should be disconnected. A single intervening valid outcome
	// resets the count to zero (see RecordOutcome) -- this bounds a
	// SUSTAINED run of fabricated claims, not a single unlucky/flaky
	// rejection among otherwise-genuine submits.
	Threshold int
}

// defaultInvalidShareThreshold is this mechanism's default Threshold
// when Enabled is true but Threshold is left unset (<= 0). Chosen
// generously above what a single genuine, non-malicious block-race
// near-miss run could plausibly produce (a real miner's claims that
// happen to cross the block-level target but lose a real block race
// against another pool/miner are still cryptographically genuine, and
// so are never even counted as "invalid" by this mechanism at all --
// see this type's own doc comment: only a REAL validation FAILURE
// counts), while still bounding a hostile flood to a small, fixed
// number of wasted async-pool dispatches before disconnect.
const defaultInvalidShareThreshold = 20

// DefaultInvalidShareGuardConfig returns this mechanism's default
// configuration: enabled, with defaultInvalidShareThreshold.
// DISPATCH_BRIEF.md's Fix 2b treats this as a security-hardening
// default that should protect a deployment out of the box (unlike
// EnableTrust, an opt-in throughput/latency tradeoff with no sane
// "on by default" story) -- an operator who wants it disabled, or a
// different threshold, can still override via each leaf's own
// -invalid-share-disconnect-threshold flag (0 disables it entirely;
// see cmd/leaf-solo, cmd/leaf-direct, cmd/leaf-proxy).
func DefaultInvalidShareGuardConfig() InvalidShareGuardConfig {
	return InvalidShareGuardConfig{Enabled: true, Threshold: defaultInvalidShareThreshold}
}

// Normalized returns cfg with a non-positive Threshold replaced by
// defaultInvalidShareThreshold. Enabled is passed through untouched,
// mirroring TrustConfig.Normalized's identical convention.
func (cfg InvalidShareGuardConfig) Normalized() InvalidShareGuardConfig {
	if cfg.Threshold <= 0 {
		cfg.Threshold = defaultInvalidShareThreshold
	}
	return cfg
}

// NewInvalidShareGuard constructs an InvalidShareGuard from cfg (which
// is normalized internally -- see InvalidShareGuardConfig.Normalized).
func NewInvalidShareGuard(cfg InvalidShareGuardConfig) *InvalidShareGuard {
	return &InvalidShareGuard{cfg: cfg.Normalized()}
}

// RecordOutcome updates the running consecutive-invalid-outcome count
// for the real validation outcome just observed (accepted == true for
// a real, successfully-validated share; false for a real validation
// FAILURE at the call site this guard is wired into -- see this
// type's own doc comment for exactly which call sites that is). It
// returns true exactly once the running consecutive-invalid count
// reaches cfg.Threshold -- the caller is expected to disconnect the
// session at that point (the counter is deliberately NOT reset by
// RecordOutcome itself on the triggering call: a disconnected session
// is expected to be torn down immediately, not kept alive for further
// submits against the same guard).
//
// A nil receiver or a disabled config always returns false (this
// mechanism is a complete no-op then, mirroring solo.MinerTrust's own
// nil-safe convention).
func (g *InvalidShareGuard) RecordOutcome(accepted bool) bool {
	if g == nil || !g.cfg.Enabled {
		return false
	}
	if accepted {
		g.consecutive.Store(0)
		return false
	}
	return g.consecutive.Add(1) >= uint64(g.cfg.Threshold)
}

// Snapshot returns the current running consecutive-invalid count, for
// diagnostics/tests. A nil receiver returns 0.
func (g *InvalidShareGuard) Snapshot() uint64 {
	if g == nil {
		return 0
	}
	return g.consecutive.Load()
}
