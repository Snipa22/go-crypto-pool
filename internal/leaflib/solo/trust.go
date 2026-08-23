// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"crypto/rand"
	"sync"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// This file is a faithful, field-for-field and branch-for-branch port
// of nodejs-pool-sxmr's (Snipa22/nodejs-pool, lib/pool.js) real
// "trusted miner" probabilistic RandomX-validation-skip mechanism —
// NOT a simplified reinvention. The real reference source (confirmed
// from the actual lib/pool.js in this session, not guessed/summarized)
// is reproduced/cited inline below at each corresponding point.
//
// Reference source, lib/pool.js:
//
//	// Miner() constructor:
//	if (global.config.pool.trustedMiners) {
//	    this.trust = {
//	        threshold: global.config.pool.trustThreshold,
//	        probability: 256,
//	        penalty: 0
//	    };
//	}
//
//	// processShare(), the actual skip decision:
//	if (global.config.pool.trustedMiners && miner.trust.threshold <= 0 && miner.trust.penalty <= 0 &&
//	    crypto.randomBytes(1).readUIntBE(0, 1) > miner.trust.probability) {
//	    hash = new Buffer(resultHash, 'hex');   // <- the miner's OWN claimed hash is taken on faith
//	    shareType = true;                        // <- "trusted" share: no real hashing happened
//	}
//	else {
//	    // ... real multiHashing.randomx(...) / cryptonight(...) call, shareType = false
//	}
//
//	// handleMinerData(), the post-outcome trust-state update, run on
//	// EVERY submit (trusted-skip or fully-validated alike) whenever
//	// global.config.pool.trustedMiners is enabled:
//	if (global.config.pool.trustedMiners) {
//	    if (shareAccepted) {
//	        miner.trust.probability -= global.config.pool.trustChange;
//	        if (miner.trust.probability < (global.config.pool.trustMin)) {
//	            miner.trust.probability = global.config.pool.trustMin;
//	        }
//	        miner.trust.penalty--;
//	        miner.trust.threshold--;
//	    }
//	    else {
//	        console.log(threadName + "Share trust broken by " + miner.logString);
//	        global.database.storeInvalidShare(miner.invalidShareProto);
//	        miner.trust.probability = 256;
//	        miner.trust.penalty = global.config.pool.trustPenalty;
//	        miner.trust.threshold = global.config.pool.trustThreshold;
//	    }
//	}
//
// State-machine semantics, spelled out (this is the real behavior the
// Go port below reproduces exactly, not an approximation):
//
//   - trust.threshold counts DOWN from trustThreshold to (and below)
//     zero, decremented once per ACCEPTED share. Skipping is only even
//     considered once threshold <= 0 — i.e. a miner must first submit
//     trustThreshold real, fully-validated accepted shares before it
//     becomes eligible for ANY validation skip at all.
//   - trust.penalty works identically but is reset to trustPenalty
//     (not trustThreshold) whenever trust is broken by a rejected
//     share — a SEPARATE "serve this many good shares first" gate a
//     miner must also clear again after breaking trust, on top of
//     threshold.
//   - trust.probability starts at 256 (no chance of a random byte in
//     [0,255] exceeding it — see the comparison below — so the skip
//     is effectively impossible until it has ramped down) and is
//     decremented by trustChange on every accepted share, floored at
//     trustMin so full validation never stops occurring entirely once
//     ramped in. It is unconditionally reset to 256 the instant a
//     share is rejected (trust immediately and completely revoked).
//   - The actual per-share coin flip: draw ONE real random byte
//     (crypto.randomBytes(1), 0-255 inclusive) and skip full
//     validation IFF that byte is STRICTLY GREATER than
//     trust.probability. Since probability only ever decreases (down
//     to the trustMin floor), the skip probability only ever
//     increases as a miner keeps submitting good shares, and instantly
//     collapses back to (near-)zero the moment trust breaks.
//
// This mechanism is deliberately probabilistic/thresholded, not a
// flat "skip after N good shares forever" rule — see the real-world
// caveat the pool operator community raised about it (a malicious
// miner CAN still get some fraction of bad shares through
// undetected on average, bounded by trustMin/256 in the steady
// state — see https://www.reddit.com/r/MoneroMining/comments/bm7jku/,
// which confirms this exact trustMin-bounded-fraction analysis
// against a real deployment). Faithfully porting that includes
// faithfully porting that known tradeoff — this is not something the
// Go port is expected or intended to "fix".

// TrustConfig configures the trust-ramp state machine (TrustConfig
// field names intentionally mirror the real
// global.config.pool.trust* keys 1:1, right down to the "trust" name
// prefix, so anyone who has operated the legacy nodejs-pool-sxmr
// stack recognizes them immediately):
//
//   - Enabled mirrors global.config.pool.trustedMiners: the master
//     on/off switch. When false, ShouldSkipValidation always returns
//     false and RecordOutcome is a no-op — every RXT/RXM share is
//     always fully, cryptographically validated, exactly like every
//     other algo, with zero behavior change from before this file
//     existed.
//   - Threshold mirrors global.config.pool.trustThreshold.
//   - Penalty mirrors global.config.pool.trustPenalty.
//   - Change mirrors global.config.pool.trustChange.
//   - Min mirrors global.config.pool.trustMin.
type TrustConfig struct {
	Enabled   bool
	Threshold int
	Penalty   int
	Change    int
	Min       int
}

// Default trust-ramp parameters, applied by Normalized when Enabled
// is true but a zero/unset field was supplied. The real nodejs-pool-
// sxmr stack sourced these four values from a per-pool-operator MySQL
// `config` table (populated via its admin web panel), NOT a static
// checked-in config file — there is no single canonical hardcoded
// default to port byte-for-byte the way createTariMiningBlob's fixed
// byte layout could be. These specific numbers are the same values
// widely documented across the broader zone117x-lineage cryptonote
// pool family this codebase is descended from (dvandal/
// cryptonote-nodejs-pool's shipped example config.json shareTrust
// block uses threshold=10/penalty=30 for the equivalent gates, and a
// contemporaneous community report on THIS EXACT nodejs-pool-sxmr
// trust mechanism — see the Reddit thread cited above — explicitly
// discusses trustMin=20 as "the default"), so they are used here as
// this Go port's own defaults rather than inventing arbitrary
// numbers. Every field remains fully operator-overridable (see
// cmd/leaf-solo, cmd/leaf-direct flags) exactly like the legacy admin
// panel allowed.
const (
	defaultTrustThreshold = 10
	defaultTrustPenalty   = 30
	defaultTrustChange    = 1
	defaultTrustMin       = 20
)

// Normalized returns c with any zero/unset numeric field replaced by
// its documented default (see the const block above). Enabled is
// passed through untouched (false stays false — there is no sane
// "default" for a boolean feature switch; callers must opt in
// explicitly). Mirrors the Normalized() convention already
// established by VardiffConfig in this package.
func (c TrustConfig) Normalized() TrustConfig {
	if c.Threshold <= 0 {
		c.Threshold = defaultTrustThreshold
	}
	if c.Penalty <= 0 {
		c.Penalty = defaultTrustPenalty
	}
	if c.Change <= 0 {
		c.Change = defaultTrustChange
	}
	if c.Min <= 0 {
		c.Min = defaultTrustMin
	}
	return c
}

// trustProbabilityStart mirrors the real Miner() constructor's
// hardcoded `probability: 256` initial value exactly — NOT derived
// from any TrustConfig field, because the real reference code never
// makes this configurable either (only threshold/probability's floor/
// probability's decrement/penalty are operator-configurable; the
// starting value of 256 is a literal in pool.js itself).
const trustProbabilityStart = 256

// MinerTrust is the real, per-session trust-ramp state, ported
// field-for-field from nodejs-pool-sxmr's Miner.trust object
// (`this.trust = {threshold, probability: 256, penalty: 0}`). One
// MinerTrust exists per Session for the lifetime of that miner
// connection — exactly like the legacy reference's per-Miner trust
// object, which is never shared across miners and never persisted
// across a reconnect (a fresh login gets a fresh threshold=
// trustThreshold/probability=256/penalty=0 state, same as the
// reference's fresh `this.trust = {...}` on every new Miner()).
//
// Safe for concurrent use — a real miner's submits are already
// serialized per-session by this package's read loop today, but
// MinerTrust does its own locking regardless so it carries no hidden
// single-goroutine assumption of its own.
type MinerTrust struct {
	mu  sync.Mutex
	cfg TrustConfig

	threshold   int
	probability int
	penalty     int
}

// NewMinerTrust constructs a MinerTrust in the real reference's exact
// initial state: threshold=cfg.Threshold, probability=256 (see
// trustProbabilityStart's doc comment), penalty=0. cfg is normalized
// (see TrustConfig.Normalized) before its Threshold/Penalty/Change/
// Min fields are read, but cfg.Enabled is preserved as given.
func NewMinerTrust(cfg TrustConfig) *MinerTrust {
	cfg = cfg.Normalized()
	return &MinerTrust{
		cfg:         cfg,
		threshold:   cfg.Threshold,
		probability: trustProbabilityStart,
		penalty:     0,
	}
}

// ShouldSkipValidation reports whether the share currently being
// processed should skip real cryptographic RandomX validation and be
// accepted purely on the miner's own claimed result — ported exactly
// from processShare's real gating condition:
//
//	miner.trust.threshold <= 0 && miner.trust.penalty <= 0 &&
//	    crypto.randomBytes(1).readUIntBE(0, 1) > miner.trust.probability
//
// A nil receiver or a config with Enabled == false always returns
// false (fully validate), which is the correct behavior for every
// non-RXT/RXM algo and for any RXT/RXM deployment that has not
// explicitly opted into trusted-miner mode — see this file's doc
// comment.
//
// If the real crypto/rand read fails (exceptionally rare — would
// indicate a broken system RNG), this fails CLOSED (returns false,
// i.e. always fully validates) rather than risk skipping validation
// on a byte that was never actually random — a deliberate, safety-
// biased divergence from the reference (which has no equivalent
// failure mode: Node's crypto.randomBytes throwing synchronously
// would simply crash that share's processing entirely).
func (t *MinerTrust) ShouldSkipValidation() bool {
	if t == nil || !t.cfg.Enabled {
		return false
	}

	t.mu.Lock()
	thresholdCleared := t.threshold <= 0
	penaltyCleared := t.penalty <= 0
	probability := t.probability
	t.mu.Unlock()

	if !thresholdCleared || !penaltyCleared {
		return false
	}

	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false
	}
	// crypto.randomBytes(1).readUIntBE(0, 1) yields an unsigned byte
	// in [0, 255], compared with real strict '>' against probability
	// — ported exactly, right down to the strictness (a probability
	// of 256 can never be exceeded by any byte in [0,255], which is
	// precisely why 256 is the real reference's chosen "never skip
	// yet" starting value).
	return int(b[0]) > probability
}

// RecordOutcome updates the trust-ramp state after a share's real
// accept/reject outcome is known, ported exactly from
// handleMinerData's post-processShare block (see this file's doc
// comment for the exact reference source). Must be called for EVERY
// submit this trust config applies to (trust-skipped or fully-
// validated alike) whenever the config is enabled — exactly like the
// reference, which runs this unconditionally on every submit once
// global.config.pool.trustedMiners is true, regardless of which
// branch of the if/else in processShare produced the outcome.
//
// A nil receiver or a config with Enabled == false is a no-op (no
// trust state to update).
func (t *MinerTrust) RecordOutcome(accepted bool) {
	if t == nil || !t.cfg.Enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if accepted {
		// miner.trust.probability -= global.config.pool.trustChange;
		// if (miner.trust.probability < (global.config.pool.trustMin)) {
		//     miner.trust.probability = global.config.pool.trustMin;
		// }
		t.probability -= t.cfg.Change
		if t.probability < t.cfg.Min {
			t.probability = t.cfg.Min
		}
		// miner.trust.penalty--;
		// miner.trust.threshold--;
		// Deliberately UNCLAMPED below zero — the real reference
		// never floors these at 0 either; ShouldSkipValidation's own
		// `<= 0` checks are what actually matter, and an
		// increasingly-negative threshold/penalty is harmless (it
		// just means "cleared this gate a while ago now").
		t.penalty--
		t.threshold--
	} else {
		// Share trust broken: unconditionally revert to "never skip
		// yet" (probability=256) and re-arm BOTH gates (penalty AND
		// threshold) back to their configured starting values —
		// ported exactly from the reference's else branch. A miner
		// must serve out max(Threshold, Penalty) further real,
		// fully-validated accepted shares (since ShouldSkipValidation
		// requires BOTH threshold<=0 AND penalty<=0) before it can
		// possibly skip validation again.
		t.probability = trustProbabilityStart
		t.penalty = t.cfg.Penalty
		t.threshold = t.cfg.Threshold
	}
}

// Snapshot is a point-in-time, read-only view of a MinerTrust's
// internal state, useful for diagnostics/tests without exposing the
// mutable fields directly (mirrors this package's existing snapshot-
// struct convention, e.g. metrics.SessionSnapshot).
type TrustSnapshot struct {
	Threshold   int
	Probability int
	Penalty     int
}

// Snapshot returns t's current state. Safe to call concurrently with
// ShouldSkipValidation/RecordOutcome. A nil receiver returns the
// zero TrustSnapshot.
func (t *MinerTrust) Snapshot() TrustSnapshot {
	if t == nil {
		return TrustSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return TrustSnapshot{Threshold: t.threshold, Probability: t.probability, Penalty: t.penalty}
}

// IsRandomXFamily reports whether algo is one of the two algos this
// trust mechanism applies to (RXT/RXM — the two RandomX-family algos
// where full validation is a real, service-backed RandomX hash that
// is genuinely expensive/latency-sensitive to skip probabilistically;
// SHA3X/C29 validation is cheap local computation with no analogous
// legacy trust mechanism in the reference, and are deliberately left
// untouched). Exported so internal/leaflib/direct's own handleSubmit
// can gate the identical real check without duplicating this list.
func IsRandomXFamily(algo poolpb.Algo) bool {
	return algo == poolpb.Algo_ALGO_RXT || algo == poolpb.Algo_ALGO_RXM
}
