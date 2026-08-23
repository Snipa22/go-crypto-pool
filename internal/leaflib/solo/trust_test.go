// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

func TestTrustConfigNormalizedAppliesDefaults(t *testing.T) {
	c := TrustConfig{Enabled: true}.Normalized()
	if c.Threshold != defaultTrustThreshold {
		t.Errorf("Threshold = %d, want %d", c.Threshold, defaultTrustThreshold)
	}
	if c.Penalty != defaultTrustPenalty {
		t.Errorf("Penalty = %d, want %d", c.Penalty, defaultTrustPenalty)
	}
	if c.Change != defaultTrustChange {
		t.Errorf("Change = %d, want %d", c.Change, defaultTrustChange)
	}
	if c.Min != defaultTrustMin {
		t.Errorf("Min = %d, want %d", c.Min, defaultTrustMin)
	}
	if !c.Enabled {
		t.Error("Enabled should be preserved as true")
	}

	// Explicit non-zero values must NOT be overridden.
	explicit := TrustConfig{Enabled: true, Threshold: 5, Penalty: 7, Change: 2, Min: 3}.Normalized()
	if explicit.Threshold != 5 || explicit.Penalty != 7 || explicit.Change != 2 || explicit.Min != 3 {
		t.Errorf("Normalized clobbered explicit values: %+v", explicit)
	}
}

func TestMinerTrustDisabledAlwaysFullyValidates(t *testing.T) {
	// Zero-value TrustConfig (Enabled: false) — nil-equivalent path.
	var trust *MinerTrust
	if trust.ShouldSkipValidation() {
		t.Error("nil MinerTrust must never skip validation")
	}
	trust.RecordOutcome(true) // must not panic

	disabled := NewMinerTrust(TrustConfig{Enabled: false})
	for i := 0; i < 1000; i++ {
		if disabled.ShouldSkipValidation() {
			t.Fatal("disabled MinerTrust must never skip validation")
		}
		disabled.RecordOutcome(true)
	}
}

func TestMinerTrustNeverSkipsBeforeThresholdCleared(t *testing.T) {
	// penalty starts at 0 (already <= 0) per the real reference's
	// Miner() constructor -- only threshold gates an initial ramp-in;
	// penalty only becomes a live gate again after a rejection resets
	// it to cfg.Penalty. Use a real Threshold high enough, and enough
	// accepts, to genuinely exhaust Change's floor at Min.
	cfg := TrustConfig{Enabled: true, Threshold: 5, Penalty: 3, Change: 50, Min: 1}
	trust := NewMinerTrust(cfg)

	for i := 0; i < 4; i++ {
		if trust.ShouldSkipValidation() {
			t.Fatalf("skip should be impossible before threshold clears (iteration %d)", i)
		}
		trust.RecordOutcome(true)
	}
	snap := trust.Snapshot()
	if snap.Threshold != 1 {
		t.Fatalf("threshold = %d, want 1 after 4 accepts from 5", snap.Threshold)
	}
	// Still must not skip: threshold is 1, not yet <= 0 (even though
	// penalty has been <= 0 the entire time, per the real semantics).
	if trust.ShouldSkipValidation() {
		t.Fatal("skip must remain impossible until threshold <= 0")
	}
}

func TestMinerTrustRampsInAndCanSkipOnceBothGatesClear(t *testing.T) {
	// penalty starts at 0 (already <= 0) -- so only threshold needs
	// to reach <= 0 for the FIRST ramp-in (penalty only becomes a
	// live, non-trivial gate again after an actual rejection). Min=1
	// means probability floors at 1 after enough large decrements,
	// making a skip overwhelmingly likely (254/256 odds per attempt).
	cfg := TrustConfig{Enabled: true, Threshold: 1, Penalty: 2, Change: 300, Min: 1}
	trust := NewMinerTrust(cfg)

	if trust.ShouldSkipValidation() {
		t.Fatal("skip should be impossible before any accept: threshold not yet <= 0")
	}
	trust.RecordOutcome(true) // threshold=0, penalty=-1, probability=1 (floored)
	snap := trust.Snapshot()
	if snap.Threshold != 0 {
		t.Fatalf("threshold = %d, want 0 after 1 accept from Threshold=1", snap.Threshold)
	}
	if snap.Probability != 1 {
		t.Fatalf("probability = %d, want 1 (floored at Min=1)", snap.Probability)
	}
	// Both gates now cleared (threshold=0, penalty=-1) AND
	// probability=1 -> any random byte in [2,255] (254/256 odds) is
	// > 1, so this must skip virtually certainly within a handful of
	// tries.
	skippedAtLeastOnce := false
	for i := 0; i < 20; i++ {
		if trust.ShouldSkipValidation() {
			skippedAtLeastOnce = true
			break
		}
	}
	if !skippedAtLeastOnce {
		t.Fatal("expected a near-certain skip once probability=1 and both gates cleared")
	}
}

func TestMinerTrustRejectFullyRevokesTrust(t *testing.T) {
	cfg := TrustConfig{Enabled: true, Threshold: 2, Penalty: 2, Change: 300, Min: 0}
	trust := NewMinerTrust(cfg)
	trust.RecordOutcome(true)
	trust.RecordOutcome(true) // now fully ramped in, threshold=0 penalty=0 probability=0

	trust.RecordOutcome(false) // real trust break

	snap := trust.Snapshot()
	if snap.Threshold != cfg.Threshold {
		t.Errorf("threshold = %d, want reset to %d after a rejected share", snap.Threshold, cfg.Threshold)
	}
	if snap.Penalty != cfg.Penalty {
		t.Errorf("penalty = %d, want reset to %d after a rejected share", snap.Penalty, cfg.Penalty)
	}
	if snap.Probability != trustProbabilityStart {
		t.Errorf("probability = %d, want reset to %d after a rejected share", snap.Probability, trustProbabilityStart)
	}
	if trust.ShouldSkipValidation() {
		t.Fatal("skip must be impossible immediately after trust is broken")
	}
}

func TestIsRandomXFamily(t *testing.T) {
	cases := []struct {
		algo poolpb.Algo
		want bool
	}{
		{poolpb.Algo_ALGO_RXT, true},
		{poolpb.Algo_ALGO_RXM, true},
		{poolpb.Algo_ALGO_SHA3X, false},
		{poolpb.Algo_ALGO_C29, false},
		{poolpb.Algo_ALGO_UNSPECIFIED, false},
	}
	for _, c := range cases {
		if got := IsRandomXFamily(c.algo); got != c.want {
			t.Errorf("IsRandomXFamily(%v) = %v, want %v", c.algo, got, c.want)
		}
	}
}
