// Copyright and license: see repository LICENSE (MIT).
package proxy

import "testing"

// TestJobMarkNonceUsedRejectsReplay mirrors
// internal/leaflib/solo/job_test.go's identical test exactly --
// leaf-proxy's own Job.MarkNonceUsed (job.go) has the same
// used-nonce-tracking contract, just keyed on a uint32 (Monero-family
// 4-byte nonce) instead of solo's uint64.
func TestJobMarkNonceUsedRejectsReplay(t *testing.T) {
	job := &Job{ID: "deadbeefdeadbeef"}

	if !job.MarkNonceUsed(42) {
		t.Fatal("first use of a nonce must be reported as newly recorded")
	}
	if job.MarkNonceUsed(42) {
		t.Fatal("replaying the same nonce must be reported as already used")
	}
	if !job.MarkNonceUsed(43) {
		t.Fatal("a different nonce must be independently trackable")
	}
}

// TestJobMarkNonceUsedCapsDistinctNonceGrowth is the required Fix 11
// test (DISPATCH_BRIEF.md 2026-09-10): mirrors solo's identical test
// exactly -- once maxTrackedNoncesPerJob distinct nonces have been
// recorded against one Job, a genuinely NEW nonce beyond the cap must
// be rejected (never grow the map further), while a REPLAY of an
// already-tracked nonce must still be correctly caught as a replay,
// not silently allowed through.
func TestJobMarkNonceUsedCapsDistinctNonceGrowth(t *testing.T) {
	job := &Job{ID: "deadbeefdeadbeef"}

	for i := uint32(0); i < maxTrackedNoncesPerJob; i++ {
		if !job.MarkNonceUsed(i) {
			t.Fatalf("nonce %d (below the cap) must be reported as newly recorded", i)
		}
	}
	if got := len(job.usedNonces); got != maxTrackedNoncesPerJob {
		t.Fatalf("expected exactly %d tracked nonces at the cap, got %d", maxTrackedNoncesPerJob, got)
	}

	if job.MarkNonceUsed(maxTrackedNoncesPerJob) {
		t.Fatal("a genuinely new nonce beyond the cap must be rejected, not newly recorded")
	}
	if got := len(job.usedNonces); got != maxTrackedNoncesPerJob {
		t.Fatalf("expected the tracked-nonce count to stay bounded at %d after a beyond-cap rejection, got %d", maxTrackedNoncesPerJob, got)
	}

	if job.MarkNonceUsed(0) {
		t.Fatal("a replay of an already-tracked nonce must still be rejected once the cap has been reached, not silently allowed through")
	}
}
