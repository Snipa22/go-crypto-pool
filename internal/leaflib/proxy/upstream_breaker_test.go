// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"testing"
	"time"
)

// resetForTest resets a *malformedBlobBreaker to its initial closed
// state -- test-only. globalMalformedBlobBreaker is a package-level
// singleton (see its own doc comment for why: convertTemplateBlobToHashingBlob
// is a free function called from two receiverless call sites, and a
// real leaf-proxy process only ever has one upstream connection
// anyway), so any test that pushes it toward/past its open threshold
// MUST restore it afterward (t.Cleanup) or it will silently affect
// every other test in this package that happens to run afterward and
// also calls convertTemplateBlobToHashingBlob.
func (b *malformedBlobBreaker) resetForTest() {
	b.consecutive.Store(0)
	b.openUntilNano.Store(0)
}

// forceOpenForTest opens this breaker directly -- test-only,
// deliberately avoiding ever needing to trigger the REAL go-xmr-lib
// infinite-loop bug (hexOfLen(1800), see
// TestApplyJob_EmptyBlobLeavesExistingGoodTemplateUntouched's own doc
// comment) inside a test: that bug leaks one permanently-CPU-core-
// spinning goroutine per real trigger BY DESIGN (Go has no way to
// cancel it -- see convertTemplateBlobToHashingBlob's own doc
// comment), and this repo's test suite already accepts exactly one
// such leak from that pre-existing test; deliberately triggering
// MORE of them from additional tests measurably starves OTHER,
// unrelated timing-sensitive tests in this same package/binary under
// `go test -race` (confirmed while writing this test: doing so here
// caused real, reproducible failures in
// TestSession_RealPureGoRandomXValidator_BlockLevelFind_ForwardedUpstream
// and TestUpstreamClient_Connect_LoginCompletesWithoutDeadlock).
// TestMalformedBlobBreaker_OpensExactlyAtThreshold above already
// proves the breaker's own state machine genuinely opens after
// malformedBlobBreakerThreshold real, consecutive recordTrigger
// calls -- THIS helper lets the test below focus purely on proving
// convertTemplateBlobToHashingBlob itself actually CHECKS that open
// state at its own top, before ever spawning a goroutine, without
// needing to reproduce the real trigger a second (or third) time.
func (b *malformedBlobBreaker) forceOpenForTest() {
	b.openUntilNano.Store(time.Now().Add(time.Hour).UnixNano())
}

// TestMalformedBlobBreaker_OpensExactlyAtThreshold is the required,
// direct unit-level proof (FIX_BRIEF.md, finding #18's own
// verification instruction: "write a test that fabricates N
// consecutive malformed-blob triggers and asserts the breaker
// actually opens ... rather than just trusting the implementation
// looks right") against a FRESH, isolated breaker instance (not the
// shared package-level singleton, so this test cannot pollute/be
// polluted by any other test in this package).
func TestMalformedBlobBreaker_OpensExactlyAtThreshold(t *testing.T) {
	b := &malformedBlobBreaker{}
	logger := discardLogger()

	for i := int64(1); i < malformedBlobBreakerThreshold; i++ {
		b.recordTrigger(logger)
		if b.IsOpen() {
			t.Fatalf("breaker opened after only %d consecutive triggers, want it to stay closed until %d", i, malformedBlobBreakerThreshold)
		}
		if !b.allow() {
			t.Fatalf("allow() returned false after only %d consecutive triggers, want true (breaker not yet open)", i)
		}
	}

	// The Nth (threshold-th) consecutive trigger must open it.
	b.recordTrigger(logger)
	if !b.IsOpen() {
		t.Fatalf("breaker did not open after %d consecutive triggers", malformedBlobBreakerThreshold)
	}
	if b.allow() {
		t.Fatal("allow() returned true while the breaker is open")
	}
	if got := b.OpensTotal(); got != 1 {
		t.Fatalf("OpensTotal() = %d, want 1 after exactly one open", got)
	}

	// A further trigger while already open must not panic/misbehave,
	// and must not re-open an ALREADY-open breaker a second time
	// (OpensTotal only increments on a genuine closed->open
	// transition -- recordTrigger's own consecutive counter was
	// already reset to 0 when it opened, so this call is really "1
	// consecutive trigger" again, not threshold more).
	b.recordTrigger(logger)
	if got := b.OpensTotal(); got != 1 {
		t.Fatalf("OpensTotal() = %d after one more trigger while already open, want still 1 (not yet threshold-many since the last open)", got)
	}
}

// TestMalformedBlobBreaker_NonTriggerOutcomeResetsConsecutiveCount
// proves resetConsecutive (called by convertTemplateBlobToHashingBlob
// for a genuine success or an ordinary, non-buggy parse error --
// NEITHER of which is a "malformed-blob trigger" in this breaker's
// own sense) genuinely breaks a streak: threshold-1 real triggers
// followed by one reset must NOT open the breaker even after
// threshold-1 MORE triggers immediately after (2*(threshold-1) total
// triggers, but never threshold CONSECUTIVE ones).
func TestMalformedBlobBreaker_NonTriggerOutcomeResetsConsecutiveCount(t *testing.T) {
	b := &malformedBlobBreaker{}
	logger := discardLogger()

	for i := 0; i < malformedBlobBreakerThreshold-1; i++ {
		b.recordTrigger(logger)
	}
	if b.IsOpen() {
		t.Fatal("breaker opened before reaching its threshold")
	}

	b.resetConsecutive()

	for i := 0; i < malformedBlobBreakerThreshold-1; i++ {
		b.recordTrigger(logger)
	}
	if b.IsOpen() {
		t.Fatal("breaker opened even though resetConsecutive broke the streak -- consecutive-only semantics are broken")
	}
	if got := b.OpensTotal(); got != 0 {
		t.Fatalf("OpensTotal() = %d, want 0 (never reached a genuine consecutive streak of threshold triggers)", got)
	}
}

// TestConvertTemplateBlobToHashingBlob_BreakerOpensAndShortCircuits
// is the required END-TO-END proof (FIX_BRIEF.md, finding #18) that
// the breaker is actually WIRED IN to convertTemplateBlobToHashingBlob
// itself (not merely a standalone type that looks correct in
// isolation): once open, EVERY call -- even one carrying a real,
// well-formed, VALID blob -- must be refused immediately, WITHOUT
// spawning a recovery-wrapped goroutine or waiting out
// convertTemplateBlobTimeout, proving the check runs unconditionally
// at the very top of the function rather than as an opportunistic
// fast path only reachable for already-malformed input.
//
// Deliberately uses forceOpenForTest rather than fabricating
// malformedBlobBreakerThreshold real triggers via the actual
// go-xmr-lib infinite-loop bug here -- see forceOpenForTest's own doc
// comment for why (that bug leaks a real, permanently-CPU-core-
// spinning goroutine per trigger, and this suite already carries
// exactly one such leak from a separate, pre-existing test;
// TestMalformedBlobBreaker_OpensExactlyAtThreshold above already
// covers "does N consecutive real triggers actually open the
// breaker" in complete isolation from convertTemplateBlobToHashingBlob's
// own goroutine-spawning).
func TestConvertTemplateBlobToHashingBlob_BreakerOpensAndShortCircuits(t *testing.T) {
	globalMalformedBlobBreaker.resetForTest()
	t.Cleanup(func() { globalMalformedBlobBreaker.resetForTest() })

	globalMalformedBlobBreaker.forceOpenForTest()

	start := time.Now()
	_, err := convertTemplateBlobToHashingBlob(onlyMinerBlockTemplate)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error while the breaker is open, even for a real, well-formed, otherwise-valid blob")
	}
	if elapsed >= convertTemplateBlobTimeout {
		t.Fatalf("call took %v (>= convertTemplateBlobTimeout %v) -- breaker is not actually short-circuiting at the top of convertTemplateBlobToHashingBlob, it is still spawning a goroutine and waiting out the full timeout", elapsed, convertTemplateBlobTimeout)
	}
	t.Logf("breaker-open call short-circuited in %v (well under convertTemplateBlobTimeout %v)", elapsed, convertTemplateBlobTimeout)
}
