// Copyright and license: see repository LICENSE (MIT).
package moneroblob

import (
	"io"
	"log"
	"testing"
)

// discardLogger is a *log.Logger that writes nowhere -- keeps the
// breaker's own (deliberately loud) open log line out of test output
// while still exercising the real RecordTrigger logging path.
func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// TestBreaker_OpensExactlyAtThreshold is the required, direct
// unit-level proof (FIX_BRIEF.md, finding #18's own verification
// instruction: "write a test that fabricates N consecutive
// malformed-blob triggers and asserts the breaker actually opens ...
// rather than just trusting the implementation looks right") against
// a FRESH, isolated breaker instance (not the shared package-level
// GlobalBreaker, so this test cannot pollute/be polluted by any other
// test).
//
// MOVED, UNCHANGED, from internal/leaflib/proxy/upstream_breaker_test.go
// as part of hoisting the breaker into this package -- see this
// package's own doc comment for why the hoist was necessary. Same
// assertions, same fresh-instance isolation.
func TestBreaker_OpensExactlyAtThreshold(t *testing.T) {
	b := &Breaker{}
	logger := discardLogger()

	for i := int64(1); i < BreakerThreshold; i++ {
		b.RecordTrigger(logger)
		if b.IsOpen() {
			t.Fatalf("breaker opened after only %d consecutive triggers, want it to stay closed until %d", i, BreakerThreshold)
		}
		if !b.Allow() {
			t.Fatalf("Allow() returned false after only %d consecutive triggers, want true (breaker not yet open)", i)
		}
	}

	// The Nth (threshold-th) consecutive trigger must open it.
	b.RecordTrigger(logger)
	if !b.IsOpen() {
		t.Fatalf("breaker did not open after %d consecutive triggers", BreakerThreshold)
	}
	if b.Allow() {
		t.Fatal("Allow() returned true while the breaker is open")
	}
	if got := b.OpensTotal(); got != 1 {
		t.Fatalf("OpensTotal() = %d, want 1 after exactly one open", got)
	}

	// A further trigger while already open must not panic/misbehave,
	// and must not re-open an ALREADY-open breaker a second time
	// (OpensTotal only increments on a genuine closed->open
	// transition -- RecordTrigger's own consecutive counter was
	// already reset to 0 when it opened, so this call is really "1
	// consecutive trigger" again, not threshold more).
	b.RecordTrigger(logger)
	if got := b.OpensTotal(); got != 1 {
		t.Fatalf("OpensTotal() = %d after one more trigger while already open, want still 1 (not yet threshold-many since the last open)", got)
	}
}

// TestBreaker_NonTriggerOutcomeResetsConsecutiveCount proves
// ResetConsecutive (called by ConvertTemplateBlobToHashingBlob for a
// genuine success or an ordinary, non-buggy parse error -- NEITHER of
// which is a "malformed-blob trigger" in this breaker's own sense)
// genuinely breaks a streak: threshold-1 real triggers followed by one
// reset must NOT open the breaker even after threshold-1 MORE triggers
// immediately after (2*(threshold-1) total triggers, but never
// threshold CONSECUTIVE ones).
//
// MOVED, UNCHANGED, from internal/leaflib/proxy/upstream_breaker_test.go.
func TestBreaker_NonTriggerOutcomeResetsConsecutiveCount(t *testing.T) {
	b := &Breaker{}
	logger := discardLogger()

	for i := 0; i < BreakerThreshold-1; i++ {
		b.RecordTrigger(logger)
	}
	if b.IsOpen() {
		t.Fatal("breaker opened before reaching its threshold")
	}

	b.ResetConsecutive()

	for i := 0; i < BreakerThreshold-1; i++ {
		b.RecordTrigger(logger)
	}
	if b.IsOpen() {
		t.Fatal("breaker opened even though ResetConsecutive broke the streak -- consecutive-only semantics are broken")
	}
	if got := b.OpensTotal(); got != 0 {
		t.Fatalf("OpensTotal() = %d, want 0 (never reached a genuine consecutive streak of threshold triggers)", got)
	}
}

// TestBreaker_AllowClosesAnElapsedBreaker proves Allow's own
// cooldown-elapsed transition: a breaker whose openUntil has already
// passed must report itself closed again (IsOpen false) and allow the
// next attempt through, so a transient burst of malformed blobs can
// never permanently wedge conversion shut.
func TestBreaker_AllowClosesAnElapsedBreaker(t *testing.T) {
	b := &Breaker{}
	// An already-elapsed "open until" instant (1ns after the epoch):
	// Allow must observe the cooldown as over and close the breaker.
	b.openUntilNano.Store(1)
	if !b.Allow() {
		t.Fatal("Allow() returned false for a breaker whose cooldown has already fully elapsed")
	}
	if b.IsOpen() {
		t.Fatal("breaker still reports itself open after Allow() observed an elapsed cooldown")
	}
}
