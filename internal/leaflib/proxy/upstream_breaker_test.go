// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/moneroblob"
)

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
// Deliberately uses moneroblob.Breaker.ForceOpenForTest rather than
// fabricating malformedBlobBreakerThreshold real triggers via the
// actual go-xmr-lib infinite-loop bug here -- see that helper's own
// doc comment for why (that bug leaks a real, permanently-CPU-core-
// spinning goroutine per trigger, and this suite already carries
// exactly one such leak from a separate, pre-existing test;
// moneroblob's own TestBreaker_OpensExactlyAtThreshold already covers
// "does N consecutive real triggers actually open the breaker" in
// complete isolation from this function's own goroutine-spawning).
//
// The two pure breaker-state-machine unit tests that used to also
// live in this file moved, unchanged, to
// internal/leaflib/moneroblob/breaker_test.go alongside the type
// itself -- see moneroblob's package doc comment for why the breaker
// was hoisted out of this package. THIS test stays here on purpose:
// it is specifically about this package's own call site being wired
// to the shared singleton.
func TestConvertTemplateBlobToHashingBlob_BreakerOpensAndShortCircuits(t *testing.T) {
	globalMalformedBlobBreaker.ResetForTest()
	t.Cleanup(func() { globalMalformedBlobBreaker.ResetForTest() })

	globalMalformedBlobBreaker.ForceOpenForTest()

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

// TestGlobalMalformedBlobBreakerIsTheSharedSingleton is the explicit
// regression guard for the ONE process-wide breaker invariant this
// package's alias exists to preserve: globalMalformedBlobBreaker must
// be the very same pointer as moneroblob.GlobalBreaker, not a
// second, independent instance. Two independent breakers would
// silently defeat the whole point of a process-wide guard (each would
// need its own threshold-many consecutive triggers before opening,
// doubling the number of leaked one-core goroutines a sustained
// malformed-blob flood can force this process to spin up).
func TestGlobalMalformedBlobBreakerIsTheSharedSingleton(t *testing.T) {
	if globalMalformedBlobBreaker != moneroblob.GlobalBreaker {
		t.Fatal("globalMalformedBlobBreaker is not moneroblob.GlobalBreaker -- this package has its own second, independent breaker instance, which defeats the process-wide guarantee")
	}
}
