// Copyright and license: see repository LICENSE (MIT).
package moneroblob

import "time"

// ResetForTest resets a *Breaker to its initial closed state.
//
// TEST-ONLY. It lives in a non-_test.go file deliberately, because
// GlobalBreaker is a package-level singleton shared with OTHER
// packages' tests (internal/leaflib/proxy's own breaker-wiring test,
// internal/leaflib/solo's extraNonce degrade-gracefully test), and Go
// does not export identifiers from one package's _test.go files to
// another package. Any test that pushes GlobalBreaker toward/past its
// open threshold MUST restore it afterward (t.Cleanup) or it will
// silently affect every other test that happens to run afterward and
// also calls ConvertTemplateBlobToHashingBlob.
func (b *Breaker) ResetForTest() {
	b.consecutive.Store(0)
	b.openUntilNano.Store(0)
}

// ForceOpenForTest opens this breaker directly.
//
// TEST-ONLY (see ResetForTest above for why this is not in a _test.go
// file). Deliberately avoids ever needing to trigger the REAL
// go-xmr-lib infinite-loop bug (a large arbitrary-bytes blob, see
// ConvertTemplateBlobToHashingBlob's doc comment) inside a test: that
// bug leaks one permanently-CPU-core-spinning goroutine per real
// trigger BY DESIGN (Go has no way to cancel it), and this repo's
// test suite already accepts exactly one such leak from a
// pre-existing internal/leaflib/proxy test; deliberately triggering
// MORE of them from additional tests measurably starves OTHER,
// unrelated timing-sensitive tests in the same test binary under
// `go test -race` (confirmed in this repo's own history: doing so
// caused real, reproducible failures in
// TestSession_RealPureGoRandomXValidator_BlockLevelFind_ForwardedUpstream
// and TestUpstreamClient_Connect_LoginCompletesWithoutDeadlock).
// This package's own TestBreaker_OpensExactlyAtThreshold proves the
// breaker's state machine genuinely opens after BreakerThreshold
// real, consecutive RecordTrigger calls -- this helper lets a
// wiring-level test focus purely on proving
// ConvertTemplateBlobToHashingBlob itself actually CHECKS that open
// state at its own top, before ever spawning a goroutine, without
// needing to reproduce the real trigger again.
func (b *Breaker) ForceOpenForTest() {
	b.openUntilNano.Store(time.Now().Add(time.Hour).UnixNano())
}
