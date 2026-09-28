// Copyright and license: see repository LICENSE (MIT).

// Package moneroblob owns the ONE, process-wide, safety-wrapped
// implementation of "turn a raw Monero blocktemplate_blob into the
// real, correctly-sized RandomX hashing blob" that every leaf mode in
// this repository shares.
//
// WHY THIS PACKAGE EXISTS (extraction, not new behavior): this exact
// wrapper — go-xmr-lib/support.ParseBlockFromTemplateBlob +
// support.GetBlockHashingBlob, wrapped in BOTH a panic-recovery net
// AND a hard wall-clock timeout AND a process-wide circuit breaker —
// used to live in internal/leaflib/proxy/upstream.go, with a
// deliberate, import-cycle-driven, BREAKER-LESS duplicate in
// internal/leaflib/solo/node.go (internal/leaflib/proxy imports
// internal/leaflib/solo, so solo could not import proxy back). That
// duplication was acceptable while only leaf-proxy needed the
// breaker, but leaf-solo's Monero shared-template path now needs the
// SAME conversion on its own hot job-derivation path — and two
// independent breakers defeat the entire point of a process-wide
// guard (a single leaf-direct binary genuinely links BOTH packages:
// internal/leaflib/direct imports solo, cmd/leaf-proxy imports
// proxy, and nothing stops a future binary from linking both).
//
// This package therefore sits BELOW both: it imports neither
// internal/leaflib/proxy nor internal/leaflib/solo, so both can
// import it with no cycle, and both now share one Breaker instance
// (GlobalBreaker) and one conversion implementation.
//
// The logic below is a faithful move of proxy's own already-
// battle-tested implementation — the thresholds, the timeout, the
// "only a panic or a timeout counts as a trigger" rule, and the
// "check the breaker BEFORE spawning any goroutine" ordering are all
// unchanged. Only the package it lives in, and the error-message
// prefix, are different.
package moneroblob

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-xmr-lib/support"
)

// BreakerThreshold/BreakerCooldown tune Breaker: after this many
// CONSECUTIVE ConvertTemplateBlobToHashingBlob triggers of the known
// go-xmr-lib bug (a panic OR a timeout -- see that function's doc
// comment; an ordinary, non-buggy parse error does NOT count, and
// resets the consecutive counter back to 0), the breaker opens for
// BreakerCooldown, during which ConvertTemplateBlobToHashingBlob
// refuses to spawn any FURTHER recovery-wrapped goroutine at all and
// returns an error immediately instead -- see Breaker's own doc
// comment for the full rationale (bounding how many leaked,
// unkillable, one-full-core goroutines a misbehaving/malicious
// upstream sending many such malformed blobs in sequence can force
// this process to spin up). 5 consecutive triggers is deliberately
// small: a single genuinely malformed blob is already fully
// mitigated by the per-call timeout/recover below on its own; this
// breaker exists purely to stop a SUSTAINED, repeated flood of them
// from spinning up an unbounded number of leaked goroutines, so it
// should trip well before that flood does serious damage, not act as
// a large tolerance window for isolated, occasional bad input.
const (
	BreakerThreshold = 5
	BreakerCooldown  = 30 * time.Second
)

// Breaker is a circuit breaker across ConvertTemplateBlobToHashingBlob
// calls (FIX_BRIEF.md, finding #18). In production there is exactly
// ONE instance of it, the package-level GlobalBreaker -- process-wide,
// not per-caller, both because ConvertTemplateBlobToHashingBlob is a
// free function called from several genuinely different call sites
// with no shared receiver (internal/leaflib/proxy's
// UpstreamClient.applyJob and WorkerTemplate.BlobForWorker/
// BlobForWorkerAndPool, plus internal/leaflib/solo's
// MoneroHashingBlobForXNPSubmit and its shared-template extraNonce
// stamp) and because a real leaf process has exactly ONE upstream
// pool/daemon connection for its entire lifetime -- a process-wide
// breaker and a "per the one upstream connection this leaf actually
// has" breaker are the same thing in practice. Additional instances
// exist only in this package's own tests, deliberately isolated from
// the singleton.
//
// WHY a breaker at all, on top of the existing per-call timeout/
// recover already in ConvertTemplateBlobToHashingBlob: that existing
// mitigation bounds the damage of any ONE malformed blob to roughly
// ConvertTimeout of wall-clock time and one leaked goroutine
// consuming one full CPU core FOREVER afterward (Go has no way to
// forcibly cancel a goroutine stuck in the vendored library's real
// infinite loop -- see that function's own doc comment) -- but
// places NO cap on how many such goroutines a malicious/misbehaving
// upstream sending MANY malformed blobs in sequence can force this
// process to leak, one per trigger, each permanently consuming a
// core. A modest number of these can degrade a leaf to
// uselessness; enough can exhaust the host entirely. This breaker
// adds the missing cap: once triggers happen consecutively often
// enough to look like a sustained pattern rather than an isolated bad
// blob, stop spawning NEW recovery-wrapped goroutines for a cooldown
// period (loudly logged/metric'd -- see RecordTrigger below) rather
// than accepting an unbounded number of them.
type Breaker struct {
	consecutive   atomic.Int64
	opensTotal    atomic.Uint64
	openUntilNano atomic.Int64
}

// Allow reports whether a NEW ConvertTemplateBlobToHashingBlob attempt
// (and its recovery-wrapped goroutine) should proceed right now.
// Returns false while the breaker is open (a recent burst of
// consecutive triggers tripped it and its cooldown has not yet
// elapsed) -- the caller must treat that as a real, if temporary,
// conversion failure and must NOT spawn a goroutine at all in that
// case (that is the entire point of this breaker). Once the cooldown
// has elapsed, this transitions the breaker back to closed (allowing
// exactly one more attempt to determine whether the malformed input
// has stopped) and returns true.
func (b *Breaker) Allow() bool {
	until := b.openUntilNano.Load()
	if until == 0 {
		return true
	}
	if time.Now().UnixNano() < until {
		return false
	}
	// Cooldown elapsed -- close the breaker again (best-effort CAS;
	// losing a race here just means another concurrent caller already
	// closed it, which is an equally correct outcome).
	b.openUntilNano.CompareAndSwap(until, 0)
	return true
}

// RecordTrigger records one genuine "known go-xmr-lib bug" trigger
// (a panic OR a timeout inside ConvertTemplateBlobToHashingBlob --
// NOT an ordinary, non-buggy parse error) and opens the breaker, with
// a loud log line, once BreakerThreshold consecutive triggers have
// been recorded. A nil logger falls back to log.Default().
func (b *Breaker) RecordTrigger(logger *log.Logger) {
	n := b.consecutive.Add(1)
	if n < BreakerThreshold {
		return
	}
	b.consecutive.Store(0)
	b.openUntilNano.Store(time.Now().Add(BreakerCooldown).UnixNano())
	b.opensTotal.Add(1)
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("moneroblob: MALFORMED-BLOB CIRCUIT BREAKER OPEN after %d consecutive go-xmr-lib blocktemplate_blob parse timeouts/panics -- refusing to spawn any further recovery-wrapped conversion goroutines for %s to bound goroutine/CPU-core leakage from a sustained malformed/malicious upstream blob stream (see ConvertTemplateBlobToHashingBlob's and Breaker's own doc comments)", n, BreakerCooldown)
}

// ResetConsecutive clears the consecutive-trigger streak after any
// outcome that is NOT itself a trigger (a genuine success, or an
// ordinary non-buggy parse error) -- only a genuinely CONSECUTIVE run
// of triggers should ever open the breaker.
func (b *Breaker) ResetConsecutive() {
	b.consecutive.Store(0)
}

// OpensTotal/IsOpen back this breaker's real-time metrics exposure
// (internal/leaflib/proxy/metrics.MalformedBlobBreakerStatsFunc, wired
// by proxy.Server.EnableMetrics) -- mirrors solo.AsyncValidationPool's
// own "plain getter methods polled at scrape time" convention exactly
// (see that type's own doc comment). IsOpen reports the breaker's
// CURRENT open/closed state without any side effect (unlike Allow, it
// never closes an elapsed breaker).
func (b *Breaker) OpensTotal() uint64 { return b.opensTotal.Load() }

// IsOpen reports the breaker's CURRENT open/closed state without any
// side effect -- see OpensTotal's doc comment.
func (b *Breaker) IsOpen() bool {
	until := b.openUntilNano.Load()
	return until != 0 && time.Now().UnixNano() < until
}

// GlobalBreaker is the single, process-wide breaker instance every
// ConvertTemplateBlobToHashingBlob call shares -- see Breaker's own
// doc comment for why process-wide is the correct scope here, and
// this package's own doc comment for why it had to be hoisted out of
// internal/leaflib/proxy to genuinely stay singular.
var GlobalBreaker = &Breaker{}

// ConvertTimeout bounds how long ConvertTemplateBlobToHashingBlob
// will wait for support.ParseBlockFromTemplateBlob +
// support.GetBlockHashingBlob to complete before giving up and
// returning an error -- see that function's doc comment for WHY a
// timeout, not just a recover, is required. A real, well-formed block
// template (even a large one, hundreds of transactions) parses in
// low-single-digit milliseconds; this is a generous multiple of that
// to avoid any risk of a false timeout on a genuinely
// slow-but-legitimate call, while still bounding the damage from the
// known hang described below to a few seconds per malformed input
// rather than forever.
const ConvertTimeout = 2 * time.Second

// ConvertTemplateBlobToHashingBlob wraps
// support.ParseBlockFromTemplateBlob + support.GetBlockHashingBlob
// with BOTH a panic-recovery net AND a hard wall-clock timeout AND
// the process-wide GlobalBreaker, converting a raw hex
// blocktemplate_blob straight into the real, correctly-sized RandomX
// hashing blob (or a normal error).
//
// This is the ONE implementation every caller in this repository
// shares: internal/leaflib/proxy's applyJob (converting an upstream
// pool's freshly-received raw blob) and WorkerTemplate.BlobForWorker/
// BlobForWorkerAndPool (re-deriving the hashing blob after patching a
// worker/pool nonce into a raw blob's coinbase tx_extra field), and
// internal/leaflib/solo's MoneroHashingBlobForXNPSubmit and
// shared-template extraNonce stamp (same re-derivation problem, same
// reason: patching the coinbase tx changes the merkle root, which is
// embedded in the hashing blob, so the pre-patch hashing blob is
// stale the moment the raw blob is patched).
//
// GENUINE, CONFIRMED go-xmr-lib v0.2.5 BUG (found and verified, not
// guessed): serialization.ConstructTXExtra's switch statement over a
// tx_extra tag byte
// (go-xmr-lib@v0.2.5/support/serialization/transaction.go:200-215)
// has NO default case, and none of its four cases (0x00/0x01/0x02/
// 0x03) advance the `mutable` slice when the byte doesn't match one
// of them -- so ANY tx_extra region byte that isn't exactly one of
// those four values causes ParseBlockFromTemplateBlob to spin
// forever in an infinite loop (NOT a panic -- confirmed via a
// throwaway reproduction: `for range 1800 sequential garbage bytes`
// hangs indefinitely; `go test -timeout` is the only thing that ever
// terminates it). This is a strictly worse failure mode than a panic
// (recover() cannot help at all), and is highly likely to trigger on
// ANY sufficiently large arbitrary/malformed/adversarial
// blocktemplate_blob, since roughly 252/256 possible tag byte values
// are unhandled. This was NOT fixed in the vendored dependency itself
// per this repo's own conventions (don't silently patch a third-party
// module as a workaround for one caller's problem) -- instead, this
// function bounds the damage with the hard timeout above: on timeout,
// it returns a normal error (leaving whatever good template the
// caller already had untouched, exactly like any other conversion
// failure) rather than blocking its caller (and, transitively, a
// leaf's ability to process new jobs) forever. The spawned goroutine
// itself CANNOT be forcibly cancelled (Go has no such primitive) and
// will keep spinning/leaking in the background consuming one CPU core
// for the lifetime of the process if this bug is ever actually
// triggered by a live pool/daemon -- this is a real, known, accepted
// limitation of this mitigation, not a complete fix. The proper fix
// is upstream, in go-xmr-lib itself (add a default case to that
// switch that returns an error).
//
// The recover (for the SEPARATE, panic-based failure modes) is a
// SAFETY NET on top of the above, not a substitute for checking real
// error returns: ParseBlockFromTemplateBlob does validate several
// length invariants via real error returns (serialization.ReadUint
// on a too-short buffer), and this function still checks and
// propagates those normally. But some of its OTHER fields (e.g. a
// corrupt/truncated tx_extra length prefix, or a tx-hash count field
// that claims far more 32-byte hashes than remain in the buffer) are
// consumed via direct slicing (blobInBytes[0:val]) rather than a
// bounds-checked read, which panics with a runtime
// slice-bounds-out-of-range error on sufficiently malformed/truncated
// input instead of returning a normal error or hanging. A malformed
// blocktemplate_blob must never be allowed to crash a leaf's entire
// process merely because one upstream (or a downstream nonce patch
// landing on an unexpected byte) produced bad bytes -- this recovers
// from that failure mode and reports it as an ordinary error instead.
func ConvertTemplateBlobToHashingBlob(blobHex string) ([]byte, error) {
	// CIRCUIT BREAKER (FIX_BRIEF.md, finding #18): checked BEFORE
	// spawning the recovery-wrapped goroutine below at all -- see
	// Breaker's own doc comment for the full rationale. While open,
	// this refuses every call outright (no goroutine, no timeout
	// wait) until the cooldown elapses.
	if !GlobalBreaker.Allow() {
		return nil, fmt.Errorf("moneroblob: malformed-blob circuit breaker is open (too many consecutive go-xmr-lib blocktemplate_blob parse timeouts/panics recently) -- refusing to spawn another recovery-wrapped conversion goroutine until its cooldown elapses")
	}
	type outcome struct {
		blob      []byte
		err       error
		recovered bool
	}
	ch := make(chan outcome, 1)
	go func() {
		var out outcome
		defer func() {
			if r := recover(); r != nil {
				out = outcome{nil, fmt.Errorf("moneroblob: recovered from a panic while parsing/converting a blocktemplate_blob (malformed or truncated input): %v", r), true}
			}
			ch <- out
		}()
		parsedBlock, perr := support.ParseBlockFromTemplateBlob(blobHex)
		if perr != nil {
			out = outcome{nil, perr, false}
			return
		}
		hashingBlob, perr := support.GetBlockHashingBlob(parsedBlock)
		out = outcome{hashingBlob, perr, false}
	}()
	select {
	case out := <-ch:
		// A panic-recovered outcome is a genuine known-bug trigger;
		// anything else (real success, or an ordinary non-buggy parse
		// error returned normally by the library) is NOT -- see
		// Breaker.RecordTrigger's own doc comment for why only a real
		// trigger should count toward the breaker's
		// consecutive-trigger streak.
		if out.recovered {
			GlobalBreaker.RecordTrigger(nil)
		} else {
			GlobalBreaker.ResetConsecutive()
		}
		return out.blob, out.err
	case <-time.After(ConvertTimeout):
		// A timeout is ALSO a genuine known-bug trigger (very likely
		// the infinite-loop bug itself, per this function's own doc
		// comment) -- counts toward the breaker exactly like a
		// recovered panic does. Note the still-running goroutine
		// above is intentionally NOT cancelled (Go has no such
		// primitive) and will keep leaking/spinning in the
		// background -- this is the exact, already-documented,
		// accepted limitation the breaker exists to bound the
		// FREQUENCY of, not eliminate entirely.
		GlobalBreaker.RecordTrigger(nil)
		return nil, fmt.Errorf("moneroblob: parsing/converting a blocktemplate_blob did not complete within %s -- likely triggered the known go-xmr-lib v0.2.5 ConstructTXExtra infinite-loop bug on malformed tx_extra data (see this function's doc comment); giving up and treating this as a failed conversion rather than blocking forever", ConvertTimeout)
	}
}
