// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// writeTimeRecorder is an io.Writer that records the wall-clock
// moment of every Write call it receives (mutex-protected), so a test
// can attach it to a *leaflib.DebugLogger (via a *log.Logger) and
// observe exactly when each vardiff.go "vardiff check: ..." Debugf
// line was actually emitted -- i.e. exactly when a session's own
// runVardiffLoop ticker really fired, with no separate test-only hook
// needed inside production code.
type writeTimeRecorder struct {
	mu    sync.Mutex
	times []time.Time
}

func (w *writeTimeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.times = append(w.times, time.Now())
	w.mu.Unlock()
	return len(p), nil
}

func (w *writeTimeRecorder) snapshot() []time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]time.Time, len(w.times))
	copy(out, w.times)
	return out
}

// newJitterTestSession builds a minimal, standalone *Session/*Server
// pair -- deliberately NOT going through the full net.Pipe/login
// harness (session_test.go's testHarness) -- wired with just enough
// state for runVardiffLoop/maybeRetarget to run to completion safely:
//
//   - currentDifficulty is left at its zero value (0), which forces
//     leaflib.ComputeRetarget to ALWAYS report changed=false (nd=0*0.9=0
//     collapses right back to curDiff=0 regardless of hashesAccumulated),
//     so maybeRetarget never reaches s.server.jobManager.RestampDifficulty
//     -- letting Server.jobManager/node/etc. stay nil with no panic risk.
//   - s.server.debugLogger is a REAL, enabled *leaflib.DebugLogger
//     backed by rec, so maybeRetarget's unconditional per-tick
//     "direct: vardiff check: ..." Debugf call (which runs BEFORE the
//     changed-vs-unchanged branch) gives an exact, real, timestamped
//     signal for every single tick this session's real runVardiffLoop
//     goroutine ever fires -- production code, completely unmodified.
func newJitterTestSession(id string, interval time.Duration, connectedAt time.Time) (*Session, *writeTimeRecorder) {
	rec := &writeTimeRecorder{}
	srv := &Server{
		vardiff:     leaflib.VardiffConfig{RetargetInterval: interval, TargetTime: 30},
		debugLogger: leaflib.NewDebugLogger(log.New(rec, "", 0), true),
		logger:      log.New(rec, "", 0),
	}
	sess := &Session{
		sessionID:   id,
		server:      srv,
		connectedAt: connectedAt,
	}
	return sess, rec
}

// TestVardiffInitialJitter_DesynchronizesSimultaneousSessions is the
// required "thundering herd" regression proof: a large population of
// sessions started at (as close as a test goroutine fan-out gets to)
// the exact same instant must NOT all fire their first vardiff tick
// at the same wall-clock moment -- their first-tick offsets from the
// common start instant must be spread out across (up to) the FULL
// RetargetInterval window, not clustered together.
//
// This is a REAL, non-tautological proof: it runs every session
// through the genuine, unmodified runVardiffLoop goroutine and
// vardiffJitterFunc's real math/rand source (never overridden here),
// and observes the real wall-clock arrival time of each session's
// first "vardiff check" Debugf line (see newJitterTestSession's doc
// comment) -- not a hand-computed/mocked jitter value.
func TestVardiffInitialJitter_DesynchronizesSimultaneousSessions(t *testing.T) {
	const interval = 200 * time.Millisecond
	const n = 12

	type firstTick struct {
		idx int
		at  time.Time
	}

	results := make(chan firstTick, n)
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		// connectedAt is backdated well past `interval` so the
		// connSeconds age gate in maybeRetarget never blocks the
		// very first tick -- this test is about the TICKER's own
		// timing, not the age gate (see the separate
		// TestMaybeRetarget_ConnSecondsFloorUnaffectedByJitter test
		// for that).
		sess, rec := newJitterTestSession(fmt.Sprintf("herd-%d", i), interval, time.Now().Add(-time.Hour))
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		wg.Add(1)
		go func(idx int, sess *Session, rec *writeTimeRecorder) {
			defer wg.Done()
			go sess.runVardiffLoop(ctx)

			deadline := time.Now().Add(3 * interval)
			for time.Now().Before(deadline) {
				if got := rec.snapshot(); len(got) > 0 {
					results <- firstTick{idx: idx, at: got[0]}
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
			t.Errorf("session %d: no vardiff tick observed within %v", idx, 3*interval)
		}(i, sess, rec)
	}
	wg.Wait()
	close(results)

	offsets := make([]time.Duration, 0, n)
	for r := range results {
		offsets = append(offsets, r.at.Sub(start))
	}
	if len(offsets) != n {
		t.Fatalf("expected %d recorded first-tick offsets, got %d", n, len(offsets))
	}

	minOff, maxOff := offsets[0], offsets[0]
	for _, o := range offsets {
		if o < minOff {
			minOff = o
		}
		if o > maxOff {
			maxOff = o
		}
	}
	spread := maxOff - minOff

	// Every first tick must land at or after `interval` (jitter's
	// minimum is 0, plus the ticker's own first period), and the
	// jittered population's spread must span a meaningful fraction
	// of the full interval window -- NOT be clustered together the
	// way an un-jittered thundering herd would be (every session
	// would land within a few milliseconds of each other, spread
	// close to 0). The probability that 12 genuinely independent
	// uniform-random jitter draws collapse into a spread under
	// interval/4 is astronomically small (~1e-6), so this threshold
	// is not flaky in practice.
	if spread < interval/4 {
		t.Errorf("first-tick offsets are suspiciously clustered (spread=%v, want > %v) -- jitter may not be applied per-session", spread, interval/4)
	}
	t.Logf("first-tick offsets spread across %v (min=%v, max=%v) for %d simultaneous sessions", spread, minOff, maxOff, n)
}

// TestVardiffSteadyStateCadenceUnaffectedByInitialJitter is the
// required "cadence" regression proof: the initial jitter delay must
// be a ONE-TIME phase shift only -- every SUBSEQUENT tick for a given
// session must still be spaced exactly `interval` apart (matching
// time.Ticker's own documented behavior), not re-randomized on every
// tick.
func TestVardiffSteadyStateCadenceUnaffectedByInitialJitter(t *testing.T) {
	const interval = 80 * time.Millisecond
	const wantTicks = 5

	sess, rec := newJitterTestSession("cadence", interval, time.Now().Add(-time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sess.runVardiffLoop(ctx)

	deadline := time.Now().Add(time.Duration(wantTicks+2) * interval * 3)
	for {
		if len(rec.snapshot()) >= wantTicks {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only observed %d/%d ticks within the deadline", len(rec.snapshot()), wantTicks)
		}
		time.Sleep(2 * time.Millisecond)
	}

	times := rec.snapshot()
	// Skip the very first tick (its absolute position is randomized
	// by the initial jitter) and check every gap BETWEEN subsequent
	// ticks lands within a generous tolerance of the real configured
	// interval.
	const tolerance = interval / 2
	for i := 2; i < wantTicks; i++ {
		gap := times[i].Sub(times[i-1])
		if gap < interval-tolerance || gap > interval+tolerance {
			t.Errorf("tick %d->%d gap = %v, want ~%v (+/- %v) -- steady-state cadence must be unaffected by the one-time initial jitter", i-1, i, gap, interval, tolerance)
		}
	}
}

// TestMaybeRetarget_ConnSecondsFloorUnaffectedByJitter confirms
// maybeRetarget's own pre-existing "don't retarget before a full
// interval of real connection time has passed" gate
// (connSeconds < int(cfg.RetargetInterval.Seconds())) still works
// exactly as before: a session younger than one real
// RetargetInterval must never retarget, regardless of the initial
// jitter delay. maybeRetarget itself is completely untouched by this
// fix (only runVardiffLoop gained the one-time jitter select before
// constructing its ticker), so this is a direct regression guard
// against that gate accidentally being weakened.
func TestMaybeRetarget_ConnSecondsFloorUnaffectedByJitter(t *testing.T) {
	sess, _ := newJitterTestSession("young", time.Minute, time.Now())
	sess.currentDifficulty.Store(1000)
	// A huge accept history that WOULD trigger a large retarget if
	// the age gate weren't in place.
	sess.hashesAccumulated.Store(1_000_000)

	sess.maybeRetarget()

	if got := sess.currentDifficulty.Load(); got != 1000 {
		t.Errorf("expected no retarget for a session younger than RetargetInterval, difficulty changed to %d", got)
	}
}
