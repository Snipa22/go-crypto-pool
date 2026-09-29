// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"strings"
	"sync"
	"testing"
)

// --- NewJobCacheKey coverage. See that function's own doc comment for
// the real, maintainer-confirmed correctness bug it exists to fix
// (solo.JobManager's job cache used to be keyed by the session's
// 2-byte xn, so two unrelated sessions drawing the same xn were served
// ONE shared *Job, template and usedNonces map). The
// end-to-end/behavioral proof lives in
// internal/leaflib/solo/job_cache_key_test.go and
// internal/leaflib/direct/job_cache_key_test.go; what is asserted here
// is the primitive's own contract. ---

// TestNewJobCacheKeyIsUniqueAcrossManyCallsIncludingIdenticalSessionIDs
// is the property the whole fix rests on: uniqueness BY CONSTRUCTION,
// not by probability. Note that every key below is generated from the
// SAME sessionID -- proving the uniqueness comes from the counter and
// not from the caller-supplied prefix, so even a repeated (or empty)
// sessionID can never produce a duplicate key.
func TestNewJobCacheKeyIsUniqueAcrossManyCallsIncludingIdenticalSessionIDs(t *testing.T) {
	const n = 100_000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		key := NewJobCacheKey("same-session-id")
		if _, dup := seen[key]; dup {
			t.Fatalf("NewJobCacheKey produced a DUPLICATE key %q on call %d of %d -- this primitive's entire purpose is being collision-free by construction", key, i+1, n)
		}
		seen[key] = struct{}{}
	}

	// A 2-byte random draw (leaflib.NewSessionXN, what this replaces
	// as a cache key) has only 65,536 possible values, so it could not
	// even represent this many distinct keys, let alone produce them
	// without collision. Asserted explicitly so the contrast with the
	// bug is recorded, not just implied.
	if n <= 65536 {
		t.Fatalf("this test must generate MORE than the 65,536 values a 2-byte xn can represent to be meaningful; n = %d", n)
	}
}

// TestNewJobCacheKeyIsUniqueUnderConcurrency: sessions are created
// concurrently in production (one per accepted connection, plus
// re-login rolls on live connections), so the counter must be
// genuinely atomic. Run this under -race.
func TestNewJobCacheKeyIsUniqueUnderConcurrency(t *testing.T) {
	const goroutines = 64
	const perGoroutine = 500

	keys := make([][]string, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			local := make([]string, perGoroutine)
			for i := range local {
				local[i] = NewJobCacheKey("concurrent-session")
			}
			keys[g] = local
		}(g)
	}
	wg.Wait()

	seen := make(map[string]struct{}, goroutines*perGoroutine)
	for g, local := range keys {
		for i, key := range local {
			if _, dup := seen[key]; dup {
				t.Fatalf("NewJobCacheKey produced a DUPLICATE key %q under concurrency (goroutine %d, index %d)", key, g, i)
			}
			seen[key] = struct{}{}
		}
	}
	if got := len(seen); got != goroutines*perGoroutine {
		t.Fatalf("got %d distinct keys, want %d", got, goroutines*perGoroutine)
	}
}

// TestNewJobCacheKeyCarriesSessionIDForTraceability: the sessionID
// prefix carries no uniqueness weight (see the test above), but it IS
// load-bearing for diagnosability -- every log line in solo/direct
// that reports a job_key is expected to be traceable back to the
// session that owns it.
func TestNewJobCacheKeyCarriesSessionIDForTraceability(t *testing.T) {
	const sessionID = "a1b2c3d4e5f60708"
	key := NewJobCacheKey(sessionID)
	if !strings.HasPrefix(key, sessionID) {
		t.Fatalf("NewJobCacheKey(%q) = %q, want it to start with the sessionID so a job_key in a log line is traceable back to its session", sessionID, key)
	}
	if key == sessionID {
		t.Fatalf("NewJobCacheKey(%q) returned the bare sessionID -- it must add the monotonic counter suffix, which is what makes a re-login's roll produce a genuinely different key for the SAME session", sessionID)
	}
}

// TestNewJobCacheKeyIsNeverASessionXN is a structural guard against the
// bug regressing by a different route than the one the solo/direct
// tests cover: a NewJobCacheKey value must never be mistakable for a
// NewSessionXN value (a bare 4-hex-char string), so any code path that
// accidentally substituted one for the other would be immediately
// obvious in logs rather than silently "working".
func TestNewJobCacheKeyIsNeverASessionXN(t *testing.T) {
	xn, err := NewSessionXN()
	if err != nil {
		t.Fatalf("NewSessionXN: %v", err)
	}
	if len(xn) != 4 {
		t.Fatalf("NewSessionXN() = %q, want a 4-hex-char (2-byte) value", xn)
	}

	for i := 0; i < 100; i++ {
		key := NewJobCacheKey(xn)
		if key == xn {
			t.Fatalf("NewJobCacheKey(%q) returned a value identical to an xn (%q)", xn, key)
		}
		if len(key) == 4 {
			t.Fatalf("NewJobCacheKey returned %q, which is xn-shaped (4 chars) -- job-cache keys must be visibly distinct from xn values", key)
		}
	}
}
