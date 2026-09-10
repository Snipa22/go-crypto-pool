// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"runtime"
	"testing"
)

// TestDefaultAsyncValidationWorkersIsNumCPU is the direct, minimal
// regression guard for DISPATCH_BRIEF.md's (2026-09-10, Fix 2a) own
// explicit requirement: "why only 8 workers? numcpu is the correct
// number of workers that we can send the backend." -- the default
// worker count must track runtime.NumCPU(), not a hardcoded literal.
func TestDefaultAsyncValidationWorkersIsNumCPU(t *testing.T) {
	if got, want := DefaultAsyncValidationWorkers(), runtime.NumCPU(); got != want {
		t.Fatalf("DefaultAsyncValidationWorkers() = %d, want runtime.NumCPU() = %d", got, want)
	}
}

// TestNewAsyncValidationPoolDefaultsToNumCPUWorkers proves the pool
// ITSELF (not just the standalone helper function) actually applies
// this default when constructed with workers<=0 -- the shape every
// real production call site (solo/direct/proxy's own NewServer) now
// uses (see each package's server.go: `NewAsyncValidationPool(0,
// ...)`), confirmed via the pool's own Workers() introspection method
// rather than re-deriving the expected value through a separate,
// potentially-diverging code path.
func TestNewAsyncValidationPoolDefaultsToNumCPUWorkers(t *testing.T) {
	p := NewAsyncValidationPool(0, 0)
	defer p.Stop()
	if got, want := p.Workers(), runtime.NumCPU(); got != want {
		t.Fatalf("NewAsyncValidationPool(0, 0).Workers() = %d, want runtime.NumCPU() = %d", got, want)
	}

	// A negative value must be treated identically to 0/unset (the
	// exact same "non-positive" fallback NewAsyncValidationPool's own
	// doc comment documents).
	pNeg := NewAsyncValidationPool(-1, -1)
	defer pNeg.Stop()
	if got, want := pNeg.Workers(), runtime.NumCPU(); got != want {
		t.Fatalf("NewAsyncValidationPool(-1, -1).Workers() = %d, want runtime.NumCPU() = %d", got, want)
	}
}

// TestNewAsyncValidationPoolHonorsExplicitWorkerCount confirms an
// operator-supplied positive worker count is NOT overridden by the
// runtime.NumCPU() default -- the "runtime.NumCPU() should be the
// DEFAULT when unset, not a forced value that removes operator
// control" half of Fix 2a's own requirement.
func TestNewAsyncValidationPoolHonorsExplicitWorkerCount(t *testing.T) {
	const explicit = 3
	p := NewAsyncValidationPool(explicit, 0)
	defer p.Stop()
	if got := p.Workers(); got != explicit {
		t.Fatalf("NewAsyncValidationPool(%d, 0).Workers() = %d, want %d (explicit value must not be overridden by the default)", explicit, got, explicit)
	}
}
