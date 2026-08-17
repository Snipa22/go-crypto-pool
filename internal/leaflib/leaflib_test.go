package leaflib

import "testing"

func TestAlgoConstants(t *testing.T) {
	algos := []Algo{AlgoRXT, AlgoC29, AlgoSHA3X, AlgoRXM}
	seen := make(map[Algo]bool)
	for _, a := range algos {
		if a == "" {
			t.Fatal("algo constant must not be empty")
		}
		if seen[a] {
			t.Fatalf("duplicate algo constant: %s", a)
		}
		seen[a] = true
	}
	if len(seen) != 4 {
		t.Fatalf("expected 4 distinct algos, got %d", len(seen))
	}
}
