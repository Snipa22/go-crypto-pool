// Copyright and license: see repository LICENSE (MIT).
package metrics

import (
	"fmt"
	"testing"
)

func TestCapAddressCounts_UnderCapReturnsUnchanged(t *testing.T) {
	counts := map[string]int{"a": 1, "b": 2}
	kept, other := CapAddressCounts(counts, 5)
	if other != 0 {
		t.Errorf("other = %d, want 0", other)
	}
	if len(kept) != 2 {
		t.Errorf("len(kept) = %d, want 2", len(kept))
	}
}

func TestCapAddressCounts_KeepsHighestCounts(t *testing.T) {
	counts := map[string]int{"low": 1, "mid": 5, "high": 10, "extra1": 2, "extra2": 3}
	kept, other := CapAddressCounts(counts, 3) // keep top 2 + other
	if len(kept) != 2 {
		t.Fatalf("len(kept) = %d, want 2: %#v", len(kept), kept)
	}
	if kept["high"] != 10 || kept["mid"] != 5 {
		t.Errorf("expected {high:10, mid:5} kept, got %#v", kept)
	}
	wantOther := 1 + 2 + 3 // low + extra1 + extra2
	if other != wantOther {
		t.Errorf("other = %d, want %d", other, wantOther)
	}
}

func TestCapAddressCounts_FloodOfDistinctAddressesBoundedToCap(t *testing.T) {
	const cap5 = 5
	counts := make(map[string]int, 50)
	for i := 0; i < 50; i++ {
		counts[fmt.Sprintf("flood-addr-%02d", i)] = 1
	}
	kept, other := CapAddressCounts(counts, cap5)
	if len(kept) != cap5-1 {
		t.Fatalf("len(kept) = %d, want %d", len(kept), cap5-1)
	}
	if other != 50-(cap5-1) {
		t.Fatalf("other = %d, want %d", other, 50-(cap5-1))
	}
}

func TestRemoteIPOf_StripsPort(t *testing.T) {
	got := RemoteIPOf(fakeAddr("10.1.2.3:4444"))
	if got != "10.1.2.3" {
		t.Errorf("RemoteIPOf = %q, want 10.1.2.3", got)
	}
}

func TestRemoteIPOf_FallsBackOnUnparsableAddr(t *testing.T) {
	got := RemoteIPOf(fakeAddr("pipe"))
	if got != "pipe" {
		t.Errorf("RemoteIPOf = %q, want raw fallback %q", got, "pipe")
	}
}

func TestRemoteIPOf_NilAddr(t *testing.T) {
	if got := RemoteIPOf(nil); got != "" {
		t.Errorf("RemoteIPOf(nil) = %q, want empty string", got)
	}
}

type fakeAddr string

func (f fakeAddr) Network() string { return "test" }
func (f fakeAddr) String() string  { return string(f) }
