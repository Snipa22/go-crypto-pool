package retention

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeRepo is an in-memory Repository test double.
type fakeRepo struct {
	partitions map[string][]HeightPartition // key: algo+"/"+poolType
	listErr    map[string]error
	dropErr    map[string]error
	dropCalls  []dropCall
}

type dropCall struct {
	algo, poolType string
	belowHeight    int64
}

func key(algo, poolType string) string { return algo + "/" + poolType }

func (f *fakeRepo) ListHeightPartitions(_ context.Context, algo, poolType string) ([]HeightPartition, error) {
	if err, ok := f.listErr[key(algo, poolType)]; ok {
		return nil, err
	}
	return f.partitions[key(algo, poolType)], nil
}

func (f *fakeRepo) DropOldPartitions(_ context.Context, algo, poolType string, belowHeight int64) ([]string, error) {
	f.dropCalls = append(f.dropCalls, dropCall{algo: algo, poolType: poolType, belowHeight: belowHeight})
	if err, ok := f.dropErr[key(algo, poolType)]; ok {
		return nil, err
	}
	var dropped []string
	var kept []HeightPartition
	for _, p := range f.partitions[key(algo, poolType)] {
		if p.RangeEnd <= belowHeight {
			dropped = append(dropped, p.Name)
			continue
		}
		kept = append(kept, p)
	}
	f.partitions[key(algo, poolType)] = kept
	return dropped, nil
}

func TestRunOnce_DropsOnlyPartitionsFullyBelowCutoff(t *testing.T) {
	repo := &fakeRepo{partitions: map[string][]HeightPartition{
		key("RXT", "PPLNS"): {
			{Name: "shares_rxt_pplns_h000000000000", RangeStart: 0, RangeEnd: 100000},
			{Name: "shares_rxt_pplns_h000000100000", RangeStart: 100000, RangeEnd: 200000},
			{Name: "shares_rxt_pplns_h000000200000", RangeStart: 200000, RangeEnd: 300000},
		},
	}}
	r := New(repo, Config{Targets: []Target{
		{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 150000},
	}})

	result := r.RunOnce(context.Background())
	// frontier=300000, cutoff=150000 -> only the [0,100000) bucket
	// (RangeEnd=100000 <= 150000) is fully below cutoff and dropped.
	if result.PartitionsDropped != 1 || result.Errors != 0 || result.TargetsChecked != 1 {
		t.Fatalf("RunOnce: got %+v, want 1 dropped / 0 errors / 1 checked", result)
	}
	if len(repo.dropCalls) != 1 || repo.dropCalls[0].belowHeight != 150000 {
		t.Fatalf("DropOldPartitions call: got %+v, want belowHeight=150000", repo.dropCalls)
	}
	remaining := repo.partitions[key("RXT", "PPLNS")]
	if len(remaining) != 2 {
		t.Fatalf("expected 2 partitions to survive, got %d: %+v", len(remaining), remaining)
	}
}

func TestRunOnce_SkipsTargetWithNonPositiveRetention(t *testing.T) {
	repo := &fakeRepo{partitions: map[string][]HeightPartition{
		key("RXT", "PPLNS"): {{Name: "p1", RangeStart: 0, RangeEnd: 100000}},
	}}
	r := New(repo, Config{Targets: []Target{
		{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 0},
	}})

	result := r.RunOnce(context.Background())
	if result.PartitionsDropped != 0 || len(repo.dropCalls) != 0 {
		t.Fatalf("RunOnce: expected no drop calls for a disabled target, got %+v calls=%v", result, repo.dropCalls)
	}
}

func TestRunOnce_NoPartitionsYetIsNotAnError(t *testing.T) {
	repo := &fakeRepo{partitions: map[string][]HeightPartition{}}
	r := New(repo, Config{Targets: []Target{
		{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 100000},
	}})

	result := r.RunOnce(context.Background())
	if result.Errors != 0 || result.PartitionsDropped != 0 || len(repo.dropCalls) != 0 {
		t.Fatalf("RunOnce: got %+v, want a no-op pass with zero errors", result)
	}
}

func TestRunOnce_ListErrorIsCountedAndDoesNotPanic(t *testing.T) {
	repo := &fakeRepo{
		partitions: map[string][]HeightPartition{},
		listErr:    map[string]error{key("RXT", "PPLNS"): errors.New("connection reset")},
	}
	r := New(repo, Config{Targets: []Target{
		{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 100000},
	}})

	result := r.RunOnce(context.Background())
	if result.Errors != 1 {
		t.Fatalf("RunOnce: got %+v, want 1 error", result)
	}
}

func TestRunOnce_DropErrorIsCountedAndDoesNotPanic(t *testing.T) {
	repo := &fakeRepo{
		partitions: map[string][]HeightPartition{
			key("RXT", "PPLNS"): {{Name: "p1", RangeStart: 0, RangeEnd: 100000}},
		},
		dropErr: map[string]error{key("RXT", "PPLNS"): errors.New("lock timeout")},
	}
	r := New(repo, Config{Targets: []Target{
		{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 50000},
	}})

	result := r.RunOnce(context.Background())
	if result.Errors != 1 || result.PartitionsDropped != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 error / 0 dropped", result)
	}
}

func TestRunOnce_MultipleTargetsAreIndependent(t *testing.T) {
	repo := &fakeRepo{partitions: map[string][]HeightPartition{
		key("RXT", "PPLNS"): {{Name: "p1", RangeStart: 0, RangeEnd: 100000}},
		key("RXM", "SOLO"):  {{Name: "p2", RangeStart: 0, RangeEnd: 100000}, {Name: "p3", RangeStart: 100000, RangeEnd: 200000}},
	}}
	r := New(repo, Config{Targets: []Target{
		{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 200000}, // frontier 100000, cutoff -100000: everything survives
		{Algo: "RXM", PoolType: "SOLO", RetentionBlocks: 100000},  // frontier 200000, cutoff 100000: p2 dropped
	}})

	result := r.RunOnce(context.Background())
	if result.TargetsChecked != 2 || result.PartitionsDropped != 1 || result.Errors != 0 {
		t.Fatalf("RunOnce: got %+v, want 2 checked / 1 dropped / 0 errors", result)
	}
	if len(repo.partitions[key("RXT", "PPLNS")]) != 1 {
		t.Fatalf("RXT/PPLNS partition should have survived, got %+v", repo.partitions[key("RXT", "PPLNS")])
	}
	if len(repo.partitions[key("RXM", "SOLO")]) != 1 {
		t.Fatalf("RXM/SOLO should have exactly 1 surviving partition, got %+v", repo.partitions[key("RXM", "SOLO")])
	}
}

func TestRunLoop_StopsOnContextCancel(t *testing.T) {
	repo := &fakeRepo{partitions: map[string][]HeightPartition{}}
	r := New(repo, Config{
		Targets:      []Target{{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 100000}},
		PollInterval: time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		r.RunLoop(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunLoop did not return after context cancellation")
	}
}

func TestRunLoop_ZeroIntervalExitsImmediately(t *testing.T) {
	repo := &fakeRepo{partitions: map[string][]HeightPartition{}}
	r := New(repo, Config{Targets: []Target{{Algo: "RXT", PoolType: "PPLNS", RetentionBlocks: 100000}}})

	done := make(chan struct{})
	go func() {
		r.RunLoop(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunLoop with PollInterval<=0 should return immediately")
	}
}
