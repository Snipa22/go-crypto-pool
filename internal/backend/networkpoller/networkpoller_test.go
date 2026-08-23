package networkpoller

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	state State
	err   error
}

func (f *fakeSource) FetchNetworkState(_ context.Context) (State, error) {
	if f.err != nil {
		return State{}, f.err
	}
	return f.state, nil
}

type fakeRepo struct {
	upserted map[string]RepoState
	err      error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{upserted: map[string]RepoState{}}
}

func (f *fakeRepo) UpsertNetworkState(_ context.Context, algo, network string, state RepoState) error {
	if f.err != nil {
		return f.err
	}
	f.upserted[algo+"/"+network] = state
	return nil
}

func TestRunOnce_Success(t *testing.T) {
	height := int64(12345)
	hr := 42.0
	repo := newFakeRepo()
	p := New(repo, Config{
		Targets: []Target{
			{Algo: "RXT", Network: "TESTNET", Source: &fakeSource{state: State{Height: height, EstimatedHashrateHS: &hr, BestBlockHash: "abcd"}}},
		},
	})

	result := p.RunOnce(context.Background())
	if result.Fetched != 1 || result.Errors != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	got, ok := repo.upserted["RXT/TESTNET"]
	if !ok {
		t.Fatalf("expected an upserted network_state row for RXT/TESTNET")
	}
	if got.Height != height {
		t.Fatalf("height = %d, want %d", got.Height, height)
	}
	if got.EstimatedHashrateHS == nil || *got.EstimatedHashrateHS != hr {
		t.Fatalf("estimated hashrate = %v, want %v", got.EstimatedHashrateHS, hr)
	}
	if got.Source == "" {
		t.Fatalf("expected a non-empty source label")
	}
}

func TestRunOnce_FetchError(t *testing.T) {
	repo := newFakeRepo()
	p := New(repo, Config{
		Targets: []Target{
			{Algo: "RXM", Network: "TESTNET", Source: &fakeSource{err: errors.New("rpc down")}},
		},
	})

	result := p.RunOnce(context.Background())
	if result.Fetched != 0 || result.Errors != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(repo.upserted) != 0 {
		t.Fatalf("expected no upsert on fetch error, got %+v", repo.upserted)
	}
}

func TestRunOnce_UpsertError(t *testing.T) {
	repo := newFakeRepo()
	repo.err = errors.New("db down")
	p := New(repo, Config{
		Targets: []Target{
			{Algo: "RXM", Network: "TESTNET", Source: &fakeSource{state: State{Height: 1}}},
		},
	})

	result := p.RunOnce(context.Background())
	if result.Fetched != 0 || result.Errors != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunOnce_MultipleTargetsIndependent(t *testing.T) {
	repo := newFakeRepo()
	p := New(repo, Config{
		Targets: []Target{
			{Algo: "RXT", Network: "TESTNET", Source: &fakeSource{err: errors.New("down")}},
			{Algo: "RXM", Network: "TESTNET", Source: &fakeSource{state: State{Height: 99}}},
		},
	})

	result := p.RunOnce(context.Background())
	if result.Fetched != 1 || result.Errors != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, ok := repo.upserted["RXM/TESTNET"]; !ok {
		t.Fatalf("expected RXM/TESTNET to be upserted despite RXT failing")
	}
}

func TestRunLoop_PollIntervalZero_NoOp(t *testing.T) {
	repo := newFakeRepo()
	p := New(repo, Config{PollInterval: 0})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	p.RunLoop(ctx) // should return immediately, not hang
}

func TestRunLoop_RunsAtLeastOnce(t *testing.T) {
	repo := newFakeRepo()
	p := New(repo, Config{
		PollInterval: time.Hour,
		Targets: []Target{
			{Algo: "RXT", Network: "TESTNET", Source: &fakeSource{state: State{Height: 1}}},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p.RunLoop(ctx)
	if _, ok := repo.upserted["RXT/TESTNET"]; !ok {
		t.Fatalf("expected RunLoop's immediate startup pass to have upserted a row")
	}
}
