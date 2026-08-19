// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
)

// fakeNodeClient is a NodeClient test double: no real GRPC, no real
// Tari base node. It lets job-management/template-refresh logic be
// tested deterministically.
type fakeNodeClient struct {
	mu sync.Mutex

	height           uint64
	targetDifficulty uint64
	mergeMiningHash  []byte

	templateCalls atomic.Int64
	tipCalls      atomic.Int64
	submitCalls   atomic.Int64

	getBlockTemplateErr error
	getTipInfoErr       error
	submitBlockErr      error

	lastSubmittedBlock *tari_generated.Block
}

func (f *fakeNodeClient) GetBlockTemplate(_ context.Context, payoutAddress string) (*tari_generated.GetNewBlockResult, error) {
	f.templateCalls.Add(1)
	if f.getBlockTemplateErr != nil {
		return nil, f.getBlockTemplateErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return &tari_generated.GetNewBlockResult{
		MergeMiningHash: f.mergeMiningHash,
		Block: &tari_generated.Block{
			Header: &tari_generated.BlockHeader{Height: f.height},
		},
		MinerData: &tari_generated.MinerData{
			TargetDifficulty: f.targetDifficulty,
		},
	}, nil
}

func (f *fakeNodeClient) GetTipInfo(_ context.Context) (*tari_generated.TipInfoResponse, error) {
	f.tipCalls.Add(1)
	if f.getTipInfoErr != nil {
		return nil, f.getTipInfoErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return &tari_generated.TipInfoResponse{
		Metadata: &tari_generated.MetaData{BestBlockHeight: f.height},
	}, nil
}

func (f *fakeNodeClient) SubmitBlock(_ context.Context, block *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	f.submitCalls.Add(1)
	f.mu.Lock()
	f.lastSubmittedBlock = block
	f.mu.Unlock()
	if f.submitBlockErr != nil {
		return nil, f.submitBlockErr
	}
	return &tari_generated.SubmitBlockResponse{}, nil
}

func (f *fakeNodeClient) setHeight(h uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.height = h
}

func TestJobManagerRefreshBuildsJobFromTemplate(t *testing.T) {
	node := &fakeNodeClient{height: 100, targetDifficulty: 999999, mergeMiningHash: []byte{1, 2, 3}}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-address",
		StaticDifficulty: 5000,
	})

	job, err := jm.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if job.Height != 100 {
		t.Errorf("Height = %d, want 100", job.Height)
	}
	if job.StaticDifficulty != 5000 {
		t.Errorf("StaticDifficulty = %d, want 5000", job.StaticDifficulty)
	}
	if job.NetworkTargetDifficulty != 999999 {
		t.Errorf("NetworkTargetDifficulty = %d, want 999999", job.NetworkTargetDifficulty)
	}
	if string(job.Header) != "\x01\x02\x03" {
		t.Errorf("Header = %v, want [1 2 3]", job.Header)
	}
	if jm.Current() != job {
		t.Error("Current() should return the just-refreshed job")
	}
	got, ok := jm.GetJob(job.ID)
	if !ok || got != job {
		t.Error("GetJob(id) should return the current job by id")
	}
	if node.templateCalls.Load() != 1 {
		t.Errorf("expected 1 template call, got %d", node.templateCalls.Load())
	}
}

func TestJobManagerRefreshPropagatesError(t *testing.T) {
	node := &fakeNodeClient{getBlockTemplateErr: errors.New("node unreachable")}
	jm := NewJobManager(JobManagerConfig{Node: node})

	if _, err := jm.Refresh(context.Background()); err == nil {
		t.Fatal("expected Refresh to propagate the node error")
	}
	if jm.Current() != nil {
		t.Error("Current() should remain nil after a failed refresh")
	}
}

func TestJobManagerNotifiesSubscribersOnRefresh(t *testing.T) {
	node := &fakeNodeClient{height: 1}
	jm := NewJobManager(JobManagerConfig{Node: node})

	var received atomic.Int64
	unsub := jm.Subscribe(func(j *Job) {
		received.Add(1)
	})
	defer unsub()

	if _, err := jm.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if received.Load() != 1 {
		t.Errorf("subscriber called %d times, want 1", received.Load())
	}

	unsub()
	if _, err := jm.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if received.Load() != 1 {
		t.Errorf("subscriber should not fire after unsubscribe, got %d calls", received.Load())
	}
}

func TestJobManagerStartRefreshesOnTimerAndTipMovement(t *testing.T) {
	node := &fakeNodeClient{height: 1}
	jm := NewJobManager(JobManagerConfig{
		Node:            node,
		RefreshInterval: 24 * time.Hour, // effectively disabled for this test
		TipPollInterval: 10 * time.Millisecond,
	})

	if _, err := jm.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh: %v", err)
	}
	initialTemplateCalls := node.templateCalls.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)

	// No tip movement yet: give the poll loop a couple of ticks and
	// confirm it did NOT trigger an extra template fetch.
	time.Sleep(50 * time.Millisecond)
	if node.templateCalls.Load() != initialTemplateCalls {
		t.Errorf("expected no refresh without tip movement, got %d extra template calls", node.templateCalls.Load()-initialTemplateCalls)
	}

	// Move the tip forward; the poll loop should notice within ~1-2 ticks
	// and trigger an immediate refresh instead of waiting for the (long)
	// RefreshInterval.
	node.setHeight(2)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if node.templateCalls.Load() > initialTemplateCalls {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if node.templateCalls.Load() <= initialTemplateCalls {
		t.Fatal("expected tip movement to trigger an immediate job refresh")
	}
	if jm.Current().Height != 2 {
		t.Errorf("Current().Height = %d, want 2 after tip-triggered refresh", jm.Current().Height)
	}
}
