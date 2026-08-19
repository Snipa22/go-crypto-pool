// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"encoding/binary"
	"encoding/hex"
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

	// blockHashSeed is the fixed prefix of the synthetic block hash
	// GetBlockTemplate returns; the real leading bytes matter for
	// nothing here except uniqueness/determinism, since the reference
	// GetJobJSON's job_id is derived from this real BlockHash field
	// (see job.go's jobIDFromBlockHash). A per-call counter is appended
	// so consecutive refreshes in the same test (e.g. two calls at the
	// same height) still get distinct job ids, mirroring how a real
	// base node hands back a genuinely different block hash on every
	// GetNewBlockResult even without a height change (nonce/timestamp
	// jitter, etc.).
	blockHashSeed []byte

	templateCalls atomic.Int64
	tipCalls      atomic.Int64
	submitCalls   atomic.Int64

	getBlockTemplateErr error
	getTipInfoErr       error
	submitBlockErr      error

	lastSubmittedBlock *tari_generated.Block
}

func (f *fakeNodeClient) GetBlockTemplate(_ context.Context, payoutAddress string) (*tari_generated.GetNewBlockResult, error) {
	call := f.templateCalls.Add(1)
	if f.getBlockTemplateErr != nil {
		return nil, f.getBlockTemplateErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	blockHash := f.syntheticBlockHash(call)
	return &tari_generated.GetNewBlockResult{
		BlockHash:       blockHash,
		MergeMiningHash: f.mergeMiningHash,
		Block: &tari_generated.Block{
			Header: &tari_generated.BlockHeader{Height: f.height},
		},
		MinerData: &tari_generated.MinerData{
			TargetDifficulty: f.targetDifficulty,
		},
	}, nil
}

// syntheticBlockHash builds a deterministic, real-shaped (32-byte)
// block hash for test fixtures: blockHashSeed (or a default 32-byte
// filler if unset) with the last 8 bytes overwritten by the refresh
// call counter, so every call to GetBlockTemplate in a test yields a
// distinct hash/job_id even at a fixed height, matching real base node
// behavior.
func (f *fakeNodeClient) syntheticBlockHash(call int64) []byte {
	seed := f.blockHashSeed
	if len(seed) == 0 {
		seed = []byte("default-test-block-hash-32byte!")
	}
	hash := make([]byte, len(seed))
	copy(hash, seed)
	if len(hash) < 8 {
		padded := make([]byte, 8)
		copy(padded, hash)
		hash = padded
	}
	binary.BigEndian.PutUint64(hash[len(hash)-8:], uint64(call))
	return hash
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
	// Real wire job_id derivation check: must be exactly the first 16
	// hex characters of hex(BlockHash) — ported exactly from
	// go-tari-sha3x-solo-stratum's minerTracking.GetJobJSON.
	wantID := hex.EncodeToString(job.BlockHash)[:16]
	if job.ID != wantID {
		t.Errorf("job.ID = %q, want %q (first 16 hex chars of BlockHash)", job.ID, wantID)
	}
	if len(job.ID) != 16 {
		t.Errorf("job.ID length = %d, want 16", len(job.ID))
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

// TestJobMarkNonceUsedRejectsReplay exercises the per-job used-nonce
// tracking ported from go-tari-sha3x-solo-stratum's
// MinerJob.UsedNonces/NonceMutex (minerTracking/structs.go) — required
// to prevent a miner from being credited twice for resubmitting the
// same nonce against the same job. See this task's "what NOT to skip"
// note: unlike XNonce splitting and address-suffix parsing, this
// mechanism DOES carry over, just relocated onto Job (global/shared
// jobs) instead of per-session.
func TestJobMarkNonceUsedRejectsReplay(t *testing.T) {
	job := &Job{ID: "deadbeefdeadbeef"}

	if !job.MarkNonceUsed(42) {
		t.Fatal("first use of a nonce must be reported as newly recorded")
	}
	if job.MarkNonceUsed(42) {
		t.Fatal("replaying the same nonce must be reported as already used")
	}
	if !job.MarkNonceUsed(43) {
		t.Fatal("a different nonce must be independently trackable")
	}
}

func TestJobMarkNonceUsedIsConcurrencySafe(t *testing.T) {
	job := &Job{ID: "deadbeefdeadbeef"}
	var wg sync.WaitGroup
	var accepted atomic.Int64
	const n = 200
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(nonce uint64) {
			defer wg.Done()
			// Every goroutine races to submit the SAME nonce; exactly
			// one must win.
			if job.MarkNonceUsed(7) {
				accepted.Add(1)
			}
		}(7)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Errorf("expected exactly 1 winner racing to mark the same nonce used, got %d", accepted.Load())
	}
}
