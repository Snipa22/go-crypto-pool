// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
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
	// so consecutive calls in the same test (e.g. two different xns at
	// the same height) still get distinct job ids, mirroring how a real
	// base node hands back a genuinely different block hash on every
	// GetNewBlockResult even without a height change (this codebase's
	// real GRPCNodeClient.GetBlockTemplate achieves this via a fresh
	// random coinbase-extra nonce buffer on every call — see node.go's
	// doc comment).
	blockHashSeed []byte

	// vmKey is the synthetic RandomX seed/key GetBlockTemplate returns
	// as GetNewBlockResult.VmKey — only meaningful for RXT tests
	// (job.go's Job.VmKey is populated straight from this field).
	// Empty/unused for SHA3X/C29 test harnesses.
	vmKey []byte

	// powData is the synthetic ProofOfWork.PowData GetBlockTemplate's
	// returned Block.Header.Pow carries — used by RXT tests to exercise
	// createTariMiningBlob's pow.to_bytes()-equivalent segment with
	// non-empty pow_data (a fresh real RXT template's pow_data is
	// typically empty, but the blob construction must handle a
	// nonempty one correctly too).
	powData []byte

	templateCalls atomic.Int64
	tipCalls      atomic.Int64
	submitCalls   atomic.Int64

	getBlockTemplateErr error
	getTipInfoErr       error
	submitBlockErr      error

	lastSubmittedBlock *tari_generated.Block
	lastRequestedAlgo  poolpb.Algo
}

func (f *fakeNodeClient) GetBlockTemplate(_ context.Context, payoutAddress string, algo poolpb.Algo) (*tari_generated.GetNewBlockResult, error) {
	f.lastRequestedAlgo = algo
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
		VmKey:           f.vmKey,
		Block: &tari_generated.Block{
			Header: &tari_generated.BlockHeader{
				Height: f.height,
				Pow:    &tari_generated.ProofOfWork{PowData: f.powData},
			},
		},
		MinerData: &tari_generated.MinerData{
			TargetDifficulty: f.targetDifficulty,
		},
	}, nil
}

// syntheticBlockHash builds a deterministic, real-shaped (32-byte)
// block hash for test fixtures: blockHashSeed (or a default 32-byte
// filler if unset) with the last 8 bytes overwritten by the per-call
// counter, so every call to GetBlockTemplate in a test yields a
// distinct hash/job_id even at a fixed height, matching real base node
// behavior (real GetBlockTemplate randomizes coinbase-extra per call —
// see node.go).
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
	binary.BigEndian.PutUint64(hash[:8], uint64(call))
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

func TestJobForXNBuildsJobFromTemplate(t *testing.T) {
	node := &fakeNodeClient{height: 100, targetDifficulty: 999999, mergeMiningHash: []byte{1, 2, 3}}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-address",
		StaticDifficulty: 5000,
	})

	job, err := jm.JobForXN(context.Background(), "aabb")
	if err != nil {
		t.Fatalf("JobForXN returned error: %v", err)
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
	if len(job.ID) != 16 {
		t.Errorf("job.ID length = %d, want 16", len(job.ID))
	}
	got, ok := jm.GetJob(job.ID)
	if !ok || got != job {
		t.Error("GetJob(id) should return the job by id")
	}
	if node.templateCalls.Load() != 1 {
		t.Errorf("expected 1 template call, got %d", node.templateCalls.Load())
	}
}

func TestJobForXNPropagatesError(t *testing.T) {
	node := &fakeNodeClient{getBlockTemplateErr: errors.New("node unreachable")}
	jm := NewJobManager(JobManagerConfig{Node: node})

	if _, err := jm.JobForXN(context.Background(), "aabb"); err == nil {
		t.Fatal("expected JobForXN to propagate the node error")
	}
}

// TestJobForXNGivesDifferentXNsDifferentJobs is the core per-xn
// requirement: two different sessions (different xn values) must get
// two different jobs (different job_id / different header material) at
// the SAME height, mirroring go-tari-sha3x-solo-stratum's
// GetBlockWithXN — a genuinely non-overlapping search space per xn,
// not a shared global job.
func TestJobForXNGivesDifferentXNsDifferentJobs(t *testing.T) {
	node := &fakeNodeClient{height: 42, mergeMiningHash: []byte("shared-height-merge-hash-32byte")}
	jm := NewJobManager(JobManagerConfig{Node: node, PayoutAddress: "solo-address"})

	jobA, err := jm.JobForXN(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForXN(aaaa): %v", err)
	}
	jobB, err := jm.JobForXN(context.Background(), "bbbb")
	if err != nil {
		t.Fatalf("JobForXN(bbbb): %v", err)
	}

	if jobA.ID == jobB.ID {
		t.Errorf("expected different xns to get different job ids, both got %q", jobA.ID)
	}
	if jobA == jobB {
		t.Error("expected different xns to get distinct *Job pointers")
	}
	if node.templateCalls.Load() != 2 {
		t.Errorf("expected 2 independent GetBlockTemplate calls (one per new xn), got %d", node.templateCalls.Load())
	}
}

// TestJobForXNIsStableForSameXNUntilInvalidated: the SAME xn requesting
// a job twice in a row (e.g. two getjob calls) must get the SAME cached
// Job — not a freshly-regenerated one — until the cache is invalidated
// by tip movement, mirroring GetBlockWithXN's "already claimed" reuse
// behavior.
func TestJobForXNIsStableForSameXNUntilInvalidated(t *testing.T) {
	node := &fakeNodeClient{height: 7}
	jm := NewJobManager(JobManagerConfig{Node: node, PayoutAddress: "solo-address"})

	first, err := jm.JobForXN(context.Background(), "cccc")
	if err != nil {
		t.Fatalf("JobForXN: %v", err)
	}
	second, err := jm.JobForXN(context.Background(), "cccc")
	if err != nil {
		t.Fatalf("JobForXN (repeat): %v", err)
	}
	if first != second {
		t.Error("expected repeat JobForXN calls with the same xn to return the SAME cached Job")
	}
	if node.templateCalls.Load() != 1 {
		t.Errorf("expected exactly 1 template call across two repeat requests for the same xn, got %d", node.templateCalls.Load())
	}

	// Tip moves -> cache invalidated -> the same xn must now get a
	// brand new, regenerated Job.
	jm.InvalidateAll()

	third, err := jm.JobForXN(context.Background(), "cccc")
	if err != nil {
		t.Fatalf("JobForXN (post-invalidate): %v", err)
	}
	if third == first {
		t.Error("expected a new Job to be generated for the same xn after cache invalidation")
	}
	if node.templateCalls.Load() != 2 {
		t.Errorf("expected a second template call after invalidation, got %d", node.templateCalls.Load())
	}

	// The stale, pre-invalidation job_id must no longer be resolvable
	// via GetJob.
	if _, ok := jm.GetJob(first.ID); ok {
		t.Error("expected the pre-invalidation job id to be gone from GetJob after InvalidateAll")
	}
	if _, ok := jm.GetJob(third.ID); !ok {
		t.Error("expected the post-invalidation job id to be resolvable via GetJob")
	}
}

func TestJobManagerNotifiesSubscribersOnInvalidation(t *testing.T) {
	node := &fakeNodeClient{height: 1}
	jm := NewJobManager(JobManagerConfig{Node: node})

	var received atomic.Int64
	unsub := jm.Subscribe(func() {
		received.Add(1)
	})
	defer unsub()

	jm.InvalidateAll()
	if received.Load() != 1 {
		t.Errorf("subscriber called %d times, want 1", received.Load())
	}

	unsub()
	jm.InvalidateAll()
	if received.Load() != 1 {
		t.Errorf("subscriber should not fire after unsubscribe, got %d calls", received.Load())
	}
}

func TestJobManagerStartInvalidatesOnTimerAndTipMovement(t *testing.T) {
	node := &fakeNodeClient{height: 1}
	jm := NewJobManager(JobManagerConfig{
		Node:            node,
		RefreshInterval: 24 * time.Hour, // effectively disabled for this test
		TipPollInterval: 10 * time.Millisecond,
	})

	job, err := jm.JobForXN(context.Background(), "dddd")
	if err != nil {
		t.Fatalf("initial JobForXN: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)

	// No tip movement yet: give the poll loop a couple of ticks and
	// confirm the cached job for "dddd" is still being served (not
	// regenerated) — i.e. no unnecessary invalidation without tip
	// movement.
	time.Sleep(50 * time.Millisecond)
	stillCached, ok := jm.GetJob(job.ID)
	if !ok || stillCached != job {
		t.Error("expected the cached job to survive tip-poll ticks with no tip movement")
	}

	// Move the tip forward; the poll loop should notice within ~1-2
	// ticks and invalidate the cache instead of waiting for the (long)
	// RefreshInterval.
	node.setHeight(2)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jm.GetJob(job.ID); !ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := jm.GetJob(job.ID); ok {
		t.Fatal("expected tip movement to invalidate the per-xn job cache")
	}

	newJob, err := jm.JobForXN(context.Background(), "dddd")
	if err != nil {
		t.Fatalf("JobForXN after tip-triggered invalidation: %v", err)
	}
	if newJob.Height != 2 {
		t.Errorf("newJob.Height = %d, want 2 after tip-triggered invalidation", newJob.Height)
	}
}

func TestJobManagerProbe(t *testing.T) {
	node := &fakeNodeClient{height: 5}
	jm := NewJobManager(JobManagerConfig{Node: node, PayoutAddress: "solo-address"})

	if err := jm.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// Probe must not cache anything under any xn.
	if _, ok := jm.GetJob(""); ok {
		t.Error("Probe must not populate the job cache")
	}
}

func TestJobManagerProbePropagatesError(t *testing.T) {
	node := &fakeNodeClient{getBlockTemplateErr: errors.New("node unreachable")}
	jm := NewJobManager(JobManagerConfig{Node: node})

	if err := jm.Probe(context.Background()); err == nil {
		t.Fatal("expected Probe to propagate the node error")
	}
}

// TestJobMarkNonceUsedRejectsReplay exercises the per-job used-nonce
// tracking ported from go-tari-sha3x-solo-stratum's
// MinerJob.UsedNonces/NonceMutex (minerTracking/structs.go) — required
// to prevent a miner from being credited twice for resubmitting the
// same nonce against the same job. Since jobs are now per-xn, this
// dedup set is naturally per-xn too.
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

// TestJobForXNConcurrentFirstRequestsForSameXNDoNotDuplicate confirms
// the genMu double-check-locking pattern: many goroutines racing to be
// the FIRST requester of a brand new xn must all observe the same
// resulting Job, and only one real template fetch should occur.
func TestJobForXNConcurrentFirstRequestsForSameXNDoNotDuplicate(t *testing.T) {
	node := &fakeNodeClient{height: 9}
	jm := NewJobManager(JobManagerConfig{Node: node, PayoutAddress: "solo-address"})

	const n = 50
	results := make([]*Job, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			job, err := jm.JobForXN(context.Background(), "eeee")
			if err != nil {
				t.Errorf("JobForXN: %v", err)
				return
			}
			results[idx] = job
		}(i)
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("expected all concurrent first-requesters of the same xn to get the same Job, index %d differed", i)
		}
	}
	if node.templateCalls.Load() != 1 {
		t.Errorf("expected exactly 1 template call despite %d concurrent first-requesters, got %d", n, node.templateCalls.Load())
	}
}
