// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// fakeNodeClient is a NodeClient test double: no real GRPC, no real
// Tari base node. It lets job-management/template-refresh logic be
// tested deterministically. Its GetBlockTemplate/BuildCandidateBlock
// build the SAME real Tari-shaped Job/candidate data
// (tariJobFromResult/tariBuildCandidateBlock, node.go) the production
// GRPCNodeClient does, so session-level tests exercise the exact real
// difficulty/candidate-construction logic, not a shadow reimplementation
// of it — only the RPC transport itself (nodeGRPC's package-level
// singleton) is faked.
type fakeNodeClient struct {
	mu sync.Mutex

	height           uint64
	targetDifficulty uint64
	mergeMiningHash  []byte

	// blockHashSeed is the fixed prefix of the synthetic block hash
	// GetBlockTemplate returns; the real leading bytes matter for
	// nothing here except giving each call a distinct BlockHash the
	// same way a real base node would (this codebase's real
	// GRPCNodeClient.GetBlockTemplate achieves this via a fresh
	// random coinbase-extra nonce buffer on every call — see node.go's
	// doc comment). tariJobFromResult itself now mints job.ID as a
	// purely random, opaque token (newRandomHexID) rather than
	// deriving it from BlockHash (see that function's doc comment for
	// why a content-derived ID was removed), so distinct BlockHash
	// values are no longer what guarantees distinct job IDs here —
	// they're kept distinct anyway purely to keep this fake's overall
	// synthetic template shape realistic.
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

func (f *fakeNodeClient) GetBlockTemplate(_ context.Context, payoutAddress string, algo poolpb.Algo) (*Job, error) {
	f.lastRequestedAlgo = algo
	call := f.templateCalls.Add(1)
	if f.getBlockTemplateErr != nil {
		return nil, f.getBlockTemplateErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	blockHash := f.syntheticBlockHash(call)
	result := &tari_generated.GetNewBlockResult{
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
	}
	return tariJobFromResult(result, algo)
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

func (f *fakeNodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	f.tipCalls.Add(1)
	if f.getTipInfoErr != nil {
		return 0, f.getTipInfoErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.height, nil
}

func (f *fakeNodeClient) BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (uint64, any, error) {
	return tariBuildCandidateBlock(job, nonce, proof)
}

func (f *fakeNodeClient) SubmitBlock(_ context.Context, candidate any) error {
	f.submitCalls.Add(1)
	block, ok := candidate.(*tari_generated.Block)
	if !ok {
		return errors.New("fakeNodeClient.SubmitBlock: candidate is not a *tari_generated.Block")
	}
	f.mu.Lock()
	f.lastSubmittedBlock = block
	f.mu.Unlock()
	if f.submitBlockErr != nil {
		return f.submitBlockErr
	}
	return nil
}

func (f *fakeNodeClient) setHeight(h uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.height = h
}

// TemplateBytesForRelay/JobFromTemplateBytes implement solo.NodeClient
// for this test double using the SAME real, production reconstruction
// path direct.NodeClient uses (proto.Marshal/Unmarshal of the real
// *tari_generated.GetNewBlockResult + this package's own
// tariJobFromResult) -- so job_relay_test.go's adoption tests exercise
// genuine (de)serialization, not a shadow/simplified stand-in.
func (f *fakeNodeClient) TemplateBytesForRelay(job *Job) ([]byte, error) {
	if job == nil {
		return nil, nil
	}
	result, ok := job.TemplateData.(*tari_generated.GetNewBlockResult)
	if !ok || result == nil {
		return nil, nil
	}
	return proto.Marshal(result)
}

func (f *fakeNodeClient) JobFromTemplateBytes(data []byte, algo poolpb.Algo) (*Job, error) {
	var result tari_generated.GetNewBlockResult
	if err := proto.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("fakeNodeClient: JobFromTemplateBytes: unmarshal: %w", err)
	}
	return tariJobFromResult(&result, algo)
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

// TestJobForXNLogsNewBlockTemplateFetchUnconditionally confirms the
// always-on (non-Debug-gated) "solo: new block template fetched" line
// added alongside the existing jm.cfg.Debug.Debugf line: it must
// appear on jm.logger even with debug logging disabled/unconfigured,
// and must report the correct algo/height/network_target_difficulty
// for the template that was actually just fetched.
func TestJobForXNLogsNewBlockTemplateFetchUnconditionally(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	node := &fakeNodeClient{height: 123, targetDifficulty: 456789, mergeMiningHash: []byte{1, 2, 3}}
	jm := NewJobManager(JobManagerConfig{
		Node:          node,
		PayoutAddress: "solo-address",
		Logger:        logger,
		// Debug deliberately left nil/disabled: this new log line
		// must not depend on debug logging being enabled.
	})

	job, err := jm.JobForXN(context.Background(), "aabb")
	if err != nil {
		t.Fatalf("JobForXN returned error: %v", err)
	}

	got := buf.String()
	want := "solo: new block template fetched (algo=sha3x height=123 network_target_difficulty=456789)"
	if !strings.Contains(got, want) {
		t.Fatalf("expected log output to contain %q, got:\n%s", want, got)
	}
	if job.NetworkTargetDifficulty != 456789 {
		t.Errorf("NetworkTargetDifficulty = %d, want 456789", job.NetworkTargetDifficulty)
	}

	// A repeat JobForXN call for the same (already-cached) xn must
	// NOT log another "new block template fetched" line -- this is a
	// cache hit, not a new fetch.
	buf.Reset()
	if _, err := jm.JobForXN(context.Background(), "aabb"); err != nil {
		t.Fatalf("JobForXN (repeat): %v", err)
	}
	if got := buf.String(); strings.Contains(got, "new block template fetched") {
		t.Errorf("expected no new-template-fetched log line on a cache hit, got:\n%s", got)
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
	jm := NewJobManager(JobManagerConfig{Node: node, PayoutAddress: "solo-test-address"})

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
	jm.InvalidateAll(TemplateSourceLocal)

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
	var lastSource atomic.Value
	unsub := jm.Subscribe(func(source string) {
		received.Add(1)
		lastSource.Store(source)
	})
	defer unsub()

	jm.InvalidateAll(TemplateSourceLocal)
	if received.Load() != 1 {
		t.Errorf("subscriber called %d times, want 1", received.Load())
	}
	if got := lastSource.Load(); got != TemplateSourceLocal {
		t.Errorf("subscriber received source = %v, want %q", got, TemplateSourceLocal)
	}

	unsub()
	jm.InvalidateAll(TemplateSourceLocal)
	if received.Load() != 1 {
		t.Errorf("subscriber should not fire after unsubscribe, got %d calls", received.Load())
	}
}

// TestJobManagerSubscribeReceivesRealSource proves Subscribe's
// callback receives the real, correct TemplateSource* value for
// EACH of InvalidateAll's distinct real trigger kinds this brief
// requires coverage for: a tip-poll-triggered/refresh-triggered
// (both "local") invalidation, and a template-relay-triggered
// ("relay") invalidation -- driven via the real tipPollLoop/
// refreshLoop/startTemplateRelaySubscription machinery (Start),
// not by calling InvalidateAll directly, so this genuinely exercises
// job.go's own 3 real call sites end-to-end.
func TestJobManagerSubscribeReceivesRealSource(t *testing.T) {
	url, shutdown := startEmbeddedNATSServerForJobTest(t)
	defer shutdown()

	jmRelay := relay.NewRelay(relay.Config{URL: url})
	defer jmRelay.Close()
	externalRelay := relay.NewRelay(relay.Config{URL: url})
	defer externalRelay.Close()
	if !jmRelay.Enabled() || !externalRelay.Enabled() {
		t.Fatalf("expected both relays to be Enabled() after connecting to a real NATS server at %s", url)
	}

	node := &fakeNodeClient{height: 100}
	jm := NewJobManager(JobManagerConfig{
		Node: node, PayoutAddress: "solo-test-address",
		Algo: poolpb.Algo_ALGO_SHA3X, Network: "testnet",
		RefreshInterval: 24 * time.Hour, // disabled: only tip-poll and the relay subscription drive this test
		TipPollInterval: 20 * time.Millisecond,
	})
	jm.cfg.Relay = jmRelay

	sources := make(chan string, 8)
	unsub := jm.Subscribe(func(source string) { sources <- source })
	defer unsub()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)
	time.Sleep(150 * time.Millisecond) // let the real NATS subscription land

	// Genuine local tip increase -> "local".
	node.setHeight(101)
	select {
	case source := <-sources:
		if source != TemplateSourceLocal {
			t.Errorf("tip-poll-triggered invalidation source = %q, want %q", source, TemplateSourceLocal)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected a tip-poll-triggered invalidation within 5s")
	}

	// Externally-received template relay message -> "relay".
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 200, Hash: "external-source-test-hash",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}
	deadline := time.After(5 * time.Second)
	found := false
	for !found {
		select {
		case source := <-sources:
			if source == TemplateSourceRelay {
				found = true
				break
			}
			// A stray "local" from a subsequent tip-poll tick is
			// possible (TipPollInterval is short); keep waiting for
			// the relay-triggered one specifically.
		case <-deadline:
			t.Fatal("expected a relay-triggered invalidation (source=\"relay\") within 5s")
		}
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
	jm := NewJobManager(JobManagerConfig{Node: node, PayoutAddress: "solo-test-address"})

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

// TestJobMarkNonceUsedCapsDistinctNonceGrowth is the required Fix 11
// test (DISPATCH_BRIEF.md 2026-09-10): once maxTrackedNoncesPerJob
// distinct nonces have been recorded against one Job, a genuinely NEW
// nonce beyond the cap must be rejected (never grow the map further),
// while a REPLAY of an already-tracked nonce must still be correctly
// caught as a replay, not silently allowed through.
func TestJobMarkNonceUsedCapsDistinctNonceGrowth(t *testing.T) {
	job := &Job{ID: "deadbeefdeadbeef"}

	for i := uint64(0); i < maxTrackedNoncesPerJob; i++ {
		if !job.MarkNonceUsed(i) {
			t.Fatalf("nonce %d (below the cap) must be reported as newly recorded", i)
		}
	}
	if got := len(job.usedNonces); got != maxTrackedNoncesPerJob {
		t.Fatalf("expected exactly %d tracked nonces at the cap, got %d", maxTrackedNoncesPerJob, got)
	}

	// A genuinely NEW nonce beyond the cap must be rejected -- and,
	// critically, must NOT have grown the map any further.
	if job.MarkNonceUsed(maxTrackedNoncesPerJob) {
		t.Fatal("a genuinely new nonce beyond the cap must be rejected, not newly recorded")
	}
	if got := len(job.usedNonces); got != maxTrackedNoncesPerJob {
		t.Fatalf("expected the tracked-nonce count to stay bounded at %d after a beyond-cap rejection, got %d", maxTrackedNoncesPerJob, got)
	}

	// A REPLAY of an already-tracked nonce (recorded before the cap
	// was ever reached) must still be correctly caught as a replay
	// even after the cap has been hit -- not silently allowed
	// through.
	if job.MarkNonceUsed(0) {
		t.Fatal("a replay of an already-tracked nonce must still be rejected once the cap has been reached, not silently allowed through")
	}
}

// TestJobForXNConcurrentFirstRequestsForSameXNDoNotDuplicate confirms
// the genMu double-check-locking pattern: many goroutines racing to be
// the FIRST requester of a brand new xn must all observe the same
// resulting Job, and only one real template fetch should occur.
func TestJobForXNConcurrentFirstRequestsForSameXNDoNotDuplicate(t *testing.T) {
	node := &fakeNodeClient{height: 9}
	jm := NewJobManager(JobManagerConfig{Node: node, PayoutAddress: "solo-test-address"})

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

// TestIsBetterCandidate covers isBetterCandidate's full documented
// priority order (relay-template-adoption brief, section 4's required
// coverage): higher height wins regardless of size; equal height +
// larger size wins; equal height + equal/smaller size does not adopt;
// lower height never wins regardless of size.
func TestIsBetterCandidate(t *testing.T) {
	tests := []struct {
		name                           string
		currentHeight, candidateHeight uint64
		currentSize, candidateSize     int
		want                           bool
	}{
		{
			name:          "higher height wins with smaller size",
			currentHeight: 100, candidateHeight: 101,
			currentSize: 10000, candidateSize: 1,
			want: true,
		},
		{
			name:          "higher height wins with larger size",
			currentHeight: 100, candidateHeight: 101,
			currentSize: 1, candidateSize: 10000,
			want: true,
		},
		{
			name:          "higher height wins with equal size",
			currentHeight: 100, candidateHeight: 101,
			currentSize: 500, candidateSize: 500,
			want: true,
		},
		{
			name:          "equal height, larger size wins",
			currentHeight: 100, candidateHeight: 100,
			currentSize: 500, candidateSize: 501,
			want: true,
		},
		{
			name:          "equal height, equal size does not adopt",
			currentHeight: 100, candidateHeight: 100,
			currentSize: 500, candidateSize: 500,
			want: false,
		},
		{
			name:          "equal height, smaller size does not adopt",
			currentHeight: 100, candidateHeight: 100,
			currentSize: 500, candidateSize: 499,
			want: false,
		},
		{
			name:          "lower height never wins despite much larger size",
			currentHeight: 100, candidateHeight: 99,
			currentSize: 1, candidateSize: 999999,
			want: false,
		},
		{
			name:          "lower height never wins with equal size",
			currentHeight: 100, candidateHeight: 50,
			currentSize: 500, candidateSize: 500,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBetterCandidate(tt.currentHeight, tt.candidateHeight, tt.currentSize, tt.candidateSize)
			if got != tt.want {
				t.Errorf("isBetterCandidate(currentHeight=%d, candidateHeight=%d, currentSize=%d, candidateSize=%d) = %v, want %v",
					tt.currentHeight, tt.candidateHeight, tt.currentSize, tt.candidateSize, got, tt.want)
			}
		})
	}
}
