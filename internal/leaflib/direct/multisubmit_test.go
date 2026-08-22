// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
)

// fakeTimedBlockClient is a blockSubmitClient test double that sleeps
// for a fixed, real, measurable duration before responding, so tests
// can PROVE genuine parallel dispatch (total elapsed time close to one
// node's own delay, not delay*N) rather than merely trusting the
// implementation reads as parallel.
type fakeTimedBlockClient struct {
	delay    time.Duration
	accept   bool
	err      error
	calls    atomic.Int64
	startedC chan struct{} // optional: signalled the instant SubmitBlock is entered
}

func (f *fakeTimedBlockClient) SubmitBlock(_ *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	f.calls.Add(1)
	if f.startedC != nil {
		f.startedC <- struct{}{}
	}
	time.Sleep(f.delay)
	if !f.accept {
		if f.err != nil {
			return nil, f.err
		}
		return nil, errors.New("rejected")
	}
	return &tari_generated.SubmitBlockResponse{}, nil
}

func (f *fakeTimedBlockClient) Close() error { return nil }

// TestMultiNodeSubmitterDispatchesInParallel is the required real
// parallel-dispatch timing proof: 5 fake clients each sleep 200ms
// before responding. If dispatch were sequential, SubmitBlock would
// take at least 5*200ms=1s; genuine parallel dispatch keeps the whole
// call well under that (asserted at 600ms, a generous margin above
// the real ~200ms expected elapsed time, to absorb CI/test-runner
// scheduling jitter without ever being able to pass a sequential
// implementation).
func TestMultiNodeSubmitterDispatchesInParallel(t *testing.T) {
	const (
		nodeCount = 5
		delay     = 200 * time.Millisecond
	)
	clients := make(map[string]blockSubmitClient, nodeCount)
	for i := 0; i < nodeCount; i++ {
		clients[fmt.Sprintf("node-%d:18102", i)] = &fakeTimedBlockClient{delay: delay, accept: true}
	}
	m := newMultiNodeSubmitterForTest(clients, discardLogger())

	start := time.Now()
	results, ok := m.SubmitBlock(context.Background(), &tari_generated.Block{})
	elapsed := time.Since(start)

	if !ok {
		t.Fatalf("expected success (all nodes accept), got ok=false, results=%v", results)
	}
	if len(results) != nodeCount {
		t.Fatalf("expected %d results, got %d", nodeCount, len(results))
	}
	for _, r := range results {
		if !r.Accepted {
			t.Errorf("node %s: expected Accepted=true, got err=%v", r.Address, r.Err)
		}
	}

	// The real proof: N*delay would be 1s for 5 nodes; genuine
	// parallel dispatch keeps total elapsed close to a SINGLE delay
	// (~200ms). 600ms is a generous upper bound that a correct
	// parallel implementation will always clear, and that NO
	// sequential implementation (which would take >=1s here) can ever
	// satisfy.
	maxAllowed := 600 * time.Millisecond
	if elapsed >= maxAllowed {
		t.Fatalf("SubmitBlock took %v for %d nodes at %v delay each — expected well under %v if dispatch is genuinely parallel (sequential dispatch would take >=%v)", elapsed, nodeCount, delay, maxAllowed, time.Duration(nodeCount)*delay)
	}
	t.Logf("parallel dispatch of %d nodes (each %v delay) completed in %v (sequential would be >=%v)", nodeCount, delay, elapsed, time.Duration(nodeCount)*delay)
}

// TestMultiNodeSubmitterAtLeastOneAcceptanceIsSuccess confirms the
// documented "at least one acceptance = overall success" semantics
// with a real mix of accepting/rejecting/erroring fake nodes.
func TestMultiNodeSubmitterAtLeastOneAcceptanceIsSuccess(t *testing.T) {
	clients := map[string]blockSubmitClient{
		"accept-node:1": &fakeTimedBlockClient{delay: 5 * time.Millisecond, accept: true},
		"reject-node:1": &fakeTimedBlockClient{delay: 5 * time.Millisecond, accept: false},
		"error-node:1":  &fakeTimedBlockClient{delay: 5 * time.Millisecond, accept: false, err: errors.New("connection refused")},
	}
	m := newMultiNodeSubmitterForTest(clients, discardLogger())

	results, ok := m.SubmitBlock(context.Background(), &tari_generated.Block{})
	if !ok {
		t.Fatalf("expected success since at least one node accepted, got ok=false, results=%v", results)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 individual results, got %d", len(results))
	}

	var acceptedCount, rejectedCount int
	for _, r := range results {
		if r.Accepted {
			acceptedCount++
		} else {
			rejectedCount++
			if r.Err == nil {
				t.Errorf("node %s: expected a non-nil error on a rejected/failed result", r.Address)
			}
		}
	}
	if acceptedCount != 1 {
		t.Errorf("expected exactly 1 accepted result, got %d", acceptedCount)
	}
	if rejectedCount != 2 {
		t.Errorf("expected exactly 2 rejected/errored results, got %d", rejectedCount)
	}
}

// TestMultiNodeSubmitterAllNodesFailingIsOverallFailure confirms
// success=false when every configured node rejects/errors.
func TestMultiNodeSubmitterAllNodesFailingIsOverallFailure(t *testing.T) {
	clients := map[string]blockSubmitClient{
		"reject-node-a:1": &fakeTimedBlockClient{delay: 5 * time.Millisecond, accept: false},
		"reject-node-b:1": &fakeTimedBlockClient{delay: 5 * time.Millisecond, accept: false},
	}
	m := newMultiNodeSubmitterForTest(clients, discardLogger())

	results, ok := m.SubmitBlock(context.Background(), &tari_generated.Block{})
	if ok {
		t.Fatalf("expected overall failure when every node rejects, got ok=true, results=%v", results)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 individual results, got %d", len(results))
	}
	for _, r := range results {
		if r.Accepted {
			t.Errorf("node %s: unexpectedly reported Accepted=true", r.Address)
		}
	}
}

// TestMultiNodeSubmitterNoConfiguredNodesIsFailure confirms the
// documented "no nodes configured at all" -> success=false, nil
// results edge case.
func TestMultiNodeSubmitterNoConfiguredNodesIsFailure(t *testing.T) {
	m := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{}, discardLogger())
	results, ok := m.SubmitBlock(context.Background(), &tari_generated.Block{})
	if ok {
		t.Fatal("expected success=false with zero configured nodes")
	}
	if results != nil {
		t.Errorf("expected nil results with zero configured nodes, got %v", results)
	}
}

// TestMultiNodeSubmitterRespectsContextCancellation confirms a slow
// node that outlives ctx's deadline is reported with ctx.Err() rather
// than blocking the whole call past that deadline.
func TestMultiNodeSubmitterRespectsContextCancellation(t *testing.T) {
	clients := map[string]blockSubmitClient{
		"slow-node:1": &fakeTimedBlockClient{delay: 2 * time.Second, accept: true},
	}
	m := newMultiNodeSubmitterForTest(clients, discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	results, ok := m.SubmitBlock(ctx, &tari_generated.Block{})
	elapsed := time.Since(start)

	if ok {
		t.Fatal("expected overall failure once ctx deadline is exceeded before the slow node responds")
	}
	if elapsed >= 1*time.Second {
		t.Fatalf("SubmitBlock took %v, expected it to return promptly once ctx (100ms deadline) expired, not wait for the slow node's full 2s delay", elapsed)
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected 1 result carrying ctx.Err(), got %v", results)
	}
	if !errors.Is(results[0].Err, context.DeadlineExceeded) {
		t.Errorf("expected result error to be context.DeadlineExceeded, got %v", results[0].Err)
	}
}

// TestMultiNodeSubmitterAddresses confirms Addresses() reflects the
// configured node set (order-independent).
func TestMultiNodeSubmitterAddresses(t *testing.T) {
	clients := map[string]blockSubmitClient{
		"node-a:1": &fakeTimedBlockClient{accept: true},
		"node-b:1": &fakeTimedBlockClient{accept: true},
	}
	m := newMultiNodeSubmitterForTest(clients, discardLogger())
	addrs := m.Addresses()
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d: %v", len(addrs), addrs)
	}
}

// discardLogger returns a *log.Logger writing to io.Discard, so tests
// that exercise SubmitBlock's real logging path don't spam test
// output or (worse) panic on a nil writer.
func discardLogger() *log.Logger {
	return log.New(discardWriter{}, "", 0)
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
