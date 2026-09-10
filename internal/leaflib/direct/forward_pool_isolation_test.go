// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// blockingShareTransport is a ShareTransport whose SubmitShare blocks
// until release is closed -- lets a test deterministically simulate a
// genuinely stuck/slow backend, for the required Fix 12 test
// (DISPATCH_BRIEF.md 2026-09-10): a slow-but-responding backend must
// not degrade process-wide RXT/RXM validation throughput for OTHER
// sessions' shares, because forwardShare/forwardBlock now run on a
// SEPARATE, dedicated forwardPool (server.go) instead of inline
// inside the shared randomxPool worker closure.
type blockingShareTransport struct {
	release chan struct{}

	mu    sync.Mutex
	calls int
}

func (b *blockingShareTransport) SubmitShare(ctx context.Context, _ *poolpb.Share) error {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return nil
}

func (b *blockingShareTransport) SubmitBlock(_ context.Context, _ *poolpb.Block) error { return nil }

func (b *blockingShareTransport) Close() error { return nil }

func (b *blockingShareTransport) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// TestDirectForwardShare_SlowBackendDoesNotStarveSharedValidationPool
// is the required Fix 12 test: a genuinely stuck backend (via
// blockingShareTransport, whose SubmitShare never returns until this
// test explicitly releases it) must not prevent OTHER sessions' real
// RXT/RXM RandomX validation (dispatched on the SAME shared
// s.server.randomxPool every session's submits go through) from
// completing quickly. Before Fix 12, forwardShare ran INSIDE the
// dispatched randomxPool closure -- a stuck backend would tie up
// however many of randomxPool's fixed workers happened to be
// forwarding at any moment, degrading (and, with enough concurrent
// stuck forwards, potentially fully stalling) validation throughput
// for every other session. After Fix 12, forwardShare is dispatched
// onto a SEPARATE forwardPool, so a fully stuck backend can only ever
// saturate forwardPool's own bounded capacity -- randomxPool's
// workers, and therefore every other session's wire-response
// latency, are completely unaffected.
func TestDirectForwardShare_SlowBackendDoesNotStarveSharedValidationPool(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	const numShares = 24

	node := &fakeDirectNodeClient{
		height:          42,
		mergeMiningHash: []byte("direct-test-merge-mining-hash-3"),
		vmKey:           []byte("test key 000"),
	}
	node.targetDifficulty = networkTargetDiff
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXT,
	})
	// A FAST validator (delay=0) -- this test is about the backend
	// forward path, not validation latency itself; validation must
	// stay fast and unaffected by the stuck backend.
	v := &fakeDelayedDirectRandomXValidator{}
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: v}
	tr := &blockingShareTransport{release: make(chan struct{})}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET, Transport: tr, MultiSubmit: multi,
		Algo: poolpb.Algo_ALGO_RXT, PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
	})
	// forwardPool is deliberately sized small (2 workers) so this
	// test can genuinely saturate/stall it with very few stuck
	// forwards, making the "randomxPool is unaffected regardless"
	// proof stronger (this would fail fast pre-Fix-12, since
	// forwardShare used to run on randomxPool itself).
	server.SetForwardPoolSize(2, 2)
	t.Cleanup(func() {
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
		if server.forwardPool != nil {
			server.forwardPool.Stop()
		}
	})

	serverConnA, clientA := net.Pipe()
	serverConnB, clientB := net.Pipe()
	go server.handleConn(ctx, serverConnA, staticDiff)
	go server.handleConn(ctx, serverConnB, staticDiff)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	hA := &directTestHarness{t: t, server: server, jm: jm, node: node, client: clientA, reader: bufio.NewReader(clientA), writer: bufio.NewWriter(clientA)}
	hB := &directTestHarness{t: t, server: server, jm: jm, node: node, client: clientB, reader: bufio.NewReader(clientB), writer: bufio.NewWriter(clientB)}

	sessionAJobID := func() string {
		hA.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
			Login: realTariTestAddress("forward-stuck-session-a"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
		})})
		resp := hA.recvLoginResponse()
		if resp.Result.Status != "OK" {
			t.Fatalf("session A login failed: status=%q", resp.Result.Status)
		}
		return resp.Result.Job.JobID
	}()

	sessionBJobID := func() string {
		hB.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
			Login: realTariTestAddress("forward-other-session-b"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
		})})
		resp := hB.recvLoginResponse()
		if resp.Result.Status != "OK" {
			t.Fatalf("session B login failed: status=%q", resp.Result.Status)
		}
		return resp.Result.Job.JobID
	}()

	// Session A submits enough shares to genuinely saturate (and
	// stall) forwardPool's tiny 2-worker capacity -- every one of
	// these forwardShare calls blocks on tr.release forever, until
	// this test explicitly closes it below.
	for i := 0; i < 4; i++ {
		nonce := make([]byte, 4)
		nonce[0] = 0xA0
		nonce[1] = byte(i)
		result := directLargeResultHash(i)
		hA.send(solo.Request{ID: i + 1000, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			JobID: sessionAJobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
	}
	for i := 0; i < 4; i++ {
		resp := hA.recvShareResponse()
		if resp.Error != nil {
			t.Fatalf("session A submit id %d rejected: %v", resp.ID, resp.Error.Message)
		}
	}

	// Give forwardPool a moment to genuinely pick up and start
	// blocking on session A's forwards (2 workers, plus its 2-slot
	// queue -- all 4 forwards should be in flight/queued and stuck).
	deadline := time.Now().Add(2 * time.Second)
	for tr.callCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("blockingShareTransport never observed at least 2 SubmitShare calls (forwardPool workers), got %d", tr.callCount())
		}
		time.Sleep(time.Millisecond)
	}

	// NOW, with the backend genuinely stuck, session B submits many
	// shares -- these go through the SAME shared randomxPool session
	// A's submits also used, but must complete quickly regardless of
	// the fully-saturated, fully-stuck forwardPool.
	start := time.Now()
	for i := 0; i < numShares; i++ {
		nonce := make([]byte, 4)
		nonce[0] = 0xB0
		nonce[1] = byte(i)
		result := directLargeResultHash(i)
		hB.send(solo.Request{ID: i + 2000, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			JobID: sessionBJobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
	}
	for i := 0; i < numShares; i++ {
		resp := hB.recvShareResponse()
		if resp.Error != nil {
			t.Fatalf("session B submit id %d rejected: %v", resp.ID, resp.Error.Message)
		}
	}
	elapsed := time.Since(start)

	// A generous bound: with a fast (delay=0) validator and a fully
	// unrelated pool for forwarding, numShares RXT submits from
	// session B must complete in well under a second regardless of
	// session A's backend being permanently stuck. Before Fix 12
	// (forwardShare running inline inside the shared randomxPool
	// closure), session A's 4 permanently-stuck forwards would have
	// permanently occupied up to 4 of randomxPool's own workers,
	// materially degrading or (with a small enough randomxPool)
	// fully stalling session B's throughput here.
	const bound = 2 * time.Second
	if elapsed >= bound {
		t.Fatalf("session B's %d RXT submits took %v (>= %v) while session A's backend forward was stuck -- the shared validation pool may be starved by a slow backend again", numShares, elapsed, bound)
	}
	t.Logf("session B processed %d submits in %v while session A's backend forward was fully stuck (bound=%v)", numShares, elapsed, bound)

	// Clean up: release the stuck backend calls so forwardPool.Stop()
	// (registered via t.Cleanup above) doesn't hang waiting for them.
	close(tr.release)
}
