// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// CLOSE-WAIT production-incident regression test (phx-dump.supportxmr.com,
// leaf-direct -legacy-mode, ~20k+ real connected Monero miners; 17,855
// CLOSE-WAIT vs 8,636 ESTAB observed via `ss -tn`). See
// internal/leaflib/direct/server.go's Server.jobFetchPool doc comment and
// session.go's handleLogin/fetchAndDeliverLoginJob doc comments for the
// full root-cause explanation: solo.JobManager.jobForXN's per-xn
// cache-miss path (job.go ~line 553-622) can block for an effectively
// unbounded time on a process-wide, context-cancellation-immune
// sync.Mutex (jm.genMu) before ever reaching its own bounded
// GetBlockTemplate HTTP call -- running that inline on Session.Run's own
// read-loop goroutine (the pre-fix behavior) means the read loop can
// never call scanner.Scan() again (the only place that would notice a
// peer's FIN) until that blocked call finally returns, leaving the
// connection stuck CLOSE-WAIT-side even though handleConn's cleanup
// defer is otherwise completely correct.

// blockingDirectNodeClient wraps *fakeDirectNodeClient, overriding only
// GetBlockTemplate to block until either the test-controlled release
// channel is closed or the caller's own ctx is done -- lets this test
// deterministically simulate exactly the "stuck behind jm.genMu, then a
// slow downstream GetBlockTemplate call" condition the production
// incident hit, without needing a real monerod/base-node.
type blockingDirectNodeClient struct {
	*fakeDirectNodeClient

	release chan struct{}

	mu    sync.Mutex
	calls int
}

func (b *blockingDirectNodeClient) GetBlockTemplate(ctx context.Context, payoutAddress string, algo poolpb.Algo) (*solo.Job, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return b.fakeDirectNodeClient.GetBlockTemplate(ctx, payoutAddress, algo)
}

func (b *blockingDirectNodeClient) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// TestDirectSession_LoginJobFetchBlocked_ClientDisconnectStillCleansUpPromptly
// is the required regression test: while a first-time-seen session's
// login-triggered job fetch is genuinely stuck (the mock
// GetBlockTemplate call has not yet been released), the CLIENT side of
// the connection disconnects. The server side's session must still be
// cleaned up (removed from Server.sessions) PROMPTLY -- well before the
// stuck job fetch is ever released -- proving Session.Run's read loop
// was free to call scanner.Scan() again (and therefore notice the
// disconnect) immediately after dispatching the job fetch, rather than
// being blocked waiting on it.
func TestDirectSession_LoginJobFetchBlocked_ClientDisconnectStillCleansUpPromptly(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1000), uint64(1) << 62

	inner := &fakeDirectNodeClient{height: 42, mergeMiningHash: []byte("direct-test-merge-mining-hash-3")}
	inner.targetDifficulty = networkTargetDiff
	node := &blockingDirectNodeClient{fakeDirectNodeClient: inner, release: make(chan struct{})}

	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
	})

	v := validator.NewSHA3XValidator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET,
		Algo:    poolpb.Algo_ALGO_SHA3X, PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
	})
	// jobFetchPool is deliberately stopped explicitly, later in this
	// test (after releasing the stuck mock call), NOT via t.Cleanup --
	// stopping it twice would panic (close of an already-closed
	// channel; see solo.AsyncValidationPool.Stop). randomxPool/
	// forwardPool are never exercised by this login-only test but are
	// stopped here anyway for parity with this package's other tests.
	t.Cleanup(func() {
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
		if server.forwardPool != nil {
			server.forwardPool.Stop()
		}
	})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: nil,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}

	// A fresh session's xn has never been seen before -- this login
	// unconditionally hits jobForXN's cache-miss path (jm.genMu.Lock()
	// then the blocked GetBlockTemplate call below), exactly the
	// production incident's own trigger condition.
	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: realTariTestAddress("closewait-jobfetch-blocked"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"sha3x"},
	})})

	// Wait until the mock GetBlockTemplate call has genuinely been
	// entered (i.e. jm.genMu was acquired and the blocked HTTP-call
	// stand-in is now in flight) before proceeding -- otherwise this
	// test could race ahead of the dispatch and prove nothing.
	deadline := time.Now().Add(2 * time.Second)
	for node.callCount() < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("blockingDirectNodeClient.GetBlockTemplate was never entered -- login did not reach the job-fetch path")
		}
		time.Sleep(time.Millisecond)
	}

	// THE CORE ASSERTION SETUP: the mock GetBlockTemplate call is
	// still blocked (release not yet closed) -- now close the CLIENT
	// side of the connection. On a real TCP socket this is the peer
	// sending FIN; net.Pipe()'s synchronous in-memory equivalent makes
	// the SERVER side's next scanner.Scan() return an error/EOF
	// immediately, IF AND ONLY IF Session.Run's read loop is actually
	// free to call Scan() again -- which is exactly the condition this
	// test proves, since the job fetch this login triggered is still
	// stuck.
	if err := clientConn.Close(); err != nil {
		t.Fatalf("clientConn.Close: %v", err)
	}

	// CORE ASSERTION: server-side session cleanup (handleConn's defer
	// -- delete(s.sessions, mc.ID())) must happen promptly, well before
	// the still-blocked job fetch is ever released below. Before this
	// fix, handleLogin ran JobForXNAtDifficulty INLINE on Session.Run's
	// read-loop goroutine, so Run could never get back to
	// scanner.Scan() (and therefore never notice the client's
	// disconnect, and therefore never return, and therefore
	// handleConn's cleanup defer could never fire) until this same
	// still-blocked GetBlockTemplate call finally returned -- exactly
	// the CLOSE-WAIT accumulation this fix eliminates.
	cleanupDeadline := time.Now().Add(2 * time.Second)
	for {
		server.mu.RLock()
		n := len(server.sessions)
		server.mu.RUnlock()
		if n == 0 {
			break
		}
		if time.Now().After(cleanupDeadline) {
			t.Fatalf("server-side session was not cleaned up within the bounded deadline (still %d live session(s)) -- read loop may be blocked waiting on the stuck job fetch again", n)
		}
		time.Sleep(time.Millisecond)
	}
	t.Log("server-side session cleaned up promptly while the job-fetch call was still genuinely blocked")

	// Now release the stuck mock call and let the dispatched
	// jobFetchPool worker finish naturally. Its eventual writeJSON
	// call targets a session/connection that is already gone --
	// leaflib.WriteJSON/ManagedConnection.Write already tolerate this
	// (a plain ErrConnectionClosed return, not a panic -- see
	// connection.go's Write), exactly like finishSubmit's own late
	// writes for a session that disappears mid-validation. If this
	// panicked, the pool's own runProtected recover (asyncvalidation.go)
	// would swallow it silently -- t.Cleanup's Stop() call below still
	// completing without the test hanging is this test's own
	// confirmation that the worker genuinely returned rather than
	// wedging.
	close(node.release)

	const stopBound = 2 * time.Second
	stopped := make(chan struct{})
	go func() {
		server.jobFetchPool.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(stopBound):
		t.Fatalf("jobFetchPool.Stop() did not return within %v after releasing the stuck job fetch -- dispatched worker may be wedged", stopBound)
	}
}
