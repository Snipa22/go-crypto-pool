// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"bytes"
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

// PERFORMANCE FIX (Alex, live production incident, 2026-08-30): leaf-direct
// has the exact same read-loop-blocking bug leaf-solo did (session.go's
// handleSubmit also called validator.RandomXValidator.Validate inline for
// RXT/RXM) -- see solo/asyncvalidation.go's package doc comment for the
// full production incident and rationale, and solo/session_async_randomx_test.go
// for the equivalent leaf-solo regression tests this file mirrors.

// directLargeResultHash mirrors solo package's own largeResultHash exactly
// -- see that function's doc comment for why the hash must be numerically
// large (little-endian) to keep accepted shares off the block-find path in
// these tests.
func directLargeResultHash(idx int) []byte {
	h := bytes.Repeat([]byte{0xFF}, 32)
	h[0] = byte(idx)
	return h
}

// fakeDelayedDirectRandomXValidator mirrors solo package's
// fakeDelayedRandomXValidator exactly.
type fakeDelayedDirectRandomXValidator struct {
	delay time.Duration

	mu             sync.Mutex
	calls          int
	concurrent     int
	peakConcurrent int
}

func (v *fakeDelayedDirectRandomXValidator) Validate(ctx context.Context, share *poolpb.Share) (bool, error) {
	v.mu.Lock()
	v.calls++
	v.concurrent++
	if v.concurrent > v.peakConcurrent {
		v.peakConcurrent = v.concurrent
	}
	v.mu.Unlock()

	if v.delay > 0 {
		time.Sleep(v.delay)
	}

	v.mu.Lock()
	v.concurrent--
	v.mu.Unlock()
	return true, nil
}

func (v *fakeDelayedDirectRandomXValidator) snapshot() (calls, peakConcurrent int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls, v.peakConcurrent
}

var _ validator.AlgoValidator = (*fakeDelayedDirectRandomXValidator)(nil)

// TestDirectSessionRandomXConcurrentSubmitsDoNotSerializeOnReadLoop mirrors
// solo package's TestSessionRandomXConcurrentSubmitsDoNotSerializeOnReadLoop
// exactly, proving leaf-direct's own handleSubmit dispatch through
// s.server.randomxPool (server.go) genuinely overlaps RandomX-family
// validations instead of blocking Session.Run's read loop on each one.
func TestDirectSessionRandomXConcurrentSubmitsDoNotSerializeOnReadLoop(t *testing.T) {
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	const numShares = 24
	const delay = 40 * time.Millisecond

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
	v := &fakeDelayedDirectRandomXValidator{delay: delay}
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: v}
	tr := &fakeShareTransport{}
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
	t.Cleanup(func() {
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
	})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr, submit: sub,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: realTariTestAddress("randomx-concurrency"), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
	})})
	loginResp := h.recvLoginResponse()
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", loginResp.Result.Status)
	}
	jobID := loginResp.Result.Job.JobID

	start := time.Now()
	for i := 0; i < numShares; i++ {
		nonce := make([]byte, 4)
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		result := directLargeResultHash(i)
		h.send(solo.Request{ID: i + 100, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
	}

	seen := make(map[int]bool, numShares)
	for i := 0; i < numShares; i++ {
		resp := h.recvShareResponse()
		if resp.ID < 100 || resp.ID >= 100+numShares {
			t.Fatalf("got response with unexpected id %d", resp.ID)
		}
		if seen[resp.ID] {
			t.Fatalf("duplicate response for id %d", resp.ID)
		}
		seen[resp.ID] = true
		if resp.Error != nil {
			t.Fatalf("submit id %d rejected: %v", resp.ID, resp.Error.Message)
		}
	}
	elapsed := time.Since(start)

	serialBound := time.Duration(numShares) * delay
	if elapsed >= serialBound/2 {
		t.Fatalf("elapsed %v is not meaningfully less than the fully-serial bound %v -- leaf-direct's read loop may be blocking on each validation again", elapsed, serialBound)
	}

	calls, peak := v.snapshot()
	if calls != numShares {
		t.Fatalf("validator saw %d calls, want %d", calls, numShares)
	}
	if peak <= 1 {
		t.Fatalf("peak concurrent validator calls = %d, want > 1 -- no genuine concurrent dispatch observed", peak)
	}
	t.Logf("numShares=%d delay=%v elapsed=%v serialBound=%v peakConcurrent=%d", numShares, delay, elapsed, serialBound, peak)
}
