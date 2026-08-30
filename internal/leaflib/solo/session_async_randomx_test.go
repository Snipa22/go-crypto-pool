// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// largeResultHash returns a 32-byte claimed RandomX result hash that is
// numerically LARGE when interpreted little-endian (matching
// rxtLittleEndianDifficulty's own real interpretation), so
// diff = U256::MAX/hash comes out SMALL -- well below the huge
// networkTargetDiff (1<<62) these tests configure. That keeps every
// accepted share on the ordinary "accepted, below block difficulty" wire
// response path instead of the block-find path (which would additionally
// trigger SubmitBlock/InvalidateAll/an unsolicited job re-push per share,
// polluting these tests' expected response stream with extra, unrelated
// wire messages). idx varies the low byte only (least-significant in
// little-endian), which is also what these tests' fake validators key
// accept/reject and delay decisions off of via resultHex's first hex byte.
func largeResultHash(idx int) []byte {
	h := bytes.Repeat([]byte{0xFF}, 32)
	h[0] = byte(idx)
	return h
}

// fakeDelayedRandomXValidator is a test double standing in for the real,
// network-backed validator.RandomXValidator: it sleeps for `delay` before
// returning, simulating the real ~4ms+ (or worse, under real concurrent
// load) synchronous randomx-service HTTP round-trip this whole fix is
// about NOT letting block Session.Run's read loop. It also tracks how
// many calls are concurrently in-flight, so a test can assert genuine
// concurrent dispatch actually happened (not just that build/vet pass with
// unused-looking concurrency code).
type fakeDelayedRandomXValidator struct {
	delay time.Duration
	// validFunc, if set, decides accept/reject per-call based on the
	// share's claimed ResultHex; a nil validFunc always accepts (valid
	// = true), fine for tests only interested in dispatch/ordering
	// behavior rather than accept/reject correctness.
	validFunc func(resultHex string) bool

	mu             sync.Mutex
	calls          int
	concurrent     int
	peakConcurrent int
}

func (v *fakeDelayedRandomXValidator) Validate(ctx context.Context, share *poolpb.Share) (bool, error) {
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

	var resultHex string
	if proof, ok := share.GetRawProof().(*poolpb.Share_RandomxProof); ok && proof.RandomxProof != nil {
		resultHex = proof.RandomxProof.GetResultHex()
	}
	if v.validFunc != nil {
		return v.validFunc(resultHex), nil
	}
	return true, nil
}

func (v *fakeDelayedRandomXValidator) snapshot() (calls, peakConcurrent int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls, v.peakConcurrent
}

// newRXTTestHarnessWithValidator is newRXTTestHarness's counterpart that
// takes an already-constructed validator.AlgoValidator instead of always
// building a real, network-backed validator.RandomXValidator -- lets these
// tests substitute a fake validator to deterministically simulate the real
// production bottleneck (a slow, synchronous randomx-service round-trip)
// without a real daemon, real network I/O, or non-deterministic timing.
func newRXTTestHarnessWithValidator(t *testing.T, staticDiff, networkTargetDiff uint64, v validator.AlgoValidator) *testHarness {
	t.Helper()
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: networkTargetDiff,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
		vmKey:            []byte("test key 000"),
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXT,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: v}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)

	h := &testHarness{
		t: t, server: server, cm: cm, jm: jm, node: node,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	t.Cleanup(func() {
		cancel()
		if server.randomxPool != nil {
			server.randomxPool.Stop()
		}
		_ = clientConn.Close()
	})
	return h
}

func rxtLoginAndGetJobID(t *testing.T, h *testHarness, addr string) string {
	t.Helper()
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress(addr), Pass: "x", Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
	})})
	resp := h.recvLoginResponse()
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	return resp.Result.Job.JobID
}

// TestSessionRandomXConcurrentSubmitsDoNotSerializeOnReadLoop is the
// primary regression test for the production bottleneck this fix
// addresses: many RXT shares submitted back-to-back on the SAME session,
// validated by a validator that simulates the real network-latency
// bottleneck (fakeDelayedRandomXValidator with a real, non-trivial delay),
// must NOT take anywhere close to numShares*delay wall-clock time to all
// get responses -- that would mean the read loop is still serializing on
// each validation exactly like the pre-fix bug. It also asserts
// peakConcurrent > 1, direct proof genuine concurrent dispatch happened
// (not just that the code compiles).
func TestSessionRandomXConcurrentSubmitsDoNotSerializeOnReadLoop(t *testing.T) {
	const numShares = 24
	const delay = 40 * time.Millisecond

	v := &fakeDelayedRandomXValidator{delay: delay}
	h := newRXTTestHarnessWithValidator(t, 1, 1<<62, v) // diff=1, huge target: every share accepted, non-block
	jobID := rxtLoginAndGetJobID(t, h, "randomx-concurrency")

	start := time.Now()
	for i := 0; i < numShares; i++ {
		nonce := make([]byte, 4)
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		result := largeResultHash(i)
		h.send(Request{ID: i + 100, Method: "submit", Params: mustJSON(t, SubmitRequest{
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

	// Fully sequential (the pre-fix bug) would take >= numShares*delay =
	// 24*40ms = 960ms. A bounded worker pool with AsyncValidationWorkers
	// (8) workers should take roughly ceil(24/8)*40ms = 120ms plus
	// scheduling overhead. Assert well under half the fully-serial bound
	// -- generous enough to avoid CI flakiness while still being a real,
	// meaningful regression guard against reintroducing full
	// serialization.
	serialBound := time.Duration(numShares) * delay
	if elapsed >= serialBound/2 {
		t.Fatalf("elapsed %v is not meaningfully less than the fully-serial bound %v -- read loop may be blocking on each validation again (the exact bug this fix addresses)", elapsed, serialBound)
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

// fakeVariableDelayValidator is fakeDelayedRandomXValidator's variant that
// picks a per-share delay based on the share's own content (its claimed
// result hash's low byte, i.e. the submit's own index below) rather than
// call arrival order, used by the id-matching test below to force
// deliberate out-of-order completion (the FIRST submitted share gets the
// LONGEST delay).
type fakeVariableDelayValidator struct {
	delayForIndex func(idx int) time.Duration
	validFunc     func(resultHex string) bool
}

func (v *fakeVariableDelayValidator) Validate(ctx context.Context, share *poolpb.Share) (bool, error) {
	var resultHex string
	if proof, ok := share.GetRawProof().(*poolpb.Share_RandomxProof); ok && proof.RandomxProof != nil {
		resultHex = proof.RandomxProof.GetResultHex()
	}
	b, _ := hex.DecodeString(resultHex)
	idx := 0
	if len(b) > 0 {
		idx = int(b[0])
	}
	if v.delayForIndex != nil {
		time.Sleep(v.delayForIndex(idx))
	}
	if v.validFunc != nil {
		return v.validFunc(resultHex), nil
	}
	return true, nil
}

// TestSessionRandomXConcurrentSubmitsRespondByOwnID verifies the
// response-ordering design decision documented on session.go's
// handleSubmit: per the real xmrig source (Client::submit/parseResponse,
// which matches purely by numeric "id" via an id-keyed map, not arrival
// order), out-of-order completion is fine as long as every response
// carries its own correct id and accept/reject outcome. This test forces
// out-of-order completion deliberately: the FIRST submitted share (index
// 0) is given the LONGEST validator delay, so later submits' responses
// are very likely to reach the wire first -- and asserts every response's
// accept/reject outcome still matches what THAT id's own submit deserves
// (even/odd index -> accept/reject), proving id-based correctness survives
// non-deterministic completion order.
func TestSessionRandomXConcurrentSubmitsRespondByOwnID(t *testing.T) {
	const numShares = 10
	const baseID = 300

	v := &fakeVariableDelayValidator{
		// Index 0 (the first submitted) waits longest; each subsequent
		// index waits less -- guarantees later submits' responses are
		// very likely to reach the wire before the first one's.
		delayForIndex: func(idx int) time.Duration {
			return time.Duration(numShares-idx) * 15 * time.Millisecond
		},
		// Deterministic accept/reject purely from the low byte of the
		// claimed result hash (which encodes the submit index, see
		// largeResultHash), so this test can verify EACH response's
		// accept/reject decision belongs to its own id regardless of
		// arrival order.
		validFunc: func(resultHex string) bool {
			b, err := hex.DecodeString(resultHex)
			if err != nil || len(b) == 0 {
				return false
			}
			return b[0]%2 == 0 // even index -> accept, odd -> reject
		},
	}
	h := newRXTTestHarnessWithValidator(t, 1, 1<<62, v)
	jobID := rxtLoginAndGetJobID(t, h, "randomx-ordering")

	for i := 0; i < numShares; i++ {
		nonce := make([]byte, 4)
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		result := largeResultHash(i)
		h.send(Request{ID: baseID + i, Method: "submit", Params: mustJSON(t, SubmitRequest{
			JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
	}

	gotArrivalOrder := make([]int, 0, numShares)
	for i := 0; i < numShares; i++ {
		resp := h.recvShareResponse()
		idx := resp.ID - baseID
		if idx < 0 || idx >= numShares {
			t.Fatalf("response id %d out of expected range", resp.ID)
		}
		gotArrivalOrder = append(gotArrivalOrder, idx)

		wantAccepted := idx%2 == 0
		gotAccepted := resp.Error == nil
		if gotAccepted != wantAccepted {
			t.Fatalf("id %d (index %d): accepted=%v, want %v -- response was matched to the wrong id, or id-keyed correctness broke under concurrent/out-of-order completion", resp.ID, idx, gotAccepted, wantAccepted)
		}
	}

	// Not a hard requirement for correctness (xmrig matches by id, not
	// order -- see the doc comment), but confirms this test actually
	// exercised genuine out-of-order completion rather than happening to
	// complete in submission order anyway.
	inOrder := true
	for i, idx := range gotArrivalOrder {
		if idx != i {
			inOrder = false
			break
		}
	}
	if inOrder {
		t.Fatalf("responses arrived in strict submission order (%v) -- this test needs genuine out-of-order completion to be a meaningful check of id-based correctness; delay schedule may need adjusting", gotArrivalOrder)
	}
	t.Logf("arrival order (by submit index): %v", gotArrivalOrder)
}

// TestSessionRandomXConcurrentSubmitsRaceSafeCountersAndDedup hammers one
// session with many concurrent-in-flight RandomX validations (via a fake
// validator with a small delay so several are genuinely in-flight at
// once) and asserts: (1) go test -race reports no data race on
// shareCount/hashesAccumulated/trust (this test's real purpose -- run with
// -race), and (2) a duplicate nonce submitted immediately after the
// original is rejected deterministically (not double-credited), proving
// job.MarkNonceUsed's synchronous, pre-dispatch placement in handleSubmit
// still correctly gates duplicates even though the REST of submit
// processing is now concurrent.
func TestSessionRandomXConcurrentSubmitsRaceSafeCountersAndDedup(t *testing.T) {
	const numShares = 30
	v := &fakeDelayedRandomXValidator{delay: 5 * time.Millisecond}
	h := newRXTTestHarnessWithValidator(t, 1, 1<<62, v)
	jobID := rxtLoginAndGetJobID(t, h, "randomx-race-safety")

	// Fire numShares distinct-nonce submits back-to-back -- with a real
	// (even if small) per-call delay, many of these will have their
	// finishSubmit closures genuinely running concurrently on the
	// server-wide pool, exercising shareCount/hashesAccumulated/trust
	// under real concurrent access. go test -race is what actually
	// proves this is safe; this test's assertions on top of that confirm
	// the accept COUNT is also correct (no double-credit / lost update).
	for i := 0; i < numShares; i++ {
		nonce := make([]byte, 4)
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		result := largeResultHash(i)
		h.send(Request{ID: i + 500, Method: "submit", Params: mustJSON(t, SubmitRequest{
			JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
	}
	// Immediately (same read loop iteration cadence) replay the very
	// first nonce again -- MarkNonceUsed already ran synchronously for
	// it before its validation was ever dispatched, so this must be
	// rejected as a duplicate regardless of whether share #0's async
	// validation has completed yet.
	dupNonce := make([]byte, 4)
	dupNonce[0] = 0
	h.send(Request{ID: 999, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: hex.EncodeToString(dupNonce), Result: hex.EncodeToString(largeResultHash(0)),
	})})

	acceptedIDs := make(map[int]bool)
	var dupResp *ShareResponse
	for i := 0; i < numShares+1; i++ {
		resp := h.recvShareResponse()
		if resp.ID == 999 {
			r := resp
			dupResp = &r
			continue
		}
		if resp.Error == nil {
			acceptedIDs[resp.ID] = true
		} else {
			t.Fatalf("submit id %d unexpectedly rejected: %v", resp.ID, resp.Error.Message)
		}
	}

	if len(acceptedIDs) != numShares {
		t.Fatalf("accepted %d distinct shares, want %d -- possible double-credit or lost accept under concurrent dispatch", len(acceptedIDs), numShares)
	}
	if dupResp == nil {
		t.Fatal("never got a response for the duplicate-nonce submit (id 999)")
	}
	if dupResp.Error == nil {
		t.Fatal("duplicate-nonce submit was accepted -- MarkNonceUsed dedup did not hold under concurrent validation dispatch")
	}

	if h.node == nil {
		t.Fatal("nil fakeNodeClient")
	}
}

var (
	_ validator.AlgoValidator = (*fakeDelayedRandomXValidator)(nil)
	_ validator.AlgoValidator = (*fakeVariableDelayValidator)(nil)
)
