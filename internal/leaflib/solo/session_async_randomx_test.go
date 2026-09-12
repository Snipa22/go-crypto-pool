// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
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
// networkTargetDiff (1<<62) these tests configure, keeping the resulting
// share an ORDINARY sub-block share (see DISPATCH_BRIEF.md: as of this
// change, solo only calls the real validator / dispatches to
// s.server.randomxPool at all for a submit whose claimed result crosses
// job.NetworkTargetDifficulty -- an ordinary share like this is credited
// entirely synchronously, inline, in Session.Run's own read loop, and
// never touches the validator or the pool). idx varies the low byte
// only (least-significant in little-endian), which is also what these
// tests' fake validators key accept/reject and delay decisions off of
// via resultHex's first hex byte.
func largeResultHash(idx int) []byte {
	h := bytes.Repeat([]byte{0xFF}, 32)
	h[0] = byte(idx)
	return h
}

// blockFindResultHash returns a 32-byte claimed RandomX result hash that
// is numerically TINY when interpreted little-endian, so
// diff = U256::MAX/hash comes out ASTRONOMICALLY LARGE -- comfortably
// above any networkTargetDiff these tests configure (including the
// 1<<62 most of them use), making every share built from this a genuine
// BLOCK-FIND CANDIDATE under the new validate-only-at-block-find model
// (DISPATCH_BRIEF.md): it DOES call the real validator and IS dispatched
// through s.server.randomxPool, exactly like a real block find would be.
//
// h[2]=1 is a fixed "salt" byte that keeps the little-endian numeric
// value (idx + 1*65536, at most 65791) safely non-zero regardless of
// idx (idx=0 alone would otherwise encode the degenerate all-zero hash,
// which claimedRandomXFamilyDifficulty correctly treats as an error, not
// as "extremely high difficulty") while staying tiny enough that the
// resulting difficulty (roughly 2^256/65536, vastly larger than any
// realistic uint64 target) reliably crosses every target these tests
// use. h[0]=idx is preserved so these tests' existing per-share fake
// validator hooks (which key accept/reject/delay decisions off
// resultHex's first hex byte, unchanged from largeResultHash's own
// convention) keep working identically.
func blockFindResultHash(idx int) []byte {
	h := make([]byte, 32)
	h[0] = byte(idx)
	h[2] = 1
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

// recvShareResponseSkippingJobPushes is recvShareResponse's tolerant
// counterpart, needed by this file's tests since blockFindResultHash
// (above): a genuine block find asynchronously invalidates and
// re-pushes a fresh job to this SAME session shortly after its own
// share response is written (session.go's finishSubmit: `go
// s.server.jobManager.InvalidateAll()`), which can legitimately
// interleave an unsolicited "job" push line into this connection's read
// stream at any point after that share's own response -- and this
// file's own concurrency tests deliberately drive MANY block-find
// candidates through the SAME session, so several such pushes can
// arrive interleaved with still-pending share responses. Skip any such
// push (identified by its own distinct "method":"job" wire shape, never
// present on a genuine ShareResponse) rather than misinterpreting it as
// a bogus, all-zero-value share response.
func (h *testHarness) recvShareResponseSkippingJobPushes() ShareResponse {
	h.t.Helper()
	for {
		raw := h.recvRaw()
		var probe struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(raw, &probe); err == nil && probe.Method == "job" {
			continue
		}
		var resp ShareResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			h.t.Fatalf("unmarshal share response: %v", err)
		}
		return resp
	}
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
//
// DISPATCH_BRIEF (2026-09-10) UPDATE: solo now only dispatches an
// RXT/RXM submit through the real validator/s.server.randomxPool at all
// when its claimed result crosses job.NetworkTargetDifficulty (a
// genuine block-find candidate) -- an ordinary sub-block share never
// reaches the validator or the pool anymore (see
// TestSessionRandomXOrdinaryShareNeverCallsValidator below). This test
// now deliberately uses blockFindResultHash (not largeResultHash) so
// every one of its shares IS such a candidate, keeping it a genuine
// regression guard for the pool's own concurrent-dispatch behavior at
// the (now much narrower, but still real) call site that still needs
// it.
func TestSessionRandomXConcurrentSubmitsDoNotSerializeOnReadLoop(t *testing.T) {
	const numShares = 24
	const delay = 40 * time.Millisecond

	v := &fakeDelayedRandomXValidator{delay: delay}
	h := newRXTTestHarnessWithValidator(t, 1, 1<<62, v) // diff=1, huge target -- but every share here is a block-find candidate (blockFindResultHash)
	jobID := rxtLoginAndGetJobID(t, h, "randomx-concurrency")

	start := time.Now()
	for i := 0; i < numShares; i++ {
		nonce := make([]byte, 4)
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		result := blockFindResultHash(i)
		h.send(Request{ID: i + 100, Method: "submit", Params: mustJSON(t, SubmitRequest{
			JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
	}

	seen := make(map[int]bool, numShares)
	for i := 0; i < numShares; i++ {
		resp := h.recvShareResponseSkippingJobPushes()
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
	// 24*40ms = 960ms. A bounded worker pool with
	// DefaultAsyncValidationWorkers() (runtime.NumCPU(), NOT a fixed
	// literal — see asyncvalidation.go's doc comment) workers should
	// take roughly ceil(24/numCPU)*40ms, comfortably under this
	// bound on any real multi-core test runner. Assert only that
	// elapsed isn't close to fully-serial (3/4 of serialBound) -- this
	// gives generous headroom for a noisy/loaded CI runner (which has
	// been observed to land right around serialBound/2, i.e. ~480ms,
	// causing flaky failures with no real concurrency regression --
	// peakConcurrent was still > 1) while still being a real,
	// meaningful regression guard against reintroducing full
	// serialization.
	serialBound := time.Duration(numShares) * delay
	if elapsed >= serialBound*3/4 {
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
		// blockFindResultHash), so this test can verify EACH response's
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
		result := blockFindResultHash(i)
		h.send(Request{ID: baseID + i, Method: "submit", Params: mustJSON(t, SubmitRequest{
			JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(result),
		})})
	}

	gotArrivalOrder := make([]int, 0, numShares)
	for i := 0; i < numShares; i++ {
		resp := h.recvShareResponseSkippingJobPushes()
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
// processing is now concurrent. Uses blockFindResultHash (not
// largeResultHash) so every share here is a genuine block-find
// candidate and actually reaches the concurrent validator/pool dispatch
// path this test means to exercise (DISPATCH_BRIEF.md: an ordinary
// sub-block share no longer touches either).
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
		result := blockFindResultHash(i)
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
		JobID: jobID, Nonce: hex.EncodeToString(dupNonce), Result: hex.EncodeToString(blockFindResultHash(0)),
	})})

	acceptedIDs := make(map[int]bool)
	var dupResp *ShareResponse
	for i := 0; i < numShares+1; i++ {
		resp := h.recvShareResponseSkippingJobPushes()
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

// --- DISPATCH_BRIEF.md (2026-09-10) required tests: "validate only at
// block-find" ---

// TestSessionRandomXOrdinaryShareNeverCallsValidator is DISPATCH_BRIEF
// required test (a): an ordinary sub-block RXT share (claimed result
// does NOT numerically cross job.NetworkTargetDifficulty) must be
// credited WITHOUT any call to the injected fake validator at all --
// asserted directly via the fake validator's own call counter, mirroring
// how leaf-proxy's own tests assert "validator not called for
// local-only shares" (internal/leaflib/proxy/session_test.go's
// "below block target -> local only, no upstream call" convention).
func TestSessionRandomXOrdinaryShareNeverCallsValidator(t *testing.T) {
	v := &fakeDelayedRandomXValidator{}
	h := newRXTTestHarnessWithValidator(t, 1, 1<<62, v) // huge target
	jobID := rxtLoginAndGetJobID(t, h, "ordinary-share-skips-validator")

	nonce := make([]byte, 4)
	nonce[0] = 1
	h.send(Request{ID: 600, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(largeResultHash(1)), // tiny claimed diff, well below the huge target
	})})
	resp := h.recvShareResponse()

	if resp.Error != nil {
		t.Fatalf("expected an ordinary sub-block share to be accepted, got error: %v", resp.Error.Message)
	}
	if resp.Result == nil || resp.Result.Status != "OK" {
		t.Fatalf("expected result status OK, got %#v", resp.Result)
	}
	if calls, _ := v.snapshot(); calls != 0 {
		t.Fatalf("validator was called %d times for an ordinary sub-block share, want 0 -- solo must only cryptographically validate RXT/RXM at block-find level (DISPATCH_BRIEF.md)", calls)
	}
	if h.node.submitCalls.Load() != 0 {
		t.Fatalf("SubmitBlock was called %d times for an ordinary sub-block share, want 0", h.node.submitCalls.Load())
	}
}

// TestSessionRandomXBlockFindCallsValidatorExactlyOnceBeforeSubmitBlock
// is DISPATCH_BRIEF required test (b): a share whose claimed result
// crosses the block target DOES trigger exactly one real validator call,
// and that call happens before SubmitBlock (proven here by the validator
// succeeding and SubmitBlock then genuinely being reached and called
// exactly once too -- if the ordering were reversed or validation were
// skipped, either count would be wrong).
func TestSessionRandomXBlockFindCallsValidatorExactlyOnceBeforeSubmitBlock(t *testing.T) {
	v := &fakeDelayedRandomXValidator{} // validFunc nil -> always valid
	h := newRXTTestHarnessWithValidator(t, 1, 1<<62, v)
	jobID := rxtLoginAndGetJobID(t, h, "block-find-validates-once")

	nonce := make([]byte, 4)
	nonce[0] = 7
	h.send(Request{ID: 601, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(blockFindResultHash(7)), // astronomically high claimed diff, crosses the huge target
	})})
	resp := h.recvShareResponseSkippingJobPushes()

	if resp.Error != nil {
		t.Fatalf("expected a genuine block-find candidate with a real, matching claimed hash to be accepted, got error: %v", resp.Error.Message)
	}
	if calls, _ := v.snapshot(); calls != 1 {
		t.Fatalf("validator was called %d times for a block-find candidate, want exactly 1", calls)
	}
	if h.node.submitCalls.Load() != 1 {
		t.Fatalf("SubmitBlock was called %d times, want exactly 1", h.node.submitCalls.Load())
	}
}

// TestSessionRandomXBlockFindFalseClaimIsRejectedNotCredited is
// DISPATCH_BRIEF required test (c): a share that FALSELY claims to
// cross the block target (blockFindResultHash) but fails real validation
// (the fake validator here always reports invalid) must be rejected
// outright -- never silently credited as a block find (SubmitBlock must
// not be called) and never silently downgraded to an ordinary accepted
// share either (the wire response must still be a rejection, not
// result:true).
func TestSessionRandomXBlockFindFalseClaimIsRejectedNotCredited(t *testing.T) {
	v := &fakeDelayedRandomXValidator{validFunc: func(string) bool { return false }}
	h := newRXTTestHarnessWithValidator(t, 1, 1<<62, v)
	jobID := rxtLoginAndGetJobID(t, h, "block-find-false-claim")

	nonce := make([]byte, 4)
	nonce[0] = 9
	h.send(Request{ID: 602, Method: "submit", Params: mustJSON(t, SubmitRequest{
		JobID: jobID, Nonce: hex.EncodeToString(nonce), Result: hex.EncodeToString(blockFindResultHash(9)), // claims to cross the target, but the daemon disagrees
	})})
	resp := h.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("a false block-find claim that fails real validation must not be accepted (neither as a block find nor silently as an ordinary share)")
	}
	if resp.Error == nil {
		t.Fatal("expected a rejection for a false block-find claim")
	}
	if calls, _ := v.snapshot(); calls != 1 {
		t.Fatalf("validator was called %d times, want exactly 1 -- a block-crossing claim must still be really checked", calls)
	}
	if h.node.submitCalls.Load() != 0 {
		t.Fatalf("SubmitBlock was called %d times for a claim that failed real validation, want 0", h.node.submitCalls.Load())
	}
}
