// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/json"
	"math"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- computeRetarget: pure formula tests ---

// TestComputeRetargetPrimaryFormula exercises the primary
// hashes/connectionSeconds*targetTime path with a computed value that
// survives step-clamping unmodified, so the exact expected output can
// be checked deterministically.
func TestComputeRetargetPrimaryFormula(t *testing.T) {
	// curDiff=6000, hashes=15000 accepted (difficulty-weighted) over
	// 60 connected seconds, targetTime=30s -> (15000/60)*30 = 7500,
	// which is within [3000,9000] (curDiff*0.5..1.5), so it applies
	// as-is with no clamping interference.
	newDiff, changed := computeRetarget(6000, 15000, 60, 30, 1, math.MaxUint64)
	if !changed {
		t.Fatal("expected a difficulty change")
	}
	if newDiff != 7500 {
		t.Errorf("newDiff = %d, want 7500", newDiff)
	}
}

// TestComputeRetargetZeroHashesFallback exercises the "zero accepted
// shares" 10% reduction fallback.
func TestComputeRetargetZeroHashesFallback(t *testing.T) {
	newDiff, changed := computeRetarget(1000, 0, 90, 30, 1, math.MaxUint64)
	if !changed {
		t.Fatal("expected a difficulty change (10% reduction)")
	}
	want := uint64(900) // 1000 * 0.9
	if newDiff != want {
		t.Errorf("newDiff = %d, want %d", newDiff, want)
	}
}

// TestComputeRetargetDeadZoneNoChange: a raw computed value within
// ±5% of curDiff must result in NO change at all.
func TestComputeRetargetDeadZoneNoChange(t *testing.T) {
	// curDiff=1000, hashes/connSeconds*targetTime = (2000/60)*30 = 1000
	// exactly -> well within the dead zone (must be > 950 and < 1050 to
	// trigger the dead-zone return; 1000 satisfies that).
	newDiff, changed := computeRetarget(1000, 2000, 60, 30, 1, math.MaxUint64)
	if changed {
		t.Errorf("expected no change for a within-dead-zone computed value, got newDiff=%d", newDiff)
	}
	if newDiff != 1000 {
		t.Errorf("newDiff = %d, want unchanged 1000", newDiff)
	}

	// A slightly-off value still inside ±5% (1030 is within
	// (950,1050)) must also result in no change.
	newDiff2, changed2 := computeRetarget(1000, 2060, 60, 30, 1, math.MaxUint64)
	if changed2 {
		t.Errorf("expected no change for a value within the dead zone, got newDiff=%d", newDiff2)
	}
}

// TestComputeRetargetStepClampUp: a raw computed value wildly above
// curDiff must be clamped to at most 1.5x curDiff, not applied
// directly.
func TestComputeRetargetStepClampUp(t *testing.T) {
	// curDiff=1000; a huge accept rate would want to jump to
	// (600000/60)*30 = 300000, but the step clamp limits it to
	// 1000*1.5 = 1500.
	newDiff, changed := computeRetarget(1000, 600000, 60, 30, 1, math.MaxUint64)
	if !changed {
		t.Fatal("expected a difficulty change")
	}
	if newDiff != 1500 {
		t.Errorf("newDiff = %d, want step-clamped 1500 (1.5x curDiff)", newDiff)
	}
}

// TestComputeRetargetStepClampDown: a raw computed value wildly below
// curDiff must be clamped to at most 0.5x curDiff, not applied
// directly.
func TestComputeRetargetStepClampDown(t *testing.T) {
	// curDiff=1000; a near-zero accept rate wants to jump down to
	// (60/60)*30 = 30, but the step clamp limits it to 1000*0.5 = 500.
	newDiff, changed := computeRetarget(1000, 60, 60, 30, 1, math.MaxUint64)
	if !changed {
		t.Fatal("expected a difficulty change")
	}
	if newDiff != 500 {
		t.Errorf("newDiff = %d, want step-clamped 500 (0.5x curDiff)", newDiff)
	}
}

// TestComputeRetargetAbsoluteBoundsAfterStepClamp: even after the
// 0.5x/1.5x step-size clamp, the absolute MinimumDifficulty/
// MaxDifficulty bounds must still apply.
func TestComputeRetargetAbsoluteBoundsAfterStepClamp(t *testing.T) {
	// curDiff=1000, step-clamp-up would allow up to 1500, but
	// maxDiff=1200 must win.
	newDiff, changed := computeRetarget(1000, 600000, 60, 30, 1, 1200)
	if !changed {
		t.Fatal("expected a difficulty change")
	}
	if newDiff != 1200 {
		t.Errorf("newDiff = %d, want absolute-max-clamped 1200", newDiff)
	}

	// curDiff=1000, step-clamp-down would allow down to 500, but
	// minDiff=800 must win.
	newDiff2, changed2 := computeRetarget(1000, 60, 60, 30, 800, math.MaxUint64)
	if !changed2 {
		t.Fatal("expected a difficulty change")
	}
	if newDiff2 != 800 {
		t.Errorf("newDiff = %d, want absolute-min-clamped 800", newDiff2)
	}
}

// TestComputeRetargetNoChangeWhenClampedBackToCurrent: if clamping
// collapses the computed value exactly back to curDiff, that must be
// reported as no change.
func TestComputeRetargetNoChangeWhenClampedBackToCurrent(t *testing.T) {
	// minDiff/maxDiff both equal to curDiff forces newDiff == curDiff
	// regardless of the raw computed value.
	newDiff, changed := computeRetarget(1000, 600000, 60, 30, 1000, 1000)
	if changed {
		t.Errorf("expected no change when absolute bounds collapse newDiff back to curDiff, got newDiff=%d", newDiff)
	}
	if newDiff != 1000 {
		t.Errorf("newDiff = %d, want 1000", newDiff)
	}
}

func TestComputeRetargetZeroConnSecondsIsNoop(t *testing.T) {
	newDiff, changed := computeRetarget(1000, 500, 0, 30, 1, math.MaxUint64)
	if changed {
		t.Error("expected no change for a degenerate connSeconds=0 input")
	}
	if newDiff != 1000 {
		t.Errorf("newDiff = %d, want unchanged 1000", newDiff)
	}
}

// --- Session-level vardiff integration tests ---

// vardiffHarness is a lighter-weight test harness than testHarness
// (session_test.go): it exposes the constructed *Server/*JobManager/
// *fakeNodeClient plus a helper to spin up one real, wire-connected,
// logged-in Session and reach its *Session directly (vardiff tests
// need to poke session-internal accept-history state to set up
// deterministic scenarios, and to assert on the exact job pushed to
// ONLY that session).
type vardiffHarness struct {
	t            *testing.T
	server       *Server
	jm           *JobManager
	node         *fakeNodeClient
	cancel       context.CancelFunc
	startingDiff uint64
}

func newVardiffHarness(t *testing.T, startingDiff, networkTargetDiff uint64, vardiff VardiffConfig) *vardiffHarness {
	t.Helper()
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: networkTargetDiff,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: startingDiff,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	v := validator.NewSHA3XValidator()
	c29 := validator.NewC29Validator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v, poolpb.Algo_ALGO_C29: c29}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, vardiff)

	h := &vardiffHarness{t: t, server: server, jm: jm, node: node, cancel: cancel, startingDiff: startingDiff}
	t.Cleanup(cancel)
	return h
}

// vardiffClient is one real, wire-connected miner session opened
// against a vardiffHarness's Server, deliberately NOT going through
// Server.Accept/ConnectionManager's own net.Listener (matching
// session_test.go's net.Pipe-based approach) so tests run fully
// in-process without a real TCP socket.
type vardiffClient struct {
	t      *testing.T
	client net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

// connectAndLogin opens a new session against h's Server and performs
// a real login handshake, returning both the wire-facing client helper
// and a direct handle to the server-side *Session (looked up by the
// xn the login handshake returned), so the test can both assert on
// wire traffic AND poke session-internal vardiff state directly.
func (h *vardiffHarness) connectAndLogin(address string) (*vardiffClient, *Session) {
	h.t.Helper()
	serverConn, clientConn := net.Pipe()
	ctx := context.Background()
	go h.server.handleConn(ctx, serverConn, h.startingDiff)

	c := &vardiffClient{
		t:      h.t,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
	}
	h.t.Cleanup(func() { _ = clientConn.Close() })

	req := Request{ID: 1, JsonRPC: "2.0", Method: "login"}
	// address is a short, readable test label; see
	// address_helper_test.go's realTariTestAddress doc comment for
	// why it must be mapped to a real, valid Tari address here.
	params, err := json.Marshal(LoginRequest{Login: realTariTestAddress(address), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})
	if err != nil {
		h.t.Fatalf("marshal login params: %v", err)
	}
	req.Params = params
	c.send(req)
	resp := c.recvLoginResponse()
	if resp.Result.Status != "OK" {
		h.t.Fatalf("login failed: status=%q", resp.Result.Status)
	}

	sess := h.sessionByXN(resp.Result.Job.XN)
	if sess == nil {
		h.t.Fatalf("could not find server-side Session for xn %q after login", resp.Result.Job.XN)
	}
	return c, sess
}

// sessionByXN reaches into the Server's session registry (via its
// exported Stats-adjacent internals) to find the *Session matching xn.
func (h *vardiffHarness) sessionByXN(xn string) *Session {
	h.server.mu.RLock()
	defer h.server.mu.RUnlock()
	for _, sess := range h.server.sessions {
		if sess.XN() == xn {
			return sess
		}
	}
	return nil
}

func (c *vardiffClient) send(req Request) {
	c.t.Helper()
	buf, err := json.Marshal(req)
	if err != nil {
		c.t.Fatalf("marshal request: %v", err)
	}
	buf = append(buf, '\n')
	if _, err := c.writer.Write(buf); err != nil {
		c.t.Fatalf("write request: %v", err)
	}
	if err := c.writer.Flush(); err != nil {
		c.t.Fatalf("flush request: %v", err)
	}
}

func (c *vardiffClient) recvRaw() []byte {
	c.t.Helper()
	_ = c.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	return line
}

func (c *vardiffClient) recvLoginResponse() LoginResponse {
	c.t.Helper()
	var resp LoginResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		c.t.Fatalf("unmarshal login response: %v", err)
	}
	return resp
}

func (c *vardiffClient) recvJobPush() JobPush {
	c.t.Helper()
	var push JobPush
	if err := json.Unmarshal(c.recvRaw(), &push); err != nil {
		c.t.Fatalf("unmarshal job push: %v", err)
	}
	return push
}

// TestSessionSkipsRetargetUnderRetargetInterval: a session younger
// than the configured RetargetInterval must not be retargeted at all
// (mirrors go-tari-sha3x-solo-stratum's getConnSeconds() < 60 guard).
func TestSessionSkipsRetargetUnderRetargetInterval(t *testing.T) {
	h := newVardiffHarness(t, 1000, 1<<62, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second, // never fires in this short test
	})
	_, sess := h.connectAndLogin("addr-young-session")

	// Simulate a huge accept history that WOULD trigger a large
	// retarget if the age gate weren't in place.
	sess.hashesAccumulated.Store(1_000_000)
	sess.connectedAt = time.Now() // "just connected"

	sess.maybeRetarget()

	if got := sess.currentDifficulty.Load(); got != 1000 {
		t.Errorf("expected no retarget for a session younger than RetargetInterval, difficulty changed to %d", got)
	}
}

// TestSessionRetargetsAfterIntervalAndPushesNewJob confirms the full
// integration path: once a session is old enough and has accept
// history that computes to a real difficulty change, maybeRetarget
// updates currentDifficulty AND pushes a fresh job (with the new
// difficulty reflected in job.StaticDifficulty / the wire target) to
// that session, and the JobManager's cache reflects it too.
func TestSessionRetargetsAfterIntervalAndPushesNewJob(t *testing.T) {
	h := newVardiffHarness(t, 1000, 1<<62, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	c, sess := h.connectAndLogin("addr-retarget")

	// Backdate connectedAt so the age gate passes, and seed an accept
	// history that computes to a real (non-dead-zone) change:
	// hashes=600000 over connSeconds=60(ish), targetTime=30 ->
	// (600000/60)*30 = 300000, step-clamped to 1000*1.5=1500.
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600000)

	// net.Pipe() is fully synchronous: a Write on one end blocks until
	// the other end actually calls Read. maybeRetarget's pushJob does
	// a real, blocking mc.Write, so it must run concurrently with (not
	// strictly before) the client's read -- calling it synchronously
	// here and only reading afterward would deadlock against the
	// pipe's own semantics (the write blocks waiting for a reader that
	// hasn't started yet, until ManagedConnection's own idle-timeout
	// eventually fails the write and tears down the connection).
	retargetDone := make(chan struct{})
	go func() {
		defer close(retargetDone)
		sess.maybeRetarget()
	}()

	// The pushed job must carry the new difficulty as its target.
	jobPush := c.recvJobPush()
	<-retargetDone
	if got := sess.currentDifficulty.Load(); got != 1500 {
		t.Fatalf("currentDifficulty = %d, want 1500 after retarget", got)
	}
	wantTarget := diffToTargetHex(1500)
	if jobPush.Params.Target != wantTarget {
		t.Errorf("pushed job target = %q, want %q (difficulty 1500)", jobPush.Params.Target, wantTarget)
	}

	// The JobManager's cached job for this xn must also reflect the
	// new difficulty.
	cached, ok := h.jm.GetJob(jobPush.Params.JobID)
	if !ok {
		t.Fatal("expected the pushed job id to be resolvable via GetJob")
	}
	if cached.StaticDifficulty != 1500 {
		t.Errorf("cached job StaticDifficulty = %d, want 1500", cached.StaticDifficulty)
	}
}

// TestSessionMaybeRetargetIsNoopWhenUnchanged: calling maybeRetarget
// when the computed value is unchanged (dead-zone) must not push any
// job at all.
func TestSessionMaybeRetargetIsNoopWhenUnchanged(t *testing.T) {
	h := newVardiffHarness(t, 1000, 1<<62, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	c, sess := h.connectAndLogin("addr-nochange")

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	// hashes=2000, connSeconds~=90, targetTime=30 -> (2000/90)*30 =
	// 666 (integer division), well within ±5% dead zone territory is
	// NOT guaranteed generically across timing jitter, so instead pin
	// connSeconds precisely via a value chosen to land exactly on
	// curDiff: use hashes=3000 over ~90s -> (3000/90)*30 = 1000
	// exactly (curDiff itself), landing in the dead zone regardless of
	// small timing jitter in connSeconds (90 vs 91 barely moves the
	// integer-divided result).
	sess.hashesAccumulated.Store(3000)

	sess.maybeRetarget()

	if got := sess.currentDifficulty.Load(); got != 1000 {
		t.Errorf("expected no change, currentDifficulty = %d", got)
	}

	// No job push should have arrived; confirm the connection has
	// nothing buffered by sending a keepalive and checking the very
	// next message is that keepalive's response, not a stray job
	// push.
	c.send(Request{ID: 99, JsonRPC: "2.0", Method: "keepalived"})
	raw := c.recvRaw()
	var errResp ErrorResponse
	if err := json.Unmarshal(raw, &errResp); err != nil {
		t.Fatalf("unmarshal keepalive response: %v", err)
	}
	if errResp.Result != "KEEPALIVED" {
		t.Errorf("expected the keepalive response to be the very next message (no stray job push), got %q", string(raw))
	}
}

// TestTwoSessionsRetargetIndependently is the key regression guard:
// two sessions with different accept-rate histories must retarget to
// DIFFERENT difficulties independently, and only the session whose
// difficulty actually changed receives a job push. This guards against
// accidentally reintroducing shared/global difficulty state.
func TestTwoSessionsRetargetIndependently(t *testing.T) {
	h := newVardiffHarness(t, 1000, 1<<62, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})

	clientA, sessA := h.connectAndLogin("addr-multi-a")
	clientB, sessB := h.connectAndLogin("addr-multi-b")

	if sessA.XN() == sessB.XN() {
		t.Fatalf("expected two independently-connected sessions to get different xn values, both got %q", sessA.XN())
	}

	// Session A: high accept rate -> difficulty goes UP.
	sessA.connectedAt = time.Now().Add(-90 * time.Second)
	sessA.hashesAccumulated.Store(600000) // -> step-clamped to 1500

	// Session B: zero accepted shares -> 10% reduction fallback.
	sessB.connectedAt = time.Now().Add(-90 * time.Second)
	sessB.hashesAccumulated.Store(0) // -> 1000*0.9 = 900

	// Both retargets do a real, blocking mc.Write via pushJob (see
	// TestSessionRetargetsAfterIntervalAndPushesNewJob's comment on
	// why net.Pipe()'s synchronous semantics require this to run
	// concurrently with the corresponding client reads below, not
	// strictly before them).
	doneA := make(chan struct{})
	doneB := make(chan struct{})
	go func() { defer close(doneA); sessA.maybeRetarget() }()
	go func() { defer close(doneB); sessB.maybeRetarget() }()

	// Each session must have received exactly its OWN job push, with
	// its OWN new difficulty — not the other session's.
	pushA := clientA.recvJobPush()
	pushB := clientB.recvJobPush()
	<-doneA
	<-doneB

	if got := sessA.currentDifficulty.Load(); got != 1500 {
		t.Errorf("session A currentDifficulty = %d, want 1500", got)
	}
	if got := sessB.currentDifficulty.Load(); got != 900 {
		t.Errorf("session B currentDifficulty = %d, want 900", got)
	}
	if sessA.currentDifficulty.Load() == sessB.currentDifficulty.Load() {
		t.Fatal("expected the two sessions to retarget to DIFFERENT difficulties independently")
	}

	if pushA.Params.Target != diffToTargetHex(1500) {
		t.Errorf("session A pushed job target = %q, want difficulty-1500 target", pushA.Params.Target)
	}
	if pushB.Params.Target != diffToTargetHex(900) {
		t.Errorf("session B pushed job target = %q, want difficulty-900 target", pushB.Params.Target)
	}

	// Neither session's job push carries the other's xn.
	if pushA.Params.XN != sessA.XN() {
		t.Errorf("session A's pushed job carries xn %q, want %q", pushA.Params.XN, sessA.XN())
	}
	if pushB.Params.XN != sessB.XN() {
		t.Errorf("session B's pushed job carries xn %q, want %q", pushB.Params.XN, sessB.XN())
	}
}

// TestRetargetOnlyPushesAffectedSessionNotOthers is the integration
// test explicitly required by the task: after ONE session's retarget,
// only that session gets a fresh job push; a second, unrelated,
// CONNECTED session must receive nothing from that event.
func TestRetargetOnlyPushesAffectedSessionNotOthers(t *testing.T) {
	h := newVardiffHarness(t, 1000, 1<<62, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})

	clientAffected, sessAffected := h.connectAndLogin("addr-affected")
	clientBystander, sessBystander := h.connectAndLogin("addr-bystander")
	_ = sessBystander

	sessAffected.connectedAt = time.Now().Add(-90 * time.Second)
	sessAffected.hashesAccumulated.Store(600000) // triggers a real change

	// maybeRetarget's pushJob does a real, blocking mc.Write (see
	// TestSessionRetargetsAfterIntervalAndPushesNewJob's comment on
	// net.Pipe()'s synchronous semantics) -- run it concurrently with
	// the read below rather than strictly before it.
	go sessAffected.maybeRetarget()

	// Affected session gets its job push.
	push := clientAffected.recvJobPush()
	if push.Params.XN != sessAffected.XN() {
		t.Errorf("expected the pushed job's xn to belong to the affected session")
	}

	// The bystander must have received NOTHING: send it a keepalive
	// and confirm the very next message on its wire is that
	// keepalive's own response, not an unrelated job push that would
	// indicate a broadcast.
	clientBystander.send(Request{ID: 1, JsonRPC: "2.0", Method: "keepalived"})
	raw := clientBystander.recvRaw()
	var errResp ErrorResponse
	if err := json.Unmarshal(raw, &errResp); err != nil {
		t.Fatalf("unmarshal bystander keepalive response: %v", err)
	}
	if errResp.Result != "KEEPALIVED" {
		t.Errorf("expected the bystander's next message to be its own keepalive response (no broadcast job push), got %q", string(raw))
	}
}
