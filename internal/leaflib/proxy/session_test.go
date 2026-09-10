// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
)

// --- test fixtures -----------------------------------------------------

// fakeBlob returns a synthetic, but STRUCTURALLY REAL, CryptoNote
// block_header-shaped blob: single-byte major/minor version varints,
// a single-byte timestamp varint, a 32-byte zeroed prev_id, a 4-byte
// zeroed nonce field, and padding out to totalLen so a reservedOffset
// placed well after the real header fields has room. This lets
// blockHeaderNonceOffset (blockheader.go) locate the real nonce field
// exactly as it would in a genuine pool-published blob.
func fakeBlob(totalLen, reservedOffset int) []byte {
	b := make([]byte, totalLen)
	b[0] = 1  // major_version
	b[1] = 1  // minor_version
	b[2] = 50 // timestamp (kept < 128 so it's a single varint byte)
	// bytes [3:35) prev_id, [35:39) nonce -- left zero.
	_ = reservedOffset
	return b
}

// fakeTemplateSource is a deterministic, offline stand-in for
// UpstreamClient implementing TemplateSource, so tests never need a
// real upstream pool connection.
type fakeTemplateSource struct {
	mu      sync.Mutex
	current *WorkerTemplate
	subs    map[uint64]func(*WorkerTemplate)
	nextSub uint64
}

func newFakeTemplateSource(t *WorkerTemplate) *fakeTemplateSource {
	return &fakeTemplateSource{current: t, subs: make(map[uint64]func(*WorkerTemplate))}
}

func (f *fakeTemplateSource) CurrentTemplate() *WorkerTemplate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current
}

func (f *fakeTemplateSource) Subscribe(fn func(*WorkerTemplate)) func() {
	f.mu.Lock()
	id := f.nextSub
	f.nextSub++
	f.subs[id] = fn
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		delete(f.subs, id)
		f.mu.Unlock()
	}
}

func (f *fakeTemplateSource) setTemplate(t *WorkerTemplate) {
	f.mu.Lock()
	f.current = t
	subs := make([]func(*WorkerTemplate), 0, len(f.subs))
	for _, fn := range f.subs {
		subs = append(subs, fn)
	}
	f.mu.Unlock()
	for _, fn := range subs {
		fn(t)
	}
}

// fakeValidator is a deterministic ShareValidator: it accepts iff
// resultHex decodes to exactly wantValidHex (or, if empty, accepts
// anything that decodes as hex) -- letting tests control PoW validity
// independently of real RandomX hashing.
type fakeValidator struct {
	mu     sync.Mutex
	calls  int
	accept bool
	err    error
}

func (f *fakeValidator) ValidateBlobSeedResult(_ context.Context, _, _ []byte, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.accept, f.err
}

func (f *fakeValidator) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeUpstream is a mock UpstreamSubmitter that records whether
// SubmitShare was ever called, so tests can assert it was NOT invoked
// for a below-block-target share, without touching a real pool.
type fakeUpstream struct {
	mu      sync.Mutex
	calls   int
	lastJob string
	accept  bool
	err     error
}

func (f *fakeUpstream) SubmitShare(_ context.Context, jobID, _, _ string, _, _ uint32) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastJob = jobID
	return f.accept, f.err
}

func (f *fakeUpstream) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// hashForDifficulty computes a 32-byte little-endian hash whose
// littleEndianDifficulty (difficulty.go) is EXACTLY diff, so tests can
// deterministically construct a claimed "result" hex at a known
// difficulty without needing a real RandomX computation.
func hashForDifficulty(diff uint64) string {
	maxU256 := new(uint256.Int).SetAllOne()
	scalar := new(uint256.Int).Div(maxU256, uint256.NewInt(diff))
	beBytes := scalar.Bytes32() // big-endian
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = beBytes[31-i]
	}
	return hex.EncodeToString(le)
}

// --- test harness --------------------------------------------------

type harness struct {
	t         *testing.T
	server    *Server
	source    *fakeTemplateSource
	validator *fakeValidator
	upstream  *fakeUpstream
	cancel    context.CancelFunc
}

func newHarness(t *testing.T, vardiff leaflib.VardiffConfig, jobMaxAge time.Duration) *harness {
	t.Helper()
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1, // this harness's fake upstream never publishes client_pool_offset
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	validator := &fakeValidator{accept: true}
	upstream := &fakeUpstream{accept: true}

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, upstream, log.New(nil2Writer{}, "", 0), vardiff, jobMaxAge)

	h := &harness{t: t, server: server, source: source, validator: validator, upstream: upstream, cancel: cancel}
	t.Cleanup(cancel)
	return h
}

// nil2Writer discards all log output during tests.
type nil2Writer struct{}

func (nil2Writer) Write(p []byte) (int, error) { return len(p), nil }

type testClient struct {
	t      *testing.T
	client net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func (h *harness) connect() (*testClient, *Session) {
	return h.connectAtDifficulty(1000)
}

// connectAtDifficulty is connect but with a caller-chosen starting
// difficulty -- added for tests that need session difficulty to be
// LOW enough for a genuinely-random real hash (e.g. a real RandomX
// computation, not a hand-picked hashForDifficulty value) to clear the
// per-share difficulty gate before the block-target check even runs.
func (h *harness) connectAtDifficulty(startingDifficulty uint64) (*testClient, *Session) {
	h.t.Helper()
	serverConn, clientConn := net.Pipe()
	ctx := context.Background()
	go h.server.handleConn(ctx, serverConn, startingDifficulty)

	c := &testClient{t: h.t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
	h.t.Cleanup(func() { _ = clientConn.Close() })
	return c, nil
}

func (h *harness) sessionCount() int { return h.server.SessionCount() }

func (h *harness) onlySession() *Session {
	h.server.mu.RLock()
	defer h.server.mu.RUnlock()
	for _, s := range h.server.sessions {
		return s
	}
	return nil
}

func (c *testClient) send(req Request) {
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

func (c *testClient) recvRaw() []byte {
	c.t.Helper()
	_ = c.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	return line
}

func (c *testClient) recvLoginResponse() LoginResponse {
	c.t.Helper()
	var resp LoginResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		c.t.Fatalf("unmarshal login response: %v", err)
	}
	return resp
}

func (c *testClient) recvJobPush() JobPush {
	c.t.Helper()
	var push JobPush
	if err := json.Unmarshal(c.recvRaw(), &push); err != nil {
		c.t.Fatalf("unmarshal job push: %v", err)
	}
	return push
}

func (c *testClient) recvShareResponse() ShareResponse {
	c.t.Helper()
	var resp ShareResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		c.t.Fatalf("unmarshal share response: %v", err)
	}
	return resp
}

func (c *testClient) login(t *testing.T, address string) LoginResponse {
	t.Helper()
	params, err := json.Marshal(LoginRequest{Login: address, Pass: "worker1", Agent: "XMRig/6.21.0"})
	if err != nil {
		t.Fatalf("marshal login params: %v", err)
	}
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: params})
	return c.recvLoginResponse()
}

// nonceHexAt returns an 8-hex-char (4-byte) nonce value.
func nonceHexAt(n uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return hex.EncodeToString(b)
}

// --- tests -----------------------------------------------------------

func TestSession_LoginGetJobSubmit_FullFlow(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()

	loginResp := c.login(t, "test-address-1")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}
	if loginResp.Result.Job.Blob == "" {
		t.Fatal("expected a non-empty job blob in the login response")
	}
	if loginResp.Result.Job.Algo != "rx/0" {
		t.Errorf("expected algo=rx/0, got %q", loginResp.Result.Job.Algo)
	}

	// getjob
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "getjob"})
	jobPush := c.recvJobPush()
	if jobPush.Params.JobID == "" {
		t.Fatal("expected a non-empty job_id from getjob")
	}

	// submit against the getjob-issued job, below both session
	// difficulty and block target initially unknown -- use a
	// difficulty comfortably ABOVE the session's starting difficulty
	// (1000) but below the upstream target (1,000,000): a real,
	// valid, locally-credited-only share.
	claimedHash := hashForDifficulty(50_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobPush.Params.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	c.send(Request{ID: 3, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	shareResp := c.recvShareResponse()
	if shareResp.Result == nil {
		t.Fatalf("expected the submit to be accepted, got error=%v", shareResp.Error)
	}
	if h.upstream.callCount() != 0 {
		t.Errorf("expected NO upstream submit call for a below-block-target share, got %d calls", h.upstream.callCount())
	}
}

// TestSession_ShareBelowBlockTarget_CreditedLocallyNotForwarded is
// THE CORE REGRESSION TEST for
// fix/leaf-proxy-gate-randomx-verify-on-target: a share whose claimed
// difficulty is ABOVE the session's own StaticDifficulty but BELOW
// job.UpstreamShareDiff (the common "accepted locally, not forwarded
// upstream" case) must now be credited WITHOUT ever calling the real,
// expensive RandomX re-validation (fakeValidator.callCount() == 0) --
// see randomx_puregolang.go's documented contract and handleSubmit's
// own doc comment. Before this fix, this exact case called the
// validator too (callCount() == 1) and simply discarded the result
// once the upstream-forward decision was made -- this assertion is
// the literal proof that expensive call is now genuinely skipped.
func TestSession_ShareBelowBlockTarget_CreditedLocallyNotForwarded(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "addr-below-target")

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	// Difficulty comfortably between the session's share difficulty
	// (1000, the harness's default starting difficulty) and the
	// upstream block target (1,000,000, from newHarness's template).
	claimedHash := hashForDifficulty(500_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(2), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("expected accepted share, got error=%v", resp.Error)
	}

	if h.upstream.callCount() != 0 {
		t.Fatalf("share below block target must NEVER be forwarded upstream, but SubmitShare was called %d time(s)", h.upstream.callCount())
	}
	if h.validator.callCount() != 0 {
		t.Fatalf("REGRESSION: share below job.UpstreamShareDiff must credit locally WITHOUT ever calling the real RandomX re-validation -- got %d call(s)", h.validator.callCount())
	}
	if sess.shareCount.Load() != 1 {
		t.Errorf("expected local shareCount=1, got %d", sess.shareCount.Load())
	}
	if sess.blockCount.Load() != 0 {
		t.Errorf("expected local blockCount=0 (not a block-level find), got %d", sess.blockCount.Load())
	}
}

// TestSession_ShareMeetingBlockTarget_ForwardedUpstream is the
// positive-path proof (testing requirement 2 from the brief): a
// share meeting/exceeding job.UpstreamShareDiff must STILL call the
// real validator exactly once and be forwarded upstream when
// validation succeeds -- the genuine block-level-find path must be
// completely unaffected by the reordering fix.
func TestSession_ShareMeetingBlockTarget_ForwardedUpstream(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "addr-block-find")
	sess := h.onlySession()

	// Difficulty ABOVE the upstream block target (1,000,000).
	claimedHash := hashForDifficulty(2_000_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(3), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("expected accepted block-level find, got error=%v", resp.Error)
	}
	if h.validator.callCount() != 1 {
		t.Fatalf("expected exactly one real RandomX re-validation call for a genuine upstream-forward candidate, got %d", h.validator.callCount())
	}
	if h.upstream.callCount() != 1 {
		t.Fatalf("expected exactly one upstream submit call for a genuine block-level find, got %d", h.upstream.callCount())
	}
	if h.upstream.lastJob != "upstream-job-1" {
		t.Errorf("expected the upstream pool's OWN job_id to be forwarded, got %q", h.upstream.lastJob)
	}
	if sess.blockCount.Load() != 1 {
		t.Errorf("expected local blockCount=1, got %d", sess.blockCount.Load())
	}
}

// TestSession_UpstreamForwardCandidate_FailedRevalidation_RejectedNotDowngraded
// is testing requirement 3 from the brief: a share that meets/exceeds
// job.UpstreamShareDiff (would otherwise be forwarded upstream) but
// fails the real RandomX re-validation must be REJECTED outright --
// never silently downgraded to a local-only credit -- and must never
// reach the upstream pool at all.
func TestSession_UpstreamForwardCandidate_FailedRevalidation_RejectedNotDowngraded(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.validator.accept = false // real re-validation says: not a valid proof
	c, _ := h.connect()
	loginResp := c.login(t, "addr-failed-revalidation")
	sess := h.onlySession()

	// Difficulty ABOVE the upstream block target (1,000,000): a
	// genuine would-be upstream-forward candidate.
	claimedHash := hashForDifficulty(2_000_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(9), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected a would-be upstream-forward candidate that fails real re-validation to be REJECTED outright, not credited")
	}
	if h.validator.callCount() != 1 {
		t.Fatalf("expected the real RandomX re-validation to have actually been called exactly once, got %d", h.validator.callCount())
	}
	if h.upstream.callCount() != 0 {
		t.Fatalf("a share failing real re-validation must NEVER be forwarded upstream, got %d call(s)", h.upstream.callCount())
	}
	if sess.shareCount.Load() != 0 {
		t.Errorf("expected NO local credit (not downgraded to a local-only share) for a failed re-validation, got shareCount=%d", sess.shareCount.Load())
	}
	if sess.blockCount.Load() != 0 {
		t.Errorf("expected blockCount=0 for a failed re-validation, got %d", sess.blockCount.Load())
	}
}

// TestSession_ShareBelowStaticDifficulty_RejectedWithoutValidatorCall
// is testing requirement 4 from the brief: a share below even the
// session's own StaticDifficulty must be rejected before any real
// RandomX re-validation call at all -- confirming the cheap
// diff-derivation-then-StaticDifficulty-check ordering happens fully
// before the expensive validator call regardless of outcome.
func TestSession_ShareBelowStaticDifficulty_RejectedWithoutValidatorCall(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "addr-below-static-diff")
	sess := h.onlySession()

	// Difficulty BELOW the session's own starting/configured
	// difficulty (1000, the harness default).
	claimedHash := hashForDifficulty(500)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(10), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected a share below the session's own StaticDifficulty to be rejected")
	}
	if h.validator.callCount() != 0 {
		t.Fatalf("a share below StaticDifficulty must be rejected WITHOUT any real RandomX re-validation call, got %d call(s)", h.validator.callCount())
	}
	if h.upstream.callCount() != 0 {
		t.Errorf("a share below StaticDifficulty must never be forwarded upstream, got %d call(s)", h.upstream.callCount())
	}
	if sess.shareCount.Load() != 0 {
		t.Errorf("expected NO local credit for a share below StaticDifficulty, got shareCount=%d", sess.shareCount.Load())
	}
}

func TestSession_CryptographicallyInvalidShare_Rejected(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.validator.accept = false // real RandomXValidator says: not a valid proof
	c, _ := h.connect()
	loginResp := c.login(t, "addr-invalid")

	claimedHash := hashForDifficulty(2_000_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(4), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected a cryptographically invalid share to be rejected")
	}
	if h.upstream.callCount() != 0 {
		t.Errorf("an invalid share must never be forwarded upstream, got %d calls", h.upstream.callCount())
	}
}

// TestSession_JobOwnership_CrossSessionSubmitRejected mirrors
// leaf-solo's job-ownership security fix, ported to this new leaf
// mode: a submit against ANOTHER session's job_id must be rejected,
// and must NOT be forwarded upstream.
func TestSession_JobOwnership_CrossSessionSubmitRejected(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	cA, _ := h.connect()
	loginA := cA.login(t, "addr-a")

	cB, _ := h.connect()
	loginB := cB.login(t, "addr-b")

	if loginA.Result.Job.JobID == loginB.Result.Job.JobID {
		t.Fatal("expected two independently-connected sessions to receive different job_ids")
	}

	// Session B submits against session A's job_id.
	claimedHash := hashForDifficulty(2_000_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginB.Result.ID, JobID: loginA.Result.Job.JobID, Nonce: nonceHexAt(5), Result: claimedHash})
	cB.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := cB.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected a cross-session job_id submit to be rejected")
	}
	if h.upstream.callCount() != 0 {
		t.Errorf("a rejected cross-session submit must never reach the upstream pool, got %d calls", h.upstream.callCount())
	}
}

func TestSession_DuplicateNonceRejected(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "addr-dup")

	claimedHash := hashForDifficulty(50_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(6), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	first := c.recvShareResponse()
	if first.Result == nil {
		t.Fatalf("expected first submit to be accepted, got %v", first.Error)
	}

	c.send(Request{ID: 3, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	second := c.recvShareResponse()
	if second.Result != nil {
		t.Fatal("expected a replayed nonce to be rejected")
	}
}

func TestSession_UnknownJobIDRejected(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "addr-unknown-job")

	claimedHash := hashForDifficulty(50_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: "not-a-real-job-id", Nonce: nonceHexAt(7), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected an unknown job_id to be rejected")
	}
}

func TestSession_JobExpiry(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 10*time.Millisecond)
	c, _ := h.connect()
	loginResp := c.login(t, "addr-expiry")

	time.Sleep(30 * time.Millisecond)

	claimedHash := hashForDifficulty(50_000)
	submitParams, _ := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(8), Result: claimedHash})
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result != nil {
		t.Fatal("expected an expired job's submit to be rejected")
	}
}

func TestJobManager_NoUpstreamTemplateYet(t *testing.T) {
	source := newFakeTemplateSource(nil)
	jm := NewJobManager(source, nil)
	_, err := jm.NextJob(1000)
	if !errors.Is(err, ErrNoUpstreamTemplate) {
		t.Fatalf("expected ErrNoUpstreamTemplate, got %v", err)
	}
}

// TestSession_AlreadyDelivered_SameJobSameDifficultyIsDeliveredAgain is
// the Part B regression test from the brief (Alex's live production
// report: "Proxy is having some job staleness issues, it's disabling
// as soon as a new job is sent, it needs to allow jobs 2-3 old, just
// like the -direct has to"), option (a) from the brief's testing
// guidance: a focused, Session-level unit test of alreadyDelivered
// (mirroring solo.Session's/direct.Session's identical method
// exactly), since JobManager.NextJob always allocates a brand-new
// random job.ID on every call (see server.go's repushAllSessions doc
// comment) -- driving two consecutive NextJob calls through the real
// production entry point can never coincidentally collide on the same
// job_id, so the real gate this method backs
// (Server.repushAllSessions' `if sess.alreadyDelivered(job) {
// continue }`) is only exercisable directly at this level, exactly as
// the brief anticipates.
//
// Uses REAL *Job values obtained from the real JobManager (the same
// production entry point Server.repushAllSessions itself calls), not
// hand-fabricated ones, and drives them through the real jobPayload
// choke point (the same one handleLogin/pushJob/repushAllSessions all
// funnel through) rather than poking the atomic fields directly.
func TestSession_AlreadyDelivered_SameJobSameDifficultyIsDeliveredAgain(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	c.login(t, "test-address-1")
	// Drain the login response's own JobPush... login's response is
	// a LoginResponse, not a JobPush, so nothing further to drain
	// here; c.login already consumed it via recvLoginResponse.

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a session after login")
	}

	// nil job never matches -- mirrors solo.Session.alreadyDelivered's
	// own explicit nil guard.
	if sess.alreadyDelivered(nil) {
		t.Fatal("alreadyDelivered(nil) must be false")
	}

	// Obtain two REAL, independently-issued jobs from the real
	// JobManager, at the session's own current difficulty -- exactly
	// what Server.repushAllSessions itself does on every call.
	jobA, err := h.server.jobs.NextJob(sess.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("NextJob (A): %v", err)
	}
	jobB, err := h.server.jobs.NextJob(sess.currentDifficulty.Load())
	if err != nil {
		t.Fatalf("NextJob (B): %v", err)
	}
	if jobA.ID == jobB.ID {
		t.Fatalf("expected two independently-issued jobs to have distinct job_ids, got %q twice", jobA.ID)
	}

	// Reset this session's delivery bookkeeping to a clean, known
	// slate (login already delivered its own job via jobPayload) so
	// the cases below start from "nothing delivered yet".
	sess.lastDeliveredJobID.Store("")
	sess.lastDeliveredDifficulty.Store(uint64(0))
	if sess.alreadyDelivered(jobA) {
		t.Fatal("alreadyDelivered must be false before anything has actually been delivered")
	}

	// Real delivery via jobPayload -- the exact same choke point
	// handleLogin/pushJob/repushAllSessions all go through before
	// putting a job on the wire (see jobPayload's doc comment).
	_ = sess.jobPayload(jobA)

	// THE CORE ASSERTION (the "skip" branch): the same job, delivered
	// again unchanged (same job_id AND same StaticDifficulty), must
	// be reported as already delivered -- this is the exact condition
	// that makes Server.repushAllSessions skip a redundant,
	// unsolicited repush of a job this session already has.
	if !sess.alreadyDelivered(jobA) {
		t.Fatal("expected alreadyDelivered(jobA) to be true immediately after jobPayload(jobA) delivered it -- this is the real gate repushAllSessions relies on")
	}

	// THE "DOES NOT SKIP" BRANCH, case 1: a genuinely DIFFERENT job
	// (different job_id) must NOT be considered already delivered --
	// proving this isn't "never repush again after the first
	// delivery".
	if sess.alreadyDelivered(jobB) {
		t.Fatal("expected alreadyDelivered(jobB) to be false -- jobB has a different job_id than what was actually delivered")
	}

	// THE "DOES NOT SKIP" BRANCH, case 2: the SAME job_id as jobA,
	// but a genuinely different StaticDifficulty (a real vardiff
	// retarget while the underlying upstream template hasn't
	// changed) must NOT be considered already delivered -- see
	// lastDeliveredJobID's doc comment (session.go) for why BOTH
	// fields are tracked, not job.ID alone: a legitimate difficulty/
	// target update sharing the same job_id must still reach the
	// miner.
	retargeted := &Job{ID: jobA.ID, StaticDifficulty: jobA.StaticDifficulty + 1}
	if sess.alreadyDelivered(retargeted) {
		t.Fatal("expected alreadyDelivered to be false when StaticDifficulty genuinely changed, even with the same job_id")
	}
}

// TestServer_RepushAllSessions_PushesFreshJobOnGenuineUpstreamUpdate is
// an end-to-end, real-code-path regression test for the "does not
// skip" branch of Server.repushAllSessions' new alreadyDelivered gate
// (Part B of the brief): a real upstream template update (fired via
// jobs.Subscribe, the exact real production trigger -- login, getjob,
// or an unsolicited push all funnel through UpstreamClient.notify)
// must still result in a genuinely fresh job being pushed to every
// logged-in downstream session, proving the new gate does not
// silently swallow legitimate repushes.
func TestServer_RepushAllSessions_PushesFreshJobOnGenuineUpstreamUpdate(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	loginResp := c.login(t, "test-address-1")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	newTmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            124,
		JobID:             "upstream-job-2",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
	}

	// repushAllSessions' unsolicited pushJob write blocks (net.Pipe is
	// unbuffered/synchronous) until the client side actually reads it
	// -- start that read concurrently BEFORE triggering the update,
	// so the write below has a waiting reader instead of stalling
	// until this harness's idle timeout tears the connection down.
	pushCh := make(chan JobPush, 1)
	go func() { pushCh <- c.recvJobPush() }()

	h.source.setTemplate(newTmpl)

	var push JobPush
	select {
	case push = <-pushCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for repushAllSessions to push a fresh job after a real upstream template update")
	}
	if push.Params.JobID == "" {
		t.Fatal("expected repushAllSessions to push a genuinely fresh job after a real upstream template update, got none")
	}
	if push.Params.JobID == loginResp.Result.Job.JobID {
		t.Fatal("expected the repushed job_id to differ from the login-issued job_id (JobManager.NextJob always allocates a fresh job_id)")
	}
}

// fakeUpstreamWithGeneration additionally implements the optional
// UpstreamGenerationSource capability (server.go), for testing the
// real generation-staleness type-assertion path in
// Session.handleSubmit -- mirrors server_test.go's
// fakeUpstreamWithHealth pattern exactly (embed the plain
// fakeUpstream, add only the new capability's method(s) on top).
type fakeUpstreamWithGeneration struct {
	fakeUpstream
	generation atomic.Uint64
}

func (f *fakeUpstreamWithGeneration) CurrentGeneration() uint64 { return f.generation.Load() }

// TestSession_StaleTemplateGenerationRejectedLocally_NotForwardedUpstream
// is the real, end-to-end regression test for the
// leaf-proxy-stale-generation-submit fix (confirmed real production
// log evidence: "upstream submit failed... share does not meet
// configured difficulty or is cryptographically invalid", tens of
// seconds after a real upstream reconnect had already succeeded).
//
// Sequence: mint a job while the upstream client's own
// CurrentGeneration() is 1 (matching the template's own Generation),
// submit a genuine would-be upstream-forward candidate against it --
// this must proceed completely normally (non-regression: a
// current-generation job must still forward upstream exactly as
// before this fix). THEN simulate a reconnect completing (bump the
// fake upstream's own generation to 2, WITHOUT touching the
// session's already-cached job, exactly mirroring the real race this
// fix closes: the session doesn't yet know its job is stale) and
// submit AGAIN against the SAME (now-stale) job_id with a fresh
// nonce -- this must be rejected LOCALLY, with fakeUpstream.
// SubmitShare and the real RandomX validator BOTH never called a
// second time.
func TestSession_StaleTemplateGenerationRejectedLocally_NotForwardedUpstream(t *testing.T) {
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
		Generation:        1,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	validator := &fakeValidator{accept: true}
	upstream := &fakeUpstreamWithGeneration{}
	upstream.accept = true
	upstream.generation.Store(1)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, upstream, log.New(nil2Writer{}, "", 0), leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, 1000)
	t.Cleanup(func() { _ = clientConn.Close() })
	c := &testClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}

	loginResp := c.login(t, "addr-generation-test")

	// Non-regression sanity: the job was minted while
	// job.TemplateGeneration (1) == upstream.CurrentGeneration() (1)
	// -- a genuine upstream-forward candidate submitted now must
	// proceed completely normally, exactly as before this fix.
	claimedHash := hashForDifficulty(2_000_000) // above the 1,000,000 upstream block target
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("expected the current-generation submit to be accepted, got error=%v", resp.Error)
	}
	if upstream.callCount() != 1 {
		t.Fatalf("expected exactly 1 upstream submit call for the current-generation share, got %d", upstream.callCount())
	}
	if validator.callCount() != 1 {
		t.Fatalf("expected exactly 1 real RandomX re-validation call for the current-generation share, got %d", validator.callCount())
	}

	// Simulate a real reconnect completing: the upstream client's
	// OWN live generation advances (exactly what applyJob's
	// generation increment does on a reconnect-triggered login), but
	// this session's already-issued job -- still job_id
	// loginResp.Result.Job.JobID -- still carries the OLD
	// generation (1), exactly reproducing the real race this fix
	// closes.
	upstream.generation.Store(2)

	// Submit AGAIN against the SAME (now-stale) job_id, with a fresh
	// nonce (avoids the unrelated duplicate-nonce rejection) and
	// still a genuine would-be upstream-forward-candidate difficulty.
	submitParams2, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(2), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal second submit params: %v", err)
	}
	c.send(Request{ID: 3, JsonRPC: "2.0", Method: "submit", Params: submitParams2})
	resp2 := c.recvShareResponse()
	if resp2.Result != nil {
		t.Fatal("expected a submit against a stale-generation job to be REJECTED locally, got accepted")
	}
	if resp2.Error == nil || resp2.Error.Message == "" {
		t.Fatal("expected a non-empty rejection message explaining the generation staleness")
	}

	// THE core assertions: neither the expensive real RandomX
	// re-validation nor the upstream forward call must have been
	// invoked a SECOND time -- the stale submit must be rejected
	// before any of that work, and must never reach the upstream
	// pool at all.
	if upstream.callCount() != 1 {
		t.Fatalf("a stale-generation submit must NEVER be forwarded upstream -- expected callCount to remain 1, got %d", upstream.callCount())
	}
	if validator.callCount() != 1 {
		t.Fatalf("a stale-generation submit must be rejected before the expensive RandomX re-validation call -- expected callCount to remain 1, got %d", validator.callCount())
	}
}

// TestSession_GenerationCheck_FailsOpenWhenUpstreamHasNoGenerationCapability
// is the explicit "fail open, don't regress" contract test required
// by the leaf-proxy-stale-generation-submit fix: when the concrete
// upstream type is a bare fakeUpstream that does NOT implement
// UpstreamGenerationSource at all (exactly like the vast majority of
// this package's existing tests, via newHarness), a submit must
// behave EXACTLY as before this change -- no false-positive
// staleness rejection is even possible, since the type-assertion in
// Session.handleSubmit simply fails and the whole staleness check is
// skipped.
func TestSession_GenerationCheck_FailsOpenWhenUpstreamHasNoGenerationCapability(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	// Precondition, made explicit: this harness's upstream is a bare
	// fakeUpstream with no generation capability at all.
	if _, ok := h.server.upstream.(UpstreamGenerationSource); ok {
		t.Fatal("precondition failed: this test requires an upstream that does NOT implement UpstreamGenerationSource")
	}

	c, _ := h.connect()
	loginResp := c.login(t, "addr-no-generation-capability")

	// A genuine would-be upstream-forward candidate must still
	// proceed all the way through to a real upstream forward,
	// completely unaffected by the (skipped) staleness check.
	claimedHash := hashForDifficulty(2_000_000)
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(3), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("expected the submit to be accepted (no generation capability -> staleness check skipped entirely), got error=%v", resp.Error)
	}
	if h.upstream.callCount() != 1 {
		t.Fatalf("expected exactly 1 upstream submit call, got %d -- a missing UpstreamGenerationSource capability must never block a genuine upstream forward", h.upstream.callCount())
	}
	if h.validator.callCount() != 1 {
		t.Fatalf("expected exactly 1 real RandomX re-validation call, got %d", h.validator.callCount())
	}
}

// TestHandleSubmit_BannedAddressAndStaleGeneration_BothReject is the
// real interaction test for the PR #85 rebase reconciliation of two
// independent, both-legitimate handleSubmit fixes: 49ae357's
// submit-time address-ban re-check and f2bfa0b's upstream-template
// generation-staleness check. Both checks are placed back-to-back in
// handleSubmit (ban re-check first, then generation staleness -- see
// that function's own doc comment for the full ordering rationale),
// so a submit that is BOTH from a now-banned address AND against a
// now-stale upstream template generation must be rejected -- and,
// since either reason is independently sufficient, this test pins
// down which rejection message actually wins: the ban re-check, since
// it is checked first. This is a deliberate, documented choice (see
// session.go's handleSubmit doc comment), not an accident -- this
// test exists specifically so a future reordering of these two checks
// cannot silently change which rejection reason a real miner sees
// without a test noticing.
func TestHandleSubmit_BannedAddressAndStaleGeneration_BothReject(t *testing.T) {
	addr := "banned-and-stale-generation"
	tmpl := &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        1_000_000,
		Difficulty:        1000,
		Generation:        1,
	}
	source := newFakeTemplateSource(tmpl)
	jm := NewJobManager(source, nil)
	validator := &fakeValidator{accept: true}
	upstream := &fakeUpstreamWithGeneration{}
	upstream.accept = true
	upstream.generation.Store(1)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, upstream, log.New(nil2Writer{}, "", 0), leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	// Address-flags cache, starting unbanned so login succeeds --
	// mirrors addressflags_enforcement_test.go's mid-session-ban
	// pattern exactly.
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{}}
	cache := addressflags.NewCache(src, 20*time.Millisecond, nil)
	cache.Start(ctx)
	server.EnableAddressFlags(cache)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, 1000)
	t.Cleanup(func() { _ = clientConn.Close() })
	c := &testClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}

	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("setup: expected login to succeed while unbanned, got status=%q", loginResp.Result.Status)
	}
	jobID := loginResp.Result.Job.JobID

	// Simulate BOTH real conditions becoming true at once, mirroring
	// each fix's own individual test exactly: (1) a real upstream
	// reconnect advances the upstream client's own generation past
	// this already-issued job's TemplateGeneration (1), and (2) an
	// operator bans this address mid-session.
	upstream.generation.Store(2)
	src.set(addr, addressflags.Flags{Banned: true})
	waitForCachePoll(t, cache, addr, true)

	// A genuine would-be upstream-forward-candidate submit against
	// the SAME (now-stale AND now-banned) job/address.
	claimedHash := hashForDifficulty(2_000_000) // above the 1,000,000 upstream block target
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: jobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()

	if resp.Result != nil {
		t.Fatal("expected a submit that is BOTH from a banned address AND against a stale generation to be rejected, got accepted")
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatal("expected a non-empty rejection message")
	}

	// THE pinned-down behavior: the ban re-check is ordered first in
	// handleSubmit (see that function's own doc comment), so its
	// rejection message is the one a real miner sees here -- NOT the
	// generation-staleness message. This is deliberate and
	// documented, not accidental.
	const wantMessage = "this address is banned from this pool"
	if resp.Error.Message != wantMessage {
		t.Fatalf("expected the ban re-check's rejection message %q to win over the generation-staleness message, got %q", wantMessage, resp.Error.Message)
	}

	// Neither the expensive real RandomX re-validation nor the
	// upstream forward call must ever have been invoked -- the
	// submit is rejected before either check's own downstream work
	// (nonce decode, blob construction, difficulty derivation,
	// async-pool dispatch) ever runs.
	if upstream.callCount() != 0 {
		t.Fatalf("a submit rejected for being banned/stale must never reach the upstream pool, got %d calls", upstream.callCount())
	}
	if validator.callCount() != 0 {
		t.Fatalf("a submit rejected for being banned/stale must never reach the real RandomX re-validation call, got %d calls", validator.callCount())
	}
}
