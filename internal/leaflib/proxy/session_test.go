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
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
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
	if sess.shareCount.Load() != 1 {
		t.Errorf("expected local shareCount=1, got %d", sess.shareCount.Load())
	}
	if sess.blockCount.Load() != 0 {
		t.Errorf("expected local blockCount=0 (not a block-level find), got %d", sess.blockCount.Load())
	}
}

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
