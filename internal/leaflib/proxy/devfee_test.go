// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// --- devFeeSelector / NewDevFeeSelector -----------------------------

// TestNewDevFeeSelector_NonPositivePercentAlwaysFalse proves a
// defensive, non-positive percent never selects the dev-fee route --
// even though production (cmd/leaf-proxy/main.go's setupDevFee) only
// ever constructs one of these when percent > 0 in the first place.
func TestNewDevFeeSelector_NonPositivePercentAlwaysFalse(t *testing.T) {
	for _, percent := range []float64{0, -1, -100} {
		selector := NewDevFeeSelector(percent)
		for _, offsetFrac := range []float64{0, 0.1, 0.5, 0.99} {
			instant := time.Unix(0, int64(float64(devFeeWindow)*offsetFrac))
			if selector(instant) {
				t.Errorf("NewDevFeeSelector(%v) selected dev-fee at offset fraction %v within the window, want always false", percent, offsetFrac)
			}
		}
	}
}

// TestNewDevFeeSelector_StatisticalDistribution is the required brief
// test: over a simulated window, the rolling time-slice selector
// routes approximately the configured percentage of selections to
// the dev-fee path. Deterministic (no real randomness/sleeping): it
// evenly sweeps a large number of synthetic instants across exactly
// one devFeeWindow and asserts the observed true-rate is within a
// small, reasonable tolerance of the configured percentage --
// exactly matching the statistical-assertion-not-exact-equality
// requirement.
func TestNewDevFeeSelector_StatisticalDistribution(t *testing.T) {
	const samples = 100_000
	base := time.Unix(0, 0)

	for _, percent := range []float64{1, 5, 25, 50, 90} {
		selector := NewDevFeeSelector(percent)
		trueCount := 0
		for i := 0; i < samples; i++ {
			offset := time.Duration(int64(devFeeWindow) * int64(i) / int64(samples))
			if selector(base.Add(offset)) {
				trueCount++
			}
		}
		got := float64(trueCount) / float64(samples) * 100
		const tolerance = 0.5 // percentage points
		if got < percent-tolerance || got > percent+tolerance {
			t.Errorf("percent=%v: observed %.3f%% dev-fee selections over %d evenly-spaced samples across one %s window, want within +/-%.1f points of %v%%",
				percent, got, samples, devFeeWindow, tolerance, percent)
		}
	}
}

// TestNewDevFeeSelector_SelectsExactlyTheFirstSliceOfEachWindow pins
// down the EXACT rule (not just its aggregate statistics): the first
// percent% of every window selects dev-fee, and the selection repeats
// identically in the NEXT window too (this is a rolling/periodic
// rule, not a one-shot window).
func TestNewDevFeeSelector_SelectsExactlyTheFirstSliceOfEachWindow(t *testing.T) {
	selector := NewDevFeeSelector(10) // first 10% of every 100s window = first 10s
	base := time.Unix(0, 0)

	cases := []struct {
		offset time.Duration
		want   bool
	}{
		{0, true},
		{5 * time.Second, true},
		{9999 * time.Millisecond, true},
		{10 * time.Second, false},
		{50 * time.Second, false},
		{99 * time.Second, false},
		// Second window: the rule must repeat identically.
		{devFeeWindow + 0, true},
		{devFeeWindow + 5*time.Second, true},
		{devFeeWindow + 10*time.Second, false},
		{2*devFeeWindow + 9999*time.Millisecond, true},
	}
	for _, tc := range cases {
		got := selector(base.Add(tc.offset))
		if got != tc.want {
			t.Errorf("selector(base + %s) = %v, want %v", tc.offset, got, tc.want)
		}
	}
}

// --- JobManager dev-fee routing / job-template pairing --------------

// TestJobManager_EnableDevFee_NilOrZeroPercentIsANoOp proves
// EnableDevFee is a defensive no-op for a nil source (percent
// irrelevant) -- NextJob must still behave exactly as it did before
// EnableDevFee was ever called, always RoutePrimary.
func TestJobManager_EnableDevFee_NilSourceIsANoOp(t *testing.T) {
	primaryTmpl := &WorkerTemplate{Blob: fakeBlob(76, 50), ReservedOffset: 50, ClientNonceOffset: -1, PoolOffset: -1, JobID: "primary-job", TargetDiff: 1000}
	source := newFakeTemplateSource(primaryTmpl)
	jm := NewJobManager(source, nil)
	jm.EnableDevFee(nil, func(time.Time) bool { return true })

	job, err := jm.NextJob(1000)
	if err != nil {
		t.Fatalf("NextJob: %v", err)
	}
	if job.Route != RoutePrimary {
		t.Errorf("Route = %v, want RoutePrimary when EnableDevFee was called with a nil source", job.Route)
	}
	if job.UpstreamJobID != "primary-job" {
		t.Errorf("UpstreamJobID = %q, want the primary template's job id", job.UpstreamJobID)
	}
}

// TestJobManager_NextJob_DevFeeRoutingMintsFromTheCorrectTemplate is
// THE required "job/template pairing" test: when the selector picks
// the dev-fee route, the resulting Job's UpstreamJobID/Height/
// SeedHash/UpstreamShareDiff must come from the DEV-FEE connection's
// own current template -- never the primary's -- and Job.Route must
// record that fact so session.go's handleSubmit resolves the correct
// connection later. The complementary primary-route case is checked
// in the same test to prove both branches are wired to the correct
// template, not just coincidentally identical.
func TestJobManager_NextJob_DevFeeRoutingMintsFromTheCorrectTemplate(t *testing.T) {
	primaryTmpl := &WorkerTemplate{
		Blob: fakeBlob(76, 50), ReservedOffset: 50, ClientNonceOffset: -1, PoolOffset: -1,
		SeedHash: []byte("primary-seed-hash-32-bytes-long!"), Height: 111,
		JobID: "primary-job-1", TargetDiff: 1000, Difficulty: 1000,
	}
	devFeeTmpl := &WorkerTemplate{
		Blob: fakeBlob(76, 50), ReservedOffset: 50, ClientNonceOffset: -1, PoolOffset: -1,
		SeedHash: []byte("dev-fee-seed-hash-32-bytes-long!"), Height: 222,
		JobID: "dev-fee-job-1", TargetDiff: 2000, Difficulty: 2000,
	}
	primarySource := newFakeTemplateSource(primaryTmpl)
	devFeeSource := newFakeTemplateSource(devFeeTmpl)

	// Route == RouteDevFee branch.
	jmDevFee := NewJobManager(primarySource, nil)
	jmDevFee.EnableDevFee(devFeeSource, func(time.Time) bool { return true })
	devJob, err := jmDevFee.NextJob(500)
	if err != nil {
		t.Fatalf("NextJob (forced dev-fee): %v", err)
	}
	if devJob.Route != RouteDevFee {
		t.Fatalf("Route = %v, want RouteDevFee", devJob.Route)
	}
	if devJob.UpstreamJobID != "dev-fee-job-1" {
		t.Errorf("UpstreamJobID = %q, want the DEV-FEE template's own job id %q, not the primary's", devJob.UpstreamJobID, "dev-fee-job-1")
	}
	if devJob.Height != 222 {
		t.Errorf("Height = %d, want the dev-fee template's own height 222", devJob.Height)
	}
	if devJob.UpstreamShareDiff != 2000 {
		t.Errorf("UpstreamShareDiff = %d, want the dev-fee template's own target_diff 2000", devJob.UpstreamShareDiff)
	}
	if string(devJob.SeedHash) != "dev-fee-seed-hash-32-bytes-long!" {
		t.Errorf("SeedHash = %q, want the dev-fee template's own seed hash", devJob.SeedHash)
	}

	// Route == RoutePrimary branch, same JobManager/selector, just
	// forced false this time -- proves NextJob is NOT hardwired to
	// one template, it genuinely branches per call.
	jmPrimary := NewJobManager(primarySource, nil)
	jmPrimary.EnableDevFee(devFeeSource, func(time.Time) bool { return false })
	primJob, err := jmPrimary.NextJob(500)
	if err != nil {
		t.Fatalf("NextJob (forced primary): %v", err)
	}
	if primJob.Route != RoutePrimary {
		t.Fatalf("Route = %v, want RoutePrimary", primJob.Route)
	}
	if primJob.UpstreamJobID != "primary-job-1" {
		t.Errorf("UpstreamJobID = %q, want the PRIMARY template's own job id %q, not the dev-fee's", primJob.UpstreamJobID, "primary-job-1")
	}
	if primJob.Height != 111 {
		t.Errorf("Height = %d, want the primary template's own height 111", primJob.Height)
	}
}

// TestJobManager_NextJob_DevFeeFaultIsolation_FallsBackToPrimary is
// the required fault-isolation guarantee: if the selector picks
// dev-fee but the dev-fee connection has no live template yet (e.g.
// still dialing/reconnecting), NextJob must fall back to the primary
// connection/RoutePrimary rather than failing the job issuance
// outright -- a transient dev-fee outage must never degrade a real
// downstream job request.
func TestJobManager_NextJob_DevFeeFaultIsolation_FallsBackToPrimary(t *testing.T) {
	primaryTmpl := &WorkerTemplate{
		Blob: fakeBlob(76, 50), ReservedOffset: 50, ClientNonceOffset: -1, PoolOffset: -1,
		JobID: "primary-job-1", TargetDiff: 1000,
	}
	primarySource := newFakeTemplateSource(primaryTmpl)
	devFeeSource := newFakeTemplateSource(nil) // no template yet -- e.g. still connecting

	jm := NewJobManager(primarySource, nil)
	jm.EnableDevFee(devFeeSource, func(time.Time) bool { return true }) // always WANTS dev-fee

	job, err := jm.NextJob(1000)
	if err != nil {
		t.Fatalf("NextJob must fall back to primary, not error, when dev-fee has no template yet: %v", err)
	}
	if job.Route != RoutePrimary {
		t.Errorf("Route = %v, want RoutePrimary (fault-isolation fallback)", job.Route)
	}
	if job.UpstreamJobID != "primary-job-1" {
		t.Errorf("UpstreamJobID = %q, want the primary template's job id", job.UpstreamJobID)
	}
}

// --- end-to-end: two real fake upstream stratum servers -------------

// routedPoolServer is a real TCP server speaking just enough of the
// upstream JSON-RPC login/submit dialect for a real UpstreamClient to
// log in and later forward a submit against it -- parameterized by
// jobID/sessionID (unlike internal/leaflib/proxy's other
// submitRecordingPoolServer, which hardcodes both) so a test can spin
// up two independent instances (primary + dev-fee) and unambiguously
// tell, from the recorded wire lines alone, which one actually
// received a given submit and with which upstream job_id.
type routedPoolServer struct {
	jobID     string
	sessionID string

	ln net.Listener

	mu    sync.Mutex
	lines []string
}

func newRoutedPoolServer(t *testing.T, jobID, sessionID string) *routedPoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start routed fake pool listener: %v", err)
	}
	s := &routedPoolServer{jobID: jobID, sessionID: sessionID, ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *routedPoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *routedPoolServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *routedPoolServer) handle(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		return
	}
	var loginReq fakeLoginRequest
	if err := json.Unmarshal(scanner.Bytes(), &loginReq); err != nil {
		return
	}
	blob := make([]byte, 152)
	for i := range blob {
		blob[i] = '0'
	}
	loginResp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"%s","status":"OK","job":{"job_id":"%s","blob":"%s","target_diff":1000,"height":1,"seed_hash":"%s"}}}`,
		loginReq.ID, s.sessionID, s.jobID, string(blob), "0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := conn.Write([]byte(loginResp + "\n")); err != nil {
		return
	}
	for scanner.Scan() {
		line := scanner.Text()
		s.mu.Lock()
		s.lines = append(s.lines, line)
		s.mu.Unlock()

		var probe fakeLoginRequest
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			continue
		}
		if probe.Method == "submit" {
			resp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"status":"OK"}}`, probe.ID)
			if _, err := conn.Write([]byte(resp + "\n")); err != nil {
				return
			}
		}
	}
}

func (s *routedPoolServer) recordedLines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.lines))
	copy(out, s.lines)
	return out
}

func (s *routedPoolServer) submitLines() []string {
	var out []string
	for _, line := range s.recordedLines() {
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err == nil && msg["method"] == "submit" {
			out = append(out, line)
		}
	}
	return out
}

// TestDevFeeIntegration_SubmitRoutedToDevFeeConnection is the
// required integration-style test: two REAL fake upstream stratum
// TCP servers (primary + dev-fee), a real *UpstreamClient logged in
// against each, a JobManager with the dev-fee mechanism forced ON
// (selector always true), and a full downstream login+submit over a
// real net.Pipe session -- confirming the submit lands on the
// DEV-FEE server's socket, carrying THAT server's own job_id, and
// NEVER on the primary server at all.
func TestDevFeeIntegration_SubmitRoutedToDevFeeConnection(t *testing.T) {
	primaryPool := newRoutedPoolServer(t, "primary-job-1", "primary-session")
	devFeePool := newRoutedPoolServer(t, "dev-fee-job-1", "dev-fee-session")

	logger := log.New(nil2Writer{}, "", 0)

	primaryHost, primaryPort := primaryPool.addr()
	primaryUpstream := NewUpstreamClient(UpstreamConfig{
		Host: primaryHost, Port: primaryPort, Login: "primary-address", Pass: "x",
		DialTimeout: 2 * time.Second, RequestTimeout: 2 * time.Second,
	}, logger)
	if err := primaryUpstream.Connect(context.Background()); err != nil {
		t.Fatalf("connecting primary fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = primaryUpstream.Close() })

	devFeeHost, devFeePort := devFeePool.addr()
	devFeeUpstream := NewUpstreamClient(UpstreamConfig{
		Host: devFeeHost, Port: devFeePort, Login: "dev-fee-address", Pass: "x",
		DialTimeout: 2 * time.Second, RequestTimeout: 2 * time.Second,
	}, logger)
	if err := devFeeUpstream.Connect(context.Background()); err != nil {
		t.Fatalf("connecting dev-fee fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = devFeeUpstream.Close() })

	jm := NewJobManager(primaryUpstream, logger)
	jm.EnableDevFee(devFeeUpstream, func(time.Time) bool { return true }) // force every issuance to dev-fee

	validator := &fakeValidator{accept: true}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, primaryUpstream, logger, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	server.EnableDevFeeUpstream(devFeeUpstream)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, 1000, "")
	t.Cleanup(func() { _ = clientConn.Close() })
	c := &testClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}

	loginResp := c.login(t, "addr-dev-fee-routing")
	if loginResp.Result.Job.JobID == "" {
		t.Fatal("expected a non-empty job id from login")
	}

	claimedHash := hashForDifficulty(2_000_000) // above both fake servers' target_diff=1000
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("expected the submit to be accepted, got error=%v", resp.Error)
	}

	// THE core correctness assertion.
	devFeeSubmits := devFeePool.submitLines()
	if len(devFeeSubmits) != 1 {
		t.Fatalf("dev-fee pool server: got %d submit lines, want exactly 1: %v", len(devFeeSubmits), devFeeSubmits)
	}
	if !strings.Contains(devFeeSubmits[0], `"job_id":"dev-fee-job-1"`) {
		t.Errorf("dev-fee pool server's recorded submit line = %q, want job_id %q", devFeeSubmits[0], "dev-fee-job-1")
	}
	if primarySubmits := primaryPool.submitLines(); len(primarySubmits) != 0 {
		t.Errorf("primary pool server must NEVER receive a submit when the dev-fee route was selected, got: %v", primarySubmits)
	}
}

// TestDevFeeIntegration_SubmitRoutedToPrimaryConnection is the
// complementary case: with the selector forced OFF, a submit lands on
// the PRIMARY server (carrying its own job_id) and the dev-fee server
// never sees anything -- proving dev-fee routing is genuinely
// bidirectional/selective, not an accidental always-dev-fee wiring
// bug that the previous test alone wouldn't catch.
func TestDevFeeIntegration_SubmitRoutedToPrimaryConnection(t *testing.T) {
	primaryPool := newRoutedPoolServer(t, "primary-job-1", "primary-session")
	devFeePool := newRoutedPoolServer(t, "dev-fee-job-1", "dev-fee-session")

	logger := log.New(nil2Writer{}, "", 0)

	primaryHost, primaryPort := primaryPool.addr()
	primaryUpstream := NewUpstreamClient(UpstreamConfig{
		Host: primaryHost, Port: primaryPort, Login: "primary-address", Pass: "x",
		DialTimeout: 2 * time.Second, RequestTimeout: 2 * time.Second,
	}, logger)
	if err := primaryUpstream.Connect(context.Background()); err != nil {
		t.Fatalf("connecting primary fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = primaryUpstream.Close() })

	devFeeHost, devFeePort := devFeePool.addr()
	devFeeUpstream := NewUpstreamClient(UpstreamConfig{
		Host: devFeeHost, Port: devFeePort, Login: "dev-fee-address", Pass: "x",
		DialTimeout: 2 * time.Second, RequestTimeout: 2 * time.Second,
	}, logger)
	if err := devFeeUpstream.Connect(context.Background()); err != nil {
		t.Fatalf("connecting dev-fee fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = devFeeUpstream.Close() })

	jm := NewJobManager(primaryUpstream, logger)
	jm.EnableDevFee(devFeeUpstream, func(time.Time) bool { return false }) // force every issuance to primary

	validator := &fakeValidator{accept: true}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, validator, primaryUpstream, logger, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	server.EnableDevFeeUpstream(devFeeUpstream)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, 1000, "")
	t.Cleanup(func() { _ = clientConn.Close() })
	c := &testClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}

	loginResp := c.login(t, "addr-primary-routing")
	claimedHash := hashForDifficulty(2_000_000)
	submitParams, err := json.Marshal(SubmitRequest{ID: loginResp.Result.ID, JobID: loginResp.Result.Job.JobID, Nonce: nonceHexAt(1), Result: claimedHash})
	if err != nil {
		t.Fatalf("marshal submit params: %v", err)
	}
	c.send(Request{ID: 2, JsonRPC: "2.0", Method: "submit", Params: submitParams})
	resp := c.recvShareResponse()
	if resp.Result == nil {
		t.Fatalf("expected the submit to be accepted, got error=%v", resp.Error)
	}

	primarySubmits := primaryPool.submitLines()
	if len(primarySubmits) != 1 {
		t.Fatalf("primary pool server: got %d submit lines, want exactly 1: %v", len(primarySubmits), primarySubmits)
	}
	if !strings.Contains(primarySubmits[0], `"job_id":"primary-job-1"`) {
		t.Errorf("primary pool server's recorded submit line = %q, want job_id %q", primarySubmits[0], "primary-job-1")
	}
	if devFeeSubmits := devFeePool.submitLines(); len(devFeeSubmits) != 0 {
		t.Errorf("dev-fee pool server must NEVER receive a submit when the primary route was selected, got: %v", devFeeSubmits)
	}
}
