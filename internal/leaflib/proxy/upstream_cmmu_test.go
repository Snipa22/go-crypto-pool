// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"testing"
	"time"
)

// fakePoolServer is a minimal, real TCP server that speaks just
// enough of the upstream JSON-RPC login dialect for UpstreamClient's
// dialAndLogin to succeed against it, and then immediately drops the
// connection after replying -- so every real dial+login round-trip
// this test drives is followed by a real, unplanned connection loss,
// forcing readLoop's real reconnectLoop hand-off (see readLoop's doc
// comment) to fire repeatedly for the duration of the test.
type fakePoolServer struct {
	ln net.Listener
}

func newFakePoolServer(t *testing.T) *fakePoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake pool listener: %v", err)
	}
	s := &fakePoolServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakePoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *fakePoolServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

// fakeLoginRequest is the subset of the real Request envelope this
// fake server needs to read the request id back out and reply.
type fakeLoginRequest struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
}

func (s *fakePoolServer) handle(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	var req fakeLoginRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		return
	}
	// A trivially-valid 76-byte blob (152 hex chars) and a
	// well-formed seed hash so applyJob's real hex-decoding path
	// succeeds -- this test only cares about the real dial+login
	// round-trip and the cmMu-protected field swap under a real
	// reconnect churn, not about exercising validator/job-template
	// correctness (covered by other tests).
	blob := make([]byte, 152)
	for i := range blob {
		blob[i] = '0'
	}
	resp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"fake-session","status":"OK","job":{"job_id":"fake-job-1","blob":"%s","target_diff":1000,"height":1,"seed_hash":"%s"}}}`,
		req.ID, string(blob), "0000000000000000000000000000000000000000000000000000000000000000")
	_, _ = conn.Write([]byte(resp + "\n"))
	// Deliberately drop the connection right after the login reply,
	// forcing readLoop's scanner to terminate and the real
	// reconnect-vs-close race this test exists to catch.
}

// TestUpstreamClient_ConcurrentReconnectAndClose_NoDataRace is the
// real proof cmMu is doing its job: it drives a real UpstreamClient
// through a real, repeated connect -> reconnect churn (via a fake
// pool server that logs the client in and then immediately drops
// every connection, forcing readLoop's real reconnectLoop hand-off
// on each cycle, all running in that one continuously-alive
// background goroutine) while the test's own goroutine calls the
// real Close() concurrently with whatever reconnect attempt happens
// to be in flight at that moment. Both reconnectLoop's dialAndLogin
// (writes uc.cm/uc.mc under cmMu.Lock) and Close (reads them under
// cmMu.Lock) therefore run concurrently in practice. Run with
// `go test -race`: if cmMu were removed or misplaced, this reliably
// trips the race detector on the real, unsynchronized uc.cm/uc.mc
// access.
func TestUpstreamClient_ConcurrentReconnectAndClose_NoDataRace(t *testing.T) {
	pool := newFakePoolServer(t)
	host, port := pool.addr()

	uc := NewUpstreamClient(UpstreamConfig{
		Host:           host,
		Port:           port,
		Login:          "test-address",
		Pass:           "x",
		DialTimeout:    2 * time.Second,
		RequestTimeout: 2 * time.Second,
	}, log.New(nowhere{}, "", 0))

	if err := uc.Connect(t.Context()); err != nil {
		t.Fatalf("initial Connect against fake pool server failed: %v", err)
	}

	// Let the real reconnect churn (readLoop -> reconnectLoop ->
	// dialAndLogin -> readLoop -> ...) run concurrently with Close
	// being called from another goroutine, for long enough that
	// -race has ample opportunity to observe the real concurrent
	// cm/mc access if cmMu weren't protecting it.
	time.Sleep(300 * time.Millisecond)
	if err := uc.Close(); err != nil {
		t.Fatalf("Close returned an unexpected error: %v", err)
	}
}

// nowhere is an io.Writer that discards everything -- used to keep
// this test's real reconnect churn from spamming test output with
// real log.Logger lines.
type nowhere struct{}

func (nowhere) Write(p []byte) (int, error) { return len(p), nil }

// wellBehavedFakePoolServer is a real TCP server that logs a client
// in exactly like fakePoolServer above, but -- unlike fakePoolServer
// -- does NOT drop the connection afterwards: it just keeps the
// socket open and idle, the way a real, healthy upstream pool
// behaves between jobs. This isolates the exact regression this test
// file exists to catch (readLoop must be reading the socket BEFORE
// login()'s blocking round-trip goes out, or Connect() deadlocks
// waiting on a response readLoop never delivers) from the separate
// reconnect-churn/cmMu-race scenario fakePoolServer drives above: if
// readLoop starts after dialAndLogin (the regression), THIS test
// would hang until RequestTimeout/DialTimeout and fail exactly like
// the real bug report's `login request:... did not respond` error --
// with no reconnect churn involved at all, so a fix that only
// happened to paper over the churn scenario without fixing the real
// startup ordering would still be caught here.
type wellBehavedFakePoolServer struct {
	ln net.Listener
}

func newWellBehavedFakePoolServer(t *testing.T) *wellBehavedFakePoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start well-behaved fake pool listener: %v", err)
	}
	s := &wellBehavedFakePoolServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *wellBehavedFakePoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *wellBehavedFakePoolServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *wellBehavedFakePoolServer) handle(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		conn.Close()
		return
	}
	var req fakeLoginRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		conn.Close()
		return
	}
	blob := make([]byte, 152)
	for i := range blob {
		blob[i] = '0'
	}
	resp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"well-behaved-session","status":"OK","job":{"job_id":"well-behaved-job-1","blob":"%s","target_diff":1000,"height":1,"seed_hash":"%s"}}}`,
		req.ID, string(blob), "0000000000000000000000000000000000000000000000000000000000000000")
	_, _ = conn.Write([]byte(resp + "\n"))
	// Deliberately do NOT close conn here -- keep it open and idle,
	// like a real healthy pool connection between jobs, until the
	// test's own Close()/listener teardown ends it.
	<-make(chan struct{}) // block this handler goroutine; conn stays open until test cleanup closes the listener/conn's underlying fd via process exit or explicit close below.
}

// TestUpstreamClient_Connect_LoginCompletesWithoutDeadlock is the
// focused regression test for the exact readLoop-after-dialAndLogin
// ordering bug: against a real, correctly-behaving fake pool server
// that does NOT force reconnect churn, a real Connect() call must
// complete (i.e. login() must actually receive its response) well
// within a short, real timeout. Before the fix, this test hangs for
// the full RequestTimeout and fails with the exact
// "did not respond to request id 1" error the live regression
// report captured, because readLoop wasn't started until AFTER
// dialAndLogin (and therefore login()) had already returned.
func TestUpstreamClient_Connect_LoginCompletesWithoutDeadlock(t *testing.T) {
	pool := newWellBehavedFakePoolServer(t)
	host, port := pool.addr()

	uc := NewUpstreamClient(UpstreamConfig{
		Host:           host,
		Port:           port,
		Login:          "test-address",
		Pass:           "x",
		DialTimeout:    2 * time.Second,
		RequestTimeout: 2 * time.Second,
	}, log.New(nowhere{}, "", 0))
	t.Cleanup(func() { _ = uc.Close() })

	done := make(chan error, 1)
	go func() { done <- uc.Connect(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Connect against well-behaved fake pool server failed: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Connect did not complete within 500ms -- readLoop/login ordering regression (deadlock waiting for a response readLoop never delivered)")
	}

	if !uc.Connected() {
		t.Fatal("Connect succeeded but Connected() reports false")
	}
	if uc.SessionID() != "well-behaved-session" {
		t.Fatalf("unexpected session id after login: %q", uc.SessionID())
	}
	if tmpl := uc.CurrentTemplate(); tmpl == nil || tmpl.JobID != "well-behaved-job-1" {
		t.Fatalf("expected initial job template from login result, got: %+v", tmpl)
	}
}
