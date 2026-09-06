// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// keepaliveRecordingPoolServer is a real TCP server that logs a
// client in exactly like wellBehavedFakePoolServer
// (upstream_cmmu_test.go), keeps the connection open afterward (a
// real healthy pool does not close the socket between jobs) --
// and, unlike that server, additionally records every subsequent
// line it reads after the login reply. This is what lets
// TestUpstreamClient_HeartbeatLoop_SendsKeepalivedPeriodically below
// observe the real, unprompted "keepalived" lines this leaf sends on
// its own during an otherwise-idle connection.
type keepaliveRecordingPoolServer struct {
	ln net.Listener

	mu    sync.Mutex
	lines []string
}

func newKeepaliveRecordingPoolServer(t *testing.T) *keepaliveRecordingPoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start keepalive-recording fake pool listener: %v", err)
	}
	s := &keepaliveRecordingPoolServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *keepaliveRecordingPoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *keepaliveRecordingPoolServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *keepaliveRecordingPoolServer) handle(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		return
	}
	var req fakeLoginRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		return
	}
	blob := make([]byte, 152)
	for i := range blob {
		blob[i] = '0'
	}
	resp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"keepalive-session","status":"OK","job":{"job_id":"keepalive-job-1","blob":"%s","target_diff":1000,"height":1,"seed_hash":"%s"}}}`,
		req.ID, string(blob), "0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := conn.Write([]byte(resp + "\n")); err != nil {
		return
	}
	// Deliberately keep reading (and recording every subsequent
	// line) instead of closing -- this is where a real, unprompted
	// "keepalived" request from this leaf's own heartbeatLoop would
	// show up on the wire, exactly as it would against a real,
	// healthy pool between jobs.
	for scanner.Scan() {
		line := scanner.Text()
		s.mu.Lock()
		s.lines = append(s.lines, line)
		s.mu.Unlock()
	}
}

func (s *keepaliveRecordingPoolServer) recordedLines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.lines))
	copy(out, s.lines)
	return out
}

// TestUpstreamClient_HeartbeatLoop_SendsKeepalivedPeriodically is the
// real end-to-end proof of the ported reference heartbeat
// (proxy.js's `setInterval(pool.heartbeat, 30000)` ->
// `sendData('keepalived')` -- see upstream.go's heartbeatLoop/
// sendKeepalive doc comments): against a real fake pool server that
// stays open after login (like a real healthy upstream pool between
// jobs), a real UpstreamClient must send an unprompted "keepalived"
// request on its own -- with params carrying the pool-assigned
// session id from the login response -- well within a couple
// multiples of a (test-shortened) heartbeat interval.
func TestUpstreamClient_HeartbeatLoop_SendsKeepalivedPeriodically(t *testing.T) {
	orig := upstreamHeartbeatInterval
	upstreamHeartbeatInterval = 50 * time.Millisecond
	t.Cleanup(func() { upstreamHeartbeatInterval = orig })

	pool := newKeepaliveRecordingPoolServer(t)
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

	if err := uc.Connect(context.Background()); err != nil {
		t.Fatalf("Connect against keepalive-recording fake pool server failed: %v", err)
	}

	var found map[string]any
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range pool.recordedLines() {
			var msg map[string]any
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				continue
			}
			if msg["method"] == "keepalived" {
				found = msg
				break
			}
		}
		if found != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if found == nil {
		t.Fatalf("no keepalived request observed within deadline; recorded lines: %v", pool.recordedLines())
	}
	if _, hasID := found["id"]; !hasID {
		t.Fatalf("keepalived request had no numeric id: %v", found)
	}
	params, ok := found["params"].(map[string]any)
	if !ok {
		t.Fatalf("keepalived request params were not an object: %v", found)
	}
	if params["id"] != "keepalive-session" {
		t.Fatalf("keepalived request params.id = %v, want %q (the pool-assigned session id)", params["id"], "keepalive-session")
	}
}

// TestUpstreamClient_HeartbeatLoop_NoGoroutineLeakAcrossReconnects is
// the regression test for the exact leak dialAndLogin's/readLoop's
// doc comments warn about avoiding: a heartbeat ticker goroutine
// that outlives its own connection generation would leak one per
// reconnect cycle. This drives a real UpstreamClient through an
// initial connect plus several real reconnect cycles
// (fakePoolServer, from upstream_cmmu_test.go, drops the connection
// right after every login, forcing readLoop's real reconnectLoop
// hand-off each time -- heartbeatLoop for each of those generations
// must also always stop promptly, via its own generation's
// stopHeartbeat channel), then an explicit Close, then asserts (via
// goleak, which retries internally -- see go.uber.org/goleak's
// default maxRetries/maxSleep -- giving any just-signalled readLoop/
// heartbeatLoop goroutine a real chance to finish exiting) that no
// goroutine -- heartbeat or otherwise -- is left running. Does NOT
// need to lower upstreamHeartbeatInterval: the assertion is that
// heartbeatLoop goroutines are gone after Close, regardless of
// whether their ticker ever actually fired, and Close's
// heartbeatWG.Wait() (upstream.go) already makes that a real,
// synchronized guarantee rather than something this test has to
// race a sleep against.
//
// Uses goleak.IgnoreCurrent() (snapshotted at the very top of this
// test, before dialing anything) rather than a bare
// goleak.VerifyNone(t): this package's OWN pre-existing test harness
// (wellBehavedFakePoolServer.handle, upstream_cmmu_test.go) parks a
// handler goroutine on a channel that is never sent to or closed --
// a deliberate, permanent leak-by-design for ITS OWN test's purposes
// (see that type's doc comment), which would otherwise cause an
// unrelated PASS/FAIL flip here depending purely on test ordering.
// IgnoreCurrent scopes this test's assertion to goroutines that are
// still around from actions THIS test itself took, which is the
// actual regression being guarded against here.
func TestUpstreamClient_HeartbeatLoop_NoGoroutineLeakAcrossReconnects(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

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

	if err := uc.Connect(context.Background()); err != nil {
		t.Fatalf("initial Connect against fake pool server failed: %v", err)
	}

	// Let several real reconnect cycles happen -- fakePoolServer
	// drops every connection right after login, so
	// readLoop->reconnectLoop->dialAndLogin fires repeatedly, each
	// generation starting (and, on that generation's disconnect,
	// stopping) its own heartbeatLoop.
	time.Sleep(300 * time.Millisecond)

	if err := uc.Close(); err != nil {
		t.Fatalf("Close returned an unexpected error: %v", err)
	}

	// t.Cleanup-registered funcs (including newFakePoolServer's own
	// listener Close) run AFTER this test function returns -- i.e.
	// after the deferred goleak.VerifyNone above already ran. Close
	// the fake pool's listener explicitly here too (harmless to
	// close twice) so its serve() goroutine, blocked in Accept, has
	// actually exited before that check runs instead of being
	// flagged as a false-positive leak.
	_ = pool.ln.Close()
}
