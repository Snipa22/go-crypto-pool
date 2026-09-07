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
)

// submitRecordingPoolServer is a real TCP server that logs a client
// in exactly like keepaliveRecordingPoolServer/fakePoolServer, keeps
// the connection open afterward, and additionally replies to every
// subsequent "submit" request with a real success result -- so
// UpstreamClient.SubmitShare's own uc.send round-trip (which blocks
// on a real response) completes normally instead of timing out. Every
// raw line received after login is recorded, which is what lets this
// file's test inspect the EXACT marshaled JSON this leaf sent for a
// real submit request -- a genuine before/after wire-format proof,
// not just "the field exists" on some intermediate struct.
type submitRecordingPoolServer struct {
	ln net.Listener

	mu    sync.Mutex
	lines []string
}

func newSubmitRecordingPoolServer(t *testing.T) *submitRecordingPoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start submit-recording fake pool listener: %v", err)
	}
	s := &submitRecordingPoolServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *submitRecordingPoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *submitRecordingPoolServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *submitRecordingPoolServer) handle(conn net.Conn) {
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
	loginResp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"submit-test-session","status":"OK","job":{"job_id":"submit-test-job-1","blob":"%s","target_diff":1000,"height":1,"seed_hash":"%s"}}}`,
		loginReq.ID, string(blob), "0000000000000000000000000000000000000000000000000000000000000000")
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

func (s *submitRecordingPoolServer) recordedLines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.lines))
	copy(out, s.lines)
	return out
}

// TestUpstreamClient_SubmitShare_SendsRealSessionIDAndPoolNonce is the
// required brief test: a genuine before/after wire-format proof that
// a real "submit" request sent upstream by UpstreamClient.SubmitShare
// carries BOTH the pool-assigned session id (proxy.js's sendData
// `params.id = this.id` post-login injection -- see
// UpstreamSubmitParams.ID's doc comment, protocol.go) AND a real,
// non-zero poolNonce value (the pool-level nonce echoed back on
// submit -- see UpstreamSubmitParams.PoolNonce's doc comment) on the
// real marshaled JSON actually written to the wire, against a real
// TCP fake pool server (not a struct-level marshal-only assertion).
func TestUpstreamClient_SubmitShare_SendsRealSessionIDAndPoolNonce(t *testing.T) {
	pool := newSubmitRecordingPoolServer(t)
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
		t.Fatalf("Connect against submit-recording fake pool server failed: %v", err)
	}
	if got := uc.SessionID(); got != "submit-test-session" {
		t.Fatalf("SessionID() = %q, want %q (precondition: login must have populated it before submit)", got, "submit-test-session")
	}

	const (
		wantJobID       = "submit-test-job-1"
		wantNonceHex    = "01020304"
		wantResultHex   = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		wantWorkerNonce = uint32(7)
		wantPoolNonce   = uint32(42)
	)
	accepted, err := uc.SubmitShare(context.Background(), wantJobID, wantNonceHex, wantResultHex, wantWorkerNonce, wantPoolNonce)
	if err != nil {
		t.Fatalf("SubmitShare: %v", err)
	}
	if !accepted {
		t.Fatal("expected SubmitShare to report accepted=true for a fake pool server that replies with a real success result")
	}

	var submitLine string
	for _, line := range pool.recordedLines() {
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if msg["method"] == "submit" {
			submitLine = line
			break
		}
	}
	if submitLine == "" {
		t.Fatalf("no submit request observed on the wire; recorded lines: %v", pool.recordedLines())
	}

	var msg map[string]any
	if err := json.Unmarshal([]byte(submitLine), &msg); err != nil {
		t.Fatalf("unmarshaling recorded submit line: %v", err)
	}
	params, ok := msg["params"].(map[string]any)
	if !ok {
		t.Fatalf("submit request params were not an object: %v", msg)
	}

	// The real, genuine before/after proof: BOTH fields present on
	// the wire, with the real, non-empty/non-zero values this test
	// passed in -- not merely "the field exists".
	if got := params["id"]; got != "submit-test-session" {
		t.Errorf(`submit request params["id"] = %v, want %q (the real upstream session id)`, got, "submit-test-session")
	}
	gotPoolNonce, ok := params["poolNonce"].(float64)
	if !ok {
		t.Fatalf(`submit request params["poolNonce"] missing or not a number: %v`, params)
	}
	if uint32(gotPoolNonce) != wantPoolNonce {
		t.Errorf(`submit request params["poolNonce"] = %v, want %d`, params["poolNonce"], wantPoolNonce)
	}

	// Sanity: the pre-existing fields must still be present and
	// correct too (this fix must not regress them).
	if params["job_id"] != wantJobID {
		t.Errorf(`submit request params["job_id"] = %v, want %q`, params["job_id"], wantJobID)
	}
	if params["nonce"] != wantNonceHex {
		t.Errorf(`submit request params["nonce"] = %v, want %q`, params["nonce"], wantNonceHex)
	}
	if params["result"] != wantResultHex {
		t.Errorf(`submit request params["result"] = %v, want %q`, params["result"], wantResultHex)
	}
	gotWorkerNonce, ok := params["workerNonce"].(float64)
	if !ok {
		t.Fatalf(`submit request params["workerNonce"] missing or not a number: %v`, params)
	}
	if uint32(gotWorkerNonce) != wantWorkerNonce {
		t.Errorf(`submit request params["workerNonce"] = %v, want %d`, params["workerNonce"], wantWorkerNonce)
	}
}
