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
	"sync/atomic"
	"testing"
	"time"
)

// churningPoolServer is a real TCP server that logs a client in and
// then serves submit/keepalived requests for a short window before
// dropping the connection -- forcing readLoop's real reconnectLoop
// hand-off (dialAndLogin redialing, relogging in, and reassigning
// uc.cm/uc.mc/uc.sessionID under cmMu) to fire repeatedly WHILE the
// test's own goroutines have SubmitShare/sendKeepalive calls
// genuinely in flight. This is the real repro server for Finding 3's
// two data races (unsynchronized uc.mc read in send, unsynchronized
// uc.sessionID read/write) -- see
// TestUpstreamClient_Send_RacesReconnect_NoDataRace.
type churningPoolServer struct {
	ln net.Listener
}

func newChurningPoolServer(t *testing.T) *churningPoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start churning fake pool listener: %v", err)
	}
	s := &churningPoolServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *churningPoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *churningPoolServer) serve() {
	var gen int64
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		g := atomic.AddInt64(&gen, 1)
		go s.handle(conn, g)
	}
}

// handle logs the connecting client in with a generation-unique
// session id/job id (so a real reassignment is observable, not just
// a repeat of the same values), then answers submit/keepalived
// requests for a short window before returning (closing the
// connection via its defer) to force the next reconnect cycle.
func (s *churningPoolServer) handle(conn net.Conn, gen int64) {
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
	loginResp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"session-gen-%d","status":"OK","job":{"job_id":"job-gen-%d","blob":"%s","target_diff":1000,"height":1,"seed_hash":"%s"}}}`,
		loginReq.ID, gen, gen, string(blob), "0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := conn.Write([]byte(loginResp + "\n")); err != nil {
		return
	}
	deadline := time.Now().Add(30 * time.Millisecond)
	for scanner.Scan() {
		if time.Now().After(deadline) {
			return
		}
		line := scanner.Text()
		var probe fakeLoginRequest
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			continue
		}
		var resp string
		switch probe.Method {
		case "submit":
			resp = fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"status":"OK"}}`, probe.ID)
		case "keepalived":
			resp = fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"status":"KEEPALIVED"}}`, probe.ID)
		default:
			continue
		}
		if _, err := conn.Write([]byte(resp + "\n")); err != nil {
			return
		}
	}
}

// TestUpstreamClient_Send_RacesReconnect_NoDataRace is the required
// Finding 3 regression test: it deliberately races a real reconnect
// (dialAndLogin, driven by readLoop -> reconnectLoop as the fake
// server repeatedly drops the connection) against in-flight
// SubmitShare/sendKeepalive calls hammering the same UpstreamClient
// from multiple goroutines. Confirmed (via a throwaway scratch build
// of the pre-fix code, using this exact test) to reliably trip
// `go test -race` on BOTH of Finding 3's real races:
//   - send's unsynchronized read of uc.mc racing dialAndLogin's
//     cmMu-guarded reassignment of uc.mc.
//   - SubmitShare/sendKeepalive's unsynchronized reads of
//     uc.sessionID racing login's write to it.
//
// After this fix (send snapshotting mc under cmMu; sessionID as an
// atomic.Pointer[string]), this passes cleanly under -race.
func TestUpstreamClient_Send_RacesReconnect_NoDataRace(t *testing.T) {
	pool := newChurningPoolServer(t)
	host, port := pool.addr()

	uc := NewUpstreamClient(UpstreamConfig{
		Host:           host,
		Port:           port,
		Login:          "test-address",
		Pass:           "x",
		DialTimeout:    2 * time.Second,
		RequestTimeout: 500 * time.Millisecond,
	}, log.New(nowhere{}, "", 0))
	t.Cleanup(func() { _ = uc.Close() })

	if err := uc.Connect(context.Background()); err != nil {
		t.Fatalf("initial connect against churning fake pool server failed: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Hammer SubmitShare from several goroutines while the server
	// forces reconnect churn in the background -- this is what
	// races send's uc.mc read against dialAndLogin's uc.mc write.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				_, _ = uc.SubmitShare(ctx, "job", "01020304", "deadbeef", 1, 2)
				cancel()
			}
		}()
	}
	// Hammer sendKeepalive concurrently too -- this is what races
	// its uc.sessionID read against login's uc.sessionID write.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				_ = uc.sendKeepalive(ctx)
				cancel()
			}
		}()
	}

	// Long enough, against a server that churns roughly every 30ms,
	// for many real reconnect generations to race many real
	// in-flight submit/keepalive calls.
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
}
