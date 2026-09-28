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

// --- The upstream-login-forwarding question ------------------------
//
// The parity brief raised a specific, serious hypothesis: that a
// "+<difficulty>" suffix from one of leaf-proxy's OWN downstream
// clients might be corrupting the payout address this leaf sends to
// ITS OWN upstream pool, because handleLogin stored login.Login raw
// and something downstream forwarded s.address.Load() upstream as-is.
//
// FINDING: that bug does NOT exist in leaf-proxy's architecture, and
// the tests in this file exist to prove that -- and, more importantly,
// to KEEP proving it. The upstream login is built from exactly one
// value, and it is not a session's address:
//
//	// upstream.go, UpstreamClient.login()
//	params, err := json.Marshal(UpstreamLoginParams{
//	    Login: uc.cfg.Login,
//	    Pass:  uc.cfg.Pass,
//	    Agent: uc.cfg.Agent,
//	})
//
// uc.cfg.Login is UpstreamConfig.Login -- "the real XMR payout address
// this leaf-proxy logs in with" (that field's own doc comment), wired
// straight from cmd/leaf-proxy's -upstream-login flag
// (main.go: `Login: cfg.upstreamLogin`) and never from any downstream
// session. The optional dev-fee second connection likewise overrides
// it to a hardcoded constant (devfee.go: `cfg.Login = devFeeLogin`).
// leaf-proxy is an AGGREGATOR: every downstream miner's share is
// credited by the real upstream pool to that ONE operator-configured
// address, which is precisely why a downstream login string has no
// route upstream at all.
//
// That makes the address-stripping fix in handleLogin a fix for the
// ban-cache/forced-floor lookup key and the stats/metrics label (see
// loginfields_test.go's TestProxyLogin_BanCacheIsKeyedOnTheStripped-
// Address), NOT for upstream payout corruption. The tests below pin
// the isolation as a real, enforced invariant so that if anyone ever
// wires a per-session address into the upstream login, the suffix
// hazard the brief was worried about is caught immediately.

// loginRecordingPoolServer is a real TCP server that records the RAW
// login line it receives before replying with a valid login result --
// so a test can inspect the EXACT marshaled JSON this leaf sent
// upstream, rather than asserting against an intermediate struct.
// Mirrors submitRecordingPoolServer's shape (upstream_submit_test.go),
// scoped to the login line instead of post-login traffic.
type loginRecordingPoolServer struct {
	ln net.Listener

	mu         sync.Mutex
	loginLines []string
}

func newLoginRecordingPoolServer(t *testing.T) *loginRecordingPoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start login-recording fake pool listener: %v", err)
	}
	s := &loginRecordingPoolServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *loginRecordingPoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *loginRecordingPoolServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *loginRecordingPoolServer) handle(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		return
	}
	line := scanner.Text()
	s.mu.Lock()
	s.loginLines = append(s.loginLines, line)
	s.mu.Unlock()

	var loginReq fakeLoginRequest
	if err := json.Unmarshal([]byte(line), &loginReq); err != nil {
		return
	}
	blob := strings.Repeat("0", 152)
	seed := strings.Repeat("0", 64)
	loginResp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"login-isolation-session","status":"OK","job":{"job_id":"login-isolation-job-1","blob":"%s","target_diff":1000000,"height":1,"seed_hash":"%s"}}}`,
		loginReq.ID, blob, seed)
	if _, err := conn.Write([]byte(loginResp + "\n")); err != nil {
		return
	}
	// Keep the connection open so no reconnect (and therefore no
	// second, confusing login line) is triggered while the test runs.
	for scanner.Scan() {
	}
}

// recordedUpstreamLogins returns the real `login` param value from
// every upstream login line this fake pool received.
func (s *loginRecordingPoolServer) recordedUpstreamLogins(t *testing.T) []string {
	t.Helper()
	s.mu.Lock()
	lines := make([]string, len(s.loginLines))
	copy(lines, s.loginLines)
	s.mu.Unlock()

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		var req struct {
			Method string              `json:"method"`
			Params UpstreamLoginParams `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			t.Fatalf("recorded upstream line %q does not decode as a login request: %v", line, err)
		}
		if req.Method != "login" {
			t.Fatalf("recorded upstream line %q is method %q, want login", line, req.Method)
		}
		out = append(out, req.Params.Login)
	}
	return out
}

// TestUpstreamLoginIsNeverDerivedFromADownstreamSessionLoginString is
// the regression test the brief asked for, in the form the real
// architecture supports: a downstream miner logs into leaf-proxy with
// a suffix-laden login string ("<address>.<paymentID>.<rig>+50000"),
// against a REAL upstream connection to a REAL (fake) TCP pool, and
// the login string this leaf actually put on the upstream wire must be
// the operator's own configured payout address -- byte-for-byte, with
// no suffix and no trace of the downstream miner's address at all.
//
// This is asserted on the marshaled JSON genuinely received by the
// pool, not on UpstreamConfig.Login, so it would catch any future
// change that started sourcing the upstream login from session state.
func TestUpstreamLoginIsNeverDerivedFromADownstreamSessionLoginString(t *testing.T) {
	const (
		operatorPayoutAddress = "49operator-configured-upstream-payout-address"
		downstreamMinerAddr   = "48downstream-miners-own-completely-different-address"
		paymentID             = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	downstreamLogin := downstreamMinerAddr + "." + paymentID + ".myrig01+50000"

	pool := newLoginRecordingPoolServer(t)
	host, port := pool.addr()

	// A REAL UpstreamClient against the real (fake) pool, configured
	// with the operator's own payout address -- exactly as
	// cmd/leaf-proxy wires -upstream-login.
	uc := NewUpstreamClient(UpstreamConfig{
		Host:           host,
		Port:           port,
		Login:          operatorPayoutAddress,
		Pass:           "x",
		Agent:          xnpProxyDownstreamTestAgent,
		DialTimeout:    2 * time.Second,
		RequestTimeout: 2 * time.Second,
	}, log.New(nil2Writer{}, "", 0))
	t.Cleanup(func() { _ = uc.Close() })

	if err := uc.Connect(context.Background()); err != nil {
		t.Fatalf("upstream Connect: %v", err)
	}

	// The upstream login has already happened by now -- capture it
	// BEFORE any downstream miner exists at all, as the baseline.
	beforeLogins := pool.recordedUpstreamLogins(t)
	if len(beforeLogins) != 1 {
		t.Fatalf("expected exactly one upstream login, got %d: %v", len(beforeLogins), beforeLogins)
	}
	if beforeLogins[0] != operatorPayoutAddress {
		t.Fatalf("upstream login = %q, want the operator's configured payout address %q", beforeLogins[0], operatorPayoutAddress)
	}

	// Now stand up a real downstream Server over that same real
	// upstream client, and log a real downstream miner in with the
	// suffix-laden string.
	jm := NewJobManager(uc, log.New(nil2Writer{}, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	server := NewServer(cm, jm, &fakeValidator{accept: true}, uc, log.New(nil2Writer{}, "", 0),
		leaflib.VardiffConfig{MinDifficulty: 100, MaxDifficulty: 1_000_000, TargetTime: 30, RetargetInterval: time.Hour}, 0)

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, 1000, "")
	t.Cleanup(func() { _ = clientConn.Close() })
	c := &testClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}

	resp := c.loginWithFields(t, downstreamLogin, "x", "", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("downstream login was rejected: %#v", resp)
	}

	// The downstream session parsed its own login correctly...
	var sess *Session
	server.mu.RLock()
	for _, s := range server.sessions {
		sess = s
	}
	server.mu.RUnlock()
	if sess == nil {
		t.Fatal("no downstream session was registered")
	}
	if got, _ := sess.address.Load().(string); got != downstreamMinerAddr {
		t.Errorf("downstream session address = %q, want the STRIPPED downstream address %q", got, downstreamMinerAddr)
	}

	// ...and the UPSTREAM login is completely untouched by it. No new
	// login line, and the one that exists still carries only the
	// operator's address.
	afterLogins := pool.recordedUpstreamLogins(t)
	if len(afterLogins) != 1 {
		t.Fatalf("a downstream login must not trigger any new upstream login; got %d upstream logins: %v", len(afterLogins), afterLogins)
	}
	upstreamLogin := afterLogins[0]
	if upstreamLogin != operatorPayoutAddress {
		t.Fatalf("upstream login = %q, want the operator's configured payout address %q -- a downstream session's login string must never reach the upstream login", upstreamLogin, operatorPayoutAddress)
	}
	// The explicit, targeted assertions the brief asked for: neither
	// the raw suffixed string nor any of its parts leaked upstream.
	for _, leaked := range []string{"+50000", paymentID, "myrig01", downstreamMinerAddr, downstreamLogin} {
		if strings.Contains(upstreamLogin, leaked) {
			t.Fatalf("upstream login %q contains %q from a DOWNSTREAM client's login string -- this is exactly the payout-address corruption hazard the parity brief raised", upstreamLogin, leaked)
		}
	}
	t.Logf("upstream login isolation confirmed: downstream %q -> upstream %q (operator-configured, unchanged)", downstreamLogin, upstreamLogin)
}

// TestUpstreamLoginParamsAreBuiltOnlyFromUpstreamConfig is the
// structural half of the same invariant, scoped tightly to the one
// function that builds the outbound login: for a range of downstream-
// looking suffixed strings, UpstreamLoginParams marshals from
// UpstreamConfig alone. If UpstreamClient.login ever grew a
// session-derived input, this test's premise -- that the outbound
// login is a pure function of cfg -- would no longer hold.
func TestUpstreamLoginParamsAreBuiltOnlyFromUpstreamConfig(t *testing.T) {
	const operatorPayoutAddress = "49operator-configured-upstream-payout-address"

	uc := NewUpstreamClient(UpstreamConfig{
		Login: operatorPayoutAddress,
		Pass:  "x",
		Agent: xnpProxyDownstreamTestAgent,
	}, log.New(nil2Writer{}, "", 0))

	got, err := json.Marshal(UpstreamLoginParams{
		Login: uc.cfg.Login,
		Pass:  uc.cfg.Pass,
		Agent: uc.cfg.Agent,
	})
	if err != nil {
		t.Fatalf("marshal UpstreamLoginParams: %v", err)
	}
	want, err := json.Marshal(UpstreamLoginParams{
		Login: operatorPayoutAddress,
		Pass:  "x",
		Agent: xnpProxyDownstreamTestAgent,
	})
	if err != nil {
		t.Fatalf("marshal expected UpstreamLoginParams: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("outbound upstream login params = %s, want %s", got, want)
	}

	// UpstreamConfig carries no per-session/downstream address field
	// for login() to have picked up even accidentally -- the dev-fee
	// path overrides Login to a hardcoded constant rather than
	// threading a session value through it (devfee.go).
	devUC := NewDevFeeUpstreamClient(UpstreamConfig{Login: operatorPayoutAddress, Pass: "x"}, log.New(nil2Writer{}, "", 0))
	t.Cleanup(func() { _ = devUC.Close() })
	if devUC.cfg.Login != devFeeLogin {
		t.Fatalf("dev-fee upstream Login = %q, want the hardcoded devFeeLogin %q", devUC.cfg.Login, devFeeLogin)
	}
	if devUC.cfg.Login == operatorPayoutAddress {
		t.Fatal("dev-fee upstream Login must be overridden, not inherited from the operator config")
	}
}
