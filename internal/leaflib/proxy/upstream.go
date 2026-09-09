// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-xmr-lib/support"
)

// UpstreamClient is leaf-proxy's real STRATUM CLIENT to an upstream
// Monero-family pool (e.g. pool.supportxmr.com) — this is the
// functional INVERSE of internal/leaflib/solo/node.go's NodeClient
// (a GRPC client to a Tari base node): here, THIS leaf is the one
// dialing out and speaking the real Monero JSON-RPC 2.0 stratum
// dialect as the client side, emulating an "advanced" XMR-Node-Proxy
// mining client (ported from the real xmr-node-proxy reference's
// Pool object, proxy.js ~line 154-287, and its message-dispatch
// counterpart handlePoolMessage/handleNewBlockTemplate, ~line
// 675-727).
//
// Deliberately NOT ported (per explicit instruction): the legacy's 1%
// developer-donation-pool skim (devPool, lib/xmr.js ~line 240-251) —
// no dev/donation pool logic exists anywhere in this type or its
// callers. Also not ported: the legacy's cluster/worker multi-process
// fan-out (this Go process handles every downstream connection in one
// process via goroutines, same model as leaf-solo).
//
// PORTED (this pass): the reference's 30-second `keepalived`
// heartbeat (proxy.js ~line 672: `setInterval(pool.heartbeat,
// 30000)`, installed right after a successful login). Real pools
// (confirmed against pool.supportxmr.com) enforce their own
// server-side idle-connection timeout well under this leaf's local
// IdleTimeout/2m default, silently tearing down an otherwise-healthy
// socket with a clean read-EOF during quiet periods between jobs;
// without this heartbeat that surfaces as constant, unnecessary
// reconnect churn (see heartbeatLoop/sendKeepalive below, and
// dialAndLogin/readLoop's doc comments for how a heartbeat goroutine
// is started/stopped exactly once per connection generation).
type UpstreamClient struct {
	cfg    UpstreamConfig
	logger *log.Logger

	// cm is a dedicated ConnectionManager used purely to get this
	// single upstream socket the SAME lifecycle guarantees leaf-solo's
	// downstream connections already get (single writer goroutine, a
	// rolling idle deadline, idempotent close) — see leaflib.go's doc
	// comment on the five bug classes ManagedConnection fixes. Reusing
	// it here, for an OUTBOUND connection, rather than hand-rolling a
	// second ad hoc net.Conn wrapper, is exactly the "reuse shared
	// infra" requirement applied to the upstream side too.
	// cmMu guards cm/mc against concurrent access between a
	// (re)connect (dialAndLogin, which replaces both after a fresh
	// dial+login) and Close (which reads both to tear them down) —
	// both can run concurrently in practice via reconnectLoop racing
	// an operator-triggered Close. ALSO guards the closed/heartbeatWG
	// hand-off below (dialAndLogin's "is this client already
	// closing, should I even bother starting a heartbeat" check, and
	// Close's own close(uc.closed)) for the same reason: without a
	// shared lock serializing "check closed, then Add" against
	// "close(closed), then Wait", heartbeatWG.Add could race with
	// heartbeatWG.Wait in the narrow window where a reconnect's
	// login finishes concurrently with an operator Close — a real
	// sync.WaitGroup contract violation ("Add ... must happen before
	// Wait"), not just a benign race. Locking cmMu around both sides
	// of that decision makes them strictly ordered instead.
	cmMu sync.Mutex
	cm   *leaflib.ConnectionManager
	mc   *leaflib.ManagedConnection

	sessionID string // the pool's own assigned session id, from the login response

	sendID atomic.Int64

	pendingMu sync.Mutex
	pending   map[int]chan UpstreamResponse

	template atomic.Pointer[WorkerTemplate]

	subMu sync.RWMutex
	subs  map[uint64]func(*WorkerTemplate)
	subID atomic.Uint64

	closeOnce sync.Once
	closed    chan struct{}

	// heartbeatWG tracks every heartbeatLoop goroutine ever started
	// (one per connection generation that successfully logged in --
	// see dialAndLogin) so Close can genuinely wait for all of them
	// to exit before returning, rather than merely signalling them
	// to stop and trusting they will promptly. This is what makes
	// "no heartbeat goroutine outlives Close()" a real, synchronized
	// guarantee instead of a race — see cmMu's doc comment above for
	// how Add/Wait are kept from racing with each other.
	heartbeatWG sync.WaitGroup

	// connected/reconnects back UpstreamHealth (see server.go's
	// UpstreamHealth interface doc comment): connected reflects
	// whether the upstream socket is currently up, reconnects counts
	// real, successful re-establishments after a real connection
	// loss (the initial Connect is NOT counted).
	connected  atomic.Bool
	reconnects atomic.Uint64

	// generation is a monotonic counter identifying which
	// upstream-connection "generation" the CURRENTLY-stored template
	// belongs to -- incremented by exactly 1 every time applyJob
	// actually stores a genuinely NEW template (i.e. inside the
	// upstream-dupe guard's non-dupe branch, right alongside
	// uc.template.Store(t)); a dupe (a getjob poll response or any
	// repeat push carrying the SAME upstream job_id as the currently
	// stored template) does NOT bump this, since it is the same live
	// template, not a new one -- see applyJob's own comment at the
	// exact increment point for why that distinction matters (an
	// over-eager increment on a harmless dupe would falsely
	// stale-reject legitimate in-flight submits).
	//
	// This exists to fix a real, confirmed production issue: when
	// reconnectLoop redials and re-logs-in after a lost upstream
	// connection, login() always calls applyJob with the pool's own
	// FRESH job (a reconnect always produces a genuinely new upstream
	// job_id, so applyJob's dupe guard never suppresses it) -- but
	// any downstream submit already in flight against the OLD,
	// pre-disconnect template still passes this leaf's own local
	// job-ownership check (session.go's ownJob) and, without this
	// generation mechanism, would sail through straight to
	// UpstreamClient.SubmitShare, wasting an upstream round-trip on a
	// submit the pool (having discarded that old session/job state on
	// disconnect) was always going to reject as "share does not meet
	// configured difficulty or is cryptographically invalid".
	// CurrentGeneration() below is the cheap, TOCTOU-free read
	// session.go's handleSubmit uses to reject such a stale submit
	// locally instead.
	generation atomic.Uint64
}

// UpstreamConfig configures a real upstream pool connection.
type UpstreamConfig struct {
	// Host/Port are the real upstream pool's stratum address, e.g.
	// pool.supportxmr.com:7777 (confirmed real, currently-published
	// SupportXMR ports as of this pass: 3333 low-diff, 5555
	// medium-diff, 7777 high-diff, 9000 TLS/SSL — see
	// cmd/leaf-proxy/main.go's doc comment for the source of that
	// confirmation; ports on any pool can drift, this is
	// operator-configured, not hardcoded here).
	Host string
	Port int

	// TLS dials with crypto/tls instead of a plain net.Dial when true
	// (e.g. SupportXMR's published port 9000).
	TLS bool
	// InsecureSkipVerifyTLS disables certificate verification; only
	// intended for testing against a self-signed local mock pool.
	InsecureSkipVerifyTLS bool

	// Login is the real XMR payout address this leaf-proxy logs in
	// with — found blocks/shares upstream are credited to this
	// address by the real pool. Pass is the real pool worker
	// identifier/password (SupportXMR, like most node-cryptonote-pool
	// derivatives, accepts an arbitrary worker-id string here, or "x"
	// if unused).
	Login string
	Pass  string

	// Agent is the mining-client identifier string sent on login.
	// Historically (PR #60, a stopgap this real fix now supersedes)
	// this deliberately did NOT contain the literal substring
	// "xmr-node-proxy", to avoid a real pool's agent-string sniffing
	// (nodejs-pool-sxmr's lib/pool.js: `agent.includes("xmr-node-proxy")`)
	// granting the "advanced xmr-node-proxy client" protocol
	// extension -- which, at the time, meant a raw, untrimmed,
	// arbitrarily-large blocktemplate_blob in place of the ordinary,
	// correctly-sized "blob" job field, something this leaf could not
	// yet safely handle.
	//
	// REVERSED (this pass, live production incident): applyJob now
	// has a real, correct blocktemplate_blob->hashing-blob conversion
	// path (see applyJob's doc comment:
	// support.ParseBlockFromTemplateBlob + support.GetBlockHashingBlob),
	// so receiving that raw blob is no longer a hazard -- but NOT
	// opting into the advanced dialect turned out to be its own,
	// worse hazard: without it, a real pool (confirmed against
	// pool.supportxmr.com) never publishes client_nonce_offset/
	// client_pool_offset on its jobs, so
	// WorkerTemplate.workerNonceOffset() (template.go) always
	// returns -1 and WorkerTemplate.BlobForWorker falls back to
	// handing every downstream miner behind this leaf a
	// byte-identical blob. At low share difficulty independent
	// miners then routinely land on the same nonce and submit the
	// same (job_id, nonce, result) triple, which the upstream pool
	// correctly flags as a duplicate share -- and enough of those in
	// nodejs-pool-sxmr's banThreshold/banPercent window gets this
	// leaf's public IP banned for "using an invalid mining protocol".
	// That is a live-confirmed production incident this default is
	// now fixing, not a hypothetical. This field's DEFAULT is
	// therefore now an agent string containing "xmr-node-proxy" --
	// opting IN to the advanced dialect by default, since it is both
	// safe (post-conversion-fix) and required to get the
	// client_nonce_offset/client_pool_offset partitioning that keeps
	// downstream miners from colliding. An operator who genuinely
	// needs the ordinary, non-advanced dialect instead can still opt
	// out by setting this field to an agent string that does NOT
	// contain "xmr-node-proxy" themselves.
	// Defaults to "go-crypto-pool-leaf-proxy/xmr-node-proxy-<version>"
	// — see cmd/leaf-proxy/main.go.
	Agent string

	DialTimeout    time.Duration
	IdleTimeout    time.Duration
	RequestTimeout time.Duration
}

func (cfg UpstreamConfig) normalized() UpstreamConfig {
	out := cfg
	if out.DialTimeout <= 0 {
		out.DialTimeout = 10 * time.Second
	}
	if out.IdleTimeout <= 0 {
		out.IdleTimeout = 2 * time.Minute
	}
	if out.RequestTimeout <= 0 {
		out.RequestTimeout = 15 * time.Second
	}
	if out.Agent == "" {
		// Deliberately contains the literal substring
		// "xmr-node-proxy" -- see UpstreamConfig.Agent's doc comment
		// for why this is now the default (opting into the
		// advanced/aggregating-proxy dialect on purpose) rather than
		// something to avoid.
		out.Agent = "go-crypto-pool-leaf-proxy/xmr-node-proxy-dev"
	}
	return out
}

// upstreamHeartbeatInterval is how often heartbeatLoop sends a
// keepalived request to the upstream pool once logged in --
// hardcoded to exactly match the reference's
// `setInterval(pool.heartbeat, 30000)` (proxy.js ~line 672), an
// empirically-tuned value, not something this leaf should re-guess
// or expose as an operator-configurable UpstreamConfig field/flag. A
// `var`, not a `const`, purely so a test in this package can lower
// it via a t.Cleanup save/restore for fast, deterministic testing;
// production always runs with this exact 30s value.
var upstreamHeartbeatInterval = 30 * time.Second

// NewUpstreamClient constructs an UpstreamClient. Call Connect to
// actually dial and log in.
func NewUpstreamClient(cfg UpstreamConfig, logger *log.Logger) *UpstreamClient {
	if logger == nil {
		logger = log.Default()
	}
	return &UpstreamClient{
		cfg:     cfg.normalized(),
		logger:  logger,
		pending: make(map[int]chan UpstreamResponse),
		subs:    make(map[uint64]func(*WorkerTemplate)),
		closed:  make(chan struct{}),
	}
}

// Connect dials the real upstream pool, performs the real login, and
// starts the background read loop. On success, an initial
// WorkerTemplate (from the login response's nested "job") is already
// available via CurrentTemplate. If the connection is later lost
// (readLoop's scanner terminating for any reason other than an
// explicit Close), a background reconnectLoop automatically redials
// and re-logs-in with exponential backoff — see reconnectLoop's doc
// comment. Connected()/ReconnectCount() expose this real health state
// for metrics (see server.go's UpstreamHealth interface).
func (uc *UpstreamClient) Connect(ctx context.Context) error {
	if err := uc.dialAndLogin(ctx); err != nil {
		return err
	}
	uc.connected.Store(true)
	return nil
}

// dialAndLogin performs the real dial + ManagedConnection registration
// + login round-trip shared by both the initial Connect and every
// reconnectLoop attempt. It does NOT start readLoop or flip
// uc.connected — callers own that (Connect does it once for the
// initial connection; reconnectLoop does it after a successful
// redial).
//
// FIXED (this pass): readLoop MUST already be reading the socket
// before login()'s request goes out, because login() blocks on
// uc.pending waiting for a response that only readLoop's scanner
// loop can ever deliver — readLoop is therefore started here, right
// after uc.mc is assigned (under cmMu) and BEFORE login() is called,
// rather than by callers after dialAndLogin returns. To avoid a
// duplicate/uncoordinated readLoop goroutine when THIS login attempt
// itself fails (dialAndLogin closes mc/cm on login failure, which is
// what makes this same readLoop's scanner terminate too), readLoop is
// told via loggedIn whether login for this exact connection ever
// actually succeeded: if not, it exits quietly instead of invoking
// reconnectLoop itself — that failure is already being surfaced as
// this function's own return value, to whichever caller (Connect, or
// reconnectLoop's own retry-with-backoff loop) is driving this
// attempt, so a second, independent reconnectLoop invocation from
// inside readLoop would be a real duplicate.
//
// stopHeartbeat is this connection generation's own heartbeat-stop
// channel, created here (unconditionally, alongside loggedIn, before
// readLoop is even started) and handed to readLoop so it can close it
// exactly once when this generation's scanner loop ends, for ANY
// reason (see readLoop's doc comment). The heartbeatLoop goroutine
// itself is only actually started below, after loggedIn.Store(true)
// — i.e. only once login has genuinely succeeded — so a login
// failure never starts a heartbeat in the first place; readLoop
// still closes stopHeartbeat in that case too, which is harmless
// (nothing is listening on it yet) and keeps readLoop as the single,
// unconditional owner of the close call rather than needing a second
// "was it actually started" flag threaded through as well. See the
// caveat above ManagedConnection.Context (connection.go) for why this
// is a fresh plain channel per generation rather than something
// derived from mc.Context().
//
// The heartbeat is started only under cmMu, after re-checking
// uc.closed — see cmMu's doc comment above for why: this is what
// keeps heartbeatWG.Add (here) from ever racing with
// heartbeatWG.Wait (Close) when a reconnect's login happens to
// finish concurrently with an operator-triggered Close.
func (uc *UpstreamClient) dialAndLogin(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", uc.cfg.Host, uc.cfg.Port)
	dialer := &net.Dialer{Timeout: uc.cfg.DialTimeout}

	var conn net.Conn
	var err error
	if uc.cfg.TLS {
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: &tls.Config{InsecureSkipVerify: uc.cfg.InsecureSkipVerifyTLS}} //nolint:gosec // operator opt-in only
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("proxy: dialing upstream pool %s: %w", addr, err)
	}

	cm := leaflib.NewConnectionManager(context.Background(), leaflib.ManagerConfig{
		MaxConnections: 1,
		IdleTimeout:    uc.cfg.IdleTimeout,
	})
	mc, err := cm.Accept(ctx, conn)
	if err != nil {
		cm.Shutdown()
		return fmt.Errorf("proxy: registering upstream connection: %w", err)
	}
	uc.cmMu.Lock()
	uc.cm = cm
	uc.mc = mc
	uc.cmMu.Unlock()

	loggedIn := &atomic.Bool{}
	stopHeartbeat := make(chan struct{})
	go uc.readLoop(mc, loggedIn, stopHeartbeat)

	if _, err := uc.login(ctx); err != nil {
		_ = mc.Close("upstream login failed")
		cm.Shutdown()
		return err
	}
	loggedIn.Store(true)

	uc.cmMu.Lock()
	select {
	case <-uc.closed:
		// The client was explicitly Closed while this login was
		// in flight -- Close has already (or is about to)
		// tear this connection down and call heartbeatWG.Wait;
		// starting a heartbeat now would both be pointless and
		// risk the Add-after-Wait misuse cmMu's doc comment
		// describes. Skip it; login itself genuinely succeeded,
		// so this is still not an error.
		uc.cmMu.Unlock()
		return nil
	default:
	}
	uc.heartbeatWG.Add(1)
	uc.cmMu.Unlock()
	go uc.heartbeatLoop(stopHeartbeat)
	return nil
}

// reconnectLoop is started by readLoop when the upstream connection
// is lost for any reason other than an explicit Close (see readLoop's
// doc comment). It redials and re-logs-in with a real exponential
// backoff (1s, doubling, capped at 30s), incrementing
// UpstreamReconnectsTotal (via ReconnectCount, observed by
// server.go's sessionSnapshots) on every SUCCESSFUL reconnect. Exits
// without further action if uc.closed fires while backing off or
// mid-attempt (an explicit Close during a reconnect attempt is not
// itself a failure worth logging/retrying).
func (uc *UpstreamClient) reconnectLoop() {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		select {
		case <-uc.closed:
			return
		default:
		}

		attemptCtx, cancel := context.WithTimeout(context.Background(), uc.cfg.DialTimeout+uc.cfg.RequestTimeout)
		err := uc.dialAndLogin(attemptCtx)
		cancel()
		if err == nil {
			uc.reconnects.Add(1)
			uc.connected.Store(true)
			uc.logger.Printf("proxy: upstream connection re-established (reconnect #%d)", uc.reconnects.Load())
			return
		}

		uc.logger.Printf("proxy: upstream reconnect attempt failed, retrying in %s: %v", backoff, err)
		select {
		case <-time.After(backoff):
		case <-uc.closed:
			return
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// Connected reports whether the upstream pool connection is currently
// established — implements server.go's UpstreamHealth.
func (uc *UpstreamClient) Connected() bool { return uc.connected.Load() }

// ReconnectCount reports the real, monotonically-increasing count of
// successful reconnects since process start (the initial startup
// Connect is NOT counted) — implements server.go's UpstreamHealth.
func (uc *UpstreamClient) ReconnectCount() uint64 { return uc.reconnects.Load() }

// Close tears down the upstream connection. Also waits (via
// heartbeatWG) for every heartbeatLoop goroutine ever started to
// have genuinely exited before returning — not just signalled to
// stop — so callers (and this package's own goroutine-leak
// regression test) can rely on "Close returned" meaning "no
// heartbeat ticker is still running", not merely "one was asked to
// stop". uc.closed is closed under cmMu (matching dialAndLogin's own
// cmMu-guarded check before Add) specifically so that check-then-Add
// there can never race with this close-then-Wait — see cmMu's doc
// comment for the full reasoning.
func (uc *UpstreamClient) Close() error {
	var err error
	uc.closeOnce.Do(func() {
		uc.cmMu.Lock()
		close(uc.closed)
		mc, cm := uc.mc, uc.cm
		uc.cmMu.Unlock()
		uc.connected.Store(false)
		if mc != nil {
			err = mc.Close("upstream client closed")
		}
		if cm != nil {
			cm.Shutdown()
		}
		uc.heartbeatWG.Wait()
	})
	return err
}

// SessionID returns the pool-assigned session id from the login
// response.
func (uc *UpstreamClient) SessionID() string { return uc.sessionID }

// CurrentTemplate returns the most recently received upstream job as
// a *WorkerTemplate, or nil if no job has been received yet.
func (uc *UpstreamClient) CurrentTemplate() *WorkerTemplate {
	return uc.template.Load()
}

// CurrentGeneration returns the upstream-connection generation number
// of the CURRENTLY-stored template (see uc.generation's doc comment)
// -- implements server.go's UpstreamGenerationSource. Deliberately a
// separate read from CurrentTemplate/WorkerTemplate.Generation rather
// than requiring callers to go through CurrentTemplate() themselves:
// this keeps the staleness check in session.go's handleSubmit cheap
// and avoids any risk of a TOCTOU race between reading the template
// pointer and reading its generation field, since applyJob sets both
// uc.template and uc.generation together, under the same call, before
// either is ever observed by another goroutine.
func (uc *UpstreamClient) CurrentGeneration() uint64 {
	return uc.generation.Load()
}

// Subscribe registers fn to be called (with the new WorkerTemplate)
// every time this client receives a fresh job from the upstream pool
// (login result, getjob result, or an unsolicited push) — mirroring
// solo.JobManager.Subscribe's role of letting Server repush fresh
// jobs to every connected downstream session on tip movement. Returns
// an unsubscribe func.
func (uc *UpstreamClient) Subscribe(fn func(*WorkerTemplate)) func() {
	id := uc.subID.Add(1)
	uc.subMu.Lock()
	uc.subs[id] = fn
	uc.subMu.Unlock()
	return func() {
		uc.subMu.Lock()
		delete(uc.subs, id)
		uc.subMu.Unlock()
	}
}

func (uc *UpstreamClient) notify(t *WorkerTemplate) {
	uc.subMu.RLock()
	fns := make([]func(*WorkerTemplate), 0, len(uc.subs))
	for _, fn := range uc.subs {
		fns = append(fns, fn)
	}
	uc.subMu.RUnlock()
	for _, fn := range fns {
		fn(t)
	}
}

// nextID returns the next outbound JSON-RPC request id (proxy.js's
// `this.sendId++`).
func (uc *UpstreamClient) nextID() int {
	return int(uc.sendID.Add(1))
}

// send writes req to the upstream socket and registers a pending
// response channel keyed by req.ID, mirroring proxy.js's
// `this.sendLog[rawSend.id] = rawSend` bookkeeping (there, used to
// remember which METHOD an id was for; here, the caller already knows
// what it's waiting for, so the channel alone is enough).
func (uc *UpstreamClient) send(ctx context.Context, req Request) (UpstreamResponse, error) {
	ch := make(chan UpstreamResponse, 1)
	uc.pendingMu.Lock()
	uc.pending[req.ID] = ch
	uc.pendingMu.Unlock()
	defer func() {
		uc.pendingMu.Lock()
		delete(uc.pending, req.ID)
		uc.pendingMu.Unlock()
	}()

	buf, err := json.Marshal(req)
	if err != nil {
		return UpstreamResponse{}, fmt.Errorf("proxy: marshaling upstream request: %w", err)
	}
	buf = append(buf, '\n')
	if err := uc.mc.Write(buf); err != nil {
		return UpstreamResponse{}, fmt.Errorf("proxy: writing to upstream pool: %w", err)
	}

	timeout := uc.cfg.RequestTimeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return UpstreamResponse{}, ctx.Err()
	case <-timer.C:
		return UpstreamResponse{}, fmt.Errorf("proxy: upstream pool did not respond to request id %d within %s", req.ID, timeout)
	case <-uc.closed:
		return UpstreamResponse{}, errors.New("proxy: upstream client closed")
	}
}

// login performs the real "login" method — see UpstreamLoginParams's
// doc comment for the exact wire shape ported from the reference's
// Pool.login.
func (uc *UpstreamClient) login(ctx context.Context) (UpstreamLoginResult, error) {
	params, err := json.Marshal(UpstreamLoginParams{
		Login: uc.cfg.Login,
		Pass:  uc.cfg.Pass,
		Agent: uc.cfg.Agent,
	})
	if err != nil {
		return UpstreamLoginResult{}, err
	}
	req := Request{ID: uc.nextID(), JsonRPC: "2.0", Method: "login", Params: params}
	resp, err := uc.send(ctx, req)
	if err != nil {
		return UpstreamLoginResult{}, fmt.Errorf("proxy: upstream login request: %w", err)
	}
	if resp.Error != nil {
		return UpstreamLoginResult{}, fmt.Errorf("proxy: upstream pool rejected login: %s", resp.Error.Message)
	}
	var result UpstreamLoginResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return UpstreamLoginResult{}, fmt.Errorf("proxy: decoding upstream login result: %w", err)
	}
	uc.sessionID = result.ID
	uc.applyJob(result.Job)
	return result, nil
}

// SubmitShare sends a real "submit" request upstream — ported from
// the reference's Pool.sendShare, PLUS proxy.js's generic
// `sendData`'s own `params.id = this.id` post-login injection (see
// UpstreamSubmitParams.ID's doc comment): submit is sent after
// login has already populated uc.sessionID (login() sets it from
// result.ID before this leaf ever issues a downstream job to
// forward), so every real submit carries the pool-assigned session
// id, exactly like keepalived already does (sendKeepalive). Called
// ONLY for genuine block-level finds (see server.go's handleSubmit):
// shares below the upstream pool's real block target are never
// forwarded here.
func (uc *UpstreamClient) SubmitShare(ctx context.Context, jobID, nonceHex, resultHex string, workerNonce, poolNonce uint32) (bool, error) {
	params, err := json.Marshal(UpstreamSubmitParams{
		JobID:       jobID,
		Nonce:       nonceHex,
		Result:      resultHex,
		WorkerNonce: workerNonce,
		PoolNonce:   poolNonce,
		ID:          uc.sessionID,
	})
	if err != nil {
		return false, err
	}
	req := Request{ID: uc.nextID(), JsonRPC: "2.0", Method: "submit", Params: params}
	resp, err := uc.send(ctx, req)
	if err != nil {
		return false, fmt.Errorf("proxy: upstream submit request: %w", err)
	}
	if resp.Error != nil {
		return false, fmt.Errorf("proxy: upstream pool rejected submit: %s", resp.Error.Message)
	}
	return true, nil
}

// sendKeepalive sends a real "keepalived" request to the upstream
// pool through the existing send/nextID plumbing -- ported from the
// reference's Pool.heartbeat/sendData (proxy.js ~line 235-258):
// `this.heartbeat = function(){ if (this.keepAlive){
// this.sendData('keepalived'); } }`. Params mirror sendData's own
// post-login `params.id = this.id` injection (see
// UpstreamKeepaliveParams's doc comment) -- {"id": uc.sessionID} once
// one is known, or an empty params object otherwise.
//
// A successful keepalived response IS a real, correlated
// request/response round-trip through uc.send/uc.pending (it gets a
// real id via the same nextID sequence as login/submit, and IS
// looked up there) -- but the reference's handlePoolMessage
// (proxy.js ~line 675-704) has no `case 'keepalived'` at all, so a
// successful result is silently discarded there. Mirroring that: any
// non-nil error from uc.send here (a response timeout, a write
// failure, or an upstream error response) is logged and otherwise
// ignored -- never propagated as fatal, never used to trigger a
// reconnect from this call. Genuine connection death is already
// detected independently by readLoop's own scanner loop terminating
// and handing off to reconnectLoop; a slow/failed keepalive response
// by itself is not evidence of that and must not be overfit into
// meaning it is.
func (uc *UpstreamClient) sendKeepalive(ctx context.Context) error {
	var params json.RawMessage
	if uc.sessionID != "" {
		p, err := json.Marshal(UpstreamKeepaliveParams{ID: uc.sessionID})
		if err != nil {
			uc.logger.Printf("proxy: upstream keepalive failed: %v", err)
			return err
		}
		params = p
	} else {
		params = json.RawMessage("{}")
	}
	req := Request{ID: uc.nextID(), JsonRPC: "2.0", Method: "keepalived", Params: params}
	if _, err := uc.send(ctx, req); err != nil {
		uc.logger.Printf("proxy: upstream keepalive failed: %v", err)
		return err
	}
	return nil
}

// heartbeatLoop is the goroutine body started by dialAndLogin
// immediately after a successful login (loggedIn.Store(true)) --
// ported from the reference's on-connect handler installing
// `setInterval(pool.heartbeat, 30000)` right after `pool.login()`
// (proxy.js ~line 672). It fires sendKeepalive every
// upstreamHeartbeatInterval (a bounded uc.cfg.RequestTimeout context
// per call, so one slow/hung keepalive can't stall the ticker
// indefinitely) until stop is closed -- this connection generation's
// own heartbeat-stop channel, closed by readLoop the moment its
// scanner loop ends for any reason, see readLoop's doc comment -- or,
// as a secondary/backstop signal for the explicit-Close case,
// uc.closed fires. stop is deliberately a plain per-generation
// channel rather than something derived from mc.Context(): see the
// caveat above ManagedConnection.Context (connection.go) -- a plain
// remote EOF does not reliably cancel that context, only an explicit
// mc.Close()/ConnectionManager.Shutdown() does, which would leave
// this ticker running (and leak one per reconnect generation) well
// past the point its connection is actually dead.
//
// Callers Add(1) to uc.heartbeatWG before starting this goroutine
// (dialAndLogin, under cmMu); this defers the matching Done() so
// Close's heartbeatWG.Wait() genuinely observes this goroutine has
// exited, not merely that it was asked to.
func (uc *UpstreamClient) heartbeatLoop(stop <-chan struct{}) {
	defer uc.heartbeatWG.Done()
	ticker := time.NewTicker(upstreamHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), uc.cfg.RequestTimeout)
			_ = uc.sendKeepalive(ctx)
			cancel()
		case <-stop:
			return
		case <-uc.closed:
			return
		}
	}
}

// convertTemplateBlobTimeout bounds how long
// convertTemplateBlobToHashingBlob will wait for
// support.ParseBlockFromTemplateBlob + support.GetBlockHashingBlob to
// complete before giving up and returning an error -- see that
// function's doc comment for WHY a timeout, not just a recover, is
// required. A real, well-formed block template (even a large one,
// hundreds of transactions) parses in low-single-digit milliseconds;
// this is a generous multiple of that to avoid any risk of a false
// timeout on a genuinely slow-but-legitimate call, while still
// bounding the damage from the known hang described below to a few
// seconds per malformed input rather than forever.
const convertTemplateBlobTimeout = 2 * time.Second

// convertTemplateBlobToHashingBlob wraps
// support.ParseBlockFromTemplateBlob + support.GetBlockHashingBlob
// with BOTH a panic-recovery net AND a hard wall-clock timeout,
// converting a raw hex blocktemplate_blob straight into the real,
// correctly-sized RandomX hashing blob (or a normal error). This is
// used both by applyJob (converting an upstream pool's
// freshly-received raw blob) and by template.go's
// WorkerTemplate.BlobForWorker (re-deriving the hashing blob after
// patching a worker-nonce into a raw blob's coinbase tx_extra field).
//
// GENUINE, CONFIRMED go-xmr-lib v0.2.5 BUG (found and verified this
// pass, not guessed): serialization.ConstructTXExtra's switch
// statement over a tx_extra tag byte
// (go-xmr-lib@v0.2.5/support/serialization/transaction.go:200-215)
// has NO default case, and none of its four cases (0x00/0x01/0x02/
// 0x03) advance the `mutable` slice when the byte doesn't match one
// of them -- so ANY tx_extra region byte that isn't exactly one of
// those four values causes ParseBlockFromTemplateBlob to spin
// forever in an infinite loop (NOT a panic -- confirmed via a
// throwaway reproduction: `for range 1800 sequential garbage bytes`
// hangs indefinitely; `go test -timeout` is the only thing that ever
// terminates it). This is a strictly worse failure mode than a panic
// (recover() cannot help at all), and is highly likely to trigger on
// ANY sufficiently large arbitrary/malformed/adversarial
// blocktemplate_blob, since roughly 252/256 possible tag byte values
// are unhandled. This was NOT fixed in the vendored dependency itself
// per this repo's own conventions (don't silently patch a third-party
// module as a workaround for one caller's problem) -- instead, this
// function bounds the damage with the hard timeout above: on timeout,
// it returns a normal error (leaving the existing good WorkerTemplate
// untouched, exactly like any other conversion failure) rather than
// blocking its caller (and, transitively, this leaf's ability to
// process new upstream jobs) forever. The spawned goroutine itself
// CANNOT be forcibly cancelled (Go has no such primitive) and will
// keep spinning/leaking in the background consuming one CPU core for
// the lifetime of the process if this bug is ever actually triggered
// by a live pool -- this is a real, known, accepted limitation of
// this mitigation, not a complete fix. The proper fix is upstream, in
// go-xmr-lib itself (add a default case to that switch that returns
// an error) -- flagging this explicitly here and in this task's final
// summary rather than guessing at (or silently carrying) a deeper fix
// within this repo.
//
// The recover (for the SEPARATE, panic-based failure modes) is a
// SAFETY NET on top of the above, not a substitute for checking real
// error returns: ParseBlockFromTemplateBlob does validate several
// length invariants via real error returns (serialization.ReadUint
// on a too-short buffer), and this function still checks and
// propagates those normally. But some of its OTHER fields (e.g. a
// corrupt/truncated tx_extra length prefix, or a tx-hash count field
// that claims far more 32-byte hashes than remain in the buffer) are
// consumed via direct slicing (blobInBytes[0:val]) rather than a
// bounds-checked read, which panics with a runtime
// slice-bounds-out-of-range error on sufficiently malformed/truncated
// input instead of returning a normal error or hanging. A malformed
// upstream blocktemplate_blob must never be allowed to crash this
// leaf's entire process merely because one upstream pool (or a
// downstream worker-nonce patch landing on an unexpected byte)
// produced bad bytes -- this recovers from that failure mode and
// reports it as an ordinary error instead.
func convertTemplateBlobToHashingBlob(blobHex string) ([]byte, error) {
	type outcome struct {
		blob []byte
		err  error
	}
	ch := make(chan outcome, 1)
	go func() {
		var out outcome
		defer func() {
			if r := recover(); r != nil {
				out = outcome{nil, fmt.Errorf("proxy: recovered from a panic while parsing/converting a blocktemplate_blob (malformed or truncated input): %v", r)}
			}
			ch <- out
		}()
		parsedBlock, perr := support.ParseBlockFromTemplateBlob(blobHex)
		if perr != nil {
			out = outcome{nil, perr}
			return
		}
		hashingBlob, perr := support.GetBlockHashingBlob(parsedBlock)
		out = outcome{hashingBlob, perr}
	}()
	select {
	case out := <-ch:
		return out.blob, out.err
	case <-time.After(convertTemplateBlobTimeout):
		return nil, fmt.Errorf("proxy: parsing/converting a blocktemplate_blob did not complete within %s -- likely triggered the known go-xmr-lib v0.2.5 ConstructTXExtra infinite-loop bug on malformed tx_extra data (see this function's doc comment); giving up and treating this as a failed conversion rather than blocking forever", convertTemplateBlobTimeout)
	}
}

// applyJob converts an UpstreamJobPayload into a *WorkerTemplate,
// decodes its hex fields, and stores/broadcasts it. Mirrors the
// reference's handleNewBlockTemplate (proxy.js ~line 706-727):
// `pool.activeBlocktemplate = new pool.coinFuncs.MasterBlockTemplate(blockTemplate)`
// followed by broadcasting a freshly-derived per-worker job to every
// connected miner.
//
// job.BlocktemplateBlob is now the real, correctly-handled conversion
// path -- per repo maintainer Alex's explicit feedback on PR #60's
// stopgap ("That means we're not properly re-encoding the blob... The
// raw blob needs to be passed through the encoder to convert it to a
// minable blob... There's a helper for that in the library."), a raw
// blocktemplate_blob is no longer refused: it is run through
// github.com/Snipa22/go-xmr-lib/support's
// ParseBlockFromTemplateBlob (parses the raw hex blob into a
// serialization.Block) followed by GetBlockHashingBlob (serializes
// just BlockHeader + merkle-root-of-tx-hashes + tx-count-varint --
// the correctly-sized, ~76-byte RandomX hashing blob real miners
// need; this is the Go port of cryptonote_format_utils.cpp's
// get_block_hashing_blob).
//
// job.Blob and job.BlocktemplateBlob are two GENUINELY INDEPENDENT
// concerns, not mutually-exclusive alternatives (real, confirmed live
// production evidence: this leaf's own real login/getjob response
// legitimately carries BOTH simultaneously -- job.Blob for backward
// compat with ordinary non-XNP miners that only ever read "blob", and
// job.BlocktemplateBlob so an XNP-class multi-tier proxy can patch its
// own worker-nonce offsets into the real raw template). A prior
// version of this function treated them as a strict either/or
// priority order (job.Blob preferred whenever non-empty), which meant
// WorkerTemplate.RawBlob was NEVER populated whenever BOTH fields
// were present -- reproducing the real "worker-nonce offset is out of
// range for this template's blob" error whenever downstream
// nonce-offset patching then had to fall back to the small hashing
// blob instead of the real raw template. See this function's own
// BUG FIX comment (right above the case switch) for the full,
// byte-level reproduction. Priority order now:
//
//   - job.Blob != "": decode it directly as the outbound hashing
//     blob (unchanged from before this fix; this preserves the
//     ordinary-miner path byte-for-byte and avoids a redundant
//     re-conversion when this leaf already computed it correctly).
//     job.BlocktemplateBlob, if ALSO present, is now additionally
//     decoded into WorkerTemplate.RawBlob (a genuinely new behavior
//     vs. before this fix) -- a malformed BlocktemplateBlob in this
//     combined case degrades gracefully (RawBlob stays nil, blob is
//     unaffected) rather than aborting the whole job.
//   - job.Blob == "" && job.BlocktemplateBlob != "": the real
//     conversion path described above. On a parse/conversion error
//     (e.g. genuinely malformed or truncated input), this logs a
//     clear message and returns WITHOUT touching the currently-stored
//     template -- mirroring the pre-fix behavior of leaving the
//     existing good template untouched on bad input, rather than
//     risk storing/broadcasting a broken one. The resulting
//     WorkerTemplate.RawBlob is the raw decoded bytes, and
//     ReservedOffset/ClientNonceOffset become meaningful again (see
//     WorkerTemplate.BlobForWorker).
//   - both empty: refuses to store/broadcast a WorkerTemplate at
//     all, exactly as before this fix -- there is no usable blob at
//     all in this case.
func (uc *UpstreamClient) applyJob(job UpstreamJobPayload) {
	// BUG FIX (Alex, live production report: "Proxy is having some
	// job staleness issues, it's disabling as soon as a new job is
	// sent, it needs to allow jobs 2-3 old, just like the -direct has
	// to"): port XNP's own handleNewBlockTemplate upstream-dupe guard
	// (proxy.js ~line 706-727):
	//
	//	if (pool.activeBlocktemplate.job_id === blockTemplate.job_id){
	//	    debug.pool('No update with this job, it is an upstream dupe');
	//	    return;
	//	}
	//
	// Checked as early as possible (right after job.JobID is
	// available, before any of the blob/offset/target decoding work
	// below) so a genuine upstream no-op duplicate -- a getjob poll
	// response, or any repeat push, that carries the exact same
	// job_id as the currently-stored template -- short-circuits
	// cheaply, mirroring XNP's own early-return shape exactly:
	// neither uc.template is touched nor uc.notify (which drives
	// server.go's repushAllSessions) is ever fired for a dupe. An
	// EMPTY incoming job.JobID can never dedupe (matches XNP's own
	// plain string-equality check, which likewise never matches
	// against an empty/missing field in practice) -- some upstream
	// shapes may omit job_id, and treating that as "cannot dedupe,
	// always apply" is the safe default.
	if job.JobID != "" {
		if current := uc.template.Load(); current != nil && current.JobID == job.JobID {
			uc.logger.Printf("proxy: no update with this job, it is an upstream dupe (job_id=%s)", job.JobID)
			return
		}
	}

	// BUG FIX (real, confirmed live production evidence: a packet
	// capture from this leaf's own real login/getjob response showed
	// BOTH job.Blob (~76 bytes -- the small, already-converted
	// RandomX hashing blob, published unconditionally for backward
	// compat with ordinary non-XNP miners that only ever read "blob")
	// AND job.BlocktemplateBlob (~230 bytes -- the real, raw template
	// carrying the reserved_offset/client_nonce_offset/
	// client_pool_offset region) present SIMULTANEOUSLY in the SAME
	// job payload -- a real, legitimate wire shape, not malformed
	// input. The switch below used to be a strict priority order
	// (job.Blob preferred whenever non-empty, matching some pools
	// e.g. pool.supportxmr.com that publish ONLY job.Blob and have no
	// raw template at all), which meant that whenever BOTH fields
	// were present, rawBlob was NEVER populated even though a real,
	// valid BlocktemplateBlob was sitting right there in the same
	// payload. Downstream nonce-offset patching for an XNP-proxy
	// session (WorkerTemplate.BlobForWorker) then had no real raw
	// blob to patch reserved_offset/client_nonce_offset/
	// client_pool_offset into, and fell back to using the small
	// hashing blob instead -- reproducing EXACTLY the real error this
	// session ("proxy: worker-nonce offset is out of range for this
	// template's blob: offset=179 blob_len=76": offset 179 is a real,
	// valid client_nonce_offset into the 230-byte raw template, but
	// is nonsensical against the 76-byte hashing blob).
	//
	// FIX: rawBlob is now populated from job.BlocktemplateBlob
	// whenever it is present, INDEPENDENTLY of whether job.Blob is
	// also present -- these are two genuinely separate concerns
	// (which bytes are the ready-to-hash blob for ordinary miners vs.
	// which bytes the offset-patching path needs) that must not share
	// one single either/or branch. blob (the ready-to-hash field
	// every session actually mines against) still prefers job.Blob
	// when present, since that's already correct and cheaper than
	// re-deriving it via convertTemplateBlobToHashingBlob -- this
	// preserves the ordinary-miner path byte-for-byte. Only when
	// job.Blob is ABSENT does this derive blob from
	// BlocktemplateBlob via the real conversion helper (unchanged
	// from before this fix). A malformed/unparseable
	// BlocktemplateBlob, when job.Blob is otherwise present and
	// valid, is now a genuine partial-degradation case: rawBlob stays
	// nil (offset-patching unavailable for this job) but blob/the
	// ordinary mining path is NOT aborted over it, mirroring
	// monero_node.go's server-side "degrade this one optional
	// feature, don't fail the whole job" philosophy.
	var (
		blob    []byte
		rawBlob []byte
	)
	switch {
	case job.Blob != "":
		decoded, err := hex.DecodeString(job.Blob)
		if err != nil {
			uc.logger.Printf("proxy: upstream job carried an unparseable blob, ignoring: %v", err)
			return
		}
		blob = decoded
		if job.BlocktemplateBlob != "" {
			rawDecoded, err := hex.DecodeString(job.BlocktemplateBlob)
			if err != nil {
				uc.logger.Printf("proxy: upstream job carried an unparseable blocktemplate_blob alongside a valid blob -- worker-nonce offset patching unavailable for this job, ordinary mining unaffected: %v", err)
			} else {
				rawBlob = rawDecoded
			}
		}
	case job.BlocktemplateBlob != "":
		decoded, err := hex.DecodeString(job.BlocktemplateBlob)
		if err != nil {
			uc.logger.Printf("proxy: upstream job carried an unparseable blocktemplate_blob, ignoring: %v", err)
			return
		}
		hashingBlob, err := convertTemplateBlobToHashingBlob(job.BlocktemplateBlob)
		if err != nil {
			uc.logger.Printf("proxy: upstream job's blocktemplate_blob failed to convert to a real RandomX hashing blob (the pool may have sent malformed or truncated data), ignoring: %v", err)
			return
		}
		blob = hashingBlob
		rawBlob = decoded
	default:
		uc.logger.Printf("proxy: upstream job carried no usable blob at all (both blob and blocktemplate_blob empty) — refusing to apply")
		return
	}
	seed, _ := hex.DecodeString(job.SeedHash)

	clientNonceOffset := -1
	if job.WorkerOffset != nil {
		clientNonceOffset = *job.WorkerOffset
	} else if job.ClientNonceOffset != nil {
		clientNonceOffset = *job.ClientNonceOffset
	}
	reservedOffset := -1
	if job.ReservedOffset != nil {
		reservedOffset = *job.ReservedOffset
	}
	poolOffset := -1
	if job.ClientPoolOffset != nil {
		poolOffset = *job.ClientPoolOffset
	}

	targetDiff := job.TargetDiff
	if targetDiff == 0 && job.Target != "" {
		// pool.supportxmr.com's real job shape carries only a
		// hex-encoded, little-endian numeric "target" (the ordinary
		// miner-facing shape XMRig itself parses), not a separate
		// target_diff/target_diff_hex pair -- see UpstreamJobPayload's
		// doc comment. Derive an equivalent block-level difficulty
		// from it so this leaf's own block-target comparison
		// (session.go's handleSubmit) still has a real, meaningful
		// value to compare against, confirmed from this pass's live
		// smoke test capture against the real pool.
		if d, tErr := targetHexToDifficulty(job.Target); tErr == nil {
			targetDiff = d
		} else {
			uc.logger.Printf("proxy: could not derive a target difficulty from upstream job's target %q: %v", job.Target, tErr)
		}
	}

	t := &WorkerTemplate{
		Blob:              blob,
		RawBlob:           rawBlob,
		ReservedOffset:    reservedOffset,
		ClientNonceOffset: clientNonceOffset,
		PoolOffset:        poolOffset,
		SeedHash:          seed,
		Height:            job.Height,
		JobID:             job.JobID,
		TargetDiff:        targetDiff,
		Difficulty:        job.Difficulty,
		// Generation: this IS a genuinely new template (the
		// upstream-dupe guard above already returned early for a
		// dupe), so this call bumps uc.generation by exactly 1 and
		// stamps that new value onto the template being stored --
		// see uc.generation's and WorkerTemplate.Generation's own
		// doc comments for the full root-cause/fix rationale
		// (session.go's handleSubmit is what actually uses this to
		// reject a stale-template submit locally, before ever
		// contacting upstream).
		Generation: uc.generation.Add(1),
	}
	uc.template.Store(t)
	uc.notify(t)
}

// targetHexToDifficulty inverts the standard Monero-family
// hex-encoded, little-endian numeric target field into an equivalent
// difficulty: difficulty = floor(max_value_for_this_width / target),
// the same well-known relationship diffToTargetHex (session.go) uses
// in the other direction for THIS leaf's own downstream-facing target
// field. targetHex's byte width determines max_value_for_this_width
// (2^(8*len)-1) -- real pools have used both 4-byte and 8-byte target
// encodings historically, so this does not assume a fixed width.
func targetHexToDifficulty(targetHex string) (uint64, error) {
	raw, err := hex.DecodeString(targetHex)
	if err != nil {
		return 0, err
	}
	if len(raw) == 0 || len(raw) > 8 {
		return 0, fmt.Errorf("proxy: unsupported target width %d bytes", len(raw))
	}
	var target uint64
	for i := len(raw) - 1; i >= 0; i-- {
		target = target<<8 | uint64(raw[i])
	}
	if target == 0 {
		return 0, fmt.Errorf("proxy: target is zero, cannot derive a difficulty")
	}
	var maxVal uint64
	if len(raw) >= 8 {
		maxVal = ^uint64(0)
	} else {
		maxVal = (uint64(1) << (8 * len(raw))) - 1
	}
	return maxVal / target, nil
}

// readLoop is the single goroutine reading from a specific upstream
// socket (mc), dispatching every inbound line either to an
// unsolicited job push (applyJob) or to whichever pending request
// its "id" correlates with (mirrors proxy.js's
// poolSocket/handlePoolMessage dispatch).
//
// readLoop takes mc explicitly (rather than reading uc.mc itself)
// because dialAndLogin now starts a fresh readLoop for its own mc
// BEFORE login() completes — see dialAndLogin's doc comment for why
// that ordering is required — and by the time a later readLoop
// invocation's scanner terminates, uc.mc may already have been
// reassigned to a newer connection by a subsequent, unrelated
// dialAndLogin call; reading uc.mc here would risk reading (or
// racing on) the WRONG generation's socket instead of the one this
// goroutine was actually started for.
//
// loggedIn reports whether THIS mc's own login round-trip ever
// actually completed successfully. When the scanner terminates:
//   - if uc.closed has fired, this is an explicit Close — no
//     reconnect attempt.
//   - if loggedIn is still false, this connection attempt's login
//     itself failed (dialAndLogin closes mc/cm on login failure,
//     which is what makes this scanner terminate) and that failure
//     is already being surfaced as dialAndLogin's own return value
//     to whichever caller (Connect, or reconnectLoop's own
//     retry-with-backoff loop) is driving this attempt — starting a
//     second, independent reconnectLoop from here would be a real
//     duplicate of that caller's own retry path.
//   - otherwise, this is a real, unplanned loss of a connection that
//     HAD successfully logged in: readLoop flips uc.connected false
//     and hands off to reconnectLoop to redial with backoff, exactly
//     as this type's own doc comments on Connect and reconnectLoop
//     already describe. (Fixed in an earlier pass: this hand-off was
//     documented but never actually wired up — reconnectLoop was
//     dead code, so a real connection loss previously left the
//     client permanently down with no automatic recovery and a stuck
//     Connected()==true reading.)
//
// stopHeartbeat is this same generation's heartbeat-stop channel
// (see dialAndLogin's doc comment) — the scanner loop ending is the
// ONLY place that currently knows, generation-precisely, "this
// specific connection attempt is over" for any reason (explicit
// Close, remote EOF, or a login failure that never started a
// heartbeat at all), so readLoop closes it here, exactly once, as
// the very first action after the loop ends and before any of the
// existing closed/loggedIn checks below — this is what stops the
// 30s heartbeat ticker (heartbeatLoop) for this generation promptly
// on a real remote EOF, which mc.Context().Done() alone would not
// do reliably (see connection.go's Context doc comment).
func (uc *UpstreamClient) readLoop(mc *leaflib.ManagedConnection, loggedIn *atomic.Bool, stopHeartbeat chan struct{}) {
	scanner := bufio.NewScanner(mc)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		uc.handleLine(line)
	}

	// This generation's connection is over, for any reason -- stop
	// its heartbeat ticker (if one was ever started; closing an
	// unstarted heartbeat's channel is harmless, see dialAndLogin's
	// doc comment). readLoop is the single, unconditional owner of
	// this close: it runs exactly once per generation (one readLoop
	// goroutine per dialAndLogin call, whose scanner loop can only
	// end once), so no sync.Once/extra guarding is needed here.
	close(stopHeartbeat)

	select {
	case <-uc.closed:
		// Explicit Close — no reconnect attempt.
		return
	default:
	}
	if !loggedIn.Load() {
		// This connection attempt's own login never completed; the
		// caller driving dialAndLogin already treats this as a
		// failed attempt via its return value and will retry/back
		// off itself. See doc comment above.
		return
	}
	uc.connected.Store(false)
	uc.logger.Printf("proxy: upstream connection lost, starting reconnect loop: %v", scanner.Err())
	uc.reconnectLoop()
}

func (uc *UpstreamClient) handleLine(line string) {
	// Peek at "method" first: an unsolicited push (the ONLY inbound
	// message that legitimately carries "method" — proxy.js's own
	// comment: "The only time method is set, is with a push of
	// data.").
	var probe struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal([]byte(line), &probe); err == nil && probe.Method == "job" {
		var push UpstreamJobPush
		if err := json.Unmarshal([]byte(line), &push); err != nil {
			uc.logger.Printf("proxy: unparseable upstream job push, dropping: %v", err)
			return
		}
		uc.applyJob(push.Params)
		return
	}

	var resp UpstreamResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		uc.logger.Printf("proxy: unparseable message from upstream pool, dropping: %v", err)
		return
	}
	uc.pendingMu.Lock()
	ch, ok := uc.pending[resp.ID]
	uc.pendingMu.Unlock()
	if !ok {
		uc.logger.Printf("proxy: upstream response for unknown request id %d, dropping", resp.ID)
		return
	}
	select {
	case ch <- resp:
	default:
	}
}
