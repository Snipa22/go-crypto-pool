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
	// an operator-triggered Close.
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

	// connected/reconnects back UpstreamHealth (see server.go's
	// UpstreamHealth interface doc comment): connected reflects
	// whether the upstream socket is currently up, reconnects counts
	// real, successful re-establishments after a real connection
	// loss (the initial Connect is NOT counted).
	connected  atomic.Bool
	reconnects atomic.Uint64
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
	// This MUST NOT contain the literal substring "xmr-node-proxy" —
	// live-confirmed against pool.supportxmr.com this session, that
	// substring (present in the legacy reference's own literal
	// "xmr-node-proxy/0.0.3") is what a real pool's agent-string
	// sniffing (nodejs-pool-sxmr's lib/pool.js:
	// `agent.includes("xmr-node-proxy")`) uses to grant the
	// "advanced xmr-node-proxy client" protocol extension — which
	// replaces the ordinary, correctly-sized "blob" job field with a
	// raw, untrimmed, arbitrarily-large blocktemplate_blob this leaf
	// has no convert_blob-style reduction step for (see applyJob).
	// Defaults to "go-crypto-pool-leaf-proxy/<version>" — see
	// cmd/leaf-proxy/main.go.
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
		out.Agent = "go-crypto-pool-leaf-proxy/dev"
	}
	return out
}

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
// itself fails (dialAndLogin closes mc/cm below, which makes this
// same readLoop's scanner terminate too), readLoop is told via
// loggedIn whether login for this exact connection ever actually
// succeeded: if not, it exits quietly instead of invoking
// reconnectLoop itself — that failure is already being surfaced as
// this function's own return value, to whichever caller (Connect, or
// reconnectLoop's own retry-with-backoff loop) is driving this
// attempt, so a second, independent reconnectLoop invocation from
// inside readLoop would be a real duplicate.
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
	go uc.readLoop(mc, loggedIn)

	if _, err := uc.login(ctx); err != nil {
		_ = mc.Close("upstream login failed")
		cm.Shutdown()
		return err
	}
	loggedIn.Store(true)
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

// Close tears down the upstream connection.
func (uc *UpstreamClient) Close() error {
	var err error
	uc.closeOnce.Do(func() {
		close(uc.closed)
		uc.connected.Store(false)
		uc.cmMu.Lock()
		mc, cm := uc.mc, uc.cm
		uc.cmMu.Unlock()
		if mc != nil {
			err = mc.Close("upstream client closed")
		}
		if cm != nil {
			cm.Shutdown()
		}
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
// the reference's Pool.sendShare. Called ONLY for genuine
// block-level finds (see server.go's handleSubmit): shares below the
// upstream pool's real block target are never forwarded here.
func (uc *UpstreamClient) SubmitShare(ctx context.Context, jobID, nonceHex, resultHex string, workerNonce, poolNonce uint32) (bool, error) {
	params, err := json.Marshal(UpstreamSubmitParams{
		JobID:       jobID,
		Nonce:       nonceHex,
		Result:      resultHex,
		WorkerNonce: workerNonce,
		PoolNonce:   poolNonce,
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

// applyJob converts an UpstreamJobPayload into a *WorkerTemplate,
// decodes its hex fields, and stores/broadcasts it. Mirrors the
// reference's handleNewBlockTemplate (proxy.js ~line 706-727):
// `pool.activeBlocktemplate = new pool.coinFuncs.MasterBlockTemplate(blockTemplate)`
// followed by broadcasting a freshly-derived per-worker job to every
// connected miner.
//
// job.BlocktemplateBlob is NEVER used as the outbound miner-facing
// blob source, even as a fallback — live-confirmed against
// pool.supportxmr.com this session, that field is the raw, untrimmed,
// arbitrarily-large (varies with mempool tx count) Monero block
// template a pool sends ONLY to a client it has recognized (via
// agent-string sniffing — see cmd/leaf-proxy/main.go's -upstream-agent
// doc comment) as an "advanced xmr-node-proxy client", and this
// codebase has no convert_blob-style reduction step to turn it into a
// real, fixed-size RandomX hashing blob. job.Blob is the ONLY field
// that is ever a real, correctly-sized RandomX hashing blob on this
// leaf's supported pools. If job.Blob is empty (e.g. misconfiguration
// still causing the pool to grant the advanced-client dialect), this
// refuses to store/broadcast a WorkerTemplate at all, rather than
// risk forwarding an invalid or oversized blob downstream — see
// template.go's WorkerTemplate.Blob doc comment.
func (uc *UpstreamClient) applyJob(job UpstreamJobPayload) {
	if job.Blob == "" {
		uc.logger.Printf("proxy: upstream job carried no usable RandomX hashing blob (blob field empty) — refusing to apply; check -upstream-agent is not identifying this leaf as an advanced xmr-node-proxy client")
		return
	}
	blob, err := hex.DecodeString(job.Blob)
	if err != nil {
		uc.logger.Printf("proxy: upstream job carried an unparseable blob, ignoring: %v", err)
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
		ReservedOffset:    reservedOffset,
		ClientNonceOffset: clientNonceOffset,
		SeedHash:          seed,
		Height:            job.Height,
		JobID:             job.JobID,
		TargetDiff:        targetDiff,
		Difficulty:        job.Difficulty,
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
func (uc *UpstreamClient) readLoop(mc *leaflib.ManagedConnection, loggedIn *atomic.Bool) {
	scanner := bufio.NewScanner(mc)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		uc.handleLine(line)
	}

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
