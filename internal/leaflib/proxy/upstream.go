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
	cm *leaflib.ConnectionManager
	mc *leaflib.ManagedConnection

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

	// Agent is the real "advanced mining client" identifier string
	// sent on login — this is literally what the legacy reference
	// used (`xmr-node-proxy/0.0.3`) and, on pools that implement the
	// extension, is how a pool recognizes an aggregating proxy client
	// and grants it the worker_offset/client_nonce_offset extranonce
	// partitioning fields (see protocol.go's UpstreamJobPayload doc
	// comment). Defaults to "go-crypto-pool-leaf-proxy/<version>" —
	// see cmd/leaf-proxy/main.go.
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
// available via CurrentTemplate.
func (uc *UpstreamClient) Connect(ctx context.Context) error {
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

	uc.cm = leaflib.NewConnectionManager(context.Background(), leaflib.ManagerConfig{
		MaxConnections: 1,
		IdleTimeout:    uc.cfg.IdleTimeout,
	})
	mc, err := uc.cm.Accept(ctx, conn)
	if err != nil {
		return fmt.Errorf("proxy: registering upstream connection: %w", err)
	}
	uc.mc = mc

	go uc.readLoop()

	if _, err := uc.login(ctx); err != nil {
		_ = uc.Close()
		return err
	}
	return nil
}

// Close tears down the upstream connection.
func (uc *UpstreamClient) Close() error {
	var err error
	uc.closeOnce.Do(func() {
		close(uc.closed)
		if uc.mc != nil {
			err = uc.mc.Close("upstream client closed")
		}
		if uc.cm != nil {
			uc.cm.Shutdown()
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
func (uc *UpstreamClient) applyJob(job UpstreamJobPayload) {
	blobHex := job.BlocktemplateBlob
	if blobHex == "" {
		blobHex = job.Blob
	}
	blob, err := hex.DecodeString(blobHex)
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

// readLoop is the single goroutine reading from the upstream socket,
// dispatching every inbound line either to an unsolicited job push
// (applyJob) or to whichever pending request its "id" correlates
// with (mirrors proxy.js's poolSocket/handlePoolMessage dispatch).
func (uc *UpstreamClient) readLoop() {
	scanner := bufio.NewScanner(uc.mc)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		uc.handleLine(line)
	}
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
