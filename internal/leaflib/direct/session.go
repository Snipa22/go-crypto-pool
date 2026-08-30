// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
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

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// c29SubmitEdgeBits/c29SubmitCycleSize mirror solo/session.go's own
// unexported constants exactly (real Tari Cuckaroo29: 42-edge cycles
// at edge_bits=29).
const (
	c29SubmitEdgeBits  = 29
	c29SubmitCycleSize = 42
)

// defaultSessionJobHistorySize mirrors solo/session.go's own default
// exactly — see that constant's doc comment for the full bounded-
// job-history rationale (the real security fix from PR #14).
const defaultSessionJobHistorySize = 8

// Session drives one miner connection's request/response loop, using
// the EXACT same real Monero-family JSON-RPC 2.0 stratum wire types
// leaf-solo already defined (solo.Request/LoginRequest/SubmitRequest/
// JobPush/ShareResponse/JobPayload — reused directly, not
// reimplemented) and the exact same real per-algo PoW validators
// (validator.Registry). The genuine difference from solo.Session:
// every validated share/block is forwarded to the real backend via
// transport.ShareTransport instead of leaf-direct self-tracking/
// submitting to a single daemon, and a genuine block-level find
// ALSO triggers real parallel multi-node GRPC submission
// (multisubmit.go) plus a best-effort NATS relay broadcast
// (internal/leaflib/relay), neither of which leaf-solo has.
type Session struct {
	mc     *leaflib.ManagedConnection
	server *Server

	sessionID string
	xn        string
	loggedIn  atomic.Bool
	address   atomic.Value // string
	worker    atomic.Value // string
	// agent mirrors solo.Session's own agent field exactly: the real
	// miner software/version string self-reported at login
	// (solo.LoginRequest.Agent), stored verbatim and unvalidated,
	// diagnostic-only.
	agent atomic.Value // string

	// trust is nil unless server.trustConfig.Enabled at newSession
	// time — see solo.MinerTrust and solo/trust.go's doc comment.
	trust *solo.MinerTrust

	// --- per-session job ownership, mirroring solo.Session's own
	// SECURITY FIX (PR #14) exactly: see solo/session.go's Session
	// type doc comment for the full rationale. Ported here verbatim
	// because it is a real, structural security property every leaf
	// mode must have, not something specific to solo mode.
	jobsMu         sync.Mutex
	jobList        []string
	jobLog         map[string]*solo.Job
	jobHistorySize int

	shareCount atomic.Uint64
	blockCount atomic.Uint64

	connectedAt       time.Time
	currentDifficulty atomic.Uint64
	// forcedMinDifficulty mirrors solo.Session's own field exactly --
	// see that field's doc comment.
	forcedMinDifficulty atomic.Uint64
	hashesAccumulated   atomic.Uint64

	// lastDeliveredJobID/lastDeliveredDifficulty mirror solo.Session's
	// own identical fields exactly -- see that type's doc comment for
	// the full rationale (BUG FIX: Alex's live "duplicate jobs down
	// the wire" report). Updated in jobPayload below; consulted by
	// server.go's invalidateAndRepushJobs via alreadyDelivered.
	lastDeliveredJobID      atomic.Value // string
	lastDeliveredDifficulty atomic.Uint64
}

// alreadyDelivered mirrors solo.Session's own identical method exactly
// -- see that method's doc comment.
func (s *Session) alreadyDelivered(job *solo.Job) bool {
	if job == nil {
		return false
	}
	lastID, _ := s.lastDeliveredJobID.Load().(string)
	if lastID == "" || lastID != job.ID {
		return false
	}
	return s.lastDeliveredDifficulty.Load() == job.StaticDifficulty
}

func newSession(mc *leaflib.ManagedConnection, server *Server, startingDifficulty uint64) *Session {
	id, _ := newRandomHexID()
	xn, err := newSessionXN()
	if err != nil {
		xn = "0000"
		server.logger.Printf("direct: failed to generate session xn, falling back to %q: %v", xn, err)
	}
	s := &Session{
		mc: mc, server: server, sessionID: id, xn: xn,
		connectedAt: time.Now(), jobLog: make(map[string]*solo.Job),
		jobHistorySize: defaultSessionJobHistorySize,
	}
	s.address.Store("")
	s.worker.Store("")
	s.agent.Store("")
	s.currentDifficulty.Store(startingDifficulty)
	if server.trustConfig.Enabled {
		s.trust = solo.NewMinerTrust(server.trustConfig)
	}
	return s
}

// Run is the session's read loop, structurally identical to
// solo.Session.Run.
func (s *Session) Run(ctx context.Context) {
	scanner := bufio.NewScanner(s.mc)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		s.handleLine(line)
	}
	s.server.recordConnectionError(classifyCloseError(scanner.Err()))
}

func classifyCloseError(err error) string {
	if err == nil {
		return "remote-eof"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "idle-timeout"
	}
	if errors.Is(err, bufio.ErrTooLong) {
		return "protocol-error"
	}
	return "other"
}

func (s *Session) handleLine(line string) {
	var req solo.Request
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		s.server.logger.Printf("direct: session %s sent unparseable message, dropping: %v", s.sessionID, err)
		return
	}
	switch req.Method {
	case "login":
		s.handleLogin(req)
	case "getjob":
		s.handleGetJob(req)
	case "submit":
		s.handleSubmit(req)
	case "keepalived":
		s.writeGeneralResponse(req.ID, "", "KEEPALIVED")
	default:
		s.writeGeneralResponse(req.ID, fmt.Sprintf("unknown method: %s", req.Method), "")
	}
}

func (s *Session) handleLogin(req solo.Request) {
	var login solo.LoginRequest
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &login); err != nil {
			s.writeGeneralResponse(req.ID, fmt.Sprintf("invalid login params: %v", err), "")
			return
		}
	}
	if login.Login == "" {
		s.writeGeneralResponse(req.ID, "invalid address provided, please use a valid address", "")
		return
	}

	// Real, coin-aware payment-address validation, mirroring
	// solo.Session's own handleLogin exactly (see that method's doc
	// comment) — leaf-direct already carries its own configured
	// poolpb.Algo on Server (s.server.algo, see server.go), the same
	// algo every job this leaf produces is stamped with, so no
	// JobManager.Algo() indirection is needed here the way solo's
	// own handleLogin needs it.
	if err := solo.ValidateAddressForAlgo(s.server.algo, login.Login); err != nil {
		s.writeGeneralResponse(req.ID, err.Error(), "")
		return
	}

	// REAL enforcement point for the manual ban/forced-minimum-
	// difficulty system -- mirrors solo.Session's own handleLogin
	// exactly (see internal/leaflib/addressflags's package doc
	// comment for the full rationale). leaf-direct's own
	// addressflags.Cache is fed by a real backend poll
	// (addressflags.HTTPSource against the backend's GET
	// /api/v1/leaf/address-flags — see cmd/leaf-direct/main.go)
	// rather than leaf-solo's local file, but the enforcement logic
	// here is identical: nil s.server.addressFlags means every
	// address is treated as unflagged.
	var forcedFloor uint64
	if s.server.addressFlags != nil {
		flags := s.server.addressFlags.Get(login.Login)
		if flags.Banned {
			s.server.logger.Printf("direct: rejecting login for banned address %s (session %s)", login.Login, s.sessionID)
			s.writeGeneralResponse(req.ID, "this address is banned from this pool", "")
			return
		}
		forcedFloor = flags.ForcedMinDifficulty
	}

	worker := login.Pass
	if login.RigID != "" {
		worker = login.RigID
	}
	if worker == "" {
		worker = "x"
	}

	s.address.Store(login.Login)
	s.worker.Store(worker)
	s.agent.Store(login.Agent)
	s.loggedIn.Store(true)

	// A forced minimum difficulty always wins over the port tier's
	// own configured starting difficulty -- mirrors solo.Session's
	// own handleLogin exactly (see that method's doc comment).
	startDiff := s.currentDifficulty.Load()
	if forcedFloor > 0 {
		s.forcedMinDifficulty.Store(forcedFloor)
		if forcedFloor > startDiff {
			startDiff = forcedFloor
			s.currentDifficulty.Store(startDiff)
		}
	}

	job, err := s.server.jobManager.JobForXNAtDifficulty(context.Background(), s.xn, s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("direct: failed to get job for session %s (xn %s): %v", s.sessionID, s.xn, err)
		s.writeGeneralResponse(req.ID, "no job template available yet, retry shortly", "")
		return
	}
	resp := solo.LoginResponse{
		ID: req.ID, JsonRPC: "2.0",
		Result: solo.LoginResult{ID: s.sessionID, Job: s.jobPayload(job), Status: "OK"},
		Status: "OK",
	}
	s.writeJSON(resp)
}

func (s *Session) handleGetJob(req solo.Request) {
	if !s.loggedIn.Load() {
		s.writeGeneralResponse(req.ID, "login required before getjob", "")
		return
	}
	job, err := s.server.jobManager.JobForXNAtDifficulty(context.Background(), s.xn, s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("direct: failed to get job for session %s (xn %s): %v", s.sessionID, s.xn, err)
		s.writeGeneralResponse(req.ID, "no job template available yet, retry shortly", "")
		return
	}
	s.pushJob(job)
}

// handleSubmit is leaf-direct's own version of solo.Session's
// handleSubmit: the wire parsing / xn-prefix / session-ownership /
// job-expiry / validator-dispatch / difficulty-derivation logic is
// the SAME real logic (this is not a rewrite of the validation
// pipeline — see this package's wireutil.go, a byte-for-byte port of
// solo's own unexported helpers), but the OUTCOME on both the
// below-block-difficulty accept path and the block-find path is
// genuinely different: shares are forwarded to the real backend via
// s.server.transport.SubmitShare, and a genuine block find triggers
// real parallel multi-node GRPC submission
// (s.server.multiSubmit.SubmitBlock) plus a best-effort NATS relay
// publish (s.server.relay.Publish) instead of a single self-submit to
// one daemon.
func (s *Session) handleSubmit(req solo.Request) {
	if !s.loggedIn.Load() {
		s.writeGeneralResponse(req.ID, "login required before submit", "")
		return
	}
	var submit solo.SubmitRequest
	if len(req.Params) == 0 {
		s.writeShareResponse(req.ID, false, "submit requires params")
		return
	}
	if err := json.Unmarshal(req.Params, &submit); err != nil {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("invalid submit params: %v", err))
		return
	}

	job, ok := s.ownJob(submit.JobID)
	if !ok {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("unknown or stale job_id: %s", submit.JobID))
		return
	}

	if maxAge := s.server.jobManager.JobMaxAge(); maxAge > 0 {
		if age := time.Since(job.CreatedAt); age > maxAge {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("job expired: job_id %s was issued %s ago (max age %s)", submit.JobID, age.Round(time.Second), maxAge))
			return
		}
	}

	// REAL ban re-check at submit time, not just login time -- see
	// solo.Session's own identical addition for the full rationale
	// (a session can log in before an address is banned, or get
	// banned mid-session; login-time-only enforcement would let an
	// already-connected botnet keep submitting shares indefinitely).
	if s.server.addressFlags != nil {
		if flags := s.server.addressFlags.Get(s.address.Load().(string)); flags.Banned {
			s.server.logger.Printf("direct: rejecting submit for now-banned address %s (session %s)", s.address.Load(), s.sessionID)
			s.writeShareResponse(req.ID, false, "this address is banned from this pool")
			return
		}
	}

	// xn-prefix check: applies to SHA3X and C29 only, NOT RXT — RXT's
	// own real nonce handling (see rxt.go/createTariMiningBlob and the
	// real Tari Rust source) treats the full 8-byte big-endian nonce
	// as one opaque value with no xn hex-prefix partitioning
	// convention, unlike SHA3X/C29 which do use xn for real
	// per-session nonce-space partitioning (mirrors solo.Session's own
	// handleSubmit — see its doc comment for the full rationale).
	// ALGO_RXM (Monero) is exempted from the xn-prefix check for the
	// same reason as ALGO_RXT (see solo.Session's own handleSubmit doc
	// comment): a real Monero-family miner treats the full nonce field
	// as one opaque value it controls end-to-end.
	if job.Algo != poolpb.Algo_ALGO_RXT && job.Algo != poolpb.Algo_ALGO_RXM {
		if !strings.HasPrefix(strings.ToLower(submit.Nonce), s.xn) {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("Invalid XNonce %v", submit.Nonce))
			return
		}
	}

	// Nonce length is algo-conditional -- mirrors solo.Session's own
	// handleSubmit exactly (see its doc comment for the full
	// rationale, including the real production packet capture
	// against 148.163.90.157:4450 showing a real xmrig client
	// sending a genuine 4-byte nonce for ALGO_RXM). RXT FIX: a real
	// XMRig client also reports a raw 4-byte nonce for RXT (there is
	// no coin-specific variant on the client side — see
	// wireutil.go's rxtXmrigNonceOffset doc comment), so RXT now
	// takes the SAME lenient 4-or-8-byte gate as RXM instead of the
	// strict 8-byte-only gate SHA3X/C29 keep.
	nonceBytes, err := hex.DecodeString(submit.Nonce)
	if job.Algo == poolpb.Algo_ALGO_RXM || job.Algo == poolpb.Algo_ALGO_RXT {
		if err != nil || (len(nonceBytes) != 4 && len(nonceBytes) != 8) {
			s.writeShareResponse(req.ID, false, "nonce must be 4 bytes for RandomX-family (rx/0) jobs, hex-encoded uint32")
			return
		}
	} else {
		if err != nil || len(nonceBytes) != 8 {
			s.writeShareResponse(req.ID, false, "nonce must be 8 bytes, hex-encoded uint64")
			return
		}
	}

	var (
		nonce uint64
		share *poolpb.Share
	)
	switch job.Algo {
	case poolpb.Algo_ALGO_RXM:
		// Mirrors solo.Session's own ALGO_RXM handling exactly (same
		// little-endian nonce convention, same
		// solo.MoneroHashingBlobForSubmit escape hatch for the real
		// RandomX verification blob) — see that method's doc comment
		// for the full rationale. A real xmrig client sends a
		// 4-byte nonce; an 8-byte submit is decoded the same way
		// for backward tolerance.
		if len(nonceBytes) == 4 {
			nonce = uint64(binary.LittleEndian.Uint32(nonceBytes))
		} else {
			nonce = binary.LittleEndian.Uint64(nonceBytes)
		}
		if submit.Result == "" {
			s.writeShareResponse(req.ID, false, "monero (rxm) submit requires a claimed result hash in \"result\"")
			return
		}
		blob, blobErr := solo.MoneroHashingBlobForSubmit(job, nonce)
		if blobErr != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("failed to build monero randomx verification blob: %v", blobErr))
			return
		}
		share = &poolpb.Share{
			Algo: poolpb.Algo_ALGO_RXM, Network: s.server.network, PoolType: s.server.poolType, PoolId: s.server.poolID,
			BlockDiff: safeInt64(job.StaticDifficulty), Shares: safeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
			PaymentAddress: s.address.Load().(string), Identifier: s.worker.Load().(string),
			Timestamp: time.Now().Unix(),
			RawProof: &poolpb.Share_RandomxProof{RandomxProof: &poolpb.RandomXProof{
				Blob: blob, SeedHash: job.VmKey, ResultHex: submit.Result,
			}},
		}
	case poolpb.Algo_ALGO_C29:
		if len(submit.POW) != c29SubmitCycleSize {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("pow must carry exactly %d edges for a C29 cycle, got %d", c29SubmitCycleSize, len(submit.POW)))
			return
		}
		nonce = binary.BigEndian.Uint64(nonceBytes)
		share = &poolpb.Share{
			Algo: poolpb.Algo_ALGO_C29, Network: s.server.network, PoolType: s.server.poolType, PoolId: s.server.poolID,
			BlockDiff: safeInt64(job.StaticDifficulty), Shares: safeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
			PaymentAddress: s.address.Load().(string), Identifier: s.worker.Load().(string),
			Timestamp: time.Now().Unix(),
			RawProof: &poolpb.Share_C29Proof{C29Proof: &poolpb.C29Proof{
				EdgeBits: c29SubmitEdgeBits, Cycle: submit.POW, Header: job.Header, Nonce: nonce,
			}},
		}
	case poolpb.Algo_ALGO_RXT:
		// NONCE RECONSTRUCTION FIX: mirrors solo.Session's own
		// ALGO_RXT handling exactly — see solo/session.go's
		// handleSubmit doc comment on this same fix for the full,
		// confirmed-from-XMRig's-real-source rationale. A real
		// unmodified XMRig client reports a raw 4-byte nonce
		// (rxtXmrigNonceOffset/Size); decode as big-endian uint32,
		// zero-extended, so createTariMiningBlob's own
		// to_be_bytes(nonce) write below reproduces byte-for-byte
		// the same blob region XMRig actually hashed. An 8-byte
		// submit is still accepted and decoded directly (lenient
		// tolerance, same as before).
		if len(nonceBytes) == 4 {
			nonce = uint64(binary.BigEndian.Uint32(nonceBytes))
		} else {
			nonce = binary.BigEndian.Uint64(nonceBytes)
		}
		if submit.Result == "" {
			s.writeShareResponse(req.ID, false, "rxt submit requires a claimed result hash in \"result\"")
			return
		}
		var powData []byte
		if pd := solo.TariPowDataFromJob(job); pd != nil {
			powData = pd
		}
		blob := createTariMiningBlob(job.Header, nonce, rxtPowAlgoByte, powData)
		share = &poolpb.Share{
			Algo: poolpb.Algo_ALGO_RXT, Network: s.server.network, PoolType: s.server.poolType, PoolId: s.server.poolID,
			BlockDiff: safeInt64(job.StaticDifficulty), Shares: safeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
			PaymentAddress: s.address.Load().(string), Identifier: s.worker.Load().(string),
			Timestamp: time.Now().Unix(),
			RawProof: &poolpb.Share_RandomxProof{RandomxProof: &poolpb.RandomXProof{
				Blob: blob, SeedHash: job.VmKey, ResultHex: submit.Result,
			}},
		}
	default:
		nonce = binary.LittleEndian.Uint64(nonceBytes)
		share = &poolpb.Share{
			Algo: poolpb.Algo_ALGO_SHA3X, Network: s.server.network, PoolType: s.server.poolType, PoolId: s.server.poolID,
			BlockDiff: safeInt64(job.StaticDifficulty), Shares: safeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
			PaymentAddress: s.address.Load().(string), Identifier: s.worker.Load().(string),
			Timestamp: time.Now().Unix(),
			RawProof: &poolpb.Share_Sha3XProof{Sha3XProof: &poolpb.SHA3XProof{
				Header: job.Header, Nonce: nonce,
			}},
		}
	}

	if !job.MarkNonceUsed(nonce) {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("duplicate nonce: %s", submit.Nonce))
		return
	}

	// PERFORMANCE FIX (Alex, live production incident, 2026-08-30): see
	// solo/session.go's handleSubmit and solo/asyncvalidation.go's
	// package doc comment for the full production incident and
	// rationale — leaf-direct has the EXACT SAME read-loop-blocking bug
	// leaf-solo did (this method's validator dispatch below also makes a
	// real, synchronous randomx-service HTTP round-trip for RXT/RXM,
	// inline, previously blocking Run's scanner.Scan() loop). finishSubmit
	// captures everything from here to the end of this method so it can
	// run either INLINE (SHA3X/C29, unchanged) or dispatched to
	// s.server.randomxPool (RXT/RXM — see the dispatch below), exactly
	// mirroring solo.Session's own identical split. Response-ordering and
	// race-safety reasoning is identical too: a real xmrig client matches
	// responses by their own numeric "id" field, not arrival order (see
	// solo/session.go's doc comment, verified against xmrig's real
	// Client.cpp source), and every piece of per-session/per-job mutable
	// state below (job.MarkNonceUsed already ran above; shareCount/
	// blockCount/hashesAccumulated are atomic; s.trust has its own
	// internal mutex; BuildCandidateBlock only reads job fields; mc.Write
	// is already synchronized onto one writer goroutine) was already
	// race-safe by construction.
	finishSubmit := func() {
		v, err := s.server.validators.Get(job.Algo)
		if err != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("no validator configured for this leaf's algo %v: %v", job.Algo, err))
			return
		}

		// Real, legacy-ported trusted-miner validation skip — mirrors
		// solo.Session's own identical handleSubmit gating exactly (see
		// solo/trust.go's doc comment). Only RXT/RXM ever consider a
		// skip; SHA3X/C29 are always fully validated regardless of
		// s.trust's state.
		var valid bool
		skipped := solo.IsRandomXFamily(job.Algo) && s.trust.ShouldSkipValidation()
		if skipped {
			valid = true
		} else {
			valid, err = v.Validate(context.Background(), share)
			if err != nil && err != validator.ErrWrongProofType {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("validation error: %v", err))
				return
			}
		}
		if !valid {
			if solo.IsRandomXFamily(job.Algo) {
				s.trust.RecordOutcome(false)
			}
			s.writeShareResponse(req.ID, false, "share does not meet configured difficulty or is cryptographically invalid")
			return
		}
		if solo.IsRandomXFamily(job.Algo) {
			s.trust.RecordOutcome(true)
		}

		s.shareCount.Add(1)

		diff, candidate, err := s.server.node.BuildCandidateBlock(job, nonce, solo.SubmitProof{Cycle: submit.POW, ResultHex: submit.Result})
		if err != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("difficulty derivation error: %v", err))
			return
		}

		// GENUINE DIFFERENCE FROM leaf-solo: every validated share (not
		// just block-level finds) is forwarded to the real backend over
		// transport.ShareTransport — this is leaf-direct's whole reason
		// for existing (see this package's doc comment). Forwarding
		// happens synchronously here but with a bounded context timeout
		// so a slow/unreachable backend degrades the miner's wire
		// response latency rather than the process hanging indefinitely;
		// a transport failure is logged and does NOT flip an otherwise
		// cryptographically-valid share into a wire-level rejection (the
		// miner did real, valid work regardless of whether the backend
		// happened to be reachable at that instant — mirrors leaf-solo's
		// own "SubmitBlock error still counts vardiff progress, still
		// tells the miner their PoW was rejected only for the pool's own
		// infra reasons" philosophy, generalized to shares).
		s.forwardShare(share)

		if job.NetworkTargetDifficulty == 0 || diff < job.NetworkTargetDifficulty {
			s.hashesAccumulated.Add(job.StaticDifficulty)
			s.writeShareResponse(req.ID, true, "")
			return
		}

		// Meets full block difficulty: this is a genuine block find.
		// Dispatch is coin-aware: for Tari (candidate is a real
		// *tari_generated.Block), leaf-direct submits in real parallel to
		// every configured GRPC node (s.server.multiSubmit), with "at
		// least one acceptance = success" semantics, and best-effort
		// broadcasts the find over the NATS relay (s.server.relay.Publish)
		// — see this package's doc comment and multisubmit.go/
		// internal/leaflib/relay for the full design. For Monero
		// (candidate is a real nonce-patched blocktemplate_blob []byte —
		// MoneroNodeClient.BuildCandidateBlock's own contract,
		// monero_node.go), there is genuinely no multi-node-submit path
		// yet: MultiNodeSubmitter (multisubmit.go) is Tari-GRPC-specific
		// (its blockSubmitClient interface is literally
		// SubmitBlock(*tari_generated.Block)) — a KNOWN, EXPLICITLY
		// DEFERRED GAP (see this repo's PR description), not silently
		// papered over. The real, working priority path instead: a single
		// real submission via this leaf's own configured
		// s.server.node.SubmitBlock (this leaf's ONE MoneroNodeClient
		// connection, the same one JobManager already uses as its
		// template source).
		var (
			submitOK     bool
			blockHashHex string
		)
		switch job.Algo {
		case poolpb.Algo_ALGO_RXM:
			blob, ok := candidate.([]byte)
			if !ok {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("internal error: unexpected monero candidate type %T", candidate))
				return
			}
			if submitErr := s.server.node.SubmitBlock(context.Background(), candidate); submitErr != nil {
				submitOK = false
				s.server.logger.Printf("direct: monero BLOCK SUBMIT FAILED (single-node; multi-node Monero submit is a known, deferred gap) for session %s (job %s, height %d): %v", s.sessionID, job.ID, job.Height, submitErr)
			} else {
				submitOK = true
			}
			sum := sha256.Sum256(blob)
			blockHashHex = hex.EncodeToString(sum[:])
		default:
			block, ok := candidate.(*tari_generated.Block)
			if !ok {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("internal error: unexpected candidate type %T", candidate))
				return
			}
			var results []NodeSubmitResult
			results, submitOK = s.server.submitBlockDirect(context.Background(), block)
			if !submitOK {
				s.hashesAccumulated.Add(job.StaticDifficulty)
				s.server.logger.Printf("direct: BLOCK SUBMIT FAILED at every configured node for session %s (job %s, height %d): %v", s.sessionID, job.ID, job.Height, results)
				s.server.recordBlock(false)
				s.writeShareResponse(req.ID, false, fmt.Sprintf("invalid block: rejected/failed at every configured node (%d configured)", len(results)))
				return
			}
			blockHashHex, _ = blockHash(block)
		}

		if !submitOK {
			s.hashesAccumulated.Add(job.StaticDifficulty)
			s.server.recordBlock(false)
			s.writeShareResponse(req.ID, false, "invalid block: rejected/failed at the configured node")
			return
		}

		s.blockCount.Add(1)
		s.server.logger.Printf("direct: BLOCK FOUND by session %s (address %s) at height %d, job %s, diff %d, hash=%s", s.sessionID, s.address.Load(), job.Height, job.ID, diff, blockHashHex)
		s.server.recordBlock(true)
		s.hashesAccumulated.Add(job.StaticDifficulty)
		s.writeShareResponse(req.ID, true, "")

		// Report the found block to the backend too (accounting/
		// visibility — the backend does not need per-node dispatch detail,
		// only that a block was found and submitted, see
		// transport.ShareTransport.SubmitBlock's doc comment).
		s.forwardBlock(share, job, blockHashHex)

		go s.server.jobManager.InvalidateAll()
	}

	// DISPATCH: mirrors solo.Session's own identical dispatch exactly —
	// only RXT/RXM go through the bounded async pool; SHA3X/C29 keep
	// running finishSubmit INLINE, synchronously, since their validators
	// have no network-latency bottleneck to fix.
	if solo.IsRandomXFamily(job.Algo) {
		if ok := s.server.randomxPool.Submit(finishSubmit); !ok {
			s.writeShareResponse(req.ID, false, "pool is shutting down, please reconnect")
		}
		return
	}
	finishSubmit()
}

func acceptedAddresses(results []NodeSubmitResult) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		if r.Accepted {
			out = append(out, r.Address)
		}
	}
	return out
}

// forwardShare best-effort-forwards share to the real backend via
// transport.ShareTransport.SubmitShare, bounded by a real timeout so a
// slow/unreachable backend cannot hang this session's submit handling
// indefinitely. Failures are logged only — see handleSubmit's doc
// comment on why a transport failure must never flip a
// cryptographically-valid share into a wire-level rejection.
func (s *Session) forwardShare(share *poolpb.Share) {
	if s.server.transport == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.transport.SubmitShare(ctx, share); err != nil {
		s.server.logger.Printf("direct: failed to forward share to backend for session %s: %v", s.sessionID, err)
		s.server.recordTransportError("share")
		return
	}
	s.server.recordTransportSuccess("share")
}

// forwardBlock reports a found block to the backend for accounting
// purposes (see handleSubmit's doc comment — the backend does not
// need per-node dispatch detail, that's logged locally only).
// blockHashHex is a coin-agnostic, already-hex-encoded identifying
// hash for the found block (Tari: blockHash(block); Monero: sha256 of
// the submitted candidate blob — see handleSubmit's coin-aware
// dispatch), computed by the caller since this method no longer
// assumes a *tari_generated.Block shape.
func (s *Session) forwardBlock(share *poolpb.Share, job *solo.Job, blockHashHex string) {
	if s.server.transport == nil {
		return
	}
	pbBlock := &poolpb.Block{
		Algo: job.Algo, Network: s.server.network, Hash: blockHashHex,
		Difficulty: share.GetBlockDiff(), Height: int64(job.Height),
		Timestamp: time.Now().Unix(), PoolType: s.server.poolType, PoolId: s.server.poolID, Valid: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.server.transport.SubmitBlock(ctx, pbBlock); err != nil {
		s.server.logger.Printf("direct: failed to report found block to backend for session %s: %v", s.sessionID, err)
		s.server.recordTransportError("block")
		return
	}
	s.server.recordTransportSuccess("block")
}

// blockHash returns a hex-encoded identifying hash for block, for the
// backend report and the relay message — best-effort: any marshal
// error just yields an empty string rather than blocking the real
// submit/report path on it.
func blockHash(block *tari_generated.Block) (string, error) {
	if block == nil || block.GetHeader() == nil {
		return "", nil
	}
	// There is no single canonical "block hash" field readily
	// available on tari_generated.Block pre-broadcast (the base node
	// computes the real header hash); nonce+height+merge-mining-hash
	// together are already unique per real find and sufficient for
	// this leaf's own logging/dedup purposes.
	h := block.GetHeader()
	return fmt.Sprintf("%x-%d", h.GetNonce(), h.GetHeight()), nil
}

func (s *Session) recordJob(job *solo.Job) {
	if job == nil {
		return
	}
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if s.jobLog == nil {
		s.jobLog = make(map[string]*solo.Job)
	}
	if _, exists := s.jobLog[job.ID]; !exists {
		s.jobList = append(s.jobList, job.ID)
	}
	s.jobLog[job.ID] = job

	size := s.jobHistorySize
	if size <= 0 {
		size = defaultSessionJobHistorySize
	}
	for len(s.jobList) > size {
		oldest := s.jobList[0]
		s.jobList = s.jobList[1:]
		delete(s.jobLog, oldest)
	}
}

func (s *Session) ownJob(id string) (*solo.Job, bool) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	job, ok := s.jobLog[id]
	return job, ok
}

// writeGeneralResponse dispatches on this session's configured algo, mirroring
// solo.Session's own writeGeneralResponse exactly (see that function's doc
// comment for the full rationale): ALGO_C29 gets solo.LegacyErrorResponse's
// real bare-string wire shape, every other algo keeps the PR #56 object/null
// solo.ErrorResponse shape.
func (s *Session) writeGeneralResponse(id int, errMsg, result string) {
	if s.server.algo == poolpb.Algo_ALGO_C29 {
		s.writeJSON(solo.LegacyErrorResponse{ID: id, JsonRPC: "2.0", Error: errMsg, Result: result})
		return
	}
	var rpcErr *solo.RPCError
	if errMsg != "" {
		rpcErr = &solo.RPCError{Code: -1, Message: errMsg}
	}
	s.writeJSON(solo.ErrorResponse{ID: id, JsonRPC: "2.0", Error: rpcErr, Result: result})
}

// writeShareResponse dispatches on this session's configured algo, mirroring
// solo.Session's own writeShareResponse exactly: ALGO_C29 gets
// solo.LegacyShareResponse's real bare-bool wire shape (the shape
// lolMiner/graxil29 actually require — see protocol.go's LegacyShareResponse
// doc comment in the solo package), every other algo keeps the confirmed-
// working object/null solo.ShareResponse shape from PR #56.
func (s *Session) writeShareResponse(id int, accepted bool, errMsg string) {
	s.server.recordShare(accepted)
	if s.server.algo == poolpb.Algo_ALGO_C29 {
		s.writeJSON(solo.LegacyShareResponse{ID: id, JsonRPC: "2.0", Error: errMsg, Result: accepted})
		return
	}
	var rpcErr *solo.RPCError
	var result *solo.ShareResult
	if accepted {
		result = &solo.ShareResult{Status: "OK"}
	} else {
		rpcErr = &solo.RPCError{Code: -1, Message: errMsg}
	}
	s.writeJSON(solo.ShareResponse{ID: id, JsonRPC: "2.0", Error: rpcErr, Result: result})
}

func (s *Session) writeJSON(v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		s.server.logger.Printf("direct: failed to marshal response for session %s: %v", s.sessionID, err)
		return
	}
	buf = append(buf, '\n')
	if err := s.mc.Write(buf); err != nil {
		_ = err
	}
}

func (s *Session) pushJob(job *solo.Job) {
	if !s.loggedIn.Load() {
		return
	}
	s.writeJSON(solo.JobPush{JsonRPC: "2.0", Method: "job", Params: s.jobPayload(job)})
}

func (s *Session) jobPayload(job *solo.Job) solo.JobPayload {
	s.recordJob(job)
	// Record what was actually delivered, mirroring
	// solo.Session.jobPayload's identical bookkeeping -- see
	// lastDeliveredJobID's doc comment.
	s.lastDeliveredJobID.Store(job.ID)
	s.lastDeliveredDifficulty.Store(job.StaticDifficulty)
	payload := solo.JobPayload{
		Algo:   algoWireName(job.Algo),
		Blob:   hex.EncodeToString(job.Header),
		Height: job.Height,
		JobID:  job.ID,
		Target: diffToTargetHex(job.StaticDifficulty),
	}
	// RXT-only (bug fix): mirrors solo.Session's own jobPayload fix
	// exactly — see that file's doc comment on this same fix for the
	// full rationale (job.Header is a bare 32-byte hash, not a
	// minable blob; real RandomX clients need the real 76-byte
	// createTariMiningBlob shape). rxtPowAlgoByte/createTariMiningBlob
	// are this package's own wireutil.go mirrors of solo's identical
	// unexported helpers; solo.TariPowDataFromJob is the shared,
	// exported escape hatch both packages already use.
	if job.Algo == poolpb.Algo_ALGO_RXT {
		blob := createTariMiningBlob(job.Header, 0, rxtPowAlgoByte, solo.TariPowDataFromJob(job))
		payload.Blob = hex.EncodeToString(blob)
	}
	// xn nonce-partitioning is a SHA3X/C29 convention only. RXT/RXM
	// (RandomX-family) miners such as xmrig and graxil neither expect
	// nor use an "xn" field on their jobs, so it must be left as the
	// Go zero value (empty string) here — JobPayload.XN's
	// `json:"xn,omitempty"` tag then omits the field from the wire
	// JSON entirely for those two algos, rather than sending `"xn":""`.
	if job.Algo != poolpb.Algo_ALGO_RXT && job.Algo != poolpb.Algo_ALGO_RXM {
		payload.XN = s.xn
	}
	if (job.Algo == poolpb.Algo_ALGO_RXT || job.Algo == poolpb.Algo_ALGO_RXM) && len(job.VmKey) > 0 {
		payload.SeedHash = hex.EncodeToString(job.VmKey)
	}
	return payload
}

// Compile-time reference to relay/proto types this file relies on
// (avoids an unused-import in edge build configurations while keeping
// the doc comments above accurate about what this file actually
// wires).
var (
	_ = relay.BlockMessage{}
	_ = proto.Marshal
	_ = transport.ShareTransport(nil)
	_ = log.Default
)
