// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
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

	// invalidShareGuard mirrors solo.Session's own identical field
	// exactly — see leaflib.InvalidShareGuard's doc comment for the
	// full DISPATCH_BRIEF.md 2026-09-10 Fix 2b rationale.
	invalidShareGuard *leaflib.InvalidShareGuard

	// --- per-session job ownership, mirroring solo.Session's own
	// SECURITY FIX (PR #14) exactly: see solo/session.go's Session
	// type doc comment for the full rationale. Ported here verbatim
	// because it is a real, structural security property every leaf
	// mode must have, not something specific to solo mode.
	// jobs is the shared, extracted implementation of the bounded
	// per-session job-ownership history -- mirrors solo.Session's own
	// identical field exactly (internal/leaflib.JobHistory; see that
	// type's doc comment for the full rationale this ports unchanged).
	jobs *leaflib.JobHistory[*solo.Job]

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
	return leaflib.AlreadyDelivered(job.ID, job.StaticDifficulty, lastID, s.lastDeliveredDifficulty.Load())
}

func newSession(mc *leaflib.ManagedConnection, server *Server, startingDifficulty uint64) *Session {
	id, _ := leaflib.NewRandomHexID()
	xn, err := leaflib.NewSessionXN()
	if err != nil {
		xn = "0000"
		server.logger.Printf("direct: failed to generate session xn, falling back to %q: %v", xn, err)
	}
	s := &Session{
		mc: mc, server: server, sessionID: id, xn: xn,
		connectedAt: time.Now(), jobs: leaflib.NewJobHistory[*solo.Job](defaultSessionJobHistorySize),
	}
	s.address.Store("")
	s.worker.Store("")
	s.agent.Store("")
	s.currentDifficulty.Store(startingDifficulty)
	if server.trustConfig.Enabled {
		s.trust = solo.NewMinerTrust(server.trustConfig)
	}
	s.invalidShareGuard = leaflib.NewInvalidShareGuard(server.invalidShareGuardConfig)
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

	s.server.debugLogger.Debugf("direct: submit received: session=%s job_id=%s nonce=%s result=%s", s.sessionID, submit.JobID, submit.Nonce, submit.Result)

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
		// XNP-PROXY SUBMIT FIX: mirrors solo.Session's own identical
		// ALGO_RXM handling exactly (see that method's doc comment
		// for the full rationale) -- a real XNP-class multi-tier
		// proxy submit carries workerNonce/poolNonce params that
		// must be patched into the raw template before re-deriving
		// the verification hashing blob, or every submit from that
		// client class hashes the wrong bytes and is guaranteed to
		// be rejected. Gated on the wire fields' mere presence, NOT
		// additionally on solo.IsXNPProxyAgent(agent) -- see
		// solo.Session's own doc comment for why requiring both would
		// risk mis-handling a genuinely proxy-shaped client whose
		// agent string doesn't happen to match that substring check.
		var (
			blob    []byte
			blobErr error
		)
		if submit.WorkerNonce != nil && submit.PoolNonce != nil {
			blob, blobErr = solo.MoneroHashingBlobForXNPSubmit(job, nonce, *submit.WorkerNonce, *submit.PoolNonce)
		} else {
			blob, blobErr = solo.MoneroHashingBlobForSubmit(job, nonce)
		}
		if blobErr != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("failed to build monero randomx verification blob: %v", blobErr))
			return
		}
		share = &poolpb.Share{
			Algo: poolpb.Algo_ALGO_RXM, Network: s.server.network, PoolType: s.server.poolType, PoolId: s.server.poolID,
			BlockDiff: leaflib.SafeInt64(job.StaticDifficulty), Shares: leaflib.SafeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
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
			BlockDiff: leaflib.SafeInt64(job.StaticDifficulty), Shares: leaflib.SafeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
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
		blob := leaflib.CreateTariMiningBlob(job.Header, nonce, leaflib.RXTPowAlgoByte, powData)
		share = &poolpb.Share{
			Algo: poolpb.Algo_ALGO_RXT, Network: s.server.network, PoolType: s.server.poolType, PoolId: s.server.poolID,
			BlockDiff: leaflib.SafeInt64(job.StaticDifficulty), Shares: leaflib.SafeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
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
			BlockDiff: leaflib.SafeInt64(job.StaticDifficulty), Shares: leaflib.SafeInt64(job.StaticDifficulty), BlockHeight: int64(job.Height),
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
		// s.trust's state. UNLIKE solo (which removed this mechanism
		// entirely -- DISPATCH_BRIEF.md, 2026-09-10, Fix 5), it stays
		// fully wired here — see Server.EnableTrust's doc comment for
		// the explicit real-money risk framing an operator enabling it
		// on leaf-direct should understand.
		var valid bool
		skipped := solo.IsRandomXFamily(job.Algo) && s.trust.ShouldSkipValidation()
		if skipped {
			valid = true
			s.server.debugLogger.Debugf("direct: validation attempt: session=%s job_id=%s algo=%v SKIPPED (trusted-miner validation skip)", s.sessionID, job.ID, job.Algo)
		} else {
			valid, err = v.Validate(context.Background(), share)
			s.server.debugLogger.Debugf("direct: validation attempt: session=%s job_id=%s algo=%v valid=%v err=%v", s.sessionID, job.ID, job.Algo, valid, err)
			if err != nil && err != validator.ErrWrongProofType {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("validation error: %v", err))
				return
			}
		}
		if !valid {
			// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b):
			// a fabricated above-target claim that fails this real
			// validation is the actual DoS vector Finding 2
			// identified -- track it against this session's own
			// leaflib.InvalidShareGuard (see that type's doc comment)
			// and disconnect once it exceeds its configured
			// consecutive-invalid-share threshold, so it can no
			// longer keep flooding s.server.randomxPool with garbage.
			// Only ever consulted for RandomX-family submits -- the
			// same scope as s.trust immediately above -- since
			// SHA3X/C29 never touch that shared async pool at all
			// (see this method's own dispatch decision at the bottom
			// of handleSubmit).
			disconnect := false
			if solo.IsRandomXFamily(job.Algo) {
				s.trust.RecordOutcome(false)
				disconnect = s.invalidShareGuard.RecordOutcome(false)
			}
			s.writeShareResponse(req.ID, false, "share does not meet configured difficulty or is cryptographically invalid")
			if disconnect {
				s.server.logger.Printf("direct: disconnecting session %s (address %s): exceeded consecutive invalid-share threshold", s.sessionID, s.address.Load())
				s.mc.Close("exceeded consecutive invalid-share threshold")
			}
			return
		}

		s.shareCount.Add(1)

		diff, candidate, err := s.server.node.BuildCandidateBlock(job, nonce, solo.SubmitProof{Cycle: submit.POW, ResultHex: submit.Result})
		if err != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("difficulty derivation error: %v", err))
			return
		}

		// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 1
		// [CRITICAL — Finding 1]): reject/don't-forward if this
		// share's REAL derived difficulty doesn't meet this job's own
		// configured StaticDifficulty — Alex's exact framing: "as
		// long as the difficulty of the hash is OVER the difficulty
		// of the job, it's fine, because we send the job diff back
		// upstream." diff here is NOT the miner's raw unconfirmed
		// claim: it is BuildCandidateBlock's own real derivation
		// (node.go's tariBuildCandidateBlock/rxtLittleEndianDifficulty
		// for RXT, monero_node.go's moneroDifficultyFromHash for RXM)
		// computed from the SAME submit.Result hex the validator call
		// above just confirmed matches the daemon's own real,
		// independently-recomputed hash (v.Validate's hash-EQUALITY
		// check) -- so this is deriving the REAL difficulty, not
		// merely re-checking an unconfirmed claim, for the ordinary
		// (non-skipped) validation path. For the trust-skipped path
		// (skipped == true above), submit.Result was never
		// cryptographically confirmed at all, so this check is only
		// ever a claimed-value floor there -- see Server.EnableTrust's
		// doc comment for the full, explicit real-money risk framing
		// of combining trust-skip with this floor check. Either way,
		// this is checked BEFORE forwardShare (below) ever reaches the
		// real backend/payout accounting, unlike the pre-fix behavior
		// this closure used to have (validated on hash-equality alone,
		// then forwarded unconditionally at s.server.transport's
		// StaticDifficulty-weighted credit regardless of REAL derived
		// difficulty).
		if solo.IsRandomXFamily(job.Algo) && diff < job.StaticDifficulty {
			disconnect := s.invalidShareGuard.RecordOutcome(false)
			s.trust.RecordOutcome(false)
			s.writeShareResponse(req.ID, false, "share does not meet the job's configured difficulty")
			if disconnect {
				s.server.logger.Printf("direct: disconnecting session %s (address %s): exceeded consecutive invalid-share threshold", s.sessionID, s.address.Load())
				s.mc.Close("exceeded consecutive invalid-share threshold")
			}
			return
		}
		if solo.IsRandomXFamily(job.Algo) {
			s.trust.RecordOutcome(true)
			s.invalidShareGuard.RecordOutcome(true)
		}

		// GENUINE DIFFERENCE FROM leaf-solo: every validated share (not
		// just block-level finds) is forwarded to the real backend over
		// transport.ShareTransport — this is leaf-direct's whole reason
		// for existing (see this package's doc comment).
		//
		// Fix 12 (DISPATCH_BRIEF.md 2026-09-10): dispatched onto
		// s.server.forwardPool -- a SEPARATE, dedicated bounded worker
		// pool from s.server.randomxPool (see forwardPool's own doc
		// comment) -- rather than run inline here. For an RXT/RXM
		// submit, "here" is already one of randomxPool's own small,
		// fixed worker goroutines (this whole finishSubmit closure is
		// dispatched there just above handleSubmit's own DISPATCH
		// comment) -- running forwardShare's up-to-5s backend call
		// synchronously on that SAME goroutine used to tie up one of
		// randomxPool's limited workers for the whole span, degrading
		// process-wide RXT/RXM validation throughput for every OTHER
		// session's shares while this one waited on a slow-but-
		// responding backend. Dispatching onto forwardPool instead
		// means this leaf's wire response to the miner (below) no
		// longer even waits on the backend round-trip at all, and a
		// slow backend can only ever saturate forwardPool's own
		// bounded capacity, never randomxPool's. A transport failure
		// is still logged only (forwardShare's own doc comment) and
		// still never flips an otherwise cryptographically-valid share
		// into a wire-level rejection -- the miner did real, valid
		// work regardless of whether the backend happened to be
		// reachable, or whether this dispatch even ran before the
		// pool was possibly stopped during a graceful shutdown race
		// (logged, not fatal, if so).
		//
		// TrySubmit, deliberately NOT Submit: this closure is already
		// running ON one of randomxPool's own worker goroutines (see
		// above) -- Submit's real backpressure-via-blocking contract
		// would let a genuinely saturated forwardPool block THIS
		// randomxPool worker, reproducing the exact cross-pool
		// resource contention this fix exists to eliminate, just one
		// level removed (confirmed via this package's own
		// TestDirectForwardShare_SlowBackendDoesNotStarveSharedValidationPool,
		// which deadlocked under Submit here before being fixed to
		// use TrySubmit). TrySubmit's "drop and log rather than
		// block" contract is correct here: forwardPool's queue is
		// already generously sized for any realistic burst -- a
		// dropped forward only happens under a genuinely pathological,
		// sustained backend stall, and losing one backend-accounting
		// forward is far preferable to ever blocking real RandomX
		// validation throughput for other sessions.
		if ok := s.server.forwardPool.TrySubmit(func() { s.forwardShare(share) }); !ok {
			s.server.logger.Printf("direct: forward pool saturated or unavailable, dropping share forward to backend for session %s", s.sessionID)
		}

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
			// skipBackendForward is set only when a real ALGO_RXM
			// block was genuinely accepted by monerod but its real,
			// canonical hash could not be confirmed afterward (see
			// the ALGO_RXM case below) — per FIX_BRIEF.md item 3,
			// this leaf must never forward a placeholder/empty hash
			// to the backend (that would silently, permanently
			// orphan a genuinely found block exactly like the old
			// sha256(blob) placeholder did). Always false for every
			// other algo.
			skipBackendForward bool
		)
		switch job.Algo {
		case poolpb.Algo_ALGO_RXM:
			if _, ok := candidate.([]byte); !ok {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("internal error: unexpected monero candidate type %T", candidate))
				return
			}
			if submitErr := s.server.node.SubmitBlock(context.Background(), candidate); submitErr != nil {
				submitOK = false
				s.server.logger.Printf("direct: monero BLOCK SUBMIT FAILED (single-node; multi-node Monero submit is a known, deferred gap) for session %s (job %s, height %d): %v", s.sessionID, job.ID, job.Height, submitErr)
			} else {
				submitOK = true
				// The real monerod submit_block RPC returns NO block
				// hash at all -- sha256(candidate blob) is NOT a
				// real Monero block ID (a real Monero block ID is a
				// Keccak-based hash of the serialized block header/
				// hashing blob; see FIX_BRIEF.md). Resolve the REAL,
				// canonical hash the exact same way the backend's
				// own MoneroVerifier.Verify ultimately checks a
				// stored hash against
				// (internal/backend/chain/monero.go's Verify --
				// get_block_header_by_height at this job's height),
				// so what gets forwarded here can actually
				// mature/unlock downstream instead of being
				// permanently orphaned like every prior leaf-direct
				// RXM block find.
				hashHex, hashErr := s.server.resolveMoneroBlockHash(context.Background(), job.Height)
				if hashErr != nil {
					s.server.recordMoneroBlockHashUnresolved()
					s.server.logger.Printf("direct: MONERO BLOCK HASH UNRESOLVED for session %s (job %s, height %d): the block was accepted by submit_block but its real canonical hash could not be confirmed via get_block_header_by_height: %v -- refusing to forward a placeholder/empty hash to the backend (that would silently, permanently orphan a genuinely found block); this find needs manual reconciliation against the real monerod chain at this height", s.sessionID, job.ID, job.Height, hashErr)
					skipBackendForward = true
				} else {
					blockHashHex = hashHex
				}
			}
		default:
			block, ok := candidate.(*tari_generated.Block)
			if !ok {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("internal error: unexpected candidate type %T", candidate))
				return
			}
			var results []NodeSubmitResult
			results, submitOK, blockHashHex = s.server.submitBlockDirect(context.Background(), block)
			if !submitOK {
				s.hashesAccumulated.Add(job.StaticDifficulty)
				s.server.logger.Printf("direct: BLOCK SUBMIT FAILED at every configured node for session %s (job %s, height %d): %v", s.sessionID, job.ID, job.Height, results)
				s.server.recordBlock(false)
				s.writeShareResponse(req.ID, false, fmt.Sprintf("invalid block: rejected/failed at every configured node (%d configured)", len(results)))
				return
			}
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
		//
		// skipBackendForward (set only by the ALGO_RXM case above,
		// FIX_BRIEF.md item 3): this find's real hash could not be
		// confirmed, so it is deliberately NOT forwarded here at
		// all — forwarding blockHashHex="" would silently write an
		// unverifiable placeholder-shaped hash into the backend's
		// blocks table, reproducing the exact permanently-orphaned-
		// block bug this fix exists to eliminate. The block was
		// already accepted by the node itself (submitOK above) and
		// recordBlock(true)/the miner's own accepted response
		// already reflect that; only backend accounting for THIS
		// find is skipped, and recordMoneroBlockHashUnresolved above
		// already made that loudly visible via metrics+logs for
		// manual reconciliation.
		//
		// Fix 12 (DISPATCH_BRIEF.md 2026-09-10): dispatched onto
		// s.server.forwardPool exactly like forwardShare above (see
		// that call site's own doc comment for the full rationale,
		// including why this uses TrySubmit rather than Submit) --
		// forwardBlock's own timeout is even longer (10s), so leaving
		// it inline here would tie up a randomxPool worker for an
		// even longer span on the (rare, but real) block-find path.
		if skipBackendForward {
			s.server.logger.Printf("direct: NOT forwarding block find to backend for session %s (job %s, height %d) -- real hash unresolved, see the MONERO BLOCK HASH UNRESOLVED log line above", s.sessionID, job.ID, job.Height)
		} else if ok := s.server.forwardPool.TrySubmit(func() { s.forwardBlock(share, job, blockHashHex) }); !ok {
			s.server.logger.Printf("direct: forward pool saturated or unavailable, dropping block forward to backend for session %s", s.sessionID)
		}

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
// hash for the found block (Tari: the REAL base-node-confirmed hash
// from realBlockHashHex/submitBlockDirect — see that function's doc
// comment; Monero: the REAL canonical hash resolved via
// s.server.resolveMoneroBlockHash/get_block_header_by_height — see
// handleSubmit's coin-aware dispatch; this method is never called at
// all for a Monero find whose real hash could not be resolved, see
// handleSubmit's skipBackendForward), computed by the caller since
// this method no longer assumes a *tari_generated.Block shape.
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

func (s *Session) recordJob(job *solo.Job) {
	if job == nil {
		return
	}
	s.jobs.Record(job.ID, job)
}

func (s *Session) ownJob(id string) (*solo.Job, bool) {
	return s.jobs.Own(id)
}

// writeGeneralResponse and writeShareResponse now delegate the actual
// algo-conditional wire-shape dispatch to
// leaflib.WriteGeneralResponse/WriteShareResponse -- mirrors
// solo.Session's own identical delegation exactly (see
// leaflib/wireshape.go's doc comment for the full rationale: this
// exact logic used to be hand-copied between this file and
// solo/session.go's own identical methods, and is the real cause of
// the repeated wire-shape production incidents this dispatch's
// DISPATCH_BRIEF cites -- see commits b3c8716, 0339d81, 0253b57).
func (s *Session) writeGeneralResponse(id int, errMsg, result string) {
	leaflib.WriteGeneralResponse(s.writeJSON, leaflib.IsLegacyWireAlgo(s.server.algo), id, errMsg, result)
}

func (s *Session) writeShareResponse(id int, accepted bool, errMsg string) {
	s.server.recordShare(accepted)
	s.server.debugLogger.Debugf("direct: submit result: session=%s accepted=%v reason=%q", s.sessionID, accepted, errMsg)
	leaflib.WriteShareResponse(s.writeJSON, leaflib.IsLegacyWireAlgo(s.server.algo), id, accepted, errMsg)
}

func (s *Session) writeJSON(v any) {
	leaflib.WriteJSON(s.mc, s.server.logger, "direct", s.sessionID, v)
}

func (s *Session) pushJob(job *solo.Job) {
	leaflib.PushJob(s.writeJSON, s.loggedIn.Load(), func() any { return s.jobPayload(job) })
}

func (s *Session) jobPayload(job *solo.Job) solo.JobPayload {
	s.recordJob(job)
	// Record what was actually delivered, mirroring
	// solo.Session.jobPayload's identical bookkeeping -- see
	// lastDeliveredJobID's doc comment.
	s.lastDeliveredJobID.Store(job.ID)
	s.lastDeliveredDifficulty.Store(job.StaticDifficulty)
	payload := solo.JobPayload{
		Algo:   leaflib.AlgoWireName(job.Algo),
		Blob:   hex.EncodeToString(job.Header),
		Height: job.Height,
		JobID:  job.ID,
		Target: leaflib.DiffToTargetHex(job.StaticDifficulty),
	}
	// RXT-only (bug fix): mirrors solo.Session's own jobPayload fix
	// exactly — see that file's doc comment on this same fix for the
	// full rationale (job.Header is a bare 32-byte hash, not a
	// minable blob; real RandomX clients need the real 76-byte
	// createTariMiningBlob shape). leaflib.RXTPowAlgoByte/createTariMiningBlob
	// are this package's own wireutil.go mirrors of solo's identical
	// unexported helpers; solo.TariPowDataFromJob is the shared,
	// exported escape hatch both packages already use.
	if job.Algo == poolpb.Algo_ALGO_RXT {
		blob := leaflib.CreateTariMiningBlob(job.Header, 0, leaflib.RXTPowAlgoByte, solo.TariPowDataFromJob(job))
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
	// XNP-PROXY SHAPE: mirrors solo.Session's own identical jobPayload
	// addition exactly — see solo/protocol.go's JobPayload doc comment
	// for the full field-by-field provenance from the real
	// nodejs-pool-sxmr reference, and solo/session.go's jobPayload for
	// the full RXM/RXT branch rationale (including the RXT
	// investigation finding: Tari's protocol has no real analog of
	// Monero's reserve_size/coinbase-reservation mechanism, so
	// ReservedOffset/ClientPoolOffset are deliberately left nil for
	// RXT while ClientNonceOffset is set to the real, meaningful
	// rxtXmrigNonceOffset constant). solo.IsXNPProxyAgent is the
	// single shared implementation of the case-sensitive
	// "xmr-node-proxy" substring check both packages use, so leaf-solo
	// and leaf-direct can never drift on detection logic.
	//
	// NON-REGRESSION: for every non-proxy agent, and for every
	// non-RXM/RXT algo regardless of agent, all four pointer fields
	// stay nil and are omitted from the wire (omitempty) — see
	// protocol_xnp_test.go (solo package) and this package's own
	// session_xnp_test.go for real marshaled-JSON byte-diffs proving
	// this.
	if solo.IsXNPProxyAgent(s.agent.Load().(string)) {
		switch job.Algo {
		case poolpb.Algo_ALGO_RXM:
			// BOUNDS-CHECK GATE (real production bug fix -- see
			// job.go's Job.ReservedOffsetUsable doc comment and
			// monero_node.go's GetBlockTemplate for the full
			// rationale and live-reproduction evidence). When
			// monerod's real reserved_offset does not fit within its
			// own returned blocktemplate_blob for THIS job,
			// ReservedOffsetUsable is false and this whole branch is
			// skipped, leaving all four pointer fields nil/omitted --
			// exactly the same "nil means not offered" degradation
			// already used for RXT's ReservedOffset/ClientPoolOffset
			// below, not a parallel signaling mechanism.
			if job.ReservedOffsetUsable {
				rawBlobHex := hex.EncodeToString(job.RawTemplateBlob)
				reservedOffset := job.ReservedOffset
				clientNonceOffset := job.ReservedOffset + 12
				clientPoolOffset := job.ReservedOffset + 8
				payload.BlocktemplateBlob = &rawBlobHex
				payload.ReservedOffset = &reservedOffset
				payload.ClientNonceOffset = &clientNonceOffset
				payload.ClientPoolOffset = &clientPoolOffset
			}
		case poolpb.Algo_ALGO_RXT:
			blobHex := payload.Blob
			clientNonceOffset := leaflib.RXTXmrigNonceOffset
			payload.BlocktemplateBlob = &blobHex
			payload.ClientNonceOffset = &clientNonceOffset
		}
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
