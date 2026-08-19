// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Session drives one miner connection's request/response loop on top of
// an already-accepted *leaflib.ManagedConnection, speaking the real
// Monero-style JSON-RPC 2.0 stratum dialect (protocol.go) that actual
// SHA3X miner software requires. It never bypasses ManagedConnection's
// lifecycle guarantees: all reads go through mc.Read (which re-arms the
// rolling idle deadline — see connection.go), all writes go through
// mc.Write (which is already synchronized onto the connection's single
// writer goroutine), and teardown always ends in mc.Close so the
// ConnectionManager registry stays consistent.
type Session struct {
	mc     *leaflib.ManagedConnection
	server *Server

	sessionID string
	// xn is this session's own randomly-assigned 2-byte extranonce
	// (job.go's newSessionXN), assigned exactly once, at connect time
	// (here, in newSession below) — mirroring go-tari-sha3x-solo-stratum's
	// miner.go connection-init timing exactly, NOT re-rolled per job or
	// per login. Every job payload sent to this session (login
	// response's nested job, unsolicited pushes, explicit getjob
	// responses) carries this same value in JobPayload.XN, and every
	// submit from this session must have its nonce hex-prefixed with
	// it (handleSubmit below) or be rejected before any PoW validation
	// runs.
	xn       string
	loggedIn atomic.Bool
	address  atomic.Value // string
	worker   atomic.Value // string

	// shareCount/blockCount are local diagnostic counters only - solo
	// mode has no share table and no backend to forward to (see
	// cmd/leaf-solo's doc comment); a share only matters here as
	// hashrate-estimation signal.
	shareCount atomic.Uint64
	blockCount atomic.Uint64

	// --- per-session vardiff state (ported from
	// go-tari-sha3x-solo-stratum's minerStruct.Difficulty/hashes/
	// connectTime, see vardiff.go) ---

	// connectedAt is this session's connection time, used by
	// vardiff.go's maybeRetarget to compute connSeconds
	// (go-tari-sha3x-solo-stratum's getConnSeconds). Set once, here,
	// at connect time; never mutated afterward, so no synchronization
	// is needed for reads from the vardiff goroutine (see the
	// happens-before guarantee documented on runVardiffLoop).
	connectedAt time.Time

	// currentDifficulty is THIS session's own current share
	// difficulty (go-tari-sha3x-solo-stratum's minerStruct.Difficulty).
	// It starts at the server's configured starting difficulty and is
	// only ever mutated by this session's own vardiff retarget
	// goroutine (vardiff.go's maybeRetarget) — no other session's
	// retarget can touch it, and no shared/global state is involved.
	currentDifficulty atomic.Uint64

	// hashesAccumulated is the difficulty-weighted accept-history
	// accumulator (go-tari-sha3x-solo-stratum's minerStruct.hashes):
	// incremented by the job's current StaticDifficulty on every
	// accepted share (see handleSubmit below), never reset for the
	// lifetime of the connection. This is NOT a raw hash count; it is
	// "sum of difficulty values of every share accepted so far",
	// which vardiff.go's computeRetarget divides by connection-time to
	// estimate this session's accepted-share rate.
	hashesAccumulated atomic.Uint64
}

func newSession(mc *leaflib.ManagedConnection, server *Server, startingDifficulty uint64) *Session {
	id, _ := newRandomHexID() // collisions are cosmetic only (diagnostic/session id, not consensus data)
	// Assigned once, here, at connect time — see the xn field's doc
	// comment. A crypto/rand read failure here is exceptionally rare
	// (would indicate a broken system RNG); falling back to the
	// all-zeros xn "0000" rather than panicking or dropping the
	// connection keeps this session merely un-partitioned from any
	// other all-zeros-fallback session instead of unusable.
	xn, err := newSessionXN()
	if err != nil {
		xn = "0000"
		server.logger.Printf("solo: failed to generate session xn, falling back to %q: %v", xn, err)
	}
	s := &Session{mc: mc, server: server, sessionID: id, xn: xn, connectedAt: time.Now()}
	s.address.Store("")
	s.worker.Store("")
	s.currentDifficulty.Store(startingDifficulty)
	return s
}

// Run is the session's read loop. It returns when the connection closes
// for any reason (remote EOF, idle timeout, manager shutdown). The
// caller (Server.handleConn) owns calling mc.Close afterward.
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
}

func (s *Session) handleLine(line string) {
	var req Request
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		s.server.logger.Printf("solo: session %s sent unparseable message, dropping: %v", s.sessionID, err)
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

// handleLogin implements the real "login" method (see protocol.go's
// doc comment: the wire message is wrapped in the same envelope as
// every other method — {"id","jsonrpc","method":"login","params":{...}}
// — confirmed against go-tari-sha3x-solo-stratum's actual dispatch
// loop). Deliberately does NOT parse "." / "+" address-suffix syntax
// for payment-ID/custom-difficulty (go-crypto-pool's solo leaf assigns
// every session the same STARTING difficulty — see
// LEAF_SOLO_STARTING_DIFFICULTY — after which each session's own
// vardiff retarget loop (vardiff.go) independently adjusts it based on
// that session's own accept history) — the address is taken as-is.
func (s *Session) handleLogin(req Request) {
	var login LoginRequest
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

	worker := login.Pass
	if login.RigID != "" {
		worker = login.RigID
	}
	if worker == "" {
		worker = "x"
	}

	s.address.Store(login.Login)
	s.worker.Store(worker)
	s.loggedIn.Store(true)

	job, err := s.server.jobManager.JobForXNAtDifficulty(context.Background(), s.xn, s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("solo: failed to get job for session %s (xn %s): %v", s.sessionID, s.xn, err)
		s.writeGeneralResponse(req.ID, "no job template available yet, retry shortly", "")
		return
	}
	resp := LoginResponse{
		ID:      req.ID,
		JsonRPC: "2.0",
		Result: LoginResult{
			ID:     s.sessionID,
			Job:    s.jobPayload(job),
			Status: "OK",
		},
		Status: "OK",
	}
	s.writeJSON(resp)
}

func (s *Session) handleGetJob(req Request) {
	if !s.loggedIn.Load() {
		s.writeGeneralResponse(req.ID, "login required before getjob", "")
		return
	}
	job, err := s.server.jobManager.JobForXNAtDifficulty(context.Background(), s.xn, s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("solo: failed to get job for session %s (xn %s): %v", s.sessionID, s.xn, err)
		s.writeGeneralResponse(req.ID, "no job template available yet, retry shortly", "")
		return
	}
	// Real miners issuing an explicit getjob get the same unsolicited
	// "job" push shape as an unprompted refresh, per
	// go-tari-sha3x-solo-stratum's dispatch (server.go's `case
	// "getjob"` calls SendNewJob(false), the same push path a
	// background refresh uses — it does not echo the request id back
	// in a Response).
	s.pushJob(job)
}

// handleSubmit implements the real "submit" method. Underlying logic
// (SHA3XValidator.Validate, block-target comparison, SubmitBlock,
// shareCount/blockCount bookkeeping) is unchanged from the previous
// wire format — only request parsing and response encoding are new
// relative to that pass. NOW ALSO enforces the real per-session xn
// prefix check (ported from go-tari-sha3x-solo-stratum's miner.go
// SubmitJob: `strings.HasPrefix(strings.ToLower(submittedWork.Nonce),
// m.xn)`), BEFORE any PoW validation work happens — a nonce that
// doesn't start with this session's own assigned xn is rejected
// outright, mirroring the legacy rejection message shape ("Invalid
// XNonce %v"). This is purely wire-level/session bookkeeping: verified
// against the real hash math in validator/sha3x.go
// (sha3xHeaderDiff/GetHeaderDiff) that the full 8-byte nonce is used
// directly as hash pre-image material with no separate xn encoding —
// xn is a leading-byte convention miners are expected to respect on
// their nonce composition, not something baked into the hash function
// itself, so no change to SHA3XValidator was needed or made. DOES
// enforce per-job used-nonce tracking via Job.MarkNonceUsed, which the
// previous wire format's implementation never had.
func (s *Session) handleSubmit(req Request) {
	if !s.loggedIn.Load() {
		s.writeGeneralResponse(req.ID, "login required before submit", "")
		return
	}
	var submit SubmitRequest
	if len(req.Params) == 0 {
		s.writeShareResponse(req.ID, false, "submit requires params")
		return
	}
	if err := json.Unmarshal(req.Params, &submit); err != nil {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("invalid submit params: %v", err))
		return
	}

	job, ok := s.server.jobManager.GetJob(submit.JobID)
	if !ok {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("unknown or stale job_id: %s", submit.JobID))
		return
	}

	// xn-prefix check happens BEFORE nonce decoding/PoW validation —
	// ported exactly from the legacy ordering and rejection shape.
	if !strings.HasPrefix(strings.ToLower(submit.Nonce), s.xn) {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("Invalid XNonce %v", submit.Nonce))
		return
	}

	nonceBytes, err := hex.DecodeString(submit.Nonce)
	if err != nil || len(nonceBytes) != 8 {
		s.writeShareResponse(req.ID, false, "nonce must be 8 bytes, hex-encoded little-endian uint64")
		return
	}
	nonce := binary.LittleEndian.Uint64(nonceBytes)

	if !job.MarkNonceUsed(nonce) {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("duplicate nonce: %s", submit.Nonce))
		return
	}

	share := &poolpb.Share{
		Algo:           poolpb.Algo_ALGO_SHA3X,
		Network:        s.server.network,
		BlockDiff:      safeInt64(job.StaticDifficulty),
		BlockHeight:    int64(job.Height),
		PaymentAddress: s.address.Load().(string),
		Identifier:     s.worker.Load().(string),
		RawProof: &poolpb.Share_Sha3XProof{
			Sha3XProof: &poolpb.SHA3XProof{
				Header: job.Header,
				Nonce:  nonce,
			},
		},
	}

	valid, err := s.server.validator.Validate(context.Background(), share)
	if err != nil && err != validator.ErrWrongProofType {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("validation error: %v", err))
		return
	}
	if !valid {
		s.writeShareResponse(req.ID, false, "share does not meet configured difficulty or is cryptographically invalid")
		return
	}

	// Valid share (met the configured static share difficulty). This is
	// local diagnostic/hashrate-estimation signal only — solo mode has
	// no share table and no backend to forward it to.
	s.shareCount.Add(1)
	diff := validator.SHA3XHeaderDiff(nonce, job.Header)

	if job.NetworkTargetDifficulty == 0 || diff < job.NetworkTargetDifficulty {
		// Accepted share, below block difficulty: this is the
		// vardiff accept-history signal (ported exactly from
		// go-tari-sha3x-solo-stratum's SubmitJob, `m.hashes +=
		// job.Target` at the "valid, non-block" accept point — see
		// vardiff.go's doc comment). job.StaticDifficulty is THIS
		// job's stamped difficulty, i.e. this session's current
		// vardiff value at the moment this share was accepted.
		s.hashesAccumulated.Add(job.StaticDifficulty)
		s.writeShareResponse(req.ID, true, "")
		return
	}

	// Meets full block difficulty: construct the real submission from
	// the already-fetched real GRPC template/coinbase data and submit
	// it for real. Mirrors go-tari-sha3x-solo-stratum's SubmitJob
	// (subsystems/poolStratum/miner.go, ~line 493).
	block := cloneBlockWithNonce(job.Result.GetBlock(), nonce)
	_, err = s.server.node.SubmitBlock(context.Background(), block)
	if err != nil {
		// Ported exactly from the reference (miner.go's SubmitJob,
		// SubmitBlock-error branch): the reference still increments
		// m.hashes here even though the wire response to the miner
		// is a rejection (their proof was cryptographically valid,
		// but the pool/node-level submission failed — that's not the
		// miner's fault to see as an accept, so mirror the
		// reference's choice byte-for-byte on both the wire response
		// AND the vardiff accounting, rather than "fixing" either).
		s.hashesAccumulated.Add(job.StaticDifficulty)
		s.server.logger.Printf("solo: SubmitBlock failed for session %s (job %s, height %d): %v", s.sessionID, job.ID, job.Height, err)
		// Ported exactly from the reference (miner.go's SubmitJob,
		// SubmitBlock-error branch): the wire response to the miner is
		// still a rejection (their proof was cryptographically valid,
		// but the pool/node-level submission failed — that is not the
		// miner's fault to see as an accept, so mirror the reference's
		// choice here byte-for-byte rather than "fixing" it).
		s.writeShareResponse(req.ID, false, fmt.Sprintf("invalid block: %v", err))
		return
	}

	s.blockCount.Add(1)
	s.server.logger.Printf("solo: BLOCK FOUND by session %s (address %s) at height %d, job %s, diff %d", s.sessionID, s.address.Load(), job.Height, job.ID, diff)
	s.hashesAccumulated.Add(job.StaticDifficulty)
	s.writeShareResponse(req.ID, true, "")

	// A block was found; every cached per-xn template is now stale
	// (built against a tip that no longer exists). Invalidate the
	// whole cache (this also fires JobManager's subscribers, which
	// triggers Server.invalidateAndRepushJobs to regenerate+push fresh
	// jobs to every connected session) rather than waiting out the
	// tip-poll interval.
	go s.server.jobManager.InvalidateAll()
}

func (s *Session) writeGeneralResponse(id int, errMsg, result string) {
	s.writeJSON(ErrorResponse{ID: id, JsonRPC: "2.0", Error: errMsg, Result: result})
}

func (s *Session) writeShareResponse(id int, accepted bool, errMsg string) {
	s.writeJSON(ShareResponse{ID: id, JsonRPC: "2.0", Error: errMsg, Result: accepted})
}

func (s *Session) writeJSON(v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		s.server.logger.Printf("solo: failed to marshal response for session %s: %v", s.sessionID, err)
		return
	}
	buf = append(buf, '\n')
	if err := s.mc.Write(buf); err != nil {
		// Connection is going away; nothing more to do here, Run's
		// scanner loop will observe the resulting read error/EOF and
		// exit, and the caller closes mc.
		_ = err
	}
}

// pushJob sends an unsolicited real "job" push (protocol.go's JobPush)
// for a newly-(re)generated Job specific to this session's own xn.
func (s *Session) pushJob(job *Job) {
	if !s.loggedIn.Load() {
		return
	}
	s.writeJSON(JobPush{JsonRPC: "2.0", Method: "job", Params: s.jobPayload(job)})
}

// jobPayload builds the real wire job object (protocol.go's JobPayload)
// for job, ported exactly from go-tari-sha3x-solo-stratum's
// minerTracking.MinerJob.GetJobJSON: Blob is hex(Header) (the merge
// mining hash), JobID is the job's already block-hash-derived real
// job_id (see job.go's jobIDFromBlockHash), Target is
// diffToTarget(difficulty) little-endian-8-byte-then-hex encoded, and
// XN is this session's own assigned extranonce (the same value on
// every job pushed to this session, since xn is assigned once at
// connect time — see the xn field's doc comment).
func (s *Session) jobPayload(job *Job) JobPayload {
	return JobPayload{
		Algo:   "sha3x",
		Blob:   hex.EncodeToString(job.Header),
		Height: job.Height,
		JobID:  job.ID,
		Target: diffToTargetHex(job.StaticDifficulty),
		XN:     s.xn,
	}
}

// diffToTargetHex ports go-tari-sha3x-solo-stratum's
// minerTracking.MinerJob.diffToTarget + GetJobJSON's subsequent
// encoding exactly: target = uint64(2^64-1) / difficulty, then that
// resulting uint64 is written out as 8 raw bytes in LITTLE-ENDIAN
// order, then hex-encoded as a string. A difficulty of 0 would be a
// division by zero in the reference's own formula too (it has no
// guard); since go-crypto-pool always stamps jobs with a non-zero
// leaf-configured StaticDifficulty (LEAF_SOLO_DIFFICULTY) in normal
// operation, treat an explicit 0 as 1 here purely to avoid a runtime
// panic on a misconfiguration rather than changing the real formula.
func diffToTargetHex(difficulty uint64) string {
	if difficulty == 0 {
		difficulty = 1
	}
	target := uint64(math.MaxUint64) / difficulty
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, target)
	return hex.EncodeToString(buf)
}

// safeInt64 converts a uint64 to int64 by clamping to math.MaxInt64
// rather than allowing a silent two's-complement wraparound. This
// matters here specifically because poolpb.Share.BlockDiff is int64 on
// the wire, while JobManagerConfig.StaticDifficulty (and any future
// vardiff-derived difficulty) is uint64 -- a naive int64(x) conversion
// of a uint64 value at or above 1<<63 wraps to a NEGATIVE int64, which
// would make validator.SHA3XValidator's `share.GetBlockDiff() > 0` guard
// evaluate false and SILENTLY SKIP the difficulty check entirely,
// accepting any cryptographically-valid-but-arbitrarily-easy share as
// if it met the configured difficulty. Found via a real failing test
// (TestSessionSubmitCryptographicallyInvalid used math.MaxUint64 as a
// deliberately-impossible-to-meet difficulty and got a false accept)
// during independent re-verification of this package -- clamping here
// is the fix, not a workaround in the test.
func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// cloneBlockWithNonce returns a deep copy of block (via proto.Clone, to
// avoid copying protobuf's internal sync.Mutex-bearing MessageState by
// value) with Header.Nonce set to nonce, so the shared job template
// isn't mutated by a (potentially losing) submission race between
// miners on the same job.
func cloneBlockWithNonce(block *tari_generated.Block, nonce uint64) *tari_generated.Block {
	if block == nil {
		return nil
	}
	blockCopy := proto.Clone(block).(*tari_generated.Block)
	if blockCopy.Header == nil {
		blockCopy.Header = &tari_generated.BlockHeader{}
	}
	blockCopy.Header.Nonce = nonce
	return blockCopy
}
