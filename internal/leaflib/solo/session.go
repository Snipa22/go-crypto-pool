// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
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
	// runs. NOTE: xn is a SHA3X-specific nonce-composition convention,
	// not the real security boundary — see jobList/jobLog below.
	xn       string
	loggedIn atomic.Bool
	address  atomic.Value // string
	worker   atomic.Value // string

	// --- SECURITY FIX: per-session job ownership (jobList/jobLog) ---
	//
	// Ported from go-tari-sha3x-solo-stratum's minerStruct
	// (subsystems/poolStratum/miner.go, ~line 50-97): each MINER
	// (session), not the pool/JobManager as a whole, owns its own
	// bounded history of jobs it has actually been issued. jobList is
	// an ordered (oldest-first) list of this session's own recent
	// job_ids; jobLog maps those same job_ids to the *Job they refer
	// to. This mirrors the legacy jobList/jobLog pair exactly (see
	// getJob/CleanMinerJobs, miner.go ~line 344-428).
	//
	// Before this existed, handleSubmit looked up
	// s.server.jobManager.GetJob(submit.JobID) against ONE GLOBAL map
	// shared by every session (job.go's jobsByID) — any session could
	// submit against any OTHER session's job_id, and the only thing
	// standing in the way was the SHA3X-specific xn-prefix check
	// below, which does not generalize to future non-xn algos
	// (RandomX/RXT/RXM). Session-scoped jobList/jobLog makes
	// cross-session submission STRUCTURALLY IMPOSSIBLE: session B's
	// code path can never even see an entry for a job_id that was only
	// ever recorded into session A's own jobLog — there is no shared
	// data structure to read from at all. See ownJob/recordJob below
	// and handleSubmit's ownership check, which now runs BEFORE the
	// xn-prefix check and applies uniformly to every algo.
	jobsMu         sync.Mutex
	jobList        []string        // oldest-first job_ids this session has actually been issued
	jobLog         map[string]*Job // job_id -> *Job, mirrors jobList
	jobHistorySize int             // bound on len(jobList); see newSession/defaultSessionJobHistorySize

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

// defaultSessionJobHistorySize is the default bound on how many of a
// session's own most-recently-issued jobs remain submittable.
//
// Reasoning: a miner can legitimately still be hashing against a
// slightly stale job for a brief window around a job push (e.g. a
// vardiff retarget or a tip-triggered invalidateAndRepushJobs firing
// while a share for the previous job is already in flight on the
// wire) — the bound must tolerate that race without being so large
// that ancient jobs stay submittable indefinitely (that's what
// JobMaxAge's real time-based expiry is for; the count-based bound
// here is about memory/history size, not staleness per se). 8 keeps
// a comfortable multi-push cushion (a session's own vardiff retarget
// interval defaults to 60s and a tip-triggered repush is comparatively
// rare) while bounding each session's own memory footprint to a small,
// constant number of held *Job pointers regardless of connection
// lifetime.
const defaultSessionJobHistorySize = 8

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
	s := &Session{mc: mc, server: server, sessionID: id, xn: xn, connectedAt: time.Now(), jobLog: make(map[string]*Job), jobHistorySize: defaultSessionJobHistorySize}
	s.address.Store("")
	s.worker.Store("")
	s.currentDifficulty.Store(startingDifficulty)
	return s
}

// Run is the session's read loop. It returns when the connection closes
// for any reason (remote EOF, idle timeout, manager shutdown). The
// caller (Server.handleConn) owns calling mc.Close afterward. Before
// returning, it classifies the real reason the read loop ended (see
// classifyCloseError) and records it against
// leaf_connection_errors_total — purely observability, it never
// changes when/why the loop actually stops.
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

// classifyCloseError maps a real bufio.Scanner terminal error from
// Session.Run's read loop onto the small, fixed set of connection-error
// categories metrics.Metrics.ConnectionErrorsTotal exposes. Every
// branch corresponds to a real, observed code path (see
// metrics.ConnErrorIdleTimeout/ConnErrorRemoteEOF/
// ConnErrorProtocolError's doc comments for exactly which):
//   - nil: bufio.Scanner reports a plain io.EOF (the common case, the
//     miner cleanly closed its side) as a nil Err() — remote-eof.
//   - a net.Error with Timeout() == true: the rolling idle deadline
//     (internal/leaflib.ManagedConnection.armDeadline) fired.
//   - bufio.ErrTooLong: the miner sent a line longer than the
//     scanner's configured buffer — a real protocol violation.
//   - leaflib.ErrConnectionClosed: the connection was already being
//     torn down by another path (e.g. manager shutdown) when this
//     read observed it. There is no dedicated "shutdown" category in
//     the fixed set, and this is not the miner's fault, so it is
//     folded into ConnErrorOther rather than inventing a new fixed
//     category with no other producer.
//   - anything else (e.g. a raw TCP reset): ConnErrorOther, the
//     bounded catch-all bucket.
func classifyCloseError(err error) string {
	if err == nil {
		return metrics.ConnErrorRemoteEOF
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return metrics.ConnErrorIdleTimeout
	}
	if errors.Is(err, bufio.ErrTooLong) {
		return metrics.ConnErrorProtocolError
	}
	return metrics.ConnErrorOther
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

// c29SubmitCycleSize/c29SubmitEdgeBits mirror validator/c29.go's
// c29ProofSize/c29EdgeBits exactly (Tari's real Cuckaroo29: 42-edge
// cycles at edge_bits=29) — duplicated here as session-package-local
// constants purely because the validator package's own constants are
// unexported (this package only wires the already-correct validator
// in, it doesn't reach into its internals).
const (
	c29SubmitEdgeBits  = 29
	c29SubmitCycleSize = 42
)

// handleSubmit implements the real "submit" method. Underlying logic
// (SHA3XValidator.Validate, block-target comparison, SubmitBlock,
// shareCount/blockCount bookkeeping) is unchanged from the previous
// wire format — only request parsing and response encoding are new
// relative to that pass.
//
// ALGO-AWARE DISPATCH (this pass): everything below the xn-prefix
// check branches on job.Algo (job.go's Job.Algo, stamped at template
// fetch time from JobManagerConfig.Algo) rather than assuming SHA3X:
//   - nonce byte order: SHA3X decodes little-endian (unchanged from
//     before), C29 decodes BIG-ENDIAN — confirmed from
//     go-tari-c29-solo-stratum's real miner.go SubmitJob
//     (`nonce := binary.BigEndian.Uint64(b)`), genuinely different
//     from SHA3X, not assumed to be the same.
//   - raw_proof shape: SHA3X builds a Share_Sha3XProof (header+nonce),
//     C29 builds a Share_C29Proof (header+nonce+the submitted "pow"
//     42-edge cycle — see protocol.go's SubmitRequest.POW, ported
//     exactly from go-tari-c29-solo-stratum's MinerRPCSubmit.POW).
//   - validator dispatch: looked up from s.server.validators (a
//     validator.Registry) BY job.Algo, not a single server-wide
//     validator field.
//   - post-accept block-find difficulty/SubmitBlock: SHA3X reuses
//     validator.SHA3XHeaderDiff and clones the block with just a
//     stamped Nonce; C29 uses validator.C29Difficulty and clones the
//     block with BOTH a stamped Nonce AND a real
//     Header.Pow.PowData = the submitted cycle, edge-packed exactly as
//     go-tari-c29-solo-stratum's SubmitJob does
//     (`job.BlockResult.Block.Header.Pow.PowData = packedData`).
//
// SECURITY FIX: the job lookup now queries THIS SESSION'S OWN job
// history (s.ownJob, jobsMu/jobList/jobLog above) instead of
// s.server.jobManager.GetJob's shared, all-sessions-spanning map. A
// submit referencing a job_id this session was never actually issued
// is rejected as "unknown or stale job_id" — this is the REAL,
// structural security boundary (session B's code path cannot even see
// an entry for a job_id only ever recorded into session A's jobLog),
// checked BEFORE the xn-prefix check and BEFORE any PoW validation, so
// it applies uniformly to every algo including future non-xn ones
// (RandomX/RXT/RXM). Also enforces a REAL per-job expiry
// (JobManager.JobMaxAge, backed by JobManagerConfig.JobMaxAge/
// Job.CreatedAt) independently of tip-invalidation: a job still
// present in this session's own history but older than the
// configured max age is rejected with a distinct "job expired"
// reason.
//
// The per-session xn prefix check (ported from
// go-tari-sha3x-solo-stratum's miner.go SubmitJob:
// `strings.HasPrefix(strings.ToLower(submittedWork.Nonce), m.xn)`)
// STAYS — it is still a real, useful nonce-composition validity check
// for BOTH algos (go-tari-c29-solo-stratum's SubmitJob has the exact
// same xn-prefix check on the exact same hex-STRING representation of
// the nonce, before decoding it) — but it is no longer the security
// boundary; it now runs AFTER session-ownership has already been
// confirmed. This is purely wire-level/session bookkeeping: verified
// against the real hash math in validator/sha3x.go
// (sha3xHeaderDiff/GetHeaderDiff) that the full 8-byte nonce is used
// directly as hash pre-image material with no separate xn encoding —
// xn is a leading-byte convention miners are expected to respect on
// their nonce composition, not something baked into the hash function
// itself, so no change to SHA3XValidator (or C29Validator) was needed
// or made. DOES enforce per-job used-nonce tracking via
// Job.MarkNonceUsed, which the previous wire format's implementation
// never had.
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

	// SECURITY: session-ownership check FIRST, independently of xn —
	// see this method's doc comment. job.ID must have actually been
	// issued to THIS session (s.ownJob), never any other session's.
	job, ok := s.ownJob(submit.JobID)
	if !ok {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("unknown or stale job_id: %s", submit.JobID))
		return
	}

	// Real per-job expiry, independent of tip-invalidation (see
	// JobManagerConfig.JobMaxAge's doc comment): a job can still be
	// present in this session's own bounded history yet be too old to
	// accept, e.g. a race right at InvalidateAll's boundary.
	if maxAge := s.server.jobManager.JobMaxAge(); maxAge > 0 {
		if age := time.Since(job.CreatedAt); age > maxAge {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("job expired: job_id %s was issued %s ago (max age %s)", submit.JobID, age.Round(time.Second), maxAge))
			return
		}
	}

	// xn-prefix check happens BEFORE nonce decoding/PoW validation —
	// ported exactly from the legacy ordering and rejection shape, and
	// identical across both algos (see doc comment above). This is a
	// real validity check, NOT the security boundary (see doc comment
	// above).
	if !strings.HasPrefix(strings.ToLower(submit.Nonce), s.xn) {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("Invalid XNonce %v", submit.Nonce))
		return
	}

	nonceBytes, err := hex.DecodeString(submit.Nonce)
	if err != nil || len(nonceBytes) != 8 {
		s.writeShareResponse(req.ID, false, "nonce must be 8 bytes, hex-encoded uint64")
		return
	}

	var (
		nonce uint64
		share *poolpb.Share
	)
	switch job.Algo {
	case poolpb.Algo_ALGO_C29:
		// Real C29 submit wire shape, ported exactly from
		// go-tari-c29-solo-stratum's messages.MinerRPCSubmit: the
		// 42-edge cycle rides in "pow", absent from SHA3X's submit
		// shape entirely.
		if len(submit.POW) != c29SubmitCycleSize {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("pow must carry exactly %d edges for a C29 cycle, got %d", c29SubmitCycleSize, len(submit.POW)))
			return
		}
		// CONFIRMED DIFFERENT FROM SHA3X: C29 decodes its nonce
		// BIG-ENDIAN (go-tari-c29-solo-stratum's miner.go SubmitJob:
		// `nonce := binary.BigEndian.Uint64(b)`), not little-endian.
		nonce = binary.BigEndian.Uint64(nonceBytes)
		share = &poolpb.Share{
			Algo:           poolpb.Algo_ALGO_C29,
			Network:        s.server.network,
			BlockDiff:      safeInt64(job.StaticDifficulty),
			BlockHeight:    int64(job.Height),
			PaymentAddress: s.address.Load().(string),
			Identifier:     s.worker.Load().(string),
			RawProof: &poolpb.Share_C29Proof{
				C29Proof: &poolpb.C29Proof{
					EdgeBits: c29SubmitEdgeBits,
					Cycle:    submit.POW,
					Header:   job.Header,
					Nonce:    nonce,
				},
			},
		}
	default:
		// SHA3X (and, defensively, any legacy/unstamped
		// ALGO_UNSPECIFIED job — matches JobManagerConfig.Algo's own
		// SHA3X-default normalization): unchanged from before C29
		// support existed.
		nonce = binary.LittleEndian.Uint64(nonceBytes)
		share = &poolpb.Share{
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
	}

	if !job.MarkNonceUsed(nonce) {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("duplicate nonce: %s", submit.Nonce))
		return
	}

	v, err := s.server.validators.Get(job.Algo)
	if err != nil {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("no validator configured for this leaf's algo %v: %v", job.Algo, err))
		return
	}

	valid, err := v.Validate(context.Background(), share)
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

	diff, block, err := s.blockCandidate(job, nonce, submit.POW)
	if err != nil {
		// Infrastructure-only failure deriving the real difficulty of
		// an already-validated share (e.g. a zero C29 hash — see
		// validator.C29Difficulty's doc comment); this is not the
		// miner's fault, but there is nothing sound to compare
		// against job.NetworkTargetDifficulty, so reject rather than
		// silently mis-accept/mis-reject a block find.
		s.writeShareResponse(req.ID, false, fmt.Sprintf("difficulty derivation error: %v", err))
		return
	}

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

	// Meets full block difficulty: submit the real, already-constructed
	// candidate block (see blockCandidate above) for real. Mirrors
	// go-tari-sha3x-solo-stratum's SubmitJob (subsystems/poolStratum/
	// miner.go, ~line 493) and go-tari-c29-solo-stratum's equivalent.
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
		// Real block ATTEMPT that failed at the node-submission
		// level — a genuinely different event from an ordinary
		// rejected share (the PoW was valid; distinguish it on
		// leaf_blocks_total, not leaf_shares_total).
		s.server.recordBlock(false)
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
	s.server.recordBlock(true)
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

// blockCandidate computes the real, algo-appropriate difficulty of an
// already-validated share and the real candidate block that would be
// submitted if that difficulty turns out to meet job.NetworkTargetDifficulty
// (handleSubmit decides whether to actually call SubmitBlock with it).
// Building the block unconditionally (not just on the block-find path)
// keeps this the single place nonce/cycle-to-block wiring happens per
// algo, mirroring both reference implementations, which likewise stamp
// job.BlockResult.Block.Header before checking whether the result meets
// full block difficulty.
func (s *Session) blockCandidate(job *Job, nonce uint64, cycle []uint64) (diff uint64, block *tari_generated.Block, err error) {
	switch job.Algo {
	case poolpb.Algo_ALGO_C29:
		diff, err = validator.C29Difficulty(cycle, c29SubmitEdgeBits)
		if err != nil {
			return 0, nil, err
		}
		return diff, cloneBlockWithC29Proof(job.Result.GetBlock(), nonce, cycle), nil
	default:
		diff = validator.SHA3XHeaderDiff(nonce, job.Header)
		return diff, cloneBlockWithNonce(job.Result.GetBlock(), nonce), nil
	}
}

// recordJob records job into this session's own bounded job history
// (jobList/jobLog — see the Session type's SECURITY FIX doc comment),
// making it the ONLY data structure handleSubmit's ownership check
// consults. Called from jobPayload below, which every job-issuing code
// path (handleLogin, pushJob — itself called from handleGetJob,
// vardiff's maybeRetarget, and server.go's invalidateAndRepushJobs) is
// already guaranteed to go through before putting a job on the wire,
// so bookkeeping happens exactly once per real job issuance with no
// separate call needed at each of those call sites.
//
// If job.ID is already present (RestampDifficulty produces a new *Job
// with the SAME ID, just a fresh StaticDifficulty/usedNonces set — see
// job.go's doc comment), the stored pointer is refreshed in place
// without growing jobList, so a restamp doesn't consume a slot in the
// bounded history and submits always see the most recently issued
// version of that job_id.
func (s *Session) recordJob(job *Job) {
	if job == nil {
		return
	}
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if s.jobLog == nil {
		s.jobLog = make(map[string]*Job)
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

// ownJob returns the Job matching id ONLY IF it was actually issued to
// THIS session (recorded via recordJob above) — see the Session type's
// SECURITY FIX doc comment. This is the real, structural security
// boundary handleSubmit gates on: there is no code path by which
// another session's job_id can appear in this map.
func (s *Session) ownJob(id string) (*Job, bool) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	job, ok := s.jobLog[id]
	return job, ok
}

func (s *Session) writeGeneralResponse(id int, errMsg, result string) {
	s.writeJSON(ErrorResponse{ID: id, JsonRPC: "2.0", Error: errMsg, Result: result})
}

func (s *Session) writeShareResponse(id int, accepted bool, errMsg string) {
	// Every submit outcome (share or block, accepted or rejected)
	// flows through this single response-writing helper, so hooking
	// leaf_shares_total here — rather than at each individual
	// rejection call site in handleSubmit — captures every real
	// branch point exactly once, uniformly labeled by result, without
	// touching any of the actual accept/reject decision logic above.
	s.server.recordShare(accepted)
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
//
// SECURITY FIX: this is also the single choke point where job is
// recorded into THIS session's own job history (s.recordJob) — every
// caller (handleLogin's LoginResponse, pushJob's JobPush) already goes
// through jobPayload before putting a job on the wire, so this
// guarantees bookkeeping happens at every point a Session is handed a
// job (login, getjob, vardiff-driven pushes, invalidation-driven
// repushes) without needing a separate recordJob call at each site.
func (s *Session) jobPayload(job *Job) JobPayload {
	s.recordJob(job)
	return JobPayload{
		Algo:   algoWireName(job.Algo),
		Blob:   hex.EncodeToString(job.Header),
		Height: job.Height,
		JobID:  job.ID,
		Target: diffToTargetHex(job.StaticDifficulty),
		XN:     s.xn,
	}
}

// algoWireName maps a Job's stamped poolpb.Algo onto the real wire
// "algo" label real miner software expects — confirmed against both
// reference implementations' MinerJobJSON.Algo: go-tari-sha3x-solo-stratum
// literally hardcodes "sha3x", go-tari-c29-solo-stratum's GetJobJSON sets
// "C29" (mixed case in that repo, but this is a case-insensitive label
// miners key off, not consensus data — lowercased here for consistency
// with the SHA3X label and this package's own login/getjob "algo": []
// string convention, which is already lowercase). ALGO_UNSPECIFIED (a
// legacy/never-should-happen Job) falls back to "sha3x" for defensive
// backward compatibility, matching JobManagerConfig.Algo's own default.
func algoWireName(algo poolpb.Algo) string {
	switch algo {
	case poolpb.Algo_ALGO_C29:
		return "c29"
	default:
		return "sha3x"
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

// cloneBlockWithC29Proof is cloneBlockWithNonce's C29 counterpart: in
// addition to stamping Header.Nonce, it also stamps
// Header.Pow.PowData with the real, edge-packed submitted cycle —
// ported exactly from go-tari-c29-solo-stratum's SubmitJob
// (`job.BlockResult.Block.Header.Pow.PowData = packedData`, where
// packedData is the SAME edgePacking(cycle, 29) output also used for
// the difficulty hash — see validator.C29EdgePacking/C29Difficulty).
// SHA3X has no equivalent supplemental pow_data (see
// tari_generated.ProofOfWork's doc comment: "for Sha3x, this would be
// empty"), which is why cloneBlockWithNonce above doesn't touch
// Header.Pow at all.
func cloneBlockWithC29Proof(block *tari_generated.Block, nonce uint64, cycle []uint64) *tari_generated.Block {
	if block == nil {
		return nil
	}
	blockCopy := proto.Clone(block).(*tari_generated.Block)
	if blockCopy.Header == nil {
		blockCopy.Header = &tari_generated.BlockHeader{}
	}
	blockCopy.Header.Nonce = nonce
	if blockCopy.Header.Pow == nil {
		blockCopy.Header.Pow = &tari_generated.ProofOfWork{}
	}
	blockCopy.Header.Pow.PowData = validator.C29EdgePacking(cycle, c29SubmitEdgeBits)
	return blockCopy
}
