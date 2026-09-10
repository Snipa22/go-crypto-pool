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
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

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
	// agent is the real miner software/version string the miner
	// self-reported at login (LoginRequest.Agent — e.g.
	// "XMRig/6.21.0"), stored verbatim and unvalidated (miner-
	// controlled, diagnostic-only; never used in any accept/reject
	// decision). Empty for a session that has not logged in yet, or
	// whose miner sent no "agent" field.
	agent atomic.Value // string

	// trust is nil unless server.trustConfig.Enabled at newSession
	// time — see trust.go's MinerTrust. Captured once per session
	// (mirroring the real reference's per-Miner, per-connection trust
	// object, which never persists across a reconnect).
	trust *MinerTrust

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
	// jobs is the shared, extracted implementation of the bounded
	// per-session job-ownership history described above
	// (internal/leaflib.JobHistory — see that type's doc comment for
	// the full rationale this ports unchanged, just relocated so
	// internal/leaflib/proxy's own identical bookkeeping — ported
	// there from the start, not re-derived by hand — shares this same
	// real implementation too).
	jobs *leaflib.JobHistory[*Job]

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

	// forcedMinDifficulty is this session's own operator-forced
	// difficulty floor (0 = none), captured from
	// addressflags.Cache.Get at login time (handleLogin below) and
	// never mutated afterward for the lifetime of the connection --
	// a mid-connection ban/floor change takes effect on this miner's
	// NEXT login, not retroactively on an already-established
	// session (mirrors how a vardiff retarget only ever affects this
	// session's own future jobs, never rewrites history). vardiff.go's
	// maybeRetarget reads this on every retarget tick to make sure
	// its own MinDifficulty floor is never allowed to undercut an
	// operator's explicit forced minimum.
	forcedMinDifficulty atomic.Uint64

	// hashesAccumulated is the difficulty-weighted accept-history
	// accumulator (go-tari-sha3x-solo-stratum's minerStruct.hashes):
	// incremented by the job's current StaticDifficulty on every
	// accepted share (see handleSubmit below), never reset for the
	// lifetime of the connection. This is NOT a raw hash count; it is
	// "sum of difficulty values of every share accepted so far",
	// which vardiff.go's computeRetarget divides by connection-time to
	// estimate this session's accepted-share rate.
	hashesAccumulated atomic.Uint64

	// --- BUG FIX (Alex, live production report: "we're sending
	// duplicate jobs down the wire to RXT"): per-session dedup of the
	// last job actually delivered to THIS session ---
	//
	// lastDeliveredJobID/lastDeliveredDifficulty are updated in
	// jobPayload below (the single real choke point every job-issuing
	// call — handleLogin, pushJob's callers handleGetJob/vardiff's
	// maybeRetarget/server.go's invalidateAndRepushJobs — already goes
	// through before putting a job on the wire, per jobPayload's own
	// "SECURITY FIX" doc comment). server.go's invalidateAndRepushJobs
	// consults these to skip re-sending an unsolicited "job" push that
	// is identical to what this session was already handed, because
	// JobManager's cache-invalidation subscription fires on EVERY
	// periodic RefreshInterval tick (default 30s) AND on tip movement,
	// not only when this session's own job genuinely changed.
	//
	// This ports go-tari-sha3x-solo-stratum's real filter for this
	// exact class of redundant push: subsystems/poolStratum/miner.go's
	// checkForNewWork, which runs on a 1s cron but only calls
	// SendNewJob when `tipData.Metadata.BestBlockHeight >
	// m.curJob.BlockResult.Block.Header.Height-1` — i.e. only when the
	// real chain tip has actually advanced past what this specific
	// miner's current job already reflects. It does NOT push on every
	// timer tick unconditionally the way this rewrite's
	// invalidateAndRepushJobs previously did.
	//
	// Tracking BOTH fields (not job.ID alone) matters: job.ID is
	// derived purely from the block hash (see job.go's Job.ID doc
	// comment) and does not depend on difficulty, but the wire
	// "target" field (jobPayload's diffToTargetHex(job.StaticDifficulty))
	// does. A dedup keyed on job.ID alone would silently swallow a
	// legitimate vardiff-driven difficulty/target update that happens
	// to share the same job.ID as the last push (JobForXNAtDifficulty
	// returns the SAME cached Job, unchanged, whenever the underlying
	// per-xn template hasn't been invalidated — see job.go's
	// jobForXN/RestampDifficulty doc comments) — a real target update
	// the miner needs to receive.
	lastDeliveredJobID      atomic.Value // string
	lastDeliveredDifficulty atomic.Uint64
}

// alreadyDelivered reports whether job is identical (same job.ID AND
// same StaticDifficulty) to the last job actually delivered to this
// session via jobPayload — see lastDeliveredJobID's doc comment. Used
// ONLY by server.go's invalidateAndRepushJobs to gate the periodic/
// tip-triggered UNSOLICITED job push; an explicit miner-initiated
// getjob request and a genuine vardiff retarget push both still
// always go through pushJob/jobPayload unconditionally — this dedup
// is deliberately scoped to the one call site that was actually
// producing redundant wire traffic.
func (s *Session) alreadyDelivered(job *Job) bool {
	if job == nil {
		return false
	}
	lastID, _ := s.lastDeliveredJobID.Load().(string)
	return leaflib.AlreadyDelivered(job.ID, job.StaticDifficulty, lastID, s.lastDeliveredDifficulty.Load())
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
	s := &Session{mc: mc, server: server, sessionID: id, xn: xn, connectedAt: time.Now(), jobs: leaflib.NewJobHistory[*Job](defaultSessionJobHistorySize)}
	s.address.Store("")
	s.worker.Store("")
	s.agent.Store("")
	s.currentDifficulty.Store(startingDifficulty)
	if server.trustConfig.Enabled {
		s.trust = NewMinerTrust(server.trustConfig)
	}
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

	// Real, coin-aware payment-address validation (address.go's
	// ValidateAddressForAlgo), dispatched on this leaf's own
	// configured JobManager algo — the same algo every job this
	// leaf produces is stamped with (job.go's Job.Algo). Rejected
	// BEFORE the address is stored/loggedIn is flipped, so an
	// invalid address never becomes this session's payout address
	// for any subsequently-accepted share.
	if err := ValidateAddressForAlgo(s.server.jobManager.Algo(), login.Login); err != nil {
		s.writeGeneralResponse(req.ID, err.Error(), "")
		return
	}

	// REAL enforcement point for the manual ban/forced-minimum-
	// difficulty system (see internal/leaflib/addressflags's package
	// doc comment for the full rationale on why this belongs here,
	// at login time on the leaf, rather than at the backend). Nil
	// s.server.addressFlags (the default -- see EnableAddressFlags'
	// doc comment) means every address is treated as unflagged,
	// identical to this feature not existing at all.
	//
	// Checked and rejected BEFORE the address is stored/loggedIn is
	// flipped and BEFORE any job is fetched -- a banned address never
	// becomes this session's payout address for any purpose, and
	// never receives a job template, exactly mirroring how an invalid
	// address is rejected above.
	var forcedFloor uint64
	if s.server.addressFlags != nil {
		flags := s.server.addressFlags.Get(login.Login)
		if flags.Banned {
			s.server.logger.Printf("solo: rejecting login for banned address %s (session %s)", login.Login, s.sessionID)
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
	// own configured starting difficulty -- an operator explicitly
	// floored this address because the port's default was
	// inappropriate for it (e.g. a known low-power rig previously
	// share-flooding at the port default), so silently starting it
	// below that floor and waiting for vardiff to eventually correct
	// it would defeat the point of the floor being enforced AT LOGIN
	// at all.
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
// for SHA3X and C29 (go-tari-c29-solo-stratum's SubmitJob has the
// exact same xn-prefix check on the exact same hex-STRING
// representation of the nonce, before decoding it) — but it is no
// longer the security boundary; it now runs AFTER session-ownership
// has already been confirmed. This is purely wire-level/session
// bookkeeping: verified against the real hash math in
// validator/sha3x.go (sha3xHeaderDiff/GetHeaderDiff) that the full
// 8-byte nonce is used directly as hash pre-image material with no
// separate xn encoding — xn is a leading-byte convention miners are
// expected to respect on their nonce composition, not something baked
// into the hash function itself, so no change to SHA3XValidator (or
// C29Validator) was needed or made. DOES enforce per-job used-nonce
// tracking via Job.MarkNonceUsed, which the previous wire format's
// implementation never had.
//
// RXT IS EXEMPT from the xn-prefix check (bug fix): RXT's own real
// nonce handling (see rxt.go/createTariMiningBlob and the real Tari
// Rust source) treats the full 8-byte big-endian nonce as one opaque
// value with no xn hex-prefix partitioning convention — unlike
// SHA3X/C29, RXT miners were never asked to respect an xn leading-byte
// convention on their nonce composition, so requiring one here was an
// unconditional carry-over from when this check was written
// SHA3X/C29-only, predating RXT support, and incorrectly rejected
// every otherwise-valid RXT submit with "Invalid XNonce". The check
// below is now algo-conditional and skipped for ALGO_RXT.
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

	// REAL ban re-check at submit time, not just login time (Alex's
	// explicit follow-up instruction: a session can log in before an
	// address is banned, or the ban flag can be set mid-session by
	// an operator responding to real-time abuse — login-time-only
	// enforcement would let an already-connected botnet keep
	// submitting shares indefinitely after being banned). Checked
	// against the address ACTUALLY stored on this session
	// (s.address), not whatever the miner claims now — mirrors
	// handleLogin's own real enforcement point exactly, just at the
	// other end of the session's lifetime. Cheap: this runs before
	// any real PoW validation work, so a banned miner's shares are
	// rejected as early as the job-ownership/expiry checks above.
	if s.server.addressFlags != nil {
		if flags := s.server.addressFlags.Get(s.address.Load().(string)); flags.Banned {
			s.server.logger.Printf("solo: rejecting submit for now-banned address %s (session %s)", s.address.Load(), s.sessionID)
			s.writeShareResponse(req.ID, false, "this address is banned from this pool")
			return
		}
	}

	// xn-prefix check happens BEFORE nonce decoding/PoW validation —
	// ported exactly from the legacy ordering and rejection shape, and
	// applies to SHA3X and C29 only, NOT RXT (see doc comment above:
	// RXT never uses xn nonce partitioning by design). This is a real
	// validity check, NOT the security boundary (see doc comment
	// above).
	// ALGO_RXM (Monero) is exempted from the xn-prefix check for the
	// same reason as ALGO_RXT (see doc comment above): a real
	// Monero-family miner (xmrig, etc.) treats the full nonce field as
	// one opaque value it controls end-to-end, with no xn hex-prefix
	// partitioning convention on this leaf's wire protocol.
	if job.Algo != poolpb.Algo_ALGO_RXT && job.Algo != poolpb.Algo_ALGO_RXM {
		if !strings.HasPrefix(strings.ToLower(submit.Nonce), s.xn) {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("Invalid XNonce %v", submit.Nonce))
			return
		}
	}

	// Nonce length is algo-conditional: SHA3X/C29/RXT genuinely use
	// an 8-byte (16 hex char) nonce and keep the strict gate below.
	// ALGO_RXM (Monero-family RandomX) is DIFFERENT — confirmed from
	// a real production packet capture against the live public RXM
	// leaf-solo instance (148.163.90.157:4450): a real xmrig client
	// sends a genuine 4-byte (8 hex char) nonce, matching Monero's
	// actual 32-bit block-header nonce field. A blanket 8-byte gate
	// applied to every algo was rejecting every real RXM submit.
	// RXM accepts either 4 bytes (the correct, expected width for a
	// real Monero-family miner) or 8 bytes (lenient tolerance, in
	// case some other RXM-speaking client zero-pads it) — both are
	// decoded down to the same low-32-bit uint64 that
	// MoneroHashingBlobForSubmit actually consumes (it only ever
	// patches uint32(nonce) into the hashing blob), so accepting
	// either width is safe and doesn't change block-candidate
	// behavior for a compliant client.
	// RXT nonce length: FIX — a real, unmodified XMRig client patches
	// its own search nonce as a raw 4-byte value at a fixed byte
	// offset (rxt.go's rxtXmrigNonceOffset/rxtXmrigNonceSize, = 39/4
	// — confirmed from XMRig's actual Job::nonceOffset()/nonceSize()
	// source, the generic RandomX-family default case) for EVERY
	// "rx/0" job, RXT included — there is no coin-specific variant on
	// the client side. RXT must therefore accept the same 4-byte
	// (lenient: or 8-byte) nonce width ALGO_RXM already does, not the
	// strict 8-byte gate every other algo keeps.
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
		// Real Monero submit wire shape: no "pow" field (C29-only);
		// the miner's claimed RandomX result hash rides in the
		// existing generic "result" field (submit.Result), matching
		// RXT's own convention. Nonce is decoded LITTLE-ENDIAN,
		// matching MoneroNodeClient.BuildCandidateBlock's own
		// binary.LittleEndian.PutUint32 write of the low 4 bytes into
		// the real block header nonce field (monero_node.go) — the
		// low 32 bits of this uint64 are what actually end up in the
		// block; a miner must send them little-endian for the wire
		// nonce to round-trip to the same 4 bytes BuildCandidateBlock
		// patches in. A real xmrig client sends exactly these 4
		// bytes (see doc comment on the length gate above); an
		// 8-byte submit is decoded the same way for backward
		// tolerance.
		if len(nonceBytes) == 4 {
			nonce = uint64(binary.LittleEndian.Uint32(nonceBytes))
		} else {
			nonce = binary.LittleEndian.Uint64(nonceBytes)
		}
		if submit.Result == "" {
			s.writeShareResponse(req.ID, false, "monero (rxm) submit requires a claimed result hash in \"result\"")
			return
		}
		// XNP-PROXY SUBMIT FIX: a real XNP-class multi-tier proxy
		// submit carries workerNonce/poolNonce params (protocol.go's
		// SubmitRequest.WorkerNonce/PoolNonce doc comment has the
		// full real-wire citation) that MUST be patched into the raw
		// template before re-deriving the verification hashing blob
		// — MoneroHashingBlobForSubmit alone only ever patches the
		// plain nonce into the ALREADY-CONVERTED hashing blob, so a
		// proxy's real worker/pool nonce patches were silently
		// dropped, guaranteeing a hash mismatch (and therefore a
		// reject) on every single submit from that client class. The
		// mere PRESENCE of both wire fields is the real, sufficient
		// signal here (an ordinary xmrig-class client has no code
		// path that would ever send them) — this is deliberately NOT
		// additionally gated on IsXNPProxyAgent(agent): requiring
		// both conditions would risk a genuinely proxy-shaped client
		// whose login agent string doesn't happen to match that
		// substring check still getting silently mis-handled.
		var (
			blob    []byte
			blobErr error
		)
		if submit.WorkerNonce != nil && submit.PoolNonce != nil {
			blob, blobErr = MoneroHashingBlobForXNPSubmit(job, nonce, *submit.WorkerNonce, *submit.PoolNonce)
		} else {
			blob, blobErr = MoneroHashingBlobForSubmit(job, nonce)
		}
		if blobErr != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("failed to build monero randomx verification blob: %v", blobErr))
			return
		}
		share = &poolpb.Share{
			Algo:           poolpb.Algo_ALGO_RXM,
			Network:        s.server.network,
			BlockDiff:      safeInt64(job.StaticDifficulty),
			BlockHeight:    int64(job.Height),
			PaymentAddress: s.address.Load().(string),
			Identifier:     s.worker.Load().(string),
			RawProof: &poolpb.Share_RandomxProof{
				RandomxProof: &poolpb.RandomXProof{
					Blob:      blob,
					SeedHash:  job.VmKey,
					ResultHex: submit.Result,
				},
			},
		}
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
	case poolpb.Algo_ALGO_RXT:
		// Real RXT (Tari's OWN native RandomX PoW — NOT merge-mining
		// RXM) submit wire shape: no "pow" field (that's C29-only);
		// the miner's claimed RandomX result hash rides in the
		// existing generic "result" field (submit.Result).
		//
		// NONCE RECONSTRUCTION FIX: a real, unmodified XMRig client
		// does NOT patch/report an 8-byte big-endian value at
		// createTariMiningBlob's own nonce field start (offset 35)
		// — it patches a raw 4-byte value at the fixed, hardcoded
		// offset 39 (rxt.go's rxtXmrigNonceOffset — confirmed from
		// XMRig's actual Job::nonceOffset() source, the generic
		// RandomX-family default case) and reports back exactly
		// those raw bytes, unmodified, as submit.Nonce. Offset 39 is
		// the low-order 4 bytes of createTariMiningBlob's 8-byte
		// nonce field [35:43) — decoding the reported 4 raw bytes as
		// a big-endian uint32 and zero-extending to uint64
		// reconstructs a nonce value whose to_be_bytes() (via
		// createTariMiningBlob below) reproduces bytes [35:39)=0,
		// [39:43)=the SAME 4 raw bytes the miner actually hashed —
		// i.e. byte-for-byte the same blob XMRig computed its
		// RandomX hash against. A legacy/lenient 8-byte submit
		// (e.g. from a hypothetical Tari-native-aware client that
		// patches the full field per createTariMiningBlob's own
		// semantic) is still accepted and decoded directly.
		if len(nonceBytes) == 4 {
			nonce = uint64(binary.BigEndian.Uint32(nonceBytes))
		} else {
			nonce = binary.BigEndian.Uint64(nonceBytes)
		}

		if submit.Result == "" {
			s.writeShareResponse(req.ID, false, "rxt submit requires a claimed result hash in \"result\"")
			return
		}

		// Build the real 76-byte Tari mining blob (rxt.go's
		// createTariMiningBlob, ported byte-for-byte from the real
		// Tari Rust create_tari_mining_blob) from THIS job's own
		// mining-hash material and pow_data, and the submitted nonce.
		// TariPowDataFromJob (node.go) is the explicitly-named escape
		// hatch for reaching into job.TemplateData's real Tari pow_data
		// — RXT's own blob format is genuinely Tari-protocol-specific
		// and isn't part of the coin-agnostic Job/NodeClient shell.
		powData := TariPowDataFromJob(job)
		blob := createTariMiningBlob(job.Header, nonce, rxtPowAlgoByte, powData)

		share = &poolpb.Share{
			Algo:           poolpb.Algo_ALGO_RXT,
			Network:        s.server.network,
			BlockDiff:      safeInt64(job.StaticDifficulty),
			BlockHeight:    int64(job.Height),
			PaymentAddress: s.address.Load().(string),
			Identifier:     s.worker.Load().(string),
			RawProof: &poolpb.Share_RandomxProof{
				RandomxProof: &poolpb.RandomXProof{
					Blob:      blob,
					SeedHash:  job.VmKey,
					ResultHex: submit.Result,
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

	// PERFORMANCE FIX (Alex, live production incident, 2026-08-30): the
	// rest of this method — real validator dispatch, accept/reject
	// bookkeeping, block-candidate construction/submission, and the
	// wire response — used to run inline, right here, in Session.Run's
	// read loop. For SHA3X/C29 (validator.SHA3XValidator/C29Validator)
	// that is a cheap, in-process CPU hash and stays exactly that way
	// below. For ALGO_RXT/ALGO_RXM, validator.RandomXValidator.Validate
	// makes a REAL, SYNCHRONOUS HTTP round-trip to an external
	// randomx-service daemon for every submitted share — confirmed via a
	// live timing test at ~4ms+ per call even under light load. Running
	// that inline blocked scanner.Scan() from ever reading the miner's
	// NEXT submitted line until this one's HTTP round-trip finished, so
	// the pool could only drain one RandomX-family share per connection
	// every ~4ms+, sequentially — far slower than a real miner submits.
	// CONFIRMED VIA REAL WIRE CAPTURE against the live public RXM leaf
	// (148.163.90.157:4450): a real xmrig client's own submit request ids
	// climbed into the thousands (id:8454, id:8458, ...) while the pool's
	// most recently WRITTEN response was still echoing id:6127 — a
	// growing, unbounded backlog that eventually caused a client-side
	// write failure and full miner disconnect, recurring roughly every
	// ~30s under sustained real load.
	//
	// finishSubmit captures everything from here to the end of this
	// method in one closure so it can be run either INLINE (SHA3X/C29,
	// unchanged behavior) or dispatched to asyncvalidation.go's bounded,
	// server-wide worker pool (RXT/RXM — see the dispatch below).
	//
	// RESPONSE-ORDERING NOTE (verified against the real xmrig source,
	// github.com/xmrig/xmrig, src/base/net/stratum/Client.cpp): a real
	// xmrig client matches a submit's response to its own request purely
	// by the numeric JSON "id" field — `Client::submit` stores each
	// outgoing submit's sequence id in `m_results[m_sequence]` (a real
	// id-keyed map) BEFORE sending, and `Client::send(id, callback)`
	// stores any registered callback in `m_callbacks` keyed the same
	// way; `parseResponse(int64_t id, ...)` looks the id up in those maps
	// to dispatch the response — there is no ordering assumption anywhere
	// in that path. Concurrent RandomX-family validations therefore do
	// NOT need to be serialized back into submission order before being
	// written to the wire: each finishSubmit closure calls
	// writeShareResponse(req.ID, ...) with ITS OWN captured req.ID
	// regardless of when it happens to complete relative to any other
	// in-flight submit on the same session, and mc.Write (connection.go)
	// already guarantees no interleaving/corruption between concurrent
	// writers — the response for a later-submitted-but-faster-to-validate
	// share is allowed to reach the wire before an earlier submit's
	// still-pending response, and a real xmrig client resolves that
	// correctly by id, not arrival order. (See
	// TestSessionRandomXConcurrentSubmitsRespondByOwnID in
	// session_async_randomx_test.go, which asserts exactly this.)
	//
	// RACE-SAFETY NOTE: every piece of per-session/per-job mutable state
	// finishSubmit touches is already safe under genuine concurrent
	// execution from multiple in-flight validations for the SAME
	// session, independently of this dispatch change: job.MarkNonceUsed
	// (above, always run synchronously in the read loop, before
	// dispatch — its own nonceMu makes it safe regardless) already ran;
	// s.shareCount/s.blockCount/s.hashesAccumulated are atomic.Uint64;
	// s.trust (MinerTrust) documents itself as "safe for concurrent use"
	// and has its own internal mutex; s.server.node.BuildCandidateBlock
	// only READS job fields and returns a fresh proto.Clone'd candidate
	// (node.go/monero_node.go — never mutates the shared job template);
	// s.mc.Write is already synchronized onto the connection's single
	// writer goroutine (connection.go). Nothing here needed a NEW lock —
	// it was already race-safe by construction, just previously
	// single-threaded by the caller.
	finishSubmit := func() {
		v, err := s.server.validators.Get(job.Algo)
		if err != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("no validator configured for this leaf's algo %v: %v", job.Algo, err))
			return
		}

		// Real, legacy-ported trusted-miner validation skip (see
		// trust.go) — only ever considered for RXT/RXM, the two
		// RandomX-family algos where full validation is a real,
		// service-backed RandomX hash genuinely expensive to compute at
		// scale; SHA3X/C29 are cheap local computation with no analogous
		// mechanism in the reference and are always fully validated
		// regardless of s.trust. ShouldSkipValidation itself already
		// returns false for a nil/disabled s.trust, so this is safe to
		// call unconditionally.
		var valid bool
		skipped := IsRandomXFamily(job.Algo) && s.trust.ShouldSkipValidation()
		if skipped {
			// Trusted share: the miner's own claimed result is taken on
			// faith, no real RandomX hash is computed — ported exactly
			// from the reference's `hash = new Buffer(resultHash, 'hex')`
			// branch (see trust.go's doc comment). This is, by
			// definition, "valid" for the purpose of crediting the share;
			// RecordOutcome below is still called with the real,
			// eventual accept/reject outcome once BuildCandidateBlock's
			// own difficulty check runs against the miner's claimed
			// result, exactly like the reference calls handleMinerData
			// unconditionally regardless of which processShare branch
			// ran.
			valid = true
		} else {
			valid, err = v.Validate(context.Background(), share)
			if err != nil && err != validator.ErrWrongProofType {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("validation error: %v", err))
				return
			}
		}
		if !valid {
			if IsRandomXFamily(job.Algo) {
				s.trust.RecordOutcome(false)
			}
			s.writeShareResponse(req.ID, false, "share does not meet configured difficulty or is cryptographically invalid")
			return
		}
		if IsRandomXFamily(job.Algo) {
			s.trust.RecordOutcome(true)
		}

		// Valid share (met the configured static share difficulty). This is
		// local diagnostic/hashrate-estimation signal only — solo mode has
		// no share table and no backend to forward it to.
		s.shareCount.Add(1)

		diff, candidate, err := s.server.node.BuildCandidateBlock(job, nonce, SubmitProof{Cycle: submit.POW, ResultHex: submit.Result})
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
		// candidate block (see NodeClient.BuildCandidateBlock above) for
		// real. Mirrors go-tari-sha3x-solo-stratum's SubmitJob
		// (subsystems/poolStratum/miner.go, ~line 493) and
		// go-tari-c29-solo-stratum's equivalent.
		err = s.server.node.SubmitBlock(context.Background(), candidate)
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

	// DISPATCH: only RXT/RXM (the two algos whose validator makes a real
	// network round-trip — see asyncvalidation.go's doc comment) go
	// through the bounded async pool. SHA3X/C29 keep running finishSubmit
	// INLINE, synchronously, in the read loop exactly as before this
	// fix — a deliberate choice, not an oversight: their validators
	// (SHA3XValidator/C29Validator) are cheap in-process CPU hashes with
	// no analogous network-latency bottleneck, so there is no throughput
	// problem to fix for them, and keeping their code path completely
	// unchanged eliminates any regression risk to already-working
	// behavior for a benefit (a handful of microseconds of dispatch
	// overhead) that doesn't exist for them.
	if IsRandomXFamily(job.Algo) {
		if ok := s.server.randomxPool.Submit(finishSubmit); !ok {
			// Pool already stopped (server shutting down) — respond
			// with a real rejection rather than leaving this submit
			// unanswered (task constraint: "no orphaned unresolved
			// submits"). This is not a cryptographic rejection of the
			// miner's share; a reconnect against a fresh instance will
			// process it normally.
			s.writeShareResponse(req.ID, false, "pool is shutting down, please reconnect")
		}
		return
	}
	finishSubmit()
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
	s.jobs.Record(job.ID, job)
}

// ownJob returns the Job matching id ONLY IF it was actually issued to
// THIS session (recorded via recordJob above) — see the Session type's
// SECURITY FIX doc comment. This is the real, structural security
// boundary handleSubmit gates on: there is no code path by which
// another session's job_id can appear in this map.
func (s *Session) ownJob(id string) (*Job, bool) {
	return s.jobs.Own(id)
}

// writeGeneralResponse and writeShareResponse now delegate the actual
// algo-conditional wire-shape dispatch to
// leaflib.WriteGeneralResponse/WriteShareResponse (see leaflib/
// wireshape.go's doc comment for the full rationale: this exact logic
// used to be hand-copied between this file and direct/session.go's
// own identical methods, and is the real cause of the repeated
// wire-shape production incidents this dispatch's DISPATCH_BRIEF
// cites — see commits b3c8716, 0339d81, 0253b57).
func (s *Session) writeGeneralResponse(id int, errMsg, result string) {
	leaflib.WriteGeneralResponse(s.writeJSON, leaflib.IsLegacyWireAlgo(s.server.jobManager.Algo()), id, errMsg, result)
}

func (s *Session) writeShareResponse(id int, accepted bool, errMsg string) {
	// Every submit outcome (share or block, accepted or rejected)
	// flows through this single response-writing helper, so hooking
	// leaf_shares_total here — rather than at each individual
	// rejection call site in handleSubmit — captures every real
	// branch point exactly once, uniformly labeled by result, without
	// touching any of the actual accept/reject decision logic above.
	s.server.recordShare(accepted)
	leaflib.WriteShareResponse(s.writeJSON, leaflib.IsLegacyWireAlgo(s.server.jobManager.Algo()), id, accepted, errMsg)
}

func (s *Session) writeJSON(v any) {
	leaflib.WriteJSON(s.mc, s.server.logger, "solo", s.sessionID, v)
}

// pushJob sends an unsolicited real "job" push (protocol.go's JobPush)
// for a newly-(re)generated Job specific to this session's own xn —
// delegating the actual "only push to a logged-in session" gate to
// leaflib.PushJob (see that function's doc comment).
func (s *Session) pushJob(job *Job) {
	leaflib.PushJob(s.writeJSON, s.loggedIn.Load(), func() any { return s.jobPayload(job) })
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
	// Record what was actually delivered, for invalidateAndRepushJobs'
	// dedup check (see lastDeliveredJobID's doc comment) — every
	// caller of jobPayload is putting job on the wire to THIS session
	// right now, so this is the single correct place to update it.
	s.lastDeliveredJobID.Store(job.ID)
	s.lastDeliveredDifficulty.Store(job.StaticDifficulty)
	payload := JobPayload{
		Algo:   algoWireName(job.Algo),
		Blob:   hex.EncodeToString(job.Header),
		Height: job.Height,
		JobID:  job.ID,
		Target: diffToTargetHex(job.StaticDifficulty),
	}
	// RXT-only (bug fix): job.Header for an ALGO_RXT job is the bare
	// 32-byte Tari merge-mining hash, NOT a minable blob — real
	// RandomX-family miner software (XMRig et al.) requires a real,
	// correctly-shaped 76-byte mining blob to patch its own nonce
	// into and hash directly (matching Monero's own real client
	// convention, which ALGO_RXM already correctly satisfies here
	// via a full pre-built hashing blob in job.Header — see
	// monero_node.go). Confirmed via a live production packet
	// capture against 148.163.90.157:4447 (RXT, this leaf) and
	// :4450 (RXM, same leaf family, working): after the wire "algo"
	// label was already fixed to "rx/0", XMRig 6.25.0 accepted the
	// RXT job but produced zero valid shares because its "blob" was
	// only 64 hex chars (32 bytes) versus RXM's working 152 hex
	// chars (76 bytes) — the bare hash is not a minable blob a real
	// RandomX client can parse.
	//
	// Built via the SAME real createTariMiningBlob helper
	// (rxt.go) already used server-side at submit time to
	// re-verify a miner's claimed nonce, with nonce=0 as a
	// placeholder: byte offset 39 (rxtXmrigNonceOffset, see its doc
	// comment) — where a stock XMRig patches its own 4-byte search
	// nonce for any generic RandomX-family job — falls squarely
	// inside this blob's own 8-byte nonce field [35:43), so a
	// nonce=0 placeholder here correctly leaves that exact region
	// ready for XMRig to overwrite. rxtPowAlgoByte/TariPowDataFromJob
	// are the same real, already-existing symbols this file's own
	// handleSubmit ALGO_RXT case already uses to build the
	// SAME-SHAPED blob for verification — reused here, not
	// reimplemented.
	if job.Algo == poolpb.Algo_ALGO_RXT {
		blob := createTariMiningBlob(job.Header, 0, rxtPowAlgoByte, TariPowDataFromJob(job))
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
	// RXT-only: surface the real RandomX seed/key (job.go's Job.VmKey,
	// taken directly from GetNewBlockResult.VmKey) as the wire
	// "seed_hash" field — mirrors XMRig's own stratum job-JSON
	// convention for RandomX-family coins. SHA3X/C29 jobs have no
	// VmKey, so this is simply omitted (omitempty) for them.
	if (job.Algo == poolpb.Algo_ALGO_RXT || job.Algo == poolpb.Algo_ALGO_RXM) && len(job.VmKey) > 0 {
		payload.SeedHash = hex.EncodeToString(job.VmKey)
	}
	// XNP-PROXY SHAPE (see protocol.go's JobPayload doc comment for
	// the full field-by-field provenance from the real nodejs-pool-
	// sxmr reference): a login whose self-reported agent string
	// identifies it as an XNP-class multi-tier proxy
	// (IsXNPProxyAgent — real reference gate:
	// `agent.includes('xmr-node-proxy')`, lib/pool.js ~211-231)
	// additionally gets the raw-template-blob + reservation-offset
	// fields below, ADDITIONALLY alongside every field already set
	// above, not as a replacement — leaving the already-correct
	// Blob/Target/etc. fields on the wire too is safe and prioritizes
	// "the proxy client gets everything it needs" over exact
	// key-set parity with the JS reference (see JobPayload's doc
	// comment).
	//
	// NON-REGRESSION: for every OTHER agent (the overwhelming
	// majority of real logins — xmrig et al.), and for every
	// non-RXM/RXT algo regardless of agent, this whole block is
	// skipped (either the IsXNPProxyAgent check or the inner algo
	// switch's default no-op), so all four pointer fields stay nil
	// and are omitted from the wire (omitempty) — see
	// protocol_xnp_test.go for a real marshaled-JSON byte-diff
	// proving this holds both for SHA3X/C29 jobs and for RXM/RXT
	// jobs served to a non-proxy agent.
	if IsXNPProxyAgent(s.agent.Load().(string)) {
		switch job.Algo {
		case poolpb.Algo_ALGO_RXM:
			// RXM: the raw, unconverted monerod blocktemplate_blob
			// (job.go's Job.RawTemplateBlob — kept deliberately
			// separate from job.Header/payload.Blob, which is
			// already the CONVERTED blockhashing_blob every
			// ordinary miner needs; see that field's doc comment)
			// plus the real monerod reserved_offset and its two
			// derived client_nonce_offset/client_pool_offset byte
			// offsets (real nodejs-pool-sxmr lib/coins/xmr.js
			// ~137-152: client_nonce_offset = reserved_offset+12,
			// client_pool_offset = reserved_offset+8). Do NOT
			// convert/patch this blob server-side — the receiving
			// XNP-class proxy does its own raw-blob-to-hashing-blob
			// conversion downstream, exactly mirroring this repo's
			// own leaf-proxy/upstream.go applyJob on the OTHER end
			// of this same real convention.
			// BOUNDS-CHECK GATE (real production bug fix -- see
			// job.go's Job.ReservedOffsetUsable doc comment and
			// monero_node.go's GetBlockTemplate for the full
			// rationale and live-reproduction evidence: a real
			// leaf-proxy rejection, "offset=179 blob_len=76", against
			// a genuine low-tx-volume testnet block). When monerod's
			// real reserved_offset does not fit within its own
			// returned blocktemplate_blob for THIS job,
			// ReservedOffsetUsable is false and this whole branch is
			// skipped, leaving all four pointer fields nil/omitted --
			// exactly the same "nil means not offered" degradation
			// this switch already uses for RXT's ReservedOffset/
			// ClientPoolOffset below, not a parallel signaling
			// mechanism.
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
			// RXT INVESTIGATION FINDING (see rxt.go's
			// createTariMiningBlob/rxtXmrigNonceOffset doc comments
			// and the real Tari GRPC GetNewBlockResult/MinerData
			// shapes): Tari's protocol has NO real analog of
			// Monero's reserve_size/coinbase-tx-reservation
			// mechanism — no reserved coinbase-extra byte range is
			// ever returned by the Tari base node. The RXT mining
			// blob already built above (createTariMiningBlob(
			// job.Header, 0, rxtPowAlgoByte, ...)) already IS the
			// final, raw, complete, self-contained 76-byte blob;
			// there is no separate "template vs hashing blob"
			// distinction the way Monero has. Given that:
			//   - ClientNonceOffset IS set, to the real, meaningful,
			//     already-existing rxtXmrigNonceOffset constant
			//     (39) — this genuinely is the one real byte offset
			//     a multi-tier RXT proxy would need to patch a
			//     sub-miner's nonce into before forwarding.
			//   - ReservedOffset/ClientPoolOffset are deliberately
			//     left nil: inventing values for a reservation
			//     concept that does not exist in Tari's protocol
			//     would be dishonest, not just harmlessly redundant.
			//   - BlocktemplateBlob is set to the SAME hex value as
			//     Blob (payload.Blob, already computed above) —
			//     numerically identical because RXT, unlike RXM,
			//     has no raw-template/hashing-blob distinction;
			//     included only for shape-parity with the RXM proxy
			//     convention, not because a real distinct raw blob
			//     exists.
			blobHex := payload.Blob
			clientNonceOffset := rxtXmrigNonceOffset
			payload.BlocktemplateBlob = &blobHex
			payload.ClientNonceOffset = &clientNonceOffset
		}
	}
	return payload
}

// algoWireName, diffToTargetHex, safeInt64, cloneBlockWithNonce, and
// cloneBlockWithC29Proof are now thin wrappers over
// internal/leaflib's identically named exported symbols (EXTRACTED
// there so internal/leaflib/direct — which used to hand-derive a
// byte-for-byte duplicate of every one of these in its own
// wireutil.go — can reuse the exact same real implementations; see
// leaflib/wireutil.go's doc comment for the full rationale). See
// each leaflib function's own doc comment for the full ported
// provenance; unchanged behavior, just relocated.
func algoWireName(algo poolpb.Algo) string {
	return leaflib.AlgoWireName(algo)
}

func diffToTargetHex(difficulty uint64) string {
	return leaflib.DiffToTargetHex(difficulty)
}

func safeInt64(v uint64) int64 {
	return leaflib.SafeInt64(v)
}

func cloneBlockWithNonce(block *tari_generated.Block, nonce uint64) *tari_generated.Block {
	return leaflib.CloneBlockWithNonce(block, nonce)
}

// cloneBlockWithC29Proof delegates to leaflib.CloneBlockWithC29Proof,
// passing this package's own c29SubmitEdgeBits constant and
// validator.C29EdgePacking explicitly (leaflib's version is
// parameterized on both, matching internal/leaflib/direct's own
// pre-extraction call shape exactly, since leaflib cannot import this
// package's unexported c29SubmitEdgeBits constant directly).
func cloneBlockWithC29Proof(block *tari_generated.Block, nonce uint64, cycle []uint64) *tari_generated.Block {
	return leaflib.CloneBlockWithC29Proof(block, nonce, cycle, c29SubmitEdgeBits, validator.C29EdgePacking)
}
