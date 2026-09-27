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

	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
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

	// paymentID is the genuine Monero payment ID this session's miner
	// supplied as a 64-lowercase-hex second dot-segment of its login
	// field (loginfields.go's ParseLoginFields / LoginFields.PaymentID)
	// -- Monero-family algos only, empty otherwise and empty whenever
	// the miner supplied none.
	//
	// KNOWN, DELIBERATE GAP (leaf-solo only): solo mode has no share
	// table, no backend to forward to, and no payout accounting at all
	// (see cmd/leaf-solo's own doc comment and shareCount's below) --
	// a share only matters here as a hashrate-estimation signal. There
	// is therefore NO real downstream path in THIS leaf mode to carry
	// a payment ID to, so this field is captured and stored for
	// diagnostic/parity purposes and nothing more, rather than
	// half-wiring new payout plumbing solo mode does not have.
	// leaf-direct, which genuinely does forward every share to the
	// backend, stamps its own identical field onto
	// poolpb.Share.PaymentId for real (see direct/session.go) -- that
	// is where the real end-to-end payment-ID plumbing
	// (backend/api.go -> db.Share.PaymentID -> balance/
	// miner_identifiers, plus legacytransport's own legacy-wire
	// mapping) actually lives.
	paymentID atomic.Value // string

	// fixedDiff reports whether this session requested (or was
	// assigned) a FIXED difficulty at login -- legacy's
	// `this.fixed_diff` (nodejs-pool-sxmr lib/pool.js lines
	// 389/393/403), set either by a valid "<address>+<difficulty>"
	// login-field suffix or by a NiceHash agent string on a
	// Monero-family algo (see loginfields.go's ParseLoginFields).
	//
	// Written exactly once, in handleLogin, before this session's own
	// vardiff goroutine is started (server.go's handleConn issues `go
	// session.runVardiffLoop(...)` only after newSession/the read loop
	// are set up); vardiff.go's maybeRetarget reads it on every tick
	// and returns immediately when set, so a fixed-difficulty session
	// is never retargeted away from its requested value for the
	// lifetime of the connection. That mirrors the legacy retarget
	// loop's own real gating check verbatim (pool.js lines 227-236):
	//
	//	function retargetMiners() {
	//	    ...
	//	    if (!miner.fixed_diff || (miner.fixed_diff && proxyAddressList.indexOf(miner.payout) !== -1)) {
	//	        miner.updateDifficulty();
	//	    }
	//	}
	//
	// The legacy `proxyAddressList` escape hatch (an xmr-node-proxy
	// aggregator logs in with a fixed diff but still needs its
	// downstream-aggregate difficulty retargeted) DOES now have an
	// equivalent here, implemented in terms of this leaf's own
	// agent-string XNP detection rather than legacy's
	// operator-maintained proxy-payout-address allowlist (this leaf has
	// no such registry at all) -- see
	// LoginFields.XNPProxyExemptFromFixedDiffPin (loginfields.go) for
	// the full citation and mechanism-divergence rationale, and
	// handleLogin below for the single call site that applies it. For
	// an XNP-proxy-detected session, the operator's requested
	// "+<difficulty>" value is still used as this session's STARTING
	// difficulty -- only the permanent PIN is withheld, so normal
	// vardiff retargeting proceeds from there exactly as it would for
	// any ordinary non-fixed-difficulty session. Every other session,
	// XNP-undetected, is pinned exactly as the plain `!fixed_diff`
	// half of the legacy gate above prescribes.
	fixedDiff atomic.Bool

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

	// invalidShareGuard tracks this session's own running count of
	// CONSECUTIVE real-validation failures for RXT/RXM block-find
	// candidates (finishSubmit's `!valid` branch) and reports once a
	// configurable threshold is reached — see
	// leaflib.InvalidShareGuard's own doc comment for the full
	// DoS-mitigation rationale (DISPATCH_BRIEF.md, 2026-09-10, Fix
	// 2b). Constructed once per session, at newSession time, from
	// server.invalidShareGuardConfig; nil-safe (see
	// InvalidShareGuard.RecordOutcome) so this field is never nil in
	// practice but would be harmless if it somehow were.
	invalidShareGuard *leaflib.InvalidShareGuard
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
	s.paymentID.Store("")
	s.currentDifficulty.Store(startingDifficulty)
	s.invalidShareGuard = leaflib.NewInvalidShareGuard(server.invalidShareGuardConfig)
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
// loop).
//
// BUG FIX: this handler used to pass login.Login -- the RAW,
// UNSTRIPPED string the miner sent -- straight into
// ValidateAddressForAlgo, so a miner using the completely standard
// "<address>+<fixed_diff>" or "<address>.<workername_or_paymentid>"
// Monero-family stratum convention was rejected outright as having a
// malformed address. It now parses those real suffixes first
// (loginfields.go's ParseLoginFields, a faithful port of the legacy
// nodejs-pool-sxmr parse -- see that function's doc comment for the
// verbatim source citation and for every scoping decision) and hands
// ONLY the stripped address to the validator.
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

	// Real login-field parse (address / "+"-fixed-difficulty /
	// ".paymentID" / ".identifier") BEFORE any address validation --
	// see this method's own doc comment and loginfields.go. The
	// clamp bounds are this leaf's OWN already-configured
	// -min-difficulty/-max-difficulty values, reached through the
	// (already Normalized, see NewServer) VardiffConfig every retarget
	// on this session is clamped to as well.
	loginFields, err := ParseLoginFields(
		s.server.jobManager.Algo(),
		login.Login,
		login.Agent,
		s.currentDifficulty.Load(),
		s.server.vardiff.MinDifficulty,
		s.server.vardiff.MaxDifficulty,
	)
	if err != nil {
		s.writeGeneralResponse(req.ID, err.Error(), "")
		return
	}

	// Real, coin-aware payment-address validation (address.go's
	// ValidateAddressForAlgo), dispatched on this leaf's own
	// configured JobManager algo — the same algo every job this
	// leaf produces is stamped with (job.go's Job.Algo). Rejected
	// BEFORE the address is stored/loggedIn is flipped, so an
	// invalid address never becomes this session's payout address
	// for any subsequently-accepted share.
	//
	// NOTE (the actual fix): loginFields.Address -- the STRIPPED
	// address -- is what goes in here, never the raw login.Login the
	// miner actually sent, and every downstream use of the miner's
	// address in this handler (ban/forced-floor lookup, s.address
	// storage) uses that same stripped value.
	if err := ValidateAddressForAlgo(s.server.jobManager.Algo(), loginFields.Address); err != nil {
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
		flags := s.server.addressFlags.Get(loginFields.Address)
		if flags.Banned {
			s.server.logger.Printf("solo: rejecting login for banned address %s (session %s)", loginFields.Address, s.sessionID)
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
	// Legacy identifier precedence, ported exactly (pool.js lines
	// 419-423): `this.identifier = pass_split[0] === "x" ?
	// addressSplit[N] : pass_split[0]` -- i.e. the PASSWORD field's own
	// identifier wins, and a login-field dot-segment identifier is only
	// consulted when that password is literally "x" (legacy's
	// "old-logins" sentinel, and also what this handler already
	// substitutes for an entirely absent password/rigid just above).
	//
	// DECISION: the dot-segment identifier feeds the SAME worker/
	// s.worker field this leaf already uses for the miner-reported
	// rig name, not a new separate field -- it is the same concept
	// (legacy stores both in the one `this.identifier`), and a second
	// field would have no consumer: s.worker is what lands in
	// poolpb.Share.Identifier and in the stats UI. The existing
	// RigID-beats-Pass precedence is left untouched: an explicit
	// "rigid" from a modern miner is a strictly more deliberate rig
	// name than a dot-suffix, and changing that would be an unrelated
	// behavior change.
	//
	// DELIBERATELY NOT PORTED: legacy's `pass.split(":")` (pool.js
	// lines 344-348, `pass_split`). In the legacy stack that split
	// exists solely to carry an e-mail address in the second
	// colon-segment for its `registerMiner` API call (pool.js lines
	// 425-440) -- a feature this repo has no equivalent of at all.
	// Porting the split would silently change the stored worker name
	// for any miner whose password legitimately contains a colon,
	// which is outside this fix's scope.
	if loginFields.Identifier != "" && worker == "x" {
		worker = loginFields.Identifier
	}

	s.address.Store(loginFields.Address)
	s.worker.Store(worker)
	s.agent.Store(login.Agent)
	s.paymentID.Store(loginFields.PaymentID)
	s.loggedIn.Store(true)

	// A miner-requested (or NiceHash-assigned) FIXED difficulty
	// becomes this session's STARTING difficulty instead of the port
	// tier's configured default, and pins it for the lifetime of the
	// connection -- mirroring legacy's `this.fixed_diff = true;
	// this.difficulty = ...` semantics (pool.js lines 392-411). The
	// fixedDiff flag is what vardiff.go's maybeRetarget gates on so
	// this session is never retargeted away from the requested value
	// (see that field's own doc comment for the verbatim legacy
	// retargetMiners citation).
	//
	// Set BEFORE the forced-floor block below deliberately: an
	// operator-forced minimum must still be able to raise a
	// fixed-difficulty session (an explicit operator ban/floor
	// outranks a miner's own request), exactly as it already outranks
	// the port tier's default.
	//
	// XNP-PROXY ESCAPE HATCH: an XNP-proxy-detected session whose
	// fixed difficulty came from the login field's own
	// "+<difficulty>" suffix gets that value as its STARTING
	// difficulty but is NOT pinned -- normal vardiff retargeting
	// proceeds from there, so an aggregating proxy's difficulty keeps
	// tracking its real (and changing) downstream-aggregate hashrate.
	// This is this leaf's equivalent of legacy's own
	// `proxyAddressList` clause in retargetMiners; see
	// LoginFields.XNPProxyExemptFromFixedDiffPin (loginfields.go) for
	// the verbatim citation, the mechanism divergence (agent-string
	// detection here vs. legacy's operator-maintained payout-address
	// allowlist, which has no equivalent in this leaf), and why the
	// NiceHash-agent pin is deliberately left untouched.
	if loginFields.FixedDiff {
		if !loginFields.XNPProxyExemptFromFixedDiffPin(login.Agent) {
			s.fixedDiff.Store(true)
		}
		s.currentDifficulty.Store(loginFields.Difficulty)
	}

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

// pushFreshJobOnStaleSubmit is handleSubmit's own dedicated fix for
// the real, live-confirmed production rejection-reason breakdown
// (brief_push_job_on_stale.md: stale_or_unknown_job was 715/1550,
// ~46%, of leaf-direct-prod's total rejects in a recent sample --
// leaf-solo mirrors leaf-direct's own identical handleSubmit closely
// enough that the same fix applies here too): a submit rejected for a
// reason that means "the job you are hashing on is no longer the one
// this server considers current for you" leaves the miner able to
// regenerate the exact same rejection indefinitely, with nothing
// pushed to correct it until the next scheduled refresh. Called ONLY
// from the rejection branches enumerated below, in ADDITION to (never
// instead of) the existing rejectShare/writeShareResponse call already
// made for this submit -- it does NOT change the wire-visible
// rejection response for THIS submit at all, it only arranges for a
// SEPARATE, additional "job" push to reach this session right after.
//
// EXACTLY FOUR call sites, no more (widened from the original two):
//   - RejectionReasonStaleOrUnknownJob -- this session's own ownJob
//     lookup failed.
//   - RejectionReasonJobExpired -- the job WAS this session's own, but
//     JobMaxAge elapsed.
//   - RejectionReasonDifficultyFloorMiss -- the submitted share's
//     difficulty is below its own job's StaticDifficulty. The dominant
//     real-world cause is the same staleness: the miner is still
//     hashing against a target from an older, lower-difficulty job it
//     has not switched off yet (a vardiff retarget upward is exactly
//     this shape), so handing it the current job at its current
//     difficulty is the correcting action.
//   - RejectionReasonDuplicateNonce -- Job.MarkNonceUsed returned
//     false. A miner replaying nonces against a job it should have
//     rotated off is, again, a miner whose current job is out of sync
//     with the server's; a fresh job gives it a fresh nonce space
//     instead of letting it exhaust the old one.
//
// Every OTHER rejection reason (claimed_difficulty_or_crypto_invalid,
// banned_address, malformed_nonce, invalid_xnonce, invalid_pow_shape,
// missing_claimed_result, malformed_submit_request, block_submit_failed,
// pool_saturated, internal_error) deliberately does NOT push -- none
// of them are caused by a stale job, and pushing on e.g.
// malformed_submit_request would hand a broken/abusive client a free
// job-template fetch per malformed line it sends.
//
// Unlike leaf-direct's own identical fix, leaf-solo has no
// jobFetchPool (that CLOSE-WAIT-incident worker-pool dispatch is a
// leaf-direct-only fix -- see direct/server.go's jobFetchPool doc
// comment); handleGetJob above already calls JobForXNAtDifficulty
// inline on Session.Run's own read-loop goroutine, so this mirrors
// that exact, already-established synchronous shape rather than
// introducing new dispatch machinery leaf-solo has never used.
//
// Fetches a fresh job at this session's OWN current difficulty
// (s.currentDifficulty.Load() -- never any other value), gated
// through s.alreadyDelivered (see that method's doc comment): if the
// freshly fetched job is byte-for-byte identical (same job.ID AND
// same difficulty) to what this session's own lastDeliveredJobID/
// lastDeliveredDifficulty bookkeeping says was already sent to it,
// this is a deliberate no-op, matching invalidateAndRepushJobs' own
// identical dedup gate (server.go) and the live production bug
// (Alex's "we're sending duplicate jobs down the wire" report) that
// gate was originally added to fix. s.pushJob(job) below is the SAME
// existing helper handleGetJob/handleLogin's own job pushes already
// use -- it already calls s.recordJob(job) (via jobPayload) so this
// freshly pushed job becomes immediately submittable against by this
// session, and already gates on s.loggedIn itself, so there is no
// separate logged-in check needed here.
func (s *Session) pushFreshJobOnStaleSubmit() {
	job, err := s.server.jobManager.JobForXNAtDifficulty(context.Background(), s.xn, s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("solo: failed to fetch fresh job for session %s (xn %s) after a stale-job-class submit rejection: %v", s.sessionID, s.xn, err)
		return
	}
	if s.alreadyDelivered(job) {
		return
	}
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

// ClaimedRandomXFamilyDifficulty derives the difficulty implied by an
// RXT/RXM miner's own CLAIMED result hash (submit.Result) using the
// SAME real, algo-appropriate, already-existing formula
// BuildCandidateBlock's own NodeClient implementations use to derive
// a share's real difficulty AFTER real validation
// (rxtLittleEndianDifficulty for ALGO_RXT — tariBuildCandidateBlock,
// node.go; moneroDifficultyFromHash for ALGO_RXM —
// MoneroNodeClient.BuildCandidateBlock, monero_node.go). Reusing
// those exact, already-real-source-confirmed functions here (rather
// than leaf-proxy's own littleEndianDifficulty, proxy/difficulty.go —
// mathematically identical for the Monero case, per that function's
// own doc comment, but never verified against RXT's own real Tari
// Rust formula, since proxy never handles RXT at all) guarantees this
// pre-validation estimate is byte-for-byte the same value
// BuildCandidateBlock would derive once a claim is confirmed real,
// for both algos this leaf actually serves — see this repo's
// DISPATCH_BRIEF.md (2026-09-10) for the explicit instruction to
// verify this rather than assuming proxy's formula transfers.
//
// Exported (FIX_BRIEF.md, finding #14) specifically so
// internal/leaflib/direct — which already imports this package
// directly for solo.Job/solo.IsRandomXFamily/solo.SubmitProof/etc,
// unlike leaf-proxy, which deliberately avoids coupling to solo at
// all (see proxy/difficulty.go's own doc comment) — can reuse this
// EXACT function for its own cheap pre-dispatch claimed-difficulty
// filter, rather than re-implementing a second, potentially-
// diverging copy of the RXT/RXM branch above (leaf-direct, unlike
// leaf-proxy, handles BOTH algos and so cannot get away with a single
// Monero-only formula the way proxy's own littleEndianDifficulty
// does).
//
// DISPATCH_BRIEF (2026-09-10, Alex): this is what lets handleSubmit
// decide "is this an ordinary sub-block share, or a genuine block-
// find candidate" WITHOUT paying for a real, synchronous
// randomx-service HTTP round-trip on every single submit — mirroring
// leaf-proxy's own identical cheap-derivation-before-expensive-
// verification shape (internal/leaflib/proxy/session.go's
// handleSubmit, step 7 of its own doc comment). It is a pure
// computation over bytes the miner already sent on the wire and does
// NOT confirm the claim is cryptographically genuine (a lying miner
// can claim any hash value here) — see handleSubmit's own doc comment
// for the accurate, corrected framing of why that is acceptable for
// the ordinary-share branch (DISPATCH_BRIEF.md, 2026-09-10, Fix 4:
// the framing this comment used to carry here — "safe because a
// difficulty floor was the only thing missing" — was itself
// misleading and has been corrected at that doc comment; it is NOT
// safe merely because no floor was enforced, it is accepted because
// solo mode has no share table/backend/payouts riding on this value)
// and why cheaply computing it here is NOT a substitute for the
// block-find branch's real v.Validate call, which is a genuine,
// daemon-confirmed hash-equality/authenticity check this pure
// computation can never provide — see handleSubmit's doc comment for
// why that distinction matters before ever trusting this number
// enough to call BuildCandidateBlock/SubmitBlock.
//
// Returns an error for malformed hex or an all-zero hash (division by
// zero has no sound difficulty) — handleSubmit treats either as an
// outright reject, matching how a malformed/all-zero claimed hash was
// always eventually rejected before this change too (Validate's own
// hex-decode-failure branch already returned (false, nil); a
// genuinely all-zero real RandomX hash has never been observed in
// practice and would previously have still failed BuildCandidateBlock's
// own identical zero-hash guard once Validate happened to pass).
func ClaimedRandomXFamilyDifficulty(algo poolpb.Algo, resultHex string) (uint64, error) {
	hashBytes, err := hex.DecodeString(resultHex)
	if err != nil {
		return 0, fmt.Errorf("claimed result hash is not valid hex: %w", err)
	}
	switch algo {
	case poolpb.Algo_ALGO_RXT:
		return rxtLittleEndianDifficulty(hashBytes)
	case poolpb.Algo_ALGO_RXM:
		return moneroDifficultyFromHash(hashBytes)
	default:
		// Every standalone monerod-family coin algo added via
		// internal/coinprofile.Registry (ALGO_XMR and below) shares
		// RXM's own real Monero check_hash_128 difficulty formula --
		// they are all confirmed, unmodified-RandomX monero-project/
		// monero source forks (see that package's doc comment), so
		// their claimed result hash has the exact same real
		// on-wire/on-chain shape Monero's own does.
		if _, ok := coinprofile.ByAlgo(algo); ok {
			return moneroDifficultyFromHash(hashBytes)
		}
		return 0, fmt.Errorf("ClaimedRandomXFamilyDifficulty: algo %v is not a RandomX-family algo", algo)
	}
}

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
		s.rejectShare(req.ID, metrics.RejectionReasonMalformedSubmitRequest, "submit requires params")
		return
	}
	if err := json.Unmarshal(req.Params, &submit); err != nil {
		s.rejectShare(req.ID, metrics.RejectionReasonMalformedSubmitRequest, fmt.Sprintf("invalid submit params: %v", err))
		return
	}

	s.server.debugLogger.Debugf("solo: submit received: session=%s job_id=%s nonce=%s result=%s", s.sessionID, submit.JobID, submit.Nonce, submit.Result)

	// SECURITY: session-ownership check FIRST, independently of xn —
	// see this method's doc comment. job.ID must have actually been
	// issued to THIS session (s.ownJob), never any other session's.
	job, ok := s.ownJob(submit.JobID)
	if !ok {
		s.rejectShare(req.ID, metrics.RejectionReasonStaleOrUnknownJob, fmt.Sprintf("unknown or stale job_id: %s", submit.JobID))
		s.pushFreshJobOnStaleSubmit()
		return
	}

	// Real per-job expiry, independent of tip-invalidation (see
	// JobManagerConfig.JobMaxAge's doc comment): a job can still be
	// present in this session's own bounded history yet be too old to
	// accept, e.g. a race right at InvalidateAll's boundary.
	if maxAge := s.server.jobManager.JobMaxAge(); maxAge > 0 {
		if age := time.Since(job.CreatedAt); age > maxAge {
			s.rejectShare(req.ID, metrics.RejectionReasonJobExpired, fmt.Sprintf("job expired: job_id %s was issued %s ago (max age %s)", submit.JobID, age.Round(time.Second), maxAge))
			s.pushFreshJobOnStaleSubmit()
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
			s.rejectShare(req.ID, metrics.RejectionReasonBannedAddress, "this address is banned from this pool")
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
	if !IsRandomXFamily(job.Algo) {
		if !strings.HasPrefix(strings.ToLower(submit.Nonce), s.xn) {
			s.rejectShare(req.ID, metrics.RejectionReasonInvalidXNonce, fmt.Sprintf("Invalid XNonce %v", submit.Nonce))
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
	if IsRandomXFamily(job.Algo) {
		if err != nil || (len(nonceBytes) != 4 && len(nonceBytes) != 8) {
			s.rejectShare(req.ID, metrics.RejectionReasonMalformedNonce, "nonce must be 4 bytes for RandomX-family (rx/0) jobs, hex-encoded uint32")
			return
		}
	} else {
		if err != nil || len(nonceBytes) != 8 {
			s.rejectShare(req.ID, metrics.RejectionReasonMalformedNonce, "nonce must be 8 bytes, hex-encoded uint64")
			return
		}
	}

	var (
		nonce uint64
		share *poolpb.Share
	)
	switch job.Algo {
	case poolpb.Algo_ALGO_RXM, poolpb.Algo_ALGO_XMR, poolpb.Algo_ALGO_ARQ, poolpb.Algo_ALGO_XEQ,
		poolpb.Algo_ALGO_GRFT, poolpb.Algo_ALGO_SFX, poolpb.Algo_ALGO_ZEPH, poolpb.Algo_ALGO_SAL:
		// Real Monero-family submit wire shape (RXM, and every other
		// confirmed monerod-compatible coin in
		// internal/coinprofile.Registry -- ALGO_XMR and below, all
		// sharing this exact wire shape since they all speak the
		// same monerod-family JSON-RPC/blob conventions): no "pow"
		// field (C29-only); the miner's claimed RandomX result hash
		// rides in the
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
			s.rejectShare(req.ID, metrics.RejectionReasonMissingClaimedResult, "monero (rxm) submit requires a claimed result hash in \"result\"")
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
			s.rejectShare(req.ID, metrics.RejectionReasonInternalError, fmt.Sprintf("failed to build monero randomx verification blob: %v", blobErr))
			return
		}
		share = &poolpb.Share{
			Algo:           job.Algo,
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
			s.rejectShare(req.ID, metrics.RejectionReasonInvalidPowShape, fmt.Sprintf("pow must carry exactly %d edges for a C29 cycle, got %d", c29SubmitCycleSize, len(submit.POW)))
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
			s.rejectShare(req.ID, metrics.RejectionReasonMissingClaimedResult, "rxt submit requires a claimed result hash in \"result\"")
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
		s.rejectShare(req.ID, metrics.RejectionReasonDuplicateNonce, fmt.Sprintf("duplicate nonce: %s", submit.Nonce))
		s.pushFreshJobOnStaleSubmit()
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
	// UPDATE (DISPATCH_BRIEF, 2026-09-10): for RXT/RXM, finishSubmit is
	// no longer reached for EVERY submitted share — only for the rare
	// one whose claimed result already crosses job.NetworkTargetDifficulty
	// (a genuine block-find candidate). An ordinary sub-block RXT/RXM
	// share is now credited earlier, inline, without ever calling
	// finishSubmit or touching the real validator/async pool at all —
	// see the dispatch decision below finishSubmit's own definition for
	// the full rationale. finishSubmit's own body is otherwise
	// unchanged: it is still exactly what SHA3X/C29 always run, and
	// still exactly what an RXT/RXM block-find candidate needs to run.
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
	// s.server.node.BuildCandidateBlock
	// only READS job fields and returns a fresh proto.Clone'd candidate
	// (node.go/monero_node.go — never mutates the shared job template);
	// s.mc.Write is already synchronized onto the connection's single
	// writer goroutine (connection.go). Nothing here needed a NEW lock —
	// it was already race-safe by construction, just previously
	// single-threaded by the caller.
	finishSubmit := func() {
		v, err := s.server.validators.Get(job.Algo)
		if err != nil {
			s.rejectShare(req.ID, metrics.RejectionReasonInternalError, fmt.Sprintf("no validator configured for this leaf's algo %v: %v", job.Algo, err))
			return
		}

		// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 5): the
		// trusted-miner probabilistic validation-skip mechanism
		// (trust.go's MinerTrust) has been removed from solo's own
		// submit path entirely — see this method's own doc comment
		// below (the DISPATCH_BRIEF block preceding this closure's
		// dispatch site) for the full removal rationale. finishSubmit
		// is now ONLY ever reached for a genuine block-find candidate
		// (see that same doc comment), so it always runs the real,
		// daemon-backed v.Validate call unconditionally — there is no
		// skip path left to gate.
		valid, err := v.Validate(context.Background(), share)
		s.server.debugLogger.Debugf("solo: validation attempt: session=%s job_id=%s algo=%v valid=%v err=%v", s.sessionID, job.ID, job.Algo, valid, err)
		if err != nil && err != validator.ErrWrongProofType {
			s.rejectShare(req.ID, metrics.RejectionReasonInternalError, fmt.Sprintf("validation error: %v", err))
			return
		}
		if !valid {
			// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b):
			// a fabricated above-target claim that fails this real,
			// daemon-confirmed validation is the actual DoS vector
			// Finding 2 identified — a hostile session can keep
			// submitting bogus block-find-level claims, each one
			// costing a real dispatch through s.server.randomxPool
			// (and the real randomx-service round-trip inside it),
			// with zero consequence to the submitting session
			// otherwise. leaflib.InvalidShareGuard tracks consecutive
			// invalid outcomes exactly like this per session; once
			// disconnect is true, this session has exceeded its
			// configured threshold and is closed here so it can no
			// longer keep flooding this shared pool (see
			// InvalidShareGuard's own doc comment for the full
			// rationale and internal/leaflib's shared implementation).
			disconnect := s.invalidShareGuard.RecordOutcome(false)
			s.rejectShare(req.ID, metrics.RejectionReasonClaimedDifficultyOrCryptoInvalid, "share does not meet configured difficulty or is cryptographically invalid")
			if disconnect {
				s.server.logger.Printf("solo: disconnecting session %s (address %s): exceeded consecutive invalid-share threshold", s.sessionID, s.address.Load())
				s.mc.Close("exceeded consecutive invalid-share threshold")
			}
			return
		}
		s.invalidShareGuard.RecordOutcome(true)

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
			s.rejectShare(req.ID, metrics.RejectionReasonInternalError, fmt.Sprintf("difficulty derivation error: %v", err))
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
		//
		// realBlockID surfaces the real, daemon-reported block ID
		// for this find (today: only for ALGO_RXM, whenever
		// s.server.node implements BlockIDSubmitter/AuxChainSubmitter
		// -- see monero_node.go's SubmitBlockWithID/
		// SubmitBlockAuxChains and moneroSubmitBlockAuxResult.
		// BlockID's own doc comment for the full derivation/
		// provenance) purely for this leaf's own local logging below
		// -- leaf-solo has no backend/share table to forward it to
		// (see this package's own doc comment), so this is
		// diagnostic-only, never fabricated (stays "" when the node
		// has no such capability, or the daemon's own response
		// genuinely carried no block_id).
		var realBlockID string
		if auxSubmitter, ok := s.server.node.(AuxChainSubmitter); ok {
			realBlockID, _, err = auxSubmitter.SubmitBlockAuxChains(context.Background(), candidate)
		} else if idSubmitter, ok := s.server.node.(BlockIDSubmitter); ok {
			realBlockID, err = idSubmitter.SubmitBlockWithID(context.Background(), candidate)
		} else {
			err = s.server.node.SubmitBlock(context.Background(), candidate)
		}
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
			s.rejectShare(req.ID, metrics.RejectionReasonBlockSubmitFailed, fmt.Sprintf("invalid block: %v", err))
			return
		}

		s.blockCount.Add(1)
		if realBlockID != "" {
			s.server.logger.Printf("solo: BLOCK FOUND by session %s (address %s) at height %d, job %s, diff %d, hash=%s", s.sessionID, s.address.Load(), job.Height, job.ID, diff, realBlockID)
		} else {
			s.server.logger.Printf("solo: BLOCK FOUND by session %s (address %s) at height %d, job %s, diff %d", s.sessionID, s.address.Load(), job.Height, job.ID, diff)
		}
		s.server.recordBlock(true)
		s.hashesAccumulated.Add(job.StaticDifficulty)
		s.writeShareResponse(req.ID, true, "")

		// A block was found; every cached per-xn template is now stale
		// (built against a tip that no longer exists). Invalidate the
		// whole cache (this also fires JobManager's subscribers, which
		// triggers Server.invalidateAndRepushJobs to regenerate+push fresh
		// jobs to every connected session) rather than waiting out the
		// tip-poll interval.
		go s.server.jobManager.InvalidateAll(TemplateSourceLocal)
	}

	// DISPATCH_BRIEF (2026-09-10, Alex's explicit direction): leaf-solo
	// only actually needs to cryptographically validate an RXT/RXM
	// share for real when it is about to submit a candidate block to
	// the daemon — the same model leaf-proxy already uses (see
	// internal/leaflib/proxy/session.go's handleSubmit doc comment: an
	// ordinary sub-block share is credited on the miner's own claimed
	// result with no real crypto check at all; the real, expensive
	// verification runs ONLY for the rare submit whose claimed result
	// numerically crosses the pool's own block-level target). SHA3X/C29
	// are cheap local CPU hashes with no external daemon dependency and
	// are completely unaffected by this — finishSubmit still always
	// runs INLINE for them below, exactly as before this change.
	//
	// For ALGO_RXT/ALGO_RXM, ClaimedRandomXFamilyDifficulty (above)
	// derives the miner's claimed difficulty from its own submitted
	// result hash alone — a cheap, pure-CPU computation, no network
	// I/O — and that alone now decides which of two paths this submit
	// takes:
	//
	//   - Below job.NetworkTargetDifficulty (the overwhelming majority
	//     of real submits): an ordinary sub-block share, CREDITED ON
	//     THE MINER'S OWN CLAIM, WITH NO CRYPTOGRAPHIC AUTHENTICITY
	//     CHECK OF ANY KIND — the real, synchronous randomx-service
	//     HTTP round-trip (validator.RandomXValidator.Validate, ~4ms+
	//     per call — see asyncvalidation.go's package doc comment for
	//     the full 2026-08-30 production-incident history that call's
	//     cost originally caused) is never made at all, and this
	//     submit never touches s.server.randomxPool either — it is
	//     handled entirely, synchronously, right here in Session.Run's
	//     read loop, the same way SHA3X/C29 always have been.
	//     CORRECTED SAFETY RATIONALE (DISPATCH_BRIEF.md, 2026-09-10,
	//     Fix 4 — this comment previously framed this as "safe because
	//     no per-share difficulty floor was ever cryptographically
	//     enforced anyway", which was misleading: hash-equality
	//     validation against a daemon-recomputed hash WAS a real
	//     per-share authenticity/anti-fabrication check, and it simply
	//     no longer runs here at all). This is accepted specifically
	//     because solo mode has no share table, no backend, and no
	//     payouts riding on this value — it is hashrate/vardiff
	//     stats only (see cmd/leaf-solo's own doc comment) — NOT
	//     because a missing difficulty floor made it a non-issue.
	//     HARDENING FIX (Fix 1): a claimed difficulty BELOW this job's
	//     own StaticDifficulty is now rejected outright rather than
	//     credited (see the floor check below) — as Alex put it, "as
	//     long as the difficulty of the hash is OVER the difficulty of
	//     the job, it's fine, because we send the job diff back
	//     upstream". This is a garbage-in filter on the claimed value,
	//     not a cryptographic check — it does not and cannot restore
	//     the authenticity guarantee described above.
	//   - At or above job.NetworkTargetDifficulty (a genuine block-find
	//     candidate, expected to be extremely rare): the real,
	//     expensive validator round-trip — and everything downstream of
	//     it (BuildCandidateBlock/SubmitBlock) — still runs, dispatched
	//     onto s.server.randomxPool exactly as before this change (see
	//     asyncvalidation.go). A real, malformed, or outright FALSE
	//     claim (a claimed hash that numerically crosses the target but
	//     does not match what the daemon actually computes) is still
	//     caught and rejected by finishSubmit's own existing
	//     `!valid` branch — never silently credited as a block find,
	//     and never silently downgraded to an ordinary accepted share
	//     either. A repeated run of such failures from the same
	//     session now also trips leaflib.InvalidShareGuard and
	//     disconnects it (Fix 2b) — see finishSubmit's own `!valid`
	//     branch above.
	//
	// TRUST REMOVED (DISPATCH_BRIEF.md, 2026-09-10, Fix 5): trust.go's
	// MinerTrust skip mechanism used to be wired into finishSubmit
	// here. Post the block-find-only change above, finishSubmit is
	// only ever reached at this one narrow, rare, block-find-level
	// call site — the trust-ramp's own gating (requiring
	// Threshold consecutive real, fully-validated accepted shares
	// before any skip is even considered) could never realistically
	// ramp in against a call site this infrequent, making the whole
	// mechanism unreachable dead weight for solo specifically. It has
	// been removed from solo's Session/Server entirely (no more
	// s.trust field, no more Server.trustConfig/EnableTrust, no more
	// -trust-* flags in cmd/leaf-solo) — every genuine block-find
	// candidate now always runs the real v.Validate call
	// unconditionally, with no skip path at all. trust.go's
	// MinerTrust/TrustConfig types themselves are NOT deleted (still
	// exported from this package) because internal/leaflib/direct
	// still wires them in for real — see direct/server.go's EnableTrust
	// doc comment for direct's own, still-live risk/tradeoff framing.
	//
	// ASYNCVALIDATION.GO RELEVANCE (explicit conclusion, per this
	// task's own instruction to state one): the bounded worker pool is
	// NOT vestigial and is kept exactly as-is. A genuine block-find
	// submit still pays the same real, synchronous ~4ms+
	// randomx-service HTTP round-trip that motivated asyncvalidation.go
	// in the first place, and a real block-race — several concurrent
	// RXT/RXM sessions independently crossing job.NetworkTargetDifficulty
	// within the same short window — could still, in principle, produce
	// more than one such submit close together; running those inline
	// would reintroduce exactly the read-loop-blocking bug
	// asyncvalidation.go exists to prevent, just at a much lower
	// frequency. What DID change is WHEN this leaf's own dispatch
	// decision (this `if` below) fires: previously every single
	// RXT/RXM submit was dispatched through the pool; now only the rare
	// submit whose claimed result already crosses the block-level
	// target is — i.e. solo's own dispatch frequency now matches
	// leaf-proxy's own already-narrow dispatch trigger (proxy only ever
	// dispatches its own genuine upstream-forward candidates), not a
	// simplification of asyncvalidation.go itself, which remains
	// shared, unmodified, production infrastructure (also used by
	// leaf-direct and leaf-proxy — see asyncvalidation.go's own doc
	// comment). Its default worker count is now runtime.NumCPU(), not
	// a hardcoded 8 — see asyncvalidation.go's own doc comment (Fix 2a).
	if IsRandomXFamily(job.Algo) {
		claimedDiff, err := ClaimedRandomXFamilyDifficulty(job.Algo, submit.Result)
		if err != nil {
			// Malformed hex, or a degenerate all-zero claimed hash —
			// see ClaimedRandomXFamilyDifficulty's own doc comment for
			// why this is treated as an outright reject, matching how
			// either case was already eventually rejected before this
			// change (Validate's own hex-decode-failure branch, or
			// BuildCandidateBlock's own zero-hash guard).
			s.rejectShare(req.ID, metrics.RejectionReasonClaimedDifficultyOrCryptoInvalid, "share does not meet configured difficulty or is cryptographically invalid")
			return
		}
		if job.NetworkTargetDifficulty == 0 || claimedDiff < job.NetworkTargetDifficulty {
			// Ordinary sub-block share: no real validator call, no
			// async dispatch — see this block's own doc comment above.
			//
			// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 1
			// [CRITICAL — Finding 1]): reject outright if the miner's
			// own claimed difficulty doesn't even meet THIS job's own
			// configured StaticDifficulty — Alex's exact framing: "as
			// long as the difficulty of the hash is OVER the
			// difficulty of the job, it's fine, because we send the
			// job diff back upstream." Before this check, any
			// claimedDiff (including a trivially low one) below
			// job.NetworkTargetDifficulty was credited as a full,
			// job.StaticDifficulty-weighted accepted share, silently
			// inflating this session's own hashrate/vardiff stats
			// with claims that don't even meet its own assigned
			// difficulty. This is a garbage-in filter on the claimed
			// value only (no daemon round-trip here either way, so no
			// new async-pool load) — see this block's own doc comment
			// above for why it does not restore cryptographic
			// authenticity.
			if claimedDiff < job.StaticDifficulty {
				s.rejectShare(req.ID, metrics.RejectionReasonDifficultyFloorMiss, "share does not meet the job's configured difficulty")
				s.pushFreshJobOnStaleSubmit()
				return
			}
			s.shareCount.Add(1)
			s.hashesAccumulated.Add(job.StaticDifficulty)
			s.writeShareResponse(req.ID, true, "")
			return
		}
		// Genuine block-find candidate: the real, expensive path,
		// still dispatched off the read loop exactly as before this
		// change (see asyncvalidation.go).
		//
		// HARDENING FIX (FIX_BRIEF.md, finding #15): TrySubmit, NOT
		// Submit -- this call runs directly on Session.Run's own read
		// loop (handleSubmit is called synchronously from it), so a
		// blocking Submit here would let one saturated/flooding
		// session's own dispatch block every OTHER session's next
		// read-loop iteration too (the shared pool is server-scoped,
		// see asyncvalidation.go's own "WHY SERVER-SCOPED" doc
		// comment) once the bounded queue and every worker are
		// simultaneously busy -- a real, if bounded, cross-session
		// interference finding #15 identified. TrySubmit's "reject
		// this ONE submit rather than block" contract confines the
		// cost of a genuinely saturated pool to the single session
		// that hit it, exactly mirroring the reasoning
		// direct/session.go's forwardPool dispatch already uses (see
		// TrySubmit's own doc comment) -- generalized here to the
		// primary randomxPool dispatch itself, across all three leaf
		// modes (see direct/session.go's and proxy/session.go's
		// identical change).
		if ok := s.server.randomxPool.TrySubmit(finishSubmit); !ok {
			// Pool already stopped (server shutting down), OR its
			// bounded queue is genuinely saturated and every worker
			// is busy right now -- respond with a real rejection
			// rather than leaving this submit unanswered or blocking
			// this read loop waiting for room (task constraint: "no
			// orphaned unresolved submits"). This is not a
			// cryptographic rejection of the miner's share; a retry
			// (this submit) or a reconnect (if the pool was actually
			// stopped) will process normally once room/a fresh
			// instance is available.
			s.rejectShare(req.ID, metrics.RejectionReasonPoolSaturated, "validation pool is saturated or shutting down, please retry")
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
	s.server.debugLogger.Debugf("solo: submit result: session=%s accepted=%v reason=%q", s.sessionID, accepted, errMsg)
	leaflib.WriteShareResponse(s.writeJSON, leaflib.IsLegacyWireAlgo(s.server.jobManager.Algo()), id, accepted, errMsg)
}

// rejectShare is handleSubmit's own single real reject call site
// wrapper (see brief_rejection_reasons.md and
// internal/leaflib/direct/session.go's identical helper): it bumps
// the new, real leaf_share_rejection_reason_total counter for
// category (one of metrics.RejectionReason*) via
// s.server.recordShareRejectionReason, THEN calls the existing,
// unmodified writeShareResponse(id, false, errMsg) -- ADDITIVE
// observability only, never a replacement for writeShareResponse's
// own existing recordShare(false) bookkeeping or the wire-visible
// errMsg a real miner/operator already sees. Every
// writeShareResponse(id, false, ...) call site in handleSubmit below
// goes through this helper instead of calling writeShareResponse
// directly, so a real reject can never be added to handleSubmit in
// the future without also being forced to pick one of the closed
// RejectionReason* categories.
func (s *Session) rejectShare(id int, category, errMsg string) {
	s.server.recordShareRejectionReason(category)
	s.writeShareResponse(id, false, errMsg)
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
// mining hash), JobID is the job's own real job_id (a purely random,
// opaque wire token — see node.go's tariJobFromResult/
// monero_node.go's GetBlockTemplate; NOT content-derived, see those
// functions' doc comments for why), Target is
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
	if !IsRandomXFamily(job.Algo) {
		payload.XN = s.xn
	}
	// RXT-only: surface the real RandomX seed/key (job.go's Job.VmKey,
	// taken directly from GetNewBlockResult.VmKey) as the wire
	// "seed_hash" field — mirrors XMRig's own stratum job-JSON
	// convention for RandomX-family coins. SHA3X/C29 jobs have no
	// VmKey, so this is simply omitted (omitempty) for them.
	if IsRandomXFamily(job.Algo) && len(job.VmKey) > 0 {
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
		case poolpb.Algo_ALGO_RXM, poolpb.Algo_ALGO_XMR, poolpb.Algo_ALGO_ARQ, poolpb.Algo_ALGO_XEQ,
			poolpb.Algo_ALGO_GRFT, poolpb.Algo_ALGO_SFX, poolpb.Algo_ALGO_ZEPH, poolpb.Algo_ALGO_SAL:
			// RXM (and every other confirmed monerod-family coin in
			// internal/coinprofile.Registry): the raw, unconverted monerod blocktemplate_blob
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
