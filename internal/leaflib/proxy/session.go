// Copyright and license: see repository LICENSE (MIT).
package proxy

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy/metrics"
)

// ShareValidator is the real local-RandomX-re-validation dependency
// leaf-proxy's Session uses to check a downstream miner's claimed
// result BEFORE ever forwarding anything upstream — implemented by
// the real, in-process, pure-Go
// internal/leaflib/validator.PureGoRandomXValidator (its
// ValidateBlobSeedResult method matches this shape exactly — see that
// type's doc comment for why leaf-proxy uses the pure-Go
// implementation while leaf-solo's RXT support still uses the
// external-daemon-backed RandomXValidator, which implements this same
// method shape too). Defined as an interface here purely so
// session_test.go can inject a deterministic fake instead of paying
// pure-Go RandomX's real per-call cost for every unit test run.
type ShareValidator interface {
	ValidateBlobSeedResult(ctx context.Context, blob, seed []byte, resultHex string) (bool, error)
}

// UpstreamSubmitter is the real "forward a genuine block-level find
// upstream" dependency, implemented by UpstreamClient.SubmitShare
// against the real upstream pool. Defined as an interface so
// server_test.go's "below block target -> local only, no upstream
// call" test can assert a mock is NEVER invoked, without needing a
// real pool connection for every test run.
type UpstreamSubmitter interface {
	SubmitShare(ctx context.Context, jobID, nonceHex, resultHex string, workerNonce, poolNonce uint32) (bool, error)
}

// Session drives one downstream miner connection's request/response
// loop, speaking the exact same real Monero-style JSON-RPC 2.0
// stratum dialect leaf-solo's miners already do (protocol.go reuses
// solo's wire types directly). It never bypasses
// leaflib.ManagedConnection's lifecycle guarantees, mirroring
// internal/leaflib/solo/session.go's own Session exactly in that
// regard.
//
// It also carries the SAME per-session repush dedup leaf-solo/
// leaf-direct already do (lastDeliveredJobID/lastDeliveredDifficulty/
// alreadyDelivered below) -- ported here per Alex's real production
// report ("Proxy is having some job staleness issues, it's disabling
// as soon as a new job is sent, it needs to allow jobs 2-3 old, just
// like the -direct has to"): without it, Server.repushAllSessions
// unconditionally handed every logged-in session a BRAND NEW random
// job_id (JobManager.NextJob always allocates one) on every upstream
// job-update subscriber fire, evicting a miner's own in-flight job
// out of its bounded jobHistorySize before it could even submit,
// producing exactly the observed "unknown or stale job_id" rejections
// within tens of milliseconds of a job being issued.
//
// It ALSO carries a per-session JOB CACHE (jobCacheMu/cachedJob below,
// backed by currentJob) -- the THIRD report of this same class of bug,
// one level deeper than the repush dedup above: JobManager.NextJob has
// NO caching at all, so even the repush-dedup fix above didn't help an
// explicit, redundant miner-initiated getjob (some miner software
// polls periodically in addition to waiting for pushed jobs) or a
// vardiff retarget tick that didn't actually change anything -- EVERY
// one of those still called NextJob directly and minted a brand-new
// job_id/nonce pair, burning a job-history slot for genuinely zero
// reason. Confirmed live: a job accepted normally, then an immediate
// burst of 8 rejects against that SAME job_id in the same
// millisecond, only ~1.5s after a genuine new upstream job event --
// far more evictions than the actual upstream job cadence (~5-15s)
// could explain on its own. Ported from XNP's own getJob() (lib/
// xmr.js), which short-circuits on an unchanged
// activeBlockTemplate.id/!miner.newDiff via miner.cachedJob, and from
// this repo's own already-correct solo.JobManager.jobForXN/
// JobForXNAtDifficulty (internal/leaflib/solo/job.go), which caches
// per-xn the same way. See currentJob's own doc comment for the exact
// caching rule.
type Session struct {
	mc     *leaflib.ManagedConnection
	server *Server

	sessionID string
	loggedIn  atomic.Bool
	address   atomic.Value // string
	worker    atomic.Value // string

	// Port is the canonical port-tier label this session was
	// accepted on (see server.go's portLabel helper, the single
	// source of truth both this field and the Prometheus "port"
	// label/stats-HTML "Port" column are derived from) -- set once
	// in newSession below and never mutated afterward for the
	// lifetime of the connection. Finding #1 (per-port stats): before
	// this field existed, Session dropped port/tier identity
	// entirely, so neither the stats HTML sessions table nor
	// per-session Prometheus metrics could distinguish which
	// configured listener/port tier a given session connected on.
	Port string

	// --- per-session job ownership (SAME security pattern as
	// leaf-solo's fix/job-ownership-and-expiry, applied here from the
	// start rather than reintroduced as a later fix): a submit must
	// reference a job_id THIS session was actually issued, never any
	// other session's or any shared/global map. See
	// internal/leaflib/solo/session.go's Session type doc comment for
	// the full rationale this mirrors.
	// jobs is the shared, extracted implementation of the bounded
	// per-session job-ownership history (internal/leaflib.JobHistory)
	// -- mirrors solo.Session's/direct.Session's own identical field
	// exactly. See internal/leaflib/solo/session.go's Session type
	// doc comment for the full rationale this mirrors.
	jobs *leaflib.JobHistory[*Job]

	shareCount atomic.Uint64
	blockCount atomic.Uint64

	connectedAt       time.Time
	currentDifficulty atomic.Uint64
	// hashesAccumulated is the difficulty-weighted accept-history sum
	// this session's own EstimatedHashrate stat card (server.go's
	// SessionStat, and the aggregate leaf-proxy-wide "Global
	// hashrate" card, statsui.go) is derived from -- see
	// leaflib.EstimateHashrateHz's doc comment for the formula.
	//
	// SECURITY/TRUST CAVEAT (FIX_BRIEF.md, finding #16 -- documentation-
	// only fix per the audit's own accepted-scope framing): the LOCAL-
	// CREDIT branch of handleSubmit below (the `diff < job.UpstreamShareDiff`
	// case) increments this counter using ONLY the miner's own
	// self-claimed result hash's derived difficulty, with ZERO
	// cryptographic validation -- s.server.validator.ValidateBlobSeedResult
	// is never called for a locally-credited share at all (see that
	// branch's own doc comment for why: this leaf only ever re-validates
	// a genuine upstream-forward candidate). A hostile miner can submit
	// arbitrary, made-up (but well-formed, sufficiently-high, distinct-
	// nonce) claims and inflate this counter -- and therefore this
	// session's own EstimatedHashrate and this leaf's aggregate
	// TotalEstimatedHashrate "Global hashrate" headline stat card --
	// completely arbitrarily, with no real PoW behind any of it. This
	// is INHERITED behavior (the local-credit design predates the
	// hashrate stat cards; ShareDecisionsTotal/local_credit already
	// carried this same trust assumption for accounting purposes) --
	// what's new is presenting a number derived from unauthenticated,
	// unvalidated input as an operator-facing "headline" stat with no
	// caveat. Treat any EstimatedHashrate/TotalEstimatedHashrate value
	// that is suspiciously high relative to a session's/fleet's real
	// known hardware as a signal to investigate, not as ground truth --
	// and see this leaf's own metrics package doc comment (Decision
	// label values) for the accompanying local_credit/upstream_forward
	// split, which is the more trustworthy of the two signals (an
	// upstream_forward share DID pass real cryptographic validation).
	hashesAccumulated atomic.Uint64

	// forcedMinDifficulty is this session's own operator-forced
	// difficulty floor (0 = none) -- mirrors solo.Session's identical
	// field exactly (see internal/leaflib/solo/session.go's doc
	// comment for the full rationale). Captured from
	// addressflags.Cache.Get at login time (handleLogin below) and
	// never mutated afterward for the lifetime of the connection;
	// consulted by maybeRetarget (vardiff.go) on every retarget tick
	// so it can never be undercut, exactly like solo's own
	// maybeRetarget.
	forcedMinDifficulty atomic.Uint64

	// lastDeliveredJobID/lastDeliveredDifficulty mirror
	// solo.Session's/direct.Session's own identical fields exactly --
	// see internal/leaflib/solo/session.go's Session type doc comment
	// for the full rationale (BUG FIX: Alex's live "duplicate jobs
	// down the wire" report, and this type's own doc comment above
	// for why the same mechanism was ported here). Updated in
	// jobPayload below; consulted by Server.repushAllSessions via
	// alreadyDelivered.
	lastDeliveredJobID      atomic.Value // string
	lastDeliveredDifficulty atomic.Uint64

	// jobCacheMu/cachedJob back currentJob's per-session job-caching
	// discipline -- see that method's doc comment for the exact rule.
	// Deliberately a SEPARATE lock from jobs' own internal mutex
	// (leaflib.JobHistory): a cache hit under currentJob's own
	// critical section must not need to also take jobs' lock (which
	// recordJob/ownJob already serialize independently through it),
	// and vice versa -- keeping these independent avoids any
	// lock-ordering coupling between the two mechanisms.
	jobCacheMu sync.Mutex
	cachedJob  *Job

	// invalidShareGuard mirrors solo.Session's own identical field
	// exactly — see leaflib.InvalidShareGuard's doc comment for the
	// full DISPATCH_BRIEF.md 2026-09-10 Fix 2b rationale. leaf-proxy
	// has no trust.go-equivalent mechanism of its own to piggyback
	// this onto (unlike solo/direct, which already had
	// s.trust.RecordOutcome for their own RXT/RXM rejections) -- this
	// is the FIRST such abuse-accounting mechanism wired into this
	// package.
	invalidShareGuard *leaflib.InvalidShareGuard
}

// alreadyDelivered mirrors solo.Session's/direct.Session's own
// identical method exactly -- see solo.Session.alreadyDelivered's doc
// comment for the full rationale. Used ONLY by Server.repushAllSessions
// to gate an unsolicited upstream-triggered job push; an explicit
// miner-initiated getjob request and a genuine vardiff retarget push
// both still always go through pushJob/jobPayload unconditionally --
// this dedup is deliberately scoped to that one call site.
func (s *Session) alreadyDelivered(job *Job) bool {
	if job == nil {
		return false
	}
	lastID, _ := s.lastDeliveredJobID.Load().(string)
	return leaflib.AlreadyDelivered(job.ID, job.StaticDifficulty, lastID, s.lastDeliveredDifficulty.Load())
}

// currentJob is the real per-session job-caching choke point every
// production job-issuance call site (handleLogin, handleGetJob,
// maybeRetarget, Server.repushAllSessions) now goes through instead
// of calling s.server.jobs.NextJob(difficulty) directly. It ports the
// SAME caching discipline this repo's own already-correct
// solo.JobManager.jobForXN/JobForXNAtDifficulty
// (internal/leaflib/solo/job.go) already has, and that XNP's own
// getJob() (lib/xmr.js) already has via miner.cachedJob/
// activeBlockTemplate.id/!miner.newDiff -- adapted to leaf-proxy's own
// architecture, which has no per-connection "xn"/nonce-space concept
// (proxy partitions worker-/pool-nonces at the WorkerTemplate level,
// not per-session -- see JobManager.NextJob) but DOES have a
// per-session cache key that matters just as much: "is the upstream
// template this session was last handed still the SAME template, at
// the SAME requested difficulty".
//
// The rule, in order:
//
//  1. Read the CURRENT upstream template's own job_id, for whichever
//     connection route the CACHED job (if any) belongs to, via
//     s.server.jobs.currentTemplateJobIDForRoute(route) -- a pure,
//     side-effect-free read, no nonce/ID allocated (see this
//     function's own "DEV-FEE ROUTING NOTE" below for why this must
//     be route-aware, not always the primary connection's template).
//  2. If that job_id is EMPTY (some pool dialects never publish
//     job_id at all -- confirmed possible, see UpstreamJobPayload.
//     JobID's own omitempty tag), caching is UNSAFE: an empty id can
//     never distinguish "same template" from "genuinely different
//     template", so this ALWAYS falls through to minting a fresh job
//     via NextJob -- exactly matching upstream.go's applyJob dupe
//     guard's own identical empty-job_id-can-never-dedupe rule (see
//     that function's doc comment), kept consistent here rather than
//     inventing a different rule for the same underlying ambiguity.
//  3. Otherwise, under jobCacheMu: if s.cachedJob is non-nil AND
//     s.cachedJob.UpstreamJobID equals the current template's job_id
//     AND s.cachedJob.StaticDifficulty equals the requested
//     difficulty, return the EXISTING s.cachedJob UNCHANGED -- no
//     NextJob call, no new nonce/ID minted, no job-history slot
//     burned. This is the actual fix: a redundant getjob poll, or a
//     vardiff tick that didn't change anything, now costs nothing.
//  4. Otherwise (template genuinely changed, OR requested difficulty
//     genuinely changed, OR no cached job yet): call NextJob, store
//     the result as the new s.cachedJob, and return it.
//
// maybeRetarget (vardiff.go) routes through this too even though
// leaflib.ComputeRetarget only reports changed=true on a genuine
// difficulty change (so in practice this will almost always mint
// fresh there, matching XNP's own !miner.newDiff gate -- a genuine
// retarget always forces a new job) -- doing so keeps a single,
// consistent code path for every production caller and costs nothing
// extra.
//
// DEV-FEE ROUTING NOTE (DISPATCH_BRIEF.md "leaf-proxy dev-fee
// second-connection"): the cache-validity check above is deliberately
// keyed against whichever connection the CACHED job itself belongs to
// (s.cachedJob.Route), via JobManager.currentTemplateJobIDForRoute --
// NOT always the primary connection's template. The primary and
// dev-fee connections' own upstream templates change completely
// independently of one another (different pools' own job cadence),
// so validating a possibly-dev-fee-routed cached job against the
// PRIMARY's template job_id would be simply wrong: it could either
// falsely invalidate a still-good dev-fee job (primary's job_id
// happened to change, dev-fee's didn't) or, worse, falsely keep
// serving a now-stale dev-fee job (primary's job_id happened to stay
// the same while dev-fee's own template moved on). When s.cachedJob
// is nil (nothing cached yet), route defaults to RoutePrimary purely
// so the very first currentTemplateJobIDForRoute call has a
// well-defined route to ask about -- this has no effect on which
// connection NextJob ultimately mints from below, since NextJob makes
// that decision itself via its own selector call, independent of
// this cache-validity check.
func (s *Session) currentJob(difficulty uint64) (*Job, error) {
	s.jobCacheMu.Lock()
	defer s.jobCacheMu.Unlock()

	route := RoutePrimary
	if s.cachedJob != nil {
		route = s.cachedJob.Route
	}
	templateJobID, ok := s.server.jobs.currentTemplateJobIDForRoute(route)
	if ok && templateJobID != "" && s.cachedJob != nil && s.cachedJob.UpstreamJobID == templateJobID && s.cachedJob.StaticDifficulty == difficulty {
		// No template yet, or this pool dialect never publishes
		// job_id (ok==false or templateJobID==""): caching is
		// unsafe/impossible for a job on this route -- falls through
		// to minting fresh below, exactly like the pre-dev-fee
		// behavior did.
		return s.cachedJob, nil
	}

	job, err := s.server.jobs.NextJob(difficulty)
	if err != nil {
		return nil, err
	}
	s.cachedJob = job
	return job, nil
}

const defaultProxySessionJobHistorySize = 8

// maxProxyLoginLen bounds the downstream login string's length (Fix
// 8, DISPATCH_BRIEF.md 2026-09-10) -- mirrors solo's
// maxLoginAddressLen exactly (internal/leaflib/solo/address.go),
// chosen for the same reason: a generous multiple of any real
// Tari/Monero wallet address's actual length (well under 200 bytes
// even in their longest real encodings), while still bounding the
// practical exposure of an arbitrary/adversarial login string
// becoming session state, a ban-cache lookup key, a Prometheus label
// value, or stats-HTML content.
const maxProxyLoginLen = 512

func newSession(mc *leaflib.ManagedConnection, server *Server, startingDifficulty uint64, port string) *Session {
	id, err := newRandomHexID()
	if err != nil {
		id = "0000000000000000"
	}
	s := &Session{
		mc:          mc,
		server:      server,
		sessionID:   id,
		Port:        port,
		connectedAt: time.Now(),
		jobs:        leaflib.NewJobHistory[*Job](defaultProxySessionJobHistorySize),
	}
	s.address.Store("")
	s.worker.Store("")
	s.currentDifficulty.Store(startingDifficulty)
	s.invalidShareGuard = leaflib.NewInvalidShareGuard(server.invalidShareGuardConfig)
	return s
}

// Run is the session's read loop.
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
// categories metrics.Metrics.ConnectionErrorsTotal exposes — mirrors
// internal/leaflib/solo/session.go's identically-named function and
// its exact category mapping (see that function's doc comment for the
// full per-branch rationale, which applies identically here: nil ->
// remote-eof, a net.Error with Timeout()==true -> idle-timeout,
// bufio.ErrTooLong -> protocol-error, anything else -> other).
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
		s.server.logger.Printf("proxy: session %s sent unparseable message, dropping: %v", s.sessionID, err)
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

func (s *Session) handleLogin(req Request) {
	var login LoginRequest
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &login); err != nil {
			s.server.recordLoginRejection(metrics.LoginRejectionReasonInvalidParams)
			s.writeGeneralResponse(req.ID, fmt.Sprintf("invalid login params: %v", err), "")
			return
		}
	}
	if login.Login == "" {
		s.server.recordLoginRejection(metrics.LoginRejectionReasonEmptyAddress)
		s.writeGeneralResponse(req.ID, "invalid address provided, please use a valid address", "")
		return
	}

	// Fix 8 (DISPATCH_BRIEF.md 2026-09-10): impose a sane maximum
	// length on the downstream login string BEFORE it becomes
	// session state, a ban-cache lookup key
	// (s.server.addressFlags.Get below), a Prometheus label value
	// (metrics recorded against this session's address), or
	// stats-HTML content. Unlike solo/direct (session.go's
	// ValidateAddressForAlgo), leaf-proxy does not itself decode
	// this string as a Tari/Monero address -- it is forwarded
	// as-is to whichever real upstream pool this leaf is configured
	// against, and that upstream's own real address format is not
	// necessarily known here -- so this is deliberately just a
	// length bound, not a format/charset validator (see
	// maxProxyLoginLen's own doc comment for why 512 is a safe,
	// generous choice). Checked as early as possible, right after
	// the "non-empty" check above and before any other use of the
	// string, so an oversized login is rejected with a clean error
	// response rather than ever touching a map/label/cache.
	if len(login.Login) > maxProxyLoginLen {
		s.server.logger.Printf("proxy: rejecting login with an oversized login string (%d bytes, max %d) from session %s", len(login.Login), maxProxyLoginLen, s.sessionID)
		s.server.recordLoginRejection(metrics.LoginRejectionReasonOversizedLogin)
		s.writeGeneralResponse(req.ID, "invalid address provided: too long", "")
		return
	}

	// REAL enforcement point for the manual ban system -- mirrors
	// solo.Session's/direct.Session's own identical handleLogin
	// check exactly (see internal/leaflib/addressflags's package doc
	// comment for the full rationale). Checked and rejected BEFORE
	// the address is stored/loggedIn is flipped and BEFORE any job is
	// fetched -- a banned address never becomes this session's
	// payout address for any purpose, and never receives a job
	// template. Nil s.server.addressFlags (the default -- see
	// EnableAddressFlags' doc comment) means every address is
	// treated as unflagged, identical to this feature not existing
	// at all.
	// Fix 7 (DISPATCH_BRIEF.md 2026-09-10): the floor half of the
	// addressflags pattern -- mirrors solo.Session's identical
	// handleLogin capture exactly (see internal/leaflib/solo/
	// session.go's handleLogin doc comment for the full rationale).
	// Captured BEFORE the address/loggedIn are stored, alongside the
	// ban check above, so a forced floor is known before this
	// session's very first job is ever fetched.
	var forcedFloor uint64
	if s.server.addressFlags != nil {
		flags := s.server.addressFlags.Get(login.Login)
		if flags.Banned {
			s.server.logger.Printf("proxy: rejecting login for banned address %s (session %s)", login.Login, s.sessionID)
			s.server.recordBanRejection(metrics.BanRejectionPhaseLogin)
			s.server.recordLoginRejection(metrics.LoginRejectionReasonBanned)
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
	s.loggedIn.Store(true)

	// A forced minimum difficulty always wins over the port tier's
	// own configured starting difficulty -- mirrors solo.Session's
	// identical handleLogin logic exactly (see that function's doc
	// comment for the full rationale).
	startDiff := s.currentDifficulty.Load()
	if global := s.server.vardiff.MinDifficulty; global > startDiff {
		startDiff = global
	}
	if forcedFloor > 0 {
		s.forcedMinDifficulty.Store(forcedFloor)
		if forcedFloor > startDiff {
			startDiff = forcedFloor
		}
	}

	// DISPATCH_BRIEF.md 2026-09-13 (Alex, "cap starting/min difficulty
	// to the pool's own target_diff"): none of the three floors folded
	// into startDiff above may exceed what the upstream pool is
	// CURRENTLY actually asking for on the template that's live right
	// now (WorkerTemplate.TargetDiff, the same target_diff field an
	// ordinary miner receives -- see Job.UpstreamShareDiff's doc
	// comment for the exact provenance). This is a ONE-TIME cap, at
	// login only: it deliberately does NOT change forcedMinDifficulty
	// itself (still stores the operator's raw, uncapped floor above,
	// for maybeRetarget's own ongoing floor-enforcement job, which is
	// explicitly out of scope for this change -- see vardiff.go's
	// maybeRetarget) and does NOT touch cfg.minDifficulty's own
	// configured value either -- only this session's own STARTING
	// currentDifficulty is capped down. If there's genuinely no
	// template yet (ok==false) or this pool dialect published a zero
	// target_diff, there is no pool diff to cap against -- skip the
	// cap entirely rather than inventing one, mirroring
	// currentTargetDiffForRoute's own doc comment.
	//
	// DISPATCH_BRIEF.md 2026-09-13 (Alex, toggle): this entire cap
	// block is now gated behind s.server.poolDiffCapEnabled (default
	// true -- see Server.poolDiffCapEnabled's own doc comment).
	// Disabled, this falls through to exactly the pre-flag
	// (pre-46a6e2c) max()-of-floors behavior, byte-identical.
	if s.server.poolDiffCapEnabled {
		if poolTargetDiff, ok := s.server.jobs.currentTargetDiffForRoute(RoutePrimary); ok && poolTargetDiff > 0 && startDiff > poolTargetDiff {
			startDiff = poolTargetDiff
		}
	}

	s.currentDifficulty.Store(startDiff)

	job, err := s.currentJob(s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("proxy: failed to get job for session %s: %v", s.sessionID, err)
		s.server.recordLoginRejection(metrics.LoginRejectionReasonNoJobTemplate)
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
	job, err := s.currentJob(s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("proxy: failed to get job for session %s: %v", s.sessionID, err)
		s.writeGeneralResponse(req.ID, "no job template available yet, retry shortly", "")
		return
	}
	s.pushJob(job)
}

// handleSubmit implements the real "submit" method for a downstream
// RandomX/XMR miner. This is the core of leaf-proxy's local
// re-validation contract.
//
// REAL PRODUCTION BUG FIX (this session, Alex's repeated job-staleness
// reports): the real, expensive RandomX re-validation call
// (s.server.validator.ValidateBlobSeedResult, ~258ms/hash pure-Go —
// see internal/leaflib/validator/randomx_puregolang.go's own doc
// comment for the full cost rationale) used to run UNCONDITIONALLY on
// every submit that passed the cheap ownership/expiry/nonce checks —
// BEFORE the claimed difficulty was even derived, let alone compared
// against job.StaticDifficulty/job.UpstreamShareDiff. That contradicts
// randomx_puregolang.go's own documented design contract for this
// leaf ("leaf-proxy... only calls its Validator's
// ValidateBlobSeedResult when a downstream miner's claimed share
// ALREADY meets the real upstream pool's BLOCK-level target") and the
// maintainer's own explicit authorization quoted there ("It /only/
// needs to verify before sending it upstream"). At real per-share
// submit rates (observed: roughly one accepted share every 0.4-0.5s
// from a single CPU miner), a ~258ms synchronous stall on this
// session's single read-loop goroutine on EVERY share is easily long
// enough to let a burst of already-queued miner submits land against
// a job that has since aged out by the time the stall clears —
// producing exactly the observed "several rejects, all in the same
// millisecond, against one stale job_id" pattern. Fixed by reordering
// so the expensive call only runs for a genuine upstream-forward
// candidate; see step 9 below and its own comment for the exact new
// rule. Ordering also cross-checked against XNP's own real reference
// implementation (xmr-node-proxy's lib/xmr.js, processShare): XNP
// derives hashDiff from the CLAIMED result first (no real hash
// computed yet), compares it against blockTemplate.targetDiff
// (block-level) and job.difficulty (own configured difficulty)
// BEFORE ever running its own real hash computation, and only
// actually computes+verifies the real hash in the branch where
// hashDiff already meets the block-level target — i.e. the exact
// cheap-comparisons-before-expensive-verification, and
// expensive-verification-gated-on-block-level-target-only, shape this
// fix restores here.
//
//  1. SECURITY: session-ownership check on job_id FIRST (s.ownJob) —
//     identical structural guarantee to leaf-solo's job-ownership fix
//     (internal/leaflib/solo/session.go's doc comment): a submit
//     against another session's job_id is rejected before any PoW
//     validation runs, because there is no shared data structure by
//     which another session's job_id could even be looked up here.
//  2. Real per-job expiry (job max age), independent of upstream
//     template invalidation.
//  3. REAL ban re-check at submit time (not just login time) —
//     mirrors solo.Session's/direct.Session's own identical addition
//     exactly (see solo/session.go's handleSubmit doc comment for the
//     full rationale). Checked against the address actually stored on
//     this session, before any real validation work. Ordered here,
//     immediately after job-ownership/expiry and before the
//     generation-staleness check below, matching solo/direct's own
//     stated "job-ownership/expiry checks first, then this ban
//     re-check, then everything else" convention literally — this
//     check has no dependency on upstream generation state, so it
//     costs nothing to run first.
//  4. REAL PRODUCTION BUG FIX (this session, confirmed live log
//     evidence of "upstream submit failed... share does not meet
//     configured difficulty or is cryptographically invalid" tens of
//     seconds after a real upstream reconnect): upstream-template
//     GENERATION staleness (job.TemplateGeneration vs. the upstream
//     client's own CurrentGeneration(), via the optional
//     UpstreamGenerationSource capability — see that interface's doc
//     comment in server.go). A Job minted against a template from a
//     since-superseded upstream-connection generation (the upstream
//     pool connection dropped and reconnected since this Job was
//     issued) is rejected locally here — cheaply, before any
//     nonce/difficulty/RandomX-validation work below, and BEFORE ever
//     contacting upstream — rather than uselessly forwarded to a pool
//     that has already discarded the old session/job state and would
//     only reject it anyway. Fails OPEN (this check is skipped
//     entirely) when the concrete upstream doesn't implement
//     UpstreamGenerationSource at all. If a submit is BOTH from a
//     banned address AND against a stale generation, step 3 above
//     already rejected it first (either reason is independently
//     sufficient — see TestHandleSubmit_BannedAddressAndStaleGeneration_BothReject
//     in session_test.go).
//  5. Decode the miner's claimed 4-byte nonce (real Monero-family
//     wire convention: 8 hex chars — CONFIRMED DIFFERENT from Tari
//     SHA3X/C29's 8-BYTE/16-hex-char nonce already used elsewhere in
//     this codebase) and write it into this job's own
//     worker-nonce-partitioned blob at the real block_header nonce
//     offset (blockheader.go) — this constructs the actual bytes a
//     real RandomX hash would be computed over.
//  6. Real per-job used-nonce tracking (replay rejection).
//  7. Real difficulty DERIVATION from the miner's already-received,
//     UNVERIFIED claimed hash (difficulty.go's littleEndianDifficulty,
//     the same well-known CryptoNote/RandomX target/difficulty
//     relationship already used for Tari's RXT elsewhere in this
//     codebase) — this is a pure computation over bytes the miner
//     already sent in submit.Result; it requires NO RandomX call at
//     all, and is what determines whether the expensive real
//     verification below is even worth running.
//  8. Reject outright, with NO RandomX call spent, if that claimed
//     difficulty doesn't even meet this session's own
//     configured/vardiff share difficulty (job.StaticDifficulty): a
//     share that fails its own requested-difficulty check is rejected
//     on that basis alone, regardless of whether the underlying PoW
//     would even be valid.
//  9. THE CORE LEAF-PROXY BEHAVIOR, and the exact gate this fix
//     restores: the real, expensive local RandomX re-validation via
//     the already-merged RandomXValidator (s.server.validator) is
//     called ONLY when the claimed difficulty ALSO meets or exceeds
//     the job's real upstream pool-requested share difficulty
//     (Job.UpstreamShareDiff — the SAME target_diff field an ordinary
//     miner receives on login/getjob, confirmed directly from the
//     real pool-server source; NOT a network/block-level target,
//     which this leaf has no visibility into and does not need for
//     this purpose) — i.e. only for a genuine "about to forward
//     upstream" candidate, per the maintainer's explicit rule quoted
//     above. A share that only meets the session's own configured
//     share difficulty is credited LOCALLY ONLY (this session's own
//     shareCount/vardiff accept-history) and NEVER forwarded
//     upstream, WITHOUT ever calling ValidateBlobSeedResult at all —
//     this is the real behavior change this fix makes (previously the
//     validator was called for this case too, and its result simply
//     discarded once the upstream-forward decision was made). If the
//     real re-validation of a genuine upstream-forward candidate
//     fails or errors, the submit is rejected outright — a share
//     claiming to meet the upstream target but failing real
//     re-validation is genuinely suspect and is never silently
//     downgraded to a local-only credit.
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

	s.server.debugLogger.Debugf("proxy: submit received: session=%s job_id=%s nonce=%s result=%s", s.sessionID, submit.JobID, submit.Nonce, submit.Result)

	job, ok := s.ownJob(submit.JobID)
	if !ok {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("unknown or stale job_id: %s", submit.JobID))
		return
	}

	if maxAge := s.server.jobMaxAge; maxAge > 0 {
		if age := time.Since(job.CreatedAt); age > maxAge {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("job expired: job_id %s was issued %s ago (max age %s)", submit.JobID, age.Round(time.Second), maxAge))
			return
		}
	}

	// REAL ban re-check at submit time, not just login time -- mirrors
	// solo.Session's/direct.Session's own identical addition exactly
	// (see solo/session.go's handleSubmit doc comment for the full
	// rationale: a session can log in before an address is banned, or
	// get banned mid-session by an operator; login-time-only
	// enforcement would let an already-connected botnet keep
	// submitting shares indefinitely after being banned). Checked
	// against the address ACTUALLY stored on this session
	// (s.address), not whatever the miner claims now. Runs BEFORE any
	// real validation work (nonce decode, blob construction,
	// difficulty derivation, the real RandomX re-validation call) --
	// mirrors solo/direct's exact ordering: job-ownership/expiry
	// checks first, then this ban re-check, then everything else
	// (including the stale-generation check immediately below --
	// deliberately placed second: this check has no dependency on
	// the upstream template's generation at all, and checking a
	// locally-known ban state before consulting the upstream client's
	// generation counter is strictly cheaper and matches solo/direct's
	// own "ban re-check right after job-ownership/expiry" ordering
	// literally, without needing any exception for this leaf).
	//
	// Ordering note (both real, both-legitimate fixes; see this
	// repo's rebase reconciliation for #85/f2bfa0b): if a submit is
	// BOTH from a now-banned address AND against a stale upstream
	// template generation, THIS check wins and its rejection message
	// is what the miner sees -- see
	// TestHandleSubmit_BannedAddressAndStaleGeneration_BothReject in
	// session_test.go, which pins this down explicitly. Either
	// rejection reason is independently sufficient; the ban check is
	// ordered first only because it was already the established
	// solo/direct convention this leaf mirrors, not because either
	// fix's own rationale requires it ahead of the other.
	if s.server.addressFlags != nil {
		if flags := s.server.addressFlags.Get(s.address.Load().(string)); flags.Banned {
			s.server.logger.Printf("proxy: rejecting submit for now-banned address %s (session %s)", s.address.Load(), s.sessionID)
			s.server.recordBanRejection(metrics.BanRejectionPhaseSubmit)
			s.writeShareResponse(req.ID, false, "this address is banned from this pool")
			return
		}
	}

	// REAL PRODUCTION BUG FIX: reject a submit whose Job was minted
	// against an upstream-connection generation that has since been
	// superseded by a real reconnect (upstream.go's reconnectLoop) —
	// see this function's own doc comment (step 4) and
	// server.go's UpstreamGenerationSource doc comment for the full
	// rationale. Fails OPEN (skips this check entirely, matching
	// pre-fix behavior exactly) when the concrete upstream doesn't
	// implement UpstreamGenerationSource at all -- this must never
	// become a hard requirement of UpstreamSubmitter itself. Checked
	// here, after the ban re-check above but still well before any
	// nonce/difficulty/RandomX-validation work below and before ever
	// contacting upstream (this fix's own explicit ordering
	// requirement), and — critically — before the async randomxPool
	// dispatch further down: a stale-generation submit is rejected
	// SYNCHRONOUSLY on this read loop, never handed to the async
	// pool needlessly.
	//
	// DEV-FEE ROUTING: resolved via s.server.upstreamForRoute(job.Route)
	// -- job.Route (job.go) already records which connection (the
	// primary, or the optional dev-fee one) this Job was actually
	// minted from, so this generation check (and the eventual
	// SubmitShare forward below) is always checked against that SAME
	// connection's own live generation counter, never the other
	// connection's.
	if gs, ok := s.server.upstreamForRoute(job.Route).(UpstreamGenerationSource); ok {
		if current := gs.CurrentGeneration(); job.TemplateGeneration < current {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("job's upstream template generation is stale (this leaf's upstream connection has reconnected since this job was issued) -- job_id %s", submit.JobID))
			return
		}
	}

	// Real Monero-family submit nonce convention: 8 hex chars = 4
	// raw bytes (proxy.js's `nonceCheck = /^[0-9a-f]{8}$/`) — NOT the
	// 8-byte/16-hex-char convention this codebase's SHA3X/C29 leaf-
	// solo uses.
	nonceHex := strings.ToLower(submit.Nonce)
	if len(nonceHex) != 8 {
		s.writeShareResponse(req.ID, false, "nonce must be 4 bytes, hex-encoded (8 hex characters)")
		return
	}
	nonceBytes, err := hex.DecodeString(nonceHex)
	if err != nil {
		s.writeShareResponse(req.ID, false, "nonce is not valid hex")
		return
	}
	nonce := binary.BigEndian.Uint32(nonceBytes)

	if !job.MarkNonceUsed(nonce) {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("duplicate nonce: %s", nonceHex))
		return
	}

	fullBlob, err := writeMinerNonce(job.Blob, nonce)
	if err != nil {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("could not locate nonce field in template: %v", err))
		return
	}

	// Cheap difficulty DERIVATION from the miner's already-received,
	// UNVERIFIED claimed hash — no RandomX call required at all, and
	// what determines whether the expensive real verification below
	// is even worth running (see this function's own doc comment,
	// steps 7-9, and randomx_puregolang.go's documented contract).
	claimedHash, err := hex.DecodeString(submit.Result)
	if err != nil {
		s.writeShareResponse(req.ID, false, "claimed result is not valid hex")
		return
	}
	diff, err := littleEndianDifficulty(claimedHash)
	if err != nil {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("difficulty derivation error: %v", err))
		return
	}

	if diff < job.StaticDifficulty {
		// Below the session's OWN requested/configured difficulty:
		// reject on that basis alone, with NO RandomX call spent
		// verifying a share that would be rejected regardless of
		// whether the underlying PoW is even valid.
		s.writeShareResponse(req.ID, false, "share does not meet configured difficulty")
		return
	}

	if job.UpstreamShareDiff == 0 || diff < job.UpstreamShareDiff {
		// Below the real upstream pool's own requested share
		// difficulty (Job.UpstreamShareDiff — the same target_diff
		// field an ordinary miner receives, NOT a network/block-level
		// target): credited locally only, per the maintainer's
		// explicit rule ("we only submit shares upstream when a
		// miner share > the pool's requested diff") — NEVER forwarded
		// upstream, and — THE REAL FIX — WITHOUT ever calling the
		// expensive s.server.validator.ValidateBlobSeedResult at all,
		// matching randomx_puregolang.go's documented contract
		// exactly (this leaf only re-validates a genuine
		// upstream-forward candidate).
		//
		// See s.hashesAccumulated's own doc comment (FIX_BRIEF.md,
		// finding #16) for the explicit caveat this implies: the
		// s.hashesAccumulated.Add call below credits this session's
		// (and this leaf's aggregate) hashrate stat purely from the
		// miner's own unvalidated claim.
		s.shareCount.Add(1)
		s.hashesAccumulated.Add(job.StaticDifficulty)
		s.server.recordShareDecision(false)
		s.writeShareResponse(req.ID, true, "")
		return
	}

	// Genuine upstream-forward candidate: claimed difficulty meets
	// or exceeds the real upstream pool's own requested share
	// difficulty. THIS is the only case that pays the real, ~258ms
	// pure-Go RandomX re-validation cost (s.server.validator.
	// ValidateBlobSeedResult) — see this function's doc comment and
	// randomx_puregolang.go's documented contract. A share that
	// fails real re-validation here is rejected outright, never
	// silently downgraded to a local-only credit: it claimed to meet
	// the upstream target, and this leaf could not itself confirm
	// that claim.
	//
	// PERFORMANCE FIX: this ~258ms pure-Go RandomX re-validation call
	// used to run INLINE, synchronously, right here in Session.Run's
	// read loop -- see internal/leaflib/solo/asyncvalidation.go's
	// package doc comment for the full production incident this same
	// class of bug caused for leaf-solo/leaf-direct's own
	// network-backed RandomXValidator (~4ms+/call there; pure-Go
	// RandomX here is ~258ms/call, an even larger stall). A slow
	// validation on one downstream session's genuine upstream-forward
	// candidate would otherwise block that SAME session's read loop
	// from ever reading its next submitted line until the call
	// returned. finishSubmit captures everything from here to the
	// end of this method -- including the real upstream forward via
	// s.server.upstream.SubmitShare, leaf-proxy's own genuinely
	// different post-validation behavior vs. solo/direct (neither of
	// which have an upstream to forward to) -- so the forward call
	// happens on the SAME worker goroutine as its own validation,
	// strictly after it completes, never lost or reordered relative
	// to other submits from this session (each closure carries its
	// own captured req.ID/job/diff/nonceHex, and s.server.upstream is
	// safe for concurrent use across sessions/goroutines -- see
	// UpstreamClient's own doc comment).
	//
	// Dispatched onto s.server.randomxPool -- the SAME
	// internal/leaflib/solo.AsyncValidationPool type solo/direct
	// already use (reused directly, not reimplemented -- see
	// server.go's randomxPool field doc comment), a small, bounded,
	// server-wide worker pool. Every piece of per-session/per-job
	// mutable state finishSubmit touches is already safe under
	// genuine concurrent execution: job.MarkNonceUsed already ran
	// synchronously above, before dispatch; s.shareCount/
	// s.blockCount/s.hashesAccumulated are atomic; Job's own fields
	// (UpstreamJobID/WorkerNonce/PoolNonce/Height/ID/StaticDifficulty)
	// are never mutated after issuance; s.mc.Write is already
	// synchronized onto the connection's single writer goroutine
	// (connection.go). Nothing here needed a NEW lock.
	finishSubmit := func() {
		valid, err := s.server.validator.ValidateBlobSeedResult(context.Background(), fullBlob, job.SeedHash, submit.Result)
		s.server.debugLogger.Debugf("proxy: validation attempt: session=%s job_id=%s valid=%v err=%v", s.sessionID, job.ID, valid, err)
		if err != nil {
			s.writeShareResponse(req.ID, false, fmt.Sprintf("validation error: %v", err))
			return
		}
		if !valid {
			// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b):
			// a fabricated above-(upstream-)target claim that fails
			// this real re-validation is the actual DoS vector
			// Finding 2 identified for this leaf too -- track it
			// against this session's own leaflib.InvalidShareGuard
			// (see that type's doc comment) and disconnect once it
			// exceeds its configured consecutive-invalid-share
			// threshold, so it can no longer keep flooding
			// s.server.randomxPool with garbage. leaf-proxy had NO
			// equivalent accounting mechanism at all before this fix
			// (unlike solo/direct's pre-existing s.trust.RecordOutcome
			// for their own RXT/RXM rejections).
			disconnect := s.invalidShareGuard.RecordOutcome(false)
			s.writeShareResponse(req.ID, false, "share is not a cryptographically valid RandomX proof for this job")
			if disconnect {
				s.server.logger.Printf("proxy: disconnecting session %s (address %s): exceeded consecutive invalid-share threshold", s.sessionID, s.address.Load())
				s.mc.Close("exceeded consecutive invalid-share threshold")
			}
			return
		}
		s.invalidShareGuard.RecordOutcome(true)

		// Real, cryptographically re-validated genuine upstream-forward
		// candidate: local credit (this is the vardiff accept-history
		// signal too — same shape as leaf-solo's
		// s.hashesAccumulated.Add(job.StaticDifficulty)), then forward it
		// upstream for real, via the real pool submit RPC -- still on
		// this same worker goroutine, off the read loop, so it can
		// never get lost or reordered relative to validation itself.
		s.shareCount.Add(1)
		s.hashesAccumulated.Add(job.StaticDifficulty)
		s.server.recordShareDecision(true)

		// Fix 10 (DISPATCH_BRIEF.md 2026-09-10): the pre-dispatch
		// CurrentGeneration() check above (before this closure was
		// ever queued onto s.server.randomxPool) only guards against
		// a generation that had ALREADY advanced at the moment this
		// submit was first read. If the upstream connection
		// reconnects WHILE this candidate sits in the pool's bounded
		// queue (real, possible: real RandomX re-validation above
		// takes ~258ms, and the queue itself can hold up to
		// AsyncValidationQueueSize entries under load), the
		// generation check above is now stale by the time we get
		// here -- a real TOCTOU gap between "checked" and "used".
		// Re-check immediately before the real upstream forward
		// call, using the SAME UpstreamGenerationSource capability
		// (fails open identically when the concrete upstream doesn't
		// implement it, matching the pre-dispatch check's own
		// fail-open contract exactly) -- if the generation has
		// advanced since job was issued, reject LOCALLY rather than
		// wasting a real round-trip against a dead/superseded
		// upstream session (see UpstreamGenerationSource's own doc
		// comment for why that costs this leaf's invalid-share/ban
		// ratio upstream). Route-resolved via upstreamForRoute
		// (job.Route), exactly like the pre-dispatch check above.
		submitter := s.server.upstreamForRoute(job.Route)
		if gs, ok := submitter.(UpstreamGenerationSource); ok {
			if current := gs.CurrentGeneration(); job.TemplateGeneration < current {
				s.writeShareResponse(req.ID, false, fmt.Sprintf("job's upstream template generation went stale while queued for validation (this leaf's upstream connection reconnected) -- job_id %s", submit.JobID))
				return
			}
		}

		accepted, err := submitter.SubmitShare(context.Background(), job.UpstreamJobID, nonceHex, submit.Result, job.WorkerNonce, job.PoolNonce)
		s.server.debugLogger.Debugf("proxy: upstream forward: session=%s upstream_job_id=%s nonce=%s result=%s worker_nonce=%v pool_nonce=%v -> accepted=%v err=%v", s.sessionID, job.UpstreamJobID, nonceHex, submit.Result, job.WorkerNonce, job.PoolNonce, accepted, err)
		if err != nil {
			s.server.logger.Printf("proxy: upstream submit failed for session %s (job %s, height %d): %v", s.sessionID, job.ID, job.Height, err)
			s.server.recordBlock(false)
			s.writeShareResponse(req.ID, false, fmt.Sprintf("upstream submit failed: %v", err))
			return
		}

		s.blockCount.Add(1)
		s.server.logger.Printf("proxy: share forwarded upstream by session %s (address %s) at height %d, upstream job %s, diff %d, accepted=%v", s.sessionID, s.address.Load(), job.Height, job.UpstreamJobID, diff, accepted)
		s.server.recordBlock(true)
		s.writeShareResponse(req.ID, true, "")
	}

	// HARDENING FIX (FIX_BRIEF.md, finding #15): TrySubmit, NOT Submit
	// -- this call runs directly on Session.Run's own read loop
	// (handleSubmit is called synchronously from it), so a blocking
	// Submit here would let one saturated/flooding session's own
	// dispatch block every OTHER session's next read-loop iteration
	// too, once the shared, server-scoped pool's bounded queue and
	// every worker are simultaneously busy -- see
	// solo/session.go's/direct/session.go's identical change for the
	// full rationale.
	if ok := s.server.randomxPool.TrySubmit(finishSubmit); !ok {
		// Pool already stopped (server shutting down), OR its bounded
		// queue is genuinely saturated and every worker is busy right
		// now -- respond with a real rejection rather than leaving
		// this submit unanswered or blocking this read loop waiting
		// for room (mirrors solo.Session's/direct.Session's identical
		// dispatch-failure handling exactly).
		s.writeShareResponse(req.ID, false, "validation pool is saturated or shutting down, please retry")
	}
}

func (s *Session) recordJob(job *Job) {
	if job == nil {
		return
	}
	s.jobs.Record(job.ID, job)
}

// ownJob returns the Job matching id ONLY IF it was actually issued
// to THIS session — see the Session type's job-ownership doc comment.
func (s *Session) ownJob(id string) (*Job, bool) {
	return s.jobs.Own(id)
}

// writeGeneralResponse/writeShareResponse always use the object/null
// wire shape (leaflib.IsLegacyWireAlgo's "legacy" branch is for
// ALGO_C29/ALGO_SHA3X only, and leaf-proxy speaks nothing but
// Monero-family RandomX — see this package's doc comment), so legacy
// is hardcoded false here — mirrors solo.Session's/direct.Session's
// own delegation to leaflib.WriteGeneralResponse/WriteShareResponse
// exactly (see leaflib/wireshape.go's doc comment), just with no real
// algo branch to make for this leaf mode.
func (s *Session) writeGeneralResponse(id int, errMsg, result string) {
	leaflib.WriteGeneralResponse(s.writeJSON, false, id, errMsg, result)
}

func (s *Session) writeShareResponse(id int, accepted bool, errMsg string) {
	// Fix 9 (DISPATCH_BRIEF.md 2026-09-10): every submit outcome
	// (share or block, accepted or rejected) flows through this
	// single response-writing helper -- mirrors solo.Session's/
	// direct.Session's own identical recordShare hook exactly (see
	// solo/session.go's writeShareResponse doc comment).
	s.server.recordShare(accepted)
	s.server.debugLogger.Debugf("proxy: submit result: session=%s accepted=%v reason=%q", s.sessionID, accepted, errMsg)
	leaflib.WriteShareResponse(s.writeJSON, false, id, accepted, errMsg)
}

func (s *Session) writeJSON(v any) {
	leaflib.WriteJSON(s.mc, s.server.logger, "proxy", s.sessionID, v)
}

func (s *Session) pushJob(job *Job) {
	leaflib.PushJob(s.writeJSON, s.loggedIn.Load(), func() any { return s.jobPayload(job) })
}

// jobPayload builds the real wire job object for job, and — the
// single choke point at which job is recorded into THIS session's own
// job history (see ownJob's doc comment): every caller (handleLogin's
// LoginResponse, pushJob's JobPush) already goes through this before
// putting a job on the wire.
func (s *Session) jobPayload(job *Job) JobPayload {
	s.recordJob(job)
	// Record what was actually delivered, mirroring solo.Session's/
	// direct.Session's identical jobPayload bookkeeping exactly --
	// see lastDeliveredJobID's doc comment. Every caller of
	// jobPayload is putting job on the wire to THIS session right
	// now, so this is the single correct place to update it.
	s.lastDeliveredJobID.Store(job.ID)
	s.lastDeliveredDifficulty.Store(job.StaticDifficulty)
	payload := JobPayload{
		// "rx/0" is the real wire algo string a real Monero-family
		// pool/miner actually uses (confirmed from the real pool-server
		// source, nodejs-pool-sxmr's lib/pool.js: `newJob.algo =
		// "rx/0"`) -- NOT "rxm" (that string is this repo's own
		// internal poolpb.Algo protobuf enum name, ALGO_RXM, meaning
		// "RandomX-Monero-family" at the schema level; it was never
		// meant to leak onto the real miner-facing wire protocol as a
		// literal algo string, and SXMR mines plain Monero RandomX,
		// not a Tari-specific merge-mined target -- caught live,
		// 2026-08-22).
		Algo:   "rx/0",
		Blob:   hex.EncodeToString(job.Blob),
		Height: job.Height,
		JobID:  job.ID,
		Target: leaflib.DiffToTargetHex(job.StaticDifficulty),
	}
	if len(job.SeedHash) > 0 {
		payload.SeedHash = hex.EncodeToString(job.SeedHash)
	}
	return payload
}
