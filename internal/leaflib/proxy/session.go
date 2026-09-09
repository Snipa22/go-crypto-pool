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
	hashesAccumulated atomic.Uint64

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
//  1. Read the CURRENT upstream template's own job_id via
//     s.server.jobs.currentTemplateJobID() -- a pure, side-effect-free
//     read, no nonce/ID allocated.
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
func (s *Session) currentJob(difficulty uint64) (*Job, error) {
	templateJobID, ok := s.server.jobs.currentTemplateJobID()
	if !ok || templateJobID == "" {
		// No template yet, or this pool dialect never publishes
		// job_id: caching is unsafe/impossible -- always mint fresh.
		return s.server.jobs.NextJob(difficulty)
	}

	s.jobCacheMu.Lock()
	defer s.jobCacheMu.Unlock()

	if s.cachedJob != nil && s.cachedJob.UpstreamJobID == templateJobID && s.cachedJob.StaticDifficulty == difficulty {
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

func newSession(mc *leaflib.ManagedConnection, server *Server, startingDifficulty uint64) *Session {
	id, err := newRandomHexID()
	if err != nil {
		id = "0000000000000000"
	}
	s := &Session{
		mc:          mc,
		server:      server,
		sessionID:   id,
		connectedAt: time.Now(),
		jobs:        leaflib.NewJobHistory[*Job](defaultProxySessionJobHistorySize),
	}
	s.address.Store("")
	s.worker.Store("")
	s.currentDifficulty.Store(startingDifficulty)
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

	job, err := s.currentJob(s.currentDifficulty.Load())
	if err != nil {
		s.server.logger.Printf("proxy: failed to get job for session %s: %v", s.sessionID, err)
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
// candidate; see step 7 below and its own comment for the exact new
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
//  3. REAL PRODUCTION BUG FIX (this session, confirmed live log
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
//     UpstreamGenerationSource at all.
//  4. Decode the miner's claimed 4-byte nonce (real Monero-family
//     wire convention: 8 hex chars — CONFIRMED DIFFERENT from Tari
//     SHA3X/C29's 8-BYTE/16-hex-char nonce already used elsewhere in
//     this codebase) and write it into this job's own
//     worker-nonce-partitioned blob at the real block_header nonce
//     offset (blockheader.go) — this constructs the actual bytes a
//     real RandomX hash would be computed over.
//  5. Real per-job used-nonce tracking (replay rejection).
//  6. Real difficulty DERIVATION from the miner's already-received,
//     UNVERIFIED claimed hash (difficulty.go's littleEndianDifficulty,
//     the same well-known CryptoNote/RandomX target/difficulty
//     relationship already used for Tari's RXT elsewhere in this
//     codebase) — this is a pure computation over bytes the miner
//     already sent in submit.Result; it requires NO RandomX call at
//     all, and is what determines whether the expensive real
//     verification below is even worth running.
//  7. Reject outright, with NO RandomX call spent, if that claimed
//     difficulty doesn't even meet this session's own
//     configured/vardiff share difficulty (job.StaticDifficulty): a
//     share that fails its own requested-difficulty check is rejected
//     on that basis alone, regardless of whether the underlying PoW
//     would even be valid.
//  8. THE CORE LEAF-PROXY BEHAVIOR, and the exact gate this fix
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

	// REAL PRODUCTION BUG FIX: reject a submit whose Job was minted
	// against an upstream-connection generation that has since been
	// superseded by a real reconnect (upstream.go's reconnectLoop) —
	// see this function's own doc comment (step 3) and
	// server.go's UpstreamGenerationSource doc comment for the full
	// rationale. Fails OPEN (skips this check entirely, matching
	// pre-fix behavior exactly) when the concrete upstream doesn't
	// implement UpstreamGenerationSource at all -- this must never
	// become a hard requirement of UpstreamSubmitter itself.
	if gs, ok := s.server.upstream.(UpstreamGenerationSource); ok {
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
	// steps 5-7, and randomx_puregolang.go's documented contract).
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
	valid, err := s.server.validator.ValidateBlobSeedResult(context.Background(), fullBlob, job.SeedHash, submit.Result)
	if err != nil {
		s.writeShareResponse(req.ID, false, fmt.Sprintf("validation error: %v", err))
		return
	}
	if !valid {
		s.writeShareResponse(req.ID, false, "share is not a cryptographically valid RandomX proof for this job")
		return
	}

	// Real, cryptographically re-validated genuine upstream-forward
	// candidate: local credit (this is the vardiff accept-history
	// signal too — same shape as leaf-solo's
	// s.hashesAccumulated.Add(job.StaticDifficulty)), then forward it
	// upstream for real, via the real pool submit RPC.
	s.shareCount.Add(1)
	s.hashesAccumulated.Add(job.StaticDifficulty)
	s.server.recordShareDecision(true)
	accepted, err := s.server.upstream.SubmitShare(context.Background(), job.UpstreamJobID, nonceHex, submit.Result, job.WorkerNonce, job.PoolNonce)
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
