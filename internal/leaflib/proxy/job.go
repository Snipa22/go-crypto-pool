// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Job is one downstream-miner-facing unit of work: a real upstream
// pool block template, worker-nonce-partitioned (template.go) for
// THIS specific job issuance, plus the local share difficulty the
// issuing session's own vardiff currently wants and the real upstream
// job_id/target needed to forward a genuine block-level find. There is
// no single global Job shared by every downstream miner — every
// login/getjob/vardiff-repush call allocates a BRAND NEW worker-nonce
// from the current WorkerTemplate (see JobManager.NextJob), so no two
// issued jobs, across ANY downstream session, ever share a search
// space for the lifetime of the current upstream template.
type Job struct {
	// ID is the real miner-facing job_id this leaf hands to its OWN
	// downstream miner — a random, locally-generated identifier
	// (NOT the upstream pool's own job_id, which is tracked
	// separately as UpstreamJobID and is what actually gets echoed
	// back on an upstream submit).
	ID string

	// Blob is THIS job's own worker-nonce-partitioned copy of the
	// upstream template's blob (WorkerTemplate.BlobForWorker's
	// output) — what actually goes on the wire as the miner-facing
	// "blob".
	Blob []byte

	// WorkerNonce is the 4-byte value written into Blob at the
	// upstream-pool-published offset for this specific job issuance.
	WorkerNonce uint32

	// PoolNonce is the 4-byte pool-level nonce value written into
	// Blob at the upstream-pool-published PoolOffset (client_pool_
	// offset) for this specific job issuance — the POOL-level peer
	// of WorkerNonce above. Ported exactly from the real reference's
	// getMasterJob (lib/xmr.js): it calls
	// `activeBlockTemplate.blobForWorker()` (which increments and
	// bakes the pool nonce into the blob about to be handed out),
	// THEN immediately captures that exact same value,
	// `activeBlockTemplate.poolNonce`, into `localData.poolNonce`
	// alongside the job's own masterJobID in a per-worker circular
	// buffer — so that later, on submit, Pool.sendShare can look the
	// job back up by id and echo back the EXACT poolNonce value that
	// was baked into THAT SPECIFIC job's blob delivery (not some
	// global/current template value, which could have since moved on
	// to a different job's issuance). This field is this leaf's
	// equivalent of that captured localData.poolNonce — see
	// JobManager.NextJob for where it is allocated/captured, and
	// session.go's handleSubmit for where it is echoed back on
	// upstream submit.
	PoolNonce uint32

	// UpstreamJobID is the upstream pool's OWN job_id for the
	// template this Job was derived from — required to forward a
	// share upstream (UpstreamClient.SubmitShare's job_id param).
	UpstreamJobID string

	// Route records which upstream connection (devfee.go's
	// UpstreamRoute) this Job's UpstreamJobID/TemplateGeneration/
	// SeedHash/Height/UpstreamShareDiff fields above were actually
	// drawn from — RoutePrimary unless the dev-fee mechanism is
	// enabled AND was genuinely selected for this specific issuance
	// (see JobManager.NextJob's own doc comment for the exact rule,
	// including its fail-open-to-primary fault-isolation guarantee).
	// session.go's handleSubmit uses this to resolve which
	// UpstreamSubmitter/UpstreamGenerationSource to re-check/forward
	// this Job's eventual submit against (Server.upstreamForRoute) —
	// this is what makes the dev-fee mechanism's core correctness
	// requirement hold: a submit routed to the dev-fee connection is
	// ALWAYS validated/submitted against that SAME connection's own
	// template, never the primary's (see the DISPATCH_BRIEF.md
	// requirement this field exists to satisfy).
	Route UpstreamRoute

	// TemplateGeneration captures which upstream-CONNECTION
	// generation (WorkerTemplate.Generation, at the moment this Job
	// was minted — see that field's doc comment for the full
	// root-cause citation) this Job's underlying upstream template
	// belongs to. Its SOLE purpose is letting session.go's
	// handleSubmit reject a submit whose Job predates the CURRENT
	// live generation before ever forwarding it upstream — fixing a
	// real, confirmed production issue: when the upstream pool
	// connection drops and reconnects
	// (upstream.go's reconnectLoop), any in-flight downstream miner
	// submit whose Job was minted against the OLD (now-gone) upstream
	// template still passes this leaf's own local job-ownership check
	// (session.go's ownJob) and, without this field, would get
	// forwarded upstream via UpstreamClient.SubmitShare regardless —
	// where the pool (having discarded that old session/job state on
	// disconnect) correctly rejects it as "share does not meet
	// configured difficulty or is cryptographically invalid",
	// wastefully spending an upstream round-trip on a submit this
	// leaf could and should have known was hopeless. Repeated
	// invalid-share submits like that risk exactly the kind of
	// ban-threshold/invalid-share-ratio enforcement this codebase's
	// own doc comments already describe elsewhere for a real upstream
	// pool (nodejs-pool's real banPercent/banThreshold mechanism).
	//
	// Deliberately NOT derived from a job_id string comparison alone:
	// a reconnect always produces a new upstream job_id from THIS
	// leaf's own applyJob dupe-guard's perspective (see that
	// function's doc comment), but an upstream pool COULD in
	// principle reuse job_id space across a reconnect under some
	// other dialect this leaf doesn't yet support — job_id string
	// equality is not a substitute for a real, monotonic
	// connection-generation counter.
	TemplateGeneration uint64

	SeedHash []byte
	Height   uint64

	// StaticDifficulty is this session's OWN current vardiff share
	// difficulty at the moment this Job was issued/restamped — see
	// internal/leaflib/solo/job.go's Job.StaticDifficulty doc comment
	// for the exact same "despite the name, this tracks a live
	// per-session vardiff value, not a fixed configured constant"
	// caveat, which applies identically here.
	StaticDifficulty uint64

	// UpstreamShareDiff is the real upstream pool's OWN requested
	// share difficulty for this template — taken directly from the
	// upstream pool's own published target_diff field, the exact
	// same target_diff every ordinary miner receives on login/getjob
	// (confirmed directly from the real pool-server source,
	// nodejs-pool-sxmr's lib/pool.js: `target_diff: this.difficulty`
	// — this.difficulty there IS the pool's own per-connection
	// requested share difficulty, nothing more).
	//
	// This is NOT a claim about network/block-level difficulty —
	// this leaf has no visibility into that and does not need it for
	// this purpose. What it IS used for: the maintainer's explicit
	// rule is "we only submit shares upstream when a miner share >
	// the pool's requested diff" — a downstream submit whose real,
	// locally-recomputed difficulty meets or exceeds
	// UpstreamShareDiff is worth forwarding upstream via a real
	// "submit" RPC (see session.go's handleSubmit); below it, the
	// share is credited to the submitting session's own local
	// stats/vardiff only and is never forwarded.
	UpstreamShareDiff uint64

	CreatedAt time.Time

	// nonceMu/usedNonces implement per-job used-nonce tracking,
	// mirroring internal/leaflib/solo/job.go's identical mechanism —
	// a miner replaying the same nonce twice must not be credited
	// twice.
	nonceMu    sync.Mutex
	usedNonces map[uint32]struct{}
}

// MarkNonceUsed records nonce as spent against this job and reports
// whether it was newly recorded (true) or already used (false — a
// replay that must be rejected without being credited again).
//
// Fix 11 (DISPATCH_BRIEF.md 2026-09-10): capped at
// maxTrackedNoncesPerJob distinct entries -- see that constant's own
// doc comment for the reasoning. A REPLAY of an already-tracked nonce
// is always still detected correctly (the "already seen" check below
// runs BEFORE the cap check, so an already-tracked entry never stops
// being recognized once the cap is reached) -- only genuinely NEW
// nonces beyond the cap are rejected (also via a false return, i.e.
// treated identically to a replay by every existing caller: neither
// case is worth crediting).
func (j *Job) MarkNonceUsed(nonce uint32) (firstUse bool) {
	j.nonceMu.Lock()
	defer j.nonceMu.Unlock()
	if j.usedNonces == nil {
		j.usedNonces = make(map[uint32]struct{})
	}
	if _, seen := j.usedNonces[nonce]; seen {
		return false
	}
	if len(j.usedNonces) >= maxTrackedNoncesPerJob {
		return false
	}
	j.usedNonces[nonce] = struct{}{}
	return true
}

// maxTrackedNoncesPerJob bounds how many distinct nonce values
// MarkNonceUsed will ever track for a single Job (Fix 11,
// DISPATCH_BRIEF.md 2026-09-10). Without this bound, a hostile miner
// submitting an unbounded stream of distinct (but otherwise
// cheaply-constructed) nonce values against one job -- each one
// passing this cheap pre-check regardless of whether the underlying
// share is genuine -- could grow this map without limit for that
// job's lifetime, since nothing else in this leaf's own job-lifecycle
// bounds it (a Job's own lifetime is governed by upstream template
// churn/session job-history size, not this map).
//
// 100,000 is chosen as generous-but-bounded: a real, honest miner
// submits, at most, a small multiple of its own real hash rate over
// the time a single upstream job stays current (typically single-
// digit to low-tens-of-seconds before a fresh upstream template
// supersedes it -- see upstream.go's applyJob) -- nowhere close to
// six figures of DISTINCT nonces against ONE job. At ~4 bytes/key
// plus Go map overhead, 100,000 entries is a small, fixed memory
// bound (a few MB at most) regardless of how long any one job is
// somehow kept alive.
const maxTrackedNoncesPerJob = 100_000

// ErrNoUpstreamTemplate is returned by JobManager.NextJob when the
// upstream client has not yet received a job from the real pool
// (e.g. immediately after Connect, before the login response's
// nested job has been applied — should not happen in practice since
// Connect only returns success after a job has been applied, but
// guarded here defensively for any future caller that constructs a
// JobManager against an UpstreamClient that hasn't connected yet).
var ErrNoUpstreamTemplate = errors.New("proxy: no upstream block template available yet")

// TemplateSource is the real upstream job source a JobManager draws
// from — internal/leaflib/proxy.UpstreamClient implements this ON THE
// REAL, LIVE upstream pool connection; tests supply a fake for
// deterministic, offline unit coverage (see job_test.go/server_test.go)
// without hitting any real network.
type TemplateSource interface {
	CurrentTemplate() *WorkerTemplate
	Subscribe(fn func(*WorkerTemplate)) func()
}

// JobManager issues per-downstream-session Jobs from the current
// upstream WorkerTemplate, allocating a fresh, genuinely
// non-overlapping worker-nonce for every single issuance (see
// WorkerTemplate.NextBlobForWorker) — this is leaf-proxy's
// counterpart to internal/leaflib/solo/job.go's JobManager, but
// drawing its templates from a real upstream POOL connection instead
// of a real Tari base node GRPC connection.
type JobManager struct {
	source TemplateSource
	logger *log.Logger

	// devFeeSource/devFeeSelect back the optional developer-fee
	// mechanism (devfee.go, DISPATCH_BRIEF.md "leaf-proxy dev-fee
	// second-connection") — both are nil unless EnableDevFee has been
	// called (cmd/leaf-proxy/main.go only calls it when
	// -dev-fee-percent > 0), which is the exact same "nil is a
	// complete no-op" convention this codebase already uses
	// throughout (debugLogger, addressFlags, etc.): NextJob below
	// never even evaluates devFeeSelect when devFeeSource is nil, so
	// leaving this unset costs this hot path nothing beyond one
	// extra nil-check.
	devFeeSource TemplateSource
	devFeeSelect func(time.Time) bool
}

// NewJobManager constructs a JobManager over source (a real
// UpstreamClient in production, a fake TemplateSource in tests).
func NewJobManager(source TemplateSource, logger *log.Logger) *JobManager {
	if logger == nil {
		logger = log.Default()
	}
	return &JobManager{source: source, logger: logger}
}

// EnableDevFee opts this JobManager into the optional developer-fee
// mechanism: from this call onward, NextJob will consult selector on
// every issuance and, when it returns true AND devFeeSource currently
// has a live template, mint that Job from devFeeSource (tagged
// Job.Route = RouteDevFee) instead of the primary source. Intended
// caller: cmd/leaf-proxy/main.go, only when -dev-fee-percent > 0 (see
// devfee.go's NewDevFeeSelector for the production selector
// construction) — never called at all when the mechanism is disabled,
// which is what makes "-dev-fee-percent=0 is a complete no-op" hold
// structurally (this method, and therefore any dev-fee code path in
// NextJob below, is simply never reached).
func (jm *JobManager) EnableDevFee(devFeeSource TemplateSource, selector func(time.Time) bool) {
	jm.devFeeSource = devFeeSource
	jm.devFeeSelect = selector
}

// currentTemplateJobIDForRoute reports the current job_id of whichever
// connection route identifies (RoutePrimary -> jm.source, RouteDevFee
// -> jm.devFeeSource) WITHOUT allocating a new Job or burning any
// worker-/pool-nonce — a pure, side-effect-free read, mirroring XNP's
// own getJob() check of `activeBlockTemplate.id` (lib/xmr.js) before
// deciding whether miner.cachedJob can be reused. Returns ("", false)
// if that connection has no template yet (some pool dialects never
// publish job_id at all either — confirmed possible, see
// UpstreamJobPayload.JobID's own omitempty tag) — Session.currentJob
// treats that identically to "cannot cache" and falls through to
// NextJob, which will itself return ErrNoUpstreamTemplate if there is
// truly no template anywhere yet.
//
// This is Session.currentJob's per-session job cache's (session.go)
// dev-fee-aware validation primitive: it lets that cache check a
// cached Job against the SAME connection it was actually minted from
// — never the other one, which matters because the primary and
// dev-fee connections' own upstream templates change completely
// independently of each other. A route of RouteDevFee when
// jm.devFeeSource is nil (should not happen in practice: NextJob
// never tags a Job RouteDevFee unless devFeeSource was non-nil at
// mint time) falls back to the primary source, the same fail-safe
// direction every other dev-fee fault-isolation fallback in this file
// takes.
func (jm *JobManager) currentTemplateJobIDForRoute(route UpstreamRoute) (id string, ok bool) {
	source := jm.source
	if route == RouteDevFee && jm.devFeeSource != nil {
		source = jm.devFeeSource
	}
	t := source.CurrentTemplate()
	if t == nil {
		return "", false
	}
	return t.JobID, true
}

// currentTargetDiffForRoute reports the current upstream pool's own
// published target_diff for whichever connection route identifies
// (RoutePrimary -> jm.source, RouteDevFee -> jm.devFeeSource) --
// mirrors currentTemplateJobIDForRoute exactly (same pure,
// side-effect-free read, same route-resolution/fail-safe-to-primary
// rule -- see that method's doc comment), just surfacing
// WorkerTemplate.TargetDiff instead of JobID.
//
// DISPATCH_BRIEF.md 2026-09-13 (Alex, "cap starting/min difficulty to
// the pool's own target_diff"): this is session.go's handleLogin's
// choke point for finding out what the upstream pool is CURRENTLY
// asking for, at the moment a downstream session's starting
// difficulty is computed, so that value can never be capped-down
// against a stale/wrong number. Returns (0, false) if that connection
// has no template yet -- handleLogin treats that identically to "no
// pool diff known yet, don't invent one" and skips the cap entirely,
// exactly like currentTemplateJobIDForRoute's own ok==false/
// templateJobID=="" callers already do for the job-caching decision.
func (jm *JobManager) currentTargetDiffForRoute(route UpstreamRoute) (diff uint64, ok bool) {
	source := jm.source
	if route == RouteDevFee && jm.devFeeSource != nil {
		source = jm.devFeeSource
	}
	t := source.CurrentTemplate()
	if t == nil {
		return 0, false
	}
	return t.TargetDiff, true
}

// NextJob allocates a brand new Job at the given (session-owned)
// difficulty from the current upstream template, UNCONDITIONALLY --
// every single call burns a fresh worker-/pool-nonce pair and mints a
// brand-new random job_id, even if the caller's previous call was for
// the exact same session against the exact same, completely unchanged
// upstream template and difficulty. This is the correct, deliberate
// behavior for THIS low-level primitive -- it must remain unconditional
// because Session.currentJob (session.go) is what adds the actual
// caching/dedup discipline ON TOP of it (mirroring
// internal/leaflib/solo/job.go's JobManager.jobForXN/
// JobForXNAtDifficulty, which caches per-xn, and XNP's own getJob()
// (lib/xmr.js), which short-circuits on an unchanged
// activeBlockTemplate.id/!miner.newDiff via miner.cachedJob).
//
// BUG FIX CONTEXT (Alex, live production report, third occurrence of
// this bug class): before Session.currentJob existed, EVERY call site
// (handleLogin, handleGetJob, maybeRetarget, Server.repushAllSessions)
// called this method directly and unconditionally, so a redundant
// getjob poll or repush -- even with the upstream template and
// requested difficulty both completely unchanged -- still minted a
// brand-new job_id and burned a fresh slot in the session's bounded
// 8-entry job history (Session.recordJob), exhausting it far faster
// than genuine upstream job changes (~5-15s) could explain: a job
// accepted normally, then an immediate burst of 8 rejects against
// that SAME job_id in the same millisecond, only ~1.5s after a
// genuine new upstream job event. Production call sites now go
// through Session.currentJob instead; this method remains the
// correct, unconditional "always mint" primitive it always was --
// used internally by currentJob, and still used directly by tests
// that intentionally want that unconditional behavior (e.g.
// template_test.go/e2e_blob_size_test.go/session_test.go's
// TestSession_AlreadyDelivered_SameJobSameDifficultyIsDeliveredAgain,
// which needs two genuinely distinct job_ids to exercise
// alreadyDelivered directly). Do not add caching logic here -- add it
// to Session.currentJob instead.
//
// BOTH the
// worker-nonce and pool-nonce counters (WorkerTemplate's
// nextWorkerNonce/nextPoolNonce -- see those fields' doc comments)
// advance by exactly one on every call, via a SINGLE call to
// WorkerTemplate.NextBlobForWorkerAndPool -- which patches BOTH
// values into ONE COPY of the underlying raw buffer (RawBlob when
// present, Blob otherwise) BEFORE any RandomX hashing-blob conversion
// happens, then converts (if needed) exactly ONCE. This is
// deliberately NOT two separate calls (one allocating+patching the
// worker-nonce, a second allocating+patching the pool-nonce on top of
// the first's OUTPUT) -- that shape was a real, live production bug
// for the advanced-client (RawBlob != nil) dialect: the first call's
// output is already the small, converted RandomX hashing blob, but
// PoolOffset (like ReservedOffset/ClientNonceOffset) is only
// meaningful relative to the FULL raw blocktemplate_blob, so
// bounds-checking/writing it against that small output blob is
// simply wrong, confirmed live:
//
//	proxy: allocating pool-nonce job: proxy: worker-nonce offset is out
//	of range for this template's blob: offset=179 blob_len=76
//
// Matches the real reference's per-job-issuance cadence: getMasterJob's
// blobForWorker() (pool-nonce patch) and the nested
// BlockTemplate.nextBlob's workerNonce patch both write into the SAME
// underlying raw buffer before any convert_blob/hex call -- see
// WorkerTemplate.BlobForWorkerAndPool's doc comment for the full
// citation. Worker-nonce and pool-nonce remain deliberately
// independent counters (see WorkerTemplate.nextPoolNonce's doc
// comment for why), even though they both advance once per issuance
// here and are now patched together in a single pass.
//
// DEV-FEE ROUTING (DISPATCH_BRIEF.md "leaf-proxy dev-fee
// second-connection"): when EnableDevFee has been called, every call
// here first consults jm.devFeeSelect(time.Now()) -- see devfee.go's
// NewDevFeeSelector for the rolling-window mechanism this
// production-wires. If it reports true AND jm.devFeeSource currently
// has a live template (CurrentTemplate() != nil), THIS Job is minted
// from the dev-fee source instead of the primary one, and tagged
// Job.Route = RouteDevFee accordingly -- every field below
// (UpstreamJobID/TemplateGeneration/SeedHash/Height/UpstreamShareDiff)
// is then genuinely the DEV-FEE connection's own current values, never
// a mix of the two. If the selector says true but the dev-fee
// connection has NO template yet (e.g. still dialing/logging in, or
// lost its connection and hasn't reconnected) this FALLS BACK to the
// primary source and RoutePrimary instead of failing this job
// issuance outright -- the explicit fault-isolation requirement: a
// dev-fee connection outage must never degrade the primary path or
// any downstream miner session. When EnableDevFee was never called at
// all (jm.devFeeSource == nil, the default -- see that field's doc
// comment), none of this logic runs at all: this is byte-identical to
// the pre-dev-fee behavior, RoutePrimary, jm.source only.
func (jm *JobManager) NextJob(difficulty uint64) (*Job, error) {
	source := jm.source
	route := RoutePrimary
	if jm.devFeeSource != nil && jm.devFeeSelect != nil && jm.devFeeSelect(time.Now()) {
		if jm.devFeeSource.CurrentTemplate() != nil {
			source = jm.devFeeSource
			route = RouteDevFee
		}
		// else: dev-fee connection has no live template right now --
		// fall through to the primary source/RoutePrimary above
		// rather than returning ErrNoUpstreamTemplate for a job the
		// primary connection could perfectly well have served. This
		// is the fault-isolation guarantee: a dev-fee outage never
		// blocks a real downstream job issuance.
	}

	t := source.CurrentTemplate()
	if t == nil {
		return nil, ErrNoUpstreamTemplate
	}
	blob, workerNonce, poolNonce, err := t.NextBlobForWorkerAndPool()
	if err != nil {
		return nil, fmt.Errorf("proxy: allocating pool-nonce job: %w", err)
	}
	id, err := newRandomHexID()
	if err != nil {
		return nil, fmt.Errorf("proxy: generating job id: %w", err)
	}
	return &Job{
		ID:                 id,
		Blob:               blob,
		WorkerNonce:        workerNonce,
		PoolNonce:          poolNonce,
		UpstreamJobID:      t.JobID,
		Route:              route,
		TemplateGeneration: t.Generation,
		SeedHash:           t.SeedHash,
		Height:             t.Height,
		StaticDifficulty:   difficulty,
		UpstreamShareDiff:  t.TargetDiff,
		CreatedAt:          time.Now(),
	}, nil
}

// Subscribe forwards to the underlying TemplateSource's Subscribe,
// discarding the *WorkerTemplate argument — mirrors
// internal/leaflib/solo/job.go's JobManager.Subscribe(func()) shape,
// which Server.go uses to trigger a fresh per-session repush on every
// new upstream template (login result, getjob result, or an
// unsolicited push) without needing the template value itself (each
// session calls NextJob independently, at ITS OWN current vardiff
// difficulty).
func (jm *JobManager) Subscribe(fn func()) func() {
	return jm.source.Subscribe(func(*WorkerTemplate) { fn() })
}

// newRandomHexID mirrors internal/leaflib/solo/session.go's
// newSessionXN-adjacent random-id helper pattern: a cosmetic,
// non-consensus diagnostic identifier, collisions are not a security
// concern (session-level job ownership, not this ID's uniqueness, is
// the real security boundary — see session.go's ownJob).
func newRandomHexID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
