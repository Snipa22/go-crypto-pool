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
func (j *Job) MarkNonceUsed(nonce uint32) (firstUse bool) {
	j.nonceMu.Lock()
	defer j.nonceMu.Unlock()
	if j.usedNonces == nil {
		j.usedNonces = make(map[uint32]struct{})
	}
	if _, seen := j.usedNonces[nonce]; seen {
		return false
	}
	j.usedNonces[nonce] = struct{}{}
	return true
}

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
}

// NewJobManager constructs a JobManager over source (a real
// UpstreamClient in production, a fake TemplateSource in tests).
func NewJobManager(source TemplateSource, logger *log.Logger) *JobManager {
	if logger == nil {
		logger = log.Default()
	}
	return &JobManager{source: source, logger: logger}
}

// currentTemplateJobID reports the current upstream template's OWN
// job_id (WorkerTemplate.JobID) WITHOUT allocating a new Job or
// burning any worker-/pool-nonce — a pure, side-effect-free read,
// mirroring XNP's own getJob() check of `activeBlockTemplate.id`
// (lib/xmr.js) before deciding whether miner.cachedJob can be reused.
// Returns ("", false) if no upstream template has been published yet
// (jm.source.CurrentTemplate() == nil) — Session.currentJob treats
// that identically to "cannot cache" and falls through to NextJob,
// which will itself return ErrNoUpstreamTemplate in that case.
func (jm *JobManager) currentTemplateJobID() (id string, ok bool) {
	t := jm.source.CurrentTemplate()
	if t == nil {
		return "", false
	}
	return t.JobID, true
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
func (jm *JobManager) NextJob(difficulty uint64) (*Job, error) {
	t := jm.source.CurrentTemplate()
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
