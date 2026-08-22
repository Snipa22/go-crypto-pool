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

	// UpstreamJobID is the upstream pool's OWN job_id for the
	// template this Job was derived from — required to forward a
	// genuine block-level find (UpstreamClient.SubmitShare's job_id
	// param).
	UpstreamJobID string

	SeedHash []byte
	Height   uint64

	// StaticDifficulty is this session's OWN current vardiff share
	// difficulty at the moment this Job was issued/restamped — see
	// internal/leaflib/solo/job.go's Job.StaticDifficulty doc comment
	// for the exact same "despite the name, this tracks a live
	// per-session vardiff value, not a fixed configured constant"
	// caveat, which applies identically here.
	StaticDifficulty uint64

	// UpstreamTargetDiff is the REAL block-level difficulty a
	// downstream submit's RandomX hash must meet for this to be a
	// genuine block find worth forwarding upstream (see
	// session.go's handleSubmit) — taken directly from the upstream
	// pool's own published target_diff for this template.
	UpstreamTargetDiff uint64

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

// NextJob allocates a brand new Job at the given (session-owned)
// difficulty from the current upstream template.
func (jm *JobManager) NextJob(difficulty uint64) (*Job, error) {
	t := jm.source.CurrentTemplate()
	if t == nil {
		return nil, ErrNoUpstreamTemplate
	}
	blob, workerNonce, err := t.NextBlobForWorker()
	if err != nil {
		return nil, fmt.Errorf("proxy: allocating worker-nonce job: %w", err)
	}
	id, err := newRandomHexID()
	if err != nil {
		return nil, fmt.Errorf("proxy: generating job id: %w", err)
	}
	return &Job{
		ID:                 id,
		Blob:               blob,
		WorkerNonce:        workerNonce,
		UpstreamJobID:      t.JobID,
		SeedHash:           t.SeedHash,
		Height:             t.Height,
		StaticDifficulty:   difficulty,
		UpstreamTargetDiff: t.TargetDiff,
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
