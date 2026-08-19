// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
)

// Job is one refreshed unit of mineable work: a real Tari SHA3X block
// template (with a coinbase already attached paying the leaf's solo
// payout address) plus the static difficulty miners must meet for a
// "share" to count, and the real network target difficulty a share must
// meet to actually BE a full block (at which point SubmitBlock is
// called for real). There is one global Job shared by every connected
// miner in this pass — see cmd/leaf-solo's doc comment: solo mode has no
// per-miner coinbase/payout splitting, everything found pays the single
// configured solo address.
type Job struct {
	ID     string
	Height uint64

	// Header is the merge-mining-hash pre-image material the real
	// GetHeaderDiff/SHA3XValidator hashes alongside the submitted nonce
	// — see validator.SHA3XValidator's doc comment and
	// go-tari-sha3x-solo-stratum's SubmitJob call site
	// (GetHeaderDiff(header, MergeMiningHash)). This is
	// Result.MergeMiningHash, not the serialized block header.
	Header []byte

	// StaticDifficulty is the leaf-configured share difficulty (vardiff
	// is explicitly out of scope for this pass — see LEAF_SOLO_DIFFICULTY
	// in cmd/leaf-solo/main.go).
	StaticDifficulty uint64

	// NetworkTargetDifficulty is the real difficulty a share's hash must
	// meet to constitute a full, submittable block, taken directly from
	// the base node's MinerData.TargetDifficulty for this template.
	NetworkTargetDifficulty uint64

	// Result is the full real GRPC response this job was built from —
	// Result.Block is what gets mutated (Header.Nonce) and submitted via
	// NodeClient.SubmitBlock when a share meets NetworkTargetDifficulty.
	Result *tari_generated.GetNewBlockResult

	CreatedAt time.Time
}

// JobManagerConfig configures a JobManager.
type JobManagerConfig struct {
	Node NodeClient

	// PayoutAddress is where found-block coinbase rewards go (solo
	// mode's only payout destination — see cmd/leaf-solo's doc comment).
	PayoutAddress string

	// StaticDifficulty is the fixed per-share difficulty every job is
	// stamped with. Vardiff is explicitly deferred; see Job's doc
	// comment.
	StaticDifficulty uint64

	// RefreshInterval is how often a brand new block template is fetched
	// unconditionally, regardless of tip movement.
	RefreshInterval time.Duration

	// TipPollInterval is how often the chain tip is polled so a new
	// template can be fetched immediately when someone else finds a
	// block, instead of waiting out the full RefreshInterval on a stale
	// template.
	TipPollInterval time.Duration

	Logger *log.Logger
}

// JobManager owns the current Job, refreshing it on a timer and
// immediately on tip movement, and fans out newly-refreshed jobs to
// subscribers (miner sessions) via OnNewJob.
type JobManager struct {
	cfg JobManagerConfig

	mu         sync.RWMutex
	current    *Job
	lastHeight uint64

	refreshMu sync.Mutex // serializes concurrent refresh attempts

	subMu sync.RWMutex
	subs  map[uint64]func(*Job)
	subID uint64

	logger *log.Logger
}

// NewJobManager constructs a JobManager. Call Start to begin the
// refresh/tip-poll loops; call Refresh directly (e.g. from tests) for a
// single synchronous fetch.
func NewJobManager(cfg JobManagerConfig) *JobManager {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 30 * time.Second
	}
	if cfg.TipPollInterval <= 0 {
		cfg.TipPollInterval = 5 * time.Second
	}
	return &JobManager{
		cfg:    cfg,
		subs:   make(map[uint64]func(*Job)),
		logger: logger,
	}
}

// Current returns the most recently refreshed Job, or nil if none has
// been fetched yet.
func (jm *JobManager) Current() *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.current
}

// GetJob returns the job matching id, if it is still the current job or
// was recently current. This implementation only tracks the single most
// recent job (solo mode's simplified single-global-job model — see
// Job's doc comment), so a submission against a job that has already
// been superseded is reported as not-found, prompting the caller to
// request a fresh job.
func (jm *JobManager) GetJob(id string) (*Job, bool) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	if jm.current != nil && jm.current.ID == id {
		return jm.current, true
	}
	return nil, false
}

// Subscribe registers fn to be called with every newly-refreshed Job.
// Returns an unsubscribe function.
func (jm *JobManager) Subscribe(fn func(*Job)) (unsubscribe func()) {
	jm.subMu.Lock()
	id := jm.subID
	jm.subID++
	jm.subs[id] = fn
	jm.subMu.Unlock()
	return func() {
		jm.subMu.Lock()
		delete(jm.subs, id)
		jm.subMu.Unlock()
	}
}

func (jm *JobManager) notify(job *Job) {
	jm.subMu.RLock()
	defer jm.subMu.RUnlock()
	for _, fn := range jm.subs {
		fn(job)
	}
}

// Start launches the periodic refresh and tip-poll loops. It returns
// immediately; both loops run until ctx is cancelled.
func (jm *JobManager) Start(ctx context.Context) {
	go jm.refreshLoop(ctx)
	go jm.tipPollLoop(ctx)
}

func (jm *JobManager) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(jm.cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := jm.Refresh(ctx); err != nil {
				jm.logger.Printf("solo: periodic job refresh failed: %v", err)
			}
		}
	}
}

func (jm *JobManager) tipPollLoop(ctx context.Context) {
	ticker := time.NewTicker(jm.cfg.TipPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tip, err := jm.cfg.Node.GetTipInfo(ctx)
			if err != nil {
				jm.logger.Printf("solo: tip poll failed: %v", err)
				continue
			}
			if tip == nil || tip.GetMetadata() == nil {
				continue
			}
			height := tip.GetMetadata().GetBestBlockHeight()
			jm.mu.RLock()
			last := jm.lastHeight
			jm.mu.RUnlock()
			if height > last {
				jm.logger.Printf("solo: new tip detected (height %d -> %d), refreshing job", last, height)
				if _, err := jm.Refresh(ctx); err != nil {
					jm.logger.Printf("solo: tip-triggered job refresh failed: %v", err)
				}
			}
		}
	}
}

// Refresh synchronously fetches a fresh block template, builds a new
// Job, stores it as current, and notifies subscribers. Safe to call
// directly (e.g. once at startup before Start, or from tests).
func (jm *JobManager) Refresh(ctx context.Context) (*Job, error) {
	jm.refreshMu.Lock()
	defer jm.refreshMu.Unlock()

	result, err := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress)
	if err != nil {
		return nil, fmt.Errorf("solo: GetBlockTemplate: %w", err)
	}
	if result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return nil, fmt.Errorf("solo: GetBlockTemplate returned an incomplete result")
	}

	id, err := newJobID()
	if err != nil {
		return nil, fmt.Errorf("solo: generating job id: %w", err)
	}

	job := &Job{
		ID:                      id,
		Height:                  result.GetBlock().GetHeader().GetHeight(),
		Header:                  result.GetMergeMiningHash(),
		StaticDifficulty:        jm.cfg.StaticDifficulty,
		NetworkTargetDifficulty: result.GetMinerData().GetTargetDifficulty(),
		Result:                  result,
		CreatedAt:               time.Now(),
	}

	jm.mu.Lock()
	jm.current = job
	if job.Height > jm.lastHeight {
		jm.lastHeight = job.Height
	}
	jm.mu.Unlock()

	jm.notify(job)
	return job, nil
}

func newJobID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
