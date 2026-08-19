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
// called for real).
//
// IMPORTANT (see this package's per-xn extranonce support, added after
// a real production crash — the graxil GPU miner panicked on a missing
// "xn" field, and the maintainer clarified that "solo" means "single
// payout address", NOT "single miner": any number of miners can point
// at a solo leaf). There is NOT one global Job shared by every
// connected miner. Each connecting session is assigned its own random
// 2-byte extranonce (xn) once, at connect time (see session.go's
// newSession), and JobManager maintains one independently-generated Job
// per xn (see JobManager.perXN below) so that miners with different xn
// values search genuinely different, non-overlapping hash spaces —
// ported from go-tari-sha3x-solo-stratum's
// subsystems/blockTemplateCache/blockTemplate.go (GetBlockSha3 +
// GetBlockWithXN) and subsystems/poolStratum/miner.go (needsXN/xn
// assignment at connection-init, getJob/SendNewJob, the submit-time xn
// prefix check).
//
// This is NOT Bitcoin-style nonce-range slicing. It's a genuinely
// distinct-block-template split: NodeClient.GetBlockTemplate (node.go)
// already appends a fresh, randomly-generated 8-byte nonce buffer to
// the coinbase-extra field on every call (mirroring the legacy
// GetBlockSha3's `binary.LittleEndian.PutUint64(buf, rand.Uint64())`
// coinbase-extra randomization), so calling it once per newly-seen xn
// already yields a block whose MergeMiningHash pre-image genuinely
// differs from every other xn's template, even at the same height —
// see node.go's GetBlockTemplate doc comment. What JobManager adds here
// is the per-xn CACHING/reuse behavior on top of that: a given xn keeps
// getting served the SAME Job on repeat requests (consistent job_id
// across getjob calls, matching the legacy GetBlockWithXN's "this xn
// already claimed a cached template" behavior) until the whole cache is
// invalidated by tip movement.
type Job struct {
	// ID is the real miner-facing job_id: the first 16 hex characters
	// of hex(BlockHash) — ported exactly from
	// go-tari-sha3x-solo-stratum's minerTracking.GetJobJSON
	// (fmt.Sprintf("%x", job.BlockResult.BlockHash)[0:16]). This is
	// what goes on the wire in JobPayload.JobID and what miners echo
	// back in SubmitRequest.JobID.
	ID     string
	Height uint64

	// Header is the merge-mining-hash pre-image material the real
	// GetHeaderDiff/SHA3XValidator hashes alongside the submitted nonce
	// — see validator.SHA3XValidator's doc comment and
	// go-tari-sha3x-solo-stratum's SubmitJob call site
	// (GetHeaderDiff(header, MergeMiningHash)). This is
	// Result.MergeMiningHash, not the serialized block header. It is
	// also, hex-encoded, the wire "blob" field (see protocol.go's
	// JobPayload doc comment).
	Header []byte

	// BlockHash is the real header hash of the completed block
	// (Result.BlockHash) that ID is derived from. Kept alongside ID
	// (rather than discarded after deriving ID) purely for
	// debuggability/logging.
	BlockHash []byte

	// StaticDifficulty is the share difficulty this Job was stamped
	// with at generation time. Despite the name (kept for backward
	// compatibility with the field's original static-difficulty-only
	// meaning), this now holds whatever difficulty value was current
	// for the owning session at the moment the job was (re)generated
	// or restamped — see vardiff.go: each session's own per-connection
	// retarget loop can change its difficulty independently, and
	// JobManager.RestampDifficulty produces a fresh *Job (same ID/
	// Header/template, new StaticDifficulty) reflecting that change.
	// This is also the difficulty the wire "target" field
	// (protocol.go's JobPayload) is derived from — see diffToTarget in
	// session.go's jobPayload helper.
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

	// nonceMu/usedNonces implement per-job used-nonce tracking, ported
	// from go-tari-sha3x-solo-stratum's MinerJob.UsedNonces/NonceMutex
	// (minerTracking/structs.go) — a miner replaying the same nonce
	// twice must not be credited twice. Since every xn now gets its own
	// distinct Job (see type doc comment), this is naturally per-xn
	// too: two different miners with two different xns can legitimately
	// use the "same" raw nonce value against their own independent
	// templates without colliding.
	nonceMu    sync.Mutex
	usedNonces map[uint64]struct{}
}

// MarkNonceUsed records nonce as spent against this job and reports
// whether it was newly recorded (true) or already used (false, i.e.
// this is a replay that must be rejected without being credited
// again).
func (j *Job) MarkNonceUsed(nonce uint64) (firstUse bool) {
	j.nonceMu.Lock()
	defer j.nonceMu.Unlock()
	if j.usedNonces == nil {
		j.usedNonces = make(map[uint64]struct{})
	}
	if _, seen := j.usedNonces[nonce]; seen {
		return false
	}
	j.usedNonces[nonce] = struct{}{}
	return true
}

// JobManagerConfig configures a JobManager.
type JobManagerConfig struct {
	Node NodeClient

	// PayoutAddress is where found-block coinbase rewards go (solo
	// mode's only payout destination — see cmd/leaf-solo's doc comment).
	PayoutAddress string

	// StaticDifficulty is the DEFAULT/fallback difficulty JobForXN
	// stamps onto a newly-generated Job when no per-session difficulty
	// override is supplied. In production, every real caller now goes
	// through JobForXNAtDifficulty with the requesting session's own
	// current vardiff difficulty (see session.go's handleLogin/
	// handleGetJob and server.go's invalidateAndRepushJobs), so this
	// field is effectively only exercised by JobForXN callers that
	// don't care about a specific difficulty (tests, Probe-adjacent
	// code paths). Vardiff (per-session adaptive retargeting) is
	// implemented in vardiff.go; this field is NOT the "one true"
	// difficulty for every session anymore.
	StaticDifficulty uint64

	// RefreshInterval is how often the ENTIRE per-xn job cache is
	// unconditionally invalidated, regardless of tip movement, forcing
	// a fresh template (with fresh randomized coinbase data) to be
	// generated for every xn on its next request. Mirrors the legacy
	// UpdateBlockTemplateCache's periodic refresh.
	RefreshInterval time.Duration

	// TipPollInterval is how often the chain tip is polled so the
	// per-xn cache can be invalidated immediately when someone else
	// finds a block, instead of waiting out the full RefreshInterval on
	// stale templates.
	TipPollInterval time.Duration

	Logger *log.Logger
}

// JobManager maintains a per-xn cache of independently-generated block
// template Jobs (see Job's doc comment for why this replaced a single
// global Job), refreshing/invalidating that cache on a timer and
// immediately on tip movement, and notifies subscribers (Server) when
// an invalidation happens so already-connected sessions can be handed
// fresh, regenerated per-xn jobs instead of continuing to work a job
// for a tip that has already moved.
type JobManager struct {
	cfg JobManagerConfig

	mu       sync.RWMutex
	perXN    map[string]*Job // xn (hex string) -> that xn's current Job
	jobsByID map[string]*Job // job.ID -> Job, spanning every xn's current entry, for submit-time lookup

	// lastTipHeight is the most recently observed real chain-tip
	// height (from NodeClient.GetTipInfo), used purely to detect tip
	// movement in tipPollLoop. It is NOT the same thing as any
	// individual Job.Height (each xn's Job is fetched independently and
	// may observe a template at a very slightly different moment).
	lastTipHeight uint64
	tipObserved   bool // false until tipPollLoop's first successful GetTipInfo, so that first poll seeds a baseline instead of being misread as tip movement from a zero-value default

	genMu sync.Mutex // serializes concurrent new-template generation

	subMu sync.RWMutex
	subs  map[uint64]func()
	subID uint64

	logger *log.Logger
}

// NewJobManager constructs a JobManager. Call Start to begin the
// refresh/tip-poll loops; call JobForXN directly (e.g. from tests) for
// a single synchronous per-xn fetch.
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
		cfg:      cfg,
		perXN:    make(map[string]*Job),
		jobsByID: make(map[string]*Job),
		subs:     make(map[uint64]func()),
		logger:   logger,
	}
}

// JobForXN returns the current Job for the given per-session xn,
// generating and caching a brand new, independently-randomized block
// template the first time this xn is seen (or after the cache has been
// invalidated by tip movement/periodic refresh) — ported from
// go-tari-sha3x-solo-stratum's GetBlockWithXN. Repeat calls with the
// same xn against the same cache generation return the SAME Job
// (consistent job_id across getjob calls), matching the legacy
// behavior exactly. A newly-generated Job (first-time-seen xn, or the
// first request after invalidation) is stamped with
// JobManagerConfig.StaticDifficulty; callers that want a specific
// session's own current vardiff difficulty stamped instead should use
// JobForXNAtDifficulty.
func (jm *JobManager) JobForXN(ctx context.Context, xn string) (*Job, error) {
	return jm.jobForXN(ctx, xn, jm.cfg.StaticDifficulty)
}

// JobForXNAtDifficulty is JobForXN's per-session-vardiff-aware
// counterpart: if xn is not yet cached (first request, or the first
// request after an invalidation), the freshly-generated Job is stamped
// with difficulty instead of JobManagerConfig.StaticDifficulty. If xn
// is already cached, the EXISTING cached Job is returned as-is
// (matching JobForXN's "repeat requests get the same Job" contract) —
// this does NOT retroactively change an already-cached job's stamped
// difficulty; that is RestampDifficulty's job, called explicitly by a
// session's vardiff retarget (vardiff.go's maybeRetarget), not by every
// ordinary getjob/login call.
func (jm *JobManager) JobForXNAtDifficulty(ctx context.Context, xn string, difficulty uint64) (*Job, error) {
	return jm.jobForXN(ctx, xn, difficulty)
}

func (jm *JobManager) jobForXN(ctx context.Context, xn string, difficulty uint64) (*Job, error) {
	if job, ok := jm.lookupXN(xn); ok {
		return job, nil
	}

	// Serialize generation so concurrent first-requests for the same
	// (or different) xn don't race to fetch redundant templates; a
	// double-check after acquiring genMu keeps this cheap in the common
	// case where the xn is already cached.
	jm.genMu.Lock()
	defer jm.genMu.Unlock()

	if job, ok := jm.lookupXN(xn); ok {
		return job, nil
	}

	result, err := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress)
	if err != nil {
		return nil, fmt.Errorf("solo: GetBlockTemplate for xn %s: %w", xn, err)
	}
	if result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return nil, fmt.Errorf("solo: GetBlockTemplate returned an incomplete result for xn %s", xn)
	}

	id, err := jobIDFromBlockHash(result.GetBlockHash())
	if err != nil {
		return nil, fmt.Errorf("solo: deriving job id from block hash for xn %s: %w", xn, err)
	}

	job := &Job{
		ID:                      id,
		Height:                  result.GetBlock().GetHeader().GetHeight(),
		Header:                  result.GetMergeMiningHash(),
		BlockHash:               result.GetBlockHash(),
		StaticDifficulty:        difficulty,
		NetworkTargetDifficulty: result.GetMinerData().GetTargetDifficulty(),
		Result:                  result,
		CreatedAt:               time.Now(),
	}

	jm.mu.Lock()
	jm.perXN[xn] = job
	jm.jobsByID[job.ID] = job
	jm.mu.Unlock()

	return job, nil
}

// RestampDifficulty is vardiff.go's job-push mechanism: given that xn's
// CURRENTLY cached Job (block template, height, header — all unchanged,
// no new GRPC call needed), produce and cache a new *Job with the SAME
// ID/Height/Header/BlockHash/NetworkTargetDifficulty/Result but a NEW
// StaticDifficulty, replacing the old entry under both perXN[xn] and
// jobsByID[id] — mirroring go-tari-sha3x-solo-stratum's getJob(), which
// on every SendNewJob call constructs a brand new minerTracking.MinerJob
// (with a fresh, empty UsedNonces set) under the SAME jobLog[blockHash]
// key whenever the block hash/xn is unchanged, just with an updated
// Target field. If xn has no cached Job yet (a retarget firing before
// this session's first getjob/login, which in practice can't happen
// since a session always logs in before its vardiff loop can start —
// see vardiff.go's runVardiffLoop is only started after Run begins, and
// login is the first message any session sends), this falls back to
// generating a brand new one at the requested difficulty, exactly like
// JobForXNAtDifficulty would. If the cached Job's StaticDifficulty
// already equals difficulty, the existing Job is returned unchanged
// (no-op, no new cache entry) — callers (vardiff.go's maybeRetarget)
// are expected not to call this unless the retarget algorithm actually
// decided the difficulty changed, but this guard makes RestampDifficulty
// itself idempotent regardless.
func (jm *JobManager) RestampDifficulty(ctx context.Context, xn string, difficulty uint64) (*Job, error) {
	jm.mu.RLock()
	existing, ok := jm.perXN[xn]
	jm.mu.RUnlock()
	if !ok {
		return jm.jobForXN(ctx, xn, difficulty)
	}
	if existing.StaticDifficulty == difficulty {
		return existing, nil
	}

	restamped := &Job{
		ID:                      existing.ID,
		Height:                  existing.Height,
		Header:                  existing.Header,
		BlockHash:               existing.BlockHash,
		StaticDifficulty:        difficulty,
		NetworkTargetDifficulty: existing.NetworkTargetDifficulty,
		Result:                  existing.Result,
		CreatedAt:               existing.CreatedAt,
	}

	jm.mu.Lock()
	jm.perXN[xn] = restamped
	jm.jobsByID[restamped.ID] = restamped
	jm.mu.Unlock()

	return restamped, nil
}

func (jm *JobManager) lookupXN(xn string) (*Job, bool) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	job, ok := jm.perXN[xn]
	return job, ok
}

// GetJob returns the job matching id, searching across every xn's
// currently-cached entry (a submission is checked against whichever
// per-xn job produced that job_id, not a single global job — see Job's
// doc comment).
func (jm *JobManager) GetJob(id string) (*Job, bool) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	job, ok := jm.jobsByID[id]
	return job, ok
}

// InvalidateAll drops every cached per-xn Job, forcing the next
// JobForXN call for any xn to generate a brand new, independently
// randomized template. Called on tip movement (a block was found,
// possibly by an entirely different miner/xn — every previously-cached
// template height is now stale) and on the unconditional periodic
// refresh timer. Mirrors go-tari-sha3x-solo-stratum's GetBlockWithXN
// discard-stale-entries-at-read-time behavior, but eagerly: rather than
// filtering stale entries out one lookup at a time, the whole
// generation is invalidated up front so no session can be served a job
// for a tip that has already moved.
func (jm *JobManager) InvalidateAll() {
	jm.mu.Lock()
	jm.perXN = make(map[string]*Job)
	jm.jobsByID = make(map[string]*Job)
	jm.mu.Unlock()
	jm.notify()
}

// Probe performs a single, uncached GetBlockTemplate call purely to
// fail fast at startup if the base node is unreachable/misconfigured,
// mirroring main.go's previous "fetch initial block template" sanity
// check. The result is discarded — it is deliberately NOT cached under
// any xn, since with per-xn jobs there is no "the" initial job to seed;
// each session's first JobForXN call generates its own.
func (jm *JobManager) Probe(ctx context.Context) error {
	result, err := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress)
	if err != nil {
		return fmt.Errorf("solo: GetBlockTemplate probe: %w", err)
	}
	if result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return fmt.Errorf("solo: GetBlockTemplate probe returned an incomplete result")
	}
	return nil
}

// Subscribe registers fn to be called every time the per-xn job cache
// is invalidated (tip movement or periodic refresh). Callers (Server)
// use this to push freshly (re-)generated per-xn jobs out to every
// currently-connected, logged-in session. Returns an unsubscribe
// function.
func (jm *JobManager) Subscribe(fn func()) (unsubscribe func()) {
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

func (jm *JobManager) notify() {
	jm.subMu.RLock()
	defer jm.subMu.RUnlock()
	for _, fn := range jm.subs {
		fn()
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
			jm.logger.Printf("solo: periodic per-xn job cache invalidation")
			jm.InvalidateAll()
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
			last := jm.lastTipHeight
			observed := jm.tipObserved
			jm.mu.RUnlock()
			if !observed {
				// First successful tip observation: just seed the
				// baseline, don't treat it as "movement" (there is
				// nothing to have moved FROM yet).
				jm.mu.Lock()
				jm.lastTipHeight = height
				jm.tipObserved = true
				jm.mu.Unlock()
				continue
			}
			if height > last {
				jm.logger.Printf("solo: new tip detected (height %d -> %d), invalidating per-xn job cache", last, height)
				jm.mu.Lock()
				jm.lastTipHeight = height
				jm.mu.Unlock()
				jm.InvalidateAll()
			}
		}
	}
}

// jobIDFromBlockHash derives the real miner-facing job_id from a raw
// block hash — ported exactly from go-tari-sha3x-solo-stratum's
// minerTracking.GetJobJSON: fmt.Sprintf("%x", blockHash)[0:16], i.e.
// the first 16 HEX CHARACTERS (8 bytes' worth) of the hex-encoded raw
// hash, not the first 16 raw bytes.
func jobIDFromBlockHash(blockHash []byte) (string, error) {
	full := hex.EncodeToString(blockHash)
	if len(full) < 16 {
		return "", fmt.Errorf("block hash too short to derive a job id: got %d hex chars, need at least 16 (raw hash %d bytes)", len(full), len(blockHash))
	}
	return full[:16], nil
}

// newRandomHexID returns 8 cryptographically-random bytes, hex-encoded.
// Used for the per-connection session/login "id" the wire protocol
// hands a miner (LoginResult.ID in protocol.go) — unrelated to a job's
// real, block-hash-derived job_id (jobIDFromBlockHash above).
func newRandomHexID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// newSessionXN returns a fresh per-session extranonce (xn): 2
// cryptographically-random bytes, hex-encoded to a 4-character string
// — ported exactly from go-tari-sha3x-solo-stratum's miner.go
// connection-init (`buf := make([]byte, 8); binary.LittleEndian.
// PutUint64(buf, rand.Uint64()); m.xn = fmt.Sprintf("%x", buf[0:2])`):
// same size (2 bytes / 4 hex chars) and same "generated once per
// connection at accept time, not per-job" timing, just sourced from
// crypto/rand instead of math/rand since this package already uses
// crypto/rand for newRandomHexID above and there's no reason to pull in
// a second, weaker RNG for an adjacent purpose.
func newSessionXN() (string, error) {
	buf := make([]byte, 2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
