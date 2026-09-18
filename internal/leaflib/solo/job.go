// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
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
	// ID is the real miner-facing job_id: a purely random, opaque
	// wire token (see node.go's tariJobFromResult / monero_node.go's
	// GetBlockTemplate, both of which mint this via newRandomHexID).
	// This is what goes on the wire in JobPayload.JobID and what
	// miners echo back in SubmitRequest.JobID — nothing about its
	// VALUE is protocol-meaningful, and it must NEVER be derived from
	// BlockHash/prevHash/height/any other template content: a
	// content-derived ID was confirmed, in real production, to
	// collide across two genuinely different templates (see
	// monero_node.go's GetBlockTemplate doc comment for the full
	// incident writeup) while ALSO providing zero real
	// collision-avoidance benefit even when it happened not to
	// collide, since RestampDifficulty (below) deliberately reuses
	// the SAME ID for the SAME template on purpose whenever only
	// StaticDifficulty changes. This field previously held the first
	// 16 hex characters of hex(BlockHash) — ported from
	// go-tari-sha3x-solo-stratum's minerTracking.GetJobJSON
	// (fmt.Sprintf("%x", job.BlockResult.BlockHash)[0:16]) — that
	// content-derived scheme is what was replaced.
	ID     string
	Height uint64

	// Algo identifies which mining algorithm this Job's template was
	// fetched for (poolpb.Algo_ALGO_SHA3X or poolpb.Algo_ALGO_C29 as of
	// this pass — see JobManagerConfig.Algo). Every downstream
	// algo-aware decision (session.go's jobPayload wire "algo" label,
	// handleSubmit's nonce-byte-order/proof-shape/validator dispatch)
	// keys off THIS field, not any global/process-wide assumption, so
	// that a Job always self-describes which algo it actually is.
	Algo poolpb.Algo

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

	// TemplateData is the opaque, coin-specific payload the owning
	// NodeClient implementation populated this Job from — e.g. for
	// Tari (GRPCNodeClient/direct.NodeClient) this holds the full real
	// *tari_generated.GetNewBlockResult GRPC response; for Monero
	// (MoneroNodeClient) it holds that implementation's own
	// get_block_template response shape. Nothing in job.go/session.go
	// ever type-asserts this field directly — only the SAME NodeClient
	// implementation that populated it does so, inside its own
	// BuildCandidateBlock (see node.go). Tari's own RXT proof
	// construction (session.go's handleSubmit, needing the real
	// pow_data bytes to build the 76-byte mining blob) uses the
	// explicitly-named escape hatch TariPowDataFromJob (node.go)
	// instead of reaching into this field directly, keeping the
	// coin-agnostic shell (Job/JobManager/NodeClient interface) free of
	// any Tari-specific type assertion.
	TemplateData any

	// VmKey is the real RandomX seed/key for an ALGO_RXT job, taken
	// directly from GetNewBlockResult.VmKey (confirmed real field,
	// go-tari-grpc-lib/v3's base_node.pb.go — the base node's GRPC
	// response already provides this; leaf-solo does not derive it
	// itself). Empty/unused for SHA3X and C29 jobs. Surfaced on the wire
	// as JobPayload.SeedHash (protocol.go) and fed to
	// validator.RandomXValidator as poolpb.RandomXProof.SeedHash at
	// submit time (session.go's handleSubmit).
	VmKey []byte

	// ReservedOffset is the real Monero get_block_template
	// reserved_offset — the byte offset, within the RAW (unconverted)
	// blocktemplate_blob, of the reserve_size-byte area monerod set
	// aside for pool extranonce insertion into the coinbase tx (see
	// monero_node.go's GetBlockTemplate, which requests reserve_size:
	// 60 and now threads the daemon's own returned reserved_offset
	// through here instead of discarding it). Coin-agnostic field
	// placement mirrors VmKey/StaticDifficulty above: only ever
	// populated for ALGO_RXM jobs (monero_node.go's GetBlockTemplate);
	// every other algo (SHA3X/C29/RXT) leaves this at its zero value,
	// which is safe since it is only ever read when
	// job.Algo == poolpb.Algo_ALGO_RXM AND the reading session has
	// been detected as an XNP-class proxy client (see session.go's
	// jobPayload — protocol.go's JobPayload.ReservedOffset/
	// ClientNonceOffset/ClientPoolOffset are derived from this field
	// only in that case; an ordinary xmrig-class miner's job payload
	// never surfaces it at all).
	ReservedOffset int

	// ReservedOffsetUsable gates whether ReservedOffset (and its two
	// derived offsets, client_nonce_offset = ReservedOffset+12 and
	// client_pool_offset = ReservedOffset+8) are actually safe to
	// publish on the wire for an XNP-proxy-detected RXM session (see
	// session.go's jobPayload). monerod's own real get_block_template
	// response is authoritative for BOTH reserved_offset AND the
	// returned blocktemplate_blob's length, but nothing upstream of
	// monero_node.go's GetBlockTemplate ever cross-checks the two
	// against each other before this field was added — CONFIRMED, via
	// a real live leaf-proxy rejection this session
	// ("proxy: worker-nonce offset is out of range for this
	// template's blob: offset=179 blob_len=76"), that on a genuine
	// low-transaction-volume testnet block monerod can return a
	// ReservedOffset that does NOT actually fit within
	// ReservedOffset+12 <= len(blocktemplate_blob) for that same
	// response. GetBlockTemplate sets this false (default) whenever
	// that bounds check fails, and true only when the reservation
	// region has been verified in-bounds for THIS job's own real
	// blob. false is the safe default for every non-ALGO_RXM job too
	// (Job's zero value), matching the existing "ReservedOffset is
	// only ever populated for ALGO_RXM jobs" convention documented
	// above.
	//
	// This mirrors this codebase's existing "nil means not offered"
	// pointer-field convention (protocol.go's JobPayload.
	// ReservedOffset/ClientNonceOffset/ClientPoolOffset, and RXT's
	// own documented choice to deliberately leave ReservedOffset/
	// ClientPoolOffset nil — see session.go's jobPayload RXT branch
	// doc comment) rather than inventing a parallel signaling
	// mechanism: jobPayload gates its RXM XNP-proxy-shape branch on
	// this bool and, when false, leaves all four pointer fields nil/
	// omitted from the wire for that job — exactly like it already
	// does for RXT's ReservedOffset/ClientPoolOffset.
	ReservedOffsetUsable bool

	// RawTemplateBlob is the real, RAW, UNCONVERTED Monero
	// blocktemplate_blob bytes for this job (monero_node.go's
	// moneroTemplateData.TemplateBlob, duplicated here so
	// session.go's jobPayload can reach it without a cross-package
	// type assertion into the opaque TemplateData field — see that
	// field's own doc comment on why algo-specific NodeClient
	// internals are normally kept out of this coin-agnostic shell).
	// This is deliberately the SAME raw bytes handed to an
	// XNP-proxy-detected session's wire "blocktemplate_blob" field
	// (protocol.go's JobPayload) — see this repo's XNP-proxy fix doc
	// comment on session.go's jobPayload for why sending the raw,
	// unconverted template (rather than the hashing blob already in
	// Header) is the deliberate, safety-reviewed behavior for that
	// one case: the receiving XNP-class proxy does its OWN
	// raw-blob-to-hashing-blob conversion downstream. Only ever
	// populated for ALGO_RXM jobs; zero-value (nil) for every other
	// algo.
	RawTemplateBlob []byte

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
func (j *Job) MarkNonceUsed(nonce uint64) (firstUse bool) {
	j.nonceMu.Lock()
	defer j.nonceMu.Unlock()
	if j.usedNonces == nil {
		j.usedNonces = make(map[uint64]struct{})
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

// maxTrackedNoncesPerJob mirrors internal/leaflib/proxy/job.go's
// identical constant exactly -- see that constant's own doc comment
// for the full reasoning (Fix 11, DISPATCH_BRIEF.md 2026-09-10). The
// same 100,000-entry bound applies here: leaf-solo's own per-xn Job
// (see this type's doc comment: every xn gets its own distinct Job)
// has the exact same unbounded-map-growth exposure this fix closes
// for leaf-proxy.
const maxTrackedNoncesPerJob = 100_000

// JobManagerConfig configures a JobManager.
type JobManagerConfig struct {
	Node NodeClient

	// Algo is which mining algorithm this JobManager fetches block
	// templates for (poolpb.Algo_ALGO_SHA3X or poolpb.Algo_ALGO_C29 as
	// of this pass). Defaults (an unset/zero ALGO_UNSPECIFIED value) to
	// poolpb.Algo_ALGO_SHA3X in NewJobManager below — this is the
	// backward-compatibility guarantee the already-deployed CT132
	// leaf-solo.service depends on: a JobManager built without
	// explicitly setting Algo behaves exactly as it did before C29
	// support existed. One JobManager instance serves exactly ONE
	// algo (this leaf's chosen single-algo-per-process model — see
	// cmd/leaf-solo/main.go's LEAF_SOLO_ALGO doc comment for why a
	// simpler single-algo flag was chosen over per-port algo selection
	// for this pass); every Job it produces is stamped with this same
	// Algo (see jobForXN below).
	Algo poolpb.Algo

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

	// JobMaxAge is the REAL per-job expiry threshold, checked against
	// Job.CreatedAt independently of tip-invalidation (see
	// SECURITY FIX doc comment on Session's jobList/jobLog below,
	// session.go's handleSubmit).
	//
	// Before this field existed, the ONLY thing that ever invalidated
	// a Job was InvalidateAll (tip movement or the periodic
	// RefreshInterval timer) — a whole-cache wipe, not a per-job
	// check. A job that happened to still be present (e.g. a session's
	// own recent-job history, or, previously, the global jobsByID map)
	// could be submitted against arbitrarily long after it was issued
	// as long as the cache hadn't been globally invalidated yet. This
	// field adds a REAL, independent age ceiling: handleSubmit rejects
	// a submit against a job older than JobMaxAge with a distinct
	// "job expired" reason, regardless of whether InvalidateAll has
	// run.
	//
	// Defaults to 6 minutes (NewJobManager), mirroring
	// go-tari-sha3x-solo-stratum's CleanMinerJobs default
	// (`time.Now().Add(-1*6*time.Minute)`, subsystems/poolStratum/
	// miner.go). Configurable via LEAF_SOLO_JOB_MAX_AGE in
	// cmd/leaf-solo/main.go.
	JobMaxAge time.Duration

	// Network is this JobManager's own network tag ("mainnet"/
	// "testnet"), stamped onto every published TemplateMessage's
	// Network field (see tipPollLoop's template-relay publish) and
	// used as part of the synthetic dedup hash (syntheticTipDedupHash)
	// so two DIFFERENT networks' tip movements never collide in the
	// relay's shared dedup cache. leaf-solo had no existing Network
	// concept on JobManagerConfig before this field was added (unlike
	// leaf-direct's Server.network) — wired from cmd/leaf-solo/
	// main.go's own -network flag exactly like every other leaf-solo
	// config value threaded into JobManagerConfig. Left empty (the
	// zero value) is safe: it just means every published/dedup-hashed
	// message carries an empty Network tag, which is still internally
	// consistent (every one of THIS instance's own messages uses the
	// same empty tag).
	Network string

	// Relay is the optional best-effort NATS template-relay mechanism
	// (internal/leaflib/relay's TemplateMessage/PublishTemplate/
	// SubscribeTemplate) this JobManager uses for a real latency win:
	// a sibling leaf instance's own tip-poll finding a new height
	// beats this instance's own next poll tick (see tipPollLoop's
	// publish call and Start's SubscribeTemplate wiring). nil-safe:
	// every relay.Relay method used here (Enabled/PublishTemplate/
	// SubscribeTemplate) is already safe to call on a nil *relay.Relay
	// receiver (see relay.Relay.Enabled()'s own `r != nil` check) --
	// this field is left nil in every pre-existing caller/test that
	// does not explicitly set it, which is functionally identical to
	// this feature not existing at all.
	Relay *relay.Relay

	Logger *log.Logger

	// Debug, if non-nil and enabled, adds verbose [DEBUG]-tagged
	// logging for this JobManager's own template-fetch/tip-poll/
	// invalidation lifecycle (see jobForXN/tipPollLoop/InvalidateAll)
	// -- see internal/leaflib/debuglog.go's doc comment. nil (the
	// default for every pre-existing caller/test) is a complete
	// no-op: Debugf is safe to call on a nil *leaflib.DebugLogger.
	Debug *leaflib.DebugLogger
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
	// Backward-compatibility default: an unconfigured/zero-value Algo
	// (poolpb.Algo_ALGO_UNSPECIFIED) means "the already-deployed CT132
	// behavior", i.e. SHA3X-only — see JobManagerConfig.Algo's doc
	// comment. This is the single normalization point that keeps
	// every pre-existing caller (tests, main.go before LEAF_SOLO_ALGO
	// was introduced) working unchanged.
	if cfg.Algo == poolpb.Algo_ALGO_UNSPECIFIED {
		cfg.Algo = poolpb.Algo_ALGO_SHA3X
	}
	return &JobManager{
		cfg:      cfg,
		perXN:    make(map[string]*Job),
		jobsByID: make(map[string]*Job),
		subs:     make(map[uint64]func()),
		logger:   logger,
	}
}

// Algo returns this JobManager's own configured (and already
// backward-compatibility-normalized — see NewJobManager) mining
// algorithm. Exported so session-level login handling (session.go's
// handleLogin) can dispatch real, coin-aware payment-address
// validation (address.go's ValidateAddressForAlgo) on the SAME algo
// value every other per-job decision in this leaf already keys off,
// without duplicating JobManagerConfig's own normalization logic.
func (jm *JobManager) Algo() poolpb.Algo {
	return jm.cfg.Algo
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

	jm.cfg.Debug.Debugf("solo: fetching block template for xn=%s at difficulty=%d", xn, difficulty)
	result, err := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress, jm.cfg.Algo)
	if err != nil {
		jm.cfg.Debug.Debugf("solo: GetBlockTemplate for xn=%s failed: %v", xn, err)
		return nil, fmt.Errorf("solo: GetBlockTemplate for xn %s: %w", xn, err)
	}
	if result == nil {
		return nil, fmt.Errorf("solo: GetBlockTemplate returned a nil job for xn %s", xn)
	}
	// Unconditional (always-on, non-Debug-gated) log line: a fresh
	// block template was just fetched from the base node for a
	// first-seen/cache-invalidated xn (this IS the "new block
	// template" event -- a cache HIT for an already-cached xn returns
	// early above, before this GetBlockTemplate call is ever made).
	// Added so real network target difficulty is visible in a leaf's
	// normal logs by default, without needing to restart with debug
	// logging enabled -- see this line's own feature brief for the
	// live-LWMA-testing motivation. Deliberately additive alongside
	// (not a replacement for) the existing jm.cfg.Debug.Debugf line
	// below, which keeps its own distinct verbose-debug role.
	jm.logger.Printf("solo: new block template fetched (algo=%s height=%d network_target_difficulty=%d)", algoWireName(result.Algo), result.Height, result.NetworkTargetDifficulty)
	job := result
	job.StaticDifficulty = difficulty
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now()
	}

	jm.mu.Lock()
	jm.perXN[xn] = job
	jm.jobsByID[job.ID] = job
	jm.mu.Unlock()

	jm.cfg.Debug.Debugf("solo: job created xn=%s job_id=%s height=%d static_difficulty=%d network_target_difficulty=%d", xn, job.ID, job.Height, job.StaticDifficulty, job.NetworkTargetDifficulty)

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
		Algo:                    existing.Algo,
		Height:                  existing.Height,
		Header:                  existing.Header,
		BlockHash:               existing.BlockHash,
		StaticDifficulty:        difficulty,
		NetworkTargetDifficulty: existing.NetworkTargetDifficulty,
		TemplateData:            existing.TemplateData,
		VmKey:                   existing.VmKey,
		ReservedOffset:          existing.ReservedOffset,
		ReservedOffsetUsable:    existing.ReservedOffsetUsable,
		RawTemplateBlob:         existing.RawTemplateBlob,
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
// currently-cached entry.
//
// SECURITY NOTE: this is NOT, and must never be treated as, a
// session-ownership/security boundary. It is a diagnostic/test
// convenience only (used by job_test.go to assert cache-invalidation
// behavior directly against JobManager). The real security boundary —
// "can the submitting session actually reference this job_id" — lives
// entirely on Session's own bounded jobList/jobLog (session.go), which
// is populated at every point a job is actually handed to that
// specific session (login, getjob, vardiff-driven push,
// invalidation-driven repush) and checked by handleSubmit BEFORE any
// other validation. Do not add a caller that uses GetJob to gate a
// submit — a shared, all-xn-spanning map has no notion of "whose job
// this actually is", which used to be the real, exploitable gap this
// fix closes (see this method's git history / the PR that introduced
// Session-level ownership).
func (jm *JobManager) GetJob(id string) (*Job, bool) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	job, ok := jm.jobsByID[id]
	return job, ok
}

// JobMaxAge returns the configured real per-job expiry threshold (see
// JobManagerConfig.JobMaxAge's doc comment) — used by Session's
// handleSubmit to reject a submit against a job that is still present
// in the submitting session's own job history but has aged out,
// independently of whether InvalidateAll has ever run.
func (jm *JobManager) JobMaxAge() time.Duration {
	return jm.cfg.JobMaxAge
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
	jm.cfg.Debug.Debugf("solo: per-xn job cache invalidated (all cached jobs dropped)")
	jm.notify()
}

// Probe performs a single, uncached GetBlockTemplate call purely to
// fail fast at startup if the base node is unreachable/misconfigured,
// mirroring main.go's previous "fetch initial block template" sanity
// check. The result is discarded — it is deliberately NOT cached under
// any xn, since with per-xn jobs there is no "the" initial job to seed;
// each session's first JobForXN call generates its own.
func (jm *JobManager) Probe(ctx context.Context) error {
	result, err := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress, jm.cfg.Algo)
	if err != nil {
		return fmt.Errorf("solo: GetBlockTemplate probe: %w", err)
	}
	if result == nil {
		return fmt.Errorf("solo: GetBlockTemplate probe returned a nil job")
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

// Start launches the periodic refresh and tip-poll loops, and
// subscribes this JobManager to its configured template relay (see
// JobManagerConfig.Relay) so a sibling leaf instance's own tip-poll
// finding a new height can invalidate THIS instance's per-xn job
// cache immediately, instead of waiting for this instance's own next
// tipPollLoop tick — the real latency win this feature exists for.
// It returns immediately; every launched loop/subscription runs until
// ctx is cancelled.
func (jm *JobManager) Start(ctx context.Context) {
	go jm.refreshLoop(ctx)
	go jm.tipPollLoop(ctx)
	jm.startTemplateRelaySubscription(ctx)
}

// startTemplateRelaySubscription subscribes to jm.cfg.Relay's
// template broadcasts, invalidating the ENTIRE per-xn job cache
// (jm.InvalidateAll) on every genuinely new (non-self, non-duplicate
// — already guaranteed by relay.Relay.SubscribeTemplate's own
// contract) template message received. Safe to call unconditionally
// even when jm.cfg.Relay is nil or disabled/unconfigured:
// SubscribeTemplate itself is nil/disabled-Relay-safe (see
// relay.Relay.Enabled()'s `r != nil` check), returning a no-op
// unsubscribe func and a nil error in that case. The returned
// unsubscribe func is invoked once ctx is cancelled, tying this
// subscription's lifetime to the SAME ctx refreshLoop/tipPollLoop
// already use.
func (jm *JobManager) startTemplateRelaySubscription(ctx context.Context) {
	unsub, err := jm.cfg.Relay.SubscribeTemplate(func(msg relay.TemplateMessage) {
		jm.logger.Printf("solo: received template relay message from another instance (height=%d algo=%s network=%s), invalidating per-xn job cache", msg.Height, msg.Algo, msg.Network)
		jm.InvalidateAll()
	})
	if err != nil {
		jm.logger.Printf("solo: template relay subscribe failed (template-relay fast-invalidation disabled, primary tip-poll path unaffected): %v", err)
		return
	}
	go func() {
		<-ctx.Done()
		unsub()
	}()
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
			height, err := jm.cfg.Node.GetTipInfo(ctx)
			if err != nil {
				jm.logger.Printf("solo: tip poll failed: %v", err)
				continue
			}
			jm.mu.RLock()
			last := jm.lastTipHeight
			observed := jm.tipObserved
			jm.mu.RUnlock()
			jm.cfg.Debug.Debugf("solo: tip poll: observed height=%d last known height=%d (baseline seeded=%v)", height, last, observed)
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
				jm.publishTemplate(ctx, height)
			}
		}
	}
}

// publishTemplate best-effort-broadcasts a relay.TemplateMessage for
// this JobManager's own genuine local tip increase (see tipPollLoop's
// `height > last` branch, which is the ONLY call site — never called
// on the first tip observation/baseline seed, and never called when
// height is unchanged) over jm.cfg.Relay, so a sibling leaf instance's
// own JobManager can invalidate its per-xn job cache immediately
// instead of waiting for its own next tip-poll tick. Never blocks or
// fails the primary tip-poll path: PublishTemplate itself is already
// a complete no-op on a nil/disabled Relay (see
// relay.Relay.Enabled()), and any real publish error is only logged.
func (jm *JobManager) publishTemplate(ctx context.Context, height uint64) {
	algo := algoWireName(jm.cfg.Algo)
	network := jm.cfg.Network
	msg := relay.TemplateMessage{
		Algo:    algo,
		Network: network,
		Height:  height,
		Hash:    syntheticTipDedupHash(algo, network, height),
	}
	if err := jm.cfg.Relay.PublishTemplate(ctx, msg); err != nil {
		jm.logger.Printf("solo: template relay publish failed (non-fatal, primary tip-poll path unaffected): %v", err)
	}
}

// syntheticTipDedupHash builds relay.TemplateMessage.Hash's dedup key
// for a bare tip-height observation: hex(sha256("<algo>|<network>|
// <height>")). This is a SYNTHETIC dedup key, not a real chain-tip
// hash — JobManager.tipPollLoop only has a bare height available from
// NodeClient.GetTipInfo (see that interface method's doc comment), no
// cheaper real tip-identifying hash to use instead. It is still
// deterministic and fit for purpose: two DIFFERENT sibling leaf
// instances (different relay.Relay.PublisherID) independently
// observing the SAME real height/algo/network compute the IDENTICAL
// hash, so relay.Relay's own shared dedup cache (markSeen) correctly
// collapses duplicate relay chatter from multiple instances observing
// the same real tip movement — exactly the behavior a real shared tip
// hash would produce, without this layer needing one.
func syntheticTipDedupHash(algo, network string, height uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", algo, network, height)))
	return hex.EncodeToString(sum[:])
}

// newRandomHexID and newSessionXN are now thin wrappers over
// internal/leaflib's identically named exported functions (EXTRACTED
// there so internal/leaflib/direct — which used to hand-derive a
// byte-for-byte duplicate of each of these in its own wireutil.go —
// can reuse the exact same real implementations; see
// leaflib/wireutil.go's doc comment for the full rationale). See each
// leaflib function's own doc comment for the full ported provenance;
// unchanged behavior, just relocated.
//
// This package used to also carry a jobIDFromBlockHash thin wrapper
// over leaflib.JobIDFromBlockHash, deriving a job's ID from its
// BlockHash. That is now REMOVED: job_id must be a purely random,
// opaque wire token, never content-derived — see node.go's
// tariJobFromResult and monero_node.go's GetBlockTemplate doc
// comments for the full real-production-bug rationale. Both this
// package's own call sites now mint via newRandomHexID instead.
func newRandomHexID() (string, error) {
	return leaflib.NewRandomHexID()
}

func newSessionXN() (string, error) {
	return leaflib.NewSessionXN()
}
