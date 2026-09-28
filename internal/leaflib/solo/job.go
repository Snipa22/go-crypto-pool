// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/moneroblob"
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

// TemplateSourceLocal/TemplateSourceRelay label every
// JobManager.Subscribe(fn func(source string)) callback invocation
// (see InvalidateAll/notify below) with WHICH of InvalidateAll's 3
// real call sites triggered this invalidation --
// internal/leaflib/direct's metrics package (leaf_direct_template_
// distribution_seconds/leaf_direct_template_distribution_miners)
// consumes these values as-is for its own "source" label, so these
// exact string VALUES ("local"/"relay") must never change without
// updating that consumer too.
//
//   - TemplateSourceLocal: tipPollLoop's own genuine tip-height
//     increase, or refreshLoop's unconditional periodic cache
//     refresh -- this instance's OWN observation, no relay involved
//     either way.
//   - TemplateSourceRelay: startTemplateRelaySubscription's callback
//     fired because jm.cfg.Relay.SubscribeTemplate delivered a
//     genuinely new (non-duplicate) template message from ANOTHER
//     instance.
const (
	TemplateSourceLocal = "local"
	TemplateSourceRelay = "relay"
)

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

	// bestHeight/bestSize/bestSet track the (height, serialized-byte-
	// size) of the best template this JobManager has adopted/served
	// so far from ANY source (local fetch or relay) -- see
	// isBetterCandidate's doc comment for the exact priority order
	// this gates. bestSet is false until the very first job (local or
	// relay) has ever been installed; see currentBestSnapshot/setBest.
	// This is deliberately separate from lastTipHeight (which tracks
	// THIS instance's own node's tip, regardless of what's actually
	// being served) and from any individual cached Job (perXN/
	// jobsByID entries reflect what miners are actually being handed
	// right now; bestHeight/bestSize reflect the best this JobManager
	// has ever confirmed, which relay adoption may keep ahead of a
	// lagging local node indefinitely -- per this feature's settled
	// design, relay is authoritative over local whenever it
	// disagrees, with no time-boxing/hysteresis/fallback).
	bestHeight uint64
	bestSize   int
	bestSet    bool

	// sharedTemplate is the ONE most-recently-established block
	// template (from EITHER a local jm.cfg.Node.GetBlockTemplate
	// fetch or a successfully-adopted relay message) that every
	// session's own per-session Job is DERIVED from, for the algos
	// usesSharedTemplate covers -- see that method's doc comment for
	// the exact per-algo scope and the real reasoning behind it, and
	// jobForXNFromSharedTemplate for the derivation itself.
	//
	// WHY THIS FIELD EXISTS (real, live-confirmed production
	// incident, sxmr-phx-dump, ~13,500 simultaneously-reconnecting
	// miners): jobForXN used to call GetBlockTemplate on ANY per-xn
	// cache miss. genLocks (below) correctly collapsed concurrent
	// first-requests for the SAME xn into one fetch, but every
	// DIFFERENT xn still got its OWN independent daemon round trip --
	// and since xn is assigned fresh per connection
	// (leaflib.NewSessionXN, a random per-session identifier with
	// ZERO cryptographic meaning to the underlying template), a mass
	// reconnect meant one real daemon RPC per session for the exact
	// same chain tip. The leaf logged the SAME height's "new block
	// template fetched" line 41,783 times in a 90-second window, the
	// upstream minotari_merge_mining_proxy started returning
	// `rpc error -32603: Internal error` under the load, and 21-40%
	// of submitted shares were rejected as stale/expired (while
	// genuine cryptographic-validation failures stayed negligible at
	// ~0.15% of accepted shares -- confirming those rejections were
	// jobs being invalidated out from under miners, NOT a validation
	// bug). The same bug fired again on EVERY genuine tip change, not
	// just at cold start, via direct.Server.invalidateAndRepushJobs'
	// per-session fan-out.
	//
	// This mirrors the proven legacy nodejs-pool-sxmr reference this
	// leaf replaces (lib/pool.js): ONE shared `activeBlockTemplate`
	// global, refreshed once per real tip change
	// (newBlockTemplate(template)), with every miner's own job
	// DERIVED by reading fields off that one shared object
	// (getJob(): height/reserved_offset/client_nonce_offset/
	// client_pool_offset/seed_hash all read straight off
	// activeBlockTemplate, zero per-miner daemon calls).
	//
	// nil means "no shared template established yet" -- either a
	// genuine first-ever cold start, or the state immediately after
	// an unseeded InvalidateAll. Guarded by jm.mu like every other
	// field in this block; read via sharedTemplateSnapshot, written
	// via setSharedTemplate/invalidateAll's own seed parameter. This
	// is deliberately a template-shaped *Job rather than a new
	// parallel type: it IS exactly what NodeClient.GetBlockTemplate/
	// NodeClient.JobFromTemplateBytes already return, so no
	// bytes-to-fields bookkeeping is duplicated anywhere.
	sharedTemplate *Job

	// sharedTemplateGen is THIS shared template generation's own
	// derivation state -- most importantly its extraNonce counter,
	// the real, direct port of the legacy
	// nodejs-pool reference's per-BlockTemplate `this.extraNonce`
	// (lib/coins/xmr.js, BlockTemplate):
	//
	//	this.extraNonce = 0;
	//	this.nextBlob = function () {
	//	    // Write a 32 bit integer, big-endian style to the 0 byte
	//	    // of the reserve offset.
	//	    this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
	//	    return global.coinFuncs.convertBlob(this.buffer).toString("hex");
	//	};
	//
	// WHY THIS FIELD EXISTS (real, live-reproduced production
	// data-integrity bug, sxmr-phx-dump): before it, two separate
	// stratum logins against the SAME leaf at the SAME tip received
	// BYTE-IDENTICAL mining blobs (only job_id/target differed),
	// because jobFromSharedTemplate copied tpl.Header /
	// tpl.RawTemplateBlob BY REFERENCE into every per-xn *Job and
	// patched nothing. Every Monero-family miner on the leaf was
	// therefore searching the exact same space as every other one.
	// jobFromSharedTemplate now consumes the next value off this
	// generation's counter on EVERY derivation and stamps it
	// big-endian at ReservedOffset+0:+4, re-deriving the hashing blob
	// from the patched raw template afterward (patching the coinbase
	// tx changes the merkle root, which is embedded in the hashing
	// blob).
	//
	// DELIBERATELY A POINTER, REPLACED (never merely reset in place)
	// whenever jm.sharedTemplate is genuinely replaced -- matching
	// legacy's own `this.extraNonce = 0` living in the BlockTemplate
	// CONSTRUCTOR, i.e. a fresh template means a fresh counter, and
	// the counter never persists across template generations. A
	// pointer rather than inline fields so that the (template,
	// generation) pair can be snapshotted together under jm.mu and
	// handed to jobFromSharedTemplate as one consistent unit: that is
	// what makes it impossible for a derivation racing a template
	// swap to consume a value from the NEW generation's counter while
	// stamping it into the OLD generation's bytes (or vice versa),
	// which would reintroduce duplicate stamps within a single
	// template generation -- exactly the bug this closes.
	//
	// nil whenever jm.sharedTemplate is nil (no template established
	// yet); read via sharedTemplateSnapshot, written via
	// setSharedTemplate / invalidateAll / adoptRelayedJobShared,
	// always in the SAME jm.mu-held critical section that writes
	// jm.sharedTemplate itself.
	sharedTemplateGen *sharedTemplateGeneration

	// templateFetchMu is the NEW, single, process-wide single-flight
	// lock guarding "is there a shared template at all yet" --
	// deliberately DISTINCT from genLocks below (which is per-xn).
	// This is what makes a cold-start stampede across MANY different
	// xns collapse to ONE real GetBlockTemplate call instead of N:
	// genLocks alone cannot do that, since by construction each
	// stampeding session holds a DIFFERENT xn's lock. It mirrors
	// genLocks' own established single-flight pattern, just applied
	// at the shared-template level instead of the per-xn level.
	// Never held across a notify/subscriber callback -- only across
	// the one real GetBlockTemplate round trip and the snapshot/
	// install of its result (see currentSharedTemplate).
	templateFetchMu sync.Mutex

	// genLocks holds one lazily-created *sync.Mutex per xn
	// (map[string]*sync.Mutex, via sync.Map so lookups/creations don't
	// need a separate lock of their own), serializing concurrent
	// new-template generation ONLY for the SAME xn -- see jobForXN's
	// own doc comment for the full rationale and the incident
	// (brief2.md, second finding on the phx-dump.supportxmr.com
	// leaf) that required narrowing this from a single global
	// sync.Mutex (the original genMu) to per-xn granularity.
	// Deliberately never pruned/removed as xns age out (InvalidateAll
	// wipes perXN/jobsByID but leaves genLocks alone) -- a stray
	// *sync.Mutex per distinct xn ever seen over this process's
	// lifetime is a few dozen bytes each, the same order of magnitude
	// this package already accepts for jobsByID's own unbounded-by-ID
	// growth, and pruning it safely (without racing a lock currently
	// held by another goroutine) would need real reference-counting
	// for no measurable benefit at realistic connection counts.
	genLocks sync.Map

	subMu sync.RWMutex
	subs  map[uint64]func(source string)
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
		subs:     make(map[uint64]func(source string)),
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

// LatestHeight returns the most recent chain-tip height this
// JobManager's tipPollLoop has observed (jm.lastTipHeight), or 0 if no
// tip has been observed yet (tipObserved is still false -- e.g. called
// before Start's first successful tip poll). Used by cmd/leaf-direct's
// legacy-mode /poolCheckin heartbeat (see
// internal/leaflib/legacytransport/checkin.go) to report the real,
// live chain-tip height as the heartbeat's block_id field, reusing this
// JobManager's own existing tip-poll state rather than running a
// separate poller.
func (jm *JobManager) LatestHeight() uint64 {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	if !jm.tipObserved {
		return 0
	}
	return jm.lastTipHeight
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

	if jm.usesSharedTemplate() {
		return jm.jobForXNFromSharedTemplate(ctx, xn, difficulty)
	}

	// NARROWED LOCK GRANULARITY (brief2.md, second finding, discovered
	// while implementing that fix's own required regression test):
	// this used to acquire a single, process-wide jm.genMu
	// sync.Mutex here, serializing EVERY concurrent first-request
	// across EVERY xn, not just concurrent first-requests for the
	// SAME xn -- confirmed via a live experiment (20 concurrent
	// JobForXNAtDifficulty calls for 20 DISTINCT xns against a mock
	// GetBlockTemplate with an artificial 30ms delay took ~607ms
	// total, i.e. fully serialized, not the ~30ms true concurrent
	// execution would take). That mattered beyond raw throughput:
	// internal/leaflib/direct.Server.invalidateAndRepushJobs' own
	// brief2.md fix bounds/parallelizes its per-session fan-out
	// specifically so a mass cache invalidation (every session's xn
	// missing at once) completes in time proportional to
	// session_count/concurrency rather than session_count -- which
	// the old single global genMu would have silently defeated
	// entirely, since every one of those concurrent callers would
	// still have funneled through the exact same single mutex one at
	// a time regardless of how many goroutines Server dispatched.
	// jm.genLocks (see that field's own doc comment) replaces genMu
	// with one lazily-created *sync.Mutex PER xn instead, preserving
	// the original, still-needed guarantee (concurrent first-
	// requests for the SAME xn collapse to a single real fetch, all
	// sharing its result -- see
	// TestJobForXNConcurrentFirstRequestsForSameXNDoNotDuplicate)
	// while letting genuinely different xns' real GetBlockTemplate
	// calls run fully concurrently, exactly as
	// direct.Server.invalidateAndRepushJobs' own fan-out now expects.
	genLockAny, _ := jm.genLocks.LoadOrStore(xn, &sync.Mutex{})
	genLock := genLockAny.(*sync.Mutex)
	genLock.Lock()
	defer genLock.Unlock()

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

	// Tracked-best bookkeeping (relay-template-adoption brief,
	// section 3): this fetch's own (height, size) is only recorded as
	// the new tracked best if there is no baseline yet (true cold
	// start -- always adopt, exactly like today) OR it is genuinely
	// better than what's already tracked (which may be relay-sourced
	// and ahead of what THIS particular fetch just observed). This
	// job is still cached/served for xn unconditionally either way —
	// per-xn independent template fetching (this package's core
	// design, see Job's own doc comment) is never short-circuited by
	// this bookkeeping; only the shared best-tracker's own value is
	// protected from regressing below a genuinely superior relayed
	// template. (Factored into recordBestIfBetter so the
	// shared-template fetch path applies the IDENTICAL rule -- see
	// that helper's own doc comment.)
	jm.recordBestIfBetter(job)

	jm.mu.Lock()
	jm.perXN[xn] = job
	jm.jobsByID[job.ID] = job
	jm.mu.Unlock()

	jm.cfg.Debug.Debugf("solo: job created xn=%s job_id=%s height=%d static_difficulty=%d network_target_difficulty=%d", xn, job.ID, job.Height, job.StaticDifficulty, job.NetworkTargetDifficulty)

	return job, nil
}

// usesSharedTemplate reports whether this JobManager derives every
// session's own per-session Job from ONE shared current template
// (jm.sharedTemplate) instead of giving each xn its OWN independent
// GetBlockTemplate daemon call.
//
// SCOPE: Monero-family algos ONLY (IsMoneroFamilyAlgo -- ALGO_RXM
// plus every coinprofile.ByAlgo-registered coin). This is a
// deliberate, evidence-based scoping decision, not an accident of
// implementation; it was arrived at by reading each algo's real
// per-session non-collision mechanism in full:
//
//   - Monero-family (RXM/XMR/ARQ/XEQ/GRFT/SFX/ZEPH/SAL): per-xn
//     independent fetching provides NO per-session differentiation
//     whatsoever, so it is pure wasted daemon load. monero_node.go's
//     GetBlockTemplate requests reserve_size: 60 and records the
//     daemon's returned reserved_offset, but it NEVER patches a
//     per-session extranonce into that reserved region -- an
//     ordinary xmrig-class session's job.Header is the daemon's
//     unpatched blockhashing_blob, byte-identical for every session
//     at an unmoved tip TODAY, before this fix. (Per-session nonce
//     partitioning for Monero-family is instead handled exactly
//     where the legacy reference handles it: reserved_offset/
//     client_nonce_offset/client_pool_offset published to
//     XNP-class proxy clients, which partition downstream -- see
//     Job.ReservedOffset/ReservedOffsetUsable and session.go's
//     jobPayload.) So sharing one template changes NOTHING about
//     Monero-family collision behavior; it only removes the
//     redundant RPCs. This is also exactly the live incident's own
//     algo (a minotari_merge_mining_proxy backend).
//
//   - Tari SHA3X/C29 (NOT shared; left completely unchanged): these
//     DO get a genuinely distinct template per fetch --
//     node.go's GetBlockTemplate/buildCoinbaseExtra appends a fresh
//     random 8-byte nonce to coinbase_extra on EVERY call, which
//     changes the resulting MergeMiningHash pre-image (see Job's own
//     doc comment). They ALSO independently partition nonce space by
//     xn at submit time (session.go's
//     `strings.HasPrefix(strings.ToLower(submit.Nonce), s.xn)`
//     check, with payload.XN = s.xn on the wire), so they would in
//     fact be safe to share. They are deliberately left out of this
//     fix's scope anyway: they are not the incident's algo, sharing
//     buys them nothing they don't already have, and including them
//     would require rewriting job_test.go's
//     TestJobForXNGivesDifferentXNsDifferentJobs -- an existing,
//     explicitly-documented Tari-path assertion ("2 independent
//     GetBlockTemplate calls (one per new xn)"). Changing a live
//     Tari behavioral contract is out of scope for a fix whose
//     entire purpose is removing redundant Monero-family RPCs.
//
//   - RXT (NOT shared, and genuinely MUST NOT be): Tari's own native
//     RandomX PoW is RandomX-FAMILY (trust.go's IsRandomXFamily), so
//     session.go omits XN from its wire job payload AND SKIPS the
//     submit-time xn nonce-prefix check entirely for it. An ordinary
//     (non-XNP) RXT session therefore has NO nonce-space
//     partitioning at all -- per-fetch coinbase_extra randomization
//     is the ONLY thing that currently gives two RXT sessions
//     genuinely different search spaces. Sharing one template across
//     RXT sessions would hand every RXT miner a byte-identical
//     76-byte mining blob (leaflib.CreateTariMiningBlob over the
//     same job.Header/pow_data) with an identical nonce space, which
//     is a real duplicate-work/duplicate-share regression, not just
//     a cosmetic one. RXT keeps its existing per-xn independent
//     fetch behavior untouched.
func (jm *JobManager) usesSharedTemplate() bool {
	return IsMoneroFamilyAlgo(jm.cfg.Algo)
}

// sharedTemplateGeneration is the small bundle of per-shared-template
// derivation state jobFromSharedTemplate needs, minted fresh every
// time jm.sharedTemplate is genuinely replaced -- see
// JobManager.sharedTemplateGen's doc comment for the full rationale
// and the production bug it exists for.
type sharedTemplateGeneration struct {
	// extraNonce is this template generation's own monotonically-
	// incrementing extraNonce counter, starting at 0 (so the first
	// derivation stamps 1, matching the legacy reference's
	// `++this.extraNonce` pre-increment).
	extraNonce atomic.Uint32

	// stampUnavailable latches true the first time this template
	// generation is found to be un-stampable AT ALL -- its reserved
	// region doesn't fit inside its own raw template blob, or
	// go-xmr-lib cannot re-derive a hashing blob from its
	// (extraNonce-patched) bytes, or the re-derived blob's parsed
	// nonce offset disagrees with the template's own.
	//
	// WHY LATCHED, rather than simply retried per derivation: every
	// one of those conditions is a property of the TEMPLATE, not of
	// any individual derivation, so retrying it once per arriving
	// session is pure waste -- and actively harmful. Each retry
	// costs a full go-xmr-lib parse attempt (a real CPU cost, once
	// per session, on the hot job-derivation path), emits another
	// copy of the same warning, and -- worst -- each panic/timeout
	// counts toward moneroblob's process-wide malformed-blob circuit
	// breaker, so a single genuinely unparseable template served to
	// enough sessions would trip that breaker OPEN and thereby also
	// refuse conversions on the unrelated XNP-proxy submit path
	// (node.go's MoneroHashingBlobForXNPSubmit), turning one bad
	// template into a leaf-wide submit outage. Latching bounds the
	// damage to exactly ONE attempt, ONE warning and ONE possible
	// breaker trigger per template generation, and the derivation
	// itself still succeeds either way (it falls back to the
	// unstamped shared bytes -- see extraNonceStampedTemplate).
	stampUnavailable atomic.Bool

	// stampUnavailableLogged guards the ONE additional log line
	// emitted the first time some OTHER derivation observes
	// stampUnavailable already latched true (see
	// extraNonceStampedTemplate's own doc comment and its
	// gen.stampUnavailable.Load() branch). This is deliberately
	// SEPARATE from the warning line the original failure itself
	// already emits when it FIRST sets the latch (the bounds check,
	// the hashing-blob re-derivation failure, or the nonce-offset
	// mismatch, each below) -- without this second guard, every
	// derivation AFTER the first for an un-stampable generation was
	// completely silent, so a live incident investigation could
	// only ever see ONE warning line for a template that in fact
	// went on serving unstamped, potentially-duplicate-search-space
	// jobs to every other session at that height. A sync.Once (not
	// a second atomic.Bool CompareAndSwap) is used purely because it
	// is the more idiomatic "do this exactly once" primitive here;
	// there is no correctness reason it couldn't be a Bool instead.
	stampUnavailableLogged sync.Once
}

// sharedTemplateSnapshot returns the currently-established shared
// template (see JobManager.sharedTemplate) TOGETHER WITH that same
// template generation's own derivation state (see
// JobManager.sharedTemplateGen), or (nil, nil, false) if none has
// been established yet. Safe to call concurrently.
//
// The two values are returned as one atomic pair on purpose: a
// derivation must never stamp one generation's counter value into a
// DIFFERENT generation's template bytes -- see
// JobManager.sharedTemplateGen's doc comment.
func (jm *JobManager) sharedTemplateSnapshot() (*Job, *sharedTemplateGeneration, bool) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.sharedTemplate, jm.sharedTemplateGen, jm.sharedTemplate != nil
}

// setSharedTemplate installs tpl as the shared current template every
// subsequent per-session Job derivation reads from. Called by the
// local-fetch path (currentSharedTemplate), the local tip-change path
// (tipPollLoop, via invalidateAll's seed parameter) and the
// relay-adoption path (adoptRelayedJob).
//
// Always installs a FRESH, zero-valued generation alongside it, in
// the same critical section -- a genuinely new template gets a
// genuinely new extraNonce counter, exactly like the legacy
// reference's `this.extraNonce = 0` living in the BlockTemplate
// constructor. See JobManager.sharedTemplateGen's doc comment.
func (jm *JobManager) setSharedTemplate(tpl *Job) {
	jm.mu.Lock()
	jm.sharedTemplate = tpl
	jm.sharedTemplateGen = newSharedTemplateGeneration(tpl)
	jm.mu.Unlock()
}

// newSharedTemplateGeneration mints the fresh, zero-valued derivation
// state that accompanies a newly-installed shared template -- nil
// when there is no template to accompany (tpl == nil, i.e. an
// unseeded invalidation), so that sharedTemplateSnapshot's
// (nil, nil, false) contract holds. The single place this pairing is
// constructed, so no call site can install a template while
// forgetting its generation (or vice versa).
func newSharedTemplateGeneration(tpl *Job) *sharedTemplateGeneration {
	if tpl == nil {
		return nil
	}
	return &sharedTemplateGeneration{}
}

// currentSharedTemplate returns the shared current template, together
// with that same generation's own derivation state (see
// JobManager.sharedTemplateGen), fetching the template from the real
// node EXACTLY ONCE if none exists yet.
//
// This is the single-flight heart of this fix. The fast path is a
// plain RLock snapshot (no fetch, no exclusive lock) -- that is what
// every one of N stampeding sessions hits once ANY one of them has
// established the template. Only a genuine "no shared template at
// all yet" state (first-ever cold start, or the first request after
// an unseeded InvalidateAll) takes jm.templateFetchMu, and the
// double-check INSIDE that lock is what guarantees the other N-1
// waiters return the just-installed template instead of each firing
// their own redundant GetBlockTemplate call. See
// JobManager.templateFetchMu's doc comment for why genLocks alone
// cannot provide this guarantee.
func (jm *JobManager) currentSharedTemplate(ctx context.Context) (*Job, *sharedTemplateGeneration, error) {
	if tpl, gen, ok := jm.sharedTemplateSnapshot(); ok {
		return tpl, gen, nil
	}

	jm.templateFetchMu.Lock()
	defer jm.templateFetchMu.Unlock()

	// Double-check under the single-flight lock: while this goroutine
	// was waiting, another one may have already completed the real
	// fetch (or a relay adoption / tip-poll seed may have installed
	// one). Returning it here instead of fetching again is precisely
	// what collapses N concurrent cold-start requests to 1 real call.
	if tpl, gen, ok := jm.sharedTemplateSnapshot(); ok {
		return tpl, gen, nil
	}

	jm.cfg.Debug.Debugf("solo: no shared template established yet -- fetching one (single-flight) for algo=%s", algoWireName(jm.cfg.Algo))
	tpl, err := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress, jm.cfg.Algo)
	if err != nil {
		jm.cfg.Debug.Debugf("solo: shared-template GetBlockTemplate failed: %v", err)
		return nil, nil, fmt.Errorf("solo: GetBlockTemplate for the shared current template: %w", err)
	}
	if tpl == nil {
		return nil, nil, fmt.Errorf("solo: GetBlockTemplate returned a nil shared current template")
	}
	if tpl.CreatedAt.IsZero() {
		tpl.CreatedAt = time.Now()
	}
	// Same unconditional (non-Debug-gated) "new block template
	// fetched" log line the per-xn path emits -- see jobForXN's own
	// comment on it. In shared-template mode this now fires ONCE per
	// real template, which is exactly the 41,783-lines-per-height
	// symptom this fix removes.
	jm.logger.Printf("solo: new block template fetched (algo=%s height=%d network_target_difficulty=%d)", algoWireName(tpl.Algo), tpl.Height, tpl.NetworkTargetDifficulty)

	jm.recordBestIfBetter(tpl)
	jm.setSharedTemplate(tpl)
	// Re-snapshot rather than returning a locally-minted generation:
	// setSharedTemplate is the single owner of the (template,
	// generation) pairing, and re-reading it here guarantees this
	// caller derives against the generation that is genuinely
	// installed (if a concurrent tip-change/relay adoption slipped a
	// NEWER template in between, this returns THAT pair --
	// consistently -- rather than a stale template with a live
	// counter).
	if installed, gen, ok := jm.sharedTemplateSnapshot(); ok {
		return installed, gen, nil
	}
	return tpl, newSharedTemplateGeneration(tpl), nil
}

// recordBestIfBetter applies the tracked-best (height, size)
// bookkeeping to tpl -- the EXACT same "only adopt if there's no
// baseline yet or this is genuinely better" rule jobForXN's own
// local-fetch path already applied inline (see the comment there and
// isBetterCandidate's doc comment). Factored out rather than
// duplicated so the shared-template fetch path and the per-xn fetch
// path can never drift on it.
func (jm *JobManager) recordBestIfBetter(job *Job) {
	size := jm.templateSizeForRelay(job)
	best := jm.currentBestSnapshot()
	if !best.set || isBetterCandidate(best.height, job.Height, best.size, size) {
		jm.setBest(job.Height, size)
	}
}

// jobFromSharedTemplate derives ONE session's OWN *Job from the
// shared current template, cloning tpl's template DATA (header/blob/
// height/seed hash/reserved-offset fields) and stamping this
// session's own difficulty plus a FRESH, random Job.ID.
//
// This deliberately mirrors RestampDifficulty's existing
// "clone into a new stamped copy" field-copying convention exactly
// (see that method, directly below) -- same field list, same order --
// just sourcing the clone FROM the shared template instead of from an
// existing per-xn job.
//
// CRITICAL (see this fix's brief, "What NOT to change"): per-session
// Job objects STAY. This never hands one literal shared *Job to
// multiple sessions. Each session gets its own distinct *Job value
// with:
//
//   - its OWN fresh random Job.ID (newRandomHexID), so submit-time
//     job ownership via Session's own bounded jobList/jobLog
//     (session.go) keeps working per-session exactly as before;
//   - its OWN StaticDifficulty (per-session vardiff, vardiff.go);
//   - its OWN zero-value nonceMu/usedNonces set, so MarkNonceUsed
//     replay protection is per-session and one session can never
//     exhaust or interfere with another's tracked-nonce state.
//
// Only the immutable, read-only template DATA is shared between them
// (BlockHash/VmKey are never mutated in place by any consumer). The
// three Monero-family fields that used to ALSO be shared by
// reference -- Header, RawTemplateBlob and TemplateData -- are now
// freshly allocated per derived Job and carry this job's OWN
// extraNonce stamp; see the EXTRANONCE STAMP note at the bottom of
// this comment, and extraNonceStampedTemplate. Every consumer that
// patches these buffers still copies before writing
// (MoneroHashingBlobForSubmit/MoneroHashingBlobForXNPSubmit/
// patchMoneroXNPReservedOffsets in node.go, and
// MoneroNodeClient.BuildCandidateBlock in monero_node.go).
//
// CreatedAt is inherited from the template rather than set to now(),
// matching RestampDifficulty: a derived job is exactly as stale as
// the template it came from, so JobManagerConfig.JobMaxAge expiry
// (session.go's handleSubmit) measures real template age and cannot
// be indefinitely extended just by a session reconnecting.
//
// EXTRANONCE STAMP (the real fix for a live-reproduced production
// data-integrity bug -- see JobManager.sharedTemplateGen's own doc
// comment for the reproduction): sharing Header/TemplateData/
// RawTemplateBlob by reference is precisely what made two separate
// stratum logins against the same leaf at the same tip receive
// BYTE-IDENTICAL mining blobs. Every call now consumes the next
// value off this template generation's extraNonce counter and gives
// the derived Job its OWN freshly-allocated, extraNonce-stamped
// RawTemplateBlob/Header/TemplateData -- see
// extraNonceStampedTemplate below for the byte-level mechanics and
// the graceful-degradation rules.
//
// gen may be nil (and tpl may be a non-Monero template), in which
// case the stamp is skipped entirely and the pre-existing
// share-by-reference behavior is preserved byte-for-byte -- this is
// what keeps every Tari/non-Monero caller and every
// non-Monero-shaped test double behaving exactly as before.
func (jm *JobManager) jobFromSharedTemplate(tpl *Job, gen *sharedTemplateGeneration, difficulty uint64) (*Job, error) {
	id, err := newRandomHexID()
	if err != nil {
		return nil, fmt.Errorf("solo: generating random job id for a shared-template-derived job: %w", err)
	}

	// Defaults preserve the exact pre-fix behavior (share the
	// template's own slices by reference); extraNonceStampedTemplate
	// overrides all three together, or none of them, never a mix --
	// a Job whose Header did not come from its own RawTemplateBlob
	// would be exactly the stale/mismatched-buffer hazard
	// MoneroNodeClient.BuildCandidateBlock's own nonce-offset
	// cross-check exists to catch.
	header := tpl.Header
	rawTemplateBlob := tpl.RawTemplateBlob
	templateData := tpl.TemplateData
	if stamped, ok := jm.extraNonceStampedTemplate(tpl, gen); ok {
		header = stamped.hashingBlob
		rawTemplateBlob = stamped.templateBlob
		templateData = stamped.data
	}

	return &Job{
		ID:                      id,
		Algo:                    tpl.Algo,
		Height:                  tpl.Height,
		Header:                  header,
		BlockHash:               tpl.BlockHash,
		StaticDifficulty:        difficulty,
		NetworkTargetDifficulty: tpl.NetworkTargetDifficulty,
		TemplateData:            templateData,
		VmKey:                   tpl.VmKey,
		ReservedOffset:          tpl.ReservedOffset,
		ReservedOffsetUsable:    tpl.ReservedOffsetUsable,
		RawTemplateBlob:         rawTemplateBlob,
		CreatedAt:               tpl.CreatedAt,
	}, nil
}

// stampedMoneroTemplate is one derived job's OWN, freshly-allocated,
// extraNonce-stamped view of a shared Monero template: the patched
// raw blocktemplate_blob, the hashing blob genuinely RE-DERIVED from
// those patched bytes, and a fresh *moneroTemplateData carrying
// exactly those same two buffers.
//
// All three travel together on purpose. MoneroNodeClient's
// BuildCandidateBlock patches the miner's nonce into
// job.TemplateData.(*moneroTemplateData).TemplateBlob and
// cross-checks the nonce offset it re-parses from that same struct's
// HashingBlob -- so a Job whose Header/RawTemplateBlob were stamped
// while its TemplateData still pointed at the PARENT template's
// unstamped buffers would submit a block that nobody ever mined
// (confirmed failure mode: see monero_node.go's GetBlockTemplate
// comment on the former prevHash+height-derived job IDs, the same
// class of stale-buffer bug).
type stampedMoneroTemplate struct {
	templateBlob []byte
	hashingBlob  []byte
	data         *moneroTemplateData
}

// extraNonceStampedTemplate is the real port of the legacy
// nodejs-pool reference's BlockTemplate.nextBlob (lib/coins/xmr.js
// ~line 158, quoted in full on JobManager.sharedTemplateGen's
// doc comment) into this package's shared-template job-derivation
// path, and the exact peer of internal/leaflib/proxy's own
// already-production-proven WorkerTemplate.BlobForWorker /
// NextBlobForWorker (template.go):
//
//  1. Consume the NEXT value off this template generation's own
//     atomic extraNonce counter (`++this.extraNonce`).
//  2. COPY tpl.RawTemplateBlob (never patch in place -- the parent
//     template is shared read-only across every session deriving
//     from it) and write that value BIG-ENDIAN into the copy's
//     4 bytes at ReservedOffset+0:+4
//     (`buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset)`;
//     Node's Buffer.writeUInt32BE is big-endian).
//  3. RE-DERIVE the hashing blob from the patched copy
//     (`convertBlob(this.buffer)`), because the bytes just written
//     live inside the coinbase transaction's reserved region, and
//     changing the coinbase tx changes the merkle root, which is
//     itself embedded in the hashing blob -- the parent's hashing
//     blob is stale the instant the raw blob is patched. The
//     re-derivation goes through moneroblob (panic recovery + hard
//     timeout + the process-wide malformed-blob circuit breaker);
//     never call go-xmr-lib's parse/convert pair directly and
//     unwrapped.
//
// ReservedOffset+0:+4 is deliberately a DIFFERENT 4 bytes from the
// already-shipped per-leaf instanceID stamp at ReservedOffset+4:+8
// (monero_node.go's stampInstanceID) -- the two coexist exactly as
// legacy's own extraNonce/instanceId do, in the same
// |+0 extraNonce|+4 instanceId|+8 clientPoolNonce|+12 clientNonce|
// reserved-region layout this package's minReservedOffsetHeadroom
// (12) already covers. The instanceID this leaf already wrote into
// tpl.RawTemplateBlob is preserved verbatim by the copy in step 2.
//
// DEGRADES GRACEFULLY, NEVER FAILS DERIVATION (ok=false, caller
// keeps the parent's unstamped bytes) -- matching this package's
// pervasive "best-effort, never block the primary path" convention
// (checkin, relay publish, XNP-proxy reservation):
//
//   - gen is nil, or tpl carries no *moneroTemplateData, or it has
//     no raw template blob: not a Monero-family shared template at
//     all (e.g. every Tari path, and this package's own Tari-shaped
//     test doubles) -- nothing to stamp. Every one of these is now
//     logged (jm.logger, always-on, never Debug-gated) rather than
//     silent, including the concrete Go type actually found in
//     tpl.TemplateData, precisely so a real Tari-shaped template
//     landing on this Monero-only path by mistake is immediately
//     diagnosable from production logs, instead of indistinguishable
//     from the ordinary/expected "not Monero-family" case.
//   - This template generation has ALREADY been found un-stampable
//     (gen.stampUnavailable is latched): skip immediately, with no
//     counter consumption, no parse attempt and no further
//     circuit-breaker exposure -- but NOT silently: the first
//     derivation to observe the latch already set (i.e. every
//     session after whichever one originally tripped it) logs
//     exactly once per template generation
//     (gen.stampUnavailableLogged), so a live incident investigation
//     can see that this generation is still being served unstamped,
//     not just the one original failure. See
//     sharedTemplateGeneration.stampUnavailable's doc comment for
//     why latching the SKIP is a correctness requirement, not just
//     an optimization -- only the skip itself is latched, never the
//     one-time log.
//   - ReservedOffset is negative, or
//     ReservedOffset+minReservedOffsetHeadroom does not fit inside
//     the raw template blob: the exact same bounds check
//     stampInstanceID/GetBlockTemplate already apply, with the exact
//     same verdict they already reach (skip the optional stamp,
//     still serve the job). Logged as a real, always-on WARNING
//     (jm.logger, not Debug-gated) -- unlike the analogous check in
//     GetBlockTemplate, this one is NOT a routine "short, low-tx
//     coinbase-only template" degradation: a raw Monero block
//     template is always large enough to fit
//     ReservedOffset+minReservedOffsetHeadroom bytes in real
//     production traffic, so this firing at all is itself a
//     suspicious/anomalous signal (wrong offset math, a corrupted
//     blob, or a genuine upstream parsing bug), not an expected
//     soft-degrade.
//   - The hashing-blob re-derivation errors (a malformed blob, or
//     the circuit breaker is open): logged as a real WARNING (this
//     one is genuinely unexpected -- these exact bytes already
//     parsed successfully once, when the template was fetched or
//     adopted) and the parent's unstamped bytes are used, exactly as
//     before this fix. Never an error return.
//   - The re-derived hashing blob no longer yields the same parsed
//     nonce offset the template recorded: refuse the stamp rather
//     than hand a miner a blob whose nonce field
//     BuildCandidateBlock would later patch at a different offset
//     than the miner actually mined at.
//
// Every one of those failure conditions latches gen.stampUnavailable
// on its way out, so the cost/noise/breaker exposure of a genuinely
// un-stampable template is paid exactly ONCE per template
// generation, not once per arriving session.
func (jm *JobManager) extraNonceStampedTemplate(tpl *Job, gen *sharedTemplateGeneration) (stampedMoneroTemplate, bool) {
	var none stampedMoneroTemplate
	if tpl == nil || gen == nil {
		jm.logger.Printf("solo: monero: extraNonceStampedTemplate skipped (tpl_nil=%v gen_nil=%v) -- per-job extraNonce stamp omitted for this derivation", tpl == nil, gen == nil)
		return none, false
	}
	data, ok := tpl.TemplateData.(*moneroTemplateData)
	if !ok || data == nil {
		jm.logger.Printf("solo: monero: shared template's TemplateData is not a usable *moneroTemplateData (concrete type %T) -- per-job extraNonce stamp omitted for this derivation, height=%d", tpl.TemplateData, tpl.Height)
		return none, false
	}
	if len(tpl.RawTemplateBlob) == 0 {
		jm.logger.Printf("solo: monero: shared template has an empty RawTemplateBlob -- per-job extraNonce stamp omitted for this derivation, height=%d", tpl.Height)
		return none, false
	}
	if gen.stampUnavailable.Load() {
		gen.stampUnavailableLogged.Do(func() {
			jm.logger.Printf("solo: monero: this shared template generation was already latched un-stampable by an earlier derivation (see that earlier WARNING line for the root cause) -- per-job extraNonce stamp omitted for every remaining job derived from it, height=%d", tpl.Height)
		})
		return none, false
	}

	offset := tpl.ReservedOffset
	if offset < 0 || offset+minReservedOffsetHeadroom > len(tpl.RawTemplateBlob) {
		gen.stampUnavailable.Store(true)
		jm.logger.Printf("solo: monero: WARNING: reserved region does not fit in template blob (offset=%d len(blob)=%d) -- this should be structurally impossible for a real Monero block template, treat as a genuine anomaly, not routine degradation -- per-job extraNonce stamp omitted for every job derived from this template, height=%d", offset, len(tpl.RawTemplateBlob), tpl.Height)
		return none, false
	}

	// `++this.extraNonce` -- the counter starts at 0 and the FIRST
	// derivation off a given template therefore stamps 1, exactly
	// like the legacy pre-increment reference (so "0" is never a
	// stamped value, and a never-stamped template is distinguishable
	// from the first stamped job).
	nonce := gen.extraNonce.Add(1)

	templateBlob := make([]byte, len(tpl.RawTemplateBlob))
	copy(templateBlob, tpl.RawTemplateBlob)
	binary.BigEndian.PutUint32(templateBlob[offset:offset+4], nonce)

	hashingBlob, err := moneroblob.ConvertTemplateBlobToHashingBlob(hex.EncodeToString(templateBlob))
	if err != nil {
		gen.stampUnavailable.Store(true)
		jm.logger.Printf("solo: monero: WARNING: could not re-derive the hashing blob after stamping extraNonce=%d at reserved_offset+0 (height=%d): %v -- falling back to the UNSTAMPED shared template bytes for every job derived from this template, which means sessions on it may duplicate each other's search space", nonce, tpl.Height, err)
		return none, false
	}

	// Re-parse the nonce offset from the FRESHLY re-derived blob and
	// require it to still match what the template recorded. The
	// extraNonce bytes live in the coinbase tx, well past the block
	// header, so this invariant should always hold -- but
	// MoneroNodeClient.BuildCandidateBlock hard-fails a submit whose
	// re-parsed offset disagrees with data.NonceOffset, so proving it
	// HERE (where the fallback is free) is strictly better than
	// discovering it at block-find time.
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(hashingBlob)
	if err != nil {
		gen.stampUnavailable.Store(true)
		jm.logger.Printf("solo: monero: WARNING: could not parse the nonce offset out of the extraNonce-stamped hashing blob (extra_nonce=%d height=%d): %v -- falling back to the UNSTAMPED shared template bytes for every job derived from this template", nonce, tpl.Height, err)
		return none, false
	}
	if nonceOffset != data.NonceOffset {
		gen.stampUnavailable.Store(true)
		jm.logger.Printf("solo: monero: WARNING: stamping extraNonce=%d changed the parsed block-header nonce offset (%d -> %d) at height=%d -- falling back to the UNSTAMPED shared template bytes for every job derived from this template rather than serving a blob BuildCandidateBlock would later reject", nonce, data.NonceOffset, nonceOffset, tpl.Height)
		return none, false
	}

	return stampedMoneroTemplate{
		templateBlob: templateBlob,
		hashingBlob:  hashingBlob,
		data: &moneroTemplateData{
			HashingBlob:    hashingBlob,
			TemplateBlob:   templateBlob,
			NonceOffset:    nonceOffset,
			SeedHash:       data.SeedHash,
			Difficulty:     data.Difficulty,
			Height:         data.Height,
			ReservedOffset: data.ReservedOffset,
		},
	}, true
}

// jobForXNFromSharedTemplate is jobForXN's cache-miss path for the
// algos usesSharedTemplate covers. It NEVER calls
// jm.cfg.Node.GetBlockTemplate itself -- it goes through
// currentSharedTemplate, which fetches at most once process-wide per
// template generation -- and then derives THIS xn's own Job from that
// shared template and caches it under perXN[xn]/jobsByID[job.ID]
// exactly as the per-xn path always has.
//
// The per-xn jm.genLocks single-flight is deliberately KEPT here (not
// replaced by templateFetchMu): it still provides the original,
// independently-needed guarantee that two concurrent first-requests
// for the SAME xn collapse to ONE cached Job rather than two
// (preserving JobForXN's documented "repeat requests for the same xn
// get the SAME Job / consistent job_id" contract -- see
// TestJobForXNConcurrentFirstRequestsForSameXNDoNotDuplicate). The
// two locks are strictly nested, always in the same order (genLock
// then templateFetchMu, never the reverse), so they cannot deadlock.
func (jm *JobManager) jobForXNFromSharedTemplate(ctx context.Context, xn string, difficulty uint64) (*Job, error) {
	genLockAny, _ := jm.genLocks.LoadOrStore(xn, &sync.Mutex{})
	genLock := genLockAny.(*sync.Mutex)
	genLock.Lock()
	defer genLock.Unlock()

	if job, ok := jm.lookupXN(xn); ok {
		return job, nil
	}

	tpl, gen, err := jm.currentSharedTemplate(ctx)
	if err != nil {
		return nil, err
	}

	job, err := jm.jobFromSharedTemplate(tpl, gen, difficulty)
	if err != nil {
		return nil, err
	}

	jm.mu.Lock()
	jm.perXN[xn] = job
	jm.jobsByID[job.ID] = job
	jm.mu.Unlock()

	jm.cfg.Debug.Debugf("solo: job derived from shared template xn=%s job_id=%s height=%d static_difficulty=%d network_target_difficulty=%d (no daemon call)", xn, job.ID, job.Height, job.StaticDifficulty, job.NetworkTargetDifficulty)

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
//
// source (one of TemplateSourceLocal/TemplateSourceRelay) identifies
// WHICH real call site triggered this invalidation and is threaded
// straight through to notify's subscriber callbacks -- see that
// const block's own doc comment for why (internal/leaflib/direct's
// template-distribution metrics consume it as their own "source"
// label).
//
// In shared-template mode (see usesSharedTemplate) this ALSO drops
// jm.sharedTemplate, so the next per-session request establishes a
// genuinely fresh one -- exactly ONCE, process-wide, via
// currentSharedTemplate's single-flight -- rather than each of the N
// repushed sessions firing its own daemon call. Callers that have
// ALREADY fetched the real replacement template should use
// invalidateAll with a seed instead, to avoid even that one round
// trip (see invalidateAll's doc comment and tipPollLoop's call sites).
func (jm *JobManager) InvalidateAll(source string) {
	jm.invalidateAll(source, nil)
}

// invalidateAll is InvalidateAll's real implementation, plus the
// ability to SEED the new cache generation with an already-fetched
// shared template (seed) in the same atomic step that wipes the old
// one.
//
// Seeding matters because of ordering: InvalidateAll's notify() is
// what drives direct.Server.invalidateAndRepushJobs' per-session
// fan-out (every connected session immediately calling
// JobForXNAtDifficulty). If the shared template were merely CLEARED
// before that notify, the first session to be repushed would trigger
// a fresh single-flight fetch -- correct, but one wholly avoidable
// daemon round trip when the caller (tipPollLoop) has ALREADY
// fetched the real new template for its own isBetterCandidate
// comparison and is holding it right there. Installing it as the
// shared template BEFORE notify fires means that whole fan-out
// derives from it with ZERO daemon calls.
//
// seed is ignored entirely (treated as nil) when this JobManager is
// not in shared-template mode, so every Tari code path behaves
// EXACTLY as it did before this fix.
func (jm *JobManager) invalidateAll(source string, seed *Job) {
	if !jm.usesSharedTemplate() {
		seed = nil
	}
	jm.mu.Lock()
	jm.perXN = make(map[string]*Job)
	jm.jobsByID = make(map[string]*Job)
	// Dropping the shared template here is what makes the NEXT
	// per-session request establish a genuinely fresh one (exactly
	// once, via currentSharedTemplate's single-flight) rather than
	// keep deriving jobs from a template for a tip that has already
	// moved.
	jm.sharedTemplate = seed
	// A genuinely new template generation means a genuinely FRESH
	// extraNonce counter, restarting at 0 -- matching legacy's own
	// `this.extraNonce = 0` in the BlockTemplate constructor. Written
	// in the SAME critical section as jm.sharedTemplate so no
	// derivation can ever observe a new template paired with the old
	// generation's counter (see
	// JobManager.sharedTemplateGen's doc comment). nil when seed is
	// nil (unseeded invalidation), which currentSharedTemplate's
	// next fetch then replaces.
	jm.sharedTemplateGen = newSharedTemplateGeneration(seed)
	jm.mu.Unlock()
	if seed != nil {
		jm.cfg.Debug.Debugf("solo: per-xn job cache invalidated and reseeded with an already-fetched shared template (job_id=%s height=%d) -- no per-session daemon calls needed", seed.ID, seed.Height)
	} else {
		jm.cfg.Debug.Debugf("solo: per-xn job cache invalidated (all cached jobs dropped)")
	}
	jm.notify(source)
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
// is invalidated (tip movement or periodic refresh), receiving the
// real source (TemplateSourceLocal/TemplateSourceRelay) of that
// invalidation -- see InvalidateAll's doc comment. Callers (Server)
// use this to push freshly (re-)generated per-xn jobs out to every
// currently-connected, logged-in session. Returns an unsubscribe
// function.
func (jm *JobManager) Subscribe(fn func(source string)) (unsubscribe func()) {
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

func (jm *JobManager) notify(source string) {
	jm.subMu.RLock()
	defer jm.subMu.RUnlock()
	for _, fn := range jm.subs {
		fn(source)
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
// template broadcasts. Per this feature's settled design (relay is
// authoritative over the local node whenever it disagrees — no
// time-boxing/hysteresis/fallback), every genuinely new (non-self,
// non-duplicate — already guaranteed by relay.Relay.SubscribeTemplate's
// own contract) template message is compared against this
// JobManager's own currently tracked best (height, size) via
// isBetterCandidate BEFORE anything is invalidated/adopted:
//
//   - Not better: logged at Debug level and otherwise ignored --
//     no cache wipe, no wasted local re-fetch (this is the exact bug
//     this feature fixes: the old behavior unconditionally wiped and
//     let the next JobForXN call re-invoke GetBlockTemplate against
//     THIS instance's own possibly-lagging node on ANY relay message
//     at all, regardless of whether it was actually better).
//   - Better, and the real template content reconstructs successfully
//     (NodeClient.JobFromTemplateBytes): adopted directly via
//     adoptRelayedJob -- every currently-known xn is immediately
//     reseeded with the reconstructed job, with NO local
//     GetBlockTemplate round-trip.
//   - Better, but reconstruction fails (e.g. an empty/malformed
//     TemplateData, or a pre-adoption-feature bare-height-only
//     publisher): falls back to a plain InvalidateAll, matching this
//     feature's pre-existing behavior exactly (the next per-xn
//     request re-fetches locally).
//
// Safe to call unconditionally even when jm.cfg.Relay is nil or
// disabled/unconfigured: SubscribeTemplate itself is nil/disabled-
// Relay-safe (see relay.Relay.Enabled()'s `r != nil` check), returning
// a no-op unsubscribe func and a nil error in that case. The returned
// unsubscribe func is invoked once ctx is cancelled, tying this
// subscription's lifetime to the SAME ctx refreshLoop/tipPollLoop
// already use.
func (jm *JobManager) startTemplateRelaySubscription(ctx context.Context) {
	unsub, err := jm.cfg.Relay.SubscribeTemplate(func(msg relay.TemplateMessage) {
		best := jm.currentBestSnapshot()
		if best.set && !isBetterCandidate(best.height, msg.Height, best.size, msg.Size) {
			jm.cfg.Debug.Debugf("solo: received template relay message from another instance (height=%d size=%d algo=%s network=%s) -- not better than tracked best (height=%d size=%d), ignoring (no cache wipe, no local re-fetch)", msg.Height, msg.Size, msg.Algo, msg.Network, best.height, best.size)
			return
		}
		job, jerr := jm.cfg.Node.JobFromTemplateBytes(msg.TemplateData, jm.cfg.Algo)
		if jerr != nil || job == nil {
			jm.logger.Printf("solo: received a superior template relay message from another instance (height=%d size=%d algo=%s network=%s) but could not reconstruct a job from its bytes (%v) -- falling back to a plain per-xn job cache invalidation", msg.Height, msg.Size, msg.Algo, msg.Network, jerr)
			jm.setBest(msg.Height, msg.Size)
			jm.InvalidateAll(TemplateSourceRelay)
			return
		}
		jm.logger.Printf("solo: adopting superior relayed template from another instance (height=%d size=%d algo=%s network=%s), reseeding per-xn job cache without a local re-fetch", msg.Height, msg.Size, msg.Algo, msg.Network)
		jm.setBest(job.Height, msg.Size)
		jm.adoptRelayedJob(job)
	})
	if err != nil {
		jm.logger.Printf("solo: template relay subscribe failed (template-relay fast-invalidation/adoption disabled, primary tip-poll path unaffected): %v", err)
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
			jm.InvalidateAll(TemplateSourceLocal)
		}
	}
}

// tipPollLoop polls the local node's chain tip and, on a genuine
// height increase, decides whether to invalidate/replace the served
// per-xn job cache. When jm.cfg.Relay is disabled/unconfigured, this
// preserves the exact original, pre-adoption-feature behavior: an
// unconditional wipe on any genuine local tip increase, no extra
// fetch/compare/publish overhead -- there is nothing to compare
// against or publish to.
//
// When a Relay IS configured, a genuine local tip increase now fetches
// a real candidate template (needed to compute its real serialized
// size and to have real content to publish -- see publishTemplateForJob)
// and compares it, via the SAME isBetterCandidate priority order the
// relay-adoption path uses, against this JobManager's own tracked
// best (which may already be ahead of this instance's own local view,
// having been set by a previously-adopted relayed template). Only a
// genuinely better local candidate invalidates the cache and gets
// published; an inferior one (this instance's own node lagging behind
// a sibling's already-adopted relayed template) leaves the
// currently-served cache untouched and publishes nothing.
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
			if height <= last {
				continue
			}

			jm.mu.Lock()
			jm.lastTipHeight = height
			jm.mu.Unlock()

			if !jm.cfg.Relay.Enabled() {
				// No relay in play (leaf-solo's own default, or
				// leaf-direct without one configured) -- nothing to
				// compare against or publish to, so preserve the
				// exact original behavior unchanged.
				jm.logger.Printf("solo: new tip detected (height %d -> %d), invalidating per-xn job cache", last, height)
				// SHARED-TEMPLATE MODE ONLY: fetch the real new
				// template ONCE here and seed the new cache
				// generation with it, so the invalidation's own
				// subscriber fan-out
				// (direct.Server.invalidateAndRepushJobs, one
				// JobForXNAtDifficulty call per connected session)
				// derives every session's job from it with ZERO
				// daemon calls. Pre-fix, this exact path was the
				// second half of the live incident: a genuine tip
				// change invalidated everything and then every
				// single connected session independently re-fetched.
				// A failed fetch here is NOT fatal -- fall through to
				// a plain unseeded invalidation, which is still
				// correct (the next per-session request establishes
				// the template once, via single-flight).
				if jm.usesSharedTemplate() {
					if seed, ferr := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress, jm.cfg.Algo); ferr == nil && seed != nil {
						if seed.CreatedAt.IsZero() {
							seed.CreatedAt = time.Now()
						}
						jm.recordBestIfBetter(seed)
						jm.invalidateAll(TemplateSourceLocal, seed)
						continue
					} else if ferr != nil {
						jm.logger.Printf("solo: tip-poll shared-template refetch failed (height %d): %v -- falling back to a plain cache invalidation (the next session request will establish it once)", height, ferr)
					}
				}
				jm.InvalidateAll(TemplateSourceLocal)
				continue
			}

			job, ferr := jm.cfg.Node.GetBlockTemplate(ctx, jm.cfg.PayoutAddress, jm.cfg.Algo)
			if ferr != nil || job == nil {
				jm.logger.Printf("solo: tip-poll candidate template fetch failed (height %d): %v", height, ferr)
				continue
			}
			data, tbErr := jm.cfg.Node.TemplateBytesForRelay(job)
			if tbErr != nil {
				data = nil
			}
			size := len(data)
			best := jm.currentBestSnapshot()
			if best.set && !isBetterCandidate(best.height, job.Height, best.size, size) {
				jm.cfg.Debug.Debugf("solo: local candidate template (height=%d size=%d) not better than tracked best (height=%d size=%d) -- keeping existing per-xn job cache, no publish", job.Height, size, best.height, best.size)
				continue
			}

			jm.logger.Printf("solo: new tip detected (height %d -> %d), invalidating per-xn job cache", last, height)
			jm.setBest(job.Height, size)
			// Seed the new cache generation with the template this
			// branch ALREADY fetched above for its own
			// isBetterCandidate comparison -- see invalidateAll's doc
			// comment for why seeding (rather than merely clearing)
			// matters for the subscriber fan-out that notify triggers.
			// No-op for non-shared-template (Tari) algos: invalidateAll
			// discards the seed for those, leaving this path
			// byte-for-byte equivalent to its pre-fix behavior.
			jm.invalidateAll(TemplateSourceLocal, job)
			jm.publishTemplateForJob(ctx, job, data)
		}
	}
}

// isBetterCandidate reports whether a candidate (height, size)
// template should replace the current one, per the maintainer's
// settled priority (relay-template-adoption brief, "design decision
// already settled with the maintainer"):
//
//  1. Strictly higher Height always wins -- a newer block height is
//     unconditionally better than any same-or-lower height template,
//     regardless of size.
//  2. At EQUAL height, strictly larger serialized template byte size
//     wins ("larger bytes = larger fee due to the way the templates
//     are built" -- taken as ground truth, not re-derived here).
//  3. Anything else (lower height, or equal height + equal-or-smaller
//     size) is NOT better -- the candidate must not be adopted.
//
// This is the SINGLE shared comparison both the relay-adoption path
// (startTemplateRelaySubscription) and the local-fetch path (jobForXN,
// tipPollLoop) call -- see this feature's brief: "The comparison
// function should be a single shared piece of logic both paths call,
// not duplicated."
func isBetterCandidate(currentHeight, candidateHeight uint64, currentSize, candidateSize int) bool {
	if candidateHeight > currentHeight {
		return true
	}
	if candidateHeight == currentHeight && candidateSize > currentSize {
		return true
	}
	return false
}

// bestTemplate is a point-in-time snapshot of JobManager's own
// tracked bestHeight/bestSize/bestSet fields -- see those fields' own
// doc comment. Returned by currentBestSnapshot so callers never read
// jm.bestHeight/bestSize/bestSet directly without jm.mu held.
type bestTemplate struct {
	height uint64
	size   int
	set    bool
}

// currentBestSnapshot returns a point-in-time copy of jm's tracked
// best (height, size) template record -- safe to call concurrently.
func (jm *JobManager) currentBestSnapshot() bestTemplate {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return bestTemplate{height: jm.bestHeight, size: jm.bestSize, set: jm.bestSet}
}

// CurrentBest returns a point-in-time snapshot of this JobManager's own
// tracked best (height, size) template record -- the same state
// isBetterCandidate/setBest already maintain internally, exposed
// read-only for a caller (leaf-direct's Server) that needs to know the
// current best height/size WITHOUT duplicating that tracking itself.
// ok is false if no template has been observed yet (mirrors
// bestTemplate.set).
func (jm *JobManager) CurrentBest() (height uint64, size int, ok bool) {
	b := jm.currentBestSnapshot()
	return b.height, b.size, b.set
}

// setBest records (height, size) as JobManager's new tracked best
// template -- called whenever a job is (re)installed as the served
// baseline by ANY path (local fetch in jobForXN/tipPollLoop, or a
// successfully-adopted relay template in
// startTemplateRelaySubscription).
func (jm *JobManager) setBest(height uint64, size int) {
	jm.mu.Lock()
	jm.bestHeight = height
	jm.bestSize = size
	jm.bestSet = true
	jm.mu.Unlock()
}

// templateSizeForRelay returns the real serialized byte size of job
// via jm.cfg.Node.TemplateBytesForRelay, for isBetterCandidate
// comparisons -- 0 (never an error) if job is nil, jm.cfg.Node is
// nil, or TemplateBytesForRelay itself errors/returns no data (e.g.
// GRPCNodeClient/MoneroNodeClient's "not supported" stubs). A 0 size
// here never blocks the primary local-fetch path; it only means this
// particular job can't outrank an existing equal-height best on size
// alone (it can still win outright via a strictly higher height).
func (jm *JobManager) templateSizeForRelay(job *Job) int {
	if job == nil || jm.cfg.Node == nil {
		return 0
	}
	data, err := jm.cfg.Node.TemplateBytesForRelay(job)
	if err != nil || data == nil {
		return 0
	}
	return len(data)
}

// adoptRelayedJob installs job (reconstructed from a superior relayed
// template -- see startTemplateRelaySubscription) as the new baseline
// for EVERY currently-known xn, replacing the whole perXN/jobsByID
// cache -- the same "wipe" shape InvalidateAll already uses, but
// seeded directly from the relayed content instead of clearing to
// empty and waiting for the next per-xn GetBlockTemplate call (which
// would just hit this instance's own, already-confirmed-lagging,
// local node again -- defeating the entire point of adopting a
// relayed template in the first place).
//
// SHARED-TEMPLATE MODE (usesSharedTemplate): the relayed template is
// ALSO installed as jm.sharedTemplate, and each already-known xn gets
// its OWN derived *Job (via jobFromSharedTemplate) carrying that xn's
// own previously-stamped difficulty. This closes two real gaps at
// once:
//
//  1. Pre-fix, adoptRelayedJob only reseeded xns ALREADY present in
//     perXN. A session connecting AFTER an adoption was a plain cache
//     miss and therefore fired its own local GetBlockTemplate call
//     against the lagging local node -- exactly the round trip
//     adoption exists to avoid. Installing the shared template means
//     those later arrivals derive from the relayed content too, with
//     zero daemon calls.
//  2. Pre-fix, every xn was handed the SAME literal *Job pointer,
//     which silently discarded each session's own vardiff difficulty
//     (all sessions inherited the relayed job's single
//     StaticDifficulty) and made one shared nonceMu/usedNonces set
//     serve every session at once. Deriving per-xn restores the
//     per-session Job guarantee this codebase depends on for
//     submit-time ownership/replay protection -- see
//     jobFromSharedTemplate's doc comment.
//
// NON-SHARED (Tari) MODE: behavior is deliberately left EXACTLY as it
// was -- every xn shares the one adopted *Job pointer. leaf-direct's
// shared fleet-wide payout_address already means there's no
// coinbase-mismatch concern across sibling instances, per this
// feature's own brief.
func (jm *JobManager) adoptRelayedJob(job *Job) {
	if jm.usesSharedTemplate() {
		jm.adoptRelayedJobShared(job)
		return
	}
	jm.mu.Lock()
	newPerXN := make(map[string]*Job, len(jm.perXN))
	for xn := range jm.perXN {
		newPerXN[xn] = job
	}
	jm.perXN = newPerXN
	jm.jobsByID = map[string]*Job{job.ID: job}
	jm.mu.Unlock()
	jm.cfg.Debug.Debugf("solo: per-xn job cache reseeded from adopted relay template (job_id=%s height=%d)", job.ID, job.Height)
	jm.notify(TemplateSourceRelay)
}

// adoptRelayedJobShared is adoptRelayedJob's shared-template-mode
// implementation -- see that method's doc comment for the full
// rationale. The per-xn derivations are computed OUTSIDE jm.mu (each
// needs a crypto/rand job ID) and then swapped in under a single
// write lock, so this never holds the manager's lock across
// randomness generation.
func (jm *JobManager) adoptRelayedJobShared(job *Job) {
	// Snapshot which xns are currently known, and each one's own
	// current difficulty, so it can be preserved across the adoption.
	jm.mu.RLock()
	difficulties := make(map[string]uint64, len(jm.perXN))
	for xn, prev := range jm.perXN {
		if prev != nil {
			difficulties[xn] = prev.StaticDifficulty
			continue
		}
		difficulties[xn] = job.StaticDifficulty
	}
	jm.mu.RUnlock()

	newPerXN := make(map[string]*Job, len(difficulties))
	newJobsByID := make(map[string]*Job, len(difficulties))
	// A newly-adopted relay template is a genuinely NEW template
	// generation, so it gets its own FRESH extraNonce counter
	// (restarting at 0) -- minted here, BEFORE the per-xn derivation
	// loop below, and installed alongside the template itself under
	// jm.mu further down. Minting it locally first (rather than
	// installing the template and then reading the counter back) is
	// what lets every xn reseeded by THIS adoption draw from the very
	// same counter the later, lazily-arriving sessions will draw
	// from, so no two sessions on this template generation can ever
	// receive the same extraNonce. See
	// JobManager.sharedTemplateGen's doc comment.
	gen := newSharedTemplateGeneration(job)
	for xn, difficulty := range difficulties {
		derived, err := jm.jobFromSharedTemplate(job, gen, difficulty)
		if err != nil {
			// A failed job-ID mint for one xn must not abort the
			// whole adoption: that xn simply ends up uncached and
			// derives its own job (from the SAME shared template
			// installed below, still with no daemon call) on its
			// next request.
			jm.logger.Printf("solo: could not derive a job for xn %s from the adopted relay template: %v (this xn will derive one on its next request instead)", xn, err)
			continue
		}
		newPerXN[xn] = derived
		newJobsByID[derived.ID] = derived
	}

	// Capture the reseeded count BEFORE publishing newPerXN into
	// jm.perXN below. Once that assignment happens and jm.mu is
	// released, newPerXN is no longer exclusively owned by this
	// goroutine -- a concurrent jobForXNFromSharedTemplate can take
	// jm.mu and write into that SAME map, so reading len(newPerXN)
	// afterwards would be a genuine data race (confirmed by
	// `go test -race`).
	reseeded := len(newPerXN)

	jm.mu.Lock()
	jm.sharedTemplate = job
	jm.sharedTemplateGen = gen
	jm.perXN = newPerXN
	jm.jobsByID = newJobsByID
	jm.mu.Unlock()

	jm.cfg.Debug.Debugf("solo: shared template adopted from relay (job_id=%s height=%d) and %d known xn(s) reseeded with their own derived jobs -- no local daemon call", job.ID, job.Height, reseeded)
	jm.notify(TemplateSourceRelay)
}

// publishTemplateForJob best-effort-broadcasts a relay.TemplateMessage
// carrying job's real serialized template content (data, already
// fetched via NodeClient.TemplateBytesForRelay by the caller — see
// tipPollLoop) so a sibling leaf instance's own JobManager can adopt
// it directly (see startTemplateRelaySubscription) rather than merely
// being told to re-poll its own possibly-lagging node. data may be
// nil/empty (e.g. TemplateBytesForRelay errored or this NodeClient
// doesn't support it) -- that degrades gracefully to a bare tip
// notification, exactly like this function's pre-adoption-feature
// behavior. Never blocks/fails the primary tip-poll path: PublishTemplate
// itself is already a complete no-op on a nil/disabled Relay, and any
// real publish error is only logged.
func (jm *JobManager) publishTemplateForJob(ctx context.Context, job *Job, data []byte) {
	algo := algoWireName(jm.cfg.Algo)
	network := jm.cfg.Network
	msg := relay.TemplateMessage{
		Algo:         algo,
		Network:      network,
		Height:       job.Height,
		TemplateData: data,
		Size:         len(data),
		Hash:         syntheticTipDedupHash(algo, network, job.Height),
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
