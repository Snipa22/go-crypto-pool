// Copyright and license: see repository LICENSE (MIT).
//
// Package direct implements leaf-direct, go-crypto-pool's mode 1: the
// primary production ingest path. It speaks the exact same real
// Monero-family stratum wire protocol and validates shares/blocks with
// the exact same real per-algo validators as leaf-solo (mode 2), but
// forwards validated shares/blocks to the real backend via
// internal/leaflib/transport.ShareTransport instead of self-submitting
// to a single daemon.
//
// Two real capabilities exist here that neither leaf-solo nor the
// legacy nodejs-pool reference ever had (see Alex, 2026-08-22):
//
//  1. Direct parallel block submission to multiple configured GRPC
//     node addresses on a genuine block find, with "at least one
//     acceptance = success" semantics (multisubmit.go).
//  2. A generic, coin-agnostic NATS-based best-effort relay
//     broadcast/resubmit mechanism for found blocks
//     (internal/leaflib/relay), fully optional/no-op when
//     unconfigured and never blocking the primary path.
//
// What this package reuses AS-IS from the already-merged, read-only
// internal/leaflib/solo package (see AGENTS.md / this task's own
// explicit direction not to reinvent these): the wire protocol types
// (protocol.go: Request/LoginRequest/SubmitRequest/JobPush/
// ShareResponse/JobPayload), the JobManager/Job types and the
// NodeClient interface (this package supplies its OWN NodeClient
// implementation, node.go, backed by a real per-node-injectable GRPC
// client rather than the older package-level-singleton API — see that
// file's doc comment), internal/leaflib.ConnectionManager/
// ManagedConnection for miner connection lifecycle,
// internal/leaflib.VardiffConfig/ComputeRetarget for adaptive
// difficulty, and internal/leaflib/validator.Registry for real
// per-algo PoW validation.
package direct

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/chainheight"
	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Server ties together internal/leaflib.ConnectionManager (miner
// connection lifecycle, reused as-is), a solo.JobManager (reused as-is
// — this package only supplies its own solo.NodeClient implementation,
// see node.go), a validator.Registry (reused as-is, real per-algo PoW
// checking), a transport.ShareTransport (the real, genuinely new
// wiring point vs. leaf-solo — every validated share/block goes here
// instead of a single self-submitted daemon), a MultiNodeSubmitter
// (real parallel multi-node GRPC block submission), and an optional
// *relay.Relay (best-effort NATS block broadcast/resubmit, no-op when
// unconfigured).
type Server struct {
	cm         *leaflib.ConnectionManager
	jobManager *solo.JobManager
	node       solo.NodeClient
	validators validator.Registry
	network    poolpb.Network
	logger     *log.Logger

	transport   transport.ShareTransport
	multiSubmit *MultiNodeSubmitter
	relay       *relay.Relay
	algo        poolpb.Algo
	poolType    poolpb.PoolType
	poolID      int32

	// chainHeightPoller is the leaf_monero_chain_height/
	// leaf_tari_chain_height background poller (see EnableMetrics),
	// nil unless EnableMetrics was called AND s.node implements
	// chainheight.TipInfoSource. Stopped from Shutdown.
	chainHeightPoller *chainheight.Poller

	vardiff solo.VardiffConfig

	// trustConfig gates the real, legacy-ported probabilistic
	// RandomX-validation-skip mechanism for RXT/RXM shares (see
	// solo/trust.go). Zero-value TrustConfig{} (Enabled: false) is
	// the default — every share is always fully validated unless a
	// caller explicitly opts in via EnableTrust. UNLIKE solo (which
	// removed this mechanism entirely -- DISPATCH_BRIEF.md,
	// 2026-09-10, Fix 5 -- it was unreachable dead weight there post
	// solo's block-find-only validation change), leaf-direct still
	// validates EVERY RXT/RXM submit for real, so a ramped trust
	// state here is a genuinely live, real-money-relevant tradeoff:
	// see EnableTrust's own doc comment below for the explicit risk
	// framing an operator enabling this on leaf-direct should
	// understand before doing so.
	trustConfig solo.TrustConfig

	// invalidShareGuardConfig mirrors solo.Server's own identical
	// field exactly -- see leaflib.InvalidShareGuard's doc comment
	// for the full DISPATCH_BRIEF.md 2026-09-10 Fix 2b rationale.
	// Defaults to leaflib.DefaultInvalidShareGuardConfig() (enabled)
	// in NewServer; overridable via SetInvalidShareGuardConfig.
	invalidShareGuardConfig leaflib.InvalidShareGuardConfig

	// addressFlags mirrors solo.Server's own identical field exactly
	// -- see that field's doc comment. leaf-direct's Cache is fed by
	// a real backend poll (addressflags.HTTPSource) rather than
	// leaf-solo's local file (addressflags.FileSource) -- see
	// cmd/leaf-direct/main.go's wiring -- but the enforcement logic
	// in session.go's handleLogin/vardiff.go's maybeRetarget is
	// identical either way.
	addressFlags *addressflags.Cache

	mu       sync.RWMutex
	sessions map[uint64]*Session

	unsubscribe func()
	relayUnsub  func()

	metrics          *directmetrics.Metrics
	maxAddressLabels int

	// statsPageMaxSessions caps how many SessionStat rows
	// StatsHTMLHandler actually renders in its "Connected sessions"
	// table -- NOT the same as ActiveSessions (which stays uncapped)
	// and NOT applied inside Stats() itself (see
	// capSessionsForDisplay's own doc comment in statsui.go for the
	// full rationale: Stats() is also used by tests and other
	// internal callers that legitimately want the full, uncapped
	// list). Defaults to DefaultStatsPageMaxSessions.
	// 0/negative disables the cap entirely (render everything),
	// mirroring this codebase's existing zero-disables convention
	// (e.g. idleTimeout/noShareTimeout). Set via
	// SetStatsPageMaxSessions.
	statsPageMaxSessions int

	// Backend-transport health tracking (statsui.go's Stats() reads
	// these) — leaf-direct's analogue of leaf-proxy's
	// UpstreamHealth: there is no persistent backend connection
	// object to type-assert against (transport.ShareTransport is a
	// stateless per-call interface, see internal/leaflib/transport),
	// so instead the last known real outcome (success or failure) of
	// forwardShare/forwardBlock is tracked directly here.
	transportOKSoFar    atomic.Bool // starts true: "no known failure yet"
	transportErrorTotal atomic.Uint64
	lastTransportKind   atomic.Value // string
	lastTransportAt     atomic.Value // time.Time

	// hideRemoteAddress mirrors internal/leaflib/solo/server.go's
	// identical field exactly — see that doc comment (including its
	// FIX_BRIEF.md finding #20 atomic.Bool rationale). Defaults to
	// false; set via SetHideRemoteAddress.
	hideRemoteAddress atomic.Bool

	// randomxPool mirrors solo.Server's own identical field exactly —
	// see solo/asyncvalidation.go's package doc comment for the full
	// production incident/rationale. leaf-direct has the exact same
	// read-loop-blocking bug leaf-solo did (its own handleSubmit also
	// calls validator.RandomXValidator.Validate inline for RXT/RXM), so
	// it reuses solo's exported AsyncValidationPool rather than
	// duplicating the type.
	randomxPool *solo.AsyncValidationPool

	// forwardPool is Fix 12's (DISPATCH_BRIEF.md 2026-09-10) own
	// SEPARATE, dedicated worker pool for session.go's
	// forwardShare/forwardBlock backend-transport calls -- see those
	// methods' own doc comments and defaultForwardPoolWorkers' doc
	// comment for the full rationale. Deliberately NOT the same
	// randomxPool instance above: forwardShare/forwardBlock used to
	// run INSIDE finishSubmit, i.e. ON randomxPool's own worker
	// goroutines for RXT/RXM submits -- a slow-but-responding backend
	// (up to forwardShare's 5s/forwardBlock's 10s timeout) tied up
	// one of randomxPool's small, fixed number of workers for that
	// entire span, degrading process-wide RXT/RXM validation
	// throughput for every OTHER session's shares while it waited.
	// Dispatching these calls onto this leaf pool instead means a
	// slow backend can only ever saturate ITS OWN bounded pool, never
	// borrow capacity from (or block) real RandomX validation.
	// Reuses solo.AsyncValidationPool's exact same generic
	// closure-dispatching implementation (it has nothing
	// RandomX-specific in its actual mechanics, only in its doc
	// comments -- see that type's own doc comment) rather than
	// hand-rolling a second bounded-queue-plus-fixed-workers type for
	// what is structurally the identical shape.
	forwardPool *solo.AsyncValidationPool

	// jobFetchPool is the CLOSE-WAIT-accumulation production-incident
	// fix (phx-dump.supportxmr.com, leaf-direct -legacy-mode, ~20k+
	// real connected Monero miners; 17,855 CLOSE-WAIT vs 8,636 ESTAB
	// observed via `ss -tn`, leaf_direct_active_connections gauge
	// tracking process fd count ~1:1): session.go's
	// handleLogin/handleGetJob used to call
	// s.server.jobManager.JobForXNAtDifficulty DIRECTLY on
	// Session.Run's own read-loop goroutine, with NO worker-pool
	// dispatch at all -- unlike forwardShare/forwardBlock
	// (forwardPool, above) and RandomX-family finishSubmit
	// (randomxPool, above), which already got this exact fix. On a
	// per-xn job-cache MISS (first time a session's xn is seen, or --
	// critically -- after chain-tip movement invalidates EVERY
	// currently-cached xn at once, see solo/job.go's jobForXN doc
	// comment), that call acquires a per-xn generation lock inside
	// solo.JobManager (originally a single server/process-wide genMu
	// sync.Mutex shared across EVERY xn; narrowed to per-xn
	// granularity by a later, related fix -- see solo/job.go's
	// genLocks field doc comment -- but the property that matters
	// here is unchanged either way) -- which CANNOT be interrupted by
	// context cancellation under any circumstances -- then makes a
	// real GetBlockTemplate HTTP round-trip (capped at 30s by
	// MoneroNodeClient's own http.Client.Timeout, but that cap is
	// per-HTTP-call only; the lock wait itself is fully unbounded).
	// Under real load, potentially thousands of the ~20k live
	// connections sharing the SAME xn (or, before the per-xn
	// narrowing above, ANY xn at all) could be queued behind that
	// lock simultaneously after a single tip-triggered invalidation,
	// each one's session stuck unable to call scanner.Scan() again
	// (so unable to ever notice a peer's FIN) for however long its
	// own turn takes -- exactly the structural cause of the observed
	// CLOSE-WAIT accumulation: handleConn's cleanup defer is correct
	// and does fire, but only once Session.Run actually returns, and
	// Run can't get back to scanner.Scan() until this call does.
	// jobFetchPool moves that call (and everything that depends on
	// its result -- building/writing the login/getjob response) onto
	// its own dedicated, bounded worker pool instead, so it can never
	// again block any session's own read-loop goroutine -- mirroring
	// forwardPool's/randomxPool's exact same "dispatch off the read
	// loop onto a bounded solo.AsyncValidationPool via TrySubmit"
	// shape. Deliberately a THIRD, separate pool from both of those
	// (not reused): the actual contended resource here (the
	// generation lock, and transitively the downstream node's
	// template-generation capacity) is unrelated to either RandomX
	// validation throughput or backend-transport concurrency, so
	// sharing either existing
	// pool would let a job-fetch stall degrade unrelated throughput
	// for other sessions, exactly the cross-resource-contention
	// failure mode forwardPool's own doc comment already describes
	// avoiding for randomxPool.
	jobFetchPool *solo.AsyncValidationPool

	// repushPool is the SECOND, related-but-distinct production-
	// incident fix on top of jobFetchPool above (same leaf,
	// phx-dump.supportxmr.com; brief2.md): leaf_direct_template_
	// distribution_seconds/_miners went completely dark (no series at
	// all) for 15+ minutes despite real mainnet height changes every
	// ~2 minutes, with zero "new tip detected... invalidating" log
	// lines in that window (journalctl still showed unrelated
	// per-session "new block template fetched" lines from job.go's
	// jobForXN, which fires on ANY cache-miss job generation, not just
	// tip movement). Root cause chain, all synchronous on ONE
	// goroutine -- solo/job.go's tipPollLoop (~line 899-967) calls
	// InvalidateAll (~line 737-744) inline, which calls notify
	// (~line 783-789) inline while holding jm.subMu.RLock(), which
	// calls THIS package's own debouncedInvalidateAndRepushJobs
	// inline, which (on the common, never-debounced genuine-height-
	// increase path) called invalidateAndRepushJobs inline: a
	// sequential, one-session-at-a-time loop over every logged-in
	// session, each one a guaranteed real GetBlockTemplate HTTP round
	// trip (every session's xn is unique, and InvalidateAll just wiped
	// the ENTIRE per-xn cache) -- amplified to ~100,000+ sequential
	// calls by the SAME session-map bloat the sibling CLOSE-WAIT leak
	// (jobFetchPool, above) causes, but a real structural bug on its
	// own even at the correct ~20k live-connection count: tipPollLoop
	// cannot get back around to its own `select { case <-ticker.C }`
	// -- and therefore cannot detect or log the NEXT tip change, and
	// this leaf's template-distribution metrics cannot fire again --
	// until that ENTIRE sequential loop returns. Confirmed via grep: no
	// recover() anywhere in this call chain (solo/job.go's
	// tipPollLoop/InvalidateAll/notify, nor this file's
	// debouncedInvalidateAndRepushJobs/invalidateAndRepushJobs/
	// firePendingRepush) -- this is NOT a swallowed panic (which would
	// crash the whole process loudly, and the leaf stayed up serving
	// connections); it is the sequential loop genuinely still running.
	//
	// The fix has two parts (see invalidateAndRepushJobs' own doc
	// comment for the second): this pool moves the
	// s.invalidateAndRepushJobs(source) call itself off tipPollLoop's
	// (or firePendingRepush's timer's) own goroutine, via the exact
	// same dispatch-onto-a-bounded-solo.AsyncValidationPool-via-
	// TrySubmit shape jobFetchPool/randomxPool/forwardPool already
	// use. Deliberately constructed with EXACTLY 1 worker (see
	// NewServer), NOT solo.DefaultAsyncValidationWorkers()
	// (runtime.NumCPU()) like every other pool on this Server: unlike
	// randomxPool/forwardPool/jobFetchPool (which all benefit from
	// real parallelism across independent sessions/submits),
	// invalidateAndRepushJobs is a single GLOBAL operation over the
	// entire session map that must never run twice concurrently --
	// two overlapping passes could race on/mis-track
	// s.lastRepushHeight/s.lastRepushAt (repushMu only guards the
	// debounce bookkeeping in debouncedInvalidateAndRepushJobs, not a
	// second invalidateAndRepushJobs call already dispatched and
	// running). This pool exists ONLY to get that one call off
	// tipPollLoop's critical path, never to parallelize multiple
	// invocations of it against each other -- the real per-session
	// fan-out parallelism now lives INSIDE invalidateAndRepushJobs
	// itself (see that method's own doc comment).
	repushPool *solo.AsyncValidationPool

	// debugLogger is nil unless ServerConfig.Debug was set (see
	// cmd/leaf-direct/main.go's -debug/LEAF_DIRECT_DEBUG wiring) --
	// the real, opt-in verbose logging sink (internal/leaflib/
	// debuglog.go). Every Session created by this Server reads it
	// through its own server back-reference (session.go's
	// s.server.debugLogger). nil is a complete no-op.
	debugLogger *leaflib.DebugLogger

	// blockForwardTimeout mirrors ServerConfig.BlockForwardTimeout
	// exactly -- see that field's doc comment for the full 2026-09-23
	// rationale. Always a positive duration (NewServer applies the
	// 10*time.Second default when ServerConfig.BlockForwardTimeout is
	// zero/negative) -- session.go's forwardBlock reads this directly,
	// never the zero value.
	blockForwardTimeout time.Duration

	// moneroHeaderResolver, if non-nil, is this Server's real
	// monerod get_block_header_by_height client (monero_hash.go),
	// used ONLY by session.go's handleSubmit to resolve the REAL,
	// canonical Monero block hash for a genuine ALGO_RXM block find
	// -- see resolveMoneroBlockHash's doc comment. nil for -coin=tari
	// (Tari's own real hash comes from submitBlockDirect/
	// realBlockHashHex instead) and, per FIX_BRIEF.md's explicit
	// fallback-hardening requirement, a genuine -coin=monero
	// misconfiguration if left nil (ServerConfig.MonerodURL empty) --
	// resolveMoneroBlockHash returns a clear error rather than a
	// placeholder in that case, never silently substituting one.
	moneroHeaderResolver moneroBlockHeaderResolver

	// mergeMineChains mirrors ServerConfig.MergeMineChains verbatim
	// (see that field's doc comment) -- consulted only by session.go's
	// ALGO_RXM block-find handling. Empty (nil) for -coin=tari and
	// every pre-existing caller.
	mergeMineChains []MergeMineChainConfig

	// repushMu/lastRepush*/pendingRepush* implement the equal-height
	// miner-visible-repush debounce described in this feature's own
	// brief (feat/equal-height-push-debounce) -- see
	// debouncedInvalidateAndRepushJobs' doc comment for the full
	// design. Deliberately a SEPARATE mutex from s.mu (which guards
	// s.sessions) to avoid any lock-ordering entanglement between
	// this bookkeeping and session-map access performed by the real
	// repush (invalidateAndRepushJobs) itself.
	repushMu sync.Mutex

	// lastRepushHeight/lastRepushSet/lastRepushAt record the
	// (height, time) of the last miner-visible repush THIS Server
	// actually performed -- NOT solo.JobManager's own tracked best
	// (see solo.JobManager.CurrentBest), which updates immediately/
	// unconditionally on every genuinely-better candidate regardless
	// of whether Server has chosen to defer the repush yet.
	lastRepushHeight uint64
	lastRepushSet    bool
	lastRepushAt     time.Time

	// pendingRepush/pendingRepushSource track whether a same-height
	// repush is currently owed/buffered during the debounce window --
	// deliberately no buffered SIZE here (see
	// debouncedInvalidateAndRepushJobs' doc comment: the eventual
	// repush re-reads JobManager.CurrentBest() fresh rather than
	// trusting a stale captured value).
	pendingRepush       bool
	pendingRepushSource string

	// pendingRepushTimer is the live time.AfterFunc timer (if any)
	// scheduled to fire the buffered same-height repush once the
	// debounce window elapses -- stopped by Shutdown so a torn-down
	// Server never fires a stale repush after shutdown.
	pendingRepushTimer *time.Timer

	// noShareTimeout is ServerConfig.NoShareTimeout, verbatim (see
	// that field's doc comment): a connected session that has NEVER
	// produced a genuinely accepted share (shareCount.Load() == 0)
	// within this long of connecting gets disconnected by the
	// periodic sweep below (runNoShareSweep). Zero/negative disables
	// the feature entirely, mirroring
	// ManagedConnection.armReadDeadline's own <=0-disables
	// convention -- see startNoShareSweep, which never even starts
	// the sweep goroutine in that case.
	noShareTimeout time.Duration

	// noShareSweepStop/noShareSweepDone are the sweep goroutine's own
	// stop signal/completion signal (started by startNoShareSweep,
	// closed/waited-on by stopNoShareSweep from Shutdown). Both stay
	// nil for a Server whose noShareTimeout is <= 0 -- see
	// startNoShareSweep's doc comment.
	noShareSweepStop chan struct{}
	noShareSweepDone chan struct{}

	// noShareSweepNow is a test-only clock seam (mirrors
	// solo.MoneroNodeClient's own nowFunc convention exactly): nil in
	// production, so sweepNoShareSessions always calls time.Now();
	// overridden by this package's own no-share-timeout tests so they
	// never sleep-based-test a real multi-minute window.
	noShareSweepNow func() time.Time
}

// defaultNoShareSweepInterval is how often runNoShareSweep scans the
// live session map for sessions that have exceeded noShareTimeout
// without ever producing an accepted share -- see that method's own
// doc comment. Deliberately short relative to any realistic
// noShareTimeout (Alex's stated "2-3 minutes" -- see
// cmd/leaf-direct's -no-share-timeout flag doc comment) so the
// timeout is enforced within a few seconds of actually elapsing,
// without hot-looping a full session-map scan far more often than
// that. Not operator-configurable -- only noShareTimeout itself is.
const defaultNoShareSweepInterval = 15 * time.Second

// equalHeightRepushDebounce bounds how often a same-height
// "improvement" (the currently-tracked-best template getting a
// larger size at the SAME height as what was last actually repushed
// to connected miners) is allowed to trigger a real miner-visible
// repush (see debouncedInvalidateAndRepushJobs). Confirmed live on
// production: multiple sibling leaf-direct instances independently
// observing the SAME new chain-tip height can each publish their own
// mempool-snapshot template in quick succession, and without this
// bound each one triggers a separate repush to every connected miner,
// wasting miner hashing effort. A genuine chain-height increase over
// what was last repushed is NEVER subject to this debounce -- see
// that method's doc comment; this constant governs ONLY the
// same-height case. Fixed for this pass (not configurable via flag --
// see feat/equal-height-push-debounce's own brief).
const equalHeightRepushDebounce = 20 * time.Second

// defaultForwardPoolWorkers/defaultForwardPoolQueueSize size Fix 12's
// forwardPool (DISPATCH_BRIEF.md 2026-09-10). Unlike randomxPool
// (CPU-bound RandomX hashing, sized to runtime.NumCPU() -- see
// solo/asyncvalidation.go), backend-forward calls are I/O-bound
// (a single outbound HTTP round-trip each, transport.ShareTransport),
// so scaling with host CPU count has no real justification here --
// what matters is bounding how many concurrent in-flight backend
// calls this leaf will ever make, independent of how many CPU cores
// happen to be available. 16 is a generous-but-bounded fixed
// concurrency limit for outbound HTTP calls to one backend (well
// beyond what a single backend endpoint needs to stay responsive
// under this leaf's own realistic accepted-share rate, while still
// bounding worst-case concurrent backend load to a small, fixed
// number regardless of miner count). AsyncValidationQueueSize (256)
// is reused unchanged for the queue bound, matching this codebase's
// existing "generous headroom for a burst, real backpressure once
// genuinely full" convention (see that constant's own doc comment).
const defaultForwardPoolWorkers = 16

// ServerConfig configures a Server.
type ServerConfig struct {
	ConnectionManager *leaflib.ConnectionManager
	JobManager        *solo.JobManager

	// Node is this leaf's coin-agnostic NodeClient, used by
	// session.go's handleSubmit to build the real, algo-appropriate
	// candidate block for a validated share (BuildCandidateBlock) —
	// see internal/leaflib/solo/node.go's NodeClient doc comment. This
	// is the SAME real NodeClient (this package's own node.go
	// implementation, backed by a real per-node-injectable GRPC
	// client) JobManager was constructed with as its own template
	// source — see cmd/leaf-direct/main.go's wiring. REQUIRED: a nil
	// Node means handleSubmit cannot construct a candidate block for
	// ANY submit, share or block-find alike.
	Node solo.NodeClient

	Validators validator.Registry
	Network    poolpb.Network
	Logger     *log.Logger
	Vardiff    solo.VardiffConfig

	// Transport is REQUIRED — this is leaf-direct's whole reason for
	// existing (forwarding validated shares/blocks to the real
	// backend). A nil Transport is accepted defensively (every
	// forward call is nil-safe — see session.go's forwardShare/
	// forwardBlock) but means shares/blocks are validated locally and
	// then silently dropped rather than reaching the backend at all;
	// callers should treat a nil Transport as a startup misconfiguration.
	Transport transport.ShareTransport

	// MultiSubmit is the real parallel-multi-node-GRPC-submit path for
	// a genuine block find (multisubmit.go). May be nil (a
	// misconfiguration — no configured submit nodes at all) in which
	// case every block find fails with success=false and an honest
	// "no configured submit nodes" result; construct via
	// NewMultiNodeSubmitter at startup with at least the primary node's
	// own address included (see cmd/leaf-direct/main.go).
	MultiSubmit *MultiNodeSubmitter

	// Relay is the optional best-effort NATS block-broadcast/resubmit
	// mechanism (internal/leaflib/relay). May be nil or a disabled
	// Relay (relay.NewRelay with an empty URL) — every call site is
	// nil/disabled-safe.
	Relay *relay.Relay

	// Algo is the single mining algorithm this Server's JobManager was
	// configured for (mirrors solo's own single-algo-per-process
	// model — see solo.JobManagerConfig.Algo's doc comment). Surfaced
	// on relay-published BlockMessage.Algo as a coin-agnostic string
	// label (see currentAlgoLabel).
	Algo poolpb.Algo

	// PoolType is the real, operator-configured pool payout model
	// (PPLNS/PPS/PROP/SOLO) stamped onto every real poolpb.Share/
	// poolpb.Block this leaf forwards to the backend (see
	// session.go's forwardShare/forwardBlock and handleSubmit's share
	// construction switch). REQUIRED and validated non-UNSPECIFIED by
	// the caller (cmd/leaf-direct/main.go) at startup -- the backend's
	// own real validation (internal/backend/api/api.go) correctly
	// rejects any Share/Block with PoolType left at its zero value
	// (poolpb.PoolType_POOL_TYPE_UNSPECIFIED) with a 400
	// "pool_type is required", since there is no safe silent default
	// for something that determines real payout accounting semantics.
	PoolType poolpb.PoolType

	// PoolID is the real, operator-assigned static integer identifying
	// this leaf-direct process's pool-server source (see
	// internal/proto/share.proto's Share.pool_id doc comment for the
	// full rationale/history). Stamped onto every real poolpb.Share/
	// poolpb.Block this leaf forwards to the backend (see session.go's
	// handleSubmit share-construction switch and forwardBlock),
	// unconditionally. Set at startup from cmd/leaf-direct's own
	// -pool-id/LEAF_DIRECT_POOL_ID flag.
	PoolID int32

	// Debug, if non-nil and enabled, opts this Server (and every
	// Session it creates) into verbose [DEBUG]-tagged logging -- see
	// internal/leaflib/debuglog.go's doc comment and
	// cmd/leaf-direct/main.go's -debug/LEAF_DIRECT_DEBUG wiring. nil
	// (the default for every pre-existing caller/test) is a complete
	// no-op.
	Debug *leaflib.DebugLogger

	// MonerodURL is this leaf's real monerod JSON-RPC base URL (the
	// SAME address Node -- solo.NewMoneroNodeClient -- is already
	// configured against, see cmd/leaf-direct/main.go's -monerod-url/
	// LEAF_DIRECT_MONEROD_URL) -- used ONLY to construct this
	// Server's own, independent moneroHeaderResolver
	// (MoneroBlockHeaderClient, monero_hash.go). session.go's
	// handleSubmit no longer queries that resolver from its hot path
	// at all (see resolveMoneroBlockHash's own doc comment for the
	// full history: the real Monero block hash for a genuine ALGO_RXM
	// block find is sourced directly from submit_block's own
	// response's real "block_id" field instead) -- this field is kept
	// only for the independent, RPC-based capability resolveMoneroBlockHash
	// still exposes (tests/tooling/potential future manual
	// reconciliation). Empty for -coin=tari (ignored entirely).
	MonerodURL string

	// MergeMineChains lists every merge-mined chain (beyond the
	// primary chain Node/MonerodURL already cover) session.go's
	// ALGO_RXM block-find handling should check the SAME real PoW
	// submission against, in addition to the primary chain. Today
	// there is exactly one real configured entry (Tari, via a
	// minotari_merge_mining_proxy -- see cmd/leaf-direct's
	// -merge-mine-chains flag), but this is deliberately a SLICE, not
	// a single hardcoded Tari-only field: a future leaf-direct-monero
	// instance could in principle be configured against more than one
	// merge-mined-chain target without a code change here. Empty
	// (the default, and every -coin=tari / pre-existing caller) means
	// no merge-mine-chain checking at all -- session.go's ALGO_RXM
	// handling then behaves exactly as before this feature existed
	// (single Monero-leg-only forward).
	MergeMineChains []MergeMineChainConfig

	// BlockForwardTimeout bounds forwardBlock's own outer ctx wrapping
	// the ENTIRE transport.ShareTransport.SubmitBlock call (session.go)
	// -- this is a caller-side bound, separate from and layered on top
	// of whatever internal per-attempt/retry-budget bounding the
	// configured Transport implementation applies itself (e.g.
	// legacytransport.LegacyTransport's own BlockSubmitRetryBudget,
	// added 2026-09-23 -- see that field's doc comment for the real
	// production incident this reconciles).
	//
	// BUG FIX (2026-09-23, same incident as the retry-budget fix
	// above): this used to be a hardcoded 10*time.Second in
	// forwardBlock, which is far shorter than legacytransport's new,
	// intentionally-generous 5-minute default retry budget -- an
	// unconfigured/zero value here would silently cancel SubmitBlock's
	// ctx and kill its retry loop after only 10s, defeating the whole
	// point of the retry fix for exactly the slow-legacy-backend case
	// it exists to absorb. Zero/negative falls back to 10*time.Second
	// (NewServer's own default, preserving the exact pre-fix behavior
	// for every caller that does not explicitly set this -- i.e. every
	// existing non-legacy-mode deployment using the normal
	// transport.HTTPProtobufTransport, which has no retry loop of its
	// own to protect). cmd/leaf-direct/main.go sets this explicitly
	// (to comfortably exceed -legacy-block-retry-budget) whenever
	// -legacy-mode is enabled.
	BlockForwardTimeout time.Duration

	// NoShareTimeout is the connection-hygiene threshold this
	// feature's own brief describes: a session that connects and
	// never produces a single genuinely accepted share (see
	// Session.shareCount) within this long gets disconnected by a
	// periodic sweep (runNoShareSweep) -- a huge number of miners at
	// real production scale connect and only ever send periodic
	// keepalived messages, never a real submit, wasting a connection
	// slot indefinitely without ever tripping the existing, generic
	// "any contact resets the clock" idle timeout
	// (ManagedConnection.armReadDeadline). This is a genuinely
	// different condition from that idle timeout: the connection is
	// NOT idle (it is actively sending non-share traffic) -- see
	// ConnErrorIdleTimeout's own doc comment for that distinction and
	// this field's own connection-error category
	// ("no-share-timeout", recorded by sweepNoShareSessions).
	//
	// Zero or negative disables this feature entirely (mirrors
	// armReadDeadline's own <=0-disables convention): NewServer never
	// even starts the sweep goroutine in that case (see
	// startNoShareSweep), so a Server built with this left at its
	// zero value costs not even one extra goroutine. Set from
	// cmd/leaf-direct's own -no-share-timeout/
	// LEAF_DIRECT_NO_SHARE_TIMEOUT flag (default 5m, widened from the
	// original 3m -- Alex's originally-stated "2-3 minutes" upper
	// bound -- to cut down on false disconnects for legitimately
	// slow-to-first-share miners).
	//
	// A session that submits its first accepted share is PERMANENTLY
	// exempt from this specific disconnect for the rest of its life
	// (shareCount only ever increases, never resets) -- it never
	// re-triggers later just because a session goes quiet AFTER its
	// first share; that's what the existing, separate idle timeout
	// already covers.
	NoShareTimeout time.Duration
}

// MergeMineChainConfig names ONE merge-mined chain this Server's
// ALGO_RXM block-find handling should independently check the real
// PoW submission against, on top of the primary chain (Monero).
type MergeMineChainConfig struct {
	// Name is this chain's blocks.merge_mine_chain marker forwarded
	// on poolpb.Block.MergeMineChain (e.g. "TARI"). Required
	// non-empty.
	Name string

	// AuxChainID is the aux-chain identifier a merge-mining proxy's
	// own submit_block response tags THIS chain's "_aux.chains" entry
	// with (see solo.AuxChainResult.ChainID's doc comment -- Tari's
	// own real minotari_merge_mining_proxy convention, confirmed
	// against tari-project/tari's own source, is "xtr").
	// Required non-empty.
	AuxChainID string
}

// NewServer constructs a Server.
func NewServer(cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		cm: cfg.ConnectionManager, jobManager: cfg.JobManager, node: cfg.Node,
		vardiff:              cfg.Vardiff.Normalized(),
		sessions:             make(map[uint64]*Session),
		maxAddressLabels:     directmetrics.DefaultMaxAddressLabels,
		statsPageMaxSessions: DefaultStatsPageMaxSessions,
		validators:           cfg.Validators, network: cfg.Network, logger: logger,
		transport: cfg.Transport, multiSubmit: cfg.MultiSubmit, relay: cfg.Relay, algo: cfg.Algo,
		poolType: cfg.PoolType, poolID: cfg.PoolID,
		invalidShareGuardConfig: leaflib.DefaultInvalidShareGuardConfig(),
		// workers=0/queueSize=0 lets NewAsyncValidationPool apply its
		// own defaults (DefaultAsyncValidationWorkers() ==
		// runtime.NumCPU() for workers, NOT a hardcoded literal --
		// see solo/asyncvalidation.go's doc comment and Alex's
		// explicit direction in DISPATCH_BRIEF.md, 2026-09-10; and
		// DefaultAsyncValidationQueueSize(workers) for queueSize --
		// max(AsyncValidationQueueSize, workers*
		// DefaultAsyncValidationQueueMultiplier), scaling with the
		// real worker count instead of staying the old flat 256
		// literal regardless of host size). An operator wanting a
		// different fixed worker count and/or queue size can override
		// via SetRandomXWorkerPoolSize (see cmd/leaf-direct's
		// -randomx-workers/-randomx-queue-size flags) before Serve
		// begins.
		randomxPool: solo.NewAsyncValidationPool(0, 0),
		// Fix 12 (DISPATCH_BRIEF.md 2026-09-10): a separate, dedicated
		// pool for forwardShare/forwardBlock -- see forwardPool's own
		// doc comment and defaultForwardPoolWorkers' doc comment for
		// the full rationale/sizing.
		forwardPool: solo.NewAsyncValidationPool(defaultForwardPoolWorkers, solo.AsyncValidationQueueSize),
		// CLOSE-WAIT fix -- see jobFetchPool's own doc comment above
		// for the full production-incident rationale. workers=0 lets
		// NewAsyncValidationPool apply DefaultAsyncValidationWorkers()
		// (runtime.NumCPU()), matching randomxPool's own convention
		// exactly (same rationale: scale with the actual host this
		// process runs on rather than an arbitrary fixed literal). An
		// operator wanting a different fixed count can override via
		// SetJobFetchPoolSize (see cmd/leaf-direct's -job-fetch-workers
		// flag) before Serve begins. AsyncValidationQueueSize (256) is
		// reused unchanged for the queue bound, matching that
		// constant's own "generous headroom for a burst, real
		// backpressure once genuinely full" convention -- exactly the
		// bound needed here: a tip-triggered invalidation can queue a
		// genuine burst of near-simultaneous first-dispatch job
		// fetches across many sessions at once.
		jobFetchPool: solo.NewAsyncValidationPool(0, solo.AsyncValidationQueueSize),
		// tipPollLoop-stall fix (brief2.md) -- see repushPool's own
		// doc comment for the full production-incident rationale and
		// the explicit "1 worker, not DefaultAsyncValidationWorkers()"
		// justification (invalidateAndRepushJobs is a single global
		// operation that must never run twice concurrently -- this
		// pool exists only to get it off tipPollLoop's own goroutine,
		// not to parallelize it against itself). queueSize is still
		// solo.AsyncValidationQueueSize (256) -- generous headroom for
		// however many notify() calls arrive while one repush pass is
		// still draining, even though in practice at most one entry
		// is ever usefully queued at a time (see TrySubmit's own
		// call sites' doc comments below).
		repushPool:  solo.NewAsyncValidationPool(1, solo.AsyncValidationQueueSize),
		debugLogger: cfg.Debug,
	}
	// defaultBlockForwardTimeout preserves this field's exact pre-fix
	// value (2026-09-23) for every caller that does not explicitly set
	// ServerConfig.BlockForwardTimeout -- see that field's doc comment.
	const defaultBlockForwardTimeout = 10 * time.Second
	s.blockForwardTimeout = cfg.BlockForwardTimeout
	if s.blockForwardTimeout <= 0 {
		s.blockForwardTimeout = defaultBlockForwardTimeout
	}
	if strings.TrimSpace(cfg.MonerodURL) != "" {
		s.moneroHeaderResolver = NewMoneroBlockHeaderClient(cfg.MonerodURL)
	}
	s.mergeMineChains = cfg.MergeMineChains
	s.transportOKSoFar.Store(true)
	if cfg.JobManager != nil {
		s.unsubscribe = cfg.JobManager.Subscribe(s.debouncedInvalidateAndRepushJobs)
	}
	if s.relay != nil {
		unsub, err := s.relay.Subscribe(s.handleRelayedBlock)
		if err != nil {
			logger.Printf("direct: relay subscribe failed (relay resubmission disabled, primary path unaffected): %v", err)
		}
		s.relayUnsub = unsub
	}
	s.noShareTimeout = cfg.NoShareTimeout
	s.startNoShareSweep()
	return s
}

// EnableMetrics constructs a *directmetrics.Metrics wired to this
// Server's live session state, mirroring solo.Server.EnableMetrics'
// exact conventions (private registry, cardinality-bounded per-address
// counts).
func (s *Server) EnableMetrics(version string, maxAddressLabels int) *directmetrics.Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = directmetrics.DefaultMaxAddressLabels
	}
	m := directmetrics.New(version, maxAddressLabels)
	m.SetSnapshotSource(s.sessionSnapshots)
	// Fix 9 (DISPATCH_BRIEF.md 2026-09-10): mirrors
	// solo.Server.EnableMetrics' identical async-pool wiring exactly
	// -- read s.randomxPool at CALL time (not captured here), since
	// SetRandomXWorkerPoolSize may replace it before Serve begins.
	m.SetAsyncPoolSource(func() directmetrics.AsyncPoolStats {
		return directmetrics.AsyncPoolStats{
			QueueDepth:         s.randomxPool.QueueDepth(),
			InFlightWorkers:    s.randomxPool.InFlightWorkers(),
			SubmitBlockedTotal: s.randomxPool.SubmitBlockedTotal(),
		}
	})
	// Relay observability (found-block + template relay, both live on
	// the 9-host mainnet fleet -- see internal/leaflib/relay's own
	// Stats() doc comment): reads s.relay's real internal counters
	// directly, never re-counts relay activity here. s.relay is
	// always a real, non-nil *relay.Relay (see cmd/leaf-direct/
	// main.go's wiring -- relay.NewRelay is called unconditionally,
	// producing a permanent no-op when -relay-nats-url is empty), so
	// this closure is safe to register unconditionally too; a
	// disabled relay's Stats() is the permanent zero RelayStats{}.
	m.SetRelaySource(func() relay.RelayStats {
		return s.relay.Stats()
	})
	s.metrics = m
	s.maxAddressLabels = maxAddressLabels
	// Wire the real XNP-reservation-unavailable counter into this
	// server's own MoneroNodeClient, if that's what it's actually
	// running against -- mirrors solo.Server.EnableMetrics' identical
	// wiring exactly (both leaf-solo and leaf-direct share the SAME
	// solo.MoneroNodeClient implementation for -coin=monero).
	if mnc, ok := s.node.(*solo.MoneroNodeClient); ok {
		mnc.SetReservationUnavailableMetric(m.XNPReservationUnavailableTotal)
	}
	return m
}

// EnableChainHeightMetrics starts a background chainheight.Poller
// against this Server's own s.node and wires it into the metrics
// registered by a prior EnableMetrics call (leaf_monero_chain_height
// or leaf_tari_chain_height, depending on this leaf's configured
// algo family -- see solo.IsMoneroFamilyAlgo). Deliberately a
// SEPARATE opt-in call rather than folded into EnableMetrics itself:
// EnableMetrics is exercised by a large number of existing
// lower-level session/server tests using synthetic NodeClient fakes
// that don't expect (and, in several cases, fail on) an extra real
// get_info/GetTipInfo call being made against them; production
// wiring (cmd/leaf-direct/main.go) calls this explicitly right after
// EnableMetrics, mirroring EnableCaptureAddresses/EnableTrust's own
// "separate, explicit opt-in" convention. A no-op if EnableMetrics
// was never called, or if s.node doesn't implement
// chainheight.TipInfoSource (i.e. some future NodeClient
// implementation without a GetTipInfo method at all).
func (s *Server) EnableChainHeightMetrics() {
	if s.metrics == nil {
		return
	}
	tipSource, ok := s.node.(chainheight.TipInfoSource)
	if !ok {
		return
	}
	s.chainHeightPoller = chainheight.New(tipSource, chainheight.DefaultInterval, s.logger)
	s.chainHeightPoller.Start()
	if solo.IsMoneroFamilyAlgo(s.algo) {
		s.metrics.SetMoneroChainHeightSource(s.chainHeightPoller.Height)
	} else {
		s.metrics.SetTariChainHeightSource(s.chainHeightPoller.Height)
	}
}

// SetHideRemoteAddress mirrors internal/leaflib/solo/server.go's
// identical method exactly — see that doc comment.
func (s *Server) SetHideRemoteAddress(hide bool) {
	s.hideRemoteAddress.Store(hide)
}

// SetStatsPageMaxSessions sets the -stats-page-max-sessions/
// LEAF_DIRECT_STATS_PAGE_MAX_SESSIONS cap StatsHTMLHandler enforces
// on its "Connected sessions" table row count -- see
// statsPageMaxSessions's own doc comment and capSessionsForDisplay
// in statsui.go for the full rationale. 0/negative disables the cap
// entirely (render everything).
func (s *Server) SetStatsPageMaxSessions(max int) {
	s.statsPageMaxSessions = max
}

// SetRandomXWorkerPoolSize mirrors solo.Server's own identical
// method exactly — see that method's doc comment.
func (s *Server) SetRandomXWorkerPoolSize(workers, queueSize int) {
	s.randomxPool.Stop()
	s.randomxPool = solo.NewAsyncValidationPool(workers, queueSize)
}

// SetForwardPoolSize replaces this Server's forwardPool (Fix 12,
// DISPATCH_BRIEF.md 2026-09-10) with a freshly constructed one sized
// to workers/queueSize -- mirrors SetRandomXWorkerPoolSize's exact
// same "stop the old one, construct a fresh one" pattern and
// pre-Serve-only calling convention. workers<=0 falls back to
// solo.DefaultAsyncValidationWorkers() (runtime.NumCPU()) via
// NewAsyncValidationPool's own fallback -- an operator who wants
// forwardPool's own, genuinely different (I/O-bound, not CPU-bound)
// sizing rationale honored instead should pass a positive workers
// value explicitly (see defaultForwardPoolWorkers' doc comment).
func (s *Server) SetForwardPoolSize(workers, queueSize int) {
	s.forwardPool.Stop()
	s.forwardPool = solo.NewAsyncValidationPool(workers, queueSize)
}

// SetJobFetchPoolSize replaces this Server's jobFetchPool (CLOSE-WAIT
// production-incident fix, see that field's own doc comment) with a
// freshly constructed one sized to workers/queueSize -- mirrors
// SetRandomXWorkerPoolSize's/SetForwardPoolSize's exact same "stop
// the old one, construct a fresh one" pattern and pre-Serve-only
// calling convention. workers<=0 falls back to
// solo.DefaultAsyncValidationWorkers() (runtime.NumCPU()) via
// NewAsyncValidationPool's own fallback, matching jobFetchPool's
// default construction in NewServer.
func (s *Server) SetJobFetchPoolSize(workers, queueSize int) {
	s.jobFetchPool.Stop()
	s.jobFetchPool = solo.NewAsyncValidationPool(workers, queueSize)
}

// SetInvalidShareGuardConfig mirrors solo.Server's own identical
// method exactly — see that method's doc comment and
// leaflib.InvalidShareGuard's package-level doc comment.
func (s *Server) SetInvalidShareGuardConfig(cfg leaflib.InvalidShareGuardConfig) {
	s.invalidShareGuardConfig = cfg.Normalized()
	s.invalidShareGuardConfig.Enabled = cfg.Enabled
}

// EnableTrust opts this server into the real, legacy-ported
// probabilistic RandomX-validation-skip mechanism for RXT/RXM shares
// (see solo/trust.go's doc comment for the full reference algorithm
// and citation) — mirrors solo.Server's own identical EnableTrust
// exactly (solo's own copy has since been removed entirely — see
// solo.Session.handleSubmit's DISPATCH_BRIEF doc comment,
// 2026-09-10, Fix 5 — but leaf-direct's is NOT vestigial: unlike
// solo, which only validates an RXT/RXM share for real at the rare
// block-find level, leaf-direct's own handleSubmit runs v.Validate
// for EVERY RXT/RXM submit, so this mechanism is a genuinely live,
// frequently-consulted skip here).
//
// REAL-MONEY RISK, SPELLED OUT EXPLICITLY (DISPATCH_BRIEF.md,
// 2026-09-10, Fix 5 — documentation-only; no behavior change to this
// method or trustConfig's wiring): unlike solo (no share table, no
// backend, no payouts — see solo's own corrected comment, Fix 4), a
// leaf-direct share that skips real validation here still reaches
// s.transport.SubmitShare and the real backend's payout accounting,
// entirely on the miner's own claimed value, with NO cryptographic
// re-check on this leaf. Combined with Fix 1's difficulty-floor
// check (session.go's handleSubmit, post-validate/post-skip) this is
// a materially SAFER combination than before this dispatch (a
// trusted-but-fabricated claim can no longer also slip under this
// job's own StaticDifficulty floor uncaught), but it is still a
// deliberate trust-for-throughput tradeoff, not a free feature: a
// sufficiently ramped-in, then-compromised or malicious miner can
// still have some fraction of its claims credited (and forwarded to
// the backend) without ever being cryptographically re-checked by
// THIS leaf, bounded only by TrustConfig.Min/256 in the steady state
// (see solo/trust.go's own doc comment for that exact, known,
// intentionally-not-"fixed" tradeoff). An operator enabling
// -trust-enabled on leaf-direct (see cmd/leaf-direct's own flag help
// text) should understand this is trading a real, if bounded,
// authenticity gap for reduced randomx-service load — not assume it
// is a strictly free optimization the way it might appear to be on
// leaf-solo (where it no longer even exists). Must be called before
// serving any connections to take effect for them — sessions capture
// s.trustConfig once, at newSession time.
func (s *Server) EnableTrust(cfg solo.TrustConfig) {
	s.trustConfig = cfg.Normalized()
	s.trustConfig.Enabled = cfg.Enabled
}

// EnableAddressFlags mirrors solo.Server's own identical method
// exactly -- see that method's doc comment.
func (s *Server) EnableAddressFlags(cache *addressflags.Cache) {
	s.addressFlags = cache
}

// MetricsHandler returns the Prometheus /metrics HTTP handler if
// EnableMetrics has been called, or a 404 handler otherwise.
func (s *Server) MetricsHandler() http.Handler {
	if s.metrics == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics not enabled", http.StatusNotFound)
		})
	}
	return s.metrics.Handler()
}

func (s *Server) sessionSnapshots() []directmetrics.SessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]directmetrics.SessionSnapshot, 0, len(s.sessions))
	for _, sess := range s.sessions {
		addr := sess.Identity().Address
		agent := sess.Identity().Agent
		out = append(out, directmetrics.SessionSnapshot{
			Address: addr, RemoteIP: directmetrics.RemoteIPOf(sess.mc.RemoteAddr()),
			Difficulty: sess.currentDifficulty.Load(),
			Agent:      agent,
			Hashrate:   leaflib.EstimateHashrateHz(sess.hashesAccumulated.Load(), sess.connectedAt),
		})
	}
	return out
}

func (s *Server) recordShare(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncShareResult(directmetrics.ResultLabel(accepted))
}

func (s *Server) recordBlock(accepted bool) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncBlockResult(directmetrics.ResultLabel(accepted))
}

func (s *Server) recordConnectionError(category string) {
	if s.metrics == nil {
		return
	}
	s.metrics.ConnectionErrorsTotal.WithLabelValues(category).Inc()
}

// recordSubmitProcessing/recordSubmitValidation are session.go's
// handleSubmit/finishSubmit's own nil-safe hooks for
// metrics.SubmitProcessingSeconds/SubmitValidationSeconds -- see
// those fields' own doc comments for the full rationale. Mirror
// recordShare/recordBlock's identical nil-safety convention above.
func (s *Server) recordSubmitProcessing(result string, seconds float64) {
	if s.metrics == nil {
		return
	}
	s.metrics.SubmitProcessingSeconds.WithLabelValues(result).Observe(seconds)
}

func (s *Server) recordSubmitValidation(algo string, seconds float64) {
	if s.metrics == nil {
		return
	}
	s.metrics.SubmitValidationSeconds.WithLabelValues(algo).Observe(seconds)
}

// connErrorNoShareTimeout is this feature's own connection-error
// category, recorded via recordConnectionError (reusing the existing
// leaf_direct_connection_errors_total metric with a new category
// label value -- its label set is a plain, open-ended Prometheus
// string label, not a closed/fixed enum, so this is not a breaking
// change for any existing dashboard; see recordConnectionError's own
// callers above for direct's established convention of passing bare
// literal strings here rather than named constants from a metrics
// package, which direct/metrics does not define any of today,
// unlike solo/metrics's ConnErrorIdleTimeout et al). Deliberately
// distinct from "idle-timeout": that category means the connection
// went fully silent; this one means the opposite -- the connection
// stayed genuinely active (e.g. repeated keepalived) but never once
// produced a real accepted share.
const connErrorNoShareTimeout = "no-share-timeout"

// startNoShareSweep launches the single, Server-scoped periodic
// no-share-timeout sweep goroutine (runNoShareSweep) if
// s.noShareTimeout is positive -- deliberately ONE ticker for the
// whole Server, never one timer/goroutine per session. At the real
// production scale this feature exists for (13,500+ concurrent
// connections, per this feature's own brief), a per-session timer on
// top of everything else already running per-session would repeat
// the exact class of session-map-bloat production incidents
// jobFetchPool's/repushPool's own doc comments above describe fixing
// elsewhere. This sweep instead scans the SAME s.sessions map every
// other per-connection bookkeeping path on this Server already
// maintains (see sessionSnapshots/handleConn) -- no second, parallel
// registry.
//
// A non-positive s.noShareTimeout is this feature's documented
// no-op: no goroutine is started at all (the stronger guarantee,
// preferred here over "start it but have it never disconnect
// anyone" -- see this package's own no-share-timeout tests, which
// confirm a disabled Server leaks no extra goroutine). Called once
// from NewServer.
func (s *Server) startNoShareSweep() {
	if s.noShareTimeout <= 0 {
		return
	}
	s.noShareSweepStop = make(chan struct{})
	s.noShareSweepDone = make(chan struct{})
	go s.runNoShareSweep()
}

func (s *Server) runNoShareSweep() {
	defer close(s.noShareSweepDone)
	ticker := time.NewTicker(defaultNoShareSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.noShareSweepStop:
			return
		case <-ticker.C:
			s.sweepNoShareSessions()
		}
	}
}

// sweepNoShareSessions is a single pass of the no-share-timeout
// sweep: it takes a real, complete snapshot of every currently-live
// session (RLock'd, mirroring sessionSnapshots' own convention
// exactly) and, for each one that has NEVER produced a genuinely
// accepted share (Session.shareCount.Load() == 0, incremented only
// in finishSubmit AFTER real validation passes -- never for a
// rejected/invalid submit) and has been connected longer than
// s.noShareTimeout, closes it via the exact same mc.Close(...)
// mechanism the existing invalid-share-guard disconnect uses (see
// finishSubmit's own disconnect call), with a clear, distinct reason
// string and connection-error category
// (connErrorNoShareTimeout) so it is never conflated with the
// generic ConnErrorIdleTimeout category -- that connection was NOT
// idle, it was actively sending non-share traffic.
//
// A session that has produced at least one accepted share is
// PERMANENTLY exempt from this specific disconnect for the rest of
// its life, even if it goes on to submit nothing else ever again --
// shareCount only ever increases, so this check can never re-trigger
// for a session once it has passed it once (that's what the
// existing, separate, generic idle timeout already covers).
func (s *Server) sweepNoShareSessions() {
	// Defensive no-op mirroring startNoShareSweep's own <=0-disables
	// convention: in normal operation this can never actually be
	// reached with a non-positive noShareTimeout (startNoShareSweep
	// never starts the goroutine that calls this in that case), but
	// keeping the same guard here too means a caller that invokes
	// this directly (e.g. this package's own tests) never has to
	// worry about it double-checking noShareTimeout itself.
	if s.noShareTimeout <= 0 {
		return
	}
	now := time.Now
	if s.noShareSweepNow != nil {
		now = s.noShareSweepNow
	}
	nowT := now()

	s.mu.RLock()
	var stale []*Session
	for _, sess := range s.sessions {
		if sess.shareCount.Load() == 0 && nowT.Sub(sess.connectedAt) > s.noShareTimeout {
			stale = append(stale, sess)
		}
	}
	s.mu.RUnlock()

	for _, sess := range stale {
		addr := sess.Identity().Address
		s.logger.Printf("direct: disconnecting session %s (address %s): no share submitted within %s of connecting", sess.sessionID, addr, s.noShareTimeout)
		_ = sess.mc.Close(fmt.Sprintf("no share submitted within %s of connecting", s.noShareTimeout))
		s.recordConnectionError(connErrorNoShareTimeout)
	}
}

// stopNoShareSweep stops the sweep goroutine started by
// startNoShareSweep, if one was ever started -- a Server built with
// noShareTimeout <= 0 never started one (see that method's own doc
// comment), so this is a safe no-op there too. Called from
// Shutdown(), mirroring every other background worker's explicit
// stop-on-Shutdown convention on this type (randomxPool.Stop(),
// forwardPool.Stop(), etc.).
func (s *Server) stopNoShareSweep() {
	if s.noShareSweepStop == nil {
		return
	}
	close(s.noShareSweepStop)
	<-s.noShareSweepDone
}

// recordShareClassification bumps the real
// leaf_direct_shares_by_classification_total counter (see
// directmetrics.Metrics.SharesByClassificationTotal's doc comment)
// for classification (one of directmetrics.ClassificationTrusted/
// ClassificationValidated/ClassificationInvalid) -- called from
// session.go's finishSubmit closure instead of touching s.metrics
// directly there, mirroring every other record* helper's nil-checked
// convention on this type.
func (s *Server) recordShareClassification(classification string) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncShareClassification(classification)
}

// recordShareRejectionReason bumps the real
// leaf_direct_share_rejection_reason_total counter (see
// directmetrics.Metrics.ShareRejectionReasonTotal's doc comment) for
// reason (one of directmetrics.RejectionReason*) -- called from
// session.go's rejectShare helper at every real reject call site
// handleSubmit reaches, mirroring every other record* helper's
// nil-checked convention on this type. ADDITIVE to (never a
// replacement for) writeShareResponse's own existing recordShare(false)
// bookkeeping -- see rejectShare's own doc comment.
func (s *Server) recordShareRejectionReason(reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncShareRejectionReason(reason)
}

// recordLoginRejection bumps the real
// leaf_direct_login_rejections_total counter (see
// directmetrics.Metrics.LoginRejectionsTotal's doc comment) for
// reason (one of directmetrics.LoginRejectionReason*) -- called from
// session.go's handleLogin/fetchAndDeliverLoginJob at every real
// login rejection return point, mirroring recordShareRejectionReason's
// identical nil-checked convention above (DISPATCH_BRIEF.md
// "login-rejection-reason metrics").
func (s *Server) recordLoginRejection(reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncLoginRejectionReason(reason)
}

// recordRelogin bumps the real leaf_relogin_total counter (see
// directmetrics.Metrics.ReloginTotal's doc comment) -- called from
// session.go's handleLogin at the exact point a re-login is
// detected, mirroring recordLoginRejection's identical nil-checked
// convention above.
func (s *Server) recordRelogin() {
	if s.metrics == nil {
		return
	}
	s.metrics.IncRelogin()
}

// recordTransportError tracks backend-forwarding failures (share/
// block), a genuinely new observability axis leaf-solo has no
// equivalent of (it never forwards anything to a backend). It also
// updates the live "is the last known real backend call succeeding"
// health state statsui.go's Stats() surfaces (leaf-direct's analogue
// of leaf-proxy's UpstreamHealth.Connected()).
func (s *Server) recordTransportError(kind string) {
	s.transportOKSoFar.Store(false)
	s.transportErrorTotal.Add(1)
	s.lastTransportKind.Store(kind)
	s.lastTransportAt.Store(time.Now())
	if s.metrics == nil {
		return
	}
	s.metrics.TransportErrorsTotal.WithLabelValues(kind).Inc()
}

// recordTransportSuccess marks a real successful backend forward
// (share/block), flipping the transport health state back to
// healthy — mirrors recordTransportError's bookkeeping without a
// counterpart Prometheus metric (a running success total is not
// currently exported; only the stats page shows it).
func (s *Server) recordTransportSuccess(kind string) {
	s.transportOKSoFar.Store(true)
	s.lastTransportKind.Store(kind)
	s.lastTransportAt.Store(time.Now())
}

// resolveMoneroBlockHash resolves the REAL, canonical Monero block
// hash at height via this Server's configured moneroHeaderResolver --
// a real get_block_header_by_height call against the same monerod
// this leaf's own solo.MoneroNodeClient already talks to (see
// ServerConfig.MonerodURL and monero_hash.go).
//
// NO LONGER CALLED FROM session.go's handleSubmit HOT PATH. This was
// true for two DIFFERENT reasons across this repo's git history, in
// order:
//
//  1. (real production incident, 2026-09-12 live test against
//     leaf-direct-monero-pplns.service/CT132): this exact post-submit
//     RPC call raced the local testnet daemon's own tip advancement --
//     monerod rpc error -2, "Requested block height: X greater than
//     current top block height: X-1" -- and lost 150 of 152 real block
//     finds in one 2-hour test. The first fix for this replaced this
//     call with a LOCAL hash computation (solo.MoneroCandidate.
//     BlockHash) -- but that local computation was itself CONFIRMED
//     WRONG by further live testing (the computed hash did not match
//     the real chain's own reported hash at the same height) and has
//     since been removed entirely.
//  2. (the correction): the real, correct fix needs no RPC round-trip
//     of ANY kind here, local or otherwise -- monerod's own real
//     submit_block response already carries the real, canonical
//     block ID directly (a top-level "block_id" field, confirmed
//     present since monero-project/monero commit
//     e8cac61f4b9a662cbc1b00e46d1f9a3dd991c5f0). handleSubmit's
//     ALGO_RXM case now sources the real block hash from THAT SAME
//     submit_block response instead (see solo.MoneroNodeClient.
//     SubmitBlockWithID/SubmitBlockAuxChains and
//     solo.moneroSubmitBlockAuxResult.BlockID's own doc comment for
//     the full derivation/citations).
//
// This method (and the moneroHeaderResolver/MonerodURL wiring behind
// it) is kept only as an independent, RPC-based capability for
// tests/tooling (see monero_hash_test.go and
// TestDirectResolveMoneroBlockHash_NoResolverConfigured) and as a
// potential future manual-reconciliation/startup-capability-check
// helper -- it is deliberately NOT deleted, per this fix's own
// explicit "keep as a startup-only capability check / test"
// allowance, but it no longer gates any real block-find forward.
//
// Returns an error -- NEVER a placeholder/empty string -- if no
// resolver is configured (ServerConfig.MonerodURL was left empty for
// a -coin=monero process, a genuine startup misconfiguration), the
// RPC call itself fails, or the daemon reports an empty hash.
func (s *Server) resolveMoneroBlockHash(ctx context.Context, height uint64) (string, error) {
	if s.moneroHeaderResolver == nil {
		return "", fmt.Errorf("direct: no Monero block-header resolver configured (ServerConfig.MonerodURL empty -- see -monerod-url/LEAF_DIRECT_MONEROD_URL)")
	}
	hashHex, err := s.moneroHeaderResolver.GetBlockHeaderHashByHeight(ctx, height)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(hashHex) == "" {
		return "", fmt.Errorf("direct: monerod returned an empty block_header.hash at height %d", height)
	}
	return hashHex, nil
}

// recordMoneroBlockHashUnresolved bumps the real
// leaf_direct_block_hash_unresolved_total counter -- the "fail
// loudly" signal for a genuine ALGO_RXM block find whose real hash
// could not be established. This now fires when the real
// submit_block RPC response carried an empty/missing top-level
// "block_id" field on an otherwise-accepted block find (see
// handleSubmit's ALGO_RXM case and solo.moneroSubmitBlockAuxResult.
// BlockID's own doc comment for the legitimate reasons that field can
// still be empty: an older, pre-e8cac61f monerod, or a merge-mining
// proxy that doesn't pass block_id through untouched) -- a real,
// reachable defensive case (unlike the prior local-hash-computation
// fix's equivalent, which was defensive-only/should-be-unreachable),
// kept per this fix's explicit "handle the empty/missing block_id
// case defensively" requirement. nil-safe like every other record*
// helper on this type (metrics may not be enabled).
func (s *Server) recordMoneroBlockHashUnresolved() {
	if s.metrics == nil {
		return
	}
	s.metrics.DirectBlockHashUnresolvedTotal.Inc()
}

// recordTemplateDistribution observes the real wall-clock duration a
// single invalidateAndRepushJobs pass took and sets the real count of
// sessions actually pushed a fresh job during that pass, labeled by
// source (directmetrics.TemplateDistributionDuration/
// TemplateDistributionMiners -- see those fields' own doc comments)
// -- called from invalidateAndRepushJobs instead of touching
// s.metrics directly there, mirroring every other record* helper's
// nil-checked convention on this type.
func (s *Server) recordTemplateDistribution(source string, seconds float64, minerCount int) {
	if s.metrics == nil {
		return
	}
	s.metrics.TemplateDistributionDuration.WithLabelValues(source).Observe(seconds)
	s.metrics.TemplateDistributionMiners.WithLabelValues(source).Set(float64(minerCount))
}

// invalidateAndRepushJobs is JobManager's Subscribe callback (see
// server.go's NewServer wiring): fires every time the per-xn job
// cache is invalidated, iterating every connected, logged-in session
// and pushing it a freshly (re-)generated job so it never keeps
// working a job for a tip that has already moved.
//
// source (solo.TemplateSourceLocal/solo.TemplateSourceRelay, threaded
// straight through from JobManager.InvalidateAll -- see that method's
// and job.go's TemplateSource* consts' own doc comments) identifies
// WHICH real event triggered this pass: this leaf's own upstream
// tip-poll/periodic-refresh finding a new template ("local"), or a
// new template learned via the NATS template relay from ANOTHER
// leaf-direct/leaf-solo instance now being distributed to THIS
// instance's own sessions ("relay") -- recorded below via
// recordTemplateDistribution, mirroring legacy nodejs-pool-sxmr's own
// per-new-block-template log line (lib/pool.js: "Block template
// distribution took ${...} miliseconds for ${minerCount} miners for
// blockID: ${height}"). This metric is meant to expose
// relay-triggered template-propagation latency/health as more relay
// nodes get wired into the mesh across the pool-migration effort,
// distinguishing "my own new tip" from "a relay redelivery"
// distribution passes.
//
// PERFORMANCE FIX (brief2.md, SAME production leaf/incident as
// jobFetchPool above): this used to loop over every logged-in session
// SEQUENTIALLY, one at a time, on whichever single goroutine called
// in (originally tipPollLoop's own, via InvalidateAll -> notify ->
// debouncedInvalidateAndRepushJobs -- see repushPool's own doc comment
// for that half of the fix, which gets THIS call itself off that
// goroutine). Because a cache invalidation wipes solo.JobManager's
// ENTIRE per-xn map and every session has a unique xn,
// JobForXNAtDifficulty below is a guaranteed cache MISS for every
// single session -- a real, synchronous GetBlockTemplate HTTP round
// trip each. Confirmed live: with s.sessions bloated to ~100,000+
// entries (the sibling CLOSE-WAIT leak's own symptom -- jobFetchPool's
// doc comment), one sequential pass took long enough that
// leaf_direct_template_distribution_seconds/_miners went dark for
// 15+ minutes. Even at the CORRECT, non-leaked ~20k live-connection
// count this was already a real structural bug (a single goroutine
// making ~20k sequential synchronous network calls), independent of
// the leak. Fixed by fanning the per-session work out across up to
// repushFanoutConcurrency goroutines at once (bounded
// semaphore-gated sync.WaitGroup, not solo.AsyncValidationPool --
// see that const's own doc comment for why this shape fits better
// here), waiting for the WHOLE batch to genuinely finish before
// recordTemplateDistribution fires -- so the metric this incident is
// named for actually reflects one real, complete distribution pass,
// not an early/partial one. EXACT same per-session semantics as
// before (skip non-logged-in sessions, respect alreadyDelivered,
// count pushed correctly) -- only the concurrency shape changed;
// pushed is now an atomic.Int64 since multiple goroutines increment
// it concurrently.
func (s *Server) invalidateAndRepushJobs(source string) {
	start := time.Now()
	s.mu.RLock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.RUnlock()

	var pushed atomic.Int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, repushFanoutConcurrency)
	for _, sess := range sessions {
		if !sess.loggedIn.Load() {
			continue
		}
		sess := sess
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			job, err := s.jobManager.JobForXNAtDifficulty(context.Background(), sess.XN(), sess.currentDifficulty.Load())
			if err != nil {
				s.logger.Printf("direct: failed to regenerate job for session %s (xn %s) after cache invalidation: %v", sess.sessionID, sess.XN(), err)
				return
			}
			// BUG FIX (Alex, live production report: "we're sending
			// duplicate jobs down the wire to RXT") -- mirrors
			// solo.Server.invalidateAndRepushJobs' identical fix
			// exactly; see that function's doc comment and
			// Session.alreadyDelivered for the real legacy reference
			// this ports.
			if sess.alreadyDelivered(job) {
				return
			}
			sess.pushJob(job)
			pushed.Add(1)
		}()
	}
	wg.Wait()
	s.recordTemplateDistribution(source, time.Since(start).Seconds(), int(pushed.Load()))
}

// repushFanoutConcurrency bounds how many of invalidateAndRepushJobs'
// own per-session JobForXNAtDifficulty calls (each a real,
// independent GetBlockTemplate HTTP round trip on a cache miss -- see
// that method's own doc comment) may be genuinely in flight
// simultaneously. A plain semaphore-gated sync.WaitGroup is used
// instead of reusing solo.AsyncValidationPool (unlike jobFetchPool/
// repushPool/randomxPool/forwardPool) because this is a one-shot fan-
// out over a single batch whose size varies every call
// (len(s.sessions)), not a long-lived queue independently fed by many
// unrelated callers over the server's whole lifetime -- "spawn up to
// N at once, wait for exactly THIS batch to finish" maps directly
// onto a semaphore + WaitGroup, whereas coordinating "has this one
// specific caller's batch fully drained" against AsyncValidationPool's
// shared, persistent queue would need extra bookkeeping anyway. 64 is
// a deliberately generous-but-bounded concurrency limit for HTTP
// calls to the local base node's own GetBlockTemplate endpoint --
// large enough that even a ~20k-live-connection leaf's full fan-out
// completes in a small number of sequential "rounds" (bounding this
// pass to roughly session_count/64 real round-trip latencies, not
// session_count of them), while still capping worst-case concurrent
// load against that one local node regardless of how many sessions
// exist.
const repushFanoutConcurrency = 64

// dispatchRepush hands a real invalidateAndRepushJobs pass off to
// s.repushPool (see that field's own doc comment for the full
// production-incident rationale) instead of running it inline on the
// caller's own goroutine. Every call site that used to call
// s.invalidateAndRepushJobs(source) directly -- debouncedInvalidate
// AndRepushJobs' three branches (the defensive CurrentBest-not-set
// fallback, the genuine-height-increase path, and the debounce-
// window-elapsed path) and firePendingRepush's own timer callback --
// now goes through this helper instead, so NONE of them can ever
// block tipPollLoop's (or, for firePendingRepush, time.AfterFunc's
// own) goroutine on invalidateAndRepushJobs' full duration again.
// Uses TrySubmit (never blocks the caller) -- on the very unlikely
// case the pool's single worker is already busy AND its queue is
// also genuinely full, this logs clearly rather than silently
// dropping the invalidation notice with no trace at all.
func (s *Server) dispatchRepush(source string) {
	if ok := s.repushPool.TrySubmit(func() { s.invalidateAndRepushJobs(source) }); !ok {
		s.logger.Printf("direct: repushPool saturated or shutting down -- dropped a %q template-cache-invalidation repush notice (tip detection and other sessions are unaffected, but connected miners will not receive an updated job from this particular notification)", source)
	}
}

// debouncedInvalidateAndRepushJobs is the ACTUAL callback registered
// with solo.JobManager.Subscribe (see NewServer) -- it decides
// whether/when to call the real, miner-visible
// invalidateAndRepushJobs, per this feature's own brief
// (feat/equal-height-push-debounce):
//
//  1. A genuine chain-height increase over what this Server has most
//     recently actually repushed to connected miners always applies
//     immediately -- no debounce, ever. An old-height job is actively
//     stale, not just suboptimal.
//  2. A same-height "improvement" (the currently-tracked-best
//     template, per solo.JobManager.CurrentBest, getting a larger
//     size at the SAME height as what was last actually repushed) is
//     debounced to at most once every equalHeightRepushDebounce.
//     Further same-height notifications arriving inside that window
//     are buffered/coalesced (this only remembers that a repush is
//     owed, not any particular size -- see pendingRepush's own doc
//     comment) and a single repush fires once the window elapses,
//     using whatever solo.JobManager's ACTUAL current state is at
//     that moment (CurrentBest is re-read fresh when the timer
//     fires, never a stale snapshot from when buffering started).
//
// This debounce governs ONLY whether/when Server calls its own real
// invalidateAndRepushJobs (the miner-visible repush). It never
// touches solo.JobManager's own per-xn cache content/timing and never
// affects the relay broadcast path (solo.JobManager.tipPollLoop's
// publishTemplateForJob call) at all -- those keep firing exactly as
// already merged, unconditionally and immediately, regardless of any
// state tracked here.
//
// DECOUPLING FIX (brief2.md): this function itself runs synchronously
// on whichever goroutine solo.JobManager.notify called it from --
// tipPollLoop's own, for the common genuine-height-increase case (see
// repushPool's own doc comment for the full incident). Every branch
// below that used to call s.invalidateAndRepushJobs(source) directly
// now calls s.dispatchRepush(source) instead, which hands the real
// (and, as of this fix, internally-parallelized -- see that method's
// own doc comment) repush pass off to s.repushPool and returns
// immediately, so THIS function -- and therefore tipPollLoop itself --
// is never blocked on how long a repush pass actually takes.
func (s *Server) debouncedInvalidateAndRepushJobs(source string) {
	height, _, ok := s.jobManager.CurrentBest()
	if !ok {
		// Defensive: should not happen once a subscription has fired
		// (setBest is always called before notify -- see job.go's
		// InvalidateAll/adoptRelayedJob), but don't block a real
		// repush on this being true.
		s.dispatchRepush(source)
		return
	}

	s.repushMu.Lock()

	if !s.lastRepushSet || height > s.lastRepushHeight {
		// Genuine height increase (or the very first repush ever) --
		// a stale same-height buffer at the OLD height is moot now;
		// discard it.
		if s.pendingRepushTimer != nil {
			s.pendingRepushTimer.Stop()
			s.pendingRepushTimer = nil
		}
		s.pendingRepush = false
		s.pendingRepushSource = ""
		s.lastRepushHeight = height
		s.lastRepushAt = time.Now()
		s.lastRepushSet = true
		s.repushMu.Unlock()
		s.dispatchRepush(source)
		return
	}

	if height < s.lastRepushHeight {
		// Should not reach here at all -- the shared isBetterCandidate
		// in solo already gates what becomes the tracked best before
		// this subscription ever fires. Log defensively and fall
		// through to the equal-height handling below rather than
		// crash or silently drop the notification.
		s.logger.Printf("direct: debouncedInvalidateAndRepushJobs: unexpected lower height notification (current best=%d, last repush=%d, source=%s) -- treating as same-height for debounce purposes", height, s.lastRepushHeight, source)
	}

	if time.Since(s.lastRepushAt) >= equalHeightRepushDebounce {
		s.lastRepushAt = time.Now()
		s.repushMu.Unlock()
		s.dispatchRepush(source)
		return
	}

	// Inside the debounce window: buffer/coalesce. There is
	// deliberately no size tracked here (see pendingRepush's own doc
	// comment) -- only the latest source is remembered, overwriting
	// any earlier-buffered one.
	s.pendingRepush = true
	s.pendingRepushSource = source
	if s.pendingRepushTimer == nil {
		remaining := equalHeightRepushDebounce - time.Since(s.lastRepushAt)
		if remaining < 0 {
			remaining = 0
		}
		s.pendingRepushTimer = time.AfterFunc(remaining, s.firePendingRepush)
	}
	s.repushMu.Unlock()
}

// firePendingRepush is pendingRepushTimer's callback -- fires once the
// debounce window has elapsed since the last actual repush. Re-checks
// pendingRepush under repushMu (it may have already been cleared/
// superseded by a genuine height increase that ran ahead of this
// timer firing) before dispatching the real invalidateAndRepushJobs
// via s.dispatchRepush (brief2.md: this runs on time.AfterFunc's own
// goroutine, not tipPollLoop's -- less urgent than the other call
// sites for that reason, but a slow repush here would still delay
// the same template-distribution metric, so it gets the identical
// off-goroutine treatment for consistency).
func (s *Server) firePendingRepush() {
	s.repushMu.Lock()
	s.pendingRepushTimer = nil
	if !s.pendingRepush {
		s.repushMu.Unlock()
		return
	}
	source := s.pendingRepushSource
	s.pendingRepush = false
	s.pendingRepushSource = ""
	s.lastRepushAt = time.Now()
	s.repushMu.Unlock()
	s.dispatchRepush(source)
}

// Serve accepts miner connections on ln, structurally identical to
// solo.Server.Serve.
func (s *Server) Serve(ctx context.Context, ln net.Listener, port solo.PortConfig) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn, port.Difficulty)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn, startingDifficulty uint64) {
	// HARDENING FIX (FIX_BRIEF.md, finding #20): mirrors
	// solo.Server's own identical handleConn recovery exactly -- see
	// that method's doc comment for the full rationale.
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("direct: recovered from a panic in handleConn for remote=%s (closing only this connection; every other session and this leaf's own accept loop are unaffected): %v\n%s", conn.RemoteAddr(), r, debug.Stack())
			_ = conn.Close()
		}
	}()

	mc, err := s.cm.Accept(ctx, conn)
	if err != nil {
		if errors.Is(err, leaflib.ErrConnectionRejected) {
			s.recordConnectionError("rejected-by-gate")
		}
		return
	}

	session := newSession(mc, s, startingDifficulty)
	s.mu.Lock()
	s.sessions[mc.ID()] = session
	s.mu.Unlock()

	s.debugLogger.Debugf("direct: connection accepted: session=%s remote=%s starting_difficulty=%d", session.sessionID, conn.RemoteAddr(), startingDifficulty)

	defer func() {
		s.mu.Lock()
		delete(s.sessions, mc.ID())
		s.mu.Unlock()
		s.debugLogger.Debugf("direct: connection closed: session=%s remote=%s", session.sessionID, conn.RemoteAddr())
		_ = mc.Close("session ended")
	}()

	go session.runVardiffLoop(mc.Context())
	session.Run(mc.Context())
}

// submitBlockDirect is the real block-submission choke point every
// genuine find goes through (session.go's handleSubmit): parallel
// multi-node GRPC submission (s.multiSubmit) is the primary,
// authoritative outcome (its own "at least one acceptance = success"
// return value IS this method's return value); the NATS relay publish
// is a purely-secondary, best-effort side effect that can never affect
// the returned outcome, per this feature's explicit design constraint
// (see internal/leaflib/relay's doc comment).
//
// The returned hash is the REAL, base-node-confirmed chain hash for
// the accepted block — realBlockHashHex extracts it from the
// authoritative node results (see that function's doc comment: it
// comes from tari_generated.SubmitBlockResponse.block_hash, the base
// node's own SubmitBlock RPC response, NOT a locally computed
// placeholder). It is computed exactly ONCE here and used for both
// the relay publish below AND returned to the caller (handleSubmit)
// for the backend report, so there is a single source of truth for
// the real hash rather than two independent call sites each trying to
// derive it.
func (s *Server) submitBlockDirect(ctx context.Context, block *tari_generated.Block) ([]NodeSubmitResult, bool, string) {
	var (
		results []NodeSubmitResult
		ok      bool
	)
	if s.multiSubmit != nil {
		results, ok = s.multiSubmit.SubmitBlock(ctx, block)
	} else {
		s.logger.Printf("direct: no MultiNodeSubmitter configured; block find cannot be submitted to any node")
	}

	hash := realBlockHashHex(results, s.logger)

	// Best-effort NATS relay publish — never allowed to affect ok/
	// results above, and never allowed to block this call meaningfully
	// (relay.Publish itself has no long-blocking network wait; it is
	// fire-and-forget at the NATS client level — see that method's doc
	// comment).
	if s.relay != nil {
		algo := s.currentAlgoLabel()
		data, err := marshalBlockForRelay(block)
		if err != nil {
			s.logger.Printf("direct: failed to marshal block for relay publish (non-fatal, primary submit unaffected): %v", err)
		} else {
			msg := relay.BlockMessage{
				Algo: algo, Network: networkLabel(s.network),
				Height: block.GetHeader().GetHeight(), Hash: hash, BlockData: data,
			}
			if err := s.relay.Publish(ctx, msg); err != nil {
				s.logger.Printf("direct: relay publish failed (non-fatal, primary submit unaffected): %v", err)
			}
		}
	}

	return results, ok, hash
}

// currentAlgoLabel returns the JobManager's configured algo as the
// wire-style string label the relay message carries (coin-agnostic —
// see relay.BlockMessage's doc comment on why this is a plain string,
// not a poolpb.Algo import).
func (s *Server) currentAlgoLabel() string {
	return leaflib.AlgoWireName(s.algo)
}

func networkLabel(n poolpb.Network) string {
	if n == poolpb.Network_NETWORK_MAINNET {
		return "mainnet"
	}
	return "testnet"
}

// handleRelayedBlock is invoked (see NewServer's Subscribe call) when
// this Server's relay receives a found-block message from ANOTHER
// leaf-direct instance (relay.Relay.Subscribe already filters out this
// instance's own published messages and duplicate deliveries — see
// that method's doc comment). It attempts a real local resubmission
// via this Server's OWN configured multi-node submitter, exactly
// mirroring the point of the relay (helping a block found by a
// geographically-distant pool instance propagate faster via every
// subscriber's own network position).
func (s *Server) handleRelayedBlock(msg relay.BlockMessage) {
	if s.multiSubmit == nil {
		s.logger.Printf("direct: received relayed block (height=%d hash=%s) but no local MultiNodeSubmitter is configured; cannot resubmit", msg.Height, msg.Hash)
		s.recordRelayResubmit(directmetrics.ResultNoSubmitter)
		return
	}
	block, err := unmarshalBlockFromRelay(msg.BlockData)
	if err != nil {
		s.logger.Printf("direct: failed to unmarshal relayed block payload (height=%d hash=%s): %v", msg.Height, msg.Hash, err)
		s.recordRelayResubmit(directmetrics.ResultUnmarshalError)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results, ok := s.multiSubmit.SubmitBlock(ctx, block)
	s.logger.Printf("direct: relay-triggered local resubmission (height=%d hash=%s publisher=%s): success=%v results=%v", msg.Height, msg.Hash, msg.PublisherID, ok, results)
	if ok {
		s.recordRelayResubmit(directmetrics.ResultAccepted)
	} else {
		s.recordRelayResubmit(directmetrics.ResultRejected)
	}
}

// recordRelayResubmit bumps leaf_direct_relay_resubmit_total, nil-safe
// like every other record* helper on this type (metrics may not be
// enabled).
func (s *Server) recordRelayResubmit(result string) {
	if s.metrics == nil {
		return
	}
	s.metrics.RelayResubmitTotal.WithLabelValues(result).Inc()
}

// marshalBlockForRelay serializes block into the coin-agnostic
// relay.BlockMessage.BlockData payload. For Tari, this is simply a
// real protobuf marshal of the already-built candidate block (the
// SAME tari_generated.Block that was/will be submitted directly via
// MultiNodeSubmitter) — a receiving leaf-direct instance's own
// unmarshalBlockFromRelay reverses this exactly, so relay-triggered
// resubmission submits the literal same block bytes the finding
// instance itself submitted.
func marshalBlockForRelay(block *tari_generated.Block) ([]byte, error) {
	return proto.Marshal(block)
}

// unmarshalBlockFromRelay reverses marshalBlockForRelay.
func unmarshalBlockFromRelay(data []byte) (*tari_generated.Block, error) {
	var block tari_generated.Block
	if err := proto.Unmarshal(data, &block); err != nil {
		return nil, err
	}
	return &block, nil
}

// Shutdown unsubscribes from job updates and the relay, closes the
// multi-node submitter's connections, stops this Server's RandomX-
// family async validation worker pool, forwardPool, jobFetchPool,
// repushPool (see solo.AsyncValidationPool.Stop — blocks until every
// in-flight job on each pool finishes), the no-share-timeout sweep
// goroutine (see stopNoShareSweep, a no-op if it was never started),
// and — if metrics are enabled — the per-second rate trackers'
// background goroutines (see directmetrics.Metrics.Stop). It does
// not close the ConnectionManager, listener, or transport — callers
// own those lifecycles.
func (s *Server) Shutdown() {
	if s.unsubscribe != nil {
		s.unsubscribe()
	}
	s.repushMu.Lock()
	if s.pendingRepushTimer != nil {
		s.pendingRepushTimer.Stop()
		s.pendingRepushTimer = nil
	}
	s.pendingRepush = false
	s.repushMu.Unlock()
	if s.relayUnsub != nil {
		s.relayUnsub()
	}
	if s.multiSubmit != nil {
		_ = s.multiSubmit.Close()
	}
	s.stopNoShareSweep()
	if s.randomxPool != nil {
		s.randomxPool.Stop()
	}
	if s.forwardPool != nil {
		s.forwardPool.Stop()
	}
	if s.jobFetchPool != nil {
		s.jobFetchPool.Stop()
	}
	if s.repushPool != nil {
		s.repushPool.Stop()
	}
	if s.metrics != nil {
		s.metrics.Stop()
	}
	if s.chainHeightPoller != nil {
		s.chainHeightPoller.Stop()
	}
}
