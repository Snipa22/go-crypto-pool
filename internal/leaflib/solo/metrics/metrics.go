// Package metrics defines leaf-solo's Prometheus instrumentation: this
// is the LEAF-SIDE stats layer, deliberately distinct in scope from
// internal/backend/metrics (which intentionally excludes per-miner
// labels because it aggregates across every leaf in the whole pool).
// A leaf-solo instance runs far fewer simultaneous connections (one
// leaf, one stratum port), so per-miner-address label cardinality is
// a reasonable, operator-relevant tradeoff at THIS level, subject to
// the explicit cap documented on MinersByAddress below.
//
// Mirrors the local convention established by internal/backend/metrics:
// a private *prometheus.Registry via New, graceful non-panicking
// registration, served via promhttp.HandlerFor.
package metrics

import (
	"errors"
	"log"
	"net"
	"net/http"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	shared "github.com/Snipa22/go-crypto-pool/internal/leaflib/metrics"
)

// Result label values for shares_total/blocks_total, mirroring the
// backend metrics package's low-cardinality-by-result convention
// exactly (see internal/backend/metrics.ResultAccepted/ResultRejected):
// deliberately NOT labeled by miner address on this counter (address
// granularity lives on MinersByAddress below instead, where it's a
// live/current-state gauge rather than an ever-growing counter).
const (
	ResultAccepted = "accepted"
	ResultRejected = "rejected"
)

// Connection-error categories for ConnectionErrorsTotal. These map
// directly onto real close paths this package's callers (session.go's
// Run, server.go's handleConn) actually observe:
//   - ConnErrorIdleTimeout: the rolling idle deadline
//     (internal/leaflib.ManagedConnection's armDeadline) fired — the
//     read returned a net.Error with Timeout() == true.
//   - ConnErrorRemoteEOF: the miner closed the connection / sent a
//     clean EOF (bufio.Scanner's normal end-of-stream, Err() == nil).
//   - ConnErrorProtocolError: the miner sent something the wire
//     protocol couldn't parse as a line-delimited message within the
//     scanner's buffer (bufio.ErrTooLong), or the connection was
//     already torn down from under the read
//     (internal/leaflib.ErrConnectionClosed).
//   - ConnErrorRejectedByGate: internal/leaflib.ConnectionManager's
//     ConnectionGate declined to admit the connection at all (over
//     MaxConnections) — see internal/leaflib.ErrConnectionRejected.
//   - ConnErrorOther: any other, unclassified read error (e.g. a raw
//     TCP reset) — kept as a single bounded fallback bucket rather
//     than inventing new fixed categories that don't correspond to a
//     real code path.
//   - ConnErrorNoShareTimeout: server.go's runNoShareSweep closed the
//     connection because it never produced a single genuinely
//     accepted share within the configured -no-share-timeout of
//     connecting (see Server.SetNoShareTimeout's doc comment).
//     Deliberately distinct from ConnErrorIdleTimeout: that category
//     means the connection went fully silent; this one means the
//     connection stayed genuinely active (e.g. repeated keepalived)
//     but never once produced a real accepted share. This reuses the
//     existing ConnectionErrorsTotal metric with a new category
//     label value rather than adding a new metric — this const
//     block documents a "small fixed category set" purely as a
//     documentation/callers convention, not a Prometheus-level closed
//     enum (the label itself is a plain, open-ended string), so
//     adding a new value here is not a breaking change for any
//     existing dashboard.
const (
	ConnErrorIdleTimeout    = "idle-timeout"
	ConnErrorRemoteEOF      = "remote-eof"
	ConnErrorProtocolError  = "protocol-error"
	ConnErrorRejectedByGate = "rejected-by-gate"
	ConnErrorNoShareTimeout = "no-share-timeout"
	ConnErrorOther          = "other"
)

// RejectionReason* label leaf_share_rejection_reason_total -- a small,
// FIXED, closed enum (never the raw free-text s.writeShareResponse
// error string -- that would be unbounded Prometheus label
// cardinality) covering every real reject call site in
// session.go's handleSubmit, found by reading that method in full
// (see brief_rejection_reasons.md, which motivated this metric from a
// leaf-direct production incident -- leaf-solo mirrors the fix here
// since session.go's handleSubmit has the exact same pattern of reject
// call sites with no per-reason visibility). Each site calls
// Metrics.IncShareRejectionReason with exactly one of these, via
// session.go's rejectShare helper -- ADDITIVE to (never replacing) the
// existing s.writeShareResponse(id, false, ...) call and the
// recordShare(false) bookkeeping it already does internally. These
// are the exact same category values internal/leaflib/direct/metrics
// defines (see that package's own doc comment on each for the full
// per-category rationale) -- kept identical across both leaf modes so
// a mixed-fleet dashboard/alert can use one consistent reason label
// set regardless of which leaf mode reported it. leaf-solo's
// handleSubmit has no equivalent of leaf-direct's ADDITIONAL
// real-derived-difficulty-floor recheck (leaf-solo never forwards an
// ordinary share to a backend at all, so that extra check doesn't
// exist here -- see solo/session.go's handleSubmit doc comment), but
// every category below still maps to at least one real leaf-solo call
// site (RejectionReasonDifficultyFloorMiss covers leaf-solo's own
// claimed-difficulty floor check instead). Just like leaf-direct,
// "login required before submit" is deliberately NOT one of these
// categories: that check rejects via writeGeneralResponse (not
// writeShareResponse) before submit params are even parsed, so it
// never touches leaf_shares_total{result="rejected"} at all.
const (
	RejectionReasonStaleOrUnknownJob                = "stale_or_unknown_job"
	RejectionReasonJobExpired                       = "job_expired"
	RejectionReasonBannedAddress                    = "banned_address"
	RejectionReasonInvalidXNonce                    = "invalid_xnonce"
	RejectionReasonMalformedNonce                   = "malformed_nonce"
	RejectionReasonInvalidPowShape                  = "invalid_pow_shape"
	RejectionReasonDuplicateNonce                   = "duplicate_nonce"
	RejectionReasonMissingClaimedResult             = "missing_claimed_result"
	RejectionReasonDifficultyFloorMiss              = "difficulty_floor_miss"
	RejectionReasonClaimedDifficultyOrCryptoInvalid = "claimed_difficulty_or_crypto_invalid"
	RejectionReasonMalformedSubmitRequest           = "malformed_submit_request"
	RejectionReasonBlockSubmitFailed                = "block_submit_failed"
	RejectionReasonPoolSaturated                    = "pool_saturated"
	RejectionReasonInternalError                    = "internal_error"
	RejectionReasonOther                            = "other"
)

// AllRejectionReasons is the full, closed enumeration of every
// RejectionReason* const above, in the order declared -- mirrors
// internal/leaflib/direct/metrics's identical AllRejectionReasons
// exactly (see that package's own doc comment).
var AllRejectionReasons = []string{
	RejectionReasonStaleOrUnknownJob,
	RejectionReasonJobExpired,
	RejectionReasonBannedAddress,
	RejectionReasonInvalidXNonce,
	RejectionReasonMalformedNonce,
	RejectionReasonInvalidPowShape,
	RejectionReasonDuplicateNonce,
	RejectionReasonMissingClaimedResult,
	RejectionReasonDifficultyFloorMiss,
	RejectionReasonClaimedDifficultyOrCryptoInvalid,
	RejectionReasonMalformedSubmitRequest,
	RejectionReasonBlockSubmitFailed,
	RejectionReasonPoolSaturated,
	RejectionReasonInternalError,
	RejectionReasonOther,
}

// LoginRejectionReason* label leaf_solo_login_rejections_total
// (DISPATCH_BRIEF.md "login-rejection-reason metrics", Alex: "Can you
// add a metric for rejected logins to see why we're rejecting? I'm
// curious how many of these are just bans we reject.") -- a small,
// FIXED, closed enum covering every real rejection return point in
// session.go's handleLogin, in the order they're checked:
//   - LoginRejectionReasonInvalidParams: json.Unmarshal(req.Params,
//     &login) failed (malformed JSON from the stratum client).
//   - LoginRejectionReasonEmptyAddress: login.Login == "".
//   - LoginRejectionReasonInvalidAddressFormat:
//     ValidateAddressForAlgo rejects the (already loginfields-parsed)
//     address as malformed for this leaf's configured coin/algo.
//   - LoginRejectionReasonBanned: s.server.addressFlags.Get(...)
//     .Banned is true (the manual ban system,
//     internal/leaflib/addressflags) -- the category this metric
//     exists specifically to quantify against the others.
//   - LoginRejectionReasonNoJobTemplate:
//     s.server.jobManager.JobForSessionAtDifficulty failed (no template
//     available yet) -- happens AFTER the address is already stored
//     and loggedIn flipped true, a distinct infra/timing failure
//     class rather than a client-side rejection, but the client still
//     never received a usable job, so it belongs in this metric too.
//
// Each site calls Metrics.IncLoginRejectionReason with exactly one of
// these, via server.go's recordLoginRejection helper -- mirrors this
// package's existing ShareRejectionReasonTotal/RejectionReason*
// convention exactly, just for the login path rather than submit.
// Deliberately NOT covering session.go's ParseLoginFields error
// return (the "+"-fixed-difficulty/too-many-login-options parse
// failure): that call site is outside this metric's closed reason
// enum, per DISPATCH_BRIEF.md's own exact scope.
const (
	LoginRejectionReasonInvalidParams        = "invalid_params"
	LoginRejectionReasonEmptyAddress         = "empty_address"
	LoginRejectionReasonInvalidAddressFormat = "invalid_address_format"
	LoginRejectionReasonBanned               = "banned"
	LoginRejectionReasonNoJobTemplate        = "no_job_template"
)

// AllLoginRejectionReasons is the full, closed enumeration of every
// LoginRejectionReason* const above, in the order declared -- mirrors
// AllRejectionReasons' identical convention, used by tests to confirm
// only the expected reason's counter moved.
var AllLoginRejectionReasons = []string{
	LoginRejectionReasonInvalidParams,
	LoginRejectionReasonEmptyAddress,
	LoginRejectionReasonInvalidAddressFormat,
	LoginRejectionReasonBanned,
	LoginRejectionReasonNoJobTemplate,
}

// OtherAddressLabel is the bucket every address beyond the configured
// cardinality cap (see CapAddressCounts) is aggregated into, on both
// the leaf_miners_by_address metric and the stats HTML page.
const OtherAddressLabel = "other"

// DefaultMaxAddressLabels is used when a caller passes maxAddressLabels
// <= 0 to New. 50 distinct concurrently-mining addresses is generously
// above what a real single-leaf solo deployment is expected to see
// (this is a single port on a single leaf, not the whole pool), while
// still bounding worst-case label cardinality from a malicious flood
// of junk login addresses to a small, fixed number.
const DefaultMaxAddressLabels = 50

// SessionSnapshot is the minimal point-in-time view of one connected
// session that this package needs to compute the snapshot-derived
// metrics/UI data below (active connections, unique remote IPs,
// per-address counts, vardiff difficulty distribution). It is
// deliberately decoupled from solo.Session (this package must not
// import the solo package, to avoid an import cycle — solo imports
// this package to wire metrics, not the other way around).
type SessionSnapshot struct {
	// Address is the session's logged-in mining/payout address, or ""
	// if the session hasn't completed login yet. Empty-address
	// sessions are excluded from the per-address breakdown (there's
	// nothing meaningful to attribute them to) but still counted in
	// ActiveConnections.
	Address string
	// RemoteIP is the connection's remote IP (port stripped — see
	// this package's doc comment on why per-IP is a bounded COUNT,
	// not a per-IP label).
	RemoteIP string
	// Difficulty is the session's current (post-vardiff) share
	// difficulty at the moment of the snapshot.
	Difficulty uint64
	// Agent is the real miner software/version string the session's
	// miner self-reported at login (solo.LoginRequest.Agent), or ""
	// if not logged in / not sent. Miner-controlled, diagnostic-only
	// — never used in any accept/reject decision.
	Agent string
	// Hashrate is this session's real, per-session estimated
	// hashrate in hashes/second at the moment of the snapshot (see
	// leaflib.EstimateHashrateHz's doc comment for the formula).
	Hashrate float64
}

// SnapshotFunc returns the current set of connected sessions. It is
// called synchronously from Metrics.Collect on every /metrics scrape
// (and from the stats HTML handler), so it must be cheap and
// non-blocking — solo.Server's real implementation is a single
// RLock'd map iteration.
type SnapshotFunc func() []SessionSnapshot

// AsyncPoolStats is the minimal point-in-time view of the shared
// AsyncValidationPool's own live state this package needs for its
// snapshot-derived async-pool metrics (Fix 9, DISPATCH_BRIEF.md
// 2026-09-10) -- deliberately decoupled from
// *solo.AsyncValidationPool itself (this package must not import the
// solo package, to avoid an import cycle: solo imports this package
// to wire metrics, not the other way around). See
// solo.AsyncValidationPool's own doc comment for why it exposes
// plain getters rather than any one metrics-registration convention.
type AsyncPoolStats struct {
	// QueueDepth is the current number of closures sitting in the
	// pool's bounded queue, waiting for a free worker.
	QueueDepth int
	// InFlightWorkers is how many of the pool's fixed worker
	// goroutines are, at this instant, actually running a dispatched
	// validation closure.
	InFlightWorkers int64
	// SubmitBlockedTotal is the real, monotonically-increasing count
	// of Submit calls that could not take the fast, non-blocking
	// path -- i.e. how many times a caller actually had to wait for
	// queue room/a free worker.
	SubmitBlockedTotal uint64
}

// AsyncPoolStatsFunc returns the current AsyncPoolStats. Called
// synchronously from Metrics.Collect on every /metrics scrape, so it
// must be cheap and non-blocking -- solo.Server's real implementation
// is three plain atomic loads via the pool's own getters.
type AsyncPoolStatsFunc func() AsyncPoolStats

// Metrics holds every Prometheus collector leaf-solo registers, plus
// the registry they live in. Constructed via New; safe for concurrent
// use.
type Metrics struct {
	registry *prometheus.Registry

	// SharesTotal/BlocksTotal are real accept/reject counters
	// incremented at handleSubmit's real branch points (session.go).
	// Labeled by result only (accepted/rejected) — NOT by miner
	// address, mirroring the backend's low-cardinality convention.
	SharesTotal *prometheus.CounterVec
	BlocksTotal *prometheus.CounterVec

	// ConnectionErrorsTotal is incremented at real connection
	// teardown points, labeled by the small fixed category set
	// above.
	ConnectionErrorsTotal *prometheus.CounterVec

	// XNPReservationUnavailableTotal counts every real
	// MoneroNodeClient.GetBlockTemplate call whose real monerod
	// reserved_offset did not fit within its own returned
	// blocktemplate_blob (see monero_node.go's GetBlockTemplate
	// bounds check and job.go's Job.ReservedOffsetUsable doc comment
	// for the full production-bug rationale) -- i.e. how often a job
	// is served with the XNP-proxy-shape fields (reserved_offset/
	// client_nonce_offset/client_pool_offset/blocktemplate_blob)
	// degraded to omitted rather than potentially-corrupt.
	XNPReservationUnavailableTotal prometheus.Counter

	// ShareRejectionReasonTotal is the real, per-category breakdown
	// of the "rejected" side of SharesTotal (leaf_shares_total
	// {result="rejected"}) -- labeled by reason (see the
	// RejectionReason* consts above). Mirrors
	// internal/leaflib/direct/metrics's identical
	// ShareRejectionReasonTotal exactly -- ADDITIVE to (never
	// replacing) SharesTotal's own existing accepted/rejected split,
	// which is completely unchanged.
	ShareRejectionReasonTotal *prometheus.CounterVec

	// LoginRejectionsTotal is the real, per-category breakdown of
	// every login-time rejection in session.go's handleLogin (see the
	// LoginRejectionReason* consts above) -- DISPATCH_BRIEF.md
	// "login-rejection-reason metrics". Previously EVERY one of these
	// rejection points was log-only, with no counter of any kind.
	LoginRejectionsTotal *prometheus.CounterVec

	// ReloginTotal counts every real re-login event detected in
	// session.go's handleLogin (BRIEF.md "decouple TCP/miner-
	// identity"): a session receiving a SECOND (or Nth) "login"
	// message on an already-logged-in connection (e.g. an
	// xmrig-proxy `--reuse-timeout` connection-reuse slot rotation).
	// Incremented exactly once per re-login EVENT, not once per
	// login overall -- a session's first, ordinary login never
	// increments this. Unlabeled: a plain counter, mirroring
	// XNPReservationUnavailableTotal's identical unlabeled-Counter
	// convention above rather than the busier per-reason metrics.
	ReloginTotal prometheus.Counter

	// SubmitProcessingSeconds observes the real, end-to-end wall-
	// clock latency of session.go's handleSubmit -- from entry to
	// the point the response is actually written to the miner
	// (accept or reject), labeled by result (accepted/rejected) so
	// the two latency profiles can be told apart. An early-exit
	// rejection (e.g. "login required before submit") is still
	// timed and counted -- it's real latency the miner experiences
	// too, not skipped as a special case. For a genuine RXT/RXM
	// block-find candidate (the one case where finishSubmit is
	// dispatched onto s.server.randomxPool rather than run inline --
	// see handleSubmit's own dispatch-decision doc comment), the
	// SAME start timestamp taken at handleSubmit's entry is threaded
	// into finishSubmit and observed from INSIDE it once it actually
	// completes on whichever goroutine runs it, so this metric
	// genuinely reflects the full latency through the real
	// randomx-service round-trip and response write, not merely the
	// cheap synchronous dispatch call.
	SubmitProcessingSeconds *prometheus.HistogramVec

	// SubmitValidationSeconds observes the real wall-clock time spent
	// specifically inside the real PoW validator call (v.Validate) in
	// session.go's finishSubmit closure, labeled by algo (see
	// leaflib.AlgoMetricLabel) so a validator regression/slowdown for
	// ONE algo is visible without averaging across every algo this
	// leaf might serve. Deliberately NOT observed at all (no
	// zero/garbage sample) for solo's own real-validator-call
	// dispatch decision that never even reaches finishSubmit (an
	// ordinary, sub-block-difficulty RXT/RXM claim, per
	// DISPATCH_BRIEF.md 2026-09-10 Fix 4 -- that path never calls
	// v.Validate at all) -- a near-zero sample there would be
	// misleading noise, not a real signal.
	SubmitValidationSeconds *prometheus.HistogramVec

	BuildInfo *prometheus.GaugeVec

	// sharesRate/blocksRate/rejectionReasonRate back
	// leaf_shares_per_second/leaf_blocks_per_second/
	// leaf_share_rejection_reason_per_second (see Collect) -- a
	// 60s-rolling-window per-second rate of SharesTotal/BlocksTotal/
	// ShareRejectionReasonTotal, additive to those counters (which
	// remain completely unchanged). One shared.RateTracker per label
	// combination, created lazily by
	// IncShareResult/IncBlockResult/IncShareRejectionReason below at
	// the exact same real accept/reject/rejection-reason branch
	// points server.go's recordShare/recordBlock/
	// recordShareRejectionReason already call. Mirrors
	// internal/leaflib/direct/metrics's identical fields exactly.
	sharesRate          *shared.LabeledRateTrackers
	blocksRate          *shared.LabeledRateTrackers
	rejectionReasonRate *shared.LabeledRateTrackers

	maxAddressLabels int
	snapshot         SnapshotFunc
	asyncPoolStats   AsyncPoolStatsFunc
}

// New constructs a Metrics using a fresh, private *prometheus.Registry
// (see internal/backend/metrics.New's doc comment for the rationale —
// this mirrors that convention exactly). version is recorded on the
// leaf_solo_build_info gauge. maxAddressLabels bounds the
// leaf_miners_by_address cardinality (see CapAddressCounts); <= 0
// falls back to DefaultMaxAddressLabels.
func New(version string, maxAddressLabels int) *Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = DefaultMaxAddressLabels
	}
	reg := prometheus.NewRegistry()
	// Standard Go runtime (go_goroutines/go_memstats_*/
	// go_gc_duration_seconds/...) and process (process_cpu_seconds_total/
	// process_resident_memory_bytes/...) collectors -- this Metrics'
	// registry is a private *prometheus.Registry (see this package's
	// doc comment), not the global default registry client_golang
	// auto-registers these onto, so without this they would never
	// appear on this leaf's /metrics at all. MustRegister (not the
	// AlreadyRegisteredError-tolerant registerCounterVec-style helpers
	// below): each is only ever registered once per New() call, so a
	// panic on a genuine double-registration bug is the correct, loud
	// failure mode here.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := &Metrics{registry: reg, maxAddressLabels: maxAddressLabels}

	m.SharesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_shares_total",
		Help: "Total number of shares submitted to this leaf-solo instance, by result (accepted/rejected). Not labeled by miner address.",
	}, []string{"result"})

	m.BlocksTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_blocks_total",
		Help: "Total number of blocks found/submitted by this leaf-solo instance, by result (accepted/rejected). Not labeled by miner address.",
	}, []string{"result"})

	m.ConnectionErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_connection_errors_total",
		Help: "Total number of miner connections that ended in an error/non-graceful category, by category (idle-timeout/remote-eof/protocol-error/rejected-by-gate/other).",
	}, []string{"category"})

	m.XNPReservationUnavailableTotal = registerCounter(reg, prometheus.CounterOpts{
		Name: "leaf_xnp_reservation_unavailable_total",
		Help: "Total number of Monero get_block_template responses whose real reserved_offset did not fit within the returned blocktemplate_blob, causing the XNP-proxy-shape job fields (reserved_offset/client_nonce_offset/client_pool_offset/blocktemplate_blob) to be omitted for that job rather than published out-of-bounds.",
	})

	m.ShareRejectionReasonTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_share_rejection_reason_total",
		Help: "Real, per-category breakdown of the 'rejected' side of leaf_shares_total, by reason (see this package's RejectionReason* consts for the full, closed enum and the exact handleSubmit call site each one maps to). Additive to leaf_shares_total's own accepted/rejected split, which remains completely unchanged.",
	}, []string{"reason"})

	m.LoginRejectionsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_solo_login_rejections_total",
		Help: "Real, per-category breakdown of every login-time rejection in session.go's handleLogin (see this package's LoginRejectionReason* consts for the full, closed enum and the exact handleLogin call site each one maps to) -- previously every one of these rejection points was log-only, with no counter of any kind.",
	}, []string{"reason"})

	m.ReloginTotal = registerCounter(reg, prometheus.CounterOpts{
		Name: "leaf_relogin_total",
		Help: "Total number of real re-login events detected in session.go's handleLogin: a session receiving a second (or Nth) login message on an already-logged-in connection (e.g. an xmrig-proxy --reuse-timeout connection-reuse slot rotation). Incremented once per re-login event, not once per login overall.",
	})

	// leaf_solo_submit_processing_seconds' bucket boundaries:
	// prometheus.DefBuckets (5ms..10s). This metric's tail can, in
	// the rare RXT/RXM block-find-candidate case, include a real
	// synchronous randomx-service HTTP round-trip (see
	// SubmitProcessingSeconds' own doc comment) -- but that call site
	// is (by construction, per DISPATCH_BRIEF.md 2026-09-10 Fix 4)
	// the rare, block-level-only path, not the typical hot-path
	// submit, and the underlying real round-trip is itself already
	// only ~4ms+ (see asyncvalidation.go's own doc comment), well
	// within DefBuckets' 10s ceiling. DefBuckets is kept, matching
	// TemplateDistributionDuration's own precedent, rather than a
	// bespoke set.
	m.SubmitProcessingSeconds = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "leaf_solo_submit_processing_seconds",
		Help:    "Real, end-to-end wall-clock seconds of session.go's handleSubmit, from entry to the point the response is written to the miner, by result (accepted/rejected). Includes early-exit rejections (e.g. login required before submit). Buckets: prometheus.DefBuckets.",
		Buckets: prometheus.DefBuckets,
	}, []string{"result"})

	// leaf_solo_submit_validation_seconds' bucket boundaries: also
	// prometheus.DefBuckets. This is narrower in scope than
	// SubmitProcessingSeconds above (only the v.Validate call itself,
	// not the surrounding handleSubmit/finishSubmit work), so its
	// real observed values are a strict subset of that metric's own
	// -- the same DefBuckets ceiling applies with even more headroom
	// here.
	m.SubmitValidationSeconds = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "leaf_solo_submit_validation_seconds",
		Help:    "Real wall-clock seconds spent specifically inside the real PoW validator call (v.Validate) in session.go's finishSubmit, by algo (sha3x/c29/rxt/rxm -- see leaflib.AlgoMetricLabel). Never observed for the trusted/validation-skip case (there is none for solo -- see this field's own doc comment) or for an ordinary, sub-block-difficulty RXT/RXM claim that never reaches v.Validate at all. Buckets: prometheus.DefBuckets.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo"})

	m.BuildInfo = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_solo_build_info",
		Help: "Always 1; version label carries the running build's version string.",
	}, []string{"version"})
	m.BuildInfo.WithLabelValues(version).Set(1)

	m.sharesRate = shared.NewLabeledRateTrackers()
	m.blocksRate = shared.NewLabeledRateTrackers()
	m.rejectionReasonRate = shared.NewLabeledRateTrackers()

	// m itself implements prometheus.Collector for the
	// snapshot-derived metrics (active connections, unique remote
	// IPs, per-address gauge, vardiff difficulty histogram) — see
	// Describe/Collect below.
	if err := reg.Register(m); err != nil {
		log.Printf("metrics: failed to register leaf-solo snapshot collector: %v", err)
	}

	return m
}

// SetSnapshotSource wires the live session-snapshot provider (see
// SnapshotFunc). Must be called once, before the /metrics endpoint is
// ever served, for the snapshot-derived metrics to report real data
// instead of zeros. Not safe to call concurrently with Collect (in
// practice this is called once at startup, before the metrics HTTP
// listener is started).
func (m *Metrics) SetSnapshotSource(fn SnapshotFunc) {
	m.snapshot = fn
}

// SetAsyncPoolSource wires the shared AsyncValidationPool's live
// stats provider (Fix 9, DISPATCH_BRIEF.md 2026-09-10). Must be
// called once, before the /metrics endpoint is ever served, for
// leaf_async_validation_queue_depth/leaf_async_validation_in_flight_workers/
// leaf_async_validation_submit_blocked_total to report real data
// instead of zeros. Not safe to call concurrently with Collect (in
// practice this is called once at startup, exactly like
// SetSnapshotSource).
func (m *Metrics) SetAsyncPoolSource(fn AsyncPoolStatsFunc) {
	m.asyncPoolStats = fn
}

// Handler returns the standard Prometheus text-exposition HTTP handler
// scoped to this Metrics' private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// IncShareResult increments SharesTotal for result (see
// resultLabel-style accepted/rejected values) AND records the same
// increment for that result's rolling-window per-second rate
// (leaf_shares_per_second, see Collect) -- callers (server.go's
// recordShare) must call this INSTEAD OF touching SharesTotal
// directly, so the two never drift out of lockstep. Mirrors
// internal/leaflib/direct/metrics's identical method exactly.
func (m *Metrics) IncShareResult(result string) {
	m.SharesTotal.WithLabelValues(result).Inc()
	m.sharesRate.Inc(result)
}

// IncBlockResult is IncShareResult's BlocksTotal/
// leaf_blocks_per_second analogue.
func (m *Metrics) IncBlockResult(result string) {
	m.BlocksTotal.WithLabelValues(result).Inc()
	m.blocksRate.Inc(result)
}

// IncShareRejectionReason is IncShareResult's ShareRejectionReasonTotal/
// leaf_share_rejection_reason_per_second analogue -- callers
// (server.go's recordShareRejectionReason, itself called from
// session.go's rejectShare helper at every real reject call site)
// must call this INSTEAD OF touching ShareRejectionReasonTotal
// directly, so the two never drift out of lockstep. Mirrors
// internal/leaflib/direct/metrics's identical method exactly.
func (m *Metrics) IncShareRejectionReason(reason string) {
	m.ShareRejectionReasonTotal.WithLabelValues(reason).Inc()
	m.rejectionReasonRate.Inc(reason)
}

// IncLoginRejectionReason bumps LoginRejectionsTotal for reason (one
// of LoginRejectionReason* above) -- callers (server.go's
// recordLoginRejection, itself called from session.go's handleLogin
// at every real rejection return point) must call this INSTEAD OF
// touching LoginRejectionsTotal directly, mirroring
// IncShareResult/IncShareRejectionReason's identical
// single-choke-point convention. Deliberately no accompanying
// per-second rate gauge (unlike IncShareRejectionReason's
// rejectionReasonRate) -- DISPATCH_BRIEF.md's own scope for this
// metric is a plain counter, matching leaf-proxy's existing
// BanRejectionsTotal convention, not the busier submit-path metrics.
func (m *Metrics) IncLoginRejectionReason(reason string) {
	m.LoginRejectionsTotal.WithLabelValues(reason).Inc()
}

// IncRelogin bumps ReloginTotal by one -- callers (server.go's
// recordRelogin, itself called from session.go's handleLogin at the
// exact point a re-login is detected) must call this INSTEAD OF
// touching ReloginTotal directly, mirroring
// IncLoginRejectionReason's identical single-choke-point convention.
func (m *Metrics) IncRelogin() {
	m.ReloginTotal.Inc()
}

// Stop releases the background ticker goroutines backing
// sharesRate/blocksRate/rejectionReasonRate's lazily-created
// shared.RateTracker instances (see shared.RateTracker.Stop's own
// doc comment -- safe to call even if some/all label combinations
// were never incremented). Callers (server.go's Shutdown) should
// call this from the owning Server's own shutdown path; a Metrics
// never explicitly Stop()'d simply keeps its trackers' goroutines
// alive for the process lifetime, which is fine for the normal
// one-Metrics-per-process production case (mirrors
// solo.AsyncValidationPool.Stop's identical "optional for a
// process-lifetime singleton" convention).
func (m *Metrics) Stop() {
	m.sharesRate.Stop()
	m.blocksRate.Stop()
	m.rejectionReasonRate.Stop()
}

// --- snapshot-derived metrics (recomputed on every scrape) ---

var (
	activeConnectionsDesc = prometheus.NewDesc(
		"leaf_active_connections",
		"Current number of active miner connections (live count, len(sessions)).",
		nil, nil,
	)
	// uniqueRemoteIPsDesc deliberately has NO per-IP label — see this
	// package's doc comment and the doc comment above on
	// SessionSnapshot.RemoteIP: exposing one Prometheus label value
	// per distinct remote IP that has ever connected is an unbounded
	// cardinality risk on WAN-facing, untrusted input (unlike the
	// address gauge below, an attacker can trivially cycle through
	// far more distinct source IPs than distinct useful addresses,
	// e.g. via IPv6). A bounded distinct-IP-count-of-currently-
	// connected-sessions gauge gives the requested "connections by
	// IP" visibility (how spread out is the current connection set)
	// without that risk; per-session RemoteAddr is still available
	// via the stats HTML page's per-session table for be operators
	// who need to look up a *specific* IP by hand.
	uniqueRemoteIPsDesc = prometheus.NewDesc(
		"leaf_unique_remote_ips_gauge",
		"Current number of distinct remote IPs among active miner connections (bounded by active-connection count, never a per-IP label).",
		nil, nil,
	)
	// minersByAddressDesc: unlike the backend's blanket exclusion of
	// per-miner labels (unbounded pool-wide cardinality), a leaf-solo
	// instance's connection count is naturally bounded by
	// MaxConnections/practical stratum-port capacity, so real
	// distinct-address cardinality here is small in practice. Still,
	// a payment address IS attacker-controllable (anyone can log in
	// with any string), so CapAddressCounts below enforces a hard cap
	// on distinct label values regardless: the top maxAddressLabels-1
	// addresses by live connection count get their own series, and
	// every address beyond that is aggregated into a single
	// OtherAddressLabel series, so this metric can never grow past
	// maxAddressLabels distinct label values no matter how many
	// distinct junk addresses a flood presents.
	minersByAddressDesc = prometheus.NewDesc(
		"leaf_miners_by_address",
		"Current number of connected sessions per mining/payout address (live snapshot, capped cardinality — overflow addresses are aggregated into address=\"other\").",
		[]string{"address"}, nil,
	)
	// minerHashrateByAddressDesc reports the real, summed per-session
	// estimated hashrate (leaflib.EstimateHashrateHz) of every
	// currently-connected session, aggregated by mining/payout
	// address and subject to the EXACT SAME cardinality cap as
	// minersByAddressDesc above (CapAddressHashrates, the float64
	// analogue of CapAddressCounts) — an address is attacker-
	// controllable (any login string), so this gauge's cardinality
	// must be bounded identically to the miners-by-address gauge it
	// is aggregated alongside, never per raw session (session IDs
	// are even more attacker-controllable via connection churn).
	minerHashrateByAddressDesc = prometheus.NewDesc(
		"leaf_miner_hashrate_hash_per_second",
		"Real, per-address SUM of currently-connected sessions' estimated hashrate in hashes/second (see leaflib.EstimateHashrateHz's doc comment for the difficulty/time estimation formula). Same capped cardinality as leaf_miners_by_address; overflow aggregated into address=\"other\".",
		[]string{"address"}, nil,
	)

	// asyncPool*Desc: Fix 9 (DISPATCH_BRIEF.md 2026-09-10) --
	// snapshot-derived, recomputed on every scrape from the shared
	// AsyncValidationPool's own live getters (see AsyncPoolStats'
	// doc comment). Named "leaf_async_validation_*" (not
	// "leaf_solo_*") deliberately: this is the exact same shared
	// pool/component leaf-direct and leaf-proxy also construct, and
	// each process's own private registry never collides with the
	// others' (one leaf mode per process), so a consistent,
	// mode-agnostic metric name across all three is more useful to
	// an operator running a mixed fleet than a mode-prefixed one
	// would be here.
	asyncPoolQueueDepthDesc = prometheus.NewDesc(
		"leaf_async_validation_queue_depth",
		"Current number of RandomX-family (RXT/RXM) share-validation closures sitting in the shared AsyncValidationPool's bounded queue, waiting for a free worker.",
		nil, nil,
	)
	asyncPoolInFlightWorkersDesc = prometheus.NewDesc(
		"leaf_async_validation_in_flight_workers",
		"Current number of the shared AsyncValidationPool's fixed worker goroutines actively running a validation closure right now.",
		nil, nil,
	)
	asyncPoolSubmitBlockedTotalDesc = prometheus.NewDesc(
		"leaf_async_validation_submit_blocked_total",
		"Total number of Submit calls to the shared AsyncValidationPool that could not take the fast, non-blocking path (queue full and every worker busy) -- the real saturation signal for Finding 2's bounded-queue/NumCPU-workers fix.",
		nil, nil,
	)

	// *PerSecondDesc: additive 60s-rolling-window per-second rate
	// gauges (see shared.RateTracker) mirroring their corresponding
	// _total counter's exact label set -- SharesTotal/BlocksTotal
	// remain completely unchanged; some dashboards/alerting may
	// already correctly apply rate()/irate() against them. Mirrors
	// internal/leaflib/direct/metrics's identical Desc vars exactly
	// (leaf_shares_per_second/leaf_blocks_per_second, not
	// leaf_direct_*, matching SharesTotal/BlocksTotal's own
	// leaf-solo-specific naming above).
	sharesPerSecondDesc = prometheus.NewDesc(
		"leaf_shares_per_second",
		"Real, leaf-computed 60-second-rolling-window per-second rate of leaf_shares_total, by result (accepted/rejected) -- computed directly by this leaf (see shared.RateTracker) rather than relying on a dashboard panel applying rate()/irate() against the _total counter itself.",
		[]string{"result"}, nil,
	)
	blocksPerSecondDesc = prometheus.NewDesc(
		"leaf_blocks_per_second",
		"Real, leaf-computed 60-second-rolling-window per-second rate of leaf_blocks_total, by result (accepted/rejected).",
		[]string{"result"}, nil,
	)
	rejectionReasonPerSecondDesc = prometheus.NewDesc(
		"leaf_share_rejection_reason_per_second",
		"Real, leaf-computed 60-second-rolling-window per-second rate of leaf_share_rejection_reason_total, by reason (see the RejectionReason* consts for the full, closed enum).",
		[]string{"reason"}, nil,
	)
)

// vardiffDifficultyBuckets covers LEAF_SOLO_MIN_DIFFICULTY..
// LEAF_SOLO_MAX_DIFFICULTY's typical real range (1 up to ~1e9, see
// cmd/leaf-solo/main.go's defaults) with exponentially-spaced buckets.
var vardiffDifficultyBuckets = prometheus.ExponentialBuckets(1, 10, 10)

// Describe deliberately sends nothing: this makes Metrics an
// "unchecked" Prometheus collector (an explicitly-supported pattern,
// see the prometheus.Collector doc comment on Describe), which is
// required here because leaf_miners_by_address's label VALUES are
// dynamic and only known at Collect time (the whole point of the
// cardinality cap above is that the exact set of addresses reported
// varies scrape to scrape as sessions connect/disconnect).
func (m *Metrics) Describe(_ chan<- *prometheus.Desc) {}

// Collect recomputes every snapshot-derived metric from the live
// session set (via m.snapshot, set by SetSnapshotSource) at scrape
// time, rather than maintaining running per-session state that would
// leak/go stale after a session disconnects.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	var snaps []SessionSnapshot
	if m.snapshot != nil {
		snaps = m.snapshot()
	}

	ch <- prometheus.MustNewConstMetric(activeConnectionsDesc, prometheus.GaugeValue, float64(len(snaps)))

	ipSet := make(map[string]struct{}, len(snaps))
	addrCounts := make(map[string]int)
	addrHashrates := make(map[string]float64)
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "leaf_vardiff_current_difficulty",
		Help:    "Distribution of currently-connected sessions' current (post-vardiff) share difficulty, recomputed on every scrape.",
		Buckets: vardiffDifficultyBuckets,
	})
	for _, s := range snaps {
		if s.RemoteIP != "" {
			ipSet[s.RemoteIP] = struct{}{}
		}
		if s.Address != "" {
			addrCounts[s.Address]++
			addrHashrates[s.Address] += s.Hashrate
		}
		hist.Observe(float64(s.Difficulty))
	}
	hist.Collect(ch)

	ch <- prometheus.MustNewConstMetric(uniqueRemoteIPsDesc, prometheus.GaugeValue, float64(len(ipSet)))

	kept, other := CapAddressCounts(addrCounts, m.maxAddressLabels)
	for addr, count := range kept {
		ch <- prometheus.MustNewConstMetric(minersByAddressDesc, prometheus.GaugeValue, float64(count), addr)
	}
	if other > 0 {
		ch <- prometheus.MustNewConstMetric(minersByAddressDesc, prometheus.GaugeValue, float64(other), OtherAddressLabel)
	}

	keptRates, otherRate := CapAddressHashrates(addrHashrates, m.maxAddressLabels)
	for addr, rate := range keptRates {
		ch <- prometheus.MustNewConstMetric(minerHashrateByAddressDesc, prometheus.GaugeValue, rate, addr)
	}
	if otherRate > 0 {
		ch <- prometheus.MustNewConstMetric(minerHashrateByAddressDesc, prometheus.GaugeValue, otherRate, OtherAddressLabel)
	}

	if m.asyncPoolStats != nil {
		stats := m.asyncPoolStats()
		ch <- prometheus.MustNewConstMetric(asyncPoolQueueDepthDesc, prometheus.GaugeValue, float64(stats.QueueDepth))
		ch <- prometheus.MustNewConstMetric(asyncPoolInFlightWorkersDesc, prometheus.GaugeValue, float64(stats.InFlightWorkers))
		ch <- prometheus.MustNewConstMetric(asyncPoolSubmitBlockedTotalDesc, prometheus.CounterValue, float64(stats.SubmitBlockedTotal))
	}

	ch <- prometheus.MustNewConstMetric(sharesPerSecondDesc, prometheus.GaugeValue, m.sharesRate.Rate(ResultAccepted), ResultAccepted)
	ch <- prometheus.MustNewConstMetric(sharesPerSecondDesc, prometheus.GaugeValue, m.sharesRate.Rate(ResultRejected), ResultRejected)

	ch <- prometheus.MustNewConstMetric(blocksPerSecondDesc, prometheus.GaugeValue, m.blocksRate.Rate(ResultAccepted), ResultAccepted)
	ch <- prometheus.MustNewConstMetric(blocksPerSecondDesc, prometheus.GaugeValue, m.blocksRate.Rate(ResultRejected), ResultRejected)

	for _, reason := range AllRejectionReasons {
		ch <- prometheus.MustNewConstMetric(rejectionReasonPerSecondDesc, prometheus.GaugeValue, m.rejectionReasonRate.Rate(reason), reason)
	}
}

// CapAddressCounts enforces the leaf_miners_by_address cardinality cap
// documented above: if counts already has max or fewer distinct
// addresses, it is returned unchanged with otherTotal == 0. Otherwise
// the top (max-1) addresses by count (ties broken by address, for
// deterministic output) are kept verbatim and every remaining
// address's count is summed into otherTotal, which the caller is
// expected to render/export under OtherAddressLabel — so the exported
// series count never exceeds max regardless of how many distinct
// addresses actually connected.
func CapAddressCounts(counts map[string]int, max int) (kept map[string]int, otherTotal int) {
	if max <= 0 {
		max = DefaultMaxAddressLabels
	}
	if len(counts) <= max {
		return counts, 0
	}

	type kv struct {
		addr  string
		count int
	}
	items := make([]kv, 0, len(counts))
	for a, c := range counts {
		items = append(items, kv{a, c})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].addr < items[j].addr
	})

	keepN := max - 1 // reserve one label slot for the "other" bucket
	if keepN < 0 {
		keepN = 0
	}
	kept = make(map[string]int, keepN)
	for i := 0; i < len(items); i++ {
		if i < keepN {
			kept[items[i].addr] = items[i].count
		} else {
			otherTotal += items[i].count
		}
	}
	return kept, otherTotal
}

// CapAddressHashrates is CapAddressCounts' float64 analogue, used to
// bound leaf_miner_hashrate_hash_per_second's cardinality identically
// to leaf_miners_by_address's (see minerHashrateByAddressDesc's doc
// comment): if rates already has max or fewer distinct addresses, it
// is returned unchanged with otherTotal == 0. Otherwise the top
// (max-1) addresses by rate (ties broken by address, for deterministic
// output) are kept verbatim and every remaining address's rate is
// summed into otherTotal, under OtherAddressLabel.
func CapAddressHashrates(rates map[string]float64, max int) (kept map[string]float64, otherTotal float64) {
	if max <= 0 {
		max = DefaultMaxAddressLabels
	}
	if len(rates) <= max {
		return rates, 0
	}

	type kv struct {
		addr string
		rate float64
	}
	items := make([]kv, 0, len(rates))
	for a, r := range rates {
		items = append(items, kv{a, r})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].rate != items[j].rate {
			return items[i].rate > items[j].rate
		}
		return items[i].addr < items[j].addr
	})

	keepN := max - 1
	if keepN < 0 {
		keepN = 0
	}
	kept = make(map[string]float64, keepN)
	for i := 0; i < len(items); i++ {
		if i < keepN {
			kept[items[i].addr] = items[i].rate
		} else {
			otherTotal += items[i].rate
		}
	}
	return kept, otherTotal
}

// RemoteIPOf extracts just the IP (no port) from a net.Addr's string
// form, falling back to the raw string if it isn't a host:port pair
// (e.g. a net.Pipe address in tests, which nets.SplitHostPort can't
// parse). Exported so solo.Server's real net.Conn.RemoteAddr() values
// can be normalized the same way this package's tests construct
// SessionSnapshot.RemoteIP.
func RemoteIPOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// --- graceful registration helpers (mirrors internal/backend/metrics) ---

func registerCounterVec(reg *prometheus.Registry, opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	cv := prometheus.NewCounterVec(opts, labels)
	if err := reg.Register(cv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register counter %s: %v", opts.Name, err)
	}
	return cv
}

func registerGaugeVec(reg *prometheus.Registry, opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	gv := prometheus.NewGaugeVec(opts, labels)
	if err := reg.Register(gv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.GaugeVec); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register gauge vec %s: %v", opts.Name, err)
	}
	return gv
}

// registerHistogramVec mirrors registerCounterVec/registerGaugeVec's
// exact same AlreadyRegisteredError-tolerant pattern, for a labeled
// *prometheus.HistogramVec.
func registerHistogramVec(reg *prometheus.Registry, opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	hv := prometheus.NewHistogramVec(opts, labels)
	if err := reg.Register(hv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register histogram vec %s: %v", opts.Name, err)
	}
	return hv
}

// registerCounter mirrors registerCounterVec/registerGaugeVec's
// graceful-registration convention exactly, for a plain (unlabeled)
// prometheus.Counter.
func registerCounter(reg *prometheus.Registry, opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
		}
		log.Printf("metrics: failed to register counter %s: %v", opts.Name, err)
	}
	return c
}
