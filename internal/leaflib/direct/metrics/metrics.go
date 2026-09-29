// Package metrics defines leaf-direct's Prometheus instrumentation,
// mirroring internal/leaflib/solo/metrics's own conventions exactly
// (private *prometheus.Registry, graceful non-panicking registration,
// bounded per-address label cardinality) plus one genuinely new metric
// (TransportErrorsTotal) leaf-solo has no equivalent of, since
// leaf-solo never forwards anything to a backend.
package metrics

import (
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	shared "github.com/Snipa22/go-crypto-pool/internal/leaflib/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
)

const (
	ResultAccepted = "accepted"
	ResultRejected = "rejected"

	// ResultSuccess/ResultError label relay publish outcomes
	// (leaf_relay_block_publish_total / leaf_relay_template_publish_total).
	ResultSuccess = "success"
	ResultError   = "error"

	// ResultDispatched/ResultDuplicate label relay receive outcomes
	// (leaf_relay_block_receive_total / leaf_relay_template_receive_total)
	// -- "dispatched" means relay.Relay's Subscribe/SubscribeTemplate
	// handler was genuinely invoked for a non-duplicate message from
	// another instance; "duplicate" means markSeen's recent-hash
	// cache recognized an already-processed hash and skipped
	// re-dispatch (see relay.Relay.Subscribe's own doc comment).
	ResultDispatched = "dispatched"
	ResultDuplicate  = "duplicate"

	// ResultNoSubmitter labels leaf_direct_relay_resubmit_total for a
	// relay-triggered resubmission attempt that could not even be
	// attempted because this instance has no MultiNodeSubmitter
	// configured (see server.go's handleRelayedBlock) -- distinct
	// from ResultRejected/ResultAccepted-style success/fail, since no
	// real submit attempt was made at all.
	ResultNoSubmitter = "no_submitter"

	// ResultUnmarshalError labels leaf_direct_relay_resubmit_total for
	// a relay-dispatched found-block message whose BlockData payload
	// failed to unmarshal (see server.go's handleRelayedBlock /
	// unmarshalBlockFromRelay) -- resubmission could not even be
	// attempted, distinct from ResultNoSubmitter (which means no
	// MultiNodeSubmitter is configured at all).
	ResultUnmarshalError = "unmarshal_error"

	// ClassificationTrusted/ClassificationValidated/ClassificationInvalid
	// label leaf_direct_shares_by_classification_total -- a 3-way
	// split mirroring legacy nodejs-pool-sxmr's (lib/pool.js) own 30s
	// log line ("Processed ${trustedShares}/${normalShares}/
	// ${invalidShares}/${totalShares} Trusted/Validated/Invalid/Total
	// shares in the last 30 seconds"; total is deliberately not
	// re-derived here since it is always the redundant sum of the
	// other three). ClassificationTrusted is a RandomX-family
	// (RXT/RXM) submit that skipped real validation entirely via
	// session.go's trusted-miner mechanism (solo/trust.go) and was
	// still accepted; ClassificationValidated is a RandomX-family
	// submit that WAS fully, cryptographically validated and
	// accepted; ClassificationInvalid is a RandomX-family submit
	// that was rejected (either the real validator said no, or it
	// failed the claimed-difficulty floor check) -- see session.go's
	// handleSubmit/finishSubmit for the exact three call sites.
	ClassificationTrusted   = "trusted"
	ClassificationValidated = "validated"
	ClassificationInvalid   = "invalid"

	// RejectionReason* label leaf_direct_share_rejection_reason_total
	// -- a small, FIXED, closed enum (never the raw free-text
	// s.writeShareResponse error string -- that would be unbounded
	// Prometheus label cardinality) covering every real
	// pre-validation-and-beyond reject call site in
	// session.go's handleSubmit, found by reading that method in
	// full (see brief_rejection_reasons.md's live incident: prior to
	// this, ZERO of these had any per-reason visibility at all --
	// only the aggregate leaf_direct_shares_total{result="rejected"}
	// counter, which cannot distinguish "12% pre-validation rejects"
	// from "0.06% genuine crypto/difficulty failures"). Each site
	// calls Metrics.IncShareRejectionReason with exactly one of
	// these, via session.go's rejectShare helper -- ADDITIVE to (never
	// replacing) the existing s.writeShareResponse(id, false, ...)
	// call and the recordShare(false) bookkeeping it already does
	// internally.
	//
	//   - RejectionReasonStaleOrUnknownJob: submit.JobID isn't in
	//     this session's own bounded JobHistory (s.ownJob) -- either
	//     genuinely unknown, or aged out of the ring buffer
	//     (defaultSessionJobHistorySize).
	//   - RejectionReasonJobExpired: job.CreatedAt exceeds the
	//     JobManager's configured JobMaxAge, independent of the ring
	//     buffer.
	//   - RejectionReasonBannedAddress: the submit-time address-flags
	//     re-check (independent of the login-time check, which never
	//     reaches writeShareResponse at all -- see
	//     RejectionReasonOther's doc comment below) found this
	//     session's address newly banned.
	//   - RejectionReasonInvalidXNonce: a SHA3X/C29 submit's nonce
	//     does not start with this session's assigned xn prefix.
	//   - RejectionReasonMalformedNonce: the submit's nonce hex
	//     failed to decode, or decoded to the wrong byte length for
	//     its algo (4/8 bytes RandomX-family, 8 bytes otherwise).
	//   - RejectionReasonInvalidPowShape: a C29 submit's "pow" field
	//     did not carry exactly c29SubmitCycleSize edges.
	//   - RejectionReasonDuplicateNonce: job.MarkNonceUsed reported a
	//     replayed/colliding nonce.
	//   - RejectionReasonMissingClaimedResult: an ALGO_RXM/ALGO_RXT
	//     submit omitted the required claimed "result" hash field.
	//   - RejectionReasonDifficultyFloorMiss: the submit's difficulty
	//     (either the miner's own cheap pre-dispatch CLAIMED value,
	//     or -- RXT/RXM only, leaf-direct-specific, see handleSubmit's
	//     "GENUINE DIFFERENCE FROM leaf-solo" comment -- the REAL,
	//     daemon-confirmed derived value) is below this job's own
	//     configured StaticDifficulty floor.
	//   - RejectionReasonClaimedDifficultyOrCryptoInvalid: either the
	//     cheap pre-dispatch claimed-difficulty/malformed-hex filter
	//     (solo.ClaimedRandomXFamilyDifficulty) rejected the submit
	//     outright, or the real validator ran and reported the share
	//     cryptographically invalid.
	//   - RejectionReasonMalformedSubmitRequest: the submit's wire
	//     params were missing or failed to JSON-unmarshal at all.
	//   - RejectionReasonBlockSubmitFailed: a share that genuinely
	//     cleared network/block difficulty was rejected/failed at
	//     every node this leaf attempted to submit it to.
	//   - RejectionReasonPoolSaturated: the shared randomxPool async
	//     validation pool's bounded queue was full (or the pool was
	//     shutting down) when this RXT/RXM submit tried to dispatch.
	//   - RejectionReasonInternalError: an infrastructure-only
	//     failure unrelated to the miner's own submission validity
	//     (no validator configured for this leaf's algo, a
	//     validator.Validate call itself erroring rather than
	//     returning invalid=false, a difficulty-derivation error, a
	//     Monero verification-blob build error, or an unexpected
	//     internal candidate type).
	//   - RejectionReasonOther: reserved fallback bucket for any
	//     future reject call site added to handleSubmit without an
	//     immediately-obvious existing category -- never emitted by
	//     any call site as of this feature's introduction. NOT used
	//     for "login required before submit": that check runs before
	//     submit params are even parsed and rejects via
	//     writeGeneralResponse (not writeShareResponse), so it never
	//     touches leaf_direct_shares_total{result="rejected"} at all
	//     -- out of scope for a "rejected share" breakdown by
	//     construction (verified by reading handleSubmit; see this
	//     feature's PR description for the full note on this
	//     deliberate deviation from brief_rejection_reasons.md's
	//     initial "not_logged_in" suggestion).
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
// RejectionReason* const above, in the order declared -- used by
// Collect to emit a leaf_direct_share_rejection_reason_per_second
// sample for every reason on every scrape (matching how
// classificationPerSecondDesc's three fixed labels are emitted
// unconditionally above), and by this package's own tests to assert
// no other, unexpected reason value is ever produced.
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

const OtherAddressLabel = "other"

// LoginRejectionReason* label leaf_direct_login_rejections_total
// (DISPATCH_BRIEF.md "login-rejection-reason metrics", Alex: "Can you
// add a metric for rejected logins to see why we're rejecting? I'm
// curious how many of these are just bans we reject.") -- a small,
// FIXED, closed enum covering every real rejection return point in
// session.go's handleLogin/fetchAndDeliverLoginJob, in the order
// they're checked. Mirrors internal/leaflib/solo/metrics's identical
// LoginRejectionReason* consts exactly (see that package's doc
// comment for the full per-value rationale, which applies identically
// here):
//   - LoginRejectionReasonInvalidParams: json.Unmarshal(req.Params,
//     &login) failed.
//   - LoginRejectionReasonEmptyAddress: login.Login == "".
//   - LoginRejectionReasonInvalidAddressFormat:
//     solo.ValidateAddressForAlgo rejects the (already
//     loginfields-parsed) address as malformed for this leaf's
//     configured algo.
//   - LoginRejectionReasonBanned: s.server.addressFlags.Get(...)
//     .Banned is true.
//   - LoginRejectionReasonNoJobTemplate:
//     s.server.jobManager.JobForSessionAtDifficulty failed -- reached from
//     fetchAndDeliverLoginJob (the jobFetchPool-dispatched closure
//     handleLogin's own TrySubmit call defers this same real login
//     rejection to), not handleLogin's own body directly -- see that
//     function's doc comment for why the job fetch runs off
//     Session.Run's read-loop goroutine.
//
// Each site calls Metrics.IncLoginRejectionReason with exactly one of
// these, via server.go's recordLoginRejection helper. Deliberately NOT
// covering solo.ParseLoginFields' own error return, mirroring
// solo/metrics's identical exclusion exactly (see that package's doc
// comment for the rationale).
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

const DefaultMaxAddressLabels = 50

// SessionSnapshot mirrors solo/metrics's own SessionSnapshot exactly.
type SessionSnapshot struct {
	Address    string
	RemoteIP   string
	Difficulty uint64
	// Agent mirrors solo/metrics's own SessionSnapshot.Agent exactly:
	// the real miner software/version string self-reported at login
	// (solo.LoginRequest.Agent), or "" if not logged in / not sent.
	Agent string
	// Hashrate mirrors solo/metrics's own SessionSnapshot.Hashrate
	// exactly: this session's real, per-session estimated hashrate
	// in hashes/second at the moment of the snapshot (see
	// leaflib.EstimateHashrateHz's doc comment for the formula).
	Hashrate float64
}

type SnapshotFunc func() []SessionSnapshot

// ChainHeightFunc is a callback returning the last known chain
// height for a coin/network this leaf talks to, and whether a value
// is actually available yet (see chainheight.Poller.Height's own
// "false means no successful poll yet" contract -- ok=false must
// result in NO Prometheus sample being emitted this scrape, not a 0
// sample). Backs leaf_monero_chain_height / leaf_tari_chain_height
// via SetMoneroChainHeightSource / SetTariChainHeightSource -- a
// single leaf-direct process runs exactly one algo family (Monero or
// Tari), so in practice only one of the two is ever wired by
// server.go's EnableMetrics, but both are independently
// nil-safe/optional at the Metrics level.
type ChainHeightFunc func() (height uint64, ok bool)

// AsyncPoolStats/AsyncPoolStatsFunc mirror solo/metrics's own
// identical types exactly (Fix 9, DISPATCH_BRIEF.md 2026-09-10) --
// leaf-direct shares the exact same solo.AsyncValidationPool
// implementation (see server.go's randomxPool field), so its own
// metrics package needs the exact same snapshot-derived shape.
type AsyncPoolStats struct {
	QueueDepth         int
	InFlightWorkers    int64
	SubmitBlockedTotal uint64
}

type AsyncPoolStatsFunc func() AsyncPoolStats

// RelayStatsFunc is a callback returning a live snapshot of the
// leaf's *relay.Relay observability state (relay.Relay.Stats()) --
// see SetRelaySource. Reusing relay.RelayStats directly (rather than
// re-declaring an equivalent local struct) means this package never
// duplicates the relay package's own counting logic, per this
// feature's explicit design constraint (prefer wiring through
// existing internal state over adding new counters at the call
// site).
type RelayStatsFunc func() relay.RelayStats

// Metrics holds every Prometheus collector leaf-direct registers.
type Metrics struct {
	registry *prometheus.Registry

	SharesTotal           *prometheus.CounterVec
	BlocksTotal           *prometheus.CounterVec
	ConnectionErrorsTotal *prometheus.CounterVec

	// TransportErrorsTotal counts real failures forwarding a validated
	// share/block to the backend over transport.ShareTransport,
	// labeled by kind ("share"/"block"). This is a genuinely NEW
	// observability axis vs. leaf-solo (which has no backend
	// connection at all) — see session.go's forwardShare/forwardBlock.
	TransportErrorsTotal *prometheus.CounterVec

	// XNPReservationUnavailableTotal mirrors solo/metrics's own
	// identical counter exactly (see that package's doc comment) --
	// leaf-direct shares the SAME solo.MoneroNodeClient
	// implementation, so the same real production bug/degradation
	// applies here too.
	XNPReservationUnavailableTotal prometheus.Counter

	// DirectBlockHashUnresolvedTotal counts real ALGO_RXM (Monero)
	// block finds that were genuinely accepted by monerod's own
	// submit_block RPC but whose real, canonical block hash could
	// NOT be confirmed afterward via get_block_header_by_height (RPC
	// failure, empty/non-OK response, or no resolver configured at
	// all -- see server.go's resolveMoneroBlockHash). This is the
	// explicit "fail loudly" signal FIX_BRIEF.md item 3 requires in
	// place of ever silently forwarding a placeholder/empty hash
	// downstream -- a non-zero rate here means real found blocks are
	// NOT being reported to the backend and need manual
	// reconciliation against the real monerod chain.
	DirectBlockHashUnresolvedTotal prometheus.Counter

	// RelayResubmitTotal counts the real OUTCOME of every
	// relay-triggered local resubmission attempt (server.go's
	// handleRelayedBlock, invoked when relay.Relay.Subscribe
	// dispatches a genuinely new found-block message from another
	// instance -- see leaf_relay_block_receive_total for the
	// dispatch-vs-duplicate split at the relay-receive level itself),
	// labeled by result: ResultAccepted (this instance's own
	// MultiNodeSubmitter reported at least one node accepted it),
	// ResultRejected (a real resubmission attempt was made but no
	// configured node accepted it), or ResultNoSubmitter (no
	// MultiNodeSubmitter is configured at all -- resubmission could
	// not even be attempted).
	RelayResubmitTotal *prometheus.CounterVec

	// SharesByClassificationTotal counts every RandomX-family
	// (RXT/RXM) submit that actually reached real-or-skipped
	// validation, labeled by classification (trusted/validated/
	// invalid -- see the Classification* consts above). This is an
	// ADDITIONAL, independent counter mirroring legacy
	// nodejs-pool-sxmr's own 3-way share-classification 30s log line
	// (lib/pool.js) -- it does NOT replace SharesTotal above (that
	// counter's own accepted/rejected split, across every algo, is
	// untouched).
	SharesByClassificationTotal *prometheus.CounterVec

	// ShareRejectionReasonTotal is the real, per-category breakdown
	// of the "rejected" side of SharesTotal (leaf_direct_shares_total
	// {result="rejected"}) -- labeled by reason (see the
	// RejectionReason* consts above). This is the direct fix for
	// brief_rejection_reasons.md's live incident: SharesTotal alone
	// cannot distinguish "a genuine cryptographic/difficulty
	// validation failure" from "a submit that never reached real
	// validation at all" (unknown job_id, expired job, malformed
	// nonce, etc.) -- ADDITIVE to (never replacing) SharesTotal's own
	// existing accepted/rejected split, which is completely
	// unchanged.
	ShareRejectionReasonTotal *prometheus.CounterVec

	// LoginRejectionsTotal is the real, per-category breakdown of
	// every login-time rejection in session.go's
	// handleLogin/fetchAndDeliverLoginJob (see the
	// LoginRejectionReason* consts above) -- DISPATCH_BRIEF.md
	// "login-rejection-reason metrics". Previously EVERY one of
	// these rejection points was log-only, with no counter of any
	// kind.
	LoginRejectionsTotal *prometheus.CounterVec

	// ReloginTotal mirrors internal/leaflib/solo/metrics's identical
	// ReloginTotal exactly -- see that field's own doc comment.
	ReloginTotal prometheus.Counter

	// SubmitProcessingSeconds mirrors internal/leaflib/solo/metrics's
	// identical field exactly (see that field's own doc comment for
	// the full "why a defer alone isn't enough" rationale) -- the one
	// real difference here: leaf-direct's own dispatch decision (see
	// session.go's handleSubmit) sends EVERY RXT/RXM claim that
	// clears the cheap pre-dispatch floor through finishSubmit on
	// s.server.randomxPool asynchronously, not just genuine
	// block-find candidates (leaf-direct forwards every validated
	// share to the backend, not just block-level finds -- see
	// handleSubmit's own "GENUINE DIFFERENCE FROM leaf-solo" doc
	// comment) -- so the same start-time-threaded-into-finishSubmit
	// technique matters for a much larger share of this leaf's real
	// RXT/RXM traffic than it does for leaf-solo's.
	SubmitProcessingSeconds *prometheus.HistogramVec

	// SubmitValidationSeconds mirrors internal/leaflib/solo/metrics's
	// identical field exactly, labeled by algo (see
	// leaflib.AlgoMetricLabel). Deliberately NOT observed for the
	// trusted-miner validation-skip branch (Server.EnableTrust,
	// s.trust.ShouldSkipValidation -- UNLIKE solo, leaf-direct still
	// wires this mechanism -- see finishSubmit's own doc comment):
	// that path genuinely does zero validation work, so a near-zero
	// sample there would be misleading noise, not a real signal.
	SubmitValidationSeconds *prometheus.HistogramVec

	// TemplateDistributionDuration observes the real wall-clock time
	// (seconds) Server.invalidateAndRepushJobs spends iterating every
	// connected session and pushing a freshly regenerated job, labeled
	// by source ("local" = this leaf's own upstream tip-poll/periodic
	// refresh found the new template; "relay" = the new template was
	// learned via the NATS template relay from ANOTHER leaf-direct/
	// leaf-solo instance and is now being distributed to THIS
	// instance's own miner sessions) -- mirrors legacy
	// nodejs-pool-sxmr's own per-new-block-template log line
	// (lib/pool.js: "Block template distribution took ${...}
	// miliseconds for ${minerCount} miners for blockID: ${height}").
	TemplateDistributionDuration *prometheus.HistogramVec

	// TemplateDistributionMiners is the real count of sessions
	// ACTUALLY pushed a fresh job during that same
	// invalidateAndRepushJobs pass (not the total connection count --
	// see leaf_direct_active_connections for that -- and not sessions
	// skipped via the not-logged-in/regeneration-error/
	// already-delivered continues), labeled by the same source value
	// as TemplateDistributionDuration -- mirrors the legacy log
	// line's own minerCount semantics exactly.
	TemplateDistributionMiners *prometheus.GaugeVec

	BuildInfo *prometheus.GaugeVec

	// sharesRate/blocksRate/classificationRate/rejectionReasonRate
	// back leaf_direct_shares_per_second/leaf_direct_blocks_per_second/
	// leaf_direct_shares_by_classification_per_second/
	// leaf_direct_share_rejection_reason_per_second (see Collect) --
	// a 60s-rolling-window per-second rate of SharesTotal/
	// BlocksTotal/SharesByClassificationTotal/
	// ShareRejectionReasonTotal, additive to those counters (which
	// remain completely unchanged). One shared.RateTracker per label
	// combination, created lazily by
	// IncShareResult/IncBlockResult/IncShareClassification/
	// IncShareRejectionReason below at the exact same real
	// accept/reject/classification/rejection-reason branch points
	// server.go's recordShare/recordBlock/recordShareClassification/
	// recordShareRejectionReason already call.
	sharesRate          *shared.LabeledRateTrackers
	blocksRate          *shared.LabeledRateTrackers
	classificationRate  *shared.LabeledRateTrackers
	rejectionReasonRate *shared.LabeledRateTrackers

	maxAddressLabels int
	snapshot         SnapshotFunc
	asyncPoolStats   AsyncPoolStatsFunc
	relayStats       RelayStatsFunc

	// moneroChainHeight/tariChainHeight back
	// leaf_monero_chain_height/leaf_tari_chain_height -- see
	// ChainHeightFunc's doc comment and SetMoneroChainHeightSource/
	// SetTariChainHeightSource.
	moneroChainHeight ChainHeightFunc
	tariChainHeight   ChainHeightFunc
}

// New constructs a Metrics using a fresh, private *prometheus.Registry.
func New(version string, maxAddressLabels int) *Metrics {
	if maxAddressLabels <= 0 {
		maxAddressLabels = DefaultMaxAddressLabels
	}
	reg := prometheus.NewRegistry()
	// Standard Go runtime/process collectors -- see
	// internal/leaflib/solo/metrics.New's identical registration for
	// the full rationale (private registry, not the global default
	// one client_golang auto-registers these onto). MustRegister:
	// only ever registered once per New() call.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := &Metrics{registry: reg, maxAddressLabels: maxAddressLabels}

	m.SharesTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_shares_total",
		Help: "Total number of shares submitted to this leaf-direct instance, by result (accepted/rejected).",
	}, []string{"result"})

	m.BlocksTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_blocks_total",
		Help: "Total number of blocks found/submitted by this leaf-direct instance, by result (accepted/rejected).",
	}, []string{"result"})

	m.ConnectionErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_connection_errors_total",
		Help: "Total number of miner connections that ended in an error/non-graceful category.",
	}, []string{"category"})

	m.TransportErrorsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_transport_errors_total",
		Help: "Total number of failures forwarding a validated share/block to the backend over the ShareTransport, by kind (share/block).",
	}, []string{"kind"})

	m.XNPReservationUnavailableTotal = registerCounter(reg, prometheus.CounterOpts{
		Name: "leaf_direct_xnp_reservation_unavailable_total",
		Help: "Total number of Monero get_block_template responses whose real reserved_offset did not fit within the returned blocktemplate_blob, causing the XNP-proxy-shape job fields (reserved_offset/client_nonce_offset/client_pool_offset/blocktemplate_blob) to be omitted for that job rather than published out-of-bounds.",
	})

	m.DirectBlockHashUnresolvedTotal = registerCounter(reg, prometheus.CounterOpts{
		Name: "leaf_direct_block_hash_unresolved_total",
		Help: "Total number of real ALGO_RXM (Monero) block finds accepted by submit_block whose real canonical block hash could not be confirmed via get_block_header_by_height afterward -- these are NOT forwarded to the backend (no placeholder hash is ever substituted) and need manual reconciliation.",
	})

	m.RelayResubmitTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_relay_resubmit_total",
		Help: "Total number of relay-triggered local block resubmission attempts (a genuinely new found-block message received from another leaf-direct instance via the NATS relay), by outcome (accepted/rejected/no_submitter).",
	}, []string{"result"})

	m.SharesByClassificationTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_shares_by_classification_total",
		Help: "Total number of RandomX-family (RXT/RXM) submits that reached real-or-skipped validation, by 3-way classification (trusted/validated/invalid), mirroring legacy nodejs-pool-sxmr's (lib/pool.js) own 30s 'Trusted/Validated/Invalid/Total shares' log line -- total is deliberately not re-derived here since it is always the redundant sum of the other three. This is an additional, independent counter; it does not replace leaf_direct_shares_total's own accepted/rejected split.",
	}, []string{"classification"})

	m.ShareRejectionReasonTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_share_rejection_reason_total",
		Help: "Real, per-category breakdown of the 'rejected' side of leaf_direct_shares_total, by reason (see the direct/metrics package's RejectionReason* consts for the full, closed enum and the exact handleSubmit call site each one maps to). Additive to leaf_direct_shares_total's own accepted/rejected split, which remains completely unchanged.",
	}, []string{"reason"})

	m.LoginRejectionsTotal = registerCounterVec(reg, prometheus.CounterOpts{
		Name: "leaf_direct_login_rejections_total",
		Help: "Real, per-category breakdown of every login-time rejection in session.go's handleLogin/fetchAndDeliverLoginJob (see this package's LoginRejectionReason* consts for the full, closed enum and the exact call site each one maps to) -- previously every one of these rejection points was log-only, with no counter of any kind.",
	}, []string{"reason"})

	m.ReloginTotal = registerCounter(reg, prometheus.CounterOpts{
		Name: "leaf_relogin_total",
		Help: "Total number of real re-login events detected in session.go's handleLogin: a session receiving a second (or Nth) login message on an already-logged-in connection (e.g. an xmrig-proxy --reuse-timeout connection-reuse slot rotation). Incremented once per re-login event, not once per login overall.",
	})

	// leaf_direct_submit_processing_seconds' bucket boundaries:
	// prometheus.DefBuckets (5ms..10s). This tail is genuinely more
	// likely to be exercised here than on leaf-solo's identically-
	// bucketed metric (see SubmitProcessingSeconds' own doc comment):
	// EVERY RXT/RXM submit that clears the cheap pre-dispatch floor
	// -- not just genuine block finds -- pays the real
	// randomx-service HTTP round-trip (~4ms+, see asyncvalidation.go)
	// plus, on the block-find path, the further multi-node GRPC
	// submit/NATS relay publish span. DefBuckets' 10s ceiling still
	// comfortably covers this in normal operation; kept rather than a
	// bespoke set, matching TemplateDistributionDuration's own
	// precedent.
	m.SubmitProcessingSeconds = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "leaf_direct_submit_processing_seconds",
		Help:    "Real, end-to-end wall-clock seconds of session.go's handleSubmit, from entry to the point the response is written to the miner, by result (accepted/rejected). Includes early-exit rejections (e.g. login required before submit). Buckets: prometheus.DefBuckets.",
		Buckets: prometheus.DefBuckets,
	}, []string{"result"})

	// leaf_direct_submit_validation_seconds' bucket boundaries: also
	// prometheus.DefBuckets -- see SubmitProcessingSeconds' own doc
	// comment above; this metric's real observed values are a strict
	// subset of that one's (only the v.Validate call itself), so the
	// same ceiling applies with even more headroom.
	m.SubmitValidationSeconds = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "leaf_direct_submit_validation_seconds",
		Help:    "Real wall-clock seconds spent specifically inside the real PoW validator call (v.Validate) in session.go's finishSubmit, by algo (sha3x/c29/rxt/rxm -- see leaflib.AlgoMetricLabel). Never observed for the trusted-miner validation-skip branch (Server.EnableTrust) -- that path genuinely does zero validation work. Buckets: prometheus.DefBuckets.",
		Buckets: prometheus.DefBuckets,
	}, []string{"algo"})

	// leaf_direct_template_distribution_seconds' bucket boundaries:
	// prometheus.DefBuckets (5ms..10s) tops out at 10s, which is
	// coarse for this leaf's typical sub-second-to-few-second
	// push-loop latencies but still usable -- kept (rather than a
	// bespoke set) since it is the standard, well-understood
	// Prometheus default every other histogram-shaped metric an
	// operator is likely to already be scraping elsewhere uses, and
	// this metric has no unusual latency profile (no multi-second
	// tail expected in normal operation) that would justify
	// diverging from it.
	m.TemplateDistributionDuration = registerHistogramVec(reg, prometheus.HistogramOpts{
		Name:    "leaf_direct_template_distribution_seconds",
		Help:    "Real wall-clock seconds Server.invalidateAndRepushJobs spent iterating every connected session and pushing a freshly regenerated job, by source (local = this leaf's own tip-poll/periodic-refresh found the new template; relay = the new template was learned via the NATS template relay from another leaf-direct/leaf-solo instance). Buckets: prometheus.DefBuckets (standard, well-understood default; no unusual latency profile expected). Mirrors legacy nodejs-pool-sxmr's (lib/pool.js) own per-new-block-template 'Block template distribution took ... miliseconds' log line.",
		Buckets: prometheus.DefBuckets,
	}, []string{"source"})

	m.TemplateDistributionMiners = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_direct_template_distribution_miners",
		Help: "Real count of sessions actually pushed a fresh job during the most recent invalidateAndRepushJobs pass (not the total connection count -- see leaf_direct_active_connections -- and not sessions skipped via not-logged-in/regeneration-error/already-delivered), by source (local/relay -- see leaf_direct_template_distribution_seconds). Mirrors legacy nodejs-pool-sxmr's own per-new-block-template log line's minerCount semantics exactly.",
	}, []string{"source"})

	m.BuildInfo = registerGaugeVec(reg, prometheus.GaugeOpts{
		Name: "leaf_direct_build_info",
		Help: "Always 1; version label carries the running build's version string.",
	}, []string{"version"})
	m.BuildInfo.WithLabelValues(version).Set(1)

	m.sharesRate = shared.NewLabeledRateTrackers()
	m.blocksRate = shared.NewLabeledRateTrackers()
	m.classificationRate = shared.NewLabeledRateTrackers()
	m.rejectionReasonRate = shared.NewLabeledRateTrackers()

	if err := reg.Register(m); err != nil {
		log.Printf("metrics: failed to register leaf-direct snapshot collector: %v", err)
	}

	return m
}

func (m *Metrics) SetSnapshotSource(fn SnapshotFunc) {
	m.snapshot = fn
}

// SetAsyncPoolSource mirrors solo/metrics's own identical method
// exactly -- see AsyncPoolStats' doc comment.
func (m *Metrics) SetAsyncPoolSource(fn AsyncPoolStatsFunc) {
	m.asyncPoolStats = fn
}

// SetRelaySource wires this leaf's *relay.Relay observability state
// into the Collect() below -- see RelayStatsFunc's doc comment. A nil
// fn (never set, e.g. an older caller predating this feature) means
// Collect emits no relay_* metric samples at all, matching this
// feature's "zero-cost/zero-registration when relay disabled"
// contract exactly at the collector level, not just the counter
// level.
func (m *Metrics) SetRelaySource(fn RelayStatsFunc) {
	m.relayStats = fn
}

// SetMoneroChainHeightSource wires leaf_monero_chain_height's data
// source (see ChainHeightFunc's doc comment) -- server.go's
// EnableMetrics calls this only when this leaf is actually running a
// Monero-family algo (IsMoneroFamilyAlgo), so a Tari-family leaf
// never even wires this and the metric is simply absent from its
// scrape output.
func (m *Metrics) SetMoneroChainHeightSource(fn ChainHeightFunc) {
	m.moneroChainHeight = fn
}

// SetTariChainHeightSource is SetMoneroChainHeightSource's
// leaf_tari_chain_height analogue, wired instead when this leaf is
// running a Tari-family algo.
func (m *Metrics) SetTariChainHeightSource(fn ChainHeightFunc) {
	m.tariChainHeight = fn
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// IncShareResult increments SharesTotal for result (see ResultLabel)
// AND records the same increment for that result's rolling-window
// per-second rate (leaf_direct_shares_per_second, see Collect) --
// callers (server.go's recordShare) must call this INSTEAD OF
// touching SharesTotal directly, so the two never drift out of
// lockstep.
func (m *Metrics) IncShareResult(result string) {
	m.SharesTotal.WithLabelValues(result).Inc()
	m.sharesRate.Inc(result)
}

// IncBlockResult is IncShareResult's BlocksTotal/
// leaf_direct_blocks_per_second analogue.
func (m *Metrics) IncBlockResult(result string) {
	m.BlocksTotal.WithLabelValues(result).Inc()
	m.blocksRate.Inc(result)
}

// IncShareClassification is IncShareResult's
// SharesByClassificationTotal/
// leaf_direct_shares_by_classification_per_second analogue.
func (m *Metrics) IncShareClassification(classification string) {
	m.SharesByClassificationTotal.WithLabelValues(classification).Inc()
	m.classificationRate.Inc(classification)
}

// IncShareRejectionReason is IncShareResult's ShareRejectionReasonTotal/
// leaf_direct_share_rejection_reason_per_second analogue -- callers
// (server.go's recordShareRejectionReason, itself called from
// session.go's rejectShare helper at every real pre-validation-and-
// beyond reject call site) must call this INSTEAD OF touching
// ShareRejectionReasonTotal directly, so the two never drift out of
// lockstep. See the RejectionReason* consts' doc comment for the
// full, closed enum this reason must be one of.
func (m *Metrics) IncShareRejectionReason(reason string) {
	m.ShareRejectionReasonTotal.WithLabelValues(reason).Inc()
	m.rejectionReasonRate.Inc(reason)
}

// IncLoginRejectionReason bumps LoginRejectionsTotal for reason (one
// of LoginRejectionReason* above) -- callers (server.go's
// recordLoginRejection) must call this INSTEAD OF touching
// LoginRejectionsTotal directly. Mirrors
// internal/leaflib/solo/metrics's identical IncLoginRejectionReason
// exactly -- no accompanying per-second rate gauge, deliberately
// (see that package's doc comment for the rationale).
func (m *Metrics) IncLoginRejectionReason(reason string) {
	m.LoginRejectionsTotal.WithLabelValues(reason).Inc()
}

// IncRelogin mirrors internal/leaflib/solo/metrics's identical
// IncRelogin exactly.
func (m *Metrics) IncRelogin() {
	m.ReloginTotal.Inc()
}

// Stop releases the background ticker goroutines backing
// sharesRate/blocksRate/classificationRate/rejectionReasonRate's
// lazily-created shared.RateTracker instances (see
// shared.RateTracker.Stop's own doc comment -- safe to call even if
// some/all label combinations were never incremented, since Stop
// only iterates trackers that actually got lazily created). Callers
// (server.go's Shutdown) should call this from the owning Server's
// own shutdown path; a Metrics never explicitly Stop()'d simply
// keeps its trackers' goroutines alive for the process lifetime,
// which is fine for the normal one-Metrics-per-process production
// case (mirrors solo.AsyncValidationPool.Stop's identical "optional
// for a process-lifetime singleton" convention).
func (m *Metrics) Stop() {
	m.sharesRate.Stop()
	m.blocksRate.Stop()
	m.classificationRate.Stop()
	m.rejectionReasonRate.Stop()
}

var (
	activeConnectionsDesc = prometheus.NewDesc(
		"leaf_direct_active_connections",
		"Current number of active miner connections.",
		nil, nil,
	)
	uniqueRemoteIPsDesc = prometheus.NewDesc(
		"leaf_direct_unique_remote_ips_gauge",
		"Current number of distinct remote IPs among active miner connections.",
		nil, nil,
	)
	minersByAddressDesc = prometheus.NewDesc(
		"leaf_direct_miners_by_address",
		"Current number of connected sessions per mining/payout address (capped cardinality).",
		[]string{"address"}, nil,
	)
	// minerHashrateByAddressDesc mirrors solo/metrics's own
	// minerHashrateByAddressDesc exactly (same real per-session
	// leaflib.EstimateHashrateHz estimate, summed per address,
	// capped identically to minersByAddressDesc above via
	// CapAddressHashrates).
	minerHashrateByAddressDesc = prometheus.NewDesc(
		"leaf_direct_miner_hashrate_hash_per_second",
		"Real, per-address SUM of currently-connected sessions' estimated hashrate in hashes/second (see leaflib.EstimateHashrateHz's doc comment for the difficulty/time estimation formula). Same capped cardinality as leaf_direct_miners_by_address; overflow aggregated into address=\"other\".",
		[]string{"address"}, nil,
	)

	// totalHashrateDesc backs leaf_direct_total_hashrate_hash_per_second
	// -- a deliberately LOW-CARDINALITY (no address label) gauge
	// reporting the TRUE total estimated hashrate across every
	// currently-connected session on this leaf-direct process,
	// computed by Collect DIRECTLY from the live snapshot (summing
	// every SessionSnapshot.Hashrate), completely independently of
	// minerHashrateByAddressDesc/addrHashrates/CapAddressHashrates
	// above.
	//
	// Why this is needed (Alex, pool operator: "we only return the
	// top 50 miners by connection, so sum() doesn't even work" when
	// trying to build a leaf-wide total-hashrate panel from
	// leaf_direct_miner_hashrate_hash_per_second for the Zabbix ->
	// Grafana migration): investigation of this exact codebase found
	// the root cause is NEITHER of the two most obvious hypotheses --
	//
	//   (a) NOT the snapshot itself: server.go's sessionSnapshots
	//       iterates s.sessions in full and returns EVERY currently-
	//       connected session, with no top-N-by-connection (or
	//       top-N-by-anything) truncation before Collect ever sees
	//       it. addrHashrates below is built by summing ALL of those
	//       snapshots' Hashrate by address -- not a top-N subset.
	//   (b) NOT a bug in CapAddressHashrates/CapAddressCounts: both
	//       correctly fold every address beyond the kept top
	//       (maxAddressLabels-1) into a single address="other"
	//       bucket whose value IS the true, exact sum of that
	//       overflow (see those functions' own otherTotal
	//       accumulation) -- so a bare, unfiltered
	//       sum(leaf_direct_miner_hashrate_hash_per_second) already
	//       mathematically equals the true total INCLUDING the
	//       "other" bucket.
	//
	// The real, practical problem is that leaf_direct_miner_hashrate
	// _hash_per_second is fundamentally an address-cardinality-capped
	// metric BY DESIGN (necessary to keep Prometheus label
	// cardinality bounded on a pool with far more than
	// maxAddressLabels distinct payout addresses at any moment): (1)
	// which specific ~49 addresses are "kept" vs. folded into
	// "other" is independently re-sorted by current hashrate on
	// EVERY scrape, so per-address time series for anything outside
	// the top set churns in and out of existence, is not durable
	// across scrapes, and any dashboard panel/query that filters or
	// groups by a specific address (rather than blindly summing
	// every label value including "other") silently undercounts;
	// and (2) operators (reasonably) do not expect a per-address
	// gauge's "other" catch-all bucket to be the one series that
	// makes their sum() correct, so in practice queries built against
	// this metric for a leaf-wide total have consistently omitted
	// it. This new gauge sidesteps all of that by never going
	// through the capped/bucketed per-address map at all.
	totalHashrateDesc = prometheus.NewDesc(
		"leaf_direct_total_hashrate_hash_per_second",
		"Real, TRUE total estimated hashrate (hashes/second) across ALL currently-connected sessions on this leaf-direct process, computed by summing every session's leaflib.EstimateHashrateHz result directly from the live snapshot -- independent of, and unaffected by, leaf_direct_miner_hashrate_hash_per_second's per-address cardinality cap. Use this metric (not sum() over the per-address one) for any leaf-wide or fleet-wide total-hashrate panel/alert.",
		nil, nil,
	)

	// moneroChainHeightDesc/tariChainHeightDesc back
	// leaf_monero_chain_height/leaf_tari_chain_height -- the
	// Zabbix-to-Grafana dashboard migration's chain-height gap (the
	// legacy dashboard sourced these via a per-host Zabbix
	// UserParameter script hitting monerod/tari_mm_daemon RPC
	// directly; this is the first Prometheus exposition of either
	// value anywhere in this codebase). Values come from a
	// chainheight.Poller wrapping this leaf's own solo.NodeClient
	// (see SetMoneroChainHeightSource/SetTariChainHeightSource) --
	// never a direct RPC/GRPC call made at scrape time.
	moneroChainHeightDesc = prometheus.NewDesc(
		"leaf_monero_chain_height",
		"Current Monero (RXM) chain height as last reported by this leaf's own monerod connection's get_info RPC, polled and cached on a background interval (see chainheight.Poller) -- not queried live on every scrape. Absent when this leaf is not running a Monero-family algo, or when no poll has ever succeeded yet.",
		nil, nil,
	)
	tariChainHeightDesc = prometheus.NewDesc(
		"leaf_tari_chain_height",
		"Current Tari base-layer chain height as last reported by this leaf's own Tari base-node connection's GetTipInfo GRPC call, polled and cached on a background interval (see chainheight.Poller) -- not queried live on every scrape. Absent when this leaf is not running a Tari-family algo, or when no poll has ever succeeded yet.",
		nil, nil,
	)

	// asyncPool*Desc mirrors solo/metrics's own identical Desc vars
	// exactly, INCLUDING the deliberately mode-agnostic
	// "leaf_async_validation_*" naming (not "leaf_direct_*") -- see
	// that package's doc comment on these vars for why: this is the
	// exact same shared solo.AsyncValidationPool component, and each
	// leaf mode's own private registry never collides with the
	// others' (one leaf mode per process).
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

	// relay* Desc vars mirror asyncPool*Desc's own "mode-agnostic
	// leaf_relay_* naming, not leaf_direct_*" convention exactly --
	// see that block's own doc comment for why: relay.Relay is a
	// shared component (internal/leaflib/relay, also used by
	// internal/leaflib/solo's JobManager for the template relay, see
	// that package's job.go), so its own observability data is named
	// mode-agnostically even though today only leaf-direct's Server
	// actually wires SetRelaySource. Values come STRAIGHT from
	// relay.Relay.Stats() (see RelayStatsFunc) -- this package never
	// re-counts relay activity itself, only republishes the relay
	// package's own real counters as Prometheus samples.
	relayBlockPublishTotalDesc = prometheus.NewDesc(
		"leaf_relay_block_publish_total",
		"Total number of found-block messages this instance's relay.Relay has published on the NATS found-block relay subject, by result (success/error). Absent entirely when no relay source is wired (see Metrics.SetRelaySource); always 0 when the relay is disabled/unconfigured (-relay-nats-url empty).",
		[]string{"result"}, nil,
	)
	relayBlockReceiveTotalDesc = prometheus.NewDesc(
		"leaf_relay_block_receive_total",
		"Total number of found-block messages this instance's relay.Relay has received from ANOTHER instance on the NATS found-block relay subject (never counts this instance's own publishes -- relay.Relay.Subscribe already filters those out), by result (dispatched = triggered local resubmission / duplicate = already-seen redelivery, skipped). See leaf_direct_relay_resubmit_total for the resubmission attempt's own success/fail outcome.",
		[]string{"result"}, nil,
	)
	relayTemplatePublishTotalDesc = prometheus.NewDesc(
		"leaf_relay_template_publish_total",
		"Total number of new-tip template messages this instance's relay.Relay has published on the NATS template-relay subject, by result (success/error).",
		[]string{"result"}, nil,
	)
	relayTemplateReceiveTotalDesc = prometheus.NewDesc(
		"leaf_relay_template_receive_total",
		"Total number of new-tip template messages this instance's relay.Relay has received from ANOTHER instance on the NATS template-relay subject (never counts this instance's own publishes), by result (dispatched = triggered a real per-xn job cache invalidation / duplicate = already-seen redelivery, skipped).",
		[]string{"result"}, nil,
	)
	relayConnectedDesc = prometheus.NewDesc(
		"leaf_relay_connected",
		"1 if this instance's relay.Relay is CURRENTLY connected to NATS, 0 otherwise -- including whenever the relay is disabled/unconfigured, or mid-reconnect after a transient disconnect. Distinct from whether the relay is merely configured (see relay.Relay.Enabled(), which stays effectively true across a transient reconnect).",
		nil, nil,
	)
	relayLastBlockPublishDesc = prometheus.NewDesc(
		"leaf_relay_last_block_publish_unixtime",
		"Unix timestamp (seconds) of this instance's most recent successful found-block relay publish. Absent/0 if this instance has never published one.",
		nil, nil,
	)
	relayLastBlockReceiveDesc = prometheus.NewDesc(
		"leaf_relay_last_block_receive_unixtime",
		"Unix timestamp (seconds) of this instance's most recent genuinely-new (non-duplicate) found-block relay receive from another instance. Absent/0 if this instance has never received one.",
		nil, nil,
	)
	relayLastTemplatePublishDesc = prometheus.NewDesc(
		"leaf_relay_last_template_publish_unixtime",
		"Unix timestamp (seconds) of this instance's most recent successful template-relay publish. Absent/0 if this instance has never published one.",
		nil, nil,
	)
	relayLastTemplateReceiveDesc = prometheus.NewDesc(
		"leaf_relay_last_template_receive_unixtime",
		"Unix timestamp (seconds) of this instance's most recent genuinely-new (non-duplicate) template-relay receive from another instance. Absent/0 if this instance has never received one.",
		nil, nil,
	)

	// *PerSecondDesc: additive 60s-rolling-window per-second rate
	// gauges (see shared.RateTracker) mirroring their corresponding
	// _total counter's exact label set -- the existing _total
	// counters (SharesTotal/BlocksTotal/SharesByClassificationTotal)
	// remain completely unchanged; some dashboards/alerting may
	// already correctly apply rate()/irate() against them.
	sharesPerSecondDesc = prometheus.NewDesc(
		"leaf_direct_shares_per_second",
		"Real, leaf-computed 60-second-rolling-window per-second rate of leaf_direct_shares_total, by result (accepted/rejected) -- computed directly by this leaf (see shared.RateTracker) rather than relying on a dashboard panel applying rate()/irate() against the _total counter itself.",
		[]string{"result"}, nil,
	)
	blocksPerSecondDesc = prometheus.NewDesc(
		"leaf_direct_blocks_per_second",
		"Real, leaf-computed 60-second-rolling-window per-second rate of leaf_direct_blocks_total, by result (accepted/rejected).",
		[]string{"result"}, nil,
	)
	classificationPerSecondDesc = prometheus.NewDesc(
		"leaf_direct_shares_by_classification_per_second",
		"Real, leaf-computed 60-second-rolling-window per-second rate of leaf_direct_shares_by_classification_total, by classification (trusted/validated/invalid).",
		[]string{"classification"}, nil,
	)
	rejectionReasonPerSecondDesc = prometheus.NewDesc(
		"leaf_direct_share_rejection_reason_per_second",
		"Real, leaf-computed 60-second-rolling-window per-second rate of leaf_direct_share_rejection_reason_total, by reason (see the RejectionReason* consts for the full, closed enum).",
		[]string{"reason"}, nil,
	)
)

func ResultLabel(accepted bool) string {
	if accepted {
		return ResultAccepted
	}
	return ResultRejected
}

func (m *Metrics) Describe(_ chan<- *prometheus.Desc) {}

func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	var snaps []SessionSnapshot
	if m.snapshot != nil {
		snaps = m.snapshot()
	}

	ch <- prometheus.MustNewConstMetric(activeConnectionsDesc, prometheus.GaugeValue, float64(len(snaps)))

	ipSet := make(map[string]struct{}, len(snaps))
	addrCounts := make(map[string]int)
	addrHashrates := make(map[string]float64)
	var totalHashrate float64
	for _, s := range snaps {
		if s.RemoteIP != "" {
			ipSet[s.RemoteIP] = struct{}{}
		}
		if s.Address != "" {
			addrCounts[s.Address]++
			addrHashrates[s.Address] += s.Hashrate
		}
		// totalHashrate sums EVERY session's estimated hashrate,
		// including sessions with no address yet (not logged in) --
		// deliberately NOT gated on s.Address != "" like
		// addrCounts/addrHashrates above, and computed straight from
		// snaps rather than derived from addrHashrates, so it is
		// never affected by CapAddressHashrates' per-address
		// cardinality cap below (see totalHashrateDesc's doc comment
		// for the full root-cause rationale).
		totalHashrate += s.Hashrate
	}

	ch <- prometheus.MustNewConstMetric(uniqueRemoteIPsDesc, prometheus.GaugeValue, float64(len(ipSet)))
	ch <- prometheus.MustNewConstMetric(totalHashrateDesc, prometheus.GaugeValue, totalHashrate)

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

	// Chain height: each is independently nil-safe/optional (see
	// SetMoneroChainHeightSource/SetTariChainHeightSource), and each
	// emits NO sample at all when the source is wired but hasn't
	// completed a successful poll yet (ok=false) -- never a
	// misleading 0.
	if m.moneroChainHeight != nil {
		if h, ok := m.moneroChainHeight(); ok {
			ch <- prometheus.MustNewConstMetric(moneroChainHeightDesc, prometheus.GaugeValue, float64(h))
		}
	}
	if m.tariChainHeight != nil {
		if h, ok := m.tariChainHeight(); ok {
			ch <- prometheus.MustNewConstMetric(tariChainHeightDesc, prometheus.GaugeValue, float64(h))
		}
	}

	// Relay metrics: emitted ONLY when a source has been wired (see
	// SetRelaySource) -- an unwired Metrics (no relay feature at all,
	// e.g. an older caller) emits nothing here, not even zero
	// samples. When wired but the relay itself is disabled
	// (-relay-nats-url empty), relay.Relay.Stats() is the permanent
	// zero RelayStats{} (see that method's doc comment), so every
	// counter below reports 0 and leaf_relay_connected reports 0 --
	// this is the "stays at zero" half of this feature's
	// zero-cost-when-disabled contract (see relay_test.go's
	// TestMetricsRelayDisabledReportsZero).
	if m.relayStats != nil {
		rs := m.relayStats()
		ch <- prometheus.MustNewConstMetric(relayBlockPublishTotalDesc, prometheus.CounterValue, float64(rs.BlockPublishSuccess), ResultSuccess)
		ch <- prometheus.MustNewConstMetric(relayBlockPublishTotalDesc, prometheus.CounterValue, float64(rs.BlockPublishError), ResultError)
		ch <- prometheus.MustNewConstMetric(relayBlockReceiveTotalDesc, prometheus.CounterValue, float64(rs.BlockReceiveDispatched), ResultDispatched)
		ch <- prometheus.MustNewConstMetric(relayBlockReceiveTotalDesc, prometheus.CounterValue, float64(rs.BlockReceiveDuplicate), ResultDuplicate)

		ch <- prometheus.MustNewConstMetric(relayTemplatePublishTotalDesc, prometheus.CounterValue, float64(rs.TemplatePublishSuccess), ResultSuccess)
		ch <- prometheus.MustNewConstMetric(relayTemplatePublishTotalDesc, prometheus.CounterValue, float64(rs.TemplatePublishError), ResultError)
		ch <- prometheus.MustNewConstMetric(relayTemplateReceiveTotalDesc, prometheus.CounterValue, float64(rs.TemplateReceiveDispatched), ResultDispatched)
		ch <- prometheus.MustNewConstMetric(relayTemplateReceiveTotalDesc, prometheus.CounterValue, float64(rs.TemplateReceiveDuplicate), ResultDuplicate)

		connected := 0.0
		if rs.Connected {
			connected = 1.0
		}
		ch <- prometheus.MustNewConstMetric(relayConnectedDesc, prometheus.GaugeValue, connected)

		ch <- prometheus.MustNewConstMetric(relayLastBlockPublishDesc, prometheus.GaugeValue, unixSecondsOrZero(rs.LastBlockPublish))
		ch <- prometheus.MustNewConstMetric(relayLastBlockReceiveDesc, prometheus.GaugeValue, unixSecondsOrZero(rs.LastBlockReceive))
		ch <- prometheus.MustNewConstMetric(relayLastTemplatePublishDesc, prometheus.GaugeValue, unixSecondsOrZero(rs.LastTemplatePublish))
		ch <- prometheus.MustNewConstMetric(relayLastTemplateReceiveDesc, prometheus.GaugeValue, unixSecondsOrZero(rs.LastTemplateReceive))
	}

	ch <- prometheus.MustNewConstMetric(sharesPerSecondDesc, prometheus.GaugeValue, m.sharesRate.Rate(ResultAccepted), ResultAccepted)
	ch <- prometheus.MustNewConstMetric(sharesPerSecondDesc, prometheus.GaugeValue, m.sharesRate.Rate(ResultRejected), ResultRejected)

	ch <- prometheus.MustNewConstMetric(blocksPerSecondDesc, prometheus.GaugeValue, m.blocksRate.Rate(ResultAccepted), ResultAccepted)
	ch <- prometheus.MustNewConstMetric(blocksPerSecondDesc, prometheus.GaugeValue, m.blocksRate.Rate(ResultRejected), ResultRejected)

	ch <- prometheus.MustNewConstMetric(classificationPerSecondDesc, prometheus.GaugeValue, m.classificationRate.Rate(ClassificationTrusted), ClassificationTrusted)
	ch <- prometheus.MustNewConstMetric(classificationPerSecondDesc, prometheus.GaugeValue, m.classificationRate.Rate(ClassificationValidated), ClassificationValidated)
	ch <- prometheus.MustNewConstMetric(classificationPerSecondDesc, prometheus.GaugeValue, m.classificationRate.Rate(ClassificationInvalid), ClassificationInvalid)

	for _, reason := range AllRejectionReasons {
		ch <- prometheus.MustNewConstMetric(rejectionReasonPerSecondDesc, prometheus.GaugeValue, m.rejectionReasonRate.Rate(reason), reason)
	}
}

// unixSecondsOrZero returns t's Unix-seconds value, or 0 for the zero
// time.Time (see relay.RelayStats' own doc comment on why "never"
// is represented as the zero time rather than the Unix epoch
// internally -- this is the one place that gets converted back to a
// bare float64 for the Prometheus gauge sample, where 0 is the
// correct, conventional "no value yet" representation).
func unixSecondsOrZero(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}

// CapAddressCounts mirrors solo/metrics's own CapAddressCounts exactly.
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

	keepN := max - 1
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

// CapAddressHashrates mirrors solo/metrics's own CapAddressHashrates
// exactly (the float64 analogue of CapAddressCounts).
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

// RemoteIPOf mirrors solo/metrics's own RemoteIPOf exactly.
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

// registerCounter mirrors solo/metrics's own identical helper exactly,
// for a plain (unlabeled) prometheus.Counter.
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
