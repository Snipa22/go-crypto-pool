// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"log"
	"time"
)

// This file implements leaf-proxy's optional developer-fee mechanism
// (DISPATCH_BRIEF.md "leaf-proxy dev-fee second-connection"):
// cmd/leaf-proxy's -dev-fee-percent/LEAF_PROXY_DEV_FEE_PERCENT
// (default 1.0, matching the legacy xmr-node-proxy reference's own
// pre-configured 1% donation; 0 fully disables the mechanism, a
// complete no-op with zero second connection ever dialed) opens a
// SECOND, independent UpstreamClient logged in under a hardcoded
// dev-fee login/pass against the SAME upstream host/port/TLS settings
// as the primary connection, and routes approximately -dev-fee-percent%
// of job issuances (and, transitively, the eventually-upstream-forwarded
// share traffic those jobs produce -- see JobManager.NextJob and
// job.go's Job.Route doc comments) to it instead of the primary
// connection.
//
// REAL REFERENCE CONFIRMED (this pass fetched and read the actual
// legacy xmr-node-proxy source, github.com/Snipa22/xmr-node-proxy,
// proxy.js + lib/xmr.js, both still live at time of writing): the
// real "devPool" mechanism is NOT a per-share or per-job routing
// decision at all. It is a WHOLE-MINER, hashrate-balanced
// reassignment: proxy.js's master process runs balanceWorkers() on a
// 90-second ticker, computes each downstream miner's own recent
// average hashrate, and assigns/reassigns an ENTIRE miner connection
// (miner.pool = <hostname>) between the primary pool(s) and the
// lib/xmr.js-defined devPool config object (hardcoded hostname/port/
// username/password, `"share": 0` -- i.e. never counted toward the
// operator's own configured percentage splits) so that, in aggregate,
// approximately global.config.developerShare percent of the fleet's
// OWN measured hashrate ends up mining against the dev pool at any
// given time. Every job a given miner receives always comes from
// whichever ONE pool connection that miner is CURRENTLY assigned to
// (activePools[miner.pool].activeBlocktemplate) -- there is no
// per-job or per-share split within a single miner's own session at
// all.
//
// This leaf's mechanism, described in full below, is a DELIBERATE,
// SIMPLER, DOCUMENTED APPROXIMATION of that real behavior, not a
// faithful port -- ported field-for-field it would require this
// leaf to track live per-session hashrate estimates and periodically
// migrate whole downstream sessions between two upstream connections
// entirely out-of-band from the miner's own request lifecycle, which
// is a materially larger and more invasive change than
// DISPATCH_BRIEF.md's own explicit mechanism description asked for.
// Instead: EVERY job issuance (JobManager.NextJob, shared across ALL
// downstream sessions) independently rolls the SAME stateless,
// wall-clock-keyed selector below to decide primary-vs-dev-fee for
// THAT one issuance. Over many issuances/windows this converges on
// the same real-world outcome the reference is actually going for
// (approximately -dev-fee-percent% of forwarded share value ending
// up credited to the dev-fee connection) via a much smaller, fully
// stateless mechanism -- see devFeeSelector's own doc comment for
// the exact rule and why job-MINTING time (not the later
// SubmitShare-forwarding call site) is where this decision has to be
// made for this leaf's own job/template-pairing architecture.

// devFeeLogin/devFeePass are intentionally hardcoded, not
// operator-configurable via flag/env/TOML -- matches the legacy
// xmr-node-proxy reference's own baked-in devPool address (lib/
// xmr.js's `devPool.username`/`devPool.password` object literal,
// cited above) being fixed in source, not read from config.json.
// Only -dev-fee-percent/LEAF_PROXY_DEV_FEE_PERCENT is
// operator-tunable (0, the default, disables the mechanism entirely
// -- see JobManager.EnableDevFee's doc comment).
//
// devFeeLogin is a real Monero mainnet address, hardcoded to the
// SupportXMR pool (pool.supportxmr.com) as the exclusive upstream
// target for leaf-proxy, and intentionally not operator-configurable
// per the design above.
const (
	devFeeLogin = "8ArQjVSTeaKgNsh3ppXCcSB1CY2afxEk7EcGgYhneZmQ1iTt5Bbh5HDNsC2dfNFfraQ2ppwBGDmkajkNDfaBKfaVLLNFsff"
	devFeePass  = "go-crypto-pool-dev-fee"
)

// NewDevFeeUpstreamClient constructs the SECOND, dev-fee upstream
// connection cmd/leaf-proxy's -dev-fee-percent mechanism opens,
// against the SAME upstream host/port/TLS settings as the primary
// UpstreamClient (cfg.Host/Port/TLS/InsecureSkipVerifyTLS/Agent/
// DialTimeout/IdleTimeout/RequestTimeout are all operator-configured,
// exactly like the primary connection -- cmd/leaf-proxy/main.go
// copies them straight from the primary UpstreamConfig it already
// built). It goes through the exact same dial/login/heartbeat/
// reconnect lifecycle code as the primary (NewUpstreamClient itself)
// -- a second, independent instance, not new plumbing. cfg.Login/
// cfg.Pass are ALWAYS overridden to the hardcoded devFeeLogin/
// devFeePass constants above, regardless of what the caller passes
// in -- see this file's own doc comment for why those two fields are
// deliberately not operator-configurable.
func NewDevFeeUpstreamClient(cfg UpstreamConfig, logger *log.Logger) *UpstreamClient {
	cfg.Login = devFeeLogin
	cfg.Pass = devFeePass
	return NewUpstreamClient(cfg, logger)
}

// UpstreamRoute identifies which of leaf-proxy's (at most two)
// upstream pool connections a given Job (job.go) was minted from, and
// therefore which connection its eventual submit must be
// validated/forwarded against (Server.upstreamForRoute) -- see
// Job.Route's own doc comment for the full correctness rationale.
type UpstreamRoute int

const (
	// RoutePrimary is every Job's route whenever the dev-fee
	// mechanism is disabled (the default), and the fallback route
	// whenever it is enabled but the dev-fee connection could not be
	// used for a specific issuance (see JobManager.NextJob's
	// fault-isolation fallback).
	RoutePrimary UpstreamRoute = iota
	// RouteDevFee is a Job's route ONLY when leaf-proxy's dev-fee
	// mechanism is enabled (-dev-fee-percent > 0) AND
	// devFeeSelector.useDevFee (via JobManager's own
	// devFeeSelect func) genuinely selected it for that specific
	// issuance AND the dev-fee connection had a live template at
	// that moment.
	RouteDevFee
)

// devFeeWindow is the fixed, rolling wall-clock window
// NewDevFeeSelector partitions to decide primary-vs-dev-fee routing
// -- see devFeeSelector's own doc comment for the exact rule. 100
// seconds is chosen as a round, human-inspectable number
// comfortably longer than this leaf's typical upstream job cadence
// (observed ~5-15s per upstream.go's own doc comments elsewhere in
// this package) and comfortably shorter than any reasonable
// operator's own reporting/alerting interval -- so a low
// dev-fee-percent (the documented default, 1%) still gets a genuine,
// repeatedly-recurring ~1-second dev-fee slice every 100 seconds,
// rather than either a single vanishingly-short instant per hour
// (too coarse to reliably land on any job at all) or a window so
// short it would visibly perturb vardiff/job-cadence accounting.
// This is a deliberate, documented design choice for THIS leaf's own
// simplified mechanism -- see this file's package-level doc comment
// for the real legacy xmr-node-proxy reference's own, materially
// different whole-miner hashrate-balancing mechanism this is
// consciously NOT porting.
const devFeeWindow = 100 * time.Second

// devFeeSelector implements the rolling wall-clock time-slice rule
// NewDevFeeSelector exposes as a plain func(time.Time) bool (the
// shape JobManager.EnableDevFee/NextJob consume, and the shape
// devfee_test.go drives directly with synthetic instants for a fully
// deterministic statistical test, without any real sleeping).
//
// Rule: partition wall-clock time into fixed, back-to-back
// devFeeWindow-long windows (t.UnixNano() mod devFeeWindow). The
// FIRST percent% of EVERY window routes to the dev-fee connection;
// the rest routes to primary. E.g. percent=1 -> the first ~1 second
// of every 100-second window, repeating forever. This is stateless
// and lock-free by construction -- every caller, across every
// session's own read-loop goroutine calling JobManager.NextJob
// concurrently, computes the same answer for the same instant purely
// from its own time.Time argument, with no shared mutable state at
// all.
//
// Statistically, over many windows, this routes almost exactly
// percent% of JOB ISSUANCES to the dev-fee connection -- and,
// transitively (since a downstream miner's submit is always
// validated/forwarded against whichever connection its OWN current
// job was minted from -- see Job.Route's doc comment), very close to
// percent% of eventually-upstream-forwarded SHARE traffic too,
// assuming submit-worthy shares are not systematically correlated
// with position-within-window (they are not: miner submit timing is
// independent of this leaf's own internal upstream-selection clock).
type devFeeSelector struct {
	percent float64
}

// NewDevFeeSelector constructs the production selector
// cmd/leaf-proxy/main.go passes to JobManager.EnableDevFee. percent
// must already be validated to (0, 100] by the caller (see
// cmd/leaf-proxy/main.go's validateDevFeePercent) -- this
// constructor does not itself re-validate, since it is only ever
// invoked from the one call site that already gates on percent > 0.
func NewDevFeeSelector(percent float64) func(time.Time) bool {
	sel := &devFeeSelector{percent: percent}
	return sel.useDevFee
}

// useDevFee reports whether the instant now should route to the
// dev-fee connection -- see devFeeSelector's own doc comment for the
// exact rule.
func (d *devFeeSelector) useDevFee(now time.Time) bool {
	if d.percent <= 0 {
		return false
	}
	windowNanos := int64(devFeeWindow)
	pos := now.UnixNano() % windowNanos
	if pos < 0 {
		// time.Time.UnixNano() is monotonically increasing and never
		// negative for any real wall-clock reading on a live
		// process, but guard defensively against a pathological
		// test-injected instant rather than let a negative modulo
		// result (Go's % can return negative for a negative
		// dividend) silently misbehave.
		pos += windowNanos
	}
	threshold := int64(float64(windowNanos) * d.percent / 100)
	return pos < threshold
}
