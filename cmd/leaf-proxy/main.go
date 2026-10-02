// Command leaf-proxy is the leaf binary for mode 3: proxy-aggregator
// (XMR-Node-Proxy-style upstream emulation). It emulates an advanced
// Monero mining client to a REAL upstream Monero-family pool (e.g.
// pool.supportxmr.com), aggregating many real downstream miner
// connections behind that single upstream connection. Every downstream
// submit is re-validated for real, locally, via the already-merged
// internal/leaflib/validator.RandomXValidator; only a submit whose
// real, locally-recomputed RandomX difficulty meets the real upstream
// pool's own block target is forwarded upstream via a real "submit"
// RPC — everything below that is credited to the submitting
// downstream session's own local stats/vardiff only, exactly
// mirroring leaf-solo's "accept locally always, only escalate on a
// genuine block-level event" shape.
//
// REAL UPSTREAM PORT CONFIRMATION (checked before writing any wire
// code, per the task's explicit instruction that ports drift):
// SupportXMR's own currently-published stratum ports are 3333
// (low starting diff), 5555 (medium), 7777 (high), and 9000
// (TLS/SSL) — confirmed via SupportXMR's own community-documented
// port list (multiple independent, mutually-consistent sources: the
// r/MoneroMining community wiki thread on SupportXMR's port meanings,
// and miningpoolstats.stream's own SupportXMR entry) as of this pass;
// this also matches the exact port (7777) the real xmr-node-proxy
// reference's own example config.json comment used. -upstream-port
// defaults to 7777 but is fully operator-configurable since pool
// ports do drift over time — do not assume this default stays
// correct indefinitely.
//
// DEVELOPER-FEE MECHANISM (re-added this pass, DISPATCH_BRIEF.md
// "leaf-proxy dev-fee second-connection" -- a PRIOR pass of this same
// file's doc comment said the legacy reference's 1% devPool skim was
// "deliberately NOT ported"; that statement is now WRONG and has been
// corrected here): -dev-fee-percent/LEAF_PROXY_DEV_FEE_PERCENT
// (default 1.0, matching the legacy reference's own pre-configured
// 1% donation; 0 fully disables the mechanism, a complete no-op with
// zero second connection ever dialed) opens a SECOND, independent
// upstream connection under a hardcoded (not operator-configurable)
// dev-fee login and routes approximately that percentage of job
// issuances/upstream-forwarded share traffic to it instead of the
// primary connection -- see internal/leaflib/proxy/devfee.go's
// package-level doc comment for the full mechanism, INCLUDING an
// explicit, confirmed citation of what the real legacy xmr-node-proxy
// reference source actually does differently (a 90-second,
// whole-miner hashrate-balancing reassignment, not a per-job rolling
// window) and why this leaf's own simplified mechanism is a
// deliberate, documented approximation of that rather than a literal
// port. Still NOT ported from the legacy reference: its Node.js
// cluster/worker multi-process architecture — this is a single Go
// process using goroutines + internal/leaflib's ConnectionManager,
// which comfortably out-scales the legacy's per-worker sharding model
// without needing to replicate it.
//
// COIN SCOPE (internal/coinprofile.Registry): this binary has no
// -coin/-algo flag at all -- it is a wire-protocol-level, coin-generic
// proxy: it emulates the upstream's own claimed protocol dialect
// (-upstream-agent) and forwards whatever monerod-shaped
// get_block_template/submit_block-derived blob traffic the upstream
// hands it, without itself needing to know WHICH monerod-family coin
// (Monero itself, or any other coin in internal/coinprofile.Registry)
// that upstream pool actually mines. Generalizing leaf-solo/
// leaf-direct's -coin flag therefore had no equivalent flag to change
// here; this doc comment note plus the example TOML's own comment are
// this dispatch's documentation of that fact, per the brief's ask to
// "generalize -coin on leaf-solo, leaf-direct, leaf-proxy."
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/cfgfile"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
)

var version = "dev"

type config struct {
	upstreamHost     string
	upstreamPort     int
	upstreamTLS      bool
	upstreamLogin    string
	upstreamPass     string
	upstreamAgent    string
	upstreamInsecure bool

	listenAddress      string
	startingDifficulty uint64
	// portsRaw is -ports/LEAF_PROXY_PORTS: an optional comma-separated
	// list of address:difficulty[:desc][:tls] port tiers, mirroring
	// cmd/leaf-direct's identical mechanism exactly (see
	// resolvePorts/parsePortEntry below and solo.PortConfig's doc
	// comment). Empty (the default) falls back to
	// listenAddress/startingDifficulty as a single implicit tier --
	// fully backward-compatible, zero behavior change for any
	// deployment that doesn't set this.
	portsRaw          string
	minDifficulty     uint64
	maxDifficulty     uint64
	vardiffTargetTime int
	vardiffInterval   time.Duration
	jobMaxAge         time.Duration

	// tlsListenAddress is -tls-listen-address/LEAF_PROXY_TLS_LISTEN_ADDRESS:
	// a SECOND, optional downstream-facing listen address served over
	// TLS, alongside (never instead of) the existing plain
	// listenAddress above. Empty (the default) disables it entirely
	// -- a complete no-op, zero behavior change for every existing
	// deployment.
	//
	// DECISION (multi-port-tier support, this pass): this field now
	// belongs ONLY to the old single-tier fallback path -- i.e. it
	// is consulted ONLY when -ports/LEAF_PROXY_PORTS is UNSET, in
	// which case it is added as a second, TLS-enabled port tier
	// alongside the implicit listenAddress/startingDifficulty tier,
	// byte-for-byte as it always has. -ports' own per-tier trailing
	// ":tls" marker is now the GENERAL mechanism for configuring a
	// TLS-enabled listener when multiple tiers are in play. Setting
	// BOTH -ports and -tls-listen-address at the same time is a
	// fatal startup misconfiguration (see main()'s explicit check
	// below) rather than silently ignoring either one -- an operator
	// who needs a TLS tier alongside explicit -ports entries should
	// move it into a -ports entry (e.g. "...:tls") instead of also
	// setting this flag.
	tlsListenAddress string

	// tlsCertFile / tlsKeyFile / tlsCertPersistPath mirror leaf-solo/
	// leaf-direct's identical trio exactly (see
	// internal/leaflib.LoadOrGenerateCert's doc comment for the full
	// design rationale) -- only ever consulted if tlsListenAddress is
	// non-empty.
	tlsCertFile        string
	tlsKeyFile         string
	tlsCertPersistPath string

	maxConnections int
	idleTimeout    time.Duration

	dialTimeout    time.Duration
	requestTimeout time.Duration

	// randomxWorkers/invalidShareDisconnectEnabled/
	// invalidShareDisconnectThreshold mirror cmd/leaf-solo's own
	// identical fields exactly — see that file's doc comments for the
	// full DISPATCH_BRIEF.md 2026-09-10 Fix 2a/Fix 2b rationale.
	randomxWorkers                  int
	invalidShareDisconnectEnabled   bool
	invalidShareDisconnectThreshold int

	// randomxQueueSize mirrors cmd/leaf-solo's own identical field
	// exactly -- see that file's doc comment for the full rationale
	// (DefaultAsyncValidationQueueSize's own doc comment in
	// internal/leaflib/solo/asyncvalidation.go).
	randomxQueueSize int

	// poolDiffCapEnabled is -pool-diff-cap-enabled/
	// LEAF_PROXY_POOL_DIFF_CAP_ENABLED: toggles the login-time
	// pool-target-diff cap added by commit 46a6e2c (none of the
	// three difficulty floors -- port starting_difficulty, global
	// min_difficulty, per-address ForcedMinDifficulty -- may leave a
	// downstream session starting ABOVE the upstream pool's own
	// current target_diff). See proxy.Server.poolDiffCapEnabled's
	// own doc comment and internal/leaflib/proxy/session.go's
	// handleLogin for the full mechanism.
	//
	// DISPATCH_BRIEF.md 2026-09-13 (Alex): "lets put this feature
	// behind a default-on flag to help protect against
	// mis-configuration, most proxy ops likely won't have this
	// issue because they'll have reasonable starting points."
	// Defaults to true (enabled) -- an operator who genuinely wants
	// the pre-46a6e2c uncapped behavior must explicitly set this to
	// false.
	poolDiffCapEnabled bool

	// metricsListenAddress/maxAddressLabels follow cmd/leaf-solo's
	// exact established convention for this flag pair (see
	// leaf-solo's identical -metrics-listen-address/
	// -max-address-labels doc comments) -- ported to this sibling
	// binary unchanged, just with the LEAF_PROXY_ prefix.
	metricsListenAddress string
	maxAddressLabels     int

	// metricsMinSharesFilter is
	// -metrics-min-shares-filter/LEAF_PROXY_METRICS_MIN_SHARES_FILTER
	// (DISPATCH_BRIEF_MIN_SHARE_FILTER.md, Alex's ask: "Add a
	// feature to filter metrics to only connections with at least 1
	// share"): when true, every metrics/stats surface derived from
	// session state (Stats() and its consumers -- the stats HTML
	// page, /api/miners -- plus the Prometheus snapshot-derived
	// metrics) excludes any currently-connected session that has
	// never submitted a single share (e.g. a scanner/probe that
	// merely logs in and sits idle) -- see
	// proxy.Server.countableSessions's doc comment for the single
	// shared choke point this goes through. Opt-in, default false
	// (today's exact existing unfiltered behavior, byte-identical),
	// matching every other flag added across this whole feature arc
	// so far.
	metricsMinSharesFilter bool

	// statsPageMaxSessions is this feature's own
	// -stats-page-max-sessions/LEAF_PROXY_STATS_PAGE_MAX_SESSIONS
	// flag (see its flag.IntVar registration below and
	// proxy.Server.SetStatsPageMaxSessions's doc comment for the
	// full rationale). 0/negative disables the cap entirely,
	// mirroring this codebase's zero-disables convention.
	statsPageMaxSessions int

	// hideRemoteAddress mirrors cmd/leaf-solo's identical flag
	// exactly (see solo.Server.SetHideRemoteAddress's doc comment
	// -- proxy.Server has an identical method). Defaults to false.
	hideRemoteAddress bool

	// addressFlagsFile / addressFlagsPollInterval configure the real,
	// manual ban enforcement described in
	// internal/leaflib/addressflags's package doc comment. Mirrors
	// cmd/leaf-solo's identical flag pair exactly: addressFlagsFile
	// empty (the default) disables the feature entirely --
	// leaf-proxy has no go-crypto-pool backend to poll instead (see
	// this binary's own doc comment: it emulates an advanced mining
	// CLIENT to an upstream Monero-family POOL, not a backend
	// connection this repo controls), so a local, operator-
	// maintained JSON file is the only real Source available to it,
	// exactly like leaf-solo.
	addressFlagsFile         string
	addressFlagsPollInterval time.Duration

	// configFile is the optional path to a TOML file providing
	// defaults for any flag above that the operator did not set
	// explicitly via CLI flag or environment variable. See
	// leaf-proxy.example.toml and internal/leaflib/cfgfile for the
	// exact precedence rule (flag > env > file > hardcoded default).
	configFile string

	// debug is -debug/LEAF_PROXY_DEBUG: enables the shared
	// leaflib.DebugLogger (internal/leaflib/debuglog.go) for this
	// process. OFF (false) by default -- purely additive, byte-
	// identical existing log output when left off.
	debug bool

	// logLevel is -log-level/LEAF_PROXY_LOG_LEVEL (DISPATCH_BRIEF.md
	// "leaf-proxy ... log levels", Alex's ask: "error level 0 / 1 /
	// 2 something like that to avoid useless errors in foreground
	// mode"). Internally holds logLevelUnset (-1) until
	// resolveLogLevel runs the documented precedence rule (see that
	// function's doc comment) -- NEVER read directly as a raw int
	// before that point. Semantics once resolved:
	//
	//   - 0 (quiet): suppress routine, non-actionable,
	//     per-connection noise (session.go's handleLine unparseable-
	//     message line, and the oversized-login-rejection line --
	//     see leaflib.DebugLogger.Logf's doc comment for the exact
	//     "fits the same shape" test applied to find these).
	//     Startup/shutdown/fatal logs are NEVER suppressed at any
	//     level.
	//   - 1 (normal, the documented default): today's exact existing
	//     un-leveled output, byte-identical -- zero behavior change
	//     for any deployment that doesn't set this flag.
	//   - 2 (verbose): folds -debug/LEAF_PROXY_DEBUG's own
	//     [DEBUG]-tagged output in too (see resolveLogLevel).
	//
	// -debug/LEAF_PROXY_DEBUG keeps working exactly as it already
	// does for backward compatibility -- this flag is additive, not
	// a replacement.
	logLevel int

	// metricsUsername/metricsPassword are -metrics-username/
	// LEAF_PROXY_METRICS_USERNAME and -metrics-password/
	// LEAF_PROXY_METRICS_PASSWORD (DISPATCH_BRIEF.md "leaf-proxy ...
	// password-protected metrics like xnp style", Alex's ask: "This
	// would be the entire metrics endpoint, including the status
	// panel, should default to off"). metricsPassword empty (the
	// default) means NO auth gate at all -- every handler on
	// metricsMux (/metrics, /, /api/miners, /api/miners/history)
	// stays exactly as open as it is today, a complete no-op. A
	// non-empty password wraps every one of those handlers in HTTP
	// Basic Auth requiring this exact username/password -- see
	// internal/leaflib/proxy/metricsauth.go's package doc comment
	// for the full mechanism. metricsUsername defaults to "proxy"
	// (mirrors XNP's own convention) and is only ever consulted when
	// metricsPassword is non-empty.
	metricsUsername string
	metricsPassword string

	// statsDBPath/statsSampleInterval are -stats-db-path/
	// LEAF_PROXY_STATS_DB_PATH and -stats-sample-interval/
	// LEAF_PROXY_STATS_SAMPLE_INTERVAL (DISPATCH_BRIEF.md "leaf-
	// proxy ... 24h stats retention", Alex's own framing: "Likely a
	// local loop and/or a small SQLite DB - Used for basic miner
	// tracking"). statsDBPath empty (the default) disables the
	// feature entirely -- matches this codebase's consistent "empty
	// path = feature off" convention (address-flags-file,
	// tls-cert-persist-path). statsSampleInterval is only ever
	// consulted when statsDBPath is non-empty. See
	// internal/leaflib/proxy/statsdb.go's package doc comment for
	// the full "basic miner tracking only, not a full time-series
	// store" scope.
	statsDBPath         string
	statsSampleInterval time.Duration

	// devFeePercent is -dev-fee-percent/LEAF_PROXY_DEV_FEE_PERCENT:
	// the ONLY operator-tunable knob for leaf-proxy's optional
	// developer-fee mechanism (see internal/leaflib/proxy/devfee.go's
	// package-level doc comment for the full design, including the
	// real legacy xmr-node-proxy reference this is a deliberate,
	// documented simplification of). Valid range is [0, 100]
	// inclusive -- validated by validateDevFeePercent below, which
	// fails fast at startup with a clear error rather than silently
	// clamping a nonsensical value. 0 (NOT the default -- see below)
	// is a COMPLETE no-op: setupDevFee never even constructs a
	// second UpstreamClient, let alone dials one, in that case.
	//
	// Defaults to 1.0 (a real, non-zero opt-OUT-only default,
	// mirroring the real legacy xmr-node-proxy reference's own
	// pre-configured 1% donation -- see this repo's own
	// DISPATCH_BRIEF.md for the explicit instruction this default
	// value comes from) -- an operator who wants the mechanism fully
	// disabled must explicitly set this to 0.
	//
	// Dev-fee login/pass are DELIBERATELY NOT configurable here (no
	// corresponding flag/env/TOML key exists for them at all) -- see
	// devfee.go's devFeeLogin/devFeePass doc comment.
	devFeePercent float64
}

func loadConfig() (config, error) {
	cfg := config{}

	flag.StringVar(&cfg.upstreamHost, "upstream-host", envOr("LEAF_PROXY_UPSTREAM_HOST", "pool.supportxmr.com"), "real upstream Monero-family pool hostname. Env: LEAF_PROXY_UPSTREAM_HOST")
	flag.IntVar(&cfg.upstreamPort, "upstream-port", envOrInt("LEAF_PROXY_UPSTREAM_PORT", 7777), "real upstream pool stratum port (SupportXMR: 3333 low-diff, 5555 medium-diff, 7777 high-diff, 9000 TLS -- see this file's doc comment). Env: LEAF_PROXY_UPSTREAM_PORT")
	flag.BoolVar(&cfg.upstreamTLS, "upstream-tls", envOrBool("LEAF_PROXY_UPSTREAM_TLS", false), "dial the upstream pool over TLS. Env: LEAF_PROXY_UPSTREAM_TLS")
	flag.BoolVar(&cfg.upstreamInsecure, "upstream-tls-insecure-skip-verify", envOrBool("LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY", false), "skip TLS certificate verification for the upstream pool (testing only). Env: LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY")
	flag.StringVar(&cfg.upstreamLogin, "upstream-login", envOr("LEAF_PROXY_UPSTREAM_LOGIN", ""), "real XMR payout address to log in to the upstream pool with. Env: LEAF_PROXY_UPSTREAM_LOGIN")
	flag.StringVar(&cfg.upstreamPass, "upstream-pass", envOr("LEAF_PROXY_UPSTREAM_PASS", "go-crypto-pool-leaf-proxy"), "real upstream pool worker identifier/password. Env: LEAF_PROXY_UPSTREAM_PASS")
	// Default agent string deliberately DOES contain the literal
	// substring "xmr-node-proxy". Confirmed from the real pool-server
	// source (nodejs-pool-sxmr's lib/pool.js: `if (agent &&
	// agent.includes("xmr-node-proxy")) { this.proxy = true; }`, a
	// plain substring check, not an exact-version match), that
	// substring is what gates a real pool granting the "advanced
	// xmr-node-proxy client" protocol extension -- which, in turn, is
	// what makes a real pool (confirmed against
	// pool.supportxmr.com) publish client_nonce_offset/
	// client_pool_offset on its jobs at all.
	//
	// REVERSED (this pass, live production incident): this used to
	// deliberately AVOID that substring, because at the time the
	// advanced dialect meant a raw, untrimmed, arbitrarily-large
	// blocktemplate_blob field (no ordinary "blob" field at all),
	// which overflowed downstream xmrig's login buffer (error code:
	// 4). internal/leaflib/proxy's applyJob now has a real conversion
	// path for blocktemplate_blob (go-xmr-lib/support's
	// ParseBlockFromTemplateBlob + GetBlockHashingBlob -- see that
	// package's upstream.go doc comment), which made receiving that
	// raw blob safe -- but NOT opting into the advanced dialect
	// turned out to be its own, worse hazard: without
	// client_nonce_offset/client_pool_offset, every downstream miner
	// behind this leaf gets a byte-identical blob, so independent
	// miners routinely submit the exact same (job_id, nonce, result)
	// triple at low share difficulty. The upstream pool flags that as
	// a duplicate share, and enough of those within
	// nodejs-pool-sxmr's banThreshold/banPercent window got this
	// leaf's public IP banned for "using an invalid mining protocol"
	// in production. This flag/env var remains configurable -- an
	// operator who genuinely needs the ordinary, non-advanced dialect
	// instead can opt out by setting this to an agent string that
	// does NOT contain "xmr-node-proxy".
	flag.StringVar(&cfg.upstreamAgent, "upstream-agent", envOr("LEAF_PROXY_UPSTREAM_AGENT", "go-crypto-pool-leaf-proxy/xmr-node-proxy-1.0"), "mining-client agent string sent on upstream login -- defaults to an identifier containing the literal substring \"xmr-node-proxy\" (see this flag's doc comment) so the upstream pool grants the advanced xmr-node-proxy-client dialect and publishes client_nonce_offset/client_pool_offset, which this leaf needs to give downstream miners non-colliding blobs; the resulting raw blocktemplate_blob is safely handled via a real blocktemplate_blob->hashing-blob conversion path. Env: LEAF_PROXY_UPSTREAM_AGENT")

	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_PROXY_LISTEN_ADDRESS", ":5555"), "downstream miner-facing TCP listen address. Ignored as a listener source when -ports/LEAF_PROXY_PORTS is set (still used as -ports' own fallback default when -ports is unset -- see -ports' doc comment). Env: LEAF_PROXY_LISTEN_ADDRESS")
	flag.StringVar(&cfg.tlsListenAddress, "tls-listen-address", envOr("LEAF_PROXY_TLS_LISTEN_ADDRESS", ""), "optional SECOND downstream miner-facing TCP listen address, served over TLS using the shared self-signed-or-operator-supplied cert (see -tls-cert-file/-tls-key-file/-tls-cert-persist-path), alongside (never instead of) -listen-address. Empty (default) disables it entirely -- zero behavior change. Only consulted when -ports/LEAF_PROXY_PORTS is UNSET -- setting both is a fatal startup misconfiguration (see -ports' doc comment). Env: LEAF_PROXY_TLS_LISTEN_ADDRESS")
	flag.Uint64Var(&cfg.startingDifficulty, "starting-difficulty", envOrUint64("LEAF_PROXY_STARTING_DIFFICULTY", 20000), "starting downstream share difficulty; vardiff adjusts it from here. Ignored when -ports/LEAF_PROXY_PORTS is set (each port tier carries its own starting difficulty instead -- see -ports' doc comment). Env: LEAF_PROXY_STARTING_DIFFICULTY")
	flag.StringVar(&cfg.portsRaw, "ports", envOr("LEAF_PROXY_PORTS", ""), "comma-separated list of address:difficulty[:desc][:tls] port tiers, e.g. '0.0.0.0:5555:1000:medium-plain,0.0.0.0:5556:1000:medium-tls:tls' (first entry plain, second entry the same difficulty on a different port with TLS enabled). The optional trailing ':tls' marker (case-insensitive) enables the shared self-signed TLS listener for that ONE port tier only -- see -tls-cert-file/-tls-key-file/-tls-cert-persist-path. When unset (the default), -listen-address/-starting-difficulty are used as a single implicit tier (plain, no TLS), and -tls-listen-address (if also set) is added as a second, TLS-enabled tier exactly as before this flag existed -- fully backward-compatible, zero behavior change for any deployment that doesn't set this. Setting BOTH -ports and -tls-listen-address is a fatal startup misconfiguration -- move any TLS tier into a -ports entry instead. Env: LEAF_PROXY_PORTS")
	flag.Uint64Var(&cfg.minDifficulty, "min-difficulty", envOrUint64("LEAF_PROXY_MIN_DIFFICULTY", 20000), "absolute floor vardiff will never retarget below. Env: LEAF_PROXY_MIN_DIFFICULTY")
	flag.Uint64Var(&cfg.maxDifficulty, "max-difficulty", envOrUint64("LEAF_PROXY_MAX_DIFFICULTY", 1_000_000_000), "absolute ceiling vardiff will never retarget above. Env: LEAF_PROXY_MAX_DIFFICULTY")
	flag.IntVar(&cfg.vardiffTargetTime, "vardiff-target-time", envOrInt("LEAF_PROXY_VARDIFF_TARGET_TIME", 15), "seconds between shares vardiff aims for. Env: LEAF_PROXY_VARDIFF_TARGET_TIME")
	flag.DurationVar(&cfg.vardiffInterval, "vardiff-retarget-interval", envOrDuration("LEAF_PROXY_VARDIFF_RETARGET_INTERVAL", 30*time.Second), "how often each downstream session's own vardiff retarget timer fires. Env: LEAF_PROXY_VARDIFF_RETARGET_INTERVAL")
	flag.DurationVar(&cfg.jobMaxAge, "job-max-age", envOrDuration("LEAF_PROXY_JOB_MAX_AGE", 6*time.Minute), "real per-job expiry threshold; a submit against an older job is rejected. Env: LEAF_PROXY_JOB_MAX_AGE")

	flag.StringVar(&cfg.tlsCertFile, "tls-cert-file", envOr("LEAF_PROXY_TLS_CERT_FILE", ""), "optional PEM-encoded TLS certificate file for the shared, process-wide self-signed-or-operator-supplied cert used by -tls-listen-address. Empty (default) auto-generates a self-signed cert instead -- see -tls-cert-persist-path. Ignored entirely if -tls-listen-address is unset. Env: LEAF_PROXY_TLS_CERT_FILE")
	flag.StringVar(&cfg.tlsKeyFile, "tls-key-file", envOr("LEAF_PROXY_TLS_KEY_FILE", ""), "optional PEM-encoded TLS private key file paired with -tls-cert-file. Env: LEAF_PROXY_TLS_KEY_FILE")
	flag.StringVar(&cfg.tlsCertPersistPath, "tls-cert-persist-path", envOr("LEAF_PROXY_TLS_CERT_PERSIST_PATH", ""), "where to persist an auto-generated self-signed TLS cert/key pair so restarts reload it instead of rotating it. Empty (default) means in-memory only -- a fresh self-signed cert is generated on every restart. Ignored if -tls-cert-file/-tls-key-file are set. Env: LEAF_PROXY_TLS_CERT_PERSIST_PATH")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_PROXY_MAX_CONNECTIONS", leaflib.DefaultLeafMaxConnections), "max concurrent downstream miner connections, 0 = unlimited. Env: LEAF_PROXY_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_PROXY_IDLE_TIMEOUT", 2*time.Minute), "rolling per-downstream-connection idle timeout. Env: LEAF_PROXY_IDLE_TIMEOUT")

	flag.DurationVar(&cfg.dialTimeout, "upstream-dial-timeout", envOrDuration("LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT", 10*time.Second), "timeout for dialing the upstream pool. Env: LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT")
	flag.DurationVar(&cfg.requestTimeout, "upstream-request-timeout", envOrDuration("LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT", 15*time.Second), "timeout for a single upstream request/response round-trip. Env: LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT")

	flag.IntVar(&cfg.randomxWorkers, "randomx-workers", envOrInt("LEAF_PROXY_RANDOMX_WORKERS", 0), "RandomX async validation worker pool size (see internal/leaflib/solo/asyncvalidation.go). 0/unset uses the documented default, runtime.NumCPU() -- NOT a hardcoded literal. Env: LEAF_PROXY_RANDOMX_WORKERS")
	flag.IntVar(&cfg.randomxQueueSize, "randomx-queue-size", envOrInt("LEAF_PROXY_RANDOMX_QUEUE_SIZE", 0), "RandomX async validation pool's bounded queue capacity (see internal/leaflib/solo/asyncvalidation.go). 0/unset uses the documented default, max(256, randomx-workers*16) -- NOT a hardcoded flat literal. Env: LEAF_PROXY_RANDOMX_QUEUE_SIZE")
	flag.BoolVar(&cfg.invalidShareDisconnectEnabled, "invalid-share-disconnect-enabled", envOr("LEAF_PROXY_INVALID_SHARE_DISCONNECT_ENABLED", "true") == "true", "disconnect a downstream session after too many CONSECUTIVE real RandomX validation failures (see internal/leaflib.InvalidShareGuard) -- a security-hardening default, enabled unless explicitly turned off. Env: LEAF_PROXY_INVALID_SHARE_DISCONNECT_ENABLED (\"false\" to disable)")
	flag.IntVar(&cfg.invalidShareDisconnectThreshold, "invalid-share-disconnect-threshold", envOrInt("LEAF_PROXY_INVALID_SHARE_DISCONNECT_THRESHOLD", 0), "consecutive-invalid-share threshold before a downstream session is disconnected (see -invalid-share-disconnect-enabled). 0/unset uses the documented default (20). Env: LEAF_PROXY_INVALID_SHARE_DISCONNECT_THRESHOLD")

	flag.BoolVar(&cfg.poolDiffCapEnabled, "pool-diff-cap-enabled", envOr("LEAF_PROXY_POOL_DIFF_CAP_ENABLED", "true") == "true", "cap all three login-time difficulty floors (port starting_difficulty, global min_difficulty, per-address ForcedMinDifficulty) so none may leave a downstream session starting ABOVE the upstream pool's own current target_diff -- a mis-configuration guardrail, enabled unless explicitly turned off. Env: LEAF_PROXY_POOL_DIFF_CAP_ENABLED (\"false\" to disable)")

	flag.StringVar(&cfg.metricsListenAddress, "metrics-listen-address", envOr("LEAF_PROXY_METRICS_LISTEN_ADDRESS", "127.0.0.1:9601"), "HTTP listen address for /metrics (Prometheus) and the stats page. Separate from -listen-address (the downstream-facing stratum port). Defaults to loopback-only (127.0.0.1) -- an operator must explicitly set this to a wildcard/public address to expose stats/metrics publicly. Set to empty string to disable. Env: LEAF_PROXY_METRICS_LISTEN_ADDRESS")
	flag.BoolVar(&cfg.hideRemoteAddress, "hide-remote-address", envOrBool("LEAF_PROXY_HIDE_REMOTE_ADDRESS", false), "omit the \"Remote address\" column from the stats HTML page entirely -- recommended for public-facing deployments. Disabled by default. Env: LEAF_PROXY_HIDE_REMOTE_ADDRESS")
	flag.IntVar(&cfg.maxAddressLabels, "max-address-labels", envOrInt("LEAF_PROXY_MAX_ADDRESS_LABELS", 0), "cap on distinct payment-address labels tracked by leaf_proxy_miners_by_address and the stats page's per-address breakdown (0 = package default). Env: LEAF_PROXY_MAX_ADDRESS_LABELS")
	flag.IntVar(&cfg.statsPageMaxSessions, "stats-page-max-sessions", envOrInt("LEAF_PROXY_STATS_PAGE_MAX_SESSIONS", proxy.DefaultStatsPageMaxSessions), "cap on how many session rows the stats HTML page's \"Connected sessions\" table renders (the separate \"Active connections\" summary count is always accurate/uncapped). 0 or negative disables the cap entirely (render every session). Env: LEAF_PROXY_STATS_PAGE_MAX_SESSIONS")
	flag.BoolVar(&cfg.metricsMinSharesFilter, "metrics-min-shares-filter", envOrBool("LEAF_PROXY_METRICS_MIN_SHARES_FILTER", false), "exclude any currently-connected session that has never submitted a single share (e.g. a scanner/probe that merely logs in and sits idle) from EVERY metrics/stats surface -- Stats(), the stats HTML page, /api/miners, and the Prometheus snapshot-derived metrics alike. Opt-in, OFF by default (today's exact existing unfiltered behavior). Env: LEAF_PROXY_METRICS_MIN_SHARES_FILTER")

	flag.StringVar(&cfg.addressFlagsFile, "address-flags-file", envOr("LEAF_PROXY_ADDRESS_FLAGS_FILE", ""), "path to a local, operator-maintained JSON file of manually banned payment addresses (see internal/leaflib/addressflags.FileSource's doc comment for the file format). Empty (default) disables the feature entirely -- leaf-proxy has no go-crypto-pool backend to poll instead. Env: LEAF_PROXY_ADDRESS_FLAGS_FILE")
	flag.DurationVar(&cfg.addressFlagsPollInterval, "address-flags-poll-interval", envOrDuration("LEAF_PROXY_ADDRESS_FLAGS_POLL_INTERVAL", 30*time.Second), "how often -address-flags-file is re-read. Ignored if -address-flags-file is unset. Env: LEAF_PROXY_ADDRESS_FLAGS_POLL_INTERVAL")

	flag.StringVar(&cfg.configFile, "config", envOr("LEAF_PROXY_CONFIG_FILE", ""), "optional path to a TOML config file providing defaults for any flag below that is not explicitly set via CLI flag or environment variable. See leaf-proxy.example.toml. Env: LEAF_PROXY_CONFIG_FILE")

	flag.BoolVar(&cfg.debug, "debug", envOrBool("LEAF_PROXY_DEBUG", false), "enable verbose [DEBUG]-tagged logging (downstream submit params, validation attempt/result, upstream forward attempts/responses, template lifecycle, connection lifecycle, vardiff retargets). OFF by default -- purely additive, never changes any existing log line. Env: LEAF_PROXY_DEBUG")
	flag.IntVar(&cfg.logLevel, "log-level", envOrInt("LEAF_PROXY_LOG_LEVEL", logLevelUnset), "0=quiet (suppress routine per-connection noise, e.g. unparseable-message/oversized-login lines), 1=normal (today's existing un-leveled output -- the default), 2=verbose (folds -debug's output in too). Left unset, defaults to 1, UNLESS -debug=true is set with this flag left unset, in which case it behaves as 2 (so an existing -debug-only deployment keeps its current verbose behavior). An explicitly-set value here always wins over that fallback. Env: LEAF_PROXY_LOG_LEVEL")

	flag.Float64Var(&cfg.devFeePercent, "dev-fee-percent", envOrFloat64("LEAF_PROXY_DEV_FEE_PERCENT", 1.0), "percentage (0-100) of job issuances/upstream-forwarded share traffic routed to a SECOND, independent upstream connection logged in under a hardcoded (not operator-configurable) dev-fee login -- see internal/leaflib/proxy/devfee.go's doc comment for the full mechanism. 0 disables the mechanism entirely: no second connection is ever dialed. Env: LEAF_PROXY_DEV_FEE_PERCENT")

	flag.StringVar(&cfg.metricsUsername, "metrics-username", envOr("LEAF_PROXY_METRICS_USERNAME", "proxy"), "HTTP Basic Auth username required on every metricsMux endpoint (/metrics, /, /api/miners, /api/miners/history) once -metrics-password is non-empty. Ignored entirely when -metrics-password is empty (the default -- no auth gate at all). Env: LEAF_PROXY_METRICS_USERNAME")
	flag.StringVar(&cfg.metricsPassword, "metrics-password", envOr("LEAF_PROXY_METRICS_PASSWORD", ""), "HTTP Basic Auth password required on every metricsMux endpoint. Empty (the default) means NO auth gate at all -- every endpoint stays exactly as open as it is today, a complete no-op (Alex's \"should default to off\"). A non-empty value wraps every metricsMux handler in Basic Auth requiring -metrics-username/this password. Env: LEAF_PROXY_METRICS_PASSWORD")

	flag.StringVar(&cfg.statsDBPath, "stats-db-path", envOr("LEAF_PROXY_STATS_DB_PATH", ""), "path to a local, pure-Go (modernc.org/sqlite, no cgo) SQLite file used for basic 24h miner-history tracking (see GET /api/miners/history and internal/leaflib/proxy/statsdb.go's doc comment). Empty (the default) disables the feature entirely -- matches this codebase's consistent \"empty path = feature off\" convention. Env: LEAF_PROXY_STATS_DB_PATH")
	flag.DurationVar(&cfg.statsSampleInterval, "stats-sample-interval", envOrDuration("LEAF_PROXY_STATS_SAMPLE_INTERVAL", 5*time.Minute), "how often to snapshot every currently-connected session into -stats-db-path and prune rows older than 24h. Only consulted when -stats-db-path is non-empty. Env: LEAF_PROXY_STATS_SAMPLE_INTERVAL")

	flag.Parse()

	if err := applyConfigFile(&cfg); err != nil {
		return cfg, err
	}

	if err := validateDevFeePercent(cfg.devFeePercent); err != nil {
		return cfg, err
	}

	if err := resolveLogLevel(&cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// logLevelUnset is -log-level/LEAF_PROXY_LOG_LEVEL's internal sentinel
// default (see config.logLevel's own doc comment) -- distinct from
// every valid level (0/1/2) so resolveLogLevel can tell "the operator
// never touched this flag/env/TOML-key at all" apart from "the
// operator explicitly chose 0". flag.IntVar's own envOrInt default
// uses this sentinel directly (see loadConfig's -log-level
// registration), and cfgfile.ApplyInt's existing visited-flag/env
// precedence check (applyConfigFile) composes with it exactly like
// every other int flag -- a TOML log_level key only ever overwrites
// this sentinel when NEITHER an explicit CLI flag NOR an explicit env
// var was set, which is already cfgfile's own contract.
const logLevelUnset = -1

// resolveLogLevel implements -log-level/LEAF_PROXY_LOG_LEVEL's
// documented precedence rule (DISPATCH_BRIEF.md "leaf-proxy ... log
// levels"): if -log-level was explicitly set (by ANY of CLI
// flag/env var/TOML key -- by the time this runs, cfg.logLevel would
// no longer equal logLevelUnset if so), that value wins outright,
// unconditionally, regardless of -debug. Otherwise (truly never
// touched by the operator at all), falls back to 2 if -debug=true (so
// an existing deployment relying on -debug alone keeps its current
// verbose behavior without needing to also add -log-level), or 1
// (the documented, byte-identical-to-today default) otherwise.
// Validates the final resolved value is in [0, 2] -- fails fast with
// a clear error rather than silently clamping an operator's typo'd
// explicit value (e.g. -log-level=5).
func resolveLogLevel(cfg *config) error {
	if cfg.logLevel == logLevelUnset {
		if cfg.debug {
			cfg.logLevel = 2
		} else {
			cfg.logLevel = 1
		}
		return nil
	}
	if cfg.logLevel < 0 || cfg.logLevel > 2 {
		return fmt.Errorf("leaf-proxy: -log-level/LEAF_PROXY_LOG_LEVEL must be 0, 1, or 2, got %d", cfg.logLevel)
	}
	return nil
}

// validateDevFeePercent enforces -dev-fee-percent/
// LEAF_PROXY_DEV_FEE_PERCENT's documented valid range (0-100
// inclusive) -- fails fast at startup with a clear error rather than
// silently clamping or accepting a nonsensical value: a negative
// percentage or one above 100 has no sane interpretation for
// internal/leaflib/proxy's devFeeSelector (a rolling-window fraction
// outside [0, 100] is meaningless).
func validateDevFeePercent(percent float64) error {
	if percent < 0 || percent > 100 {
		return fmt.Errorf("leaf-proxy: -dev-fee-percent/LEAF_PROXY_DEV_FEE_PERCENT must be between 0 and 100 (inclusive), got %v", percent)
	}
	return nil
}

// fileConfig mirrors config field-for-field (excluding configFile
// itself) with pointer types so an absent TOML key decodes to nil and
// is left untouched by the cfgfile.ApplyXxx helpers below. Durations
// are represented in the TOML file as a plain integer number of
// seconds (go-toml/v2 does not natively decode into time.Duration)
// and converted with time.Duration(v) * time.Second when applied.
type fileConfig struct {
	UpstreamHost     *string `toml:"upstream_host"`
	UpstreamPort     *int    `toml:"upstream_port"`
	UpstreamTLS      *bool   `toml:"upstream_tls"`
	UpstreamInsecure *bool   `toml:"upstream_tls_insecure_skip_verify"`
	UpstreamLogin    *string `toml:"upstream_login"`
	UpstreamPass     *string `toml:"upstream_pass"`
	UpstreamAgent    *string `toml:"upstream_agent"`

	ListenAddress          *string `toml:"listen_address"`
	TLSListenAddress       *string `toml:"tls_listen_address"`
	StartingDifficulty     *uint64 `toml:"starting_difficulty"`
	PortsRaw               *string `toml:"ports"`
	MinDifficulty          *uint64 `toml:"min_difficulty"`
	MaxDifficulty          *uint64 `toml:"max_difficulty"`
	VardiffTargetTime      *int    `toml:"vardiff_target_time_seconds"`
	VardiffIntervalSeconds *int    `toml:"vardiff_retarget_interval_seconds"`
	JobMaxAgeSeconds       *int    `toml:"job_max_age_seconds"`

	TLSCertFile        *string `toml:"tls_cert_file"`
	TLSKeyFile         *string `toml:"tls_key_file"`
	TLSCertPersistPath *string `toml:"tls_cert_persist_path"`

	MaxConnections     *int `toml:"max_connections"`
	IdleTimeoutSeconds *int `toml:"idle_timeout_seconds"`

	DialTimeoutSeconds    *int `toml:"upstream_dial_timeout_seconds"`
	RequestTimeoutSeconds *int `toml:"upstream_request_timeout_seconds"`

	RandomXWorkers                  *int  `toml:"randomx_workers"`
	RandomXQueueSize                *int  `toml:"randomx_queue_size"`
	InvalidShareDisconnectEnabled   *bool `toml:"invalid_share_disconnect_enabled"`
	InvalidShareDisconnectThreshold *int  `toml:"invalid_share_disconnect_threshold"`

	PoolDiffCapEnabled *bool `toml:"pool_diff_cap_enabled"`

	MetricsListenAddress   *string `toml:"metrics_listen_address"`
	MaxAddressLabels       *int    `toml:"max_address_labels"`
	StatsPageMaxSessions   *int    `toml:"stats_page_max_sessions"`
	HideRemoteAddress      *bool   `toml:"hide_remote_address"`
	MetricsMinSharesFilter *bool   `toml:"metrics_min_shares_filter"`

	AddressFlagsFile                *string `toml:"address_flags_file"`
	AddressFlagsPollIntervalSeconds *int    `toml:"address_flags_poll_interval_seconds"`

	Debug    *bool `toml:"debug"`
	LogLevel *int  `toml:"log_level"`

	DevFeePercent *float64 `toml:"dev_fee_percent"`

	MetricsUsername *string `toml:"metrics_username"`
	MetricsPassword *string `toml:"metrics_password"`

	StatsDBPath                *string `toml:"stats_db_path"`
	StatsSampleIntervalSeconds *int    `toml:"stats_sample_interval_seconds"`
}

// applyConfigFile merges cfg.configFile (if set) into cfg, honoring
// the flag > env > file > hardcoded-default precedence rule owned by
// internal/leaflib/cfgfile. It is a no-op when cfg.configFile == "".
func applyConfigFile(cfg *config) error {
	if cfg.configFile == "" {
		return nil
	}

	visited := cfgfile.VisitedFlags(flag.CommandLine)

	var fc fileConfig
	if err := cfgfile.Decode(cfg.configFile, &fc); err != nil {
		return fmt.Errorf("leaf-proxy: loading -config %s: %w", cfg.configFile, err)
	}

	cfgfile.ApplyString(&cfg.upstreamHost, fc.UpstreamHost, visited, "upstream-host", "LEAF_PROXY_UPSTREAM_HOST")
	cfgfile.ApplyInt(&cfg.upstreamPort, fc.UpstreamPort, visited, "upstream-port", "LEAF_PROXY_UPSTREAM_PORT")
	cfgfile.ApplyBool(&cfg.upstreamTLS, fc.UpstreamTLS, visited, "upstream-tls", "LEAF_PROXY_UPSTREAM_TLS")
	cfgfile.ApplyBool(&cfg.upstreamInsecure, fc.UpstreamInsecure, visited, "upstream-tls-insecure-skip-verify", "LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY")
	cfgfile.ApplyString(&cfg.upstreamLogin, fc.UpstreamLogin, visited, "upstream-login", "LEAF_PROXY_UPSTREAM_LOGIN")
	cfgfile.ApplyString(&cfg.upstreamPass, fc.UpstreamPass, visited, "upstream-pass", "LEAF_PROXY_UPSTREAM_PASS")
	cfgfile.ApplyString(&cfg.upstreamAgent, fc.UpstreamAgent, visited, "upstream-agent", "LEAF_PROXY_UPSTREAM_AGENT")

	cfgfile.ApplyString(&cfg.listenAddress, fc.ListenAddress, visited, "listen-address", "LEAF_PROXY_LISTEN_ADDRESS")
	cfgfile.ApplyString(&cfg.tlsListenAddress, fc.TLSListenAddress, visited, "tls-listen-address", "LEAF_PROXY_TLS_LISTEN_ADDRESS")
	cfgfile.ApplyUint64(&cfg.startingDifficulty, fc.StartingDifficulty, visited, "starting-difficulty", "LEAF_PROXY_STARTING_DIFFICULTY")
	cfgfile.ApplyString(&cfg.portsRaw, fc.PortsRaw, visited, "ports", "LEAF_PROXY_PORTS")
	cfgfile.ApplyUint64(&cfg.minDifficulty, fc.MinDifficulty, visited, "min-difficulty", "LEAF_PROXY_MIN_DIFFICULTY")
	cfgfile.ApplyUint64(&cfg.maxDifficulty, fc.MaxDifficulty, visited, "max-difficulty", "LEAF_PROXY_MAX_DIFFICULTY")
	cfgfile.ApplyInt(&cfg.vardiffTargetTime, fc.VardiffTargetTime, visited, "vardiff-target-time", "LEAF_PROXY_VARDIFF_TARGET_TIME")

	if fc.VardiffIntervalSeconds != nil {
		d := time.Duration(*fc.VardiffIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.vardiffInterval, &d, visited, "vardiff-retarget-interval", "LEAF_PROXY_VARDIFF_RETARGET_INTERVAL")
	}
	if fc.JobMaxAgeSeconds != nil {
		d := time.Duration(*fc.JobMaxAgeSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.jobMaxAge, &d, visited, "job-max-age", "LEAF_PROXY_JOB_MAX_AGE")
	}

	cfgfile.ApplyString(&cfg.tlsCertFile, fc.TLSCertFile, visited, "tls-cert-file", "LEAF_PROXY_TLS_CERT_FILE")
	cfgfile.ApplyString(&cfg.tlsKeyFile, fc.TLSKeyFile, visited, "tls-key-file", "LEAF_PROXY_TLS_KEY_FILE")
	cfgfile.ApplyString(&cfg.tlsCertPersistPath, fc.TLSCertPersistPath, visited, "tls-cert-persist-path", "LEAF_PROXY_TLS_CERT_PERSIST_PATH")

	cfgfile.ApplyInt(&cfg.maxConnections, fc.MaxConnections, visited, "max-connections", "LEAF_PROXY_MAX_CONNECTIONS")
	if fc.IdleTimeoutSeconds != nil {
		d := time.Duration(*fc.IdleTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.idleTimeout, &d, visited, "idle-timeout", "LEAF_PROXY_IDLE_TIMEOUT")
	}

	if fc.DialTimeoutSeconds != nil {
		d := time.Duration(*fc.DialTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.dialTimeout, &d, visited, "upstream-dial-timeout", "LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT")
	}
	if fc.RequestTimeoutSeconds != nil {
		d := time.Duration(*fc.RequestTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.requestTimeout, &d, visited, "upstream-request-timeout", "LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT")
	}

	cfgfile.ApplyInt(&cfg.randomxWorkers, fc.RandomXWorkers, visited, "randomx-workers", "LEAF_PROXY_RANDOMX_WORKERS")
	cfgfile.ApplyInt(&cfg.randomxQueueSize, fc.RandomXQueueSize, visited, "randomx-queue-size", "LEAF_PROXY_RANDOMX_QUEUE_SIZE")
	cfgfile.ApplyBool(&cfg.invalidShareDisconnectEnabled, fc.InvalidShareDisconnectEnabled, visited, "invalid-share-disconnect-enabled", "LEAF_PROXY_INVALID_SHARE_DISCONNECT_ENABLED")
	cfgfile.ApplyInt(&cfg.invalidShareDisconnectThreshold, fc.InvalidShareDisconnectThreshold, visited, "invalid-share-disconnect-threshold", "LEAF_PROXY_INVALID_SHARE_DISCONNECT_THRESHOLD")

	cfgfile.ApplyBool(&cfg.poolDiffCapEnabled, fc.PoolDiffCapEnabled, visited, "pool-diff-cap-enabled", "LEAF_PROXY_POOL_DIFF_CAP_ENABLED")

	cfgfile.ApplyString(&cfg.metricsListenAddress, fc.MetricsListenAddress, visited, "metrics-listen-address", "LEAF_PROXY_METRICS_LISTEN_ADDRESS")
	cfgfile.ApplyInt(&cfg.maxAddressLabels, fc.MaxAddressLabels, visited, "max-address-labels", "LEAF_PROXY_MAX_ADDRESS_LABELS")
	cfgfile.ApplyInt(&cfg.statsPageMaxSessions, fc.StatsPageMaxSessions, visited, "stats-page-max-sessions", "LEAF_PROXY_STATS_PAGE_MAX_SESSIONS")
	cfgfile.ApplyBool(&cfg.hideRemoteAddress, fc.HideRemoteAddress, visited, "hide-remote-address", "LEAF_PROXY_HIDE_REMOTE_ADDRESS")
	cfgfile.ApplyBool(&cfg.metricsMinSharesFilter, fc.MetricsMinSharesFilter, visited, "metrics-min-shares-filter", "LEAF_PROXY_METRICS_MIN_SHARES_FILTER")

	cfgfile.ApplyString(&cfg.addressFlagsFile, fc.AddressFlagsFile, visited, "address-flags-file", "LEAF_PROXY_ADDRESS_FLAGS_FILE")
	if fc.AddressFlagsPollIntervalSeconds != nil {
		d := time.Duration(*fc.AddressFlagsPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.addressFlagsPollInterval, &d, visited, "address-flags-poll-interval", "LEAF_PROXY_ADDRESS_FLAGS_POLL_INTERVAL")
	}

	cfgfile.ApplyBool(&cfg.debug, fc.Debug, visited, "debug", "LEAF_PROXY_DEBUG")
	cfgfile.ApplyInt(&cfg.logLevel, fc.LogLevel, visited, "log-level", "LEAF_PROXY_LOG_LEVEL")

	cfgfile.ApplyFloat64(&cfg.devFeePercent, fc.DevFeePercent, visited, "dev-fee-percent", "LEAF_PROXY_DEV_FEE_PERCENT")

	cfgfile.ApplyString(&cfg.metricsUsername, fc.MetricsUsername, visited, "metrics-username", "LEAF_PROXY_METRICS_USERNAME")
	cfgfile.ApplyString(&cfg.metricsPassword, fc.MetricsPassword, visited, "metrics-password", "LEAF_PROXY_METRICS_PASSWORD")

	cfgfile.ApplyString(&cfg.statsDBPath, fc.StatsDBPath, visited, "stats-db-path", "LEAF_PROXY_STATS_DB_PATH")
	if fc.StatsSampleIntervalSeconds != nil {
		d := time.Duration(*fc.StatsSampleIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.statsSampleInterval, &d, visited, "stats-sample-interval", "LEAF_PROXY_STATS_SAMPLE_INTERVAL")
	}

	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envOrUint64(key string, def uint64) uint64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envOrBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envOrDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envOrFloat64(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// resolvePorts mirrors cmd/leaf-direct/main.go's identical function
// exactly (see that file's doc comment on -ports/LEAF_DIRECT_PORTS
// for the full rationale) -- this is leaf-proxy's own local copy,
// renamed to reference LEAF_PROXY_PORTS in error messages. When
// cfg.portsRaw is unset (the default), -listen-address/
// -starting-difficulty are used as a single implicit tier (plain, no
// TLS) -- fully backward-compatible with every deployment that
// predates this feature.
func resolvePorts(cfg config) ([]solo.PortConfig, error) {
	if strings.TrimSpace(cfg.portsRaw) == "" {
		return []solo.PortConfig{{Address: cfg.listenAddress, Difficulty: cfg.startingDifficulty, PortDesc: "default"}}, nil
	}
	entries := strings.Split(cfg.portsRaw, ",")
	ports := make([]solo.PortConfig, 0, len(entries))
	for i, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		port, err := parsePortEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("LEAF_PROXY_PORTS entry %d (%q): %w", i+1, raw, err)
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, errors.New("LEAF_PROXY_PORTS was set but contained no usable entries")
	}
	return ports, nil
}

// parsePortEntry mirrors cmd/leaf-direct/main.go's identical function
// exactly (see resolvePorts' doc comment above) -- this is
// leaf-proxy's own local copy.
//
// DISPATCH_BRIEF.md section 6 ("IPv6 support"): real bug fix, not
// just docs. This used to split the WHOLE raw string on ":",
// unconditionally -- which breaks for any IPv6 literal host, since
// the address itself contains colons. Confirmed by hand before
// fixing: "[::1]:5555:20000" naively split on ":" produces
// ["[", "", "1]", "5555", "20000"], nothing like the intended
// address="[::1]:5555". Fixed by detecting a leading "[...]" bracket
// group FIRST (RFC 3986 IPv6-literal-in-URL style) and routing to
// parseIPv6PortEntry below, which treats "[...]:port" as one atomic
// address token before applying the SAME difficulty/desc/
// ":tls"-stripping grammar to whatever fields remain after it. Any
// entry that does NOT start with "[" (every existing IPv4/hostname
// entry) falls through to exactly the pre-existing logic below,
// completely unmodified -- this is an additive fix, not a rewrite of
// the working IPv4 path.
func parsePortEntry(raw string) (solo.PortConfig, error) {
	if strings.HasPrefix(raw, "[") {
		return parseIPv6PortEntry(raw)
	}

	fields := strings.Split(raw, ":")

	// Strip an optional trailing ":tls" marker FIRST, before any of
	// the existing difficulty/desc peeling logic below runs. This
	// makes the grammar a strict superset of the pre-existing one:
	// any entry with no trailing ":tls" field is untouched by this
	// block and parses exactly as before (byte-for-byte identical
	// PortConfig{TLS: false, ...}).
	var tlsEnabled bool
	if len(fields) > 0 && strings.EqualFold(fields[len(fields)-1], "tls") {
		tlsEnabled = true
		fields = fields[:len(fields)-1]
	}

	if len(fields) < 2 {
		return solo.PortConfig{}, errors.New(`expected "address:difficulty", "address:difficulty:desc", or either with a trailing ":tls"`)
	}
	var (
		addressFields []string
		difficulty    uint64
		desc          string
		err           error
	)
	if difficulty, err = strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil {
		addressFields = fields[:len(fields)-1]
	} else if len(fields) >= 3 {
		difficulty, err = strconv.ParseUint(fields[len(fields)-2], 10, 64)
		if err != nil {
			return solo.PortConfig{}, fmt.Errorf("invalid difficulty: %w", err)
		}
		addressFields = fields[:len(fields)-2]
		desc = fields[len(fields)-1]
	} else {
		return solo.PortConfig{}, fmt.Errorf("invalid difficulty: %w", err)
	}
	address := strings.Join(addressFields, ":")
	if address == "" {
		return solo.PortConfig{}, errors.New("address portion is empty")
	}
	if difficulty == 0 {
		return solo.PortConfig{}, errors.New("difficulty must be > 0")
	}
	return solo.PortConfig{Address: address, Difficulty: difficulty, PortDesc: desc, TLS: tlsEnabled}, nil
}

// parseIPv6PortEntry parses an entry whose address portion is an
// IPv6 literal in RFC 3986 bracket form:
// "[host]:port:difficulty[:desc][:tls]", e.g. "[::1]:5555:20000" or
// "[::]:5556:20000:dual-stack:tls". The "[host]:port" prefix is
// treated as ONE atomic address token (raw's own leading "[" was
// already confirmed by parsePortEntry's caller) -- everything after
// it is handed to the exact same difficulty/desc/":tls" grammar the
// non-IPv6 path above already implements, just without an address
// component of its own to peel off (that part is already resolved by
// the time this function gets to it).
func parseIPv6PortEntry(raw string) (solo.PortConfig, error) {
	closeIdx := strings.Index(raw, "]")
	if closeIdx == -1 {
		return solo.PortConfig{}, errors.New(`unterminated IPv6 literal: missing closing "]"`)
	}
	afterBracket := raw[closeIdx+1:]
	if !strings.HasPrefix(afterBracket, ":") {
		return solo.PortConfig{}, errors.New(`expected ":port" immediately after IPv6 literal "]"`)
	}
	afterColon := afterBracket[1:]
	portEnd := strings.IndexByte(afterColon, ':')
	var portStr, tail string
	if portEnd == -1 {
		portStr = afterColon
	} else {
		portStr = afterColon[:portEnd]
		tail = afterColon[portEnd:] // includes its own leading ":"
	}
	if portStr == "" {
		return solo.PortConfig{}, errors.New("missing port after IPv6 literal")
	}
	if _, err := strconv.ParseUint(portStr, 10, 32); err != nil {
		return solo.PortConfig{}, fmt.Errorf("invalid port %q after IPv6 literal: %w", portStr, err)
	}
	address := raw[:closeIdx+1] + ":" + portStr

	fields := strings.Split(strings.TrimPrefix(tail, ":"), ":")
	if tail == "" {
		fields = nil
	}

	var tlsEnabled bool
	if len(fields) > 0 && strings.EqualFold(fields[len(fields)-1], "tls") {
		tlsEnabled = true
		fields = fields[:len(fields)-1]
	}

	var (
		difficulty uint64
		desc       string
		err        error
	)
	switch len(fields) {
	case 1:
		if difficulty, err = strconv.ParseUint(fields[0], 10, 64); err != nil {
			return solo.PortConfig{}, fmt.Errorf("invalid difficulty: %w", err)
		}
	case 2:
		if difficulty, err = strconv.ParseUint(fields[0], 10, 64); err != nil {
			return solo.PortConfig{}, fmt.Errorf("invalid difficulty: %w", err)
		}
		desc = fields[1]
	default:
		return solo.PortConfig{}, errors.New(`expected "[addr]:port:difficulty", "[addr]:port:difficulty:desc", or either with a trailing ":tls"`)
	}
	if difficulty == 0 {
		return solo.PortConfig{}, errors.New("difficulty must be > 0")
	}
	return solo.PortConfig{Address: address, Difficulty: difficulty, PortDesc: desc, TLS: tlsEnabled}, nil
}

// setupDevFee wires cmd/leaf-proxy's optional dev-fee mechanism
// (-dev-fee-percent/LEAF_PROXY_DEV_FEE_PERCENT) into jobManager --
// see internal/leaflib/proxy/devfee.go's package-level doc comment
// for the full design, including the real legacy xmr-node-proxy
// reference this is a deliberate, documented simplification of.
//
// Returns the constructed, already-Connect()-ed dev-fee
// *proxy.UpstreamClient so main() can wire it into
// Server.EnableDevFeeUpstream and defer its Close, or (nil, nil) when
// cfg.devFeePercent <= 0 -- a COMPLETE no-op: this function does not
// even construct a proxy.UpstreamClient, let alone dial one, in that
// case (see TestSetupDevFee_ZeroPercentIsANoOp in main_test.go). A
// genuine dial/login failure for the dev-fee connection is returned
// as an error (main() treats it as fatal, matching how a failed
// PRIMARY upstream connect is already handled) rather than silently
// degrading to "dev-fee disabled" -- an operator who explicitly
// configured a non-zero -dev-fee-percent should be told loudly if
// the second connection this promises could not actually be
// established, not have it silently vanish.
func setupDevFee(ctx context.Context, cfg config, logger *log.Logger, debugLogger *leaflib.DebugLogger, jobManager *proxy.JobManager) (*proxy.UpstreamClient, error) {
	if cfg.devFeePercent <= 0 {
		return nil, nil
	}
	logger.Printf("dev-fee mechanism ENABLED at %v%% (-dev-fee-percent) -- opening a SECOND upstream connection to %s:%d under a hardcoded (not operator-configurable) dev-fee login; see internal/leaflib/proxy/devfee.go's doc comment for the full mechanism", cfg.devFeePercent, cfg.upstreamHost, cfg.upstreamPort)
	devFeeUpstream := proxy.NewDevFeeUpstreamClient(proxy.UpstreamConfig{
		Host:                  cfg.upstreamHost,
		Port:                  cfg.upstreamPort,
		TLS:                   cfg.upstreamTLS,
		InsecureSkipVerifyTLS: cfg.upstreamInsecure,
		Agent:                 cfg.upstreamAgent,
		DialTimeout:           cfg.dialTimeout,
		IdleTimeout:           cfg.idleTimeout,
		RequestTimeout:        cfg.requestTimeout,
	}, logger)
	devFeeUpstream.SetDebugLogger(debugLogger)
	if err := devFeeUpstream.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connecting dev-fee upstream connection: %w", err)
	}
	jobManager.EnableDevFee(devFeeUpstream, proxy.NewDevFeeSelector(cfg.devFeePercent))
	tmpl := devFeeUpstream.CurrentTemplate()
	logger.Printf("dev-fee upstream connection established: session_id=%s height=%d", devFeeUpstream.SessionID(), tmpl.Height)
	return devFeeUpstream, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("leaf-proxy: %v", err)
	}
	logger := log.New(os.Stdout, "leaf-proxy: ", log.LstdFlags|log.Lmicroseconds)

	// debugLogger is constructed exactly once per process (never a
	// global/package-level singleton -- see
	// internal/leaflib/debuglog.go's doc comment) and threaded down
	// via Server.SetDebugLogger and UpstreamClient.SetDebugLogger
	// below.
	//
	// DISPATCH_BRIEF.md "log levels": -log-level=2 (verbose) folds
	// -debug's own [DEBUG]-tagged output in too, so the underlying
	// "enabled" flag Debugf checks is true whenever EITHER cfg.debug
	// OR the already-resolved cfg.logLevel (see resolveLogLevel,
	// called by loadConfig above -- cfg.logLevel is never the
	// logLevelUnset sentinel by this point) is 2. -debug alone
	// keeps working exactly as it already does (this is additive,
	// not a replacement: cfg.debug==true always sets enabled=true
	// here regardless of logLevel). debugLogger.Level is set
	// separately, right after construction, since only this leaf's
	// own Logf call sites (session.go's quiet-mode-gated noise
	// lines, and this file's own hashrate-report ticker below)
	// consult it.
	debugEnabled := cfg.debug || cfg.logLevel >= 2
	debugLogger := leaflib.NewDebugLogger(logger, debugEnabled)
	debugLogger.Level = cfg.logLevel
	if cfg.debug {
		logger.Print("debug logging ENABLED (-debug/LEAF_PROXY_DEBUG) -- verbose [DEBUG]-tagged output follows for downstream submits, validation, upstream forwarding, template lifecycle, connection lifecycle, and vardiff retargets")
	}
	logger.Printf("log level set to %d (0=quiet, 1=normal, 2=verbose -- see -log-level/LEAF_PROXY_LOG_LEVEL)", cfg.logLevel)

	if cfg.upstreamLogin == "" {
		logger.Fatal("LEAF_PROXY_UPSTREAM_LOGIN (or -upstream-login) is required: a real XMR payout address to log in to the upstream pool with")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger.Printf("connecting to real upstream pool %s:%d (tls=%v) as agent %q", cfg.upstreamHost, cfg.upstreamPort, cfg.upstreamTLS, cfg.upstreamAgent)
	upstream := proxy.NewUpstreamClient(proxy.UpstreamConfig{
		Host:                  cfg.upstreamHost,
		Port:                  cfg.upstreamPort,
		TLS:                   cfg.upstreamTLS,
		InsecureSkipVerifyTLS: cfg.upstreamInsecure,
		Login:                 cfg.upstreamLogin,
		Pass:                  cfg.upstreamPass,
		Agent:                 cfg.upstreamAgent,
		DialTimeout:           cfg.dialTimeout,
		IdleTimeout:           cfg.idleTimeout,
		RequestTimeout:        cfg.requestTimeout,
	}, logger)
	upstream.SetDebugLogger(debugLogger)

	if err := upstream.Connect(ctx); err != nil {
		logger.Fatalf("failed to connect/login to upstream pool: %v", err)
	}
	defer upstream.Close()

	tmpl := upstream.CurrentTemplate()
	logger.Printf("upstream login succeeded: session_id=%s height=%d reserved_offset=%d client_nonce_offset_present=%v target_diff=%d seed_hash=%s",
		upstream.SessionID(), tmpl.Height, tmpl.ReservedOffset, tmpl.ClientNonceOffset >= 0, tmpl.TargetDiff, tmpl.SeedHashHex())

	jobManager := proxy.NewJobManager(upstream, logger)

	// Optional developer-fee mechanism (-dev-fee-percent/
	// LEAF_PROXY_DEV_FEE_PERCENT, default 1.0) -- see setupDevFee's
	// own doc comment and internal/leaflib/proxy/devfee.go's
	// package-level doc comment for the full design. A COMPLETE
	// no-op (devFeeUpstream stays nil, nothing else below changes
	// behavior at all) when cfg.devFeePercent <= 0.
	devFeeUpstream, err := setupDevFee(ctx, cfg, logger, debugLogger, jobManager)
	if err != nil {
		logger.Fatalf("failed to set up dev-fee mechanism: %v", err)
	}
	if devFeeUpstream != nil {
		defer devFeeUpstream.Close()
	}

	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{
		MaxConnections: cfg.maxConnections,
		IdleTimeout:    cfg.idleTimeout,
	})

	// Real, in-process, pure-Go RandomX validator -- NO external
	// randomx-service HTTP daemon dependency. leaf-proxy's local
	// re-validation gate (internal/leaflib/proxy/session.go's
	// handleSubmit) only calls ValidateBlobSeedResult on a genuine
	// block-level find (a submit that already meets the real upstream
	// pool's block target), not on every ordinary sub-block share -- at
	// that call frequency, pure-Go RandomX's real ~258ms/hash cost
	// (benchmarked separately, git.gammaspectra.live/P2Pool/go-randomx
	// @v1.0.0) is genuinely acceptable, and removing the external
	// daemon dependency simplifies leaf-proxy's deployment. See
	// internal/leaflib/validator/randomx_puregolang.go's doc comment
	// for the full honest writeup, including why leaf-solo's RXT
	// support (a real per-share hot path) still uses the external-
	// daemon-backed RandomXValidator instead.
	rxValidator := validator.NewPureGoRandomXValidator()

	vardiffCfg := leaflib.VardiffConfig{
		MinDifficulty:    cfg.minDifficulty,
		MaxDifficulty:    cfg.maxDifficulty,
		TargetTime:       cfg.vardiffTargetTime,
		RetargetInterval: cfg.vardiffInterval,
	}

	server := proxy.NewServer(cm, jobManager, rxValidator, upstream, logger, vardiffCfg, cfg.jobMaxAge)
	defer server.Shutdown()

	if devFeeUpstream != nil {
		server.EnableDevFeeUpstream(devFeeUpstream)
	}

	server.SetDebugLogger(debugLogger)

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2a): worker
	// count is runtime.NumCPU() by DEFAULT (proxy.NewServer's own
	// construction already applies this), not a hardcoded literal 8;
	// an operator who wants a different fixed count can still get one
	// via -randomx-workers. Queue size DEFAULTS to
	// solo.DefaultAsyncValidationQueueSize(workers) (max(256,
	// workers*16)) -- scales with the pool's own real worker count
	// instead of the old flat 256 literal; an operator who wants a
	// different fixed queue size can still get one via
	// -randomx-queue-size.
	if cfg.randomxWorkers > 0 || cfg.randomxQueueSize > 0 {
		server.SetRandomXWorkerPoolSize(cfg.randomxWorkers, cfg.randomxQueueSize)
		logger.Printf("RandomX async validation worker pool size overridden to %d (default would have been runtime.NumCPU()=%d), queue size overridden to %d (0 means the documented default, max(256, workers*16), is in effect)", cfg.randomxWorkers, runtime.NumCPU(), cfg.randomxQueueSize)
	}

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b): disconnect
	// a downstream session after too many consecutive real RandomX
	// validation failures. Enabled by default.
	server.SetInvalidShareGuardConfig(leaflib.InvalidShareGuardConfig{
		Enabled:   cfg.invalidShareDisconnectEnabled,
		Threshold: cfg.invalidShareDisconnectThreshold,
	})
	if cfg.invalidShareDisconnectEnabled {
		logger.Printf("consecutive-invalid-share disconnect guard ENABLED (threshold=%d -- 0 means the documented default is in effect)", cfg.invalidShareDisconnectThreshold)
	} else {
		logger.Printf("consecutive-invalid-share disconnect guard DISABLED by operator config")
	}

	// DISPATCH_BRIEF.md 2026-09-13 (Alex): toggle for the login-time
	// pool-target-diff cap (commit 46a6e2c). Enabled by default; an
	// operator with reasonable starting points who genuinely wants
	// the pre-46a6e2c uncapped max()-of-floors behavior can opt out
	// via -pool-diff-cap-enabled=false.
	server.SetPoolDiffCapEnabled(cfg.poolDiffCapEnabled)
	if cfg.poolDiffCapEnabled {
		logger.Printf("pool-target-diff login cap ENABLED (-pool-diff-cap-enabled) -- none of the three difficulty floors may start a session above the upstream pool's own current target_diff")
	} else {
		logger.Printf("pool-target-diff login cap DISABLED by operator config (-pool-diff-cap-enabled=false) -- falling back to the pre-46a6e2c uncapped max()-of-floors behavior")
	}

	// DISPATCH_BRIEF_MIN_SHARE_FILTER.md: opt-in min-1-share metrics
	// filter. Set unconditionally (NOT gated behind
	// cfg.metricsListenAddress != "" like SetHideRemoteAddress/
	// SetStatsPageMaxSessions below) because Stats() -- the surface
	// this toggles -- is also consumed by -stats-db-path's
	// SampleForStatsDB sampling loop (wired below, independent of
	// whether the metrics HTTP server is enabled at all), not just
	// the HTML/metrics endpoints. Default false (today's exact
	// existing unfiltered behavior).
	server.SetMetricsMinSharesFilter(cfg.metricsMinSharesFilter)
	if cfg.metricsMinSharesFilter {
		logger.Printf("metrics min-1-share filter ENABLED (-metrics-min-shares-filter) -- a session that has never submitted a share is excluded from every metrics/stats surface (Stats(), the stats HTML page, /api/miners, and the Prometheus snapshot-derived metrics)")
	}

	// Real, manual ban enforcement (see internal/leaflib/addressflags's
	// package doc comment). Disabled (server.addressFlags stays nil)
	// unless -address-flags-file/LEAF_PROXY_ADDRESS_FLAGS_FILE is set
	// -- leaf-proxy has no go-crypto-pool backend to poll instead, so
	// a local file is the only real Source, mirroring cmd/leaf-solo's
	// identical wiring exactly.
	if cfg.addressFlagsFile != "" {
		flagsCache := addressflags.NewCache(addressflags.NewFileSource(cfg.addressFlagsFile), cfg.addressFlagsPollInterval, logger)
		flagsCache.Start(ctx)
		server.EnableAddressFlags(flagsCache)
		logger.Printf("manual ban enforcement ENABLED, polling %s every %s", cfg.addressFlagsFile, cfg.addressFlagsPollInterval)
	}

	// DISPATCH_BRIEF.md section 5 ("24h stats retention"), Alex's own
	// framing: "Likely a local loop and/or a small SQLite DB - Used
	// for basic miner tracking". Disabled entirely (statsDB stays
	// nil, no background loop ever starts) unless -stats-db-path/
	// LEAF_PROXY_STATS_DB_PATH is non-empty. See
	// internal/leaflib/proxy/statsdb.go's package doc comment for
	// the full scope/design.
	var statsDB *proxy.StatsDB
	if cfg.statsDBPath != "" {
		db, err := proxy.OpenStatsDB(cfg.statsDBPath, logger)
		if err != nil {
			logger.Fatalf("failed to open -stats-db-path %s: %v", cfg.statsDBPath, err)
		}
		statsDB = db
		defer statsDB.Close()
		go statsDB.RunSampleLoop(ctx, cfg.statsSampleInterval, server.SampleForStatsDB)
		logger.Printf("24h stats retention ENABLED at %s, sampling every %s (GET /api/miners/history?address=<addr> once the metrics HTTP server, below, is also enabled)", cfg.statsDBPath, cfg.statsSampleInterval)
	}

	// DISPATCH_BRIEF_HASHRATE_API_FOLLOWUP.md section 1, Alex's own
	// ask verbatim: "for the foreground hashrate ticker, show it at
	// all log levels, make it a 30 second print no matter what."
	// This ticker is now ALWAYS active -- there is no flag/env/TOML
	// key to disable it or change its period (the former
	// -hashrate-report-interval/LEAF_PROXY_HASHRATE_REPORT_INTERVAL/
	// hashrate_report_interval_seconds has been removed entirely,
	// not deprecated-to-no-op). The interval is hardcoded to exactly
	// 30 seconds below. The summary line is printed via logger.
	// Printf directly -- deliberately NOT debugLogger.Logf/Debugf or
	// any -log-level check -- so it is unconditional and prints at
	// EVERY log level, including -log-level=0 (quiet). This is a
	// deliberate, intentional exception to the "quiet means quiet"
	// rule the rest of this leaf's noise-gating follows; do not
	// "fix" this by adding a level check back in.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logger.Printf("%s", server.HashrateReportSummary())
			}
		}
	}()
	logger.Printf("foreground hashrate report ENABLED, fixed 30s interval, printed at every log level (not gated by -log-level)")

	// Real Prometheus /metrics + basic stats HTML page, exactly
	// mirroring cmd/leaf-solo/main.go's already-working
	// EnableMetrics/MetricsHandler/StatsHTMLHandler wiring pattern
	// (see that file for the reference implementation this was
	// ported from) -- ported unchanged aside from the LEAF_PROXY_
	// flag/env prefix and leaf-proxy's own metrics.Metrics type.
	//
	// DISPATCH_BRIEF.md section 1 ("password-protected metrics, xnp
	// style"), Alex's own ask: "This would be the entire metrics
	// endpoint, including the status panel, should default to off".
	// Every handler registered on metricsMux below (/metrics, /,
	// /api/miners, and -- when -stats-db-path is also set --
	// /api/miners/history) is wrapped ONCE, as the very last step
	// before constructing metricsSrv, in WrapMetricsAuth
	// (metricsauth.go): a complete no-op when -metrics-password is
	// empty (the default), or an HTTP Basic Auth gate requiring
	// -metrics-username/-metrics-password once a non-empty password
	// is configured.
	//
	// DISPATCH_BRIEF.md section 4 ("miner-stats JSON API"), Alex's
	// own ask: "API for miner stats - The metrics panel is
	// semi-limited in this, though it's fine for normal stats for
	// the proxy (Overall/live view)". GET /api/miners is registered
	// unconditionally alongside /metrics and / (it costs nothing
	// when unused, exactly like those two already did before this
	// pass).
	if cfg.metricsListenAddress != "" {
		server.SetHideRemoteAddress(cfg.hideRemoteAddress)
		server.SetStatsPageMaxSessions(cfg.statsPageMaxSessions)
		server.EnableMetrics(version, cfg.maxAddressLabels)
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", server.MetricsHandler())
		metricsMux.Handle("/", server.StatsHTMLHandler())
		metricsMux.Handle("/api/miners", server.MinersJSONHandler())
		if statsDB != nil {
			metricsMux.Handle("/api/miners/history", proxy.MinersHistoryHandler(statsDB))
		}
		var metricsHandler http.Handler = metricsMux
		if cfg.metricsPassword != "" {
			metricsHandler = proxy.WrapMetricsAuth(metricsMux, cfg.metricsUsername, cfg.metricsPassword)
			logger.Printf("metrics/stats HTTP server is PASSWORD-PROTECTED (-metrics-password set) -- HTTP Basic Auth required on every endpoint (username %q)", cfg.metricsUsername)
		} else {
			logger.Printf("metrics/stats HTTP server has NO password configured (-metrics-password is empty) -- every endpoint is open, matching this leaf's pre-existing default behavior")
		}
		metricsSrv := &http.Server{Addr: cfg.metricsListenAddress, Handler: metricsHandler}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Printf("metrics/stats HTTP server error: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
		logger.Printf("serving /metrics and stats page on %s", cfg.metricsListenAddress)
	} else {
		logger.Printf("metrics/stats HTTP server disabled (-metrics-listen-address is empty)")
	}

	// portsExplicitlySet mirrors cmd/leaf-direct's -ports/-tls-*
	// mutual-exclusivity check (see -ports' and -tls-listen-address's
	// own doc comments above for the full rationale): when -ports is
	// explicitly set, -tls-listen-address is no longer consulted at
	// all -- an operator setting BOTH is a fatal startup
	// misconfiguration rather than either flag being silently
	// ignored.
	portsExplicitlySet := strings.TrimSpace(cfg.portsRaw) != ""
	if portsExplicitlySet && cfg.tlsListenAddress != "" {
		logger.Fatalf("-ports/LEAF_PROXY_PORTS and -tls-listen-address/LEAF_PROXY_TLS_LISTEN_ADDRESS cannot both be set: -ports' own per-tier \":tls\" marker is now the general mechanism for a TLS-enabled listener -- move any TLS tier into a -ports entry (e.g. \"0.0.0.0:5556:1000:tls\") instead of also setting -tls-listen-address")
	}

	ports, err := resolvePorts(cfg)
	if err != nil {
		logger.Fatalf("invalid port configuration: %v", err)
	}

	// -tls-listen-address, when set, is ONLY ever added here -- in
	// the old single-tier fallback path (-ports unset) -- as a
	// second, TLS-enabled port tier alongside the implicit
	// listenAddress/startingDifficulty tier resolvePorts already
	// returned above. This preserves byte-for-byte the exact
	// pre-existing behavior for every deployment that doesn't use
	// -ports.
	if !portsExplicitlySet && cfg.tlsListenAddress != "" {
		ports = append(ports, solo.PortConfig{Address: cfg.tlsListenAddress, Difficulty: cfg.startingDifficulty, PortDesc: "tls", TLS: true})
	}

	for _, p := range ports {
		desc := p.PortDesc
		if desc == "" {
			desc = "-"
		}
		logger.Printf("port tier: address=%s starting-difficulty=%d desc=%s", p.Address, p.Difficulty, desc)
	}

	listeners := make([]net.Listener, 0, len(ports))

	// One shared tls.Certificate for the whole process (see
	// internal/leaflib.LoadOrGenerateCert's doc comment) -- only
	// constructed at all if at least one resolved port tier has TLS
	// enabled. If no port has TLS enabled, this is skipped entirely:
	// no behavior change, no wasted work, matching "TLS is fully
	// optional" (see -ports'/-tls-listen-address's own doc
	// comments).
	var tlsCert tls.Certificate
	var tlsConfigured bool
	for _, p := range ports {
		if p.TLS {
			tlsConfigured = true
			break
		}
	}
	if tlsConfigured {
		cert, err := leaflib.LoadOrGenerateCert(cfg.tlsCertFile, cfg.tlsKeyFile, cfg.tlsCertPersistPath, cfg.listenAddress, logger)
		if err != nil {
			logger.Fatalf("failed to load/generate shared TLS certificate: %v", err)
		}
		tlsCert = cert
	}

	for _, p := range ports {
		ln, err := net.Listen("tcp", p.Address)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			logger.Fatalf("failed to listen on %s: %v", p.Address, err)
		}
		if p.TLS {
			ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{tlsCert}})
			logger.Printf("listening for downstream miners on %s (TLS) (starting difficulty %d)", p.Address, p.Difficulty)
		} else {
			logger.Printf("listening for downstream miners on %s (starting difficulty %d)", p.Address, p.Difficulty)
		}
		listeners = append(listeners, ln)
	}

	errCh := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for i, ln := range listeners {
		wg.Add(1)
		go func(ln net.Listener, port solo.PortConfig) {
			defer wg.Done()
			errCh <- server.Serve(ctx, ln, port)
		}(ln, ports[i])
	}

	select {
	case <-ctx.Done():
		logger.Println("shutdown signal received, draining connections...")
		for _, ln := range listeners {
			_ = ln.Close()
		}
		cm.Shutdown()
	case err := <-errCh:
		if err != nil {
			logger.Fatalf("listener error: %v", err)
		}
	}
}
