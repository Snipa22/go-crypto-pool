// Command leaf-solo is the leaf binary for mode 2: standalone solo
// mining (no backend). See AGENTS.md / architecture: leaf-direct
// submits shares to the backend, leaf-solo does not — there is no
// share-forwarding to a backend anywhere in this binary. A miner
// connects over a minimal JSON-line TCP protocol (see
// internal/leaflib/solo/protocol.go), receives a real SHA3X block
// template fetched from a real Tari base node over GRPC, and submits
// nonces. Every submission is validated for real via the already-merged
// internal/leaflib/validator.SHA3XValidator; a submission that also
// meets the real network's full block target difficulty gets submitted
// to the base node for real via GRPC SubmitBlock. Accepted shares below
// block difficulty are only a local diagnostic/hashrate-estimation
// counter — solo mode has no share table and no payout scheme.
//
// Known simplification, now REMOVED: difficulty used to be static and
// leaf-configured (LEAF_SOLO_DIFFICULTY / -difficulty). Real per-session
// vardiff (adaptive difficulty retargeting, ported from
// go-tari-sha3x-solo-stratum's minerStruct.NewDiff) is now implemented
// — see internal/leaflib/solo/vardiff.go. Every session starts at
// LEAF_SOLO_STARTING_DIFFICULTY and its own per-connection retarget
// loop independently adjusts it from there based on that session's own
// accept history.
//
// Also REMOVED: the single-listener/single-starting-difficulty model.
// leaf-solo now supports any number of simultaneous stratum "port
// tiers" (internal/leaflib/solo/portconfig.go's PortConfig) — each a
// (listen address, starting difficulty, operator label) triple, all
// sharing the SAME JobManager/ConnectionManager/NodeClient/validator
// (one backend node connection, one set of per-xn job templates,
// exposed on multiple ports). See LEAF_SOLO_PORTS / -ports below;
// LEAF_SOLO_LISTEN_ADDRESS + LEAF_SOLO_STARTING_DIFFICULTY remain
// fully supported as the implicit single-tier configuration when
// LEAF_SOLO_PORTS is unset, so the already-deployed CT132
// leaf-solo.service (which only knows the old single-value env vars)
// keeps working unmodified.
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
	monerozmq "github.com/Snipa22/go-crypto-pool/internal/leaflib/monero/zmq"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// version is a build-time-overridable identifier surfaced on the
// leaf_solo_build_info metric and the stats page — override via
// -ldflags "-X main.version=...", e.g. from a CI tag; "dev" is the
// honest fallback for a local/untagged build.
var version = "dev"

type config struct {
	nodeGRPCAddress string
	listenAddress   string
	payoutAddress   string
	network         string

	// coin selects which coin/PoW family this leaf-solo process talks
	// to for its block source: "tari" (default, unchanged behavior --
	// GRPCNodeClient against a real Tari base node) or "monero" (a
	// real MoneroNodeClient against a real monerod JSON-RPC daemon --
	// see monerodURL below). This governs NodeClient construction and
	// forces algo to ALGO_RXM below; it does NOT touch the wire
	// protocol layer at all (protocol.go's JSON-RPC 2.0 dialect is
	// already Monero-compatible).
	coin string

	// monerodURL is the real monerod JSON-RPC base URL (e.g.
	// "http://148.163.90.157:28081") this leaf talks to when
	// -coin/LEAF_SOLO_COIN is "monero". Ignored/unused for coin=tari.
	// REQUIRED when coin=monero -- see main's own validation.
	monerodURL string

	// randomxWorkers overrides the RandomX-family (RXT/RXM) async
	// validation worker pool's size (see
	// internal/leaflib/solo/asyncvalidation.go's doc comment). 0
	// (the default) means "use DefaultAsyncValidationWorkers()
	// (runtime.NumCPU())" -- see DISPATCH_BRIEF.md, 2026-09-10, Fix
	// 2a: this used to be a hardcoded literal 8 with no operator
	// override at all.
	randomxWorkers int

	// invalidShareDisconnectEnabled/invalidShareDisconnectThreshold
	// configure leaflib.InvalidShareGuard (see that type's doc
	// comment for the full DISPATCH_BRIEF.md 2026-09-10 Fix 2b
	// rationale): a session whose real RandomX-family block-find-
	// level validation fails this many times CONSECUTIVELY is
	// disconnected. Enabled by DEFAULT (unlike trust, this is a
	// security-hardening default, not an opt-in throughput
	// tradeoff) -- an operator can disable it entirely via
	// -invalid-share-disconnect-enabled=false. Threshold 0/unset
	// uses the documented default (see
	// leaflib.DefaultInvalidShareGuardConfig).
	invalidShareDisconnectEnabled   bool
	invalidShareDisconnectThreshold int

	// algo selects which SINGLE mining algorithm this leaf-solo
	// process serves: "sha3x" (default), "c29", or "rxt" -- for
	// coin=tari only. See loadConfig's LEAF_SOLO_ALGO doc comment for
	// why a simple single-algo-per-process flag was chosen over
	// per-port algo selection for this pass, and why leaving it unset
	// preserves the already-deployed CT132 leaf-solo.service's
	// SHA3X-only behavior exactly. When coin=monero, this flag's
	// value is ignored entirely -- Monero has genuinely only one algo
	// (plain RandomX/rx), so algoFromString always returns ALGO_RXM
	// for coin=monero regardless of what -algo is set to (see
	// resolveAlgo below).
	algo string

	// randomXServiceURL is the RandomX-verification HTTP daemon address
	// (github.com/Snipa22/go-xmr-lib's hashValidation.RXVerifier — see
	// internal/leaflib/validator/randomx.go) this leaf's RandomXValidator
	// talks to for RXT (and, if ever configured for it, RXM) shares.
	// Only actually consulted when -algo/LEAF_SOLO_ALGO is "rxt" — for
	// sha3x/c29 leaves the registry's RXT/RXM entries are built but
	// never invoked. Defaults to the real, locally-running daemon this
	// pass was tested against (http://127.0.0.1:39093).
	randomXServiceURL string

	// coinbaseExtraTag is -coinbase-extra-tag / LEAF_SOLO_COINBASE_EXTRA_TAG:
	// an explicit operator override for the coinbase-extra ownership
	// tag appended to every fetched Tari block template (see
	// internal/leaflib/solo/node.go's GRPCNodeClient.coinbaseExtraTag).
	// Left empty (the default), resolveCoinbaseExtraTag computes a
	// per-algo default instead ("supportxtm-sha3x"/"supportxtm-c29"/
	// "supportxtm-rxt"/"supportxtm-rxm") from whichever algo/coin this
	// process is actually configured for (see resolveAlgo/isMoneroCoin)
	// — a single blended tag across every algo/process defeats
	// per-algo on-chain attribution, which is the whole point of this
	// flag existing. When set, this value is used VERBATIM, overriding
	// the per-algo default entirely.
	coinbaseExtraTag string

	startingDifficulty uint64
	portsRaw           string
	minDifficulty      uint64
	maxDifficulty      uint64
	vardiffTargetTime  int
	vardiffInterval    time.Duration

	// tlsCertFile / tlsKeyFile / tlsCertPersistPath mirror
	// leaf-direct's identical trio exactly (see that binary's config
	// struct doc comment for the full design rationale) -- only ever
	// consulted if at least one -ports/LEAF_SOLO_PORTS entry carries
	// the ":tls" suffix (see parsePortEntry). If no port has TLS
	// enabled, none of these three are touched at all.
	tlsCertFile        string
	tlsKeyFile         string
	tlsCertPersistPath string

	refreshInterval time.Duration
	tipPollInterval time.Duration
	jobMaxAge       time.Duration

	maxConnections int
	idleTimeout    time.Duration

	metricsListenAddress string
	maxAddressLabels     int

	// hideRemoteAddress, when true, tells the stats HTML page to
	// omit the "Remote address" column entirely (see
	// solo.Server.SetHideRemoteAddress). Defaults to false --
	// preserves the existing page unless an operator explicitly
	// opts in.
	hideRemoteAddress bool

	// addressFlagsFile / addressFlagsPollInterval configure the real,
	// manual ban/forced-minimum-difficulty enforcement described in
	// internal/leaflib/addressflags's package doc comment.
	// addressFlagsFile empty (the default) disables the feature
	// entirely -- leaf-solo has no backend to poll instead (see this
	// binary's own doc comment: "there is no share-forwarding to a
	// backend anywhere in this binary"), so this local, operator-
	// maintained JSON file is the only real Source available to it.
	addressFlagsFile         string
	addressFlagsPollInterval time.Duration

	// relayNATSURL / relaySubject / templateRelaySubject configure the
	// SAME internal/leaflib/relay.Relay type leaf-direct already uses
	// for its found-block broadcast -- leaf-solo has no found-block
	// broadcast use case of its own (BlockMessage/Publish/Subscribe
	// simply go unused here), but it now needs a *relay.Relay purely
	// for the template-relay feature (see solo.JobManagerConfig.Relay
	// and job.go's tipPollLoop/Start wiring): a sibling leaf-solo (or
	// leaf-direct) instance's own tip-poll finding a new height can
	// invalidate THIS instance's per-xn job cache immediately, instead
	// of waiting for this instance's own next tip-poll tick.
	// relayNATSURL empty (the default) disables the relay entirely --
	// a complete no-op, never required, matching every other optional
	// feature's contract in this repo.
	relayNATSURL         string
	relaySubject         string
	templateRelaySubject string

	// relayNATSUsername/relayNATSPassword are
	// -relay-nats-username/-relay-nats-password
	// (LEAF_SOLO_RELAY_NATS_USERNAME/LEAF_SOLO_RELAY_NATS_PASSWORD):
	// optional NATS username/password auth (mirrors nats.UserInfo --
	// see relay.Config.Username/Password's doc comment). Both empty
	// (the default) preserves today's plaintext-no-auth connect
	// behavior byte-for-byte. relayNATSPassword is a plain string
	// secret, never logged.
	relayNATSUsername string
	relayNATSPassword string

	// relayNATSTLSCAFile/relayNATSTLSCertFile/relayNATSTLSKeyFile are
	// -relay-nats-tls-ca-file/-relay-nats-tls-cert-file/
	// -relay-nats-tls-key-file
	// (LEAF_SOLO_RELAY_NATS_TLS_CA_FILE/
	// LEAF_SOLO_RELAY_NATS_TLS_CERT_FILE/
	// LEAF_SOLO_RELAY_NATS_TLS_KEY_FILE): optional TLS options for
	// the NATS connection (mirrors nats.RootCAs/nats.ClientCert --
	// see relay.Config's own doc comment). All empty (the default)
	// appends no TLS option at all.
	relayNATSTLSCAFile   string
	relayNATSTLSCertFile string
	relayNATSTLSKeyFile  string

	// moneroZMQURL is -monero-zmq-url / LEAF_SOLO_MONERO_ZMQ_URL: the
	// real monerod ZMQ endpoint (e.g. "tcp://127.0.0.1:28082") for an
	// ADDITIONAL, faster block-invalidation trigger on top of the
	// existing tip-poll baseline (see internal/leaflib/monero/zmq).
	// Empty (the default) disables this entirely -- a complete no-op,
	// never dialed. Ignored entirely for -coin=tari.
	moneroZMQURL string

	// configFile is the optional path to a TOML file providing
	// defaults for any flag above that the operator did not set
	// explicitly via CLI flag or environment variable. See
	// leaf-solo.example.toml and internal/leaflib/cfgfile for the
	// exact precedence rule (flag > env > file > hardcoded default).
	configFile string

	// debug is -debug/LEAF_SOLO_DEBUG: enables the shared
	// leaflib.DebugLogger (internal/leaflib/debuglog.go) for this
	// process. OFF (false) by default -- purely additive when
	// enabled, and produces byte-identical log output to the
	// pre-existing behavior when left off (see that file's doc
	// comment). Wired into solo.Server via
	// Server.SetDebugLogger below, which threads it down to every
	// Session this process creates.
	debug bool
}

func loadConfig() (config, error) {
	cfg := config{}

	flag.StringVar(&cfg.nodeGRPCAddress, "node-grpc-address", envOr("LEAF_NODE_GRPC_ADDRESS", ""), "Tari base node GRPC address (host:port). REQUIRED when -coin=tari (the default); ignored for -coin=monero. Env: LEAF_NODE_GRPC_ADDRESS")
	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_SOLO_LISTEN_ADDRESS", ":4444"), "miner-facing TCP listen address. Env: LEAF_SOLO_LISTEN_ADDRESS")
	flag.StringVar(&cfg.payoutAddress, "payout-address", envOr("LEAF_SOLO_PAYOUT_ADDRESS", ""), "solo payout address; found-block coinbase rewards go here. Env: LEAF_SOLO_PAYOUT_ADDRESS")
	flag.StringVar(&cfg.network, "network", envOr("LEAF_SOLO_NETWORK", "testnet"), "network tag for share/diagnostic records: mainnet|testnet. Env: LEAF_SOLO_NETWORK")
	flag.StringVar(&cfg.coin, "coin", envOr("LEAF_SOLO_COIN", "tari"), "which coin/PoW family this leaf-solo process serves: tari (default, unchanged behavior) or monero (real MoneroNodeClient against a real monerod JSON-RPC daemon -- see -monerod-url). Env: LEAF_SOLO_COIN")
	flag.StringVar(&cfg.monerodURL, "monerod-url", envOr("LEAF_SOLO_MONEROD_URL", ""), "real monerod JSON-RPC base URL (e.g. http://148.163.90.157:28081), no trailing slash or /json_rpc suffix required. REQUIRED when -coin=monero; ignored for -coin=tari. For RXM/merge-mining, point this at your local minotari_merge_mining_proxy listener, NOT raw monerod directly -- pointing at raw monerod will mine Monero-only with no Tari merge-mine revenue. Env: LEAF_SOLO_MONEROD_URL")
	flag.IntVar(&cfg.randomxWorkers, "randomx-workers", envOrInt("LEAF_SOLO_RANDOMX_WORKERS", 0), "RandomX-family (RXT/RXM) async validation worker pool size (see internal/leaflib/solo/asyncvalidation.go). 0/unset uses the documented default, runtime.NumCPU() -- NOT a hardcoded literal. Env: LEAF_SOLO_RANDOMX_WORKERS")
	flag.BoolVar(&cfg.invalidShareDisconnectEnabled, "invalid-share-disconnect-enabled", envOr("LEAF_SOLO_INVALID_SHARE_DISCONNECT_ENABLED", "true") == "true", "disconnect a session after too many CONSECUTIVE real RandomX-family (RXT/RXM) block-find-level validation failures (see internal/leaflib.InvalidShareGuard) -- a security-hardening default, enabled unless explicitly turned off. Env: LEAF_SOLO_INVALID_SHARE_DISCONNECT_ENABLED (\"false\" to disable)")
	flag.IntVar(&cfg.invalidShareDisconnectThreshold, "invalid-share-disconnect-threshold", envOrInt("LEAF_SOLO_INVALID_SHARE_DISCONNECT_THRESHOLD", 0), "consecutive-invalid-share threshold before a session is disconnected (see -invalid-share-disconnect-enabled). 0/unset uses the documented default (20). Env: LEAF_SOLO_INVALID_SHARE_DISCONNECT_THRESHOLD")
	flag.StringVar(&cfg.algo, "algo", envOr("LEAF_SOLO_ALGO", "sha3x"), "which single mining algorithm this leaf-solo process serves: sha3x (default), c29, or rxt -- for -coin=tari only. Ignored (always ALGO_RXM/plain RandomX) when -coin=monero. Env: LEAF_SOLO_ALGO")
	flag.StringVar(&cfg.randomXServiceURL, "randomx-service-url", envOr("LEAF_SOLO_RANDOMX_SERVICE_URL", "http://127.0.0.1:39093"), "RandomX-verification HTTP daemon address (consulted for -algo=rxt, and for -coin=monero's real RandomX/rx validation -- both share the same real randomx-service-backed RandomXValidator). Env: LEAF_SOLO_RANDOMX_SERVICE_URL")
	flag.StringVar(&cfg.coinbaseExtraTag, "coinbase-extra-tag", envOr("LEAF_SOLO_COINBASE_EXTRA_TAG", ""), "coinbase-extra ownership tag appended to every fetched Tari block template (identifies this leaf's found blocks on-chain). Left unset (the default), a per-algo default is computed instead: supportxtm-sha3x / supportxtm-c29 / supportxtm-rxt / supportxtm-rxm, based on -algo/-coin -- see resolveCoinbaseExtraTag. When set, this value is used verbatim, overriding the per-algo default. Truncated to solo.MaxCoinbaseExtraTagLen bytes if longer. Env: LEAF_SOLO_COINBASE_EXTRA_TAG")

	// LEAF_SOLO_STARTING_DIFFICULTY replaces the old, now-removed
	// LEAF_SOLO_DIFFICULTY (which used to be THE only difficulty any
	// session ever had). It's still read as a fallback below for a
	// smooth migration, but LEAF_SOLO_STARTING_DIFFICULTY takes
	// precedence when both are set.
	flag.Uint64Var(&cfg.startingDifficulty, "starting-difficulty", envOrUint64Fallback("LEAF_SOLO_STARTING_DIFFICULTY", "LEAF_SOLO_DIFFICULTY", 10000), "starting share difficulty for a newly-connected session; vardiff adjusts it from here based on that session's own accept history. Env: LEAF_SOLO_STARTING_DIFFICULTY (falls back to legacy LEAF_SOLO_DIFFICULTY if unset)")
	flag.StringVar(&cfg.portsRaw, "ports", envOr("LEAF_SOLO_PORTS", ""), "comma-separated list of address:difficulty[:desc][:tls] port tiers, e.g. ':4444:10000:low-diff,:4445:1000000:high-diff:tls'. The optional trailing ':tls' marker (case-insensitive) enables the shared self-signed TLS listener for that ONE port tier only -- see -tls-cert-file/-tls-key-file/-tls-cert-persist-path. When set, this REPLACES -listen-address/-starting-difficulty entirely (they are ignored). When unset (the default), -listen-address/-starting-difficulty are used as a single implicit port tier, preserving the pre-multi-port behavior exactly. Env: LEAF_SOLO_PORTS")
	flag.Uint64Var(&cfg.minDifficulty, "min-difficulty", envOrUint64("LEAF_SOLO_MIN_DIFFICULTY", 100), "absolute floor vardiff will never retarget below. Env: LEAF_SOLO_MIN_DIFFICULTY")
	flag.Uint64Var(&cfg.maxDifficulty, "max-difficulty", envOrUint64("LEAF_SOLO_MAX_DIFFICULTY", 1_000_000_000), "absolute ceiling vardiff will never retarget above. Env: LEAF_SOLO_MAX_DIFFICULTY")
	flag.IntVar(&cfg.vardiffTargetTime, "vardiff-target-time", envOrInt("LEAF_SOLO_VARDIFF_TARGET_TIME", 30), "seconds between shares vardiff aims for. Env: LEAF_SOLO_VARDIFF_TARGET_TIME")
	flag.DurationVar(&cfg.vardiffInterval, "vardiff-retarget-interval", envOrDuration("LEAF_SOLO_VARDIFF_RETARGET_INTERVAL", 60*time.Second), "how often each session's own vardiff retarget timer fires (also the minimum connection age before a session's first retarget). Env: LEAF_SOLO_VARDIFF_RETARGET_INTERVAL")

	flag.StringVar(&cfg.tlsCertFile, "tls-cert-file", envOr("LEAF_SOLO_TLS_CERT_FILE", ""), "optional PEM-encoded TLS certificate file for the shared, process-wide self-signed-or-operator-supplied cert used by any ':tls'-suffixed -ports entry. Empty (default) auto-generates a self-signed cert instead -- see -tls-cert-persist-path. Ignored entirely if no port has TLS enabled. Env: LEAF_SOLO_TLS_CERT_FILE")
	flag.StringVar(&cfg.tlsKeyFile, "tls-key-file", envOr("LEAF_SOLO_TLS_KEY_FILE", ""), "optional PEM-encoded TLS private key file paired with -tls-cert-file. Env: LEAF_SOLO_TLS_KEY_FILE")
	flag.StringVar(&cfg.tlsCertPersistPath, "tls-cert-persist-path", envOr("LEAF_SOLO_TLS_CERT_PERSIST_PATH", ""), "where to persist an auto-generated self-signed TLS cert/key pair so restarts reload it instead of rotating it. Empty (default) means in-memory only -- a fresh self-signed cert is generated on every restart. Ignored if -tls-cert-file/-tls-key-file are set. Env: LEAF_SOLO_TLS_CERT_PERSIST_PATH")

	flag.DurationVar(&cfg.refreshInterval, "refresh-interval", envOrDuration("LEAF_SOLO_REFRESH_INTERVAL", 30*time.Second), "unconditional block-template refresh interval. Env: LEAF_SOLO_REFRESH_INTERVAL")
	flag.DurationVar(&cfg.tipPollInterval, "tip-poll-interval", envOrDuration("LEAF_SOLO_TIP_POLL_INTERVAL", 5*time.Second), "chain-tip poll interval (forces an immediate refresh on tip movement). Env: LEAF_SOLO_TIP_POLL_INTERVAL")

	// LEAF_SOLO_JOB_MAX_AGE is the SECURITY-FIX real per-job expiry
	// threshold (see solo.JobManagerConfig.JobMaxAge's doc comment):
	// a submit against a job older than this, independent of whether
	// InvalidateAll has run, is rejected outright. Mirrors
	// go-tari-sha3x-solo-stratum's CleanMinerJobs default of 6
	// minutes.
	flag.DurationVar(&cfg.jobMaxAge, "job-max-age", envOrDuration("LEAF_SOLO_JOB_MAX_AGE", 6*time.Minute), "real per-job expiry threshold, independent of tip-invalidation; a submit against an older job is rejected as expired. Env: LEAF_SOLO_JOB_MAX_AGE")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_SOLO_MAX_CONNECTIONS", leaflib.DefaultLeafMaxConnections), "max concurrent miner connections, 0 = unlimited. Env: LEAF_SOLO_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_SOLO_IDLE_TIMEOUT", 2*time.Minute), "rolling per-connection idle timeout. Env: LEAF_SOLO_IDLE_TIMEOUT")

	flag.StringVar(&cfg.metricsListenAddress, "metrics-listen-address", envOr("LEAF_SOLO_METRICS_LISTEN_ADDRESS", "127.0.0.1:9600"), "HTTP listen address for /metrics (Prometheus) and the stats page. Separate from -listen-address (the miner-facing stratum port). Defaults to loopback-only (127.0.0.1) -- an operator must explicitly set this to a wildcard/public address (e.g. :9600 or 0.0.0.0:9600) to expose stats/metrics publicly. Set to empty string to disable. Env: LEAF_SOLO_METRICS_LISTEN_ADDRESS")
	flag.IntVar(&cfg.maxAddressLabels, "max-address-labels", envOrInt("LEAF_SOLO_MAX_ADDRESS_LABELS", 0), "cap on distinct payment-address labels tracked by leaf_miners_by_address and the stats page's per-address breakdown (0 = package default). Env: LEAF_SOLO_MAX_ADDRESS_LABELS")
	flag.BoolVar(&cfg.hideRemoteAddress, "hide-remote-address", envOr("LEAF_SOLO_HIDE_REMOTE_ADDRESS", "false") == "true", "omit the \"Remote address\" column from the stats HTML page entirely -- recommended for public-facing deployments so remote miner IPs are never exposed on a page anyone can load. Disabled by default (existing behavior unchanged). Env: LEAF_SOLO_HIDE_REMOTE_ADDRESS (\"true\" to enable)")

	flag.StringVar(&cfg.addressFlagsFile, "address-flags-file", envOr("LEAF_SOLO_ADDRESS_FLAGS_FILE", ""), "path to a local, operator-maintained JSON file of manually banned/forced-minimum-difficulty payment addresses (see internal/leaflib/addressflags.FileSource's doc comment for the file format). Empty (default) disables the feature entirely -- leaf-solo has no backend to poll instead. Env: LEAF_SOLO_ADDRESS_FLAGS_FILE")
	flag.DurationVar(&cfg.addressFlagsPollInterval, "address-flags-poll-interval", envOrDuration("LEAF_SOLO_ADDRESS_FLAGS_POLL_INTERVAL", 30*time.Second), "how often -address-flags-file is re-read. Ignored if -address-flags-file is unset. Env: LEAF_SOLO_ADDRESS_FLAGS_POLL_INTERVAL")

	flag.StringVar(&cfg.relayNATSURL, "relay-nats-url", envOr("LEAF_SOLO_RELAY_NATS_URL", ""), "NATS server URL for the template-relay fast-invalidation broadcast (see internal/leaflib/relay) -- leaf-solo has no found-block broadcast use case of its own, this is purely for the template relay. Empty (default) fully disables the relay -- a complete no-op, never required. Env: LEAF_SOLO_RELAY_NATS_URL")
	flag.StringVar(&cfg.relaySubject, "relay-subject", envOr("LEAF_SOLO_RELAY_SUBJECT", ""), "NATS subject for the (unused, by leaf-solo) found-block relay stream (empty = relay package default). Env: LEAF_SOLO_RELAY_SUBJECT")
	flag.StringVar(&cfg.templateRelaySubject, "template-relay-subject", envOr("LEAF_SOLO_TEMPLATE_RELAY_SUBJECT", ""), "NATS subject for the template (new-tip) relay fast-invalidation broadcast (empty = relay.DefaultTemplateSubject). Reuses the SAME -relay-nats-url connection above -- no second NATS URL flag. Env: LEAF_SOLO_TEMPLATE_RELAY_SUBJECT")
	flag.StringVar(&cfg.relayNATSUsername, "relay-nats-username", envOr("LEAF_SOLO_RELAY_NATS_USERNAME", ""), "optional NATS username for the relay connection above (mirrors nats.UserInfo). Empty (default) connects with no auth. Env: LEAF_SOLO_RELAY_NATS_USERNAME")
	flag.StringVar(&cfg.relayNATSPassword, "relay-nats-password", envOr("LEAF_SOLO_RELAY_NATS_PASSWORD", ""), "optional NATS password paired with -relay-nats-username (mirrors nats.UserInfo). Never logged. Env: LEAF_SOLO_RELAY_NATS_PASSWORD")
	flag.StringVar(&cfg.relayNATSTLSCAFile, "relay-nats-tls-ca-file", envOr("LEAF_SOLO_RELAY_NATS_TLS_CA_FILE", ""), "optional CA bundle file to verify the NATS server's TLS certificate against (mirrors nats.RootCAs). Empty (default) appends no TLS CA option. Env: LEAF_SOLO_RELAY_NATS_TLS_CA_FILE")
	flag.StringVar(&cfg.relayNATSTLSCertFile, "relay-nats-tls-cert-file", envOr("LEAF_SOLO_RELAY_NATS_TLS_CERT_FILE", ""), "optional client certificate file for mutual TLS against the NATS server (mirrors nats.ClientCert; must be set together with -relay-nats-tls-key-file). Env: LEAF_SOLO_RELAY_NATS_TLS_CERT_FILE")
	flag.StringVar(&cfg.relayNATSTLSKeyFile, "relay-nats-tls-key-file", envOr("LEAF_SOLO_RELAY_NATS_TLS_KEY_FILE", ""), "optional client private key file paired with -relay-nats-tls-cert-file (mirrors nats.ClientCert). Env: LEAF_SOLO_RELAY_NATS_TLS_KEY_FILE")
	flag.StringVar(&cfg.moneroZMQURL, "monero-zmq-url", envOr("LEAF_SOLO_MONERO_ZMQ_URL", ""), "real monerod ZMQ endpoint (e.g. tcp://127.0.0.1:28082) for an ADDITIONAL, faster block-invalidation trigger on top of the existing tip-poll baseline (see internal/leaflib/monero/zmq). Empty (default) disables this entirely -- a complete no-op. Ignored for -coin=tari. Env: LEAF_SOLO_MONERO_ZMQ_URL")

	flag.StringVar(&cfg.configFile, "config", envOr("LEAF_SOLO_CONFIG_FILE", ""), "optional path to a TOML config file providing defaults for any flag below that is not explicitly set via CLI flag or environment variable. See leaf-solo.example.toml. Env: LEAF_SOLO_CONFIG_FILE")

	flag.BoolVar(&cfg.debug, "debug", envOr("LEAF_SOLO_DEBUG", "false") == "true", "enable verbose [DEBUG]-tagged logging (share submit params, validation attempt/result, job lifecycle, connection lifecycle, vardiff retargets). OFF by default -- purely additive, never changes any existing log line. Env: LEAF_SOLO_DEBUG (\"true\" to enable)")

	flag.Parse()

	if err := applyConfigFile(&cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// fileConfig mirrors config field-for-field (excluding configFile
// itself) with pointer types so an absent TOML key decodes to nil and
// is left untouched by the cfgfile.ApplyXxx helpers below. Durations
// are represented in the TOML file as a plain integer number of
// seconds (go-toml/v2 does not natively decode into time.Duration)
// and converted with time.Duration(v) * time.Second when applied.
type fileConfig struct {
	NodeGRPCAddress *string `toml:"node_grpc_address"`
	ListenAddress   *string `toml:"listen_address"`
	PayoutAddress   *string `toml:"payout_address"`
	Network         *string `toml:"network"`
	Coin            *string `toml:"coin"`
	MonerodURL      *string `toml:"monerod_url"`

	RandomXWorkers                  *int  `toml:"randomx_workers"`
	InvalidShareDisconnectEnabled   *bool `toml:"invalid_share_disconnect_enabled"`
	InvalidShareDisconnectThreshold *int  `toml:"invalid_share_disconnect_threshold"`

	Algo              *string `toml:"algo"`
	RandomXServiceURL *string `toml:"randomx_service_url"`
	CoinbaseExtraTag  *string `toml:"coinbase_extra_tag"`

	StartingDifficulty     *uint64 `toml:"starting_difficulty"`
	PortsRaw               *string `toml:"ports"`
	MinDifficulty          *uint64 `toml:"min_difficulty"`
	MaxDifficulty          *uint64 `toml:"max_difficulty"`
	VardiffTargetTime      *int    `toml:"vardiff_target_time_seconds"`
	VardiffIntervalSeconds *int    `toml:"vardiff_retarget_interval_seconds"`

	TLSCertFile        *string `toml:"tls_cert_file"`
	TLSKeyFile         *string `toml:"tls_key_file"`
	TLSCertPersistPath *string `toml:"tls_cert_persist_path"`

	RefreshIntervalSeconds *int `toml:"refresh_interval_seconds"`
	TipPollIntervalSeconds *int `toml:"tip_poll_interval_seconds"`
	JobMaxAgeSeconds       *int `toml:"job_max_age_seconds"`

	MaxConnections     *int `toml:"max_connections"`
	IdleTimeoutSeconds *int `toml:"idle_timeout_seconds"`

	MetricsListenAddress *string `toml:"metrics_listen_address"`
	MaxAddressLabels     *int    `toml:"max_address_labels"`
	HideRemoteAddress    *bool   `toml:"hide_remote_address"`

	AddressFlagsFile                *string `toml:"address_flags_file"`
	AddressFlagsPollIntervalSeconds *int    `toml:"address_flags_poll_interval_seconds"`

	RelayNATSURL         *string `toml:"relay_nats_url"`
	RelaySubject         *string `toml:"relay_subject"`
	TemplateRelaySubject *string `toml:"template_relay_subject"`

	RelayNATSUsername    *string `toml:"relay_nats_username"`
	RelayNATSPassword    *string `toml:"relay_nats_password"`
	RelayNATSTLSCAFile   *string `toml:"relay_nats_tls_ca_file"`
	RelayNATSTLSCertFile *string `toml:"relay_nats_tls_cert_file"`
	RelayNATSTLSKeyFile  *string `toml:"relay_nats_tls_key_file"`
	MoneroZMQURL         *string `toml:"monero_zmq_url"`

	Debug *bool `toml:"debug"`
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
		return fmt.Errorf("leaf-solo: loading -config %s: %w", cfg.configFile, err)
	}

	cfgfile.ApplyString(&cfg.nodeGRPCAddress, fc.NodeGRPCAddress, visited, "node-grpc-address", "LEAF_NODE_GRPC_ADDRESS")
	cfgfile.ApplyString(&cfg.listenAddress, fc.ListenAddress, visited, "listen-address", "LEAF_SOLO_LISTEN_ADDRESS")
	cfgfile.ApplyString(&cfg.payoutAddress, fc.PayoutAddress, visited, "payout-address", "LEAF_SOLO_PAYOUT_ADDRESS")
	cfgfile.ApplyString(&cfg.network, fc.Network, visited, "network", "LEAF_SOLO_NETWORK")
	cfgfile.ApplyString(&cfg.coin, fc.Coin, visited, "coin", "LEAF_SOLO_COIN")
	cfgfile.ApplyString(&cfg.monerodURL, fc.MonerodURL, visited, "monerod-url", "LEAF_SOLO_MONEROD_URL")

	cfgfile.ApplyInt(&cfg.randomxWorkers, fc.RandomXWorkers, visited, "randomx-workers", "LEAF_SOLO_RANDOMX_WORKERS")
	cfgfile.ApplyBool(&cfg.invalidShareDisconnectEnabled, fc.InvalidShareDisconnectEnabled, visited, "invalid-share-disconnect-enabled", "LEAF_SOLO_INVALID_SHARE_DISCONNECT_ENABLED")
	cfgfile.ApplyInt(&cfg.invalidShareDisconnectThreshold, fc.InvalidShareDisconnectThreshold, visited, "invalid-share-disconnect-threshold", "LEAF_SOLO_INVALID_SHARE_DISCONNECT_THRESHOLD")

	cfgfile.ApplyString(&cfg.algo, fc.Algo, visited, "algo", "LEAF_SOLO_ALGO")
	cfgfile.ApplyString(&cfg.randomXServiceURL, fc.RandomXServiceURL, visited, "randomx-service-url", "LEAF_SOLO_RANDOMX_SERVICE_URL")
	cfgfile.ApplyString(&cfg.coinbaseExtraTag, fc.CoinbaseExtraTag, visited, "coinbase-extra-tag", "LEAF_SOLO_COINBASE_EXTRA_TAG")

	// startingDifficulty is a special case: the flag is fed by
	// envOrUint64Fallback with TWO env var names
	// (LEAF_SOLO_STARTING_DIFFICULTY primary, legacy LEAF_SOLO_DIFFICULTY
	// fallback) -- a config-file value must not override an explicit
	// setting of EITHER one, so we build the Source manually (ORing in
	// the legacy env var) instead of calling cfgfile.ApplyUint64 directly.
	startingDifficultySrc := cfgfile.FieldSource(visited, "starting-difficulty", "LEAF_SOLO_STARTING_DIFFICULTY")
	startingDifficultySrc.ExplicitEnv = startingDifficultySrc.ExplicitEnv || os.Getenv("LEAF_SOLO_DIFFICULTY") != ""
	if fc.StartingDifficulty != nil && cfgfile.ShouldApplyFile(startingDifficultySrc) {
		cfg.startingDifficulty = *fc.StartingDifficulty
	}

	cfgfile.ApplyString(&cfg.portsRaw, fc.PortsRaw, visited, "ports", "LEAF_SOLO_PORTS")
	cfgfile.ApplyUint64(&cfg.minDifficulty, fc.MinDifficulty, visited, "min-difficulty", "LEAF_SOLO_MIN_DIFFICULTY")
	cfgfile.ApplyUint64(&cfg.maxDifficulty, fc.MaxDifficulty, visited, "max-difficulty", "LEAF_SOLO_MAX_DIFFICULTY")
	cfgfile.ApplyInt(&cfg.vardiffTargetTime, fc.VardiffTargetTime, visited, "vardiff-target-time", "LEAF_SOLO_VARDIFF_TARGET_TIME")

	if fc.VardiffIntervalSeconds != nil {
		d := time.Duration(*fc.VardiffIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.vardiffInterval, &d, visited, "vardiff-retarget-interval", "LEAF_SOLO_VARDIFF_RETARGET_INTERVAL")
	}

	cfgfile.ApplyString(&cfg.tlsCertFile, fc.TLSCertFile, visited, "tls-cert-file", "LEAF_SOLO_TLS_CERT_FILE")
	cfgfile.ApplyString(&cfg.tlsKeyFile, fc.TLSKeyFile, visited, "tls-key-file", "LEAF_SOLO_TLS_KEY_FILE")
	cfgfile.ApplyString(&cfg.tlsCertPersistPath, fc.TLSCertPersistPath, visited, "tls-cert-persist-path", "LEAF_SOLO_TLS_CERT_PERSIST_PATH")

	if fc.RefreshIntervalSeconds != nil {
		d := time.Duration(*fc.RefreshIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.refreshInterval, &d, visited, "refresh-interval", "LEAF_SOLO_REFRESH_INTERVAL")
	}
	if fc.TipPollIntervalSeconds != nil {
		d := time.Duration(*fc.TipPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.tipPollInterval, &d, visited, "tip-poll-interval", "LEAF_SOLO_TIP_POLL_INTERVAL")
	}
	if fc.JobMaxAgeSeconds != nil {
		d := time.Duration(*fc.JobMaxAgeSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.jobMaxAge, &d, visited, "job-max-age", "LEAF_SOLO_JOB_MAX_AGE")
	}

	cfgfile.ApplyInt(&cfg.maxConnections, fc.MaxConnections, visited, "max-connections", "LEAF_SOLO_MAX_CONNECTIONS")
	if fc.IdleTimeoutSeconds != nil {
		d := time.Duration(*fc.IdleTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.idleTimeout, &d, visited, "idle-timeout", "LEAF_SOLO_IDLE_TIMEOUT")
	}

	cfgfile.ApplyString(&cfg.metricsListenAddress, fc.MetricsListenAddress, visited, "metrics-listen-address", "LEAF_SOLO_METRICS_LISTEN_ADDRESS")
	cfgfile.ApplyInt(&cfg.maxAddressLabels, fc.MaxAddressLabels, visited, "max-address-labels", "LEAF_SOLO_MAX_ADDRESS_LABELS")
	cfgfile.ApplyBool(&cfg.hideRemoteAddress, fc.HideRemoteAddress, visited, "hide-remote-address", "LEAF_SOLO_HIDE_REMOTE_ADDRESS")

	cfgfile.ApplyString(&cfg.addressFlagsFile, fc.AddressFlagsFile, visited, "address-flags-file", "LEAF_SOLO_ADDRESS_FLAGS_FILE")
	if fc.AddressFlagsPollIntervalSeconds != nil {
		d := time.Duration(*fc.AddressFlagsPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.addressFlagsPollInterval, &d, visited, "address-flags-poll-interval", "LEAF_SOLO_ADDRESS_FLAGS_POLL_INTERVAL")
	}

	cfgfile.ApplyString(&cfg.relayNATSURL, fc.RelayNATSURL, visited, "relay-nats-url", "LEAF_SOLO_RELAY_NATS_URL")
	cfgfile.ApplyString(&cfg.relaySubject, fc.RelaySubject, visited, "relay-subject", "LEAF_SOLO_RELAY_SUBJECT")
	cfgfile.ApplyString(&cfg.templateRelaySubject, fc.TemplateRelaySubject, visited, "template-relay-subject", "LEAF_SOLO_TEMPLATE_RELAY_SUBJECT")
	cfgfile.ApplyString(&cfg.relayNATSUsername, fc.RelayNATSUsername, visited, "relay-nats-username", "LEAF_SOLO_RELAY_NATS_USERNAME")
	cfgfile.ApplyString(&cfg.relayNATSPassword, fc.RelayNATSPassword, visited, "relay-nats-password", "LEAF_SOLO_RELAY_NATS_PASSWORD")
	cfgfile.ApplyString(&cfg.relayNATSTLSCAFile, fc.RelayNATSTLSCAFile, visited, "relay-nats-tls-ca-file", "LEAF_SOLO_RELAY_NATS_TLS_CA_FILE")
	cfgfile.ApplyString(&cfg.relayNATSTLSCertFile, fc.RelayNATSTLSCertFile, visited, "relay-nats-tls-cert-file", "LEAF_SOLO_RELAY_NATS_TLS_CERT_FILE")
	cfgfile.ApplyString(&cfg.relayNATSTLSKeyFile, fc.RelayNATSTLSKeyFile, visited, "relay-nats-tls-key-file", "LEAF_SOLO_RELAY_NATS_TLS_KEY_FILE")
	cfgfile.ApplyString(&cfg.moneroZMQURL, fc.MoneroZMQURL, visited, "monero-zmq-url", "LEAF_SOLO_MONERO_ZMQ_URL")

	cfgfile.ApplyBool(&cfg.debug, fc.Debug, visited, "debug", "LEAF_SOLO_DEBUG")

	return nil
}

// resolvePorts turns cfg's port configuration into a concrete list of
// solo.PortConfig port tiers. If cfg.portsRaw is set (LEAF_SOLO_PORTS /
// -ports), it is parsed as a comma-separated list of
// "address:difficulty[:desc]" entries — each entry's address is
// everything up to the LAST TWO colon-separated fields (so IPv6
// addresses and bare ":PORT" forms both work: "difficulty" and
// "desc"/(no desc) are peeled off the tail, and whatever remains is
// the listen address verbatim). If cfg.portsRaw is unset, this returns
// a single implicit port tier built from cfg.listenAddress /
// cfg.startingDifficulty — this is the exact backward-compatible path
// the already-deployed CT132 leaf-solo.service (old single-value env
// vars only) relies on.
func resolvePorts(cfg config) ([]solo.PortConfig, error) {
	if strings.TrimSpace(cfg.portsRaw) == "" {
		return []solo.PortConfig{{
			Address:    cfg.listenAddress,
			Difficulty: cfg.startingDifficulty,
			PortDesc:   "default",
		}}, nil
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
			return nil, fmt.Errorf("LEAF_SOLO_PORTS entry %d (%q): %w", i+1, raw, err)
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, errors.New("LEAF_SOLO_PORTS was set but contained no usable entries")
	}
	return ports, nil
}

// parsePortEntry parses one "address:difficulty" or
// "address:difficulty:desc" entry, with an optional trailing ":tls"
// marker (case-insensitive) enabling the shared TLS listener for that
// port tier -- see PortConfig.TLS's doc comment. address itself is
// free to contain colons (bare ":4444", "0.0.0.0:4444", "[::1]:4444")
// — difficulty (and an optional trailing desc) are peeled off the END
// of the colon-separated fields rather than assuming address has no
// colons of its own.
func parsePortEntry(raw string) (solo.PortConfig, error) {
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
		return solo.PortConfig{}, errors.New(`expected "address:difficulty" or "address:difficulty:desc", optionally with a trailing ":tls"`)
	}

	// Try treating the LAST field as difficulty first (the
	// "address:difficulty:desc" shape); if that doesn't parse as a
	// number, fall back to the second-to-last field being difficulty
	// and the last being desc.
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
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

// envOrUint64Fallback reads primaryKey, falling back to fallbackKey
// (for smooth migration off a renamed/repurposed env var — here,
// LEAF_SOLO_STARTING_DIFFICULTY replacing LEAF_SOLO_DIFFICULTY) before
// finally falling back to def if neither is set.
func envOrUint64Fallback(primaryKey, fallbackKey string, def uint64) uint64 {
	if v := os.Getenv(primaryKey); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	if v := os.Getenv(fallbackKey); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
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

func envOrDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func networkFromString(s string) poolpb.Network {
	switch s {
	case "mainnet":
		return poolpb.Network_NETWORK_MAINNET
	default:
		return poolpb.Network_NETWORK_TESTNET
	}
}

// algoFromString parses -algo/LEAF_SOLO_ALGO. Defaults to
// poolpb.Algo_ALGO_SHA3X for any unrecognized value (including the
// empty string), matching this leaf's pre-multi-algo behavior exactly
// when the flag/env var is left unset. Only meaningful for -coin=tari
// -- resolveAlgo (below) is what main actually calls, and it overrides
// this entirely to ALGO_RXM for -coin=monero.
func algoFromString(s string) poolpb.Algo {
	switch s {
	case "c29":
		return poolpb.Algo_ALGO_C29
	case "rxt":
		return poolpb.Algo_ALGO_RXT
	default:
		return poolpb.Algo_ALGO_SHA3X
	}
}

// isMoneroCoin reports whether cfg.coin/-coin selects the real Monero
// path (case-insensitive, tolerant of surrounding whitespace) -- the
// single normalization point every coin-conditional branch in main
// below consults, so "Monero"/"MONERO"/" monero " all behave
// identically.
func isMoneroCoin(coin string) bool {
	return strings.EqualFold(strings.TrimSpace(coin), "monero")
}

// resolveAlgo is what main actually calls to get the real
// poolpb.Algo this leaf-solo process serves: for -coin=monero, this is
// ALWAYS poolpb.Algo_ALGO_RXM (Monero genuinely has only one algo --
// plain RandomX/rx -- so there is no meaningful per-process -algo
// choice to make for it, unlike Tari's SHA3X/C29/RXT), regardless of
// whatever -algo/LEAF_SOLO_ALGO happens to be set to; for -coin=tari
// (the default), this is algoFromString(cfg.algo) exactly as before
// Monero support existed.
func resolveAlgo(cfg config) poolpb.Algo {
	if isMoneroCoin(cfg.coin) {
		return poolpb.Algo_ALGO_RXM
	}
	return algoFromString(cfg.algo)
}

// algoTagSuffix derives the "supportxtm-<suffix>" default's per-algo
// suffix from resolveAlgo's real, already-normalized poolpb.Algo for
// this process (reusing that exact resolution logic rather than a
// second, separate/hardcoded mapping) -- "rxm" is handled specially
// since resolveAlgo maps EVERY -coin=monero configuration to
// ALGO_RXM regardless of -algo, and that mapping is exactly what
// distinguishes it from Tari's own native RXT.
func algoTagSuffix(cfg config) string {
	switch resolveAlgo(cfg) {
	case poolpb.Algo_ALGO_C29:
		return "c29"
	case poolpb.Algo_ALGO_RXT:
		return "rxt"
	case poolpb.Algo_ALGO_RXM:
		return "rxm"
	default:
		return "sha3x"
	}
}

// defaultCoinbaseExtraTag computes this leaf-solo instance's default
// coinbase-extra ownership tag: "supportxtm-<algo>", derived from
// whichever algo/coin this process is actually configured to serve
// (see algoTagSuffix/resolveAlgo) -- NOT one single blended constant
// across every algo, since per-algo on-chain attribution is the whole
// point (see resolveCoinbaseExtraTag).
func defaultCoinbaseExtraTag(cfg config) string {
	return "supportxtm-" + algoTagSuffix(cfg)
}

// resolveCoinbaseExtraTag is what main actually calls to get the real
// coinbase-extra tag this leaf-solo process uses: cfg.coinbaseExtraTag
// (-coinbase-extra-tag / LEAF_SOLO_COINBASE_EXTRA_TAG) verbatim if the
// operator explicitly set it, else defaultCoinbaseExtraTag(cfg)'s
// per-algo default.
func resolveCoinbaseExtraTag(cfg config) string {
	if strings.TrimSpace(cfg.coinbaseExtraTag) != "" {
		return cfg.coinbaseExtraTag
	}
	return defaultCoinbaseExtraTag(cfg)
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("leaf-solo: %v", err)
	}
	logger := log.New(os.Stdout, "leaf-solo: ", log.LstdFlags|log.Lmicroseconds)

	// debugLogger is constructed exactly once per process (never a
	// global/package-level singleton -- see
	// internal/leaflib/debuglog.go's doc comment) and threaded down
	// via Server.SetDebugLogger below. Writes to the SAME
	// stdout-backed logger as every other leaf-solo log line, so
	// [DEBUG]-tagged lines interleave naturally with the existing
	// log stream rather than going to a second destination. Passing
	// cfg.debug=false here (the default) means every Debugf call
	// downstream is a near-zero-cost no-op -- see DebugLogger.Debugf's
	// own doc comment on why the enabled check runs BEFORE any
	// formatting work.
	debugLogger := leaflib.NewDebugLogger(logger, cfg.debug)
	if cfg.debug {
		logger.Print("debug logging ENABLED (-debug/LEAF_SOLO_DEBUG) -- verbose [DEBUG]-tagged output follows for share submits, validation, job lifecycle, connection lifecycle, and vardiff retargets")
	}

	if isMoneroCoin(cfg.coin) {
		if strings.TrimSpace(cfg.monerodURL) == "" {
			logger.Fatal("LEAF_SOLO_MONEROD_URL (or -monerod-url) is required when -coin=monero")
		}
		if cfg.nodeGRPCAddress != "" {
			logger.Printf("note: -coin=monero -- ignoring -node-grpc-address/LEAF_NODE_GRPC_ADDRESS (%s); no Tari GRPC daemon is involved", cfg.nodeGRPCAddress)
		}
	} else if cfg.nodeGRPCAddress == "" {
		logger.Fatal("LEAF_NODE_GRPC_ADDRESS (or -node-grpc-address) is required")
	}
	if cfg.payoutAddress == "" {
		logger.Fatal("LEAF_SOLO_PAYOUT_ADDRESS (or -payout-address) is required")
	}

	ports, err := resolvePorts(cfg)
	if err != nil {
		logger.Fatalf("invalid port configuration: %v", err)
	}
	for _, p := range ports {
		desc := p.PortDesc
		if desc == "" {
			desc = "-"
		}
		logger.Printf("port tier: address=%s starting-difficulty=%d desc=%s", p.Address, p.Difficulty, desc)
	}
	logger.Printf("vardiff bounds [%d, %d], target time %ds, retarget interval %s", cfg.minDifficulty, cfg.maxDifficulty, cfg.vardiffTargetTime, cfg.vardiffInterval)
	logger.Printf("job max age (security: per-job expiry independent of tip invalidation): %s", cfg.jobMaxAge)

	// coinbaseExtraTag is resolved from -coinbase-extra-tag/
	// LEAF_SOLO_COINBASE_EXTRA_TAG if explicitly set, else a per-algo
	// default ("supportxtm-<algo>") computed from whichever algo/coin
	// this process is actually configured for -- see
	// resolveCoinbaseExtraTag. Logged unconditionally so a freshly
	// deployed/reconfigured leaf-solo's actual on-chain attribution
	// tag is directly verifiable from its own startup logs.
	coinbaseExtraTagStr := resolveCoinbaseExtraTag(cfg)
	coinbaseExtraTag := solo.NormalizeCoinbaseExtraTag(coinbaseExtraTagStr, defaultCoinbaseExtraTag(cfg))
	logger.Printf("coinbase-extra tag: %q (%d bytes)", string(coinbaseExtraTag), len(coinbaseExtraTag))

	// Real coin-conditional NodeClient construction: both
	// implementations satisfy the exact same coin-agnostic
	// solo.NodeClient interface (node.go), so everything downstream
	// (JobManager, Server, session.go's handleSubmit) is unaffected by
	// which one gets constructed here.
	var node solo.NodeClient
	if isMoneroCoin(cfg.coin) {
		logger.Printf("connecting to Monero daemon (monerod JSON-RPC) at %s", cfg.monerodURL)
		logger.Printf("NOTE: for RXM/merge-mining revenue, -monerod-url must point at a local minotari_merge_mining_proxy listener, NOT raw monerod -- pointing at raw monerod mines Monero-only with zero Tari merge-mine revenue")
		node = solo.NewMoneroNodeClient(cfg.monerodURL)
	} else {
		logger.Printf("connecting to Tari base node GRPC at %s", cfg.nodeGRPCAddress)
		node = solo.NewGRPCNodeClient(cfg.nodeGRPCAddress, coinbaseExtraTag)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Real, best-effort NATS relay -- leaf-solo has no found-block
	// broadcast use case of its own (BlockMessage/Publish/Subscribe go
	// unused here), but it needs the SAME *relay.Relay type purely for
	// the template-relay fast-invalidation feature (see
	// solo.JobManagerConfig.Relay and job.go's tipPollLoop/Start
	// wiring). A complete no-op if -relay-nats-url/LEAF_SOLO_RELAY_NATS_URL
	// is unset (see internal/leaflib/relay.Config.URL's doc comment).
	templateRelay := relay.NewRelay(relay.Config{
		URL: cfg.relayNATSURL, Subject: cfg.relaySubject, TemplateSubject: cfg.templateRelaySubject, Logger: logger,
		Username: cfg.relayNATSUsername, Password: cfg.relayNATSPassword,
		TLSCAFile: cfg.relayNATSTLSCAFile, TLSCertFile: cfg.relayNATSTLSCertFile, TLSKeyFile: cfg.relayNATSTLSKeyFile,
	})
	defer func() { _ = templateRelay.Close() }()
	if templateRelay.Enabled() {
		logger.Printf("NATS template relay enabled at %s", cfg.relayNATSURL)
	} else {
		logger.Printf("NATS template relay disabled (-relay-nats-url is empty) -- complete no-op, never required for correctness")
	}

	jobManager := solo.NewJobManager(solo.JobManagerConfig{
		Node:          node,
		PayoutAddress: cfg.payoutAddress,
		Algo:          resolveAlgo(cfg),
		// StaticDifficulty is only the JobForXN fallback default (see
		// JobManagerConfig.StaticDifficulty's doc comment) — every
		// real session created by Server.handleConn goes through
		// JobForXNAtDifficulty with its OWN port tier's starting
		// difficulty (or its current vardiff value thereafter), so
		// this is not "the" difficulty for any port; the first
		// configured port's difficulty is used here purely as a
		// reasonable default for any hypothetical direct JobForXN
		// caller.
		StaticDifficulty: ports[0].Difficulty,
		RefreshInterval:  cfg.refreshInterval,
		TipPollInterval:  cfg.tipPollInterval,
		JobMaxAge:        cfg.jobMaxAge,
		Network:          cfg.network,
		Relay:            templateRelay,
		Logger:           logger,
		Debug:            debugLogger,
	})

	logger.Println("probing base node connectivity...")
	if err := jobManager.Probe(ctx); err != nil {
		logger.Fatalf("base node connectivity probe failed: %v", err)
	}
	jobManager.Start(ctx)

	// Real, ADDITIONAL fast-invalidation trigger for the real monerod
	// ZMQ pub/sub stream -- -coin=monero ONLY, and only when
	// -monero-zmq-url is explicitly set (a complete no-op otherwise --
	// see internal/leaflib/monero/zmq's own doc comment). This never
	// REPLACES jobManager's own tip-poll loop (already started above),
	// it is purely an additional, faster trigger running alongside it.
	if isMoneroCoin(cfg.coin) && cfg.moneroZMQURL != "" {
		zmqClient := monerozmq.NewClient(cfg.moneroZMQURL, jobManager.InvalidateAll, logger)
		go zmqClient.Start(ctx)
		logger.Printf("real monerod ZMQ fast-invalidation trigger enabled at %s (topic %q)", cfg.moneroZMQURL, monerozmq.TopicNewBlock)
	} else if cfg.moneroZMQURL != "" {
		logger.Printf("note: -monero-zmq-url is set but -coin != monero -- ignoring it (%s); no ZMQ subscription started", cfg.moneroZMQURL)
	}

	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{
		MaxConnections: cfg.maxConnections,
		IdleTimeout:    cfg.idleTimeout,
	})

	// Registry covers all four algos so this Server can dispatch a
	// submit to the right validator by the job's own Algo field. This
	// leaf currently fetches/serves SHA3X, C29, and now RXT job
	// templates (see -algo above); RXM remains out of scope. The
	// RandomX validator (shared by RXT/RXM) is wired to the real,
	// configured randomx-service daemon (cfg.randomXServiceURL,
	// defaulting to the locally-tested http://127.0.0.1:39093) rather
	// than an empty placeholder — this is what RXT submits actually
	// verify against.
	validators := validator.NewRegistry(cfg.randomXServiceURL)
	vardiffCfg := solo.VardiffConfig{
		MinDifficulty:    cfg.minDifficulty,
		MaxDifficulty:    cfg.maxDifficulty,
		TargetTime:       cfg.vardiffTargetTime,
		RetargetInterval: cfg.vardiffInterval,
	}
	// One Server shared by every port tier: same
	// JobManager/ConnectionManager/NodeClient/validator, multiple
	// concurrent listeners (see the Serve fan-out below) each
	// stamping newly-accepted sessions with ITS OWN starting
	// difficulty.
	server := solo.NewServer(cm, jobManager, node, validators, networkFromString(cfg.network), logger, vardiffCfg)
	defer server.Shutdown()

	server.SetDebugLogger(debugLogger)

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2a): worker
	// count is runtime.NumCPU() by DEFAULT (server.NewServer's own
	// construction already applies this -- see solo/asyncvalidation.go's
	// doc comment), not a hardcoded literal 8; an operator who wants a
	// different fixed count can still get one via -randomx-workers.
	if cfg.randomxWorkers > 0 {
		server.SetRandomXWorkerPoolSize(cfg.randomxWorkers, 0)
		logger.Printf("RandomX-family async validation worker pool size overridden to %d (default would have been runtime.NumCPU()=%d)", cfg.randomxWorkers, runtime.NumCPU())
	}

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b): disconnect
	// a session after too many consecutive real RandomX-family
	// block-find-level validation failures, so a hostile session
	// submitting fabricated above-target claims cannot keep flooding
	// the shared async validation pool for free. Enabled by default
	// (a security-hardening default, not an opt-in tradeoff) --
	// -invalid-share-disconnect-enabled=false turns it off entirely.
	server.SetInvalidShareGuardConfig(leaflib.InvalidShareGuardConfig{
		Enabled:   cfg.invalidShareDisconnectEnabled,
		Threshold: cfg.invalidShareDisconnectThreshold,
	})
	if cfg.invalidShareDisconnectEnabled {
		logger.Printf("consecutive-invalid-share disconnect guard ENABLED (threshold=%d -- 0 means the documented default is in effect)", cfg.invalidShareDisconnectThreshold)
	} else {
		logger.Printf("consecutive-invalid-share disconnect guard DISABLED by operator config")
	}

	// Real, manual ban/forced-minimum-difficulty enforcement (see
	// internal/leaflib/addressflags's package doc comment). Disabled
	// (server.addressFlags stays nil) unless -address-flags-file/
	// LEAF_SOLO_ADDRESS_FLAGS_FILE is set -- leaf-solo has no backend
	// to poll instead, so a local file is the only real Source.
	if cfg.addressFlagsFile != "" {
		flagsCache := addressflags.NewCache(addressflags.NewFileSource(cfg.addressFlagsFile), cfg.addressFlagsPollInterval, logger)
		flagsCache.Start(ctx)
		server.EnableAddressFlags(flagsCache)
		logger.Printf("manual ban/forced-minimum-difficulty enforcement ENABLED, polling %s every %s", cfg.addressFlagsFile, cfg.addressFlagsPollInterval)
	}

	if cfg.metricsListenAddress != "" {
		server.SetHideRemoteAddress(cfg.hideRemoteAddress)
		server.EnableMetrics(version, cfg.maxAddressLabels)
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", server.MetricsHandler())
		metricsMux.Handle("/", server.StatsHTMLHandler())
		metricsSrv := &http.Server{Addr: cfg.metricsListenAddress, Handler: metricsMux}
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

	listeners := make([]net.Listener, 0, len(ports))

	// One shared tls.Certificate for the whole process (see
	// internal/leaflib.LoadOrGenerateCert's doc comment) -- only
	// constructed at all if at least one configured port tier has
	// TLS enabled. If no port has TLS enabled, this is skipped
	// entirely: no behavior change, no wasted work.
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
			logger.Printf("listening for miners on %s (TLS) (starting difficulty %d)", p.Address, p.Difficulty)
		} else {
			logger.Printf("listening for miners on %s (starting difficulty %d)", p.Address, p.Difficulty)
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
