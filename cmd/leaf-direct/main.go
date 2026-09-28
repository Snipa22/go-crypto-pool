// Command leaf-direct is the leaf binary for mode 1: direct-to-backend.
// This is the "normal" production ingest path — a real Monero-family
// stratum server that speaks the exact same wire protocol and
// validates shares/blocks with the exact same real per-algo validators
// as leaf-solo, but forwards every validated share/block to the real
// backend over HTTP+Protobuf (internal/leaflib/transport) instead of
// self-tracking/submitting to a single daemon.
//
// Two capabilities exist here that leaf-solo has no equivalent of:
//
//  1. Direct parallel block submission to multiple configured GRPC
//     node addresses on a genuine block find (LEAF_DIRECT_SUBMIT_NODES),
//     with "at least one acceptance = success" semantics.
//  2. A generic, coin-agnostic best-effort NATS relay
//     broadcast/resubmit mechanism for found blocks
//     (LEAF_DIRECT_RELAY_NATS_URL), fully optional and never blocking
//     the primary path when unconfigured.
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

	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/cfgfile"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/direct"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/legacytransport"
	monerozmq "github.com/Snipa22/go-crypto-pool/internal/leaflib/monero/zmq"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	legacypb "github.com/Snipa22/go-crypto-pool/internal/legacyproto"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// version is a build-time-overridable identifier — override via
// -ldflags "-X main.version=...".
var version = "dev"

type config struct {
	nodeGRPCAddress string
	listenAddress   string
	payoutAddress   string
	trustEnabled    bool
	trustThreshold  int
	trustPenalty    int
	trustChange     int
	trustMin        int
	network         string
	coin            string
	standalone      bool
	monerodURL      string
	mergeMineChains string
	algo            string
	poolType        string

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

	// jobFetchWorkers is CLOSE-WAIT-production-incident fix's own
	// -job-fetch-workers -- mirrors -randomx-workers's exact same
	// "0/unset uses the documented default" convention (see
	// internal/leaflib/direct.Server.jobFetchPool's doc comment for
	// the full rationale).
	jobFetchWorkers int

	// poolID is LEAF_DIRECT_POOL_ID / -pool-id: the real, static,
	// operator-assigned integer identifying this leaf-direct
	// process's pool-server source (see internal/proto/share.proto's
	// Share.pool_id doc comment for the full rationale/history).
	// REQUIRED -- no safe silent default, since an unset pool_id
	// would defeat the entire purpose of pool-source tracking (every
	// leaf silently reporting as pool_id=0 is indistinguishable from
	// "not configured" and makes the backend's real, wired-up
	// pool_id-broken-out stats endpoint (GET
	// /api/v1/stats/hashrate/sources) useless).
	poolID int

	randomXServiceURL string

	// coinbaseExtraTag mirrors leaf-solo's own cfg.coinbaseExtraTag
	// exactly -- -coinbase-extra-tag / LEAF_DIRECT_COINBASE_EXTRA_TAG,
	// an explicit operator override for the coinbase-extra ownership
	// tag appended to every fetched Tari block template. Left empty
	// (the default), resolveCoinbaseExtraTag computes a per-algo
	// default ("supportxtm-sha3x"/"supportxtm-c29"/"supportxtm-rxt"/
	// "supportxtm-rxm") instead -- see that function's doc comment.
	coinbaseExtraTag string

	startingDifficulty uint64
	portsRaw           string
	minDifficulty      uint64
	maxDifficulty      uint64
	vardiffTargetTime  int
	vardiffInterval    time.Duration

	// tlsCertFile / tlsKeyFile / tlsCertPersistPath configure the
	// optional, ALONGSIDE-existing-plaintext-ports TLS listener
	// support (see internal/leaflib.LoadOrGenerateCert's doc comment
	// for the full design rationale -- self-signed certs are
	// intentional and sufficient here, mining traffic is only being
	// wire-shape-disguised as HTTPS, not authenticated). These are
	// only ever consulted if at least one -ports/LEAF_DIRECT_PORTS
	// entry carries the ":tls" suffix (see parsePortEntry); if no
	// port has TLS enabled, none of these three are touched at all --
	// zero behavior change for every existing deployment. All three
	// left empty (the default) means: no operator-supplied cert/key,
	// and no on-disk persistence of an auto-generated one (a fresh
	// self-signed cert is generated in memory and rotates every
	// restart).
	tlsCertFile        string
	tlsKeyFile         string
	tlsCertPersistPath string

	refreshInterval time.Duration
	tipPollInterval time.Duration
	jobMaxAge       time.Duration

	maxConnections int
	idleTimeout    time.Duration

	// noShareTimeout is this feature's own -no-share-timeout/
	// LEAF_DIRECT_NO_SHARE_TIMEOUT flag (see its flag.DurationVar
	// registration below and direct.ServerConfig.NoShareTimeout's
	// doc comment for the full rationale). Zero/negative disables
	// the feature entirely, mirroring idleTimeout's own
	// -idle-timeout convention.
	noShareTimeout time.Duration

	metricsListenAddress string
	maxAddressLabels     int

	// statsPageMaxSessions is this feature's own
	// -stats-page-max-sessions/LEAF_DIRECT_STATS_PAGE_MAX_SESSIONS
	// flag (see its flag.IntVar registration below and
	// direct.Server.SetStatsPageMaxSessions's doc comment for the
	// full rationale). 0/negative disables the cap entirely,
	// mirroring idleTimeout/noShareTimeout's own zero-disables
	// convention.
	statsPageMaxSessions int

	// hideRemoteAddress mirrors cmd/leaf-solo's identical flag
	// exactly (see solo.Server.SetHideRemoteAddress's doc comment).
	// Defaults to false.
	hideRemoteAddress bool

	// backendBaseURL / backendAuth* configure the real
	// HTTPProtobufTransport this leaf forwards every validated share/
	// block to — this leaf's whole reason for existing (see this
	// binary's own doc comment).
	backendBaseURL      string
	backendAuthHeader   string
	backendAuthValue    string
	backendShareTimeout time.Duration
	backendBlockTimeout time.Duration

	// legacyMode / legacyBackendURL / legacyAuthKey / legacyPoolType /
	// legacyPoolID configure the opt-in, default-off legacy
	// nodejs-pool-sxmr wire-protocol mode (see
	// internal/leaflib/legacytransport). When legacyMode is false (the
	// default), all four legacy* fields below are ignored entirely --
	// no validation, no effect, zero behavior change from the pre-
	// existing HTTPProtobufTransport path.
	legacyMode bool

	// legacyBackendURL is LEAF_DIRECT_LEGACY_BACKEND_URL: the legacy
	// backend's full base URL (scheme+host+port), e.g.
	// "https://schwifty37.snipanet.com:4443". legacytransport.New
	// appends "/leafApi" itself. REQUIRED when legacyMode is true.
	legacyBackendURL string

	// legacyAuthKey is LEAF_DIRECT_LEGACY_AUTH_KEY: the real WSData.key
	// secret (a plain string field, not an HTTP header -- see
	// legacytransport's package doc comment). Never logged, never
	// written to any file this code creates. REQUIRED when legacyMode
	// is true.
	legacyAuthKey string

	// legacyPoolType is LEAF_DIRECT_LEGACY_POOL_TYPE: pplns|pps|prop|solo.
	// REQUIRED when legacyMode is true.
	//
	// This is deliberately a SEPARATE flag from -pool-type, since the
	// legacy backend is a genuinely different deployment that may use a
	// different payout-model value than this leaf's own go-crypto-pool-
	// side -pool-type. This is an OPEN DESIGN QUESTION -- confirm with
	// Alex whether legacy-mode pool-type/pool-id should ever be allowed
	// to just mirror -pool-type/-pool-id, or whether they must always be
	// independently configured like this. Defaulting to independent
	// config here as the safer assumption.
	legacyPoolType string

	// legacyPoolID is LEAF_DIRECT_LEGACY_POOL_ID: REQUIRED (> 0) when
	// legacyMode is true.
	//
	// Same rationale/doc-comment as legacyPoolType above -- independent
	// from -pool-id by design, flagged as needing Alex's explicit
	// confirmation.
	legacyPoolID int

	// legacyCheckinEnabled is LEAF_DIRECT_LEGACY_CHECKIN_ENABLED:
	// whether the real legacy /poolCheckin heartbeat (see
	// internal/leaflib/legacytransport/checkin.go) runs at all.
	// Defaults to true (ENABLED) whenever legacyMode is also true --
	// this is the OPEN DESIGN QUESTION flagged for Alex's review: the
	// heartbeat is a genuinely separate concern from core share/block
	// forwarding (pool-core's own routing/health-check side effect,
	// not payout correctness), but this codebase's precedent (PR #133,
	// legacy-mode's own all-or-nothing required-field validation) is
	// to default to the safer, stricter option and let review be the
	// safety net -- so this defaults to true rather than false. An
	// operator who genuinely wants legacy share/block forwarding
	// WITHOUT the heartbeat (e.g. running the Python sidecar a while
	// longer during a staged rollout) can still set this to false
	// explicitly. Ignored entirely when legacyMode is false.
	legacyCheckinEnabled bool

	// legacyCheckinAPIURL is LEAF_DIRECT_LEGACY_CHECKIN_API_URL: the
	// legacy backend's real `config_api` base URL (e.g.
	// "http://203.0.113.10:32322/poolApi/" in production) --
	// legacytransport.Checkin appends "poolCheckin" itself. REQUIRED
	// when legacyMode && legacyCheckinEnabled, ignored otherwise.
	legacyCheckinAPIURL string

	// legacyCheckinAuthToken is LEAF_DIRECT_LEGACY_CHECKIN_AUTH_TOKEN:
	// the real `api_auth_token` secret, sent as the `x-pool-auth` HTTP
	// header -- DELIBERATELY SEPARATE from -legacy-auth-key (the
	// WSData.key checked on /leafApi): these are two distinct real
	// secrets on the real legacy backend (confirmed from
	// remoteShare.js's separate auth checks on /leafApi vs
	// /poolApi/poolCheckin). Never logged. REQUIRED when
	// legacyMode && legacyCheckinEnabled, ignored otherwise.
	legacyCheckinAuthToken string

	// legacyCheckinInterval overrides
	// legacytransport.DefaultCheckinInterval (10s, matching the real
	// legacy sender's exact cadence). Ignored when the heartbeat is
	// not running.
	legacyCheckinInterval time.Duration

	// legacyBlockRetryBudget is LEAF_DIRECT_LEGACY_BLOCK_RETRY_BUDGET:
	// the total wall-clock budget legacytransport.LegacyTransport's
	// SubmitBlock retry-with-backoff loop is allowed before giving up
	// on a found block that keeps getting a non-2xx response from the
	// legacy backend (see legacytransport.DefaultBlockSubmitRetryBudget's
	// doc comment for the full 2026-09-23 production-incident
	// rationale: a genuine mainnet block find was permanently lost
	// because the legacy backend's own chain view hadn't synced yet at
	// the single moment of a one-shot submission). Defaults to
	// legacytransport.DefaultBlockSubmitRetryBudget (5 MINUTES --
	// Alex's explicit direction, 2026-09-23) when unset/zero. Ignored
	// entirely when legacyMode is false (the normal, non-legacy
	// transport.HTTPProtobufTransport has no retry loop at all).
	//
	// IMPORTANT: this value also drives the outer forwardBlock ctx
	// timeout (direct.ServerConfig.BlockForwardTimeout, set from this
	// value + slack below) -- the two are deliberately kept in sync so
	// the retry loop this flag configures actually gets to run its
	// full intended budget rather than being cut short by its own
	// caller.
	legacyBlockRetryBudget time.Duration

	// addressFlagsPollInterval configures the real, manual ban/
	// forced-minimum-difficulty enforcement described in
	// internal/leaflib/addressflags's package doc comment. Unlike
	// leaf-solo, leaf-direct always has a real backend connection
	// (LEAF_DIRECT_BACKEND_BASE_URL, above) already configured, so
	// it always polls the backend's own GET
	// /api/v1/leaf/address-flags endpoint (addressflags.HTTPSource)
	// for this rather than needing a separate file/URL flag -- there
	// is no way to disable this feature short of the backend never
	// having anything flagged, which is exactly the common case.
	addressFlagsPollInterval time.Duration

	// submitNodesRaw is LEAF_DIRECT_SUBMIT_NODES: a comma-separated
	// list of ADDITIONAL GRPC node addresses (beyond the primary
	// template-source node, which is always included too) to submit a
	// genuine block find to, in real parallel — see
	// internal/leaflib/direct/multisubmit.go.
	submitNodesRaw string

	// relayNATSURL is LEAF_DIRECT_RELAY_NATS_URL: empty disables the
	// NATS relay entirely (a complete no-op) — see
	// internal/leaflib/relay.
	relayNATSURL string
	relaySubject string

	// relayNATSUsername/relayNATSPassword are
	// LEAF_DIRECT_RELAY_NATS_USERNAME/LEAF_DIRECT_RELAY_NATS_PASSWORD:
	// optional NATS username/password auth (mirrors nats.UserInfo --
	// see relay.Config.Username/Password's doc comment). Both empty
	// (the default) preserves today's plaintext-no-auth connect
	// behavior byte-for-byte. relayNATSPassword is a plain string
	// secret, never logged, exactly like legacyAuthKey above.
	relayNATSUsername string
	relayNATSPassword string

	// relayNATSTLSCAFile/relayNATSTLSCertFile/relayNATSTLSKeyFile are
	// LEAF_DIRECT_RELAY_NATS_TLS_CA_FILE/
	// LEAF_DIRECT_RELAY_NATS_TLS_CERT_FILE/
	// LEAF_DIRECT_RELAY_NATS_TLS_KEY_FILE: optional TLS options for
	// the NATS connection (mirrors nats.RootCAs/nats.ClientCert --
	// see relay.Config's own doc comment). All empty (the default)
	// appends no TLS option at all.
	relayNATSTLSCAFile   string
	relayNATSTLSCertFile string
	relayNATSTLSKeyFile  string

	// templateRelaySubject is LEAF_DIRECT_TEMPLATE_RELAY_SUBJECT:
	// overrides relay.DefaultTemplateSubject for the template-relay
	// fast-invalidation broadcast (see internal/leaflib/relay's
	// TemplateMessage/PublishTemplate/SubscribeTemplate). Empty (the
	// default) falls back to relay.DefaultTemplateSubject. Reuses the
	// SAME relayNATSURL connection above -- there is no separate NATS
	// URL for this.
	templateRelaySubject string

	// moneroZMQURL is LEAF_DIRECT_MONERO_ZMQ_URL: the real monerod ZMQ
	// endpoint (e.g. "tcp://127.0.0.1:28082") to subscribe to for a
	// real, ADDITIONAL fast block-invalidation trigger on top of the
	// existing tip-poll baseline (see internal/leaflib/monero/zmq).
	// Empty (the default) disables this entirely -- a complete no-op,
	// never dialed. Ignored entirely for -coin=tari.
	moneroZMQURL string

	// configFile is the optional path to a TOML file providing
	// defaults for any flag above that the operator did not set
	// explicitly via CLI flag or environment variable. See
	// leaf-direct.example.toml and internal/leaflib/cfgfile for the
	// exact precedence rule (flag > env > file > hardcoded default).
	configFile string

	// debug is -debug/LEAF_DIRECT_DEBUG: enables the shared
	// leaflib.DebugLogger (internal/leaflib/debuglog.go) for this
	// process. OFF (false) by default -- purely additive, byte-
	// identical existing log output when left off. Wired into
	// direct.ServerConfig.Debug below.
	debug bool
}

func loadConfig() (config, error) {
	cfg := config{}

	flag.StringVar(&cfg.nodeGRPCAddress, "node-grpc-address", envOr("LEAF_NODE_GRPC_ADDRESS", ""), "Tari base node GRPC address (host:port); also the primary template-source AND is always included in the multi-node submit set. REQUIRED when -coin=tari (the default); ignored for -coin=monero. Env: LEAF_NODE_GRPC_ADDRESS")
	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_DIRECT_LISTEN_ADDRESS", ":4444"), "miner-facing TCP listen address. Env: LEAF_DIRECT_LISTEN_ADDRESS")
	flag.StringVar(&cfg.payoutAddress, "payout-address", envOr("LEAF_DIRECT_PAYOUT_ADDRESS", ""), "pool payout/coinbase address for fetched block templates. Env: LEAF_DIRECT_PAYOUT_ADDRESS")
	flag.StringVar(&cfg.network, "network", envOr("LEAF_DIRECT_NETWORK", "testnet"), "network tag for share/block records: mainnet|testnet. Env: LEAF_DIRECT_NETWORK")
	flag.StringVar(&cfg.coin, "coin", envOr("LEAF_DIRECT_COIN", "tari"), "which coin/PoW family this leaf-direct process serves: tari (default, unchanged behavior) or a coin ticker from internal/coinprofile.Registry (xmr, arq, xeq, grft, sfx, zeph, sal -- case-insensitive). \"monero\" is a backward-compatible alias for \"xmr\" in its exact existing merge-mine (ALGO_RXM) behavior; see -standalone to run non-merge-mined XMR instead. An unregistered ticker fails fast at startup. Env: LEAF_DIRECT_COIN")
	flag.BoolVar(&cfg.standalone, "standalone", envOr("LEAF_DIRECT_STANDALONE", "false") == "true", "only meaningful for -coin=xmr/monero: when true, runs standalone (non-merge-mined) XMR (poolpb.Algo_ALGO_XMR) against -monerod-url instead of the default Tari-merge-mined ALGO_RXM behavior. No effect for -coin=tari or any other registered coin ticker (already always standalone). Env: LEAF_DIRECT_STANDALONE (\"true\" to enable)")
	flag.StringVar(&cfg.monerodURL, "monerod-url", envOr("LEAF_DIRECT_MONEROD_URL", ""), "real monerod-JSON-RPC-compatible base URL (e.g. http://148.163.90.157:28081). REQUIRED when -coin resolves to any monerod-family coin; ignored for -coin=tari. Env: LEAF_DIRECT_MONEROD_URL")
	flag.StringVar(&cfg.mergeMineChains, "merge-mine-chains", envOr("LEAF_DIRECT_MERGE_MINE_CHAINS", ""), "comma-separated NAME:auxid pairs naming every merge-mined chain this leaf should ALSO check the same PoW submission against, on top of the primary chain -- only meaningful for -coin=monero, ignored for -coin=tari. auxid is the aux-chain identifier a merge-mining proxy's own submit_block response tags that chain's aux_chain_data entry with (see internal/leaflib/solo.AuxChainResult's doc comment; Tari's own real minotari_merge_mining_proxy convention, confirmed live, is \"xtr\"). Empty (default) disables merge-mine-chain checking entirely -- this leaf then behaves exactly as it did before this feature existed. Example: 'TARI:xtr'. A future deployment could configure more than one entry (comma-separated) without a code change. Env: LEAF_DIRECT_MERGE_MINE_CHAINS")
	flag.BoolVar(&cfg.trustEnabled, "trust-enabled", envOr("LEAF_DIRECT_TRUST_ENABLED", "false") == "true", "enable the real, legacy-ported probabilistic RandomX-validation-skip mechanism for RXT/RXM shares (see internal/leaflib/solo/trust.go) -- mirrors leaf-solo's identical flag exactly. Disabled by default. REAL-MONEY RISK (DISPATCH_BRIEF.md, 2026-09-10): unlike leaf-solo (no share table/backend/payouts, and this mechanism has since been removed there entirely), a leaf-direct share that skips validation here still reaches the real backend's payout accounting on the miner's own claimed value, with no cryptographic re-check by this leaf -- see internal/leaflib/direct.Server.EnableTrust's doc comment for the full risk framing. A deliberate trust-for-throughput tradeoff, not a free feature. Env: LEAF_DIRECT_TRUST_ENABLED (\"true\" to enable)")
	flag.IntVar(&cfg.trustThreshold, "trust-threshold", envOrInt("LEAF_DIRECT_TRUST_THRESHOLD", 0), "real trust-ramp threshold gate -- 0/unset uses the documented default (10). Env: LEAF_DIRECT_TRUST_THRESHOLD")
	flag.IntVar(&cfg.trustPenalty, "trust-penalty", envOrInt("LEAF_DIRECT_TRUST_PENALTY", 0), "real trust-ramp penalty gate, re-armed after any rejected share -- 0/unset uses the documented default (30). Env: LEAF_DIRECT_TRUST_PENALTY")
	flag.IntVar(&cfg.trustChange, "trust-change", envOrInt("LEAF_DIRECT_TRUST_CHANGE", 0), "real per-accepted-share probability decrement -- 0/unset uses the documented default (1). Env: LEAF_DIRECT_TRUST_CHANGE")
	flag.IntVar(&cfg.trustMin, "trust-min", envOrInt("LEAF_DIRECT_TRUST_MIN", 0), "real probability floor -- 0/unset uses the documented default (20). Env: LEAF_DIRECT_TRUST_MIN")
	flag.IntVar(&cfg.randomxWorkers, "randomx-workers", envOrInt("LEAF_DIRECT_RANDOMX_WORKERS", 0), "RandomX-family (RXT/RXM) async validation worker pool size (see internal/leaflib/solo/asyncvalidation.go). 0/unset uses the documented default, runtime.NumCPU() -- NOT a hardcoded literal. Env: LEAF_DIRECT_RANDOMX_WORKERS")
	flag.IntVar(&cfg.randomxQueueSize, "randomx-queue-size", envOrInt("LEAF_DIRECT_RANDOMX_QUEUE_SIZE", 0), "RandomX-family (RXT/RXM) async validation pool's bounded queue capacity (see internal/leaflib/solo/asyncvalidation.go). 0/unset uses the documented default, max(256, randomx-workers*16) -- NOT a hardcoded flat literal. Env: LEAF_DIRECT_RANDOMX_QUEUE_SIZE")
	flag.IntVar(&cfg.jobFetchWorkers, "job-fetch-workers", envOrInt("LEAF_DIRECT_JOB_FETCH_WORKERS", 0), "job-template-fetch (login/getjob) async worker pool size (see internal/leaflib/direct.Server.jobFetchPool's doc comment for the CLOSE-WAIT production-incident fix this pool exists for). 0/unset uses the documented default, runtime.NumCPU() -- NOT a hardcoded literal. Env: LEAF_DIRECT_JOB_FETCH_WORKERS")
	flag.BoolVar(&cfg.invalidShareDisconnectEnabled, "invalid-share-disconnect-enabled", envOr("LEAF_DIRECT_INVALID_SHARE_DISCONNECT_ENABLED", "true") == "true", "disconnect a session after too many CONSECUTIVE real RandomX-family (RXT/RXM) validation failures (see internal/leaflib.InvalidShareGuard) -- a security-hardening default, enabled unless explicitly turned off. Env: LEAF_DIRECT_INVALID_SHARE_DISCONNECT_ENABLED (\"false\" to disable)")
	flag.IntVar(&cfg.invalidShareDisconnectThreshold, "invalid-share-disconnect-threshold", envOrInt("LEAF_DIRECT_INVALID_SHARE_DISCONNECT_THRESHOLD", 0), "consecutive-invalid-share threshold before a session is disconnected (see -invalid-share-disconnect-enabled). 0/unset uses the documented default (20). Env: LEAF_DIRECT_INVALID_SHARE_DISCONNECT_THRESHOLD")
	flag.StringVar(&cfg.algo, "algo", envOr("LEAF_DIRECT_ALGO", "sha3x"), "which single mining algorithm this leaf-direct process serves: sha3x (default), c29, or rxt -- for -coin=tari only. Ignored (always ALGO_RXM/plain RandomX) when -coin=monero. Env: LEAF_DIRECT_ALGO")
	flag.StringVar(&cfg.poolType, "pool-type", envOr("LEAF_DIRECT_POOL_TYPE", ""), "real pool payout model stamped onto every share/block forwarded to the backend: pplns|pps|prop|solo. REQUIRED UNCONDITIONALLY, even when -legacy-mode=true -- legacytransport derives the actual outgoing legacy PoolType from this value (see requiredFieldsError's doc comment). Env: LEAF_DIRECT_POOL_TYPE")
	flag.IntVar(&cfg.poolID, "pool-id", envOrInt("LEAF_DIRECT_POOL_ID", 0), "real, static, operator-assigned pool-server-source identifier stamped onto every share/block forwarded to the backend (see internal/proto/share.proto's Share.pool_id doc comment). REQUIRED, must be > 0, when -legacy-mode=false. Not required (and has no effect) when -legacy-mode=true -- legacytransport uses its own separate -legacy-pool-id instead (see requiredFieldsError's doc comment). Env: LEAF_DIRECT_POOL_ID")
	flag.StringVar(&cfg.randomXServiceURL, "randomx-service-url", envOr("LEAF_DIRECT_RANDOMX_SERVICE_URL", "http://127.0.0.1:39093"), "RandomX-verification HTTP daemon address (only consulted when -algo=rxt). Env: LEAF_DIRECT_RANDOMX_SERVICE_URL")
	flag.StringVar(&cfg.coinbaseExtraTag, "coinbase-extra-tag", envOr("LEAF_DIRECT_COINBASE_EXTRA_TAG", ""), "coinbase-extra ownership tag appended to every fetched Tari block template (identifies this leaf's found blocks on-chain). Left unset (the default), a per-algo default is computed instead: supportxtm-sha3x / supportxtm-c29 / supportxtm-rxt / supportxtm-rxm, based on -algo/-coin -- see resolveCoinbaseExtraTag. When set, this value is used verbatim, overriding the per-algo default. Truncated to solo.MaxCoinbaseExtraTagLen bytes if longer. Env: LEAF_DIRECT_COINBASE_EXTRA_TAG")

	flag.Uint64Var(&cfg.startingDifficulty, "starting-difficulty", envOrUint64("LEAF_DIRECT_STARTING_DIFFICULTY", 10000), "starting share difficulty for a newly-connected session. Env: LEAF_DIRECT_STARTING_DIFFICULTY")
	flag.StringVar(&cfg.portsRaw, "ports", envOr("LEAF_DIRECT_PORTS", ""), "comma-separated list of address:difficulty[:desc][:tls] port tiers, e.g. '0.0.0.0:4444:1000:sha3x-plain,0.0.0.0:4443:1000:sha3x-tls:tls' (first entry plain, second entry same difficulty on a different port with TLS enabled). The optional trailing ':tls' marker (case-insensitive) enables the shared self-signed TLS listener for that ONE port tier only -- see -tls-cert-file/-tls-key-file/-tls-cert-persist-path. When unset, -listen-address/-starting-difficulty are used as a single implicit tier (plain, no TLS). Fully backward-compatible: any entry without a trailing ':tls' field parses exactly as before. Env: LEAF_DIRECT_PORTS")
	flag.Uint64Var(&cfg.minDifficulty, "min-difficulty", envOrUint64("LEAF_DIRECT_MIN_DIFFICULTY", 100), "absolute floor vardiff will never retarget below. Env: LEAF_DIRECT_MIN_DIFFICULTY")
	flag.Uint64Var(&cfg.maxDifficulty, "max-difficulty", envOrUint64("LEAF_DIRECT_MAX_DIFFICULTY", 1_000_000_000), "absolute ceiling vardiff will never retarget above. Env: LEAF_DIRECT_MAX_DIFFICULTY")
	flag.IntVar(&cfg.vardiffTargetTime, "vardiff-target-time", envOrInt("LEAF_DIRECT_VARDIFF_TARGET_TIME", 30), "seconds between shares vardiff aims for. Env: LEAF_DIRECT_VARDIFF_TARGET_TIME")
	flag.DurationVar(&cfg.vardiffInterval, "vardiff-retarget-interval", envOrDuration("LEAF_DIRECT_VARDIFF_RETARGET_INTERVAL", 60*time.Second), "how often each session's own vardiff retarget timer fires. Env: LEAF_DIRECT_VARDIFF_RETARGET_INTERVAL")

	flag.StringVar(&cfg.tlsCertFile, "tls-cert-file", envOr("LEAF_DIRECT_TLS_CERT_FILE", ""), "optional PEM-encoded TLS certificate file for the shared, process-wide self-signed-or-operator-supplied cert used by any ':tls'-suffixed -ports entry. Empty (default) auto-generates a self-signed cert instead -- see -tls-cert-persist-path. Ignored entirely if no port has TLS enabled. Env: LEAF_DIRECT_TLS_CERT_FILE")
	flag.StringVar(&cfg.tlsKeyFile, "tls-key-file", envOr("LEAF_DIRECT_TLS_KEY_FILE", ""), "optional PEM-encoded TLS private key file paired with -tls-cert-file. Env: LEAF_DIRECT_TLS_KEY_FILE")
	flag.StringVar(&cfg.tlsCertPersistPath, "tls-cert-persist-path", envOr("LEAF_DIRECT_TLS_CERT_PERSIST_PATH", ""), "where to persist an auto-generated self-signed TLS cert/key pair so restarts reload it instead of rotating it. Empty (default) means in-memory only -- a fresh self-signed cert is generated on every restart. Ignored if -tls-cert-file/-tls-key-file are set. Env: LEAF_DIRECT_TLS_CERT_PERSIST_PATH")

	flag.DurationVar(&cfg.refreshInterval, "refresh-interval", envOrDuration("LEAF_DIRECT_REFRESH_INTERVAL", 30*time.Second), "unconditional block-template refresh interval. Env: LEAF_DIRECT_REFRESH_INTERVAL")
	flag.DurationVar(&cfg.tipPollInterval, "tip-poll-interval", envOrDuration("LEAF_DIRECT_TIP_POLL_INTERVAL", 5*time.Second), "chain-tip poll interval. Env: LEAF_DIRECT_TIP_POLL_INTERVAL")
	flag.DurationVar(&cfg.jobMaxAge, "job-max-age", envOrDuration("LEAF_DIRECT_JOB_MAX_AGE", 6*time.Minute), "real per-job expiry threshold, independent of tip-invalidation. Env: LEAF_DIRECT_JOB_MAX_AGE")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_DIRECT_MAX_CONNECTIONS", leaflib.DefaultLeafMaxConnections), "max concurrent miner connections, 0 = unlimited. Env: LEAF_DIRECT_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_DIRECT_IDLE_TIMEOUT", 2*time.Minute), "rolling per-connection idle timeout. Env: LEAF_DIRECT_IDLE_TIMEOUT")
	flag.DurationVar(&cfg.noShareTimeout, "no-share-timeout", envOrDuration("LEAF_DIRECT_NO_SHARE_TIMEOUT", 3*time.Minute), "disconnect a session that has never submitted a single accepted share within this long of connecting (a huge number of miners connect and only ever send keepalived, never a real submit, wasting a connection slot indefinitely -- this is separate from -idle-timeout, which only resets on total silence). 0 or negative disables this check entirely. Env: LEAF_DIRECT_NO_SHARE_TIMEOUT")

	flag.StringVar(&cfg.metricsListenAddress, "metrics-listen-address", envOr("LEAF_DIRECT_METRICS_LISTEN_ADDRESS", "127.0.0.1:9601"), "HTTP listen address for /metrics. Defaults to loopback-only (127.0.0.1) -- an operator must explicitly set this to a wildcard/public address to expose it publicly. Empty disables it. Includes real found-block/template NATS relay observability (leaf_relay_*/leaf_direct_relay_resubmit_total) whenever -relay-nats-url is configured -- see internal/leaflib/direct/metrics's doc comment. Env: LEAF_DIRECT_METRICS_LISTEN_ADDRESS")
	flag.IntVar(&cfg.maxAddressLabels, "max-address-labels", envOrInt("LEAF_DIRECT_MAX_ADDRESS_LABELS", 0), "cap on distinct payment-address labels tracked by metrics (0 = package default). Env: LEAF_DIRECT_MAX_ADDRESS_LABELS")
	flag.IntVar(&cfg.statsPageMaxSessions, "stats-page-max-sessions", envOrInt("LEAF_DIRECT_STATS_PAGE_MAX_SESSIONS", direct.DefaultStatsPageMaxSessions), "cap on how many session rows the stats HTML page's \"Connected sessions\" table renders (the separate \"Active connections\" summary count is always accurate/uncapped). 0 or negative disables the cap entirely (render every session). Env: LEAF_DIRECT_STATS_PAGE_MAX_SESSIONS")
	flag.BoolVar(&cfg.hideRemoteAddress, "hide-remote-address", envOr("LEAF_DIRECT_HIDE_REMOTE_ADDRESS", "false") == "true", "omit the \"Remote address\" column from the stats HTML page entirely -- recommended for public-facing deployments. Disabled by default. Env: LEAF_DIRECT_HIDE_REMOTE_ADDRESS (\"true\" to enable)")

	flag.StringVar(&cfg.backendBaseURL, "backend-base-url", envOr("LEAF_DIRECT_BACKEND_BASE_URL", ""), "real backend base URL every validated share/block is forwarded to over HTTP+Protobuf, and that the address-flags ban/forced-min-difficulty poller polls. REQUIRED when -legacy-mode=false. Not required (and unused) when -legacy-mode=true, which forwards via -legacy-backend-url instead and has no address-flags equivalent yet. Env: LEAF_DIRECT_BACKEND_BASE_URL")
	flag.StringVar(&cfg.backendAuthHeader, "backend-auth-header", envOr("LEAF_DIRECT_BACKEND_AUTH_HEADER", ""), "optional shared-secret/bearer auth header name sent with every backend request. Env: LEAF_DIRECT_BACKEND_AUTH_HEADER")
	flag.StringVar(&cfg.backendAuthValue, "backend-auth-value", envOr("LEAF_DIRECT_BACKEND_AUTH_VALUE", ""), "value for -backend-auth-header. Env: LEAF_DIRECT_BACKEND_AUTH_VALUE")
	flag.DurationVar(&cfg.backendShareTimeout, "backend-share-timeout", envOrDuration("LEAF_DIRECT_BACKEND_SHARE_TIMEOUT", 5*time.Second), "per-call timeout forwarding a share to the backend. Env: LEAF_DIRECT_BACKEND_SHARE_TIMEOUT")
	flag.DurationVar(&cfg.backendBlockTimeout, "backend-block-timeout", envOrDuration("LEAF_DIRECT_BACKEND_BLOCK_TIMEOUT", 10*time.Second), "per-call timeout reporting a found block to the backend. Env: LEAF_DIRECT_BACKEND_BLOCK_TIMEOUT")
	flag.DurationVar(&cfg.addressFlagsPollInterval, "address-flags-poll-interval", envOrDuration("LEAF_DIRECT_ADDRESS_FLAGS_POLL_INTERVAL", 30*time.Second), "how often the backend's GET /api/v1/leaf/address-flags endpoint is polled for manual ban/forced-minimum-difficulty state (see internal/leaflib/addressflags). Env: LEAF_DIRECT_ADDRESS_FLAGS_POLL_INTERVAL")

	flag.BoolVar(&cfg.legacyMode, "legacy-mode", envOr("LEAF_DIRECT_LEGACY_MODE", "false") == "true", "opt-in, default-off legacy nodejs-pool-sxmr /leafApi wire-protocol mode: when true, leaf-direct forwards validated shares/blocks to a legacy nodejs-pool-sxmr backend (internal/leaflib/legacytransport) instead of the normal HTTP+Protobuf backend transport. Requires -legacy-backend-url/-legacy-auth-key/-legacy-pool-type/-legacy-pool-id to all be set. Disabled by default -- zero behavior change for existing deployments. Env: LEAF_DIRECT_LEGACY_MODE (\"true\" to enable)")
	flag.StringVar(&cfg.legacyBackendURL, "legacy-backend-url", envOr("LEAF_DIRECT_LEGACY_BACKEND_URL", ""), "legacy nodejs-pool-sxmr backend base URL (e.g. https://schwifty37.snipanet.com:4443) -- the transport appends /leafApi itself. No scheme is assumed; the real target very likely terminates TLS externally in front of the Node process's plain app.listen(8000), so https is the expected common case. REQUIRED when -legacy-mode=true, ignored otherwise. Env: LEAF_DIRECT_LEGACY_BACKEND_URL")
	flag.StringVar(&cfg.legacyAuthKey, "legacy-auth-key", envOr("LEAF_DIRECT_LEGACY_AUTH_KEY", ""), "real legacy WSData.key secret (a plain string field checked server-side, NOT an HTTP header). Never logged. REQUIRED when -legacy-mode=true, ignored otherwise. Env: LEAF_DIRECT_LEGACY_AUTH_KEY")
	flag.StringVar(&cfg.legacyPoolType, "legacy-pool-type", envOr("LEAF_DIRECT_LEGACY_POOL_TYPE", ""), "legacy backend payout-model value stamped onto every share/block forwarded in legacy mode: pplns|pps|prop|solo. Deliberately SEPARATE from -pool-type -- the legacy backend is a genuinely different deployment that may use a different payout model value. OPEN DESIGN QUESTION: confirm with Alex whether legacy-mode pool-type/pool-id should ever be allowed to just mirror -pool-type/-pool-id, or whether they must always be independently configured like this; defaulting to independent config here as the safer assumption. REQUIRED when -legacy-mode=true, ignored otherwise. Env: LEAF_DIRECT_LEGACY_POOL_TYPE")
	flag.IntVar(&cfg.legacyPoolID, "legacy-pool-id", envOrInt("LEAF_DIRECT_LEGACY_POOL_ID", 0), "legacy backend pool-server-source identifier stamped onto every share/block forwarded in legacy mode, must be > 0. Deliberately SEPARATE from -pool-id -- same OPEN DESIGN QUESTION/rationale as -legacy-pool-type above; confirm with Alex. REQUIRED when -legacy-mode=true, ignored otherwise. Env: LEAF_DIRECT_LEGACY_POOL_ID")
	flag.BoolVar(&cfg.legacyCheckinEnabled, "legacy-checkin-enabled", envOr("LEAF_DIRECT_LEGACY_CHECKIN_ENABLED", "true") == "true", "whether the real legacy /poolCheckin heartbeat (internal/leaflib/legacytransport/checkin.go) runs alongside legacy share/block forwarding. Defaults to true (enabled) whenever -legacy-mode=true. Ignored entirely when -legacy-mode=false. Env: LEAF_DIRECT_LEGACY_CHECKIN_ENABLED (\"false\" to disable while still forwarding shares/blocks in legacy mode)")
	flag.StringVar(&cfg.legacyCheckinAPIURL, "legacy-checkin-api-url", envOr("LEAF_DIRECT_LEGACY_CHECKIN_API_URL", ""), "legacy backend's real config_api base URL for the /poolCheckin heartbeat, e.g. http://203.0.113.10:32322/poolApi/ -- the heartbeat appends poolCheckin itself. REQUIRED when -legacy-mode=true and -legacy-checkin-enabled=true (the default), ignored otherwise. Env: LEAF_DIRECT_LEGACY_CHECKIN_API_URL")
	flag.StringVar(&cfg.legacyCheckinAuthToken, "legacy-checkin-auth-token", envOr("LEAF_DIRECT_LEGACY_CHECKIN_AUTH_TOKEN", ""), "real legacy api_auth_token secret sent as the x-pool-auth HTTP header on every /poolCheckin POST. DELIBERATELY SEPARATE from -legacy-auth-key (the WSData.key checked on /leafApi) -- these are two distinct real secrets on the real legacy backend. Never logged. REQUIRED when -legacy-mode=true and -legacy-checkin-enabled=true (the default), ignored otherwise. Env: LEAF_DIRECT_LEGACY_CHECKIN_AUTH_TOKEN")
	flag.DurationVar(&cfg.legacyCheckinInterval, "legacy-checkin-interval", envOrDuration("LEAF_DIRECT_LEGACY_CHECKIN_INTERVAL", legacytransport.DefaultCheckinInterval), "how often the /poolCheckin heartbeat fires -- matches the real legacy sender's exact 10s cadence by default. Env: LEAF_DIRECT_LEGACY_CHECKIN_INTERVAL")
	flag.DurationVar(&cfg.legacyBlockRetryBudget, "legacy-block-retry-budget", envOrDuration("LEAF_DIRECT_LEGACY_BLOCK_RETRY_BUDGET", legacytransport.DefaultBlockSubmitRetryBudget), "total wall-clock budget legacytransport's SubmitBlock retry-with-backoff loop keeps retrying a found block against the legacy backend before giving up (real production-incident fix, 2026-09-23: absorbs the legacy backend's own transient chain-sync-lag race that previously permanently lost a genuine mainnet block find). Defaults to 5 minutes (Alex's explicit direction, superseding an earlier 60-120s draft). Ignored when -legacy-mode=false. Env: LEAF_DIRECT_LEGACY_BLOCK_RETRY_BUDGET")

	flag.StringVar(&cfg.submitNodesRaw, "submit-nodes", envOr("LEAF_DIRECT_SUBMIT_NODES", ""), "comma-separated list of ADDITIONAL Tari base node GRPC addresses (beyond -node-grpc-address, which is always included) to submit a genuine block find to, in real parallel. Env: LEAF_DIRECT_SUBMIT_NODES")

	flag.StringVar(&cfg.relayNATSURL, "relay-nats-url", envOr("LEAF_DIRECT_RELAY_NATS_URL", ""), "NATS server URL for the best-effort found-block relay broadcast/resubmit mechanism. Empty (default) fully disables the relay -- a complete no-op, never required. Env: LEAF_DIRECT_RELAY_NATS_URL")
	flag.StringVar(&cfg.relaySubject, "relay-subject", envOr("LEAF_DIRECT_RELAY_SUBJECT", ""), "NATS subject for the relay (empty = relay package default). Env: LEAF_DIRECT_RELAY_SUBJECT")
	flag.StringVar(&cfg.relayNATSUsername, "relay-nats-username", envOr("LEAF_DIRECT_RELAY_NATS_USERNAME", ""), "optional NATS username for the relay connection above (mirrors nats.UserInfo). Empty (default) connects with no auth. Env: LEAF_DIRECT_RELAY_NATS_USERNAME")
	flag.StringVar(&cfg.relayNATSPassword, "relay-nats-password", envOr("LEAF_DIRECT_RELAY_NATS_PASSWORD", ""), "optional NATS password paired with -relay-nats-username (mirrors nats.UserInfo). Never logged. Env: LEAF_DIRECT_RELAY_NATS_PASSWORD")
	flag.StringVar(&cfg.relayNATSTLSCAFile, "relay-nats-tls-ca-file", envOr("LEAF_DIRECT_RELAY_NATS_TLS_CA_FILE", ""), "optional CA bundle file to verify the NATS server's TLS certificate against (mirrors nats.RootCAs). Empty (default) appends no TLS CA option. Env: LEAF_DIRECT_RELAY_NATS_TLS_CA_FILE")
	flag.StringVar(&cfg.relayNATSTLSCertFile, "relay-nats-tls-cert-file", envOr("LEAF_DIRECT_RELAY_NATS_TLS_CERT_FILE", ""), "optional client certificate file for mutual TLS against the NATS server (mirrors nats.ClientCert; must be set together with -relay-nats-tls-key-file). Env: LEAF_DIRECT_RELAY_NATS_TLS_CERT_FILE")
	flag.StringVar(&cfg.relayNATSTLSKeyFile, "relay-nats-tls-key-file", envOr("LEAF_DIRECT_RELAY_NATS_TLS_KEY_FILE", ""), "optional client private key file paired with -relay-nats-tls-cert-file (mirrors nats.ClientCert). Env: LEAF_DIRECT_RELAY_NATS_TLS_KEY_FILE")
	flag.StringVar(&cfg.templateRelaySubject, "template-relay-subject", envOr("LEAF_DIRECT_TEMPLATE_RELAY_SUBJECT", ""), "NATS subject for the template (new-tip) relay fast-invalidation broadcast (empty = relay.DefaultTemplateSubject). Reuses the SAME -relay-nats-url connection above -- no second NATS URL flag. Env: LEAF_DIRECT_TEMPLATE_RELAY_SUBJECT")
	flag.StringVar(&cfg.moneroZMQURL, "monero-zmq-url", envOr("LEAF_DIRECT_MONERO_ZMQ_URL", ""), "real monerod ZMQ endpoint (e.g. tcp://127.0.0.1:28082) for an ADDITIONAL, faster block-invalidation trigger on top of the existing tip-poll baseline (see internal/leaflib/monero/zmq). Empty (default) disables this entirely -- a complete no-op. Ignored for -coin=tari. Env: LEAF_DIRECT_MONERO_ZMQ_URL")

	flag.StringVar(&cfg.configFile, "config", envOr("LEAF_DIRECT_CONFIG_FILE", ""), "optional path to a TOML config file providing defaults for any flag below that is not explicitly set via CLI flag or environment variable. See leaf-direct.example.toml. Env: LEAF_DIRECT_CONFIG_FILE")

	flag.BoolVar(&cfg.debug, "debug", envOr("LEAF_DIRECT_DEBUG", "false") == "true", "enable verbose [DEBUG]-tagged logging (share submit params, validation attempt/result, backend HTTP forward attempts, job lifecycle, connection lifecycle, vardiff retargets). OFF by default -- purely additive, never changes any existing log line. Env: LEAF_DIRECT_DEBUG (\"true\" to enable)")

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
	Standalone      *bool   `toml:"standalone"`
	MonerodURL      *string `toml:"monerod_url"`
	MergeMineChains *string `toml:"merge_mine_chains"`

	TrustEnabled   *bool `toml:"trust_enabled"`
	TrustThreshold *int  `toml:"trust_threshold"`
	TrustPenalty   *int  `toml:"trust_penalty"`
	TrustChange    *int  `toml:"trust_change"`
	TrustMin       *int  `toml:"trust_min"`

	RandomXWorkers                  *int  `toml:"randomx_workers"`
	RandomXQueueSize                *int  `toml:"randomx_queue_size"`
	InvalidShareDisconnectEnabled   *bool `toml:"invalid_share_disconnect_enabled"`
	InvalidShareDisconnectThreshold *int  `toml:"invalid_share_disconnect_threshold"`

	// JobFetchWorkers mirrors RandomXWorkers's exact same convention
	// -- see cfg.jobFetchWorkers's doc comment.
	JobFetchWorkers *int `toml:"job_fetch_workers"`

	Algo              *string `toml:"algo"`
	PoolType          *string `toml:"pool_type"`
	PoolID            *int    `toml:"pool_id"`
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

	MaxConnections        *int `toml:"max_connections"`
	IdleTimeoutSeconds    *int `toml:"idle_timeout_seconds"`
	NoShareTimeoutSeconds *int `toml:"no_share_timeout_seconds"`

	MetricsListenAddress *string `toml:"metrics_listen_address"`
	MaxAddressLabels     *int    `toml:"max_address_labels"`
	StatsPageMaxSessions *int    `toml:"stats_page_max_sessions"`
	HideRemoteAddress    *bool   `toml:"hide_remote_address"`

	BackendBaseURL             *string `toml:"backend_base_url"`
	BackendAuthHeader          *string `toml:"backend_auth_header"`
	BackendAuthValue           *string `toml:"backend_auth_value"`
	BackendShareTimeoutSeconds *int    `toml:"backend_share_timeout_seconds"`
	BackendBlockTimeoutSeconds *int    `toml:"backend_block_timeout_seconds"`

	AddressFlagsPollIntervalSeconds *int `toml:"address_flags_poll_interval_seconds"`

	LegacyMode       *bool   `toml:"legacy_mode"`
	LegacyBackendURL *string `toml:"legacy_backend_url"`
	LegacyAuthKey    *string `toml:"legacy_auth_key"`
	LegacyPoolType   *string `toml:"legacy_pool_type"`
	LegacyPoolID     *int    `toml:"legacy_pool_id"`

	LegacyCheckinEnabled          *bool   `toml:"legacy_checkin_enabled"`
	LegacyCheckinAPIURL           *string `toml:"legacy_checkin_api_url"`
	LegacyCheckinAuthToken        *string `toml:"legacy_checkin_auth_token"`
	LegacyCheckinIntervalSeconds  *int    `toml:"legacy_checkin_interval_seconds"`
	LegacyBlockRetryBudgetSeconds *int    `toml:"legacy_block_retry_budget_seconds"`

	SubmitNodesRaw *string `toml:"submit_nodes"`

	RelayNATSURL *string `toml:"relay_nats_url"`
	RelaySubject *string `toml:"relay_subject"`

	RelayNATSUsername    *string `toml:"relay_nats_username"`
	RelayNATSPassword    *string `toml:"relay_nats_password"`
	RelayNATSTLSCAFile   *string `toml:"relay_nats_tls_ca_file"`
	RelayNATSTLSCertFile *string `toml:"relay_nats_tls_cert_file"`
	RelayNATSTLSKeyFile  *string `toml:"relay_nats_tls_key_file"`

	TemplateRelaySubject *string `toml:"template_relay_subject"`
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
		return fmt.Errorf("leaf-direct: loading -config %s: %w", cfg.configFile, err)
	}

	cfgfile.ApplyString(&cfg.nodeGRPCAddress, fc.NodeGRPCAddress, visited, "node-grpc-address", "LEAF_NODE_GRPC_ADDRESS")
	cfgfile.ApplyString(&cfg.listenAddress, fc.ListenAddress, visited, "listen-address", "LEAF_DIRECT_LISTEN_ADDRESS")
	cfgfile.ApplyString(&cfg.payoutAddress, fc.PayoutAddress, visited, "payout-address", "LEAF_DIRECT_PAYOUT_ADDRESS")
	cfgfile.ApplyString(&cfg.network, fc.Network, visited, "network", "LEAF_DIRECT_NETWORK")
	cfgfile.ApplyString(&cfg.coin, fc.Coin, visited, "coin", "LEAF_DIRECT_COIN")
	cfgfile.ApplyBool(&cfg.standalone, fc.Standalone, visited, "standalone", "LEAF_DIRECT_STANDALONE")
	cfgfile.ApplyString(&cfg.monerodURL, fc.MonerodURL, visited, "monerod-url", "LEAF_DIRECT_MONEROD_URL")
	cfgfile.ApplyString(&cfg.mergeMineChains, fc.MergeMineChains, visited, "merge-mine-chains", "LEAF_DIRECT_MERGE_MINE_CHAINS")

	cfgfile.ApplyBool(&cfg.trustEnabled, fc.TrustEnabled, visited, "trust-enabled", "LEAF_DIRECT_TRUST_ENABLED")
	cfgfile.ApplyInt(&cfg.trustThreshold, fc.TrustThreshold, visited, "trust-threshold", "LEAF_DIRECT_TRUST_THRESHOLD")
	cfgfile.ApplyInt(&cfg.trustPenalty, fc.TrustPenalty, visited, "trust-penalty", "LEAF_DIRECT_TRUST_PENALTY")
	cfgfile.ApplyInt(&cfg.trustChange, fc.TrustChange, visited, "trust-change", "LEAF_DIRECT_TRUST_CHANGE")
	cfgfile.ApplyInt(&cfg.trustMin, fc.TrustMin, visited, "trust-min", "LEAF_DIRECT_TRUST_MIN")
	cfgfile.ApplyInt(&cfg.randomxWorkers, fc.RandomXWorkers, visited, "randomx-workers", "LEAF_DIRECT_RANDOMX_WORKERS")
	cfgfile.ApplyInt(&cfg.randomxQueueSize, fc.RandomXQueueSize, visited, "randomx-queue-size", "LEAF_DIRECT_RANDOMX_QUEUE_SIZE")
	cfgfile.ApplyInt(&cfg.jobFetchWorkers, fc.JobFetchWorkers, visited, "job-fetch-workers", "LEAF_DIRECT_JOB_FETCH_WORKERS")
	cfgfile.ApplyBool(&cfg.invalidShareDisconnectEnabled, fc.InvalidShareDisconnectEnabled, visited, "invalid-share-disconnect-enabled", "LEAF_DIRECT_INVALID_SHARE_DISCONNECT_ENABLED")
	cfgfile.ApplyInt(&cfg.invalidShareDisconnectThreshold, fc.InvalidShareDisconnectThreshold, visited, "invalid-share-disconnect-threshold", "LEAF_DIRECT_INVALID_SHARE_DISCONNECT_THRESHOLD")

	cfgfile.ApplyString(&cfg.algo, fc.Algo, visited, "algo", "LEAF_DIRECT_ALGO")
	cfgfile.ApplyString(&cfg.poolType, fc.PoolType, visited, "pool-type", "LEAF_DIRECT_POOL_TYPE")
	cfgfile.ApplyInt(&cfg.poolID, fc.PoolID, visited, "pool-id", "LEAF_DIRECT_POOL_ID")
	cfgfile.ApplyString(&cfg.randomXServiceURL, fc.RandomXServiceURL, visited, "randomx-service-url", "LEAF_DIRECT_RANDOMX_SERVICE_URL")
	cfgfile.ApplyString(&cfg.coinbaseExtraTag, fc.CoinbaseExtraTag, visited, "coinbase-extra-tag", "LEAF_DIRECT_COINBASE_EXTRA_TAG")

	cfgfile.ApplyUint64(&cfg.startingDifficulty, fc.StartingDifficulty, visited, "starting-difficulty", "LEAF_DIRECT_STARTING_DIFFICULTY")
	cfgfile.ApplyString(&cfg.portsRaw, fc.PortsRaw, visited, "ports", "LEAF_DIRECT_PORTS")
	cfgfile.ApplyUint64(&cfg.minDifficulty, fc.MinDifficulty, visited, "min-difficulty", "LEAF_DIRECT_MIN_DIFFICULTY")
	cfgfile.ApplyUint64(&cfg.maxDifficulty, fc.MaxDifficulty, visited, "max-difficulty", "LEAF_DIRECT_MAX_DIFFICULTY")
	cfgfile.ApplyInt(&cfg.vardiffTargetTime, fc.VardiffTargetTime, visited, "vardiff-target-time", "LEAF_DIRECT_VARDIFF_TARGET_TIME")

	if fc.VardiffIntervalSeconds != nil {
		d := time.Duration(*fc.VardiffIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.vardiffInterval, &d, visited, "vardiff-retarget-interval", "LEAF_DIRECT_VARDIFF_RETARGET_INTERVAL")
	}

	cfgfile.ApplyString(&cfg.tlsCertFile, fc.TLSCertFile, visited, "tls-cert-file", "LEAF_DIRECT_TLS_CERT_FILE")
	cfgfile.ApplyString(&cfg.tlsKeyFile, fc.TLSKeyFile, visited, "tls-key-file", "LEAF_DIRECT_TLS_KEY_FILE")
	cfgfile.ApplyString(&cfg.tlsCertPersistPath, fc.TLSCertPersistPath, visited, "tls-cert-persist-path", "LEAF_DIRECT_TLS_CERT_PERSIST_PATH")

	if fc.RefreshIntervalSeconds != nil {
		d := time.Duration(*fc.RefreshIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.refreshInterval, &d, visited, "refresh-interval", "LEAF_DIRECT_REFRESH_INTERVAL")
	}
	if fc.TipPollIntervalSeconds != nil {
		d := time.Duration(*fc.TipPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.tipPollInterval, &d, visited, "tip-poll-interval", "LEAF_DIRECT_TIP_POLL_INTERVAL")
	}
	if fc.JobMaxAgeSeconds != nil {
		d := time.Duration(*fc.JobMaxAgeSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.jobMaxAge, &d, visited, "job-max-age", "LEAF_DIRECT_JOB_MAX_AGE")
	}

	cfgfile.ApplyInt(&cfg.maxConnections, fc.MaxConnections, visited, "max-connections", "LEAF_DIRECT_MAX_CONNECTIONS")
	if fc.IdleTimeoutSeconds != nil {
		d := time.Duration(*fc.IdleTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.idleTimeout, &d, visited, "idle-timeout", "LEAF_DIRECT_IDLE_TIMEOUT")
	}
	if fc.NoShareTimeoutSeconds != nil {
		d := time.Duration(*fc.NoShareTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.noShareTimeout, &d, visited, "no-share-timeout", "LEAF_DIRECT_NO_SHARE_TIMEOUT")
	}

	cfgfile.ApplyString(&cfg.metricsListenAddress, fc.MetricsListenAddress, visited, "metrics-listen-address", "LEAF_DIRECT_METRICS_LISTEN_ADDRESS")
	cfgfile.ApplyInt(&cfg.maxAddressLabels, fc.MaxAddressLabels, visited, "max-address-labels", "LEAF_DIRECT_MAX_ADDRESS_LABELS")
	cfgfile.ApplyInt(&cfg.statsPageMaxSessions, fc.StatsPageMaxSessions, visited, "stats-page-max-sessions", "LEAF_DIRECT_STATS_PAGE_MAX_SESSIONS")
	cfgfile.ApplyBool(&cfg.hideRemoteAddress, fc.HideRemoteAddress, visited, "hide-remote-address", "LEAF_DIRECT_HIDE_REMOTE_ADDRESS")

	cfgfile.ApplyString(&cfg.backendBaseURL, fc.BackendBaseURL, visited, "backend-base-url", "LEAF_DIRECT_BACKEND_BASE_URL")
	cfgfile.ApplyString(&cfg.backendAuthHeader, fc.BackendAuthHeader, visited, "backend-auth-header", "LEAF_DIRECT_BACKEND_AUTH_HEADER")
	cfgfile.ApplyString(&cfg.backendAuthValue, fc.BackendAuthValue, visited, "backend-auth-value", "LEAF_DIRECT_BACKEND_AUTH_VALUE")
	if fc.BackendShareTimeoutSeconds != nil {
		d := time.Duration(*fc.BackendShareTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.backendShareTimeout, &d, visited, "backend-share-timeout", "LEAF_DIRECT_BACKEND_SHARE_TIMEOUT")
	}
	if fc.BackendBlockTimeoutSeconds != nil {
		d := time.Duration(*fc.BackendBlockTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.backendBlockTimeout, &d, visited, "backend-block-timeout", "LEAF_DIRECT_BACKEND_BLOCK_TIMEOUT")
	}

	if fc.AddressFlagsPollIntervalSeconds != nil {
		d := time.Duration(*fc.AddressFlagsPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.addressFlagsPollInterval, &d, visited, "address-flags-poll-interval", "LEAF_DIRECT_ADDRESS_FLAGS_POLL_INTERVAL")
	}

	cfgfile.ApplyBool(&cfg.legacyMode, fc.LegacyMode, visited, "legacy-mode", "LEAF_DIRECT_LEGACY_MODE")
	cfgfile.ApplyString(&cfg.legacyBackendURL, fc.LegacyBackendURL, visited, "legacy-backend-url", "LEAF_DIRECT_LEGACY_BACKEND_URL")
	cfgfile.ApplyString(&cfg.legacyAuthKey, fc.LegacyAuthKey, visited, "legacy-auth-key", "LEAF_DIRECT_LEGACY_AUTH_KEY")
	cfgfile.ApplyString(&cfg.legacyPoolType, fc.LegacyPoolType, visited, "legacy-pool-type", "LEAF_DIRECT_LEGACY_POOL_TYPE")
	cfgfile.ApplyInt(&cfg.legacyPoolID, fc.LegacyPoolID, visited, "legacy-pool-id", "LEAF_DIRECT_LEGACY_POOL_ID")

	cfgfile.ApplyBool(&cfg.legacyCheckinEnabled, fc.LegacyCheckinEnabled, visited, "legacy-checkin-enabled", "LEAF_DIRECT_LEGACY_CHECKIN_ENABLED")
	cfgfile.ApplyString(&cfg.legacyCheckinAPIURL, fc.LegacyCheckinAPIURL, visited, "legacy-checkin-api-url", "LEAF_DIRECT_LEGACY_CHECKIN_API_URL")
	cfgfile.ApplyString(&cfg.legacyCheckinAuthToken, fc.LegacyCheckinAuthToken, visited, "legacy-checkin-auth-token", "LEAF_DIRECT_LEGACY_CHECKIN_AUTH_TOKEN")
	if fc.LegacyCheckinIntervalSeconds != nil {
		d := time.Duration(*fc.LegacyCheckinIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.legacyCheckinInterval, &d, visited, "legacy-checkin-interval", "LEAF_DIRECT_LEGACY_CHECKIN_INTERVAL")
	}
	if fc.LegacyBlockRetryBudgetSeconds != nil {
		d := time.Duration(*fc.LegacyBlockRetryBudgetSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.legacyBlockRetryBudget, &d, visited, "legacy-block-retry-budget", "LEAF_DIRECT_LEGACY_BLOCK_RETRY_BUDGET")
	}

	cfgfile.ApplyString(&cfg.submitNodesRaw, fc.SubmitNodesRaw, visited, "submit-nodes", "LEAF_DIRECT_SUBMIT_NODES")

	cfgfile.ApplyString(&cfg.relayNATSURL, fc.RelayNATSURL, visited, "relay-nats-url", "LEAF_DIRECT_RELAY_NATS_URL")
	cfgfile.ApplyString(&cfg.relaySubject, fc.RelaySubject, visited, "relay-subject", "LEAF_DIRECT_RELAY_SUBJECT")
	cfgfile.ApplyString(&cfg.relayNATSUsername, fc.RelayNATSUsername, visited, "relay-nats-username", "LEAF_DIRECT_RELAY_NATS_USERNAME")
	cfgfile.ApplyString(&cfg.relayNATSPassword, fc.RelayNATSPassword, visited, "relay-nats-password", "LEAF_DIRECT_RELAY_NATS_PASSWORD")
	cfgfile.ApplyString(&cfg.relayNATSTLSCAFile, fc.RelayNATSTLSCAFile, visited, "relay-nats-tls-ca-file", "LEAF_DIRECT_RELAY_NATS_TLS_CA_FILE")
	cfgfile.ApplyString(&cfg.relayNATSTLSCertFile, fc.RelayNATSTLSCertFile, visited, "relay-nats-tls-cert-file", "LEAF_DIRECT_RELAY_NATS_TLS_CERT_FILE")
	cfgfile.ApplyString(&cfg.relayNATSTLSKeyFile, fc.RelayNATSTLSKeyFile, visited, "relay-nats-tls-key-file", "LEAF_DIRECT_RELAY_NATS_TLS_KEY_FILE")

	cfgfile.ApplyString(&cfg.templateRelaySubject, fc.TemplateRelaySubject, visited, "template-relay-subject", "LEAF_DIRECT_TEMPLATE_RELAY_SUBJECT")
	cfgfile.ApplyString(&cfg.moneroZMQURL, fc.MoneroZMQURL, visited, "monero-zmq-url", "LEAF_DIRECT_MONERO_ZMQ_URL")

	cfgfile.ApplyBool(&cfg.debug, fc.Debug, visited, "debug", "LEAF_DIRECT_DEBUG")

	return nil
}

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
			return nil, fmt.Errorf("LEAF_DIRECT_PORTS entry %d (%q): %w", i+1, raw, err)
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, errors.New("LEAF_DIRECT_PORTS was set but contained no usable entries")
	}
	return ports, nil
}

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
	if s == "mainnet" {
		return poolpb.Network_NETWORK_MAINNET
	}
	return poolpb.Network_NETWORK_TESTNET
}

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

// normalizeCoinTicker mirrors leaf-solo's own normalizeCoinTicker
// exactly -- see that function's doc comment.
func normalizeCoinTicker(coin string) string {
	t := coinprofile.NormalizeTicker(coin)
	if t == "monero" {
		return "xmr"
	}
	return t
}

// validateCoinFlag mirrors leaf-solo's own validateCoinFlag exactly
// -- see that function's doc comment.
func validateCoinFlag(coin string) error {
	ticker := normalizeCoinTicker(coin)
	if ticker == "" || ticker == "tari" {
		return nil
	}
	if _, ok := coinprofile.Lookup(ticker); !ok {
		return fmt.Errorf("unknown/unregistered -coin/LEAF_DIRECT_COIN value %q -- see internal/coinprofile.Registry for supported tickers (or use \"tari\")", coin)
	}
	return nil
}

// isMoneroFamilyCoin mirrors leaf-solo's own isMoneroFamilyCoin
// exactly -- see that function's doc comment.
func isMoneroFamilyCoin(coin string) bool {
	ticker := normalizeCoinTicker(coin)
	if ticker == "" || ticker == "tari" {
		return false
	}
	_, ok := coinprofile.Lookup(ticker)
	return ok
}

// parseMergeMineChains parses -merge-mine-chains/LEAF_DIRECT_MERGE_MINE_CHAINS
// ("NAME:auxid,NAME2:auxid2", e.g. "TARI:xtr") into
// direct.ServerConfig.MergeMineChains. An empty/whitespace-only raw
// string (the default) returns nil -- no merge-mine-chain checking at
// all, exactly the pre-existing behavior. A malformed entry (missing
// ':', or an empty name/auxid on either side of it) is logged and
// skipped rather than aborting startup -- a genuinely misconfigured
// merge-mine-chains flag should not take down an otherwise-working
// leaf-direct process; the primary (Monero) leg still works fine
// with zero configured merge-mine chains.
func parseMergeMineChains(raw string, logger *log.Logger) []direct.MergeMineChainConfig {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []direct.MergeMineChainConfig
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			logger.Printf("warning: -merge-mine-chains entry %q is not NAME:auxid, skipping", entry)
			continue
		}
		name := strings.TrimSpace(parts[0])
		auxID := strings.TrimSpace(parts[1])
		if name == "" || auxID == "" {
			logger.Printf("warning: -merge-mine-chains entry %q has an empty name or auxid, skipping", entry)
			continue
		}
		out = append(out, direct.MergeMineChainConfig{Name: name, AuxChainID: auxID})
	}
	return out
}

// resolveAlgo mirrors leaf-solo's own resolveAlgo exactly -- see that
// function's doc comment for the full -coin=tari / -coin=monero /
// -coin=xmr[-standalone] / other-registered-ticker breakdown.
func resolveAlgo(cfg config) poolpb.Algo {
	ticker := normalizeCoinTicker(cfg.coin)
	if ticker == "" || ticker == "tari" {
		return algoFromString(cfg.algo)
	}
	if ticker == "xmr" && !cfg.standalone {
		return poolpb.Algo_ALGO_RXM
	}
	if profile, ok := coinprofile.Lookup(ticker); ok {
		return profile.Algo
	}
	return algoFromString(cfg.algo)
}

// algoTagSuffix mirrors leaf-solo's own algoTagSuffix exactly -- see
// that function's doc comment.
func algoTagSuffix(cfg config) string {
	algo := resolveAlgo(cfg)
	switch algo {
	case poolpb.Algo_ALGO_C29:
		return "c29"
	case poolpb.Algo_ALGO_RXT:
		return "rxt"
	case poolpb.Algo_ALGO_RXM:
		return "rxm"
	default:
		if profile, ok := coinprofile.ByAlgo(algo); ok {
			return coinprofile.NormalizeTicker(profile.Ticker)
		}
		return "sha3x"
	}
}

// defaultCoinbaseExtraTag mirrors leaf-solo's own
// defaultCoinbaseExtraTag exactly -- see that function's doc comment.
func defaultCoinbaseExtraTag(cfg config) string {
	return "supportxtm-" + algoTagSuffix(cfg)
}

// resolveCoinbaseExtraTag mirrors leaf-solo's own
// resolveCoinbaseExtraTag exactly -- see that function's doc comment.
func resolveCoinbaseExtraTag(cfg config) string {
	if strings.TrimSpace(cfg.coinbaseExtraTag) != "" {
		return cfg.coinbaseExtraTag
	}
	return defaultCoinbaseExtraTag(cfg)
}

// poolTypeFromString parses the real string convention mirrored from
// internal/backend/api/api.go's own (private, unexported) poolTypeString
// reverse-mapping (PPLNS/PPS/PROP/SOLO), accepted here case-insensitively
// for a friendlier flag/env UX. Returns
// poolpb.PoolType_POOL_TYPE_UNSPECIFIED plus false for any unrecognized
// value -- callers MUST treat that as a fatal startup misconfiguration
// (see main's own required-flag validation), since forwarding a Share/
// Block with an UNSPECIFIED PoolType is exactly the real, confirmed-live
// bug this flag exists to prevent (the backend correctly rejects it with
// "pool_type is required").
// requiredFieldsError returns a non-nil error describing exactly one
// missing/invalid required field (payout-address is checked by the
// caller separately, before this is called), or nil if the config is
// valid to proceed with. It never calls logger.Fatal itself so tests
// can exercise it directly without forking the binary.
//
// -backend-base-url and -pool-id are gated on -legacy-mode; -pool-type
// is NOT. This split was decided by reading, not assuming, the real
// downstream consumers of each field (internal/leaflib/direct/
// session.go and internal/leaflib/legacytransport/legacytransport.go):
//
//   - -backend-base-url only ever feeds
//     transport.NewHTTPProtobufTransport (the NEW go-crypto-pool
//     backend's HTTP+Protobuf transport, main.go's non-legacy branch
//     below) and addressFlagsCache's addressflags.NewHTTPSource (this
//     binary's ban/forced-min-difficulty poller, also below) -- both
//     are skipped entirely in -legacy-mode=true (see the legacyMode
//     branches at both call sites). It has NO consumer at all in
//     legacy mode, so requiring it there blocks a legacy-only
//     deployment (e.g. jagtech-phx-01) on a flag it genuinely does
//     not need.
//
//   - -pool-id (ServerConfig.PoolID) is stamped onto every
//     poolpb.Share/poolpb.Block leaf-direct constructs (session.go),
//     but legacytransport's buildLegacyShare/buildLegacyBlock NEVER
//     read share.GetPoolId()/block.GetPoolId() -- buildLegacyShare
//     uses its OWN, separately-configured -legacy-pool-id
//     (legacytransport.Config.LegacyPoolID) for the outgoing legacy
//     PoolID field, and legacypb.Block has no PoolID destination at
//     all ("pool_id similarly have no legacy Block destination and
//     are dropped" -- buildLegacyBlock's own doc comment). So
//     -pool-id has ZERO real effect in legacy mode. Relaxed to
//     optional there (default 0, consumed by nothing).
//
//   - -pool-type (ServerConfig.PoolType), by contrast, DOES have a
//     real, live effect in legacy mode, despite -legacy-pool-type
//     existing as a seemingly-parallel, separately-configured flag:
//     buildLegacyShare/buildLegacyBlock derive the actual OUTGOING
//     legacy PoolType field from share.GetPoolType()/
//     block.GetPoolType() (i.e. from -pool-type, converted via
//     legacyPoolTypeFromPB) -- NOT from
//     legacytransport.Config.LegacyPoolType/-legacy-pool-type, which
//     is validated as required at startup but then never actually
//     read by either build function. (This mirrors -legacy-pool-type's
//     own flag doc comment's "OPEN DESIGN QUESTION" -- confirmed here
//     by reading the code, not left as a guess. Fixing THAT mismatch
//     is a separate, real payout-semantics design decision outside
//     this fix's scope -- flagged in the PR description for Alex, not
//     silently changed here.) Because -pool-type substantively
//     controls what PoolType value is actually forwarded to the
//     legacy backend for every real share/block, it stays REQUIRED
//     unconditionally -- relaxing it in legacy mode would risk
//     forwarding POOL_TYPE_UNSPECIFIED-derived legacy shares/blocks,
//     which is exactly the payout-accounting corruption this
//     validation exists to prevent.
func requiredFieldsError(cfg config) error {
	if !cfg.legacyMode && cfg.backendBaseURL == "" {
		return errors.New("LEAF_DIRECT_BACKEND_BASE_URL (or -backend-base-url) is required -- leaf-direct's whole purpose is forwarding validated shares/blocks to the real backend (not required when -legacy-mode=true, which forwards via -legacy-backend-url instead)")
	}
	if _, ok := poolTypeFromString(cfg.poolType); !ok {
		return fmt.Errorf("LEAF_DIRECT_POOL_TYPE (or -pool-type) is required and must be one of pplns|pps|prop|solo, got %q -- the backend correctly rejects any share/block whose pool_type is left unset (this is still required even when -legacy-mode=true -- see requiredFieldsError's doc comment)", cfg.poolType)
	}
	if !cfg.legacyMode && cfg.poolID <= 0 {
		return fmt.Errorf("LEAF_DIRECT_POOL_ID (or -pool-id) is required and must be a positive integer, got %d -- an unset/zero pool_id would defeat the entire purpose of pool-source tracking (not required when -legacy-mode=true, which has no consumer for it)", cfg.poolID)
	}
	if cfg.legacyMode {
		if strings.TrimSpace(cfg.legacyBackendURL) == "" {
			return errors.New("LEAF_DIRECT_LEGACY_BACKEND_URL (or -legacy-backend-url) is required when -legacy-mode=true")
		}
		if cfg.legacyAuthKey == "" {
			return errors.New("LEAF_DIRECT_LEGACY_AUTH_KEY (or -legacy-auth-key) is required when -legacy-mode=true")
		}
		if _, ok := legacyPoolTypeFromString(cfg.legacyPoolType); !ok {
			return fmt.Errorf("LEAF_DIRECT_LEGACY_POOL_TYPE (or -legacy-pool-type) is required and must be one of pplns|pps|prop|solo when -legacy-mode=true, got %q", cfg.legacyPoolType)
		}
		if cfg.legacyPoolID <= 0 {
			return fmt.Errorf("LEAF_DIRECT_LEGACY_POOL_ID (or -legacy-pool-id) is required and must be a positive integer when -legacy-mode=true, got %d", cfg.legacyPoolID)
		}
		if cfg.legacyCheckinEnabled {
			if strings.TrimSpace(cfg.legacyCheckinAPIURL) == "" {
				return errors.New("LEAF_DIRECT_LEGACY_CHECKIN_API_URL (or -legacy-checkin-api-url) is required when -legacy-mode=true and -legacy-checkin-enabled=true (the default)")
			}
			if cfg.legacyCheckinAuthToken == "" {
				return errors.New("LEAF_DIRECT_LEGACY_CHECKIN_AUTH_TOKEN (or -legacy-checkin-auth-token) is required when -legacy-mode=true and -legacy-checkin-enabled=true (the default)")
			}
		}
	}
	return nil
}

func poolTypeFromString(s string) (poolpb.PoolType, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pplns":
		return poolpb.PoolType_POOL_TYPE_PPLNS, true
	case "pps":
		return poolpb.PoolType_POOL_TYPE_PPS, true
	case "prop":
		return poolpb.PoolType_POOL_TYPE_PROP, true
	case "solo":
		return poolpb.PoolType_POOL_TYPE_SOLO, true
	default:
		return poolpb.PoolType_POOL_TYPE_UNSPECIFIED, false
	}
}

// legacyPoolTypeFromString parses the -legacy-pool-type flag/env value
// into the legacy legacypb.POOLTYPE enum, using the identical
// pplns|pps|prop|solo string convention as poolTypeFromString above
// (case-insensitive). Returns ok=false for any unrecognized value --
// callers MUST treat that as a fatal startup misconfiguration, exactly
// like poolTypeFromString's own doc comment describes for -pool-type.
func legacyPoolTypeFromString(s string) (legacypb.POOLTYPE, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pplns":
		return legacypb.POOLTYPE_PPLNS, true
	case "pps":
		return legacypb.POOLTYPE_PPS, true
	case "prop":
		return legacypb.POOLTYPE_PROP, true
	case "solo":
		return legacypb.POOLTYPE_SOLO, true
	default:
		return 0, false
	}
}

// resolveSubmitNodes parses cfg.submitNodesRaw into a deduplicated
// address list that ALWAYS includes the primary node-grpc-address
// first (see this binary's doc comment: the multi-node submit set is
// the primary node PLUS any additionally configured ones, not
// instead of it).
func resolveSubmitNodes(primary, raw string) []string {
	out := []string{primary}
	seen := map[string]struct{}{primary: {}}
	for _, addr := range strings.Split(raw, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// connectionPortCounter implements legacytransport.PortMinerCounter
// against this leaf's own *leaflib.ConnectionManager, deriving each
// live connection's port from ManagedConnection.LocalAddr() (the
// listener/port it was accepted on) rather than needing the
// ConnectionManager itself to know anything about "ports" as a
// concept. ports is the full set of configured port numbers (from
// resolvePorts) so a port with zero current connections still reports
// 0 rather than being silently absent from the heartbeat's ports map
// -- matching the real legacy sender's own behavior of always
// including every configured port.
type connectionPortCounter struct {
	cm    *leaflib.ConnectionManager
	ports []int
}

// PortMinerCounts implements legacytransport.PortMinerCounter.
func (c *connectionPortCounter) PortMinerCounts() map[int]int {
	counts := make(map[int]int, len(c.ports))
	for _, p := range c.ports {
		counts[p] = 0
	}
	for _, mc := range c.cm.Snapshot() {
		tcpAddr, ok := mc.LocalAddr().(*net.TCPAddr)
		if !ok {
			continue
		}
		counts[tcpAddr.Port]++
	}
	return counts
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("leaf-direct: %v", err)
	}
	logger := log.New(os.Stdout, "leaf-direct: ", log.LstdFlags|log.Lmicroseconds)

	// debugLogger is constructed exactly once per process (never a
	// global/package-level singleton -- see
	// internal/leaflib/debuglog.go's doc comment) and threaded down
	// via direct.ServerConfig.Debug and the backend transport's own
	// Debug field below.
	debugLogger := leaflib.NewDebugLogger(logger, cfg.debug)
	if cfg.debug {
		logger.Print("debug logging ENABLED (-debug/LEAF_DIRECT_DEBUG) -- verbose [DEBUG]-tagged output follows for share submits, validation, backend forwarding, job lifecycle, connection lifecycle, and vardiff retargets")
	}

	// Fail fast on an unrecognized -coin/LEAF_DIRECT_COIN ticker --
	// never silently fall through to Tari or Monero defaults. See
	// validateCoinFlag's own doc comment.
	if err := validateCoinFlag(cfg.coin); err != nil {
		logger.Fatalf("%v", err)
	}
	coinTicker := normalizeCoinTicker(cfg.coin)
	if cfg.standalone && coinTicker != "xmr" {
		logger.Printf("note: -standalone/LEAF_DIRECT_STANDALONE is set but -coin=%s has no merge-mine concept to disambiguate from -- it is already always standalone, this flag has no effect for it", cfg.coin)
	}

	if isMoneroFamilyCoin(cfg.coin) {
		if strings.TrimSpace(cfg.monerodURL) == "" {
			logger.Fatalf("LEAF_DIRECT_MONEROD_URL (or -monerod-url) is required when -coin=%s", cfg.coin)
		}
		if cfg.nodeGRPCAddress != "" {
			logger.Printf("note: -coin=%s -- ignoring -node-grpc-address/LEAF_NODE_GRPC_ADDRESS (%s); no Tari GRPC daemon is involved", cfg.coin, cfg.nodeGRPCAddress)
		}
		if cfg.submitNodesRaw != "" {
			logger.Printf("note: -coin=%s -- ignoring -submit-nodes/LEAF_DIRECT_SUBMIT_NODES (%s); real multi-node monerod-family block submission is a known, deferred gap (MultiNodeSubmitter is Tari-GRPC-specific) -- see this leaf's own doc comment. A block find submits via a single real MoneroNodeClient.SubmitBlock call instead.", cfg.coin, cfg.submitNodesRaw)
		}
	} else if cfg.nodeGRPCAddress == "" {
		logger.Fatal("LEAF_NODE_GRPC_ADDRESS (or -node-grpc-address) is required")
	}
	if cfg.payoutAddress == "" {
		logger.Fatal("LEAF_DIRECT_PAYOUT_ADDRESS (or -payout-address) is required")
	}

	// requiredFieldsError applies leaf-direct's own required-field
	// startup validation, gating -backend-base-url/-pool-id (but NOT
	// -pool-type -- see the function's own doc comment for why) on
	// -legacy-mode. Extracted into its own testable function (see
	// requiredFieldsError's doc comment and main_test.go's
	// TestRequiredFieldsError_*) rather than inlined logger.Fatal
	// calls, specifically so "legacy-mode starts up with
	// backend-base-url/pool-id unset" and "non-legacy-mode still
	// requires them" are both provable without forking the binary.
	if err := requiredFieldsError(cfg); err != nil {
		logger.Fatalf("%v", err)
	}
	// Safe to ignore the bool here: requiredFieldsError already
	// proved cfg.poolType parses (it is REQUIRED unconditionally,
	// legacy mode or not -- see that function's doc comment).
	poolType, _ := poolTypeFromString(cfg.poolType)

	// Legacy-mode validation: when -legacy-mode=false (the default),
	// all four legacy-* flags/env vars below are ignored entirely -- no
	// validation, no effect. When true, all four are REQUIRED (folded
	// into requiredFieldsError above); legacyPoolType is simply
	// re-derived here for use in backendTransport construction below.
	var legacyPoolType legacypb.POOLTYPE
	if cfg.legacyMode {
		legacyPoolType, _ = legacyPoolTypeFromString(cfg.legacyPoolType)
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

	// coinbaseExtraTag mirrors leaf-solo's own resolution exactly --
	// see cmd/leaf-solo/main.go's identical block for the full
	// rationale. Logged unconditionally so a freshly deployed/
	// reconfigured leaf-direct's actual on-chain attribution tag is
	// directly verifiable from its own startup logs.
	coinbaseExtraTagStr := resolveCoinbaseExtraTag(cfg)
	coinbaseExtraTag := solo.NormalizeCoinbaseExtraTag(coinbaseExtraTagStr, defaultCoinbaseExtraTag(cfg))
	logger.Printf("coinbase-extra tag: %q (%d bytes)", string(coinbaseExtraTag), len(coinbaseExtraTag))

	// Real coin-conditional NodeClient construction. For -coin=tari
	// (default), this is direct.NewNodeClient's own real
	// per-call-injectable GRPC client (unchanged). For -coin=monero,
	// this is solo.NewMoneroNodeClient -- the SAME real implementation
	// leaf-solo uses, satisfying the identical coin-agnostic
	// solo.NodeClient interface direct.NodeClient also implements, so
	// JobManager/Server/session.go's handleSubmit are unaffected by
	// which one gets constructed here.
	var node solo.NodeClient
	if isMoneroFamilyCoin(cfg.coin) {
		if coinTicker == "xmr" && !cfg.standalone {
			logger.Printf("NOTE: for RXM/merge-mining revenue, -monerod-url must point at a local minotari_merge_mining_proxy listener, NOT raw monerod -- pointing at raw monerod mines Monero-only with zero Tari merge-mine revenue")
		}
		logger.Printf("connecting to monerod-compatible daemon (-coin=%s) at %s", cfg.coin, cfg.monerodURL)
		moneroNode := solo.NewMoneroNodeClient(cfg.monerodURL)
		// instance ID: this leaf's own real, per-process
		// disambiguator stamped into every coinbase's reserved
		// region (ReservedOffset+4:+8) -- see MoneroNodeClient.
		// instanceID's doc comment for the full production-bug
		// rationale (multiple leaves sharing one payout address, or
		// adopting each other's relayed templates, must never serve
		// byte-identical coinbases). Logged unconditionally, exactly
		// like the coinbase-extra tag above, so a deployed leaf's
		// own instance ID is directly verifiable from its logs.
		instanceID := moneroNode.InstanceID()
		logger.Printf("monero per-leaf instance ID: %x", instanceID)
		node = moneroNode
	} else {
		logger.Printf("connecting to primary Tari base node GRPC at %s", cfg.nodeGRPCAddress)
		tariNode, err := direct.NewNodeClient(cfg.nodeGRPCAddress, coinbaseExtraTag)
		if err != nil {
			logger.Fatalf("failed to construct primary node client for %s: %v", cfg.nodeGRPCAddress, err)
		}
		node = tariNode
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Optional, best-effort NATS relay -- a complete no-op if
	// LEAF_DIRECT_RELAY_NATS_URL is unset (see internal/leaflib/relay).
	// Constructed BEFORE JobManager (below) so the SAME *relay.Relay
	// (one shared *nats.Conn for both the found-block AND template
	// relay streams -- see relay.go's own doc comment) can be threaded
	// into solo.JobManagerConfig.Relay at construction time.
	blockRelay := relay.NewRelay(relay.Config{
		URL: cfg.relayNATSURL, Subject: cfg.relaySubject, TemplateSubject: cfg.templateRelaySubject, Logger: logger,
		Username: cfg.relayNATSUsername, Password: cfg.relayNATSPassword,
		TLSCAFile: cfg.relayNATSTLSCAFile, TLSCertFile: cfg.relayNATSTLSCertFile, TLSKeyFile: cfg.relayNATSTLSKeyFile,
	})
	defer func() { _ = blockRelay.Close() }()
	if blockRelay.Enabled() {
		logger.Printf("NATS relay enabled at %s", cfg.relayNATSURL)
	} else {
		logger.Printf("NATS relay disabled (LEAF_DIRECT_RELAY_NATS_URL is empty) -- complete no-op, never required for correctness")
	}

	jobManager := solo.NewJobManager(solo.JobManagerConfig{
		Node: node, PayoutAddress: cfg.payoutAddress, Algo: resolveAlgo(cfg),
		StaticDifficulty: ports[0].Difficulty, RefreshInterval: cfg.refreshInterval,
		TipPollInterval: cfg.tipPollInterval, JobMaxAge: cfg.jobMaxAge, Logger: logger,
		Network: cfg.network, Relay: blockRelay, Debug: debugLogger,
	})

	logger.Println("probing base node connectivity...")
	if err := jobManager.Probe(ctx); err != nil {
		logger.Fatalf("base node connectivity probe failed: %v", err)
	}
	jobManager.Start(ctx)

	// Real, ADDITIONAL fast-invalidation trigger for the real monerod
	// ZMQ pub/sub stream -- any monerod-family -coin ONLY, and only
	// when -monero-zmq-url is explicitly set (a complete no-op
	// otherwise -- see internal/leaflib/monero/zmq's own doc comment).
	// This never REPLACES jobManager's own tip-poll loop (already
	// started above), it is purely an additional, faster trigger
	// running alongside it.
	if isMoneroFamilyCoin(cfg.coin) && cfg.moneroZMQURL != "" {
		zmqClient := monerozmq.NewClient(cfg.moneroZMQURL, func() { jobManager.InvalidateAll(solo.TemplateSourceLocal) }, logger)
		go zmqClient.Start(ctx)
		logger.Printf("real monerod ZMQ fast-invalidation trigger enabled at %s (topic %q)", cfg.moneroZMQURL, monerozmq.TopicNewBlock)
	} else if cfg.moneroZMQURL != "" {
		logger.Printf("note: -monero-zmq-url is set but -coin=%s is not a monerod-family coin -- ignoring it (%s); no ZMQ subscription started", cfg.coin, cfg.moneroZMQURL)
	}

	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{
		MaxConnections: cfg.maxConnections, IdleTimeout: cfg.idleTimeout,
	})

	validators := validator.NewRegistry(cfg.randomXServiceURL)
	vardiffCfg := solo.VardiffConfig{
		MinDifficulty: cfg.minDifficulty, MaxDifficulty: cfg.maxDifficulty,
		TargetTime: cfg.vardiffTargetTime, RetargetInterval: cfg.vardiffInterval,
	}

	// Real backend transport -- the genuinely new wiring point vs.
	// leaf-solo (see this binary's own doc comment). backendTransport is
	// explicitly typed as the transport.ShareTransport interface (not a
	// concrete type) so either real implementation can be constructed
	// here without changing any downstream call site (direct.ServerConfig
	// .Transport is already declared as this same interface type).
	var backendTransport transport.ShareTransport
	if cfg.legacyMode {
		legacyTr, err := legacytransport.New(legacytransport.Config{
			BackendBaseURL: cfg.legacyBackendURL, AuthKey: cfg.legacyAuthKey,
			LegacyPoolType: legacyPoolType, LegacyPoolID: int32(cfg.legacyPoolID),
			ShareTimeout: cfg.backendShareTimeout, BlockTimeout: cfg.backendBlockTimeout,
			BlockSubmitRetryBudget: cfg.legacyBlockRetryBudget, Logger: logger,
		})
		if err != nil {
			logger.Fatalf("failed to construct legacy backend transport: %v", err)
		}
		backendTransport = legacyTr
		logger.Printf("LEGACY MODE ENABLED: forwarding validated shares/blocks to legacy nodejs-pool-sxmr backend at %s/leafApi (legacy pool-type=%s legacy pool-id=%d)", cfg.legacyBackendURL, cfg.legacyPoolType, cfg.legacyPoolID)
	} else {
		httpTr, err := transport.NewHTTPProtobufTransport(transport.HTTPProtobufTransportConfig{
			BaseURL: cfg.backendBaseURL, AuthHeaderName: cfg.backendAuthHeader, AuthHeaderValue: cfg.backendAuthValue,
			ShareTimeout: cfg.backendShareTimeout, BlockTimeout: cfg.backendBlockTimeout,
			Debug: debugLogger,
		})
		if err != nil {
			logger.Fatalf("failed to construct backend transport: %v", err)
		}
		backendTransport = httpTr
		logger.Printf("forwarding validated shares/blocks to backend at %s", cfg.backendBaseURL)
	}
	defer func() { _ = backendTransport.Close() }()

	// Real direct parallel multi-node GRPC block submission -- Tari
	// only (MultiNodeSubmitter's blockSubmitClient interface is
	// genuinely SubmitBlock(*tari_generated.Block)-shaped -- see
	// multisubmit.go). For -coin=monero this is left nil/unconfigured
	// on purpose: real multi-node Monero block submission is a KNOWN,
	// EXPLICITLY DEFERRED gap (see this binary's own doc comment and
	// the PR description) -- session.go's handleSubmit instead submits
	// a genuine Monero block find via a single real
	// node.SubmitBlock(MoneroNodeClient) call, which is this leaf's
	// one configured monerod connection (the same one JobManager uses
	// as its template source).
	var multiSubmit *direct.MultiNodeSubmitter
	if !isMoneroFamilyCoin(cfg.coin) {
		submitAddrs := resolveSubmitNodes(cfg.nodeGRPCAddress, cfg.submitNodesRaw)
		var err error
		multiSubmit, err = direct.NewMultiNodeSubmitter(submitAddrs, logger)
		if err != nil {
			logger.Fatalf("failed to construct multi-node block submitter: %v", err)
		}
		logger.Printf("multi-node block submit configured for %d node(s): %v", len(submitAddrs), submitAddrs)
	} else {
		logger.Printf("multi-node block submit disabled for -coin=%s (known, deferred gap -- single-node MoneroNodeClient.SubmitBlock is the real, working priority path)", cfg.coin)
	}
	defer func() {
		if multiSubmit != nil {
			_ = multiSubmit.Close()
		}
	}()

	// moneroHeaderURL is only set for a monerod-family -coin -- it
	// wires ServerConfig.MonerodURL so this Server's own, independent
	// get_block_header_by_height resolver (monero_hash.go) can
	// capture the REAL block hash on a genuine block find instead of
	// the old sha256(blob) placeholder (see FIX_BRIEF.md). Left empty
	// for -coin=tari (ignored entirely).
	var moneroHeaderURL string
	if isMoneroFamilyCoin(cfg.coin) {
		moneroHeaderURL = cfg.monerodURL
	}
	// BUG FIX (2026-09-23, real production incident -- see
	// legacytransport.DefaultBlockSubmitRetryBudget's doc comment):
	// forwardBlock's own outer ctx timeout (ServerConfig.
	// BlockForwardTimeout) must comfortably exceed whatever retry
	// budget the legacy transport is actually configured with, or
	// the retry loop gets killed early by its own caller. Only
	// meaningful in legacy mode -- the normal transport.
	// HTTPProtobufTransport has no retry loop, so this leaves
	// blockForwardTimeout at direct.NewServer's own 10s default
	// (zero value here) for every non-legacy-mode deployment,
	// exactly preserving today's behavior.
	var blockForwardTimeout time.Duration
	if cfg.legacyMode {
		// +30s slack on top of the retry budget: the final retry
		// attempt still needs its own full per-attempt BlockTimeout
		// to run to completion (or fail) AFTER the budget's deadline
		// is checked, plus scheduling/network jitter headroom.
		blockForwardTimeout = cfg.legacyBlockRetryBudget + cfg.backendBlockTimeout + 30*time.Second
	}
	server := direct.NewServer(direct.ServerConfig{
		ConnectionManager: cm, JobManager: jobManager, Node: node, Validators: validators,
		Network: networkFromString(cfg.network), Logger: logger, Vardiff: vardiffCfg,
		Transport: backendTransport, MultiSubmit: multiSubmit, Relay: blockRelay,
		Algo: resolveAlgo(cfg), PoolType: poolType, PoolID: int32(cfg.poolID),
		Debug:               debugLogger,
		MonerodURL:          moneroHeaderURL,
		MergeMineChains:     parseMergeMineChains(cfg.mergeMineChains, logger),
		BlockForwardTimeout: blockForwardTimeout,
		NoShareTimeout:      cfg.noShareTimeout,
	})
	defer server.Shutdown()

	if cfg.trustEnabled {
		trustCfg := solo.TrustConfig{
			Enabled:   true,
			Threshold: cfg.trustThreshold,
			Penalty:   cfg.trustPenalty,
			Change:    cfg.trustChange,
			Min:       cfg.trustMin,
		}
		server.EnableTrust(trustCfg)
		logger.Printf("trusted-miner RandomX-validation skip ENABLED for RXT/RXM (threshold=%d penalty=%d change=%d min=%d -- 0 means the documented default is in effect)", cfg.trustThreshold, cfg.trustPenalty, cfg.trustChange, cfg.trustMin)
	}

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2a): worker
	// count is runtime.NumCPU() by DEFAULT (direct.NewServer's own
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
		logger.Printf("RandomX-family async validation worker pool size overridden to %d (default would have been runtime.NumCPU()=%d), queue size overridden to %d (0 means the documented default, max(256, workers*16), is in effect)", cfg.randomxWorkers, runtime.NumCPU(), cfg.randomxQueueSize)
	}

	// CLOSE-WAIT production-incident fix: worker count is
	// runtime.NumCPU() by DEFAULT (direct.NewServer's own
	// construction already applies this), not a hardcoded literal;
	// an operator who wants a different fixed count can still get one
	// via -job-fetch-workers.
	if cfg.jobFetchWorkers > 0 {
		server.SetJobFetchPoolSize(cfg.jobFetchWorkers, 0)
		logger.Printf("job-fetch (login/getjob) async worker pool size overridden to %d (default would have been runtime.NumCPU()=%d)", cfg.jobFetchWorkers, runtime.NumCPU())
	}

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b): disconnect
	// a session after too many consecutive real RandomX-family
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

	// Real, manual ban/forced-minimum-difficulty enforcement (see
	// internal/leaflib/addressflags's package doc comment). Non-legacy
	// leaf-direct always has the real (NEW go-crypto-pool) backend
	// configured that it is already forwarding shares/blocks to, so it
	// polls that backend's own GET /api/v1/leaf/address-flags endpoint.
	//
	// -legacy-mode=true has no such backend: cfg.backendBaseURL is not
	// even required in that mode (see requiredFieldsError), and no
	// legacy-aware addressflags.Source exists anywhere in this
	// codebase today (only HTTPSource, above, and leaf-solo's file-
	// backed FileSource -- neither of which leaf-direct's legacy path
	// wires up; checked internal/leaflib/legacytransport and
	// internal/leaflib/addressflags directly, this is not assumed).
	// Constructing/starting it unconditionally would either poll a
	// nonexistent NEW-backend endpoint at an EMPTY baseURL (or,
	// incidentally, the legacy backend's URL if an operator happened
	// to also set -backend-base-url, which the legacy nodejs-pool-sxmr
	// backend does not implement either way) -- so it is skipped
	// entirely in legacy mode, with a clear, unambiguous startup log
	// line rather than a silent no-op, since this is a real capability
	// gap operators need to know about.
	if cfg.legacyMode {
		logger.Println("manual ban/forced-minimum-difficulty enforcement UNAVAILABLE in -legacy-mode=true: no legacy-backend-aware addressflags.Source exists yet, and the NEW backend's /api/v1/leaf/address-flags is not applicable to a legacy-only deployment -- logins/vardiff proceed with NO ban or forced-min-difficulty enforcement via this path")
	} else {
		addressFlagsCache := addressflags.NewCache(
			addressflags.NewHTTPSource(cfg.backendBaseURL, cfg.backendAuthHeader, cfg.backendAuthValue),
			cfg.addressFlagsPollInterval, logger,
		)
		addressFlagsCache.Start(ctx)
		server.EnableAddressFlags(addressFlagsCache)
		logger.Printf("manual ban/forced-minimum-difficulty enforcement ENABLED, polling %s%s every %s", cfg.backendBaseURL, "/api/v1/leaf/address-flags", cfg.addressFlagsPollInterval)
	}

	// Real legacy /poolCheckin heartbeat (see
	// internal/leaflib/legacytransport/checkin.go) -- legacy-mode-only,
	// gated the exact same way every other legacy-mode feature in this
	// binary is (cfg.legacyMode), plus its own independent
	// -legacy-checkin-enabled toggle (default true -- see that flag's
	// own doc comment for the open design question flagged for Alex).
	// When either gate is off, this whole block is skipped: zero
	// goroutines, zero dials, identical behavior to before this
	// feature existed.
	if cfg.legacyMode && cfg.legacyCheckinEnabled {
		portNumbers := make([]int, 0, len(ports))
		for _, p := range ports {
			if _, portStr, splitErr := net.SplitHostPort(p.Address); splitErr == nil {
				if n, convErr := strconv.Atoi(portStr); convErr == nil {
					portNumbers = append(portNumbers, n)
				}
			}
		}
		checkin, err := legacytransport.NewCheckin(legacytransport.CheckinConfig{
			APIURL: cfg.legacyCheckinAPIURL, AuthToken: cfg.legacyCheckinAuthToken,
			PoolID: int32(cfg.legacyPoolID), Interval: cfg.legacyCheckinInterval,
		})
		if err != nil {
			logger.Fatalf("failed to construct legacy checkin heartbeat: %v", err)
		}
		portCounter := &connectionPortCounter{cm: cm, ports: portNumbers}
		go checkin.Run(ctx, jobManager, portCounter)
		logger.Printf("LEGACY CHECKIN HEARTBEAT ENABLED: POSTing to %spoolCheckin every %s (legacy pool-id=%d, ports=%v)", cfg.legacyCheckinAPIURL, cfg.legacyCheckinInterval, cfg.legacyPoolID, portNumbers)
	} else if cfg.legacyMode {
		logger.Printf("legacy checkin heartbeat DISABLED by operator config (-legacy-checkin-enabled=false) -- legacy share/block forwarding continues normally, but pool-core's own routing/health-check logic may drain traffic from this leaf without it (see this binary's -legacy-checkin-enabled flag doc comment)")
	}

	if cfg.metricsListenAddress != "" {
		server.SetHideRemoteAddress(cfg.hideRemoteAddress)
		server.SetStatsPageMaxSessions(cfg.statsPageMaxSessions)
		server.EnableMetrics(version, cfg.maxAddressLabels)
		server.EnableChainHeightMetrics()
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", server.MetricsHandler())
		metricsMux.Handle("/", server.StatsHTMLHandler())
		metricsSrv := &http.Server{Addr: cfg.metricsListenAddress, Handler: metricsMux}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Printf("metrics HTTP server error: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
		logger.Printf("serving /metrics and / (basic stats page) on %s", cfg.metricsListenAddress)
	} else {
		logger.Printf("metrics HTTP server disabled (-metrics-listen-address is empty)")
	}

	listeners := make([]net.Listener, 0, len(ports))

	// One shared tls.Certificate for the whole process (see
	// internal/leaflib.LoadOrGenerateCert's doc comment) -- only
	// constructed at all if at least one configured port tier has
	// TLS enabled. If no port has TLS enabled, this is skipped
	// entirely: no behavior change, no wasted work, matching "TLS is
	// fully optional" (see this binary's -ports/-tls-cert-file flag
	// help text).
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
