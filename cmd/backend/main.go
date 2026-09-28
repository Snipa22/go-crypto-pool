// Command backend is the entrypoint for the unified go-crypto-pool
// backend service. It opens a Postgres connection pool, wires it into
// the HTTP+Protobuf share/block ingestion API (internal/backend/api),
// and serves it.
//
// Configuration is via flags, environment variables, or an optional
// TOML config file (see -config / backend.example.toml and
// internal/leaflib/cfgfile for the exact flag > env > file > default
// precedence rule) -- every setting below is available as both a
// flag (its env var name lowercased, with underscores replaced by
// hyphens and the GCPOOL_ prefix stripped, e.g. GCPOOL_DB_DSN ->
// -db-dsn) and the environment variable documented below:
//
//	GCPOOL_DB_DSN            (required) Postgres DSN, e.g.
//	                         "postgres://user:pass@host:5432/db?sslmode=disable"
//	GCPOOL_LISTEN_ADDR       (optional) HTTP listen address, default ":8080"
//	GCPOOL_AUTH_HEADER_NAME  (required, unless
//	                         GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION
//	                         is set — see below) shared-secret auth
//	                         header name to require on /api/v1/share
//	                         and /api/v1/block, e.g. "Authorization".
//	                         Must be set together with
//	                         GCPOOL_AUTH_HEADER_VALUE — see
//	                         internal/backend/api.Config for the
//	                         header-check itself. This command's own
//	                         validateIngestionAuthConfig refuses to
//	                         start (fail fast, non-zero exit) if this
//	                         and GCPOOL_AUTH_HEADER_VALUE are not both
//	                         set, UNLESS the explicit override below
//	                         is passed — see PROD_HARDENING_REVIEW.md
//	                         finding #1: share/block ingestion is the
//	                         leaf-to-backend trust boundary carrying
//	                         real payout-triggering data, so
//	                         "unauthenticated by default" is a
//	                         regression versus legacy's own
//	                         always-on shared-secret model
//	                         (nodejs-pool-sxmr's lib/remoteShare.js),
//	                         not a preserved legacy behavior.
//	GCPOOL_AUTH_HEADER_VALUE (required, unless overridden — see above)
//	                         expected value for the header above.
//	GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION
//	                         (optional, "true" to enable) explicit,
//	                         loudly-logged escape hatch that allows
//	                         this command to start with
//	                         GCPOOL_AUTH_HEADER_NAME/
//	                         GCPOOL_AUTH_HEADER_VALUE both unset,
//	                         leaving /api/v1/share and /api/v1/block
//	                         completely unauthenticated. LOCAL/DEV USE
//	                         ONLY — this is real-money-risk in any
//	                         deployment reachable by anyone other than
//	                         the operator's own trusted leaves. Default
//	                         "false": with no flags/env set at all,
//	                         this command refuses to start rather than
//	                         silently accepting every share/block.
//	GCPOOL_NETWORK           (required) the network this backend is
//	                         configured for. Accepts "mainnet" or
//	                         "testnet" (case-insensitive). There is no
//	                         default — startup fails fast if this is
//	                         missing or does not parse to a valid
//	                         network, since silently defaulting to
//	                         either network here is exactly the kind of
//	                         cross-network contamination this backend
//	                         must prevent. Every submitted Share/Block
//	                         must carry this exact network or it is
//	                         rejected with 400.
//	GCPOOL_TARI_GRPC_ADDR    (optional) host:port of a real Tari base
//	                         node's GRPC endpoint. When set, the block
//	                         unlocker (internal/backend/unlocker) polls
//	                         every pending ALGO_RXT/ALGO_C29/ALGO_SHA3X
//	                         block against it (internal/backend/chain.
//	                         TariVerifier) to detect maturity/orphaning.
//	                         When unset, those algos' blocks are simply
//	                         never auto-unlocked — a deliberate opt-in,
//	                         not a startup failure, since not every
//	                         deployment mines every coin.
//	GCPOOL_MONERO_RPC_ADDR   (optional) base URL of a real monerod
//	                         JSON-RPC endpoint (e.g.
//	                         "http://127.0.0.1:18081"). When set, the
//	                         unlocker polls every pending ALGO_RXM block
//	                         against it (internal/backend/chain.
//	                         MoneroVerifier). Same opt-in behavior as
//	                         GCPOOL_TARI_GRPC_ADDR above.
//	GCPOOL_UNLOCKER_POLL_INTERVAL (optional) how often the unlocker
//	                         re-checks pending blocks, as a
//	                         time.ParseDuration string (e.g. "60s").
//	                         Default "60s". Only consulted if at least
//	                         one of the two RPC addrs above is set.
//	GCPOOL_UNLOCKER_TARI_MATURITY (optional) confirmations required
//	                         before a Tari-family block (RXT/C29/SHA3X)
//	                         is marked unlocked/payable. Default 60 —
//	                         a PLACEHOLDER, operationally-tunable value,
//	                         not a Tari protocol constant; pool
//	                         operators should set this to their own
//	                         real reorg-safety requirement.
//	GCPOOL_UNLOCKER_MONERO_MATURITY (optional) confirmations required
//	                         before an RXM block is marked unlocked/
//	                         payable. Default 60, mirroring Monero's
//	                         own real CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
//	                         (coinbase spend maturity) — a sensible
//	                         starting default, but still operator-
//	                         tunable via this variable, not hardcoded.
//	GCPOOL_UNLOCKER_STUCK_TIMEOUT (optional) how long a CHAIN-
//	                         UNRESOLVED pending block (Verify error,
//	                         not-found, or below-maturity-depth — see
//	                         unlocker.Config.StuckTimeout's doc
//	                         comment for the exact three cases) may
//	                         sit before the unlocker gives up waiting
//	                         and auto-marks it invalid+unlocked
//	                         instead of retrying it forever, as a
//	                         time.ParseDuration string (e.g. "30m").
//	                         Default "30m" -- deliberately ON by
//	                         default, unlike most other optional knobs
//	                         in this file. Does NOT affect a block
//	                         that is confirmed mature on-chain but
//	                         whose payout failed (outcomePayoutRetry):
//	                         that case always retries forever
//	                         regardless of this setting, since money
//	                         already confirmed owed must never time
//	                         out. Set to "0" to restore the pre-this-
//	                         feature forever-retry behavior for
//	                         chain-unresolved blocks too.
//	GCPOOL_PAYOUT_TARI_FEE_ADDRESS (optional) pool operator
//	                         fee-collection payment address for
//	                         Tari-family algos (RXT/C29/SHA3X).
//	GCPOOL_PAYOUT_MONERO_FEE_ADDRESS (optional) pool operator
//	                         fee-collection payment address for RXM.
//	                         When either is set, every block the
//	                         unlocker marks matured for that coin
//	                         family also triggers a real
//	                         internal/backend/payout.Calculator
//	                         PPS/PPLNS/Solo payout cycle for that
//	                         block, crediting miner balances. When
//	                         unset, blocks still mature/unlock
//	                         correctly — they are simply never
//	                         auto-paid out. See
//	                         buildPayoutCalculator's doc comment for
//	                         the rest of this feature's env vars
//	                         (GCPOOL_PAYOUT_TARI_DONATION_ADDRESS,
//	                         GCPOOL_PAYOUT_MONERO_DONATION_ADDRESS,
//	                         GCPOOL_PAYOUT_{PPS,PPLNS,SOLO}_FEE_PERCENT,
//	                         GCPOOL_PAYOUT_DONATION_PERCENT,
//	                         GCPOOL_PAYOUT_PPLNS_SHARE_MULTI).
//	GCPOOL_MONERO_WALLET_RPC_ADDR (optional) base URL of a real
//	                         monero-wallet-rpc endpoint (e.g.
//	                         "http://127.0.0.1:18083"). When set, the
//	                         real internal/backend/disburse.Engine
//	                         periodically pays out every miner's
//	                         accrued pending_balance via a real
//	                         on-chain transfer (internal/backend/wallet.
//	                         MoneroWalletRPC). When unset, balances
//	                         still accrue correctly, they simply
//	                         aren't disbursed on-chain automatically.
//	                         See buildDisburseEngine's doc comment for
//	                         the rest of this feature's env vars
//	                         (GCPOOL_MONERO_WALLET_RPC_{USER,PASSWORD},
//	                         GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC,
//	                         GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH,
//	                         GCPOOL_DISBURSE_POLL_INTERVAL,
//	                         GCPOOL_FORCE_PAYOUT_FEE_ATOMIC).
//	GCPOOL_<TICKER>_WALLET_RPC_ADDR (optional, env-var-only -- not a
//	                         flag, since the name is only known at
//	                         runtime; see this file's package doc
//	                         comment's note on
//	                         GCPOOL_RETENTION_<ALGO>_<POOL_TYPE>_BLOCKS
//	                         for the same pattern) base URL of a real
//	                         monero-wallet-rpc-COMPATIBLE endpoint for
//	                         one of the 7 standalone monerod-family
//	                         coins added via internal/coinprofile.Registry
//	                         (TICKER is that coin's own Ticker, e.g.
//	                         GCPOOL_ARQ_WALLET_RPC_ADDR,
//	                         GCPOOL_XEQ_WALLET_RPC_ADDR, ...). When
//	                         set, that coin gets its own, genuinely
//	                         separate internal/backend/disburse.Engine
//	                         (wallet.NewMoneroWalletRPC is already a
//	                         generic monero-wallet-rpc-compatible
//	                         client, so it is reused as-is -- no new
//	                         per-coin wallet client code). When unset
//	                         (the default for every one of the 7 coins
//	                         until an operator configures it), that
//	                         coin's balances still accrue correctly,
//	                         they simply are not auto-disbursed
//	                         on-chain -- exactly the same "absent env
//	                         var = disabled, never fatal" contract as
//	                         GCPOOL_MONERO_WALLET_RPC_ADDR/
//	                         GCPOOL_TARI_WALLET_GRPC_ADDR above. See
//	                         buildCoinDisburseEngines' doc comment.
//	GCPOOL_<TICKER>_WALLET_RPC_USER,
//	GCPOOL_<TICKER>_WALLET_RPC_PASSWORD (optional, env-var-only) HTTP
//	                         Digest auth credentials for the same
//	                         per-coin wallet RPC endpoint, mirroring
//	                         GCPOOL_MONERO_WALLET_RPC_{USER,PASSWORD}.
//	                         Both empty means no auth is attempted.
//	                         GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC,
//	                         GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH,
//	                         GCPOOL_DISBURSE_POLL_INTERVAL,
//	                         GCPOOL_FORCE_PAYOUT_FEE_ATOMIC, and
//	                         GCPOOL_WALLET_RPC_TIMEOUT are all SHARED
//	                         with the Monero engine's identically-named
//	                         knobs above (and with each other, across
//	                         every one of the 7 new coins) -- see
//	                         buildCoinDisburseEngines' doc comment for
//	                         why a per-coin override of any of these
//	                         was deliberately not added: there is no
//	                         known coin-specific reason (fee-per-KB,
//	                         batch limit, or wallet-rpc auth quirk)
//	                         to need one, and this dispatch does not
//	                         invent one speculatively.
//	GCPOOL_WALLET_RPC_TIMEOUT (optional) timeout for real wallet RPC
//	                         calls -- the monero-wallet-rpc HTTP
//	                         client's timeout, and the bound on
//	                         Tari's READ-ONLY wallet GRPC lookups.
//	                         Default "60s". This is money-critical,
//	                         not cosmetic: a transfer RPC that takes
//	                         longer than this is abandoned
//	                         client-side while the wallet may still
//	                         broadcast it for real, which the
//	                         disbursement engine must then treat as
//	                         AMBIGUOUS and halt on until an operator
//	                         resolves it (see
//	                         defaultWalletRPCTimeout and
//	                         internal/backend/disburse). Set it
//	                         generously.
//	GCPOOL_STATS_API_RATE_LIMIT_PER_SECOND (optional) sustained
//	                         requests/second, per source IP, allowed
//	                         against the public, unauthenticated GET
//	                         routes registered by
//	                         internal/backend/statsapi,
//	                         internal/backend/networkapi, and
//	                         internal/backend/legacyconfig (see run()'s
//	                         wiring of internal/backend/ratelimit).
//	                         Default 30. <= 0 disables rate limiting
//	                         entirely for those three route groups.
//	GCPOOL_STATS_API_RATE_LIMIT_BURST (optional) token-bucket burst
//	                         size (per source IP) for
//	                         GCPOOL_STATS_API_RATE_LIMIT_PER_SECOND
//	                         above. Default 90. Only consulted when
//	                         the rate limit is enabled.
//	GCPOOL_JWT_SECRET        (required) HMAC-SHA256 signing secret for
//	                         internal/backend/authapi's JWTs (also
//	                         reused as its password-hashing key --
//	                         see that package's doc comment). The
//	                         authapi routes (POST /authenticate,
//	                         /authed/*, /user/*) are always registered
//	                         by this command, so this is required
//	                         unconditionally, unlike every other env
//	                         var above (which gate genuinely optional
//	                         features) -- run() fails fast at startup
//	                         if this is unset.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/netutil"

	"github.com/Snipa22/go-crypto-pool/internal/backend/addressmap"
	"github.com/Snipa22/go-crypto-pool/internal/backend/api"
	"github.com/Snipa22/go-crypto-pool/internal/backend/authapi"
	"github.com/Snipa22/go-crypto-pool/internal/backend/chain"
	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/backend/disburse"
	"github.com/Snipa22/go-crypto-pool/internal/backend/leafflagsapi"
	"github.com/Snipa22/go-crypto-pool/internal/backend/legacyapi"
	"github.com/Snipa22/go-crypto-pool/internal/backend/legacyconfig"
	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/backend/networkapi"
	"github.com/Snipa22/go-crypto-pool/internal/backend/networkpoller"
	"github.com/Snipa22/go-crypto-pool/internal/backend/payout"
	"github.com/Snipa22/go-crypto-pool/internal/backend/ratelimit"
	"github.com/Snipa22/go-crypto-pool/internal/backend/retention"
	"github.com/Snipa22/go-crypto-pool/internal/backend/statsapi"
	"github.com/Snipa22/go-crypto-pool/internal/backend/unlocker"
	"github.com/Snipa22/go-crypto-pool/internal/backend/wallet"
	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/cfgfile"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

const defaultListenAddr = ":8080"

// defaultMetricsListenAddr is GET /metrics' own default HTTP listen
// address -- loopback-only, matching the leaf binaries' own
// -metrics-listen-address defaults (127.0.0.1:9600/9601). 9600/9601
// are already taken by leaf-solo/leaf-direct+leaf-proxy respectively
// (a single host could conceivably run one of each alongside this
// backend), so 9602 is picked here to avoid a same-host collision by
// default -- still just a placeholder port an operator is free to
// override via -metrics-listen-addr/GCPOOL_METRICS_LISTEN_ADDR.
const defaultMetricsListenAddr = "127.0.0.1:9602"

// defaultIngestionRateLimit/defaultIngestionRateBurst are this
// command's defaults for -ingestion-rate-limit/-ingestion-rate-burst
// (GCPOOL_INGESTION_RATE_LIMIT/GCPOOL_INGESTION_RATE_BURST) — the
// per-source-IP requests-per-second cap (and its burst allowance)
// applied across /api/v1/share and /api/v1/block combined (see
// api.Config.IngestionRateLimit/IngestionRateBurst).
//
// Sizing rationale: this pool's own leaf-proxy vardiff already
// targets roughly one share every 15-30s PER WORKER (see recent
// commit history: "lower vardiff target-time/retarget-interval
// defaults to 15s/30s"). But a single leaf can aggregate hundreds of
// individual miner workers behind ONE backend-facing IP
// (proxy-aggregator mode is an explicitly supported leaf mode per
// AGENTS.md) -- e.g. 300 workers submitting once every ~20s each is
// already ~15 req/s sustained from that one IP, well before
// accounting for any bursty/uneven submit timing across workers. 200
// req/s sustained with a burst of 400 is chosen to comfortably exceed
// that kind of aggregate submit rate for a single legitimate
// high-hashrate proxy-aggregator leaf, while still bounding a single
// misbehaving/malicious source to a fraction of what this process can
// otherwise sink. Deliberately NOT a stingy value like 5-10 req/s —
// that WOULD throttle real proxy-aggregator leaves.
const (
	defaultIngestionRateLimit = 200
	defaultIngestionRateBurst = 400
)

// defaultUnlockerPollInterval/defaultTariMaturity/defaultMoneroMaturity
// are this command's PLACEHOLDER defaults for the unlocker's env vars
// — see this file's package doc comment for why these are
// operator-tunable rather than baked-in protocol constants.
const (
	defaultUnlockerPollInterval = 60 * time.Second
	defaultTariMaturity         = int64(60)
	defaultMoneroMaturity       = int64(60)

	// defaultUnlockerStuckTimeout is this command's default for
	// GCPOOL_UNLOCKER_STUCK_TIMEOUT/unlocker.Config.StuckTimeout.
	// Unlike defaultUnlockerPollInterval/defaultTariMaturity/
	// defaultMoneroMaturity above, this is NOT a placeholder an
	// operator is expected to have to tune -- 30 minutes is the
	// confirmed, deliberate ON-by-default value (see
	// unlocker.Config.StuckTimeout's doc comment and the
	// GCPOOL_UNLOCKER_STUCK_TIMEOUT env var doc above): "if it
	// hasn't resolved in that time, it won't."
	defaultUnlockerStuckTimeout = 30 * time.Minute

	// defaultNetworkPollerInterval is internal/backend/networkpoller's
	// own PLACEHOLDER default poll interval, mirroring
	// defaultUnlockerPollInterval's role/rationale above for the
	// same reasons -- operator-tunable via
	// GCPOOL_NETWORK_POLLER_POLL_INTERVAL, not a protocol constant.
	defaultNetworkPollerInterval = 60 * time.Second
)

// defaultStatsAPIRateLimitPerSecond/defaultStatsAPIRateLimitBurst are
// this command's defaults for the internal/backend/ratelimit
// per-source-IP token-bucket limiter applied to the public,
// unauthenticated, read-only statsapi/networkapi/legacyconfig routes
// (see run()'s wiring). Deliberately set MATERIALLY HIGHER than a
// sane default would be for the leaf-to-backend share/block
// ingestion endpoint: these are public stats-page endpoints, which a
// browser dashboard, a monitoring script, and any number of
// legitimate distinct miners behind the SAME NAT/source IP may all
// poll concurrently and far more frequently than a single leaf's own
// periodic ingestion poll -- a low, ingestion-appropriate value here
// would produce false-positive 429s against ordinary legitimate
// traffic, not just an actual flood. 30 req/s sustained with a burst
// of 90 (3x) is picked as a reasonable middle of the brief's
// suggested 20-50 req/s-sustained / 2-4x-burst range: generous enough
// for a dashboard auto-refreshing every few seconds across all 3
// wrapped route groups from one shared source IP, while still
// bounding a single IP's worst-case request rate against this
// backend's Postgres-backed queries to a small, fixed number.
const (
	defaultStatsAPIRateLimitPerSecond = 30
	defaultStatsAPIRateLimitBurst     = 90

	// statsAPIRateLimitJanitorInterval/statsAPIRateLimitJanitorMaxAge
	// bound the per-source-IP limiter map's memory footprint (see
	// internal/backend/ratelimit.Limiter.RunJanitor): every 5 minutes,
	// any source IP not seen again in the last 15 minutes has its
	// token-bucket entry evicted, so a flood of distinct/rotating
	// source IPs cannot grow this map without bound forever.
	statsAPIRateLimitJanitorInterval = 5 * time.Minute
	statsAPIRateLimitJanitorMaxAge   = 15 * time.Minute
)

// Version is the backend's build version, recorded on the
// backend_build_info Prometheus gauge. Overridable at build time via
// -ldflags "-X main.Version=...", e.g. from a CI-set git tag/commit;
// defaults to "dev" for local/unreleased builds.
var Version = "dev"

// config holds every backend setting that was previously read
// directly via os.Getenv scattered across run() and the various
// buildXxxConfig/buildXxxEngine helpers below -- see this file's
// package doc comment for the full env-var-by-env-var writeup, and
// loadConfig for how each field is populated (flag > env > TOML file
// > hardcoded default). The one deliberate exception is the dynamic
// per-(algo,pool_type) GCPOOL_RETENTION_<ALGO>_<POOL_TYPE>_BLOCKS
// override consumed inside buildRetentionConfig's own db.ValidAlgos/
// db.ValidPoolTypes loop -- those cannot become static flags/fields
// since their names are only known at runtime, so that inner loop's
// os.Getenv call is intentionally left as-is.
type config struct {
	dbDSN           string
	listenAddr      string
	authHeaderName  string
	authHeaderValue string
	network         string

	// metricsListenAddr is GET /metrics' own HTTP listen address --
	// deliberately SEPARATE from listenAddr (see this file's package
	// doc comment / run()'s wiring). Defaults to loopback-only
	// (127.0.0.1), matching the 3 leaf binaries' own
	// -metrics-listen-address convention (cmd/leaf-solo,
	// cmd/leaf-direct, cmd/leaf-proxy): an operator must explicitly
	// set this to a wildcard/public address to expose /metrics
	// publicly. Per PROD_HARDENING_REVIEW.md finding #12, /metrics
	// exposes wallet_balance_atomic (the real hot-wallet balance) and
	// previously shared the SAME public, wildcard-bindable listener
	// as share/block ingestion -- this field is what fixes that.
	// Empty disables the separate /metrics listener entirely
	// (mirroring the leaf binaries' own "empty disables" convention)
	// -- a deployment that sets this to "" gets no /metrics endpoint
	// at all from this process, not a fallback onto listenAddr.
	metricsListenAddr string

	// maxConnections caps the number of simultaneously-open TCP
	// connections the main (listenAddr) HTTP listener will accept,
	// via a netutil.LimitListener wrapping the raw net.Listener (see
	// run()'s wiring) -- 0 means unlimited. Per
	// PROD_HARDENING_REVIEW.md finding #12: the leaf binaries already
	// have an analogous cap for their own listeners
	// (internal/leaflib/manager.go's ConnectionManager.MaxConnections,
	// DefaultLeafMaxConnections), but this backend previously had
	// none at all for its own public HTTP listener.
	maxConnections int

	// ingestionRateLimit/ingestionRateBurst configure the per-source-
	// IP rate limiter in front of /api/v1/share and /api/v1/block
	// (see api.Config.IngestionRateLimit/IngestionRateBurst and
	// defaultIngestionRateLimit/defaultIngestionRateBurst's doc
	// comment for sizing rationale). ingestionRateLimit <= 0 means
	// "disabled" (no rate limiting), mirroring maxConnections' own
	// 0 = unlimited convention above. This is a genuinely different
	// defense than maxConnections: that caps total concurrent TCP
	// connections across ALL sources combined, this bounds the
	// request RATE of any one individual source.
	ingestionRateLimit float64
	ingestionRateBurst int

	// insecureAllowUnauthenticatedIngestion is the explicit,
	// loudly-logged escape hatch that allows run() to start with
	// authHeaderName/authHeaderValue both unset (see
	// validateIngestionAuthConfig and this file's package doc
	// comment for GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION).
	// Local/dev use only — false is the only safe production value,
	// and false is this field's default.
	insecureAllowUnauthenticatedIngestion bool

	// statsAPIRateLimitPerSecond/statsAPIRateLimitBurst configure the
	// per-source-IP token-bucket rate limiter (internal/backend/
	// ratelimit) applied to the public, unauthenticated, read-only
	// statsapi/networkapi/legacyconfig routes -- see run()'s wiring
	// and defaultStatsAPIRateLimitPerSecond's doc comment for the
	// default rationale. statsAPIRateLimitPerSecond <= 0 disables
	// this limiter entirely.
	statsAPIRateLimitPerSecond float64
	statsAPIRateLimitBurst     int

	tariGRPCAddr  string
	moneroRPCAddr string

	unlockerPollInterval   time.Duration
	unlockerTariMaturity   int64
	unlockerMoneroMaturity int64
	unlockerStuckTimeout   time.Duration

	networkPollerPollInterval time.Duration

	payoutTariFeeAddress        string
	payoutMoneroFeeAddress      string
	payoutTariDonationAddress   string
	payoutMoneroDonationAddress string
	// payoutExtraFeeAddressesRaw/payoutExtraDonationAddressesRaw
	// generalize payoutTariFeeAddress/payoutMoneroFeeAddress (and
	// their donation counterparts) to the new standalone
	// monerod-family coins added via internal/coinprofile.Registry --
	// see payout.Config.ExtraFeeAddresses's doc comment for why each
	// one needs its own independent address rather than sharing
	// RXM's Monero address. Format: comma-separated
	// "TICKER=address" pairs, e.g. "ARQ=ar2...,XEQ=Tvz...". Parsed by
	// parseExtraCoinAddresses, which fails fast (refuses to start) on
	// an unregistered ticker or an address that doesn't validate
	// against that coin's own CoinProfile.
	payoutExtraFeeAddressesRaw      string
	payoutExtraDonationAddressesRaw string
	payoutPPSFeePercent             float64
	payoutPPLNSFeePercent           float64
	payoutSoloFeePercent            float64
	payoutDonationPercent           float64
	payoutPPLNSShareMulti           float64

	retentionPollInterval time.Duration
	retentionBlocks       int64

	moneroWalletRPCAddr     string
	moneroWalletRPCUser     string
	moneroWalletRPCPassword string

	// walletRPCTimeout bounds the real wallet RPC calls both
	// disbursement engines make -- see defaultWalletRPCTimeout and
	// buildDisburseEngine's doc comment for why this is
	// money-critical rather than a routine tuning knob.
	walletRPCTimeout time.Duration

	disburseMinPayoutAtomic         int64
	disburseMaxDestinationsPerBatch int
	disbursePollInterval            time.Duration
	forcePayoutFeeAtomic            int64

	tariWalletGRPCAddr   string
	tariWalletFeePerGram uint64

	walletStatsPollInterval time.Duration

	// jwtSecret is the HMAC-SHA256 signing secret for
	// internal/backend/authapi's JWTs (also reused as its password-
	// hashing key -- see that package's doc comment). Required --
	// run() fails fast at startup if this is empty, since the authapi
	// routes it gates are always registered (see run()'s own doc
	// comment / wiring below), unlike every other feature in this
	// file, which is opt-in based on whether its own config knob was
	// set.
	jwtSecret string

	// configFile is the optional path to a TOML file providing
	// defaults for any flag above that the operator did not set
	// explicitly via CLI flag or environment variable. See
	// backend.example.toml and internal/leaflib/cfgfile for the
	// exact precedence rule (flag > env > file > hardcoded default).
	configFile string

	// debug is -debug/GCPOOL_DEBUG: enables the shared
	// leaflib.DebugLogger (internal/leaflib/debuglog.go) for this
	// process. OFF (false) by default -- purely additive, byte-
	// identical existing log output when left off. Wired into
	// unlocker.Config.Debug/disburse.Config.Debug/
	// networkpoller.Config.Debug below (see run()).
	debug bool
}

// loadConfig registers one flag per config field (mirroring the
// GCPOOL_* env var of the same name -- see this file's package doc
// comment), parses flag.CommandLine, and then merges in an optional
// -config TOML file per the flag > env > file > hardcoded-default
// precedence rule owned by internal/leaflib/cfgfile. Only the default
// (no-subcommand) run() path calls this -- the block/retention/
// address/migrate CLI subcommands parse their own, separate flag
// sets in their own files and never call loadConfig.
func loadConfig() (config, error) {
	cfg := config{}

	// envErrs collects any fail-fast env-var parse error from
	// checkedInt64/checkedDuration below (see those closures' doc
	// comment) so loadConfig can register every flag first (flag.FlagSet
	// requires that) and still refuse to start with a single, clear
	// combined error if any of them failed to parse -- rather than
	// silently falling back to a default the way envOrInt64/envOrDuration
	// do for every other, non-money-critical knob in this file. See
	// PROD_HARDENING_REVIEW.md finding #9.
	var envErrs []error

	// checkedInt64/checkedDuration are the fail-fast counterparts of
	// envOrInt64/envOrDuration used ONLY for the money-critical knobs
	// PROD_HARDENING_REVIEW.md finding #9 calls out by name
	// (GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC, GCPOOL_FORCE_PAYOUT_FEE_ATOMIC,
	// GCPOOL_UNLOCKER_*, GCPOOL_WALLET_RPC_TIMEOUT): a typo'd
	// GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC=abc must fail startup loudly,
	// never silently become 0. Every other envOrXxx call in this
	// function is unchanged (still silently defaults) -- deliberately
	// scoped to just these knobs per that finding's own "at minimum"
	// wording, not a blanket behavior change for every flag in this
	// file.
	checkedInt64 := func(key string, def int64) int64 {
		v, err := envOrInt64Checked(key, def)
		if err != nil {
			envErrs = append(envErrs, err)
		}
		return v
	}
	checkedDuration := func(key string, def time.Duration) time.Duration {
		v, err := envOrDurationChecked(key, def)
		if err != nil {
			envErrs = append(envErrs, err)
		}
		return v
	}

	flag.StringVar(&cfg.dbDSN, "db-dsn", envOr("GCPOOL_DB_DSN", ""), "(required) Postgres DSN, e.g. \"postgres://user:pass@host:5432/db?sslmode=disable\". Env: GCPOOL_DB_DSN")
	flag.StringVar(&cfg.listenAddr, "listen-addr", envOr("GCPOOL_LISTEN_ADDR", defaultListenAddr), "HTTP listen address. Env: GCPOOL_LISTEN_ADDR")
	flag.StringVar(&cfg.metricsListenAddr, "metrics-listen-addr", envOr("GCPOOL_METRICS_LISTEN_ADDR", defaultMetricsListenAddr), "HTTP listen address for GET /metrics ONLY -- deliberately separate from -listen-addr (see PROD_HARDENING_REVIEW.md finding #12: /metrics exposes wallet_balance_atomic, the real hot-wallet balance, and must not share a public listener with share/block ingestion). Defaults to loopback-only, matching the leaf binaries' own -metrics-listen-address convention. Empty disables the /metrics endpoint entirely. Env: GCPOOL_METRICS_LISTEN_ADDR")
	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("GCPOOL_MAX_CONNECTIONS", leaflib.DefaultLeafMaxConnections), "max concurrent TCP connections the main HTTP listener (-listen-addr) will accept, 0 = unlimited. Env: GCPOOL_MAX_CONNECTIONS")
	flag.Float64Var(&cfg.ingestionRateLimit, "ingestion-rate-limit", envOrFloat64("GCPOOL_INGESTION_RATE_LIMIT", defaultIngestionRateLimit), "sustained requests-per-second allowed per source IP across /api/v1/share and /api/v1/block combined, 0 (or negative) = disabled (no rate limiting). Default chosen to comfortably exceed the aggregate submit rate of a single leaf proxying hundreds of workers at the pool's own ~15-30s per-worker vardiff target, while still bounding a single misbehaving/malicious source. Env: GCPOOL_INGESTION_RATE_LIMIT")
	flag.IntVar(&cfg.ingestionRateBurst, "ingestion-rate-burst", envOrInt("GCPOOL_INGESTION_RATE_BURST", defaultIngestionRateBurst), "burst size (rate.Limiter's burst parameter) for the same per-source-IP limiter -ingestion-rate-limit configures. Only consulted when -ingestion-rate-limit > 0. Env: GCPOOL_INGESTION_RATE_BURST")
	flag.StringVar(&cfg.authHeaderName, "auth-header-name", envOr("GCPOOL_AUTH_HEADER_NAME", ""), "(required, unless -insecure-allow-unauthenticated-ingestion is set) shared-secret auth header name to require on /api/v1/share and /api/v1/block, e.g. \"Authorization\". Must be set together with -auth-header-value -- run() refuses to start if both are empty and the override flag below isn't set. Env: GCPOOL_AUTH_HEADER_NAME")
	flag.StringVar(&cfg.authHeaderValue, "auth-header-value", envOr("GCPOOL_AUTH_HEADER_VALUE", ""), "(required, unless -insecure-allow-unauthenticated-ingestion is set) expected value for -auth-header-name above. Env: GCPOOL_AUTH_HEADER_VALUE")
	flag.BoolVar(&cfg.insecureAllowUnauthenticatedIngestion, "insecure-allow-unauthenticated-ingestion", envOr("GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION", "false") == "true", "LOCAL/DEV USE ONLY: explicit, loudly-logged override that allows this command to start with -auth-header-name/-auth-header-value both unset, leaving /api/v1/share and /api/v1/block completely unauthenticated. Disabled by default -- with no flags/env set at all, run() refuses to start rather than silently accepting every share/block. Env: GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION (\"true\" to enable)")
	flag.StringVar(&cfg.network, "network", envOr("GCPOOL_NETWORK", ""), "(required) the network this backend is configured for. Accepts \"mainnet\" or \"testnet\" (case-insensitive). There is no default -- startup fails fast if this is missing or does not parse to a valid network. Env: GCPOOL_NETWORK")

	flag.Float64Var(&cfg.statsAPIRateLimitPerSecond, "stats-api-rate-limit-per-second", envOrFloat64("GCPOOL_STATS_API_RATE_LIMIT_PER_SECOND", defaultStatsAPIRateLimitPerSecond), "sustained requests/second, per source IP, allowed against the public, unauthenticated GET routes registered by internal/backend/statsapi, internal/backend/networkapi, and internal/backend/legacyconfig (see run()'s wiring). <= 0 disables rate limiting entirely. Env: GCPOOL_STATS_API_RATE_LIMIT_PER_SECOND")
	flag.IntVar(&cfg.statsAPIRateLimitBurst, "stats-api-rate-limit-burst", envOrInt("GCPOOL_STATS_API_RATE_LIMIT_BURST", defaultStatsAPIRateLimitBurst), "token-bucket burst size (per source IP) for -stats-api-rate-limit-per-second above. Only consulted when the rate limit is enabled. Env: GCPOOL_STATS_API_RATE_LIMIT_BURST")

	flag.StringVar(&cfg.tariGRPCAddr, "tari-grpc-addr", envOr("GCPOOL_TARI_GRPC_ADDR", ""), "host:port of a real Tari base node's GRPC endpoint. When set, the block unlocker polls every pending ALGO_RXT/ALGO_C29/ALGO_SHA3X block against it to detect maturity/orphaning. When unset, those algos' blocks are simply never auto-unlocked. Env: GCPOOL_TARI_GRPC_ADDR")
	flag.StringVar(&cfg.moneroRPCAddr, "monero-rpc-addr", envOr("GCPOOL_MONERO_RPC_ADDR", ""), "base URL of a real monerod JSON-RPC endpoint (e.g. \"http://127.0.0.1:18081\"). When set, the unlocker polls every pending ALGO_RXM block against it. Same opt-in behavior as -tari-grpc-addr above. Env: GCPOOL_MONERO_RPC_ADDR")

	flag.DurationVar(&cfg.unlockerPollInterval, "unlocker-poll-interval", checkedDuration("GCPOOL_UNLOCKER_POLL_INTERVAL", defaultUnlockerPollInterval), "how often the unlocker re-checks pending blocks. Only consulted if at least one of -tari-grpc-addr/-monero-rpc-addr is set. Env: GCPOOL_UNLOCKER_POLL_INTERVAL")
	flag.Int64Var(&cfg.unlockerTariMaturity, "unlocker-tari-maturity", checkedInt64("GCPOOL_UNLOCKER_TARI_MATURITY", defaultTariMaturity), "confirmations required before a Tari-family block (RXT/C29/SHA3X) is marked unlocked/payable. A PLACEHOLDER, operationally-tunable value, not a Tari protocol constant. Env: GCPOOL_UNLOCKER_TARI_MATURITY")
	flag.Int64Var(&cfg.unlockerMoneroMaturity, "unlocker-monero-maturity", checkedInt64("GCPOOL_UNLOCKER_MONERO_MATURITY", defaultMoneroMaturity), "confirmations required before an RXM block is marked unlocked/payable, mirroring Monero's own CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW. Env: GCPOOL_UNLOCKER_MONERO_MATURITY")
	flag.DurationVar(&cfg.unlockerStuckTimeout, "unlocker-stuck-timeout", envOrDuration("GCPOOL_UNLOCKER_STUCK_TIMEOUT", defaultUnlockerStuckTimeout), "how long a chain-unresolved pending block (Verify error, not-found, or below-maturity-depth) may sit before the unlocker gives up and auto-marks it invalid+unlocked instead of retrying it forever. Does NOT apply to a confirmed-mature block whose payout failed -- that always retries forever. Default 30m, deliberately on by default; set to 0 to restore forever-retry for chain-unresolved blocks too. Env: GCPOOL_UNLOCKER_STUCK_TIMEOUT")

	flag.DurationVar(&cfg.networkPollerPollInterval, "network-poller-poll-interval", envOrDuration("GCPOOL_NETWORK_POLLER_POLL_INTERVAL", defaultNetworkPollerInterval), "how often the network-state poller re-checks the real upstream chain(s) configured via -tari-grpc-addr/-monero-rpc-addr. Env: GCPOOL_NETWORK_POLLER_POLL_INTERVAL")

	flag.StringVar(&cfg.payoutTariFeeAddress, "payout-tari-fee-address", envOr("GCPOOL_PAYOUT_TARI_FEE_ADDRESS", ""), "pool operator fee-collection payment address for Tari-family algos (RXT/C29/SHA3X). When set, every matured Tari-family block also triggers a real payout cycle for that block, crediting miner balances. When unset, Tari-family blocks still mature/unlock correctly, they are simply never auto-paid out. Env: GCPOOL_PAYOUT_TARI_FEE_ADDRESS")
	flag.StringVar(&cfg.payoutMoneroFeeAddress, "payout-monero-fee-address", envOr("GCPOOL_PAYOUT_MONERO_FEE_ADDRESS", ""), "pool operator fee-collection payment address for RXM (Monero). When set, every matured RXM block also triggers a real payout cycle for that block, crediting miner balances. When unset, RXM blocks still mature/unlock correctly, they are simply never auto-paid out. Env: GCPOOL_PAYOUT_MONERO_FEE_ADDRESS")
	flag.StringVar(&cfg.payoutTariDonationAddress, "payout-tari-donation-address", envOr("GCPOOL_PAYOUT_TARI_DONATION_ADDRESS", ""), "donation address for Tari-family (RXT/C29/SHA3X) payout cycles. Env: GCPOOL_PAYOUT_TARI_DONATION_ADDRESS")
	flag.StringVar(&cfg.payoutMoneroDonationAddress, "payout-monero-donation-address", envOr("GCPOOL_PAYOUT_MONERO_DONATION_ADDRESS", ""), "donation address for RXM (Monero) payout cycles. Env: GCPOOL_PAYOUT_MONERO_DONATION_ADDRESS")
	flag.StringVar(&cfg.payoutExtraFeeAddressesRaw, "payout-extra-fee-addresses", envOr("GCPOOL_PAYOUT_EXTRA_FEE_ADDRESSES", ""), "comma-separated TICKER=address pairs of pool operator fee-collection addresses for standalone monerod-family coins from internal/coinprofile.Registry (e.g. \"ARQ=ar2...,XEQ=Tvz...\") -- each coin is independent and needs its own address (see -payout-monero-fee-address's doc comment for why RXM's Monero address cannot be shared). Env: GCPOOL_PAYOUT_EXTRA_FEE_ADDRESSES")
	flag.StringVar(&cfg.payoutExtraDonationAddressesRaw, "payout-extra-donation-addresses", envOr("GCPOOL_PAYOUT_EXTRA_DONATION_ADDRESSES", ""), "comma-separated TICKER=address pairs of donation addresses for the same standalone monerod-family coins as -payout-extra-fee-addresses. Env: GCPOOL_PAYOUT_EXTRA_DONATION_ADDRESSES")
	flag.Float64Var(&cfg.payoutPPSFeePercent, "payout-pps-fee-percent", envOrFloat64("GCPOOL_PAYOUT_PPS_FEE_PERCENT", 0), "PPS pool-type operator fee percentage (0-100). Env: GCPOOL_PAYOUT_PPS_FEE_PERCENT")
	flag.Float64Var(&cfg.payoutPPLNSFeePercent, "payout-pplns-fee-percent", envOrFloat64("GCPOOL_PAYOUT_PPLNS_FEE_PERCENT", 0), "PPLNS pool-type operator fee percentage (0-100). Env: GCPOOL_PAYOUT_PPLNS_FEE_PERCENT")
	flag.Float64Var(&cfg.payoutSoloFeePercent, "payout-solo-fee-percent", envOrFloat64("GCPOOL_PAYOUT_SOLO_FEE_PERCENT", 0), "Solo pool-type operator fee percentage (0-100). Env: GCPOOL_PAYOUT_SOLO_FEE_PERCENT")
	flag.Float64Var(&cfg.payoutDonationPercent, "payout-donation-percent", envOrFloat64("GCPOOL_PAYOUT_DONATION_PERCENT", 0), "donation split percentage (0-100) of each fee cut routed to -payout-tari-donation-address/-payout-monero-donation-address, shared across coin families. Env: GCPOOL_PAYOUT_DONATION_PERCENT")
	flag.Float64Var(&cfg.payoutPPLNSShareMulti, "payout-pplns-share-multi", envOrFloat64("GCPOOL_PAYOUT_PPLNS_SHARE_MULTI", defaultPPLNSShareMulti), "PPLNS window multiplier. A placeholder, operator-tunable value -- see payout.Config's doc comment. Env: GCPOOL_PAYOUT_PPLNS_SHARE_MULTI")

	flag.DurationVar(&cfg.retentionPollInterval, "retention-poll-interval", envOrDuration("GCPOOL_RETENTION_POLL_INTERVAL", defaultRetentionPollInterval), "how often the retention job re-evaluates every target. Only consulted if at least one retention window is configured. Env: GCPOOL_RETENTION_POLL_INTERVAL")
	flag.Int64Var(&cfg.retentionBlocks, "retention-blocks", envOrInt64("GCPOOL_RETENTION_BLOCKS", 0), "the DEFAULT retention window, in block-height units, applied to every (algo, pool_type) combination in db.ValidAlgos x db.ValidPoolTypes that does not have a more specific GCPOOL_RETENTION_<ALGO>_<POOL_TYPE>_BLOCKS override (env-var-only, not a flag -- see this file's package doc comment). 0 (or unset) means no default. Env: GCPOOL_RETENTION_BLOCKS")

	flag.StringVar(&cfg.moneroWalletRPCAddr, "monero-wallet-rpc-addr", envOr("GCPOOL_MONERO_WALLET_RPC_ADDR", ""), "base URL of a real monero-wallet-rpc endpoint (e.g. \"http://127.0.0.1:18083\"). When set, accrued pending_balance is periodically paid out via a real on-chain transfer. Env: GCPOOL_MONERO_WALLET_RPC_ADDR")
	flag.StringVar(&cfg.moneroWalletRPCUser, "monero-wallet-rpc-user", envOr("GCPOOL_MONERO_WALLET_RPC_USER", ""), "HTTP Digest auth username matching whatever --rpc-login the real monero-wallet-rpc process was started with. Env: GCPOOL_MONERO_WALLET_RPC_USER")
	flag.StringVar(&cfg.moneroWalletRPCPassword, "monero-wallet-rpc-password", envOr("GCPOOL_MONERO_WALLET_RPC_PASSWORD", ""), "HTTP Digest auth password matching -monero-wallet-rpc-user above. Env: GCPOOL_MONERO_WALLET_RPC_PASSWORD")
	flag.DurationVar(&cfg.walletRPCTimeout, "wallet-rpc-timeout", checkedDuration("GCPOOL_WALLET_RPC_TIMEOUT", defaultWalletRPCTimeout), "timeout for real wallet RPC calls (monero-wallet-rpc HTTP client; Tari's read-only wallet GRPC lookups). Must be long enough that a slow-but-successful transfer isn't abandoned mid-flight -- an over-tight value turns a real payout into an AMBIGUOUS payout that HALTS disbursement until an operator resolves it by hand. Env: GCPOOL_WALLET_RPC_TIMEOUT")
	flag.Int64Var(&cfg.disburseMinPayoutAtomic, "disburse-min-payout-atomic", checkedInt64("GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC", 0), "minimum pending_balance (atomic units) required before a miner is paid out at all. Shared by both the Monero and Tari disbursement engines. Env: GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC")
	flag.Int64Var(&cfg.forcePayoutFeeAtomic, "force-payout-fee-atomic", checkedInt64("GCPOOL_FORCE_PAYOUT_FEE_ATOMIC", 0), "flat atomic-unit fee charged against every force_payout=TRUE balance row paid out this cycle (see POST /user/forcePayment), deducted from the miner's payout and credited to pool revenue. Shared by both the Monero and Tari disbursement engines. 0 (default) means no extra fee. Env: GCPOOL_FORCE_PAYOUT_FEE_ATOMIC")
	flag.IntVar(&cfg.disburseMaxDestinationsPerBatch, "disburse-max-destinations-per-batch", envOrInt("GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH", defaultDisburseMaxDestinationsPerBatch), "cap on destinations per real Transfer call, for the Monero disbursement engine only (the Tari engine hardcodes 1, see buildTariDisburseEngine's doc comment). Env: GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH")
	flag.DurationVar(&cfg.disbursePollInterval, "disburse-poll-interval", envOrDuration("GCPOOL_DISBURSE_POLL_INTERVAL", defaultDisbursePollInterval), "how often the disbursement engine(s) run a cycle. Shared by both the Monero and Tari disbursement engines. Env: GCPOOL_DISBURSE_POLL_INTERVAL")

	flag.StringVar(&cfg.tariWalletGRPCAddr, "tari-wallet-grpc-addr", envOr("GCPOOL_TARI_WALLET_GRPC_ADDR", ""), "address (host:port) of a real Tari console/base wallet GRPC endpoint. When set, enables the Tari payout disbursement engine. Env: GCPOOL_TARI_WALLET_GRPC_ADDR")
	flag.Uint64Var(&cfg.tariWalletFeePerGram, "tari-wallet-fee-per-gram", envOrUint64("GCPOOL_TARI_WALLET_FEE_PER_GRAM", 0), "default fee_per_gram for a Transfer whose Priority is zero. 0 (or unset) leaves wallet.NewTariWalletGRPC's own package default in effect. Env: GCPOOL_TARI_WALLET_FEE_PER_GRAM")

	flag.DurationVar(&cfg.walletStatsPollInterval, "wallet-stats-poll-interval", envOrDuration("GCPOOL_WALLET_STATS_POLL_INTERVAL", defaultWalletStatsPollInterval), "how often the wallet-stats poller calls GetBalance on every configured wallet. Only consulted if at least one wallet RPC is configured. Env: GCPOOL_WALLET_STATS_POLL_INTERVAL")

	flag.StringVar(&cfg.jwtSecret, "jwt-secret", envOr("GCPOOL_JWT_SECRET", ""), "(required) HMAC-SHA256 signing secret for internal/backend/authapi's JWTs (also reused as its password-hashing key -- see that package's doc comment). Env: GCPOOL_JWT_SECRET")

	flag.StringVar(&cfg.configFile, "config", envOr("BACKEND_CONFIG_FILE", ""), "optional path to a TOML config file providing defaults for any flag below not explicitly set via CLI flag or environment variable. See backend.example.toml. Env: BACKEND_CONFIG_FILE")

	flag.BoolVar(&cfg.debug, "debug", envOr("GCPOOL_DEBUG", "false") == "true", "enable verbose [DEBUG]-tagged logging for the block unlocker/disbursement engines/network-state poller's poll-cycle detail (what was checked, what changed). OFF by default -- purely additive, never changes any existing log line. Env: GCPOOL_DEBUG (\"true\" to enable)")

	flag.Parse()

	// Fail fast on any unparseable money-critical env var (see
	// checkedInt64/checkedDuration above) BEFORE ever touching
	// -config/applyConfigFile below -- a malformed env var must
	// surface as a startup error, not silently mask a valid TOML
	// file value for the same field (see
	// internal/leaflib/cfgfile.FieldSource: it treats "env var is
	// non-empty" as "explicitly set", regardless of whether that
	// value actually parsed, so letting a bad env var reach
	// applyConfigFile would have it win over the file anyway --
	// erroring out here instead means that never matters).
	if len(envErrs) > 0 {
		return cfg, fmt.Errorf("backend: invalid environment variable value(s): %w", errors.Join(envErrs...))
	}

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
	DBDSN              *string  `toml:"db_dsn"`
	ListenAddr         *string  `toml:"listen_addr"`
	MetricsListenAddr  *string  `toml:"metrics_listen_addr"`
	MaxConnections     *int     `toml:"max_connections"`
	IngestionRateLimit *float64 `toml:"ingestion_rate_limit"`
	IngestionRateBurst *int     `toml:"ingestion_rate_burst"`
	AuthHeaderName     *string  `toml:"auth_header_name"`
	AuthHeaderValue    *string  `toml:"auth_header_value"`
	Network            *string  `toml:"network"`

	InsecureAllowUnauthenticatedIngestion *bool `toml:"insecure_allow_unauthenticated_ingestion"`

	StatsAPIRateLimitPerSecond *float64 `toml:"stats_api_rate_limit_per_second"`
	StatsAPIRateLimitBurst     *int     `toml:"stats_api_rate_limit_burst"`

	TariGRPCAddr  *string `toml:"tari_grpc_addr"`
	MoneroRPCAddr *string `toml:"monero_rpc_addr"`

	UnlockerPollIntervalSeconds *int   `toml:"unlocker_poll_interval_seconds"`
	UnlockerTariMaturity        *int64 `toml:"unlocker_tari_maturity"`
	UnlockerMoneroMaturity      *int64 `toml:"unlocker_monero_maturity"`
	UnlockerStuckTimeoutSeconds *int   `toml:"unlocker_stuck_timeout_seconds"`

	NetworkPollerPollIntervalSeconds *int `toml:"network_poller_poll_interval_seconds"`

	PayoutTariFeeAddress         *string  `toml:"payout_tari_fee_address"`
	PayoutMoneroFeeAddress       *string  `toml:"payout_monero_fee_address"`
	PayoutTariDonationAddress    *string  `toml:"payout_tari_donation_address"`
	PayoutMoneroDonationAddress  *string  `toml:"payout_monero_donation_address"`
	PayoutExtraFeeAddresses      *string  `toml:"payout_extra_fee_addresses"`
	PayoutExtraDonationAddresses *string  `toml:"payout_extra_donation_addresses"`
	PayoutPPSFeePercent          *float64 `toml:"payout_pps_fee_percent"`
	PayoutPPLNSFeePercent        *float64 `toml:"payout_pplns_fee_percent"`
	PayoutSoloFeePercent         *float64 `toml:"payout_solo_fee_percent"`
	PayoutDonationPercent        *float64 `toml:"payout_donation_percent"`
	PayoutPPLNSShareMulti        *float64 `toml:"payout_pplns_share_multi"`

	RetentionPollIntervalSeconds *int   `toml:"retention_poll_interval_seconds"`
	RetentionBlocks              *int64 `toml:"retention_blocks"`

	MoneroWalletRPCAddr     *string `toml:"monero_wallet_rpc_addr"`
	MoneroWalletRPCUser     *string `toml:"monero_wallet_rpc_user"`
	MoneroWalletRPCPassword *string `toml:"monero_wallet_rpc_password"`

	WalletRPCTimeoutSeconds *int `toml:"wallet_rpc_timeout_seconds"`

	DisburseMinPayoutAtomic         *int64 `toml:"disburse_min_payout_atomic"`
	DisburseMaxDestinationsPerBatch *int   `toml:"disburse_max_destinations_per_batch"`
	DisbursePollIntervalSeconds     *int   `toml:"disburse_poll_interval_seconds"`
	ForcePayoutFeeAtomic            *int64 `toml:"force_payout_fee_atomic"`

	TariWalletGRPCAddr   *string `toml:"tari_wallet_grpc_addr"`
	TariWalletFeePerGram *uint64 `toml:"tari_wallet_fee_per_gram"`

	WalletStatsPollIntervalSeconds *int `toml:"wallet_stats_poll_interval_seconds"`

	JWTSecret *string `toml:"jwt_secret"`

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
		return fmt.Errorf("backend: loading -config %s: %w", cfg.configFile, err)
	}

	cfgfile.ApplyString(&cfg.dbDSN, fc.DBDSN, visited, "db-dsn", "GCPOOL_DB_DSN")
	cfgfile.ApplyString(&cfg.listenAddr, fc.ListenAddr, visited, "listen-addr", "GCPOOL_LISTEN_ADDR")
	cfgfile.ApplyString(&cfg.metricsListenAddr, fc.MetricsListenAddr, visited, "metrics-listen-addr", "GCPOOL_METRICS_LISTEN_ADDR")
	cfgfile.ApplyInt(&cfg.maxConnections, fc.MaxConnections, visited, "max-connections", "GCPOOL_MAX_CONNECTIONS")
	cfgfile.ApplyFloat64(&cfg.ingestionRateLimit, fc.IngestionRateLimit, visited, "ingestion-rate-limit", "GCPOOL_INGESTION_RATE_LIMIT")
	cfgfile.ApplyInt(&cfg.ingestionRateBurst, fc.IngestionRateBurst, visited, "ingestion-rate-burst", "GCPOOL_INGESTION_RATE_BURST")
	cfgfile.ApplyString(&cfg.authHeaderName, fc.AuthHeaderName, visited, "auth-header-name", "GCPOOL_AUTH_HEADER_NAME")
	cfgfile.ApplyString(&cfg.authHeaderValue, fc.AuthHeaderValue, visited, "auth-header-value", "GCPOOL_AUTH_HEADER_VALUE")
	cfgfile.ApplyString(&cfg.network, fc.Network, visited, "network", "GCPOOL_NETWORK")

	cfgfile.ApplyBool(&cfg.insecureAllowUnauthenticatedIngestion, fc.InsecureAllowUnauthenticatedIngestion, visited, "insecure-allow-unauthenticated-ingestion", "GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION")

	cfgfile.ApplyFloat64(&cfg.statsAPIRateLimitPerSecond, fc.StatsAPIRateLimitPerSecond, visited, "stats-api-rate-limit-per-second", "GCPOOL_STATS_API_RATE_LIMIT_PER_SECOND")
	cfgfile.ApplyInt(&cfg.statsAPIRateLimitBurst, fc.StatsAPIRateLimitBurst, visited, "stats-api-rate-limit-burst", "GCPOOL_STATS_API_RATE_LIMIT_BURST")

	cfgfile.ApplyString(&cfg.tariGRPCAddr, fc.TariGRPCAddr, visited, "tari-grpc-addr", "GCPOOL_TARI_GRPC_ADDR")
	cfgfile.ApplyString(&cfg.moneroRPCAddr, fc.MoneroRPCAddr, visited, "monero-rpc-addr", "GCPOOL_MONERO_RPC_ADDR")

	if fc.UnlockerPollIntervalSeconds != nil {
		d := time.Duration(*fc.UnlockerPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.unlockerPollInterval, &d, visited, "unlocker-poll-interval", "GCPOOL_UNLOCKER_POLL_INTERVAL")
	}
	cfgfile.ApplyInt64(&cfg.unlockerTariMaturity, fc.UnlockerTariMaturity, visited, "unlocker-tari-maturity", "GCPOOL_UNLOCKER_TARI_MATURITY")
	cfgfile.ApplyInt64(&cfg.unlockerMoneroMaturity, fc.UnlockerMoneroMaturity, visited, "unlocker-monero-maturity", "GCPOOL_UNLOCKER_MONERO_MATURITY")
	if fc.UnlockerStuckTimeoutSeconds != nil {
		d := time.Duration(*fc.UnlockerStuckTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.unlockerStuckTimeout, &d, visited, "unlocker-stuck-timeout", "GCPOOL_UNLOCKER_STUCK_TIMEOUT")
	}

	if fc.NetworkPollerPollIntervalSeconds != nil {
		d := time.Duration(*fc.NetworkPollerPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.networkPollerPollInterval, &d, visited, "network-poller-poll-interval", "GCPOOL_NETWORK_POLLER_POLL_INTERVAL")
	}

	cfgfile.ApplyString(&cfg.payoutTariFeeAddress, fc.PayoutTariFeeAddress, visited, "payout-tari-fee-address", "GCPOOL_PAYOUT_TARI_FEE_ADDRESS")
	cfgfile.ApplyString(&cfg.payoutMoneroFeeAddress, fc.PayoutMoneroFeeAddress, visited, "payout-monero-fee-address", "GCPOOL_PAYOUT_MONERO_FEE_ADDRESS")
	cfgfile.ApplyString(&cfg.payoutTariDonationAddress, fc.PayoutTariDonationAddress, visited, "payout-tari-donation-address", "GCPOOL_PAYOUT_TARI_DONATION_ADDRESS")
	cfgfile.ApplyString(&cfg.payoutMoneroDonationAddress, fc.PayoutMoneroDonationAddress, visited, "payout-monero-donation-address", "GCPOOL_PAYOUT_MONERO_DONATION_ADDRESS")
	cfgfile.ApplyString(&cfg.payoutExtraFeeAddressesRaw, fc.PayoutExtraFeeAddresses, visited, "payout-extra-fee-addresses", "GCPOOL_PAYOUT_EXTRA_FEE_ADDRESSES")
	cfgfile.ApplyString(&cfg.payoutExtraDonationAddressesRaw, fc.PayoutExtraDonationAddresses, visited, "payout-extra-donation-addresses", "GCPOOL_PAYOUT_EXTRA_DONATION_ADDRESSES")
	cfgfile.ApplyFloat64(&cfg.payoutPPSFeePercent, fc.PayoutPPSFeePercent, visited, "payout-pps-fee-percent", "GCPOOL_PAYOUT_PPS_FEE_PERCENT")
	cfgfile.ApplyFloat64(&cfg.payoutPPLNSFeePercent, fc.PayoutPPLNSFeePercent, visited, "payout-pplns-fee-percent", "GCPOOL_PAYOUT_PPLNS_FEE_PERCENT")
	cfgfile.ApplyFloat64(&cfg.payoutSoloFeePercent, fc.PayoutSoloFeePercent, visited, "payout-solo-fee-percent", "GCPOOL_PAYOUT_SOLO_FEE_PERCENT")
	cfgfile.ApplyFloat64(&cfg.payoutDonationPercent, fc.PayoutDonationPercent, visited, "payout-donation-percent", "GCPOOL_PAYOUT_DONATION_PERCENT")
	cfgfile.ApplyFloat64(&cfg.payoutPPLNSShareMulti, fc.PayoutPPLNSShareMulti, visited, "payout-pplns-share-multi", "GCPOOL_PAYOUT_PPLNS_SHARE_MULTI")

	if fc.RetentionPollIntervalSeconds != nil {
		d := time.Duration(*fc.RetentionPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.retentionPollInterval, &d, visited, "retention-poll-interval", "GCPOOL_RETENTION_POLL_INTERVAL")
	}
	cfgfile.ApplyInt64(&cfg.retentionBlocks, fc.RetentionBlocks, visited, "retention-blocks", "GCPOOL_RETENTION_BLOCKS")

	cfgfile.ApplyString(&cfg.moneroWalletRPCAddr, fc.MoneroWalletRPCAddr, visited, "monero-wallet-rpc-addr", "GCPOOL_MONERO_WALLET_RPC_ADDR")
	cfgfile.ApplyString(&cfg.moneroWalletRPCUser, fc.MoneroWalletRPCUser, visited, "monero-wallet-rpc-user", "GCPOOL_MONERO_WALLET_RPC_USER")
	cfgfile.ApplyString(&cfg.moneroWalletRPCPassword, fc.MoneroWalletRPCPassword, visited, "monero-wallet-rpc-password", "GCPOOL_MONERO_WALLET_RPC_PASSWORD")
	if fc.WalletRPCTimeoutSeconds != nil {
		d := time.Duration(*fc.WalletRPCTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.walletRPCTimeout, &d, visited, "wallet-rpc-timeout", "GCPOOL_WALLET_RPC_TIMEOUT")
	}
	cfgfile.ApplyInt64(&cfg.disburseMinPayoutAtomic, fc.DisburseMinPayoutAtomic, visited, "disburse-min-payout-atomic", "GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC")
	cfgfile.ApplyInt64(&cfg.forcePayoutFeeAtomic, fc.ForcePayoutFeeAtomic, visited, "force-payout-fee-atomic", "GCPOOL_FORCE_PAYOUT_FEE_ATOMIC")
	cfgfile.ApplyInt(&cfg.disburseMaxDestinationsPerBatch, fc.DisburseMaxDestinationsPerBatch, visited, "disburse-max-destinations-per-batch", "GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH")
	if fc.DisbursePollIntervalSeconds != nil {
		d := time.Duration(*fc.DisbursePollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.disbursePollInterval, &d, visited, "disburse-poll-interval", "GCPOOL_DISBURSE_POLL_INTERVAL")
	}

	cfgfile.ApplyString(&cfg.tariWalletGRPCAddr, fc.TariWalletGRPCAddr, visited, "tari-wallet-grpc-addr", "GCPOOL_TARI_WALLET_GRPC_ADDR")
	cfgfile.ApplyUint64(&cfg.tariWalletFeePerGram, fc.TariWalletFeePerGram, visited, "tari-wallet-fee-per-gram", "GCPOOL_TARI_WALLET_FEE_PER_GRAM")

	if fc.WalletStatsPollIntervalSeconds != nil {
		d := time.Duration(*fc.WalletStatsPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.walletStatsPollInterval, &d, visited, "wallet-stats-poll-interval", "GCPOOL_WALLET_STATS_POLL_INTERVAL")
	}

	cfgfile.ApplyString(&cfg.jwtSecret, fc.JWTSecret, visited, "jwt-secret", "GCPOOL_JWT_SECRET")

	cfgfile.ApplyBool(&cfg.debug, fc.Debug, visited, "debug", "GCPOOL_DEBUG")

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

func envOrInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// envOrInt64Checked mirrors envOrInt64 but, instead of silently
// falling back to def on a parse failure, returns a non-nil error
// describing exactly what failed to parse -- the fail-fast variant
// loadConfig's checkedInt64 closure uses for the specific
// money-critical env vars called out in PROD_HARDENING_REVIEW.md
// finding #9. def is still returned alongside the error so a caller
// that (incorrectly) ignored the error would see the same
// pre-existing default-fallback behavior, but loadConfig never does
// that -- it always surfaces the error.
func envOrInt64Checked(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def, fmt.Errorf("%s: invalid integer value %q: %w", key, v, err)
	}
	return n, nil
}

func envOrUint64(key string, def uint64) uint64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
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

// envOrDurationChecked mirrors envOrDuration but fails loudly instead
// of silently defaulting -- same rationale/callers as
// envOrInt64Checked above.
func envOrDurationChecked(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: invalid duration value %q: %w", key, v, err)
	}
	return d, nil
}

func envOrFloat64(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// parseNetwork parses the GCPOOL_NETWORK environment variable value
// into a poolpb.Network. Only "mainnet" and "testnet" (case-insensitive)
// are accepted; anything else (including empty string) is an error —
// there is deliberately no default value here.
func parseNetwork(raw string) (poolpb.Network, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "mainnet":
		return poolpb.Network_NETWORK_MAINNET, nil
	case "testnet":
		return poolpb.Network_NETWORK_TESTNET, nil
	default:
		return poolpb.Network_NETWORK_UNSPECIFIED, fmt.Errorf("GCPOOL_NETWORK: unrecognized value %q, want \"mainnet\" or \"testnet\"", raw)
	}
}

// networkDBString maps a poolpb.Network to the exact "MAINNET"/
// "TESTNET" string this schema's network columns/CHECK constraints
// use (see migrations/0001_initial_schema.up.sql) — deliberately
// separate from poolpb.Network's own generated String() method (which
// would render "NETWORK_MAINNET"/"NETWORK_TESTNET" instead), mirroring
// internal/backend/api's own private networkString helper since this
// command needs the identical mapping for payoutTrigger's network
// field but cannot import that unexported function.
func networkDBString(n poolpb.Network) string {
	switch n {
	case poolpb.Network_NETWORK_MAINNET:
		return "MAINNET"
	case poolpb.Network_NETWORK_TESTNET:
		return "TESTNET"
	default:
		return ""
	}
}

// repositoryAdapter adapts *db.Repository (whose InsertShare/InsertBlock
// operate on db.Share/db.Block) to api.ShareBlockRepository (which
// operates on api.ShareRecord/api.BlockRecord). This keeps
// internal/backend/api free of any dependency on internal/backend/db —
// this command is the only place the two packages need to meet.
type repositoryAdapter struct {
	repo *db.Repository
}

// InsertShare forwards to *db.Repository.InsertShare, translating a
// db.ErrAddressBanned (a banned payment address, see
// addressflags.go) into this command's own api.ErrAddressBanned
// sentinel so handleShare can map it to a 403 without
// internal/backend/api needing to import internal/backend/db
// directly -- see api.ErrAddressBanned's own doc comment for why
// this translation happens here, at the one place both packages
// meet, rather than either package reaching into the other's error
// types itself.
func (a repositoryAdapter) InsertShare(ctx context.Context, s api.ShareRecord, bucketSize int64) error {
	err := a.repo.InsertShare(ctx, db.Share{
		Algo:           s.Algo,
		Network:        s.Network,
		PoolType:       s.PoolType,
		PoolID:         s.PoolID,
		BlockHeight:    s.BlockHeight,
		Shares:         s.Shares,
		PaymentAddress: s.PaymentAddress,
		PaymentID:      s.PaymentID,
		FoundBlock:     s.FoundBlock,
		BlockDiff:      s.BlockDiff,
		Timestamp:      s.Timestamp,
		Identifier:     s.Identifier,
		TrustedShare:   s.TrustedShare,
	}, bucketSize)
	if err != nil && errors.Is(err, db.ErrAddressBanned) {
		return fmt.Errorf("%w: %v", api.ErrAddressBanned, err)
	}
	return err
}

func (a repositoryAdapter) InsertBlock(ctx context.Context, b api.BlockRecord) error {
	return a.repo.InsertBlock(ctx, db.Block{
		Algo:           b.Algo,
		Network:        b.Network,
		PoolType:       b.PoolType,
		Hash:           b.Hash,
		Height:         b.Height,
		Difficulty:     b.Difficulty,
		Shares:         b.Shares,
		Timestamp:      b.Timestamp,
		Unlocked:       b.Unlocked,
		Valid:          b.Valid,
		Value:          b.Value,
		PoolID:         b.PoolID,
		MergeMineChain: b.MergeMineChain,
	})
}

// statsRepositoryAdapter adapts *db.Repository (whose MinerBalances/
// ShareStatsSince/WorkerShareStatsSince operate on db.Balance/
// db.ShareStats/db.WorkerShareStats) to statsapi.Repository (which
// operates on statsapi.BalanceRecord/ShareStatsRecord/
// WorkerShareStatsRecord), mirroring repositoryAdapter's role above
// for the read-only miner stats API.
type statsRepositoryAdapter struct {
	repo *db.Repository
}

func (a statsRepositoryAdapter) MinerBalances(ctx context.Context, paymentAddress, algo, network string, paymentID *string) ([]statsapi.BalanceRecord, error) {
	rows, err := a.repo.MinerBalances(ctx, paymentAddress, algo, network, paymentID)
	if err != nil {
		return nil, err
	}
	out := make([]statsapi.BalanceRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, statsapi.BalanceRecord{
			Algo:           r.Algo,
			Network:        r.Network,
			PaymentAddress: r.PaymentAddress,
			PaymentID:      r.PaymentID,
			PendingBalance: r.PendingBalance,
			PaidBalance:    r.PaidBalance,
			UpdatedAt:      r.UpdatedAt,
		})
	}
	return out, nil
}

func (a statsRepositoryAdapter) ShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (statsapi.ShareStatsRecord, error) {
	s, err := a.repo.ShareStatsSince(ctx, algo, network, paymentAddress, paymentID, sinceUnix)
	if err != nil {
		return statsapi.ShareStatsRecord{}, err
	}
	return statsapi.ShareStatsRecord{SharesSum: s.SharesSum, ShareCount: s.ShareCount}, nil
}

func (a statsRepositoryAdapter) WorkerShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (statsapi.WorkerShareStatsResultRecord, error) {
	result, err := a.repo.WorkerShareStatsSince(ctx, algo, network, paymentAddress, paymentID, sinceUnix)
	if err != nil {
		return statsapi.WorkerShareStatsResultRecord{}, err
	}
	out := statsapi.WorkerShareStatsResultRecord{Rows: make([]statsapi.WorkerShareStatsRecord, 0, len(result.Rows))}
	for _, r := range result.Rows {
		out.Rows = append(out.Rows, statsapi.WorkerShareStatsRecord{
			Identifier: r.Identifier,
			SharesSum:  r.SharesSum,
			ShareCount: r.ShareCount,
		})
	}
	if result.Other != nil {
		out.Other = &statsapi.WorkerShareStatsOtherRecord{
			SharesSum:       result.Other.SharesSum,
			ShareCount:      result.Other.ShareCount,
			IdentifierCount: result.Other.IdentifierCount,
		}
	}
	return out, nil
}

// PoolSourceShareStatsSince adapts *db.Repository's
// PoolSourceShareStatsSince (which operates on db.PoolSourceShareStats)
// to statsapi.Repository's PoolSourceShareStatsSince (which operates
// on statsapi.PoolSourceShareStatsRecord), mirroring
// WorkerShareStatsSince's adapter above.
func (a statsRepositoryAdapter) PoolSourceShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (statsapi.PoolSourceShareStatsResultRecord, error) {
	result, err := a.repo.PoolSourceShareStatsSince(ctx, algo, network, paymentAddress, paymentID, sinceUnix)
	if err != nil {
		return statsapi.PoolSourceShareStatsResultRecord{}, err
	}
	out := statsapi.PoolSourceShareStatsResultRecord{Rows: make([]statsapi.PoolSourceShareStatsRecord, 0, len(result.Rows))}
	for _, r := range result.Rows {
		out.Rows = append(out.Rows, statsapi.PoolSourceShareStatsRecord{
			PoolID:     r.PoolID,
			SharesSum:  r.SharesSum,
			ShareCount: r.ShareCount,
		})
	}
	if result.Other != nil {
		out.Other = &statsapi.PoolSourceShareStatsOtherRecord{
			SharesSum:   result.Other.SharesSum,
			ShareCount:  result.Other.ShareCount,
			PoolIDCount: result.Other.PoolIDCount,
		}
	}
	return out, nil
}

// addressMapRepositoryAdapter adapts *db.Repository (whose
// SetAddressMap/GetAddressMap operate on db.AddressMap) to
// addressmap.Repository (which operates on addressmap.Record),
// mirroring statsRepositoryAdapter's role above for the SXMR
// merge-mining XMR-to-Tari address mapping API.
type addressMapRepositoryAdapter struct {
	repo *db.Repository
}

func (a addressMapRepositoryAdapter) Set(ctx context.Context, xmrAddress, tariAddress string) error {
	err := a.repo.SetAddressMap(ctx, xmrAddress, tariAddress)
	if err != nil && errors.Is(err, db.ErrAddressAlreadyMapped) {
		return addressmap.ErrAlreadyMapped
	}
	return err
}

func (a addressMapRepositoryAdapter) Get(ctx context.Context, xmrAddress string) (addressmap.Record, error) {
	m, err := a.repo.GetAddressMap(ctx, xmrAddress)
	if err != nil {
		if errors.Is(err, db.ErrAddressMapNotFound) {
			return addressmap.Record{}, addressmap.ErrNotFound
		}
		return addressmap.Record{}, err
	}
	return addressmap.Record{
		XMRAddress:  m.XMRAddress,
		TariAddress: m.TariAddress,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}, nil
}

// authRepositoryAdapter adapts *db.Repository (whose
// GetUserByUsername/GetUserByID/UpdateUserPassword/
// ToggleUserEnableEmail/ToggleUserEnableEmailByUsername/
// UpdateUserPayoutThreshold/UpdateUserThreshold/SetForcePayout
// operate on db.User) to authapi.Repository (which operates on
// authapi.User), mirroring addressMapRepositoryAdapter's role above
// for the SXMR-legacy authentication/account-settings API.
type authRepositoryAdapter struct {
	repo *db.Repository
}

func dbUserToAuthUser(u db.User) authapi.User {
	return authapi.User{
		ID:              u.ID,
		Username:        u.Username,
		Email:           u.Email,
		Pass:            u.Pass,
		Admin:           u.Admin,
		EnableEmail:     u.EnableEmail,
		PayoutThreshold: u.PayoutThreshold,
	}
}

func (a authRepositoryAdapter) GetUserByUsername(ctx context.Context, username string) (authapi.User, error) {
	u, err := a.repo.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return authapi.User{}, authapi.ErrUserNotFound
		}
		return authapi.User{}, err
	}
	return dbUserToAuthUser(u), nil
}

func (a authRepositoryAdapter) GetUserByID(ctx context.Context, id int64) (authapi.User, error) {
	u, err := a.repo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return authapi.User{}, authapi.ErrUserNotFound
		}
		return authapi.User{}, err
	}
	return dbUserToAuthUser(u), nil
}

func (a authRepositoryAdapter) UpdateUserPassword(ctx context.Context, id int64, passHash string) error {
	return a.repo.UpdateUserPassword(ctx, id, passHash)
}

func (a authRepositoryAdapter) ToggleUserEnableEmail(ctx context.Context, id int64) error {
	return a.repo.ToggleUserEnableEmail(ctx, id)
}

func (a authRepositoryAdapter) ToggleUserEnableEmailByUsername(ctx context.Context, username string) error {
	return a.repo.ToggleUserEnableEmailByUsername(ctx, username)
}

func (a authRepositoryAdapter) UpdateUserPayoutThreshold(ctx context.Context, id int64, threshold int64) error {
	return a.repo.UpdateUserPayoutThreshold(ctx, id, threshold)
}

func (a authRepositoryAdapter) UpdateUserThreshold(ctx context.Context, username string, threshold int64) error {
	err := a.repo.UpdateUserThreshold(ctx, username, threshold)
	if err != nil && errors.Is(err, db.ErrUserNotFound) {
		return authapi.ErrUserNotFound
	}
	return err
}

func (a authRepositoryAdapter) SetForcePayout(ctx context.Context, algo, network, paymentAddress string, paymentID *string) error {
	err := a.repo.SetForcePayout(ctx, algo, network, paymentAddress, paymentID)
	if err != nil && errors.Is(err, db.ErrBalanceNotFound) {
		return authapi.ErrBalanceNotFound
	}
	return err
}

// legacyConfigRepositoryAdapter adapts *db.Repository (whose
// LatestMotd operates on db.Motd) to legacyconfig.Repository (which
// operates on legacyconfig.MotdRecord), mirroring
// authRepositoryAdapter's role above for the SXMR-legacy GET
// /pool/motd endpoint.
type legacyConfigRepositoryAdapter struct {
	repo *db.Repository
}

func (a legacyConfigRepositoryAdapter) LatestMotd(ctx context.Context) (legacyconfig.MotdRecord, error) {
	m, err := a.repo.LatestMotd(ctx)
	if err != nil {
		if errors.Is(err, db.ErrMotdNotFound) {
			return legacyconfig.MotdRecord{}, legacyconfig.ErrMotdNotFound
		}
		return legacyconfig.MotdRecord{}, err
	}
	return legacyconfig.MotdRecord{
		Created: m.Created,
		Subject: m.Subject,
		Body:    m.Body,
		Type:    m.Type,
		Active:  m.Active,
	}, nil
}

// networkAPIRepositoryAdapter adapts *db.Repository (whose
// ListPools/NetworkStatsSince operate on db.Pool/db.NetworkStats) to
// networkapi.Repository (which operates on networkapi.PoolRecord/
// networkapi.NetworkStatsRecord), mirroring statsRepositoryAdapter's
// role above for the public pool-wide network/topology API.
type networkAPIRepositoryAdapter struct {
	repo *db.Repository
}

func (a networkAPIRepositoryAdapter) ListPools(ctx context.Context, algo, network string) ([]networkapi.PoolRecord, error) {
	rows, err := a.repo.ListPools(ctx, algo, network)
	if err != nil {
		return nil, err
	}
	out := make([]networkapi.PoolRecord, 0, len(rows))
	for _, p := range rows {
		ports := make([]networkapi.PortRecord, 0, len(p.Ports))
		for _, pt := range p.Ports {
			ports = append(ports, networkapi.PortRecord{
				Port:            pt.Port,
				Description:     pt.Description,
				MinDifficulty:   pt.MinDifficulty,
				MaxDifficulty:   pt.MaxDifficulty,
				StartDifficulty: pt.StartDifficulty,
				VariableDiff:    pt.VariableDiff,
			})
		}
		out = append(out, networkapi.PoolRecord{
			Algo:      p.Algo,
			Network:   p.Network,
			PoolType:  p.PoolType,
			Name:      p.Name,
			Enabled:   p.Enabled,
			CreatedAt: p.CreatedAt,
			Ports:     ports,
		})
	}
	return out, nil
}

func (a networkAPIRepositoryAdapter) NetworkStatsSince(ctx context.Context, algo, network string, sinceUnix int64) (networkapi.NetworkStatsRecord, error) {
	s, err := a.repo.NetworkStatsSince(ctx, algo, network, sinceUnix)
	if err != nil {
		return networkapi.NetworkStatsRecord{}, err
	}
	return networkapi.NetworkStatsRecord{
		SharesSum:                  s.SharesSum,
		ShareCount:                 s.ShareCount,
		BlocksFound:                s.BlocksFound,
		LastBlockAt:                s.LastBlockAt,
		LastBlockHeight:            s.LastBlockHeight,
		NetworkHeight:              s.NetworkHeight,
		NetworkDifficulty:          s.NetworkDifficulty,
		NetworkEstimatedHashrateHS: s.NetworkEstimatedHashrateHS,
		NetworkStateUpdatedAt:      s.NetworkStateUpdatedAt,
	}, nil
}

// networkPollerRepositoryAdapter adapts *db.Repository (whose
// UpsertNetworkState operates on db.NetworkState) to
// networkpoller.Repository (which operates on
// networkpoller.RepoState), mirroring networkAPIRepositoryAdapter's
// role above for the write side of the same network_state table --
// see internal/backend/networkpoller's package doc comment for how
// this differs in direction from networkAPIRepositoryAdapter (writes
// the real, live upstream chain-state snapshot vs. reads it back out
// for networkapi's HTTP surface).
type networkPollerRepositoryAdapter struct {
	repo *db.Repository
}

func (a networkPollerRepositoryAdapter) UpsertNetworkState(ctx context.Context, algo, network string, state networkpoller.RepoState) error {
	return a.repo.UpsertNetworkState(ctx, algo, network, db.NetworkState{
		Height:              state.Height,
		Difficulty:          state.Difficulty,
		EstimatedHashrateHS: state.EstimatedHashrateHS,
		BestBlockHash:       state.BestBlockHash,
		Source:              state.Source,
		PolledAt:            state.PolledAt,
	})
}

// leafFlagsRepositoryAdapter adapts *db.Repository (whose
// ListAddressFlags operates on db.AddressFlag) to
// leafflagsapi.Repository (which operates on leafflagsapi.Flag — a
// deliberately narrower, leaf-facing projection with no audit
// metadata; see that package's doc comment for why), mirroring
// networkAPIRepositoryAdapter's role above for the real, read-only
// GET /api/v1/leaf/address-flags endpoint leaf-direct polls (see
// internal/leaflib/addressflags.HTTPSource).
type leafFlagsRepositoryAdapter struct {
	repo *db.Repository
}

func (a leafFlagsRepositoryAdapter) ListActiveAddressFlags(ctx context.Context) ([]leafflagsapi.Flag, error) {
	rows, err := a.repo.ListAddressFlags(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]leafflagsapi.Flag, 0, len(rows))
	for _, f := range rows {
		out = append(out, leafflagsapi.Flag{
			PaymentAddress:      f.PaymentAddress,
			Banned:              f.Banned,
			ForcedMinDifficulty: f.ForcedMinDifficulty,
		})
	}
	return out, nil
}

// legacyBlocksRepositoryAdapter adapts *db.Repository (whose
// ListBlocks operates on db.Block) to legacyapi.BlocksRepository
// (which operates on legacyapi.BlockRecord), mirroring
// networkAPIRepositoryAdapter's role above for the SXMR-legacy-shaped
// GET /pool/blocks[/:pool_type] wrapper route.
type legacyBlocksRepositoryAdapter struct {
	repo *db.Repository
}

func (a legacyBlocksRepositoryAdapter) ListBlocks(ctx context.Context, algo, network, poolType string, limit, offset int) ([]legacyapi.BlockRecord, error) {
	rows, err := a.repo.ListBlocks(ctx, algo, network, poolType, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]legacyapi.BlockRecord, 0, len(rows))
	for _, b := range rows {
		out = append(out, legacyapi.BlockRecord{
			Algo:       b.Algo,
			Network:    b.Network,
			PoolType:   b.PoolType,
			Hash:       b.Hash,
			Height:     b.Height,
			Difficulty: b.Difficulty,
			Shares:     b.Shares,
			Timestamp:  b.Timestamp,
			Unlocked:   b.Unlocked,
			Valid:      b.Valid,
			Value:      b.Value,
		})
	}
	return out, nil
}

// legacyPayoutsRepositoryAdapter adapts *db.Repository (whose
// ListPayouts operates on db.Payout) to legacyapi.PayoutsRepository
// (which operates on legacyapi.PayoutRecord), mirroring
// legacyBlocksRepositoryAdapter's role above for the SXMR-legacy-
// shaped GET /pool/payments[/:pool_type] and
// GET /miner/:address/payments wrapper routes.
type legacyPayoutsRepositoryAdapter struct {
	repo *db.Repository
}

func (a legacyPayoutsRepositoryAdapter) ListPayouts(ctx context.Context, algo, network string, paymentAddress *string, limit, offset int) ([]legacyapi.PayoutRecord, int64, error) {
	rows, total, err := a.repo.ListPayouts(ctx, algo, network, paymentAddress, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	out := make([]legacyapi.PayoutRecord, 0, len(rows))
	for _, p := range rows {
		out = append(out, legacyapi.PayoutRecord{
			ID:          p.ID,
			Status:      p.Status,
			BalanceIDs:  p.BalanceIDs,
			Amount:      p.Amount,
			Fee:         p.Fee,
			TxHash:      p.TxHash,
			CompletedAt: p.CompletedAt,
		})
	}
	return out, total, nil
}

// legacyIdentifiersRepositoryAdapter adapts *db.Repository (whose
// MinerIdentifiersSince operates on db.MinerIdentifier) to
// legacyapi.IdentifiersRepository (which operates on
// legacyapi.IdentifierRecord), mirroring legacyBlocksRepositoryAdapter's
// role above for the SXMR-legacy-shaped GET /miner/:address/identifiers
// route and the allWorkers stats/chart shapes.
type legacyIdentifiersRepositoryAdapter struct {
	repo *db.Repository
}

func (a legacyIdentifiersRepositoryAdapter) MinerIdentifiersSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]legacyapi.IdentifierRecord, error) {
	rows, err := a.repo.MinerIdentifiersSince(ctx, algo, network, paymentAddress, paymentID, sinceUnix)
	if err != nil {
		return nil, err
	}
	out := make([]legacyapi.IdentifierRecord, 0, len(rows))
	for _, m := range rows {
		out = append(out, legacyapi.IdentifierRecord{
			WorkerName: m.WorkerName,
			LastShare:  m.LastShare,
		})
	}
	return out, nil
}

// unlockerRepositoryAdapter adapts *db.Repository (whose
// PendingBlocks/SetBlockStatus operate on db.PendingBlock) to
// unlocker.Repository (which operates on unlocker.Block), mirroring
// repositoryAdapter's role above for the ingestion side — see
// unlocker.Repository's doc comment for why this indirection exists.
type unlockerRepositoryAdapter struct {
	repo *db.Repository
}

func (a unlockerRepositoryAdapter) PendingBlocks(ctx context.Context, algo string) ([]unlocker.Block, error) {
	rows, err := a.repo.PendingBlocks(ctx, algo)
	if err != nil {
		return nil, err
	}
	out := make([]unlocker.Block, 0, len(rows))
	for _, r := range rows {
		out = append(out, unlocker.Block{
			ID:             r.ID,
			Algo:           r.Algo,
			Network:        r.Network,
			Hash:           r.Hash,
			Height:         r.Height,
			PoolType:       r.PoolType,
			Difficulty:     r.Difficulty,
			Value:          r.Value,
			InsertedAt:     r.InsertedAt,
			MergeMineChain: r.MergeMineChain,
		})
	}
	return out, nil
}

func (a unlockerRepositoryAdapter) SetBlockStatus(ctx context.Context, id int64, valid, unlocked bool) error {
	return a.repo.SetBlockStatus(ctx, id, valid, unlocked)
}

// payoutRepositoryAdapter adapts *db.Repository (whose SharesAtHeight/
// SoloShare/ApplyBlockPayout operate on db.PayoutShare/
// db.BlockPayoutRun) to payout.Repository (which operates on
// payout.ShareRow/payout.BlockPayoutRun), mirroring
// repositoryAdapter/unlockerRepositoryAdapter's role above.
type payoutRepositoryAdapter struct {
	repo *db.Repository
}

func (a payoutRepositoryAdapter) SharesAtHeight(ctx context.Context, algo, poolType string, height int64) ([]payout.ShareRow, error) {
	rows, err := a.repo.SharesAtHeight(ctx, algo, poolType, height)
	if err != nil {
		return nil, err
	}
	out := make([]payout.ShareRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, payout.ShareRow{
			Shares:         r.Shares,
			PaymentAddress: r.PaymentAddress,
			PaymentID:      r.PaymentID,
		})
	}
	return out, nil
}

func (a payoutRepositoryAdapter) SoloShare(ctx context.Context, algo string, height int64) (payout.ShareRow, bool, error) {
	r, found, err := a.repo.SoloShare(ctx, algo, height)
	if err != nil {
		return payout.ShareRow{}, false, err
	}
	return payout.ShareRow{
		Shares:         r.Shares,
		PaymentAddress: r.PaymentAddress,
		PaymentID:      r.PaymentID,
	}, found, nil
}

// ApplyBlockPayout hands one whole matured-block payout run to
// db.Repository.ApplyBlockPayout's single transaction. Note there is
// deliberately no CreditBalance passthrough on this adapter any more:
// payout.Repository no longer exposes a per-payee credit call at all,
// because a credit outside a claimed, all-or-nothing block run is the
// money bug migrations/0013_block_payouts.up.sql exists to close.
func (a payoutRepositoryAdapter) ApplyBlockPayout(ctx context.Context, run payout.BlockPayoutRun) (payout.BlockPayoutOutcome, error) {
	credits := make([]db.BlockCredit, 0, len(run.Credits))
	for _, c := range run.Credits {
		credits = append(credits, db.BlockCredit{
			PayoutBucket:   c.PayoutBucket,
			PaymentAddress: c.PaymentAddress,
			PaymentID:      c.PaymentID,
			Amount:         c.Amount,
		})
	}
	out, err := a.repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
		BlockID:  run.BlockID,
		Algo:     run.Algo,
		Network:  run.Network,
		PoolType: run.PoolType,
		Height:   run.Height,
		Reward:   run.Reward,
		Credits:  credits,
	})
	if err != nil {
		return payout.BlockPayoutOutcome{}, err
	}
	return payout.BlockPayoutOutcome{
		AlreadyApplied: out.AlreadyApplied,
		TotalPaid:      out.TotalPaid,
		Credited:       out.Credited,
	}, nil
}

// disburseRepositoryAdapter adapts *db.Repository (whose
// PayableBalances/UnresolvedPayouts/RecordPendingPayout/
// CompletePayoutSent/FailPayout/MarkPayoutAmbiguous operate on
// db.PayableBalance/db.DisburseEntry/db.UnresolvedPayout) to
// disburse.Repository (which operates on disburse.PayableBalance/
// disburse.DebitEntry/disburse.UnresolvedPayout), mirroring
// payoutRepositoryAdapter's role above.
type disburseRepositoryAdapter struct {
	repo *db.Repository
}

func (a disburseRepositoryAdapter) PayableBalances(ctx context.Context, algo, network, currency string, minPayout int64) ([]disburse.PayableBalance, error) {
	rows, err := a.repo.PayableBalances(ctx, algo, network, currency, minPayout)
	if err != nil {
		return nil, err
	}
	out := make([]disburse.PayableBalance, 0, len(rows))
	for _, r := range rows {
		out = append(out, disburse.PayableBalance{
			ID:             r.ID,
			PaymentAddress: r.PaymentAddress,
			PaymentID:      r.PaymentID,
			PendingBalance: r.PendingBalance,
			ForcePayout:    r.ForcePayout,
		})
	}
	return out, nil
}

func (a disburseRepositoryAdapter) UnresolvedPayouts(ctx context.Context, algo, network, currency string) ([]disburse.UnresolvedPayout, error) {
	rows, err := a.repo.UnresolvedPayouts(ctx, algo, network, currency)
	if err != nil {
		return nil, err
	}
	out := make([]disburse.UnresolvedPayout, 0, len(rows))
	for _, r := range rows {
		out = append(out, disburse.UnresolvedPayout{
			ID:         r.ID,
			Status:     r.Status,
			Amount:     r.Amount,
			BalanceIDs: r.BalanceIDs,
			TxHash:     derefString(r.TxHash),
			Error:      derefString(r.Error),
			Created:    r.CreatedAt,
		})
	}
	return out, nil
}

// derefString flattens a *string column (payouts.tx_hash/error are
// both nullable) to a plain string for the disburse package's own
// non-pointer UnresolvedPayout fields -- those are log/report-only
// there, where "" and NULL are equivalent, so carrying the pointer
// through would add a nil check at every use site for no gain.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (a disburseRepositoryAdapter) RecordPendingPayout(ctx context.Context, algo, network, currency string, entries []disburse.DebitEntry, amount int64) (int64, error) {
	return a.repo.RecordPendingPayout(ctx, algo, network, currency, disburseEntriesToDB(entries), amount)
}

func (a disburseRepositoryAdapter) CompletePayoutSent(ctx context.Context, payoutID int64, entries []disburse.DebitEntry, txHash string, fee int64) error {
	return a.repo.CompletePayoutSent(ctx, payoutID, disburseEntriesToDB(entries), txHash, fee)
}

func (a disburseRepositoryAdapter) FailPayout(ctx context.Context, payoutID int64, errMsg string) error {
	return a.repo.FailPayout(ctx, payoutID, errMsg)
}

func (a disburseRepositoryAdapter) MarkPayoutAmbiguous(ctx context.Context, payoutID int64, txHash, errMsg string) error {
	return a.repo.MarkPayoutAmbiguous(ctx, payoutID, txHash, errMsg)
}

// disburseEntriesToDB converts disburse.DebitEntry to db.DisburseEntry
// -- shared by RecordPendingPayout and CompletePayoutSent above,
// which deliberately persist the IDENTICAL entry set (the pre-attempt
// record and the post-success debit must never disagree, see
// disburse.runBatch).
func disburseEntriesToDB(entries []disburse.DebitEntry) []db.DisburseEntry {
	out := make([]db.DisburseEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, db.DisburseEntry{
			BalanceID:            e.BalanceID,
			Amount:               e.Amount,
			ForcePayout:          e.ForcePayout,
			ForcePayoutFeeAtomic: e.ForcePayoutFeeAtomic,
		})
	}
	return out
}

// retentionRepositoryAdapter adapts a raw *pgxpool.Pool (rather than
// *db.Repository) to retention.Repository, since db.ListHeightPartitions/
// db.DropOldPartitions are free functions taking a pool directly, not
// db.Repository methods (see internal/backend/db/partition.go) —
// unlike unlockerRepositoryAdapter/disburseRepositoryAdapter above,
// which wrap *db.Repository methods.
type retentionRepositoryAdapter struct {
	pool *pgxpool.Pool
}

func (a retentionRepositoryAdapter) ListHeightPartitions(ctx context.Context, algo, poolType string) ([]retention.HeightPartition, error) {
	rows, err := db.ListHeightPartitions(ctx, a.pool, algo, poolType)
	if err != nil {
		return nil, err
	}
	out := make([]retention.HeightPartition, 0, len(rows))
	for _, r := range rows {
		out = append(out, retention.HeightPartition{Name: r.Name, RangeStart: r.RangeStart, RangeEnd: r.RangeEnd})
	}
	return out, nil
}

func (a retentionRepositoryAdapter) DropOldPartitions(ctx context.Context, algo, poolType string, belowHeight int64) ([]string, []retention.SkippedPartition, error) {
	dropped, skipped, err := db.DropOldPartitions(ctx, a.pool, algo, poolType, belowHeight)
	if err != nil {
		return nil, nil, err
	}
	out := make([]retention.SkippedPartition, 0, len(skipped))
	for _, s := range skipped {
		out = append(out, retention.SkippedPartition{
			Name:        s.Name,
			RangeStart:  s.RangeStart,
			RangeEnd:    s.RangeEnd,
			BlockID:     s.BlockID,
			BlockHeight: s.BlockHeight,
		})
	}
	return dropped, out, nil
}

// payoutTrigger adapts a *payout.Calculator into unlocker.PayoutTrigger
// — the concrete implementation the unlocker's Config.PayoutTrigger
// field is set to in production (see buildPayoutCalculator/run()
// below). network is fixed at construction time (this backend's own
// configured network — see GCPOOL_NETWORK), matching every other
// network-scoped write path in this command.
//
// b.ID (the real `blocks.id`) is passed straight through as the
// payout run's idempotency key — see payout.MaturedBlock and
// migrations/0013_block_payouts.up.sql. An AlreadyApplied result is
// NOT an error: it is the expected outcome when the unlocker retries
// a block whose payout committed but whose status write did not, and
// returning nil here is what lets that retry finally mark the block
// unlocked.
type payoutTrigger struct {
	calc    *payout.Calculator
	network string
}

func (t payoutTrigger) TriggerPayout(ctx context.Context, b unlocker.Block) error {
	result, err := t.calc.RunForMaturedBlock(ctx, b.ID, b.Algo, t.network, b.PoolType, b.Height, b.Difficulty, b.Value)
	if err != nil {
		return err
	}
	if result.AlreadyApplied {
		log.Printf("backend: payout for block id=%d (%s/%s height=%d) was ALREADY applied (%d entries, %d atomic units) — credited nothing this time, as intended",
			b.ID, b.Algo, b.PoolType, b.Height, result.Credited, result.TotalPaid)
	}
	return nil
}

// tariAlgos is every algo string mined against a Tari base node —
// mirrors internal/leaflib/solo/node.go's tariPowAlgo grouping exactly
// (SHA3X, C29, RXT all speak to the same base node GRPC surface; only
// RXM is Monero).
var tariAlgos = []string{"RXT", "C29", "SHA3X"}

// buildUnlockerConfig reads cfg's tariGRPCAddr/moneroRPCAddr/
// unlocker* fields (see this file's package doc comment for the
// underlying GCPOOL_TARI_GRPC_ADDR/GCPOOL_MONERO_RPC_ADDR/
// GCPOOL_UNLOCKER_* env vars) and returns a ready-to-use
// unlocker.Config plus whether any verifier was actually configured
// (ok == false means the caller should not start the unlocker at all
// — see run()).
func buildUnlockerConfig(cfg config, debug *leaflib.DebugLogger) (out unlocker.Config, ok bool, err error) {
	out.Coins = map[string]unlocker.CoinConfig{}
	out.MergeMineChainVerifiers = map[string]unlocker.CoinConfig{}
	out.PollInterval = cfg.unlockerPollInterval
	out.StuckTimeout = cfg.unlockerStuckTimeout
	out.Debug = debug

	if cfg.tariGRPCAddr != "" {
		verifier, err := chain.NewTariVerifier(cfg.tariGRPCAddr)
		if err != nil {
			return out, false, fmt.Errorf("connecting to Tari base node GRPC at %s: %w", cfg.tariGRPCAddr, err)
		}
		for _, algo := range tariAlgos {
			out.Coins[algo] = unlocker.CoinConfig{Verifier: verifier, MaturityDepth: cfg.unlockerTariMaturity}
		}
		// The SAME Tari base node GRPC verifier ALSO covers ALGO_RXM
		// blocks rows whose merge_mine_chain is "TARI" -- the
		// secondary, merge-mined-chain leg of an RXM find (see
		// internal/proto.Block.merge_mine_chain's doc comment and
		// internal/backend/unlocker's merge_mine_chain-keyed
		// dispatch). This is genuinely the SAME chain/verifier the
		// tariAlgos loop above already configures for RXT/C29/SHA3X
		// -- a Tari block is a Tari block regardless of which algo's
		// leaf happened to submit it.
		out.MergeMineChainVerifiers["TARI"] = unlocker.CoinConfig{Verifier: verifier, MaturityDepth: cfg.unlockerTariMaturity}
		ok = true
	}

	if cfg.moneroRPCAddr != "" {
		out.Coins["RXM"] = unlocker.CoinConfig{Verifier: chain.NewMoneroVerifier(cfg.moneroRPCAddr), MaturityDepth: cfg.unlockerMoneroMaturity}
		ok = true
	}

	return out, ok, nil
}

// sortedKeys returns m's keys sorted, purely for deterministic,
// readable startup log output (buildUnlockerConfig's map iteration
// order is otherwise unspecified).
func sortedKeys(m map[string]unlocker.CoinConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildNetworkPollerConfig reads the same cfg.tariGRPCAddr/
// cfg.moneroRPCAddr fields buildUnlockerConfig consumes (see this
// file's package doc comment) plus the poller-specific
// cfg.networkPollerPollInterval, and returns a ready-to-use
// networkpoller.Config plus whether any real upstream Source was
// actually configured (ok == false means the caller should not start
// the poller at all -- mirrors buildUnlockerConfig's own opt-in
// story exactly).
//
// Deliberately does NOT call nodeGRPC.InitNodeGRPC itself: when
// cfg.tariGRPCAddr is set, buildUnlockerConfig's own
// chain.NewTariVerifier call already does so exactly once (see
// networkpoller.TariNetworkSource's doc comment for why only one
// InitNodeGRPC call's worth of address should be live per process),
// and run() below only calls this function after buildUnlockerConfig
// has already run.
func buildNetworkPollerConfig(cfg config, network poolpb.Network, m *metrics.Metrics, debug *leaflib.DebugLogger) (out networkpoller.Config, ok bool, err error) {
	out.PollInterval = cfg.networkPollerPollInterval
	out.Debug = debug
	out.Metrics = m

	netStr := networkDBString(network)

	if cfg.tariGRPCAddr != "" {
		out.Targets = append(out.Targets,
			networkpoller.Target{Algo: "RXT", Network: netStr, Source: networkpoller.NewTariNetworkSource(networkpoller.TariAlgoRandomX)},
			networkpoller.Target{Algo: "C29", Network: netStr, Source: networkpoller.NewTariNetworkSource(networkpoller.TariAlgoCuckaroo)},
			networkpoller.Target{Algo: "SHA3X", Network: netStr, Source: networkpoller.NewTariNetworkSource(networkpoller.TariAlgoSHA3X)},
		)
		ok = true
	}

	if cfg.moneroRPCAddr != "" {
		out.Targets = append(out.Targets, networkpoller.Target{Algo: "RXM", Network: netStr, Source: networkpoller.NewMoneroNetworkSource(cfg.moneroRPCAddr)})
		ok = true
	}

	return out, ok, nil
}

// buildPayoutCalculator reads cfg's payout* fields (see this file's
// package doc comment for the underlying GCPOOL_PAYOUT_* env vars)
// and returns a ready-to-use *payout.Calculator plus whether payout
// calculation should actually be wired into the unlocker's
// matured-block trigger (ok == false when NEITHER
// cfg.payoutTariFeeAddress NOR cfg.payoutMoneroFeeAddress is set — a
// deployment that hasn't configured any fee address yet gets correct
// chain-maturity tracking out of the unlocker alone, exactly
// mirroring buildUnlockerConfig's own opt-in story for
// cfg.tariGRPCAddr/cfg.moneroRPCAddr). A deployment may enable only
// one coin family (e.g. Tari-only) by setting just that family's fee
// address; the payout.Calculator itself refuses (via
// payout.addressesForAlgo) to process an algo whose family's fee
// address was never configured.
//
//	GCPOOL_PAYOUT_TARI_FEE_ADDRESS   (required to enable Tari-family
//	                                 payout) pool operator
//	                                 fee-collection address for
//	                                 RXT/C29/SHA3X.
//	GCPOOL_PAYOUT_MONERO_FEE_ADDRESS (required to enable Monero
//	                                 payout) pool operator
//	                                 fee-collection address for RXM.
//	GCPOOL_PAYOUT_TARI_DONATION_ADDRESS,
//	GCPOOL_PAYOUT_MONERO_DONATION_ADDRESS (optional) per-coin-family
//	                                 donation addresses.
//	GCPOOL_PAYOUT_PPS_FEE_PERCENT, GCPOOL_PAYOUT_PPLNS_FEE_PERCENT,
//	GCPOOL_PAYOUT_SOLO_FEE_PERCENT (optional) per-pool-type operator
//	                                fee percentage (0-100). Default 0.
//	GCPOOL_PAYOUT_DONATION_PERCENT  (optional) donation split
//	                                percentage (0-100) of each fee
//	                                cut, shared across coin families.
//	                                Default 0 (no donation split).
//	GCPOOL_PAYOUT_PPLNS_SHARE_MULTI (optional) PPLNS window multiplier.
//	                                Default 2 (a placeholder, operator-
//	                                tunable value — see payout.Config's
//	                                doc comment).
func buildPayoutCalculator(cfg config, repo *db.Repository, m *metrics.Metrics) (calc *payout.Calculator, ok bool, err error) {
	extraFee, err := parseExtraCoinAddresses(cfg.payoutExtraFeeAddressesRaw, "-payout-extra-fee-addresses/GCPOOL_PAYOUT_EXTRA_FEE_ADDRESSES")
	if err != nil {
		return nil, false, err
	}
	extraDonation, err := parseExtraCoinAddresses(cfg.payoutExtraDonationAddressesRaw, "-payout-extra-donation-addresses/GCPOOL_PAYOUT_EXTRA_DONATION_ADDRESSES")
	if err != nil {
		return nil, false, err
	}

	if strings.TrimSpace(cfg.payoutTariFeeAddress) == "" && strings.TrimSpace(cfg.payoutMoneroFeeAddress) == "" && len(extraFee) == 0 {
		return nil, false, nil
	}

	if err := validateDonationConfig(cfg, extraFee, extraDonation); err != nil {
		return nil, false, err
	}

	pcfg := payout.Config{
		TariFeeAddress:         cfg.payoutTariFeeAddress,
		MoneroFeeAddress:       cfg.payoutMoneroFeeAddress,
		TariDonationAddress:    cfg.payoutTariDonationAddress,
		MoneroDonationAddress:  cfg.payoutMoneroDonationAddress,
		ExtraFeeAddresses:      extraFee,
		ExtraDonationAddresses: extraDonation,
		PPSFeePercent:          cfg.payoutPPSFeePercent,
		PPLNSFeePercent:        cfg.payoutPPLNSFeePercent,
		SoloFeePercent:         cfg.payoutSoloFeePercent,
		DonationPercent:        cfg.payoutDonationPercent,
		PPLNSShareMulti:        cfg.payoutPPLNSShareMulti,
		Metrics:                m,
	}

	return payout.New(payoutRepositoryAdapter{repo: repo}, pcfg), true, nil
}

// parseExtraCoinAddresses parses raw ("TICKER=address,TICKER2=address2")
// into a map keyed by that coin's exact uppercase algo string (e.g.
// "ARQ") -- see payout.Config.ExtraFeeAddresses's doc comment. Fails
// fast (a real error, never a silently-skipped entry) on a malformed
// entry, an unregistered ticker, or an address that does not validate
// against that coin's own internal/coinprofile.CoinProfile -- a
// misconfigured payout address here would misroute real funds, not
// just misfile a log line. An empty/whitespace-only raw string (the
// default) returns a nil map -- no extra coins configured, matching
// every other optional-flag convention in this codebase.
func parseExtraCoinAddresses(raw, flagLabel string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s: entry %q is not TICKER=address", flagLabel, entry)
		}
		ticker := strings.TrimSpace(parts[0])
		address := strings.TrimSpace(parts[1])
		if ticker == "" || address == "" {
			return nil, fmt.Errorf("%s: entry %q has an empty ticker or address", flagLabel, entry)
		}
		profile, ok := coinprofile.Lookup(ticker)
		if !ok {
			return nil, fmt.Errorf("%s: entry %q: unknown/unregistered coin ticker %q -- see internal/coinprofile.Registry for supported tickers", flagLabel, entry, ticker)
		}
		if err := coinprofile.ValidateAddress(profile, address); err != nil {
			return nil, fmt.Errorf("%s: entry %q: %w", flagLabel, entry, err)
		}
		out[profile.Ticker] = address
	}
	return out, nil
}

// validateDonationConfig fails fast (returning a real error, never
// just a log line) when a donation percentage is configured with no
// address to send that donation to, per coin family. Per
// PROD_HARDENING_REVIEW.md finding #10: payout.seedPaymentData/
// applyDonations (internal/backend/payout/payout.go) credit an
// EMPTY-STRING address row whenever DonationPercent > 0 but the
// matching family's *DonationAddress is unset -- and the resulting
// empty-address `balance` row then makes its WHOLE disbursement
// batch fail every cycle (wallet/monero_rpc.go's Transfer rejects an
// empty destination address), silently blocking every OTHER miner
// co-batched with it. There is no legitimate reason to configure a
// donation percentage with nowhere to send it, so this is refused at
// startup rather than left to poison a batch in production. Each
// coin family is only checked if that family's payout is actually
// enabled (its fee address is set) -- an operator running Tari-only
// should not be forced to configure a Monero donation address they
// will never use.
func validateDonationConfig(cfg config, extraFee, extraDonation map[string]string) error {
	if cfg.payoutDonationPercent <= 0 {
		return nil
	}
	if strings.TrimSpace(cfg.payoutTariFeeAddress) != "" && strings.TrimSpace(cfg.payoutTariDonationAddress) == "" {
		return fmt.Errorf("GCPOOL_PAYOUT_DONATION_PERCENT is %v (> 0) and GCPOOL_PAYOUT_TARI_FEE_ADDRESS is set, but GCPOOL_PAYOUT_TARI_DONATION_ADDRESS is empty -- "+
			"refusing to start: an empty donation address would credit a real balance row with payment_address='', "+
			"which poisons its entire disbursement batch every cycle (see PROD_HARDENING_REVIEW.md finding #10)",
			cfg.payoutDonationPercent)
	}
	if strings.TrimSpace(cfg.payoutMoneroFeeAddress) != "" && strings.TrimSpace(cfg.payoutMoneroDonationAddress) == "" {
		return fmt.Errorf("GCPOOL_PAYOUT_DONATION_PERCENT is %v (> 0) and GCPOOL_PAYOUT_MONERO_FEE_ADDRESS is set, but GCPOOL_PAYOUT_MONERO_DONATION_ADDRESS is empty -- "+
			"refusing to start: an empty donation address would credit a real balance row with payment_address='', "+
			"which poisons its entire disbursement batch every cycle (see PROD_HARDENING_REVIEW.md finding #10)",
			cfg.payoutDonationPercent)
	}
	for ticker := range extraFee {
		if _, ok := extraDonation[ticker]; !ok {
			return fmt.Errorf("GCPOOL_PAYOUT_DONATION_PERCENT is %v (> 0) and -payout-extra-fee-addresses configures %s, but -payout-extra-donation-addresses has no entry for it -- "+
				"refusing to start (see PROD_HARDENING_REVIEW.md finding #10)",
				cfg.payoutDonationPercent, ticker)
		}
	}
	return nil
}

const defaultPPLNSShareMulti = 2

// defaultRetentionPollInterval is this command's PLACEHOLDER default
// poll cadence for the shares retention/cleanup job — see
// buildRetentionConfig's doc comment for the env var that overrides
// it. An hourly cadence is a reasonable starting point: dropping a
// whole partition is cheap (a catalog DROP TABLE, not a row scan — see
// internal/backend/retention's package doc comment), so there is no
// real cost to checking often, but there is also no benefit to
// checking every few seconds when partitions only age out on the
// order of HeightPartitionBucketSize blocks at a time.
const defaultRetentionPollInterval = 1 * time.Hour

// buildRetentionConfig reads cfg.retentionPollInterval/
// cfg.retentionBlocks (see this file's package doc comment for the
// underlying GCPOOL_RETENTION_* env vars) and returns a ready-to-use
// retention.Config plus whether the retention job should actually be
// started (ok == false when no retention window was configured at
// all — a deployment that hasn't set any GCPOOL_RETENTION_* variable
// keeps every share forever, exactly like today, mirroring
// buildUnlockerConfig/buildDisburseEngine's "config knob absent ->
// feature disabled" convention).
//
//	GCPOOL_RETENTION_POLL_INTERVAL          (optional) how often the
//	                                         retention job re-evaluates
//	                                         every target, as a
//	                                         time.ParseDuration string
//	                                         (e.g. "1h"). Default "1h".
//	                                         Only consulted if at least
//	                                         one retention window below
//	                                         is configured.
//	GCPOOL_RETENTION_BLOCKS                 (optional) the DEFAULT
//	                                         retention window, in block-
//	                                         height units, applied to
//	                                         every (algo, pool_type)
//	                                         combination in db.ValidAlgos
//	                                         x db.ValidPoolTypes that
//	                                         does not have a more
//	                                         specific override below.
//	                                         Unset (or <=0) means "no
//	                                         default" — a combination
//	                                         with neither this nor its
//	                                         own override set to a
//	                                         positive value is never
//	                                         touched by the retention
//	                                         job.
//	GCPOOL_RETENTION_<ALGO>_<POOL_TYPE>_BLOCKS
//	                                         (optional, env-var-only --
//	                                         not a flag, since the name
//	                                         is only known at runtime;
//	                                         see this file's package
//	                                         doc comment) per-combination
//	                                         override of the retention
//	                                         window above, e.g.
//	                                         GCPOOL_RETENTION_RXT_PPLNS_BLOCKS.
//	                                         ALGO/POOL_TYPE are the
//	                                         exact db.ValidAlgos/
//	                                         db.ValidPoolTypes string
//	                                         values. Set to "0" (or any
//	                                         value <=0) to explicitly
//	                                         disable retention for one
//	                                         combination even when
//	                                         GCPOOL_RETENTION_BLOCKS is
//	                                         set for everything else.
func buildRetentionConfig(cfg config) (out retention.Config, ok bool, err error) {
	out.PollInterval = cfg.retentionPollInterval

	defaultBlocks := cfg.retentionBlocks

	for _, algo := range db.ValidAlgos {
		for _, poolType := range db.ValidPoolTypes {
			blocks := defaultBlocks
			envName := fmt.Sprintf("GCPOOL_RETENTION_%s_%s_BLOCKS", algo, poolType)
			if raw := os.Getenv(envName); raw != "" {
				v, parseErr := strconv.ParseInt(raw, 10, 64)
				if parseErr != nil {
					return out, false, fmt.Errorf("%s: %w", envName, parseErr)
				}
				blocks = v
			}
			if blocks <= 0 {
				continue
			}
			out.Targets = append(out.Targets, retention.Target{Algo: algo, PoolType: poolType, RetentionBlocks: blocks})
			ok = true
		}
	}

	return out, ok, nil
}

// defaultDisbursePollInterval/defaultDisburseMaxDestinationsPerBatch
// are this command's PLACEHOLDER defaults for the disbursement
// engine's env vars — see this file's package doc comment for why
// these are operator-tunable rather than baked-in protocol constants.
const (
	defaultDisbursePollInterval            = 10 * time.Minute
	defaultWalletStatsPollInterval         = 1 * time.Minute
	defaultDisburseMaxDestinationsPerBatch = 15

	// defaultWalletRPCTimeout is the default for
	// GCPOOL_WALLET_RPC_TIMEOUT / -wallet-rpc-timeout, matching
	// wallet.DefaultTimeout.
	//
	// This is NOT an ordinary tuning knob. Until this flag existed,
	// the Monero wallet RPC client had a hardcoded 30s HTTP timeout
	// with no override wired anywhere in this command -- and a real
	// monero-wallet-rpc `transfer` call can exceed 30s while still
	// broadcasting the transaction for real. That produced a client
	// -side timeout error for a payout that genuinely happened,
	// which the disbursement engine recorded as FAILED and re-sent
	// on the next cycle: a real double payment. The engine no longer
	// makes that assumption (any non-provably-unbroadcast error is
	// now AMBIGUOUS and halts disbursement -- see
	// internal/backend/disburse and
	// migrations/0010_payouts_ambiguous_status.up.sql), but an
	// over-tight timeout still converts perfectly good payouts into
	// halted incidents needing manual resolution. 60s is chosen to
	// be comfortably longer than a real transfer on a busy wallet,
	// while still bounded so a dead wallet RPC cannot hang the
	// disbursement loop forever.
	defaultWalletRPCTimeout = wallet.DefaultTimeout
)

// buildDisburseEngine reads cfg's moneroWalletRPC*/disburse* fields
// (see this file's package doc comment for the underlying
// GCPOOL_MONERO_WALLET_RPC_*/GCPOOL_DISBURSE_* env vars) and returns
// a ready-to-use *disburse.Engine plus whether the real
// payout-disbursement loop should actually be started (ok == false
// when cfg.moneroWalletRPCAddr is unset — a deployment that hasn't
// configured a wallet RPC endpoint yet still gets correct payout
// CALCULATION (crediting pending_balance, via buildPayoutCalculator
// above), it simply never auto-disburses those balances on-chain).
// Disbursement is Monero-only today — internal/backend/wallet has no
// Tari-family WalletClient implementation yet, mirroring
// GCPOOL_MONERO_RPC_ADDR's coin-specific scope on the chain-
// verification side.
//
//	GCPOOL_MONERO_WALLET_RPC_ADDR     (required to enable disbursement)
//	                                  base URL of a real monero-wallet-rpc
//	                                  endpoint (e.g. "http://127.0.0.1:18083").
//	GCPOOL_MONERO_WALLET_RPC_USER,
//	GCPOOL_MONERO_WALLET_RPC_PASSWORD (optional) HTTP Digest auth
//	                                  credentials, matching whatever
//	                                  --rpc-login the real
//	                                  monero-wallet-rpc process was
//	                                  started with. Both empty means
//	                                  no auth is attempted.
//	GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC (optional) minimum pending_balance
//	                                  (atomic units) required before a
//	                                  miner is paid out at all. Default 0.
//	GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH (optional) cap on
//	                                  destinations per real Transfer
//	                                  call. Default 15.
//	GCPOOL_DISBURSE_POLL_INTERVAL     (optional) how often the
//	                                  disbursement engine runs a cycle,
//	                                  as a time.ParseDuration string.
//	                                  Default "10m".
//	GCPOOL_FORCE_PAYOUT_FEE_ATOMIC    (optional) flat atomic-unit fee
//	                                  charged against every
//	                                  force_payout=TRUE balance row
//	                                  paid out this cycle (see POST
//	                                  /user/forcePayment), deducted
//	                                  from the miner's payout and
//	                                  credited to pool revenue
//	                                  (payouts.force_payout_fee_atomic).
//	                                  Default 0 (no extra fee).
//	GCPOOL_WALLET_RPC_TIMEOUT         (optional) timeout for the real
//	                                  monero-wallet-rpc HTTP client.
//	                                  Default 60s. Money-critical --
//	                                  see defaultWalletRPCTimeout's
//	                                  doc comment: too short and a
//	                                  slow-but-successful transfer
//	                                  becomes an AMBIGUOUS payout
//	                                  that halts disbursement until
//	                                  an operator resolves it.
func buildDisburseEngine(cfg config, repo *db.Repository, m *metrics.Metrics, debug *leaflib.DebugLogger) (engine *disburse.Engine, walletClient wallet.WalletClient, interval time.Duration, ok bool, err error) {
	if cfg.moneroWalletRPCAddr == "" {
		return nil, nil, 0, false, nil
	}

	opts := []wallet.Option{wallet.WithTimeout(cfg.walletRPCTimeout)}
	if cfg.moneroWalletRPCUser != "" || cfg.moneroWalletRPCPassword != "" {
		opts = append(opts, wallet.WithDigestAuth(cfg.moneroWalletRPCUser, cfg.moneroWalletRPCPassword))
	}
	walletClient = wallet.NewMoneroWalletRPC(cfg.moneroWalletRPCAddr, opts...)

	dcfg := disburse.Config{
		Wallet:                  walletClient,
		MaxDestinationsPerBatch: cfg.disburseMaxDestinationsPerBatch,
		MinPayoutAtomic:         cfg.disburseMinPayoutAtomic,
		ForcePayoutFeeAtomic:    cfg.forcePayoutFeeAtomic,
		Metrics:                 m,
		Debug:                   debug,
	}

	return disburse.New(disburseRepositoryAdapter{repo: repo}, dcfg), walletClient, cfg.disbursePollInterval, true, nil
}

// buildTariDisburseEngine is buildDisburseEngine's Tari counterpart.
// It is a genuinely SEPARATE *disburse.Engine (not a second Target on
// the Monero one) because the two coins need two different real
// wallet backends AND, critically, a different
// MaxDestinationsPerBatch: TariWalletGRPC.Transfer refuses more than
// one destination per call (see that method's own doc comment for
// the real double-payment risk this constraint prevents — Tari's
// real Transfer RPC reports success/failure per recipient, but this
// codebase's WalletClient contract is strictly all-or-nothing, and
// until that interface carries real per-destination results, a
// multi-destination Tari batch could see some recipients genuinely
// paid on-chain while the whole call still reports failure, leaving
// disburse.Engine's own safety logic unable to tell which ones to
// debit — this is NOT a stylistic choice, MaxDestinationsPerBatch
// MUST be 1 for any Tari disburse.Engine, enforced by both this
// function (hardcoded, not reachable via env var) and TariWalletGRPC
// itself as a defense-in-depth pair).
//
//	GCPOOL_TARI_WALLET_GRPC_ADDR      (required to enable Tari
//	                                  disbursement) address (host:port)
//	                                  of a real Tari console/base
//	                                  wallet GRPC endpoint.
//	GCPOOL_TARI_WALLET_FEE_PER_GRAM   (optional) default fee_per_gram
//	                                  for a Transfer whose Priority is
//	                                  zero. See wallet.WithFeePerGram's
//	                                  doc comment. Default: whatever
//	                                  wallet.NewTariWalletGRPC's own
//	                                  default is (see that package).
//	GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC,
//	GCPOOL_DISBURSE_POLL_INTERVAL,
//	GCPOOL_FORCE_PAYOUT_FEE_ATOMIC    shared with the Monero engine's
//	                                  identically-named env vars (see
//	                                  buildDisburseEngine) — both
//	                                  engines read the same values,
//	                                  since there is no real reason a
//	                                  deployment would want a
//	                                  different minimum payout, poll
//	                                  cadence, or force-payout fee per
//	                                  coin.
//	GCPOOL_WALLET_RPC_TIMEOUT         shared with the Monero engine,
//	                                  but applied only to Tari's
//	                                  READ-ONLY wallet GRPC lookups
//	                                  (GetBalance, and Transfer's
//	                                  GetTransactionInfo fee
//	                                  fallback). It deliberately does
//	                                  NOT bound Tari's fund-moving
//	                                  Transfer call -- see
//	                                  wallet.WithTariReadTimeout's doc
//	                                  comment: go-tari-grpc-lib's
//	                                  walletGRPC builds its own
//	                                  context.Background() internally,
//	                                  so the only "timeout" available
//	                                  would be abandoning an in-flight
//	                                  transfer without cancelling it,
//	                                  which manufactures exactly the
//	                                  ambiguous "did the coin move?"
//	                                  incident this whole change
//	                                  exists to avoid.
func buildTariDisburseEngine(cfg config, repo *db.Repository, m *metrics.Metrics, debug *leaflib.DebugLogger) (engine *disburse.Engine, walletClient wallet.WalletClient, interval time.Duration, ok bool, err error) {
	if cfg.tariWalletGRPCAddr == "" {
		return nil, nil, 0, false, nil
	}

	opts := []wallet.TariOption{wallet.WithTariReadTimeout(cfg.walletRPCTimeout)}
	if cfg.tariWalletFeePerGram != 0 {
		opts = append(opts, wallet.WithFeePerGram(cfg.tariWalletFeePerGram))
	}
	tariWalletClient, err := wallet.NewTariWalletGRPC(cfg.tariWalletGRPCAddr, opts...)
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("connecting to Tari wallet GRPC at %s: %w", cfg.tariWalletGRPCAddr, err)
	}
	walletClient = tariWalletClient

	dcfg := disburse.Config{
		Wallet: walletClient,
		// Hardcoded, not env-var-configurable -- see this function's
		// own doc comment for why 1 is the only safe value for Tari
		// today.
		MaxDestinationsPerBatch: 1,
		MinPayoutAtomic:         cfg.disburseMinPayoutAtomic,
		ForcePayoutFeeAtomic:    cfg.forcePayoutFeeAtomic,
		Metrics:                 m,
		Debug:                   debug,
	}

	return disburse.New(disburseRepositoryAdapter{repo: repo}, dcfg), walletClient, cfg.disbursePollInterval, true, nil
}

// buildCoinDisburseEngines is buildDisburseEngine/buildTariDisburseEngine's
// counterpart for every standalone monerod-family coin in
// internal/coinprofile.Registry (XMR, ARQ, XEQ, GRFT, SFX, ZEPH,
// SAL) -- generalized into ONE loop over the real Registry, per
// payoutbrief.md dispatch #3's explicit instruction, rather than 7
// more hand-copied near-identical build*DisburseEngine functions.
//
// wallet.NewMoneroWalletRPC is already a generic monero-wallet-rpc-
// COMPATIBLE client (no Monero-specific wire assumption beyond what
// every one of these forks' own `*-wallet-rpc` binary also
// implements, per the brief's own framing), so it is reused as-is
// for every coin here -- there is no new per-coin wallet client type
// anywhere in this codebase, only new wiring.
//
// For each coin with ticker T (e.g. "ARQ"), reads, env-var-only (see
// this file's package doc comment's GCPOOL_<TICKER>_WALLET_RPC_ADDR
// entry -- not exposed as a flag, since the name is only known at
// runtime, exactly like GCPOOL_RETENTION_<ALGO>_<POOL_TYPE>_BLOCKS in
// buildRetentionConfig above):
//
//	GCPOOL_<T>_WALLET_RPC_ADDR      (required to enable T's engine)
//	                                 base URL of a real
//	                                 monero-wallet-rpc-compatible
//	                                 endpoint. Absent means T's engine
//	                                 is simply not built -- never
//	                                 fatal, mirroring
//	                                 GCPOOL_MONERO_WALLET_RPC_ADDR/
//	                                 GCPOOL_TARI_WALLET_GRPC_ADDR's own
//	                                 "config knob absent -> feature
//	                                 disabled" contract.
//	GCPOOL_<T>_WALLET_RPC_USER,
//	GCPOOL_<T>_WALLET_RPC_PASSWORD  (optional) HTTP Digest auth,
//	                                 mirroring
//	                                 GCPOOL_MONERO_WALLET_RPC_{USER,PASSWORD}.
//
// Every other Config knob -- MinPayoutAtomic, MaxDestinationsPerBatch,
// ForcePayoutFeeAtomic, the poll interval, and the wallet RPC timeout
// -- is DELIBERATELY shared across every coin built here AND with the
// existing Monero engine (cfg.disburseMinPayoutAtomic/
// cfg.disburseMaxDestinationsPerBatch/cfg.forcePayoutFeeAtomic/
// cfg.disbursePollInterval/cfg.walletRPCTimeout), exactly like
// buildTariDisburseEngine already shares those same fields with
// buildDisburseEngine today. No per-coin override of any of these
// exists: this dispatch does not invent a coin-specific fee-per-KB,
// batch limit, or wallet-rpc auth quirk it cannot verify (see
// payoutbrief.md's explicit "out of scope" list) -- if a real
// deployment of one of these coins genuinely needs one, that is a
// real, separate follow-up once that coin's actual wallet-rpc
// behavior is observed, not something to guess here.
//
// MaxDestinationsPerBatch is NOT hardcoded to 1 the way
// buildTariDisburseEngine's is: that constraint is specific to
// Tari's own GRPC Transfer semantics (see that function's doc
// comment), not a general multi-destination concern -- every one of
// these 7 coins speaks real monero-wallet-rpc-style multi-destination
// `transfer`/`transfer_split` semantics, exactly like the existing
// Monero engine already relies on.
//
// Returns one *disburse.Engine plus its wallet.WalletClient per
// ENABLED coin, keyed by uppercase Ticker -- which is simultaneously
// that coin's db.ValidAlgos entry (the `algo` this engine's
// RunOnce/Target should use) AND the currency its balance/payout rows
// use (see fix #1/#2 elsewhere in this change-set: blockPayoutCurrency
// and db.ValidCurrencies both key on exactly this same Ticker string).
// A coin absent from the returned maps had no
// GCPOOL_<TICKER>_WALLET_RPC_ADDR set and was simply not built.
//
// Every safety property disburse.Engine/wallet.WalletClient already
// has for the Monero/Tari engines (the AMBIGUOUS-status halt-on-
// unresolved-payout gate CheckTargets/RunOnce enforce, the
// in-process TryLock overlap guard, ErrNotBroadcast disambiguation)
// applies automatically to every engine built here too, because this
// function does nothing but construct the SAME disburse.Engine/
// wallet.WalletClient types every other coin already uses -- see
// TestCoinDisburseEngineRunOnceCreditsAndPaysOutARQCurrency for a
// real, from-scratch proof of this for one representative coin
// (ARQ), run against a real Postgres instance and a fake
// wallet-rpc test server.
func buildCoinDisburseEngines(cfg config, repo *db.Repository, m *metrics.Metrics, debug *leaflib.DebugLogger) (engines map[string]*disburse.Engine, clients map[string]wallet.WalletClient) {
	engines = make(map[string]*disburse.Engine)
	clients = make(map[string]wallet.WalletClient)

	tickers := make([]string, 0, len(coinprofile.Registry))
	for _, p := range coinprofile.Registry {
		tickers = append(tickers, p.Ticker)
	}
	sort.Strings(tickers)

	for _, ticker := range tickers {
		addr := os.Getenv(fmt.Sprintf("GCPOOL_%s_WALLET_RPC_ADDR", ticker))
		if addr == "" {
			continue
		}
		user := os.Getenv(fmt.Sprintf("GCPOOL_%s_WALLET_RPC_USER", ticker))
		pass := os.Getenv(fmt.Sprintf("GCPOOL_%s_WALLET_RPC_PASSWORD", ticker))

		opts := []wallet.Option{wallet.WithTimeout(cfg.walletRPCTimeout)}
		if user != "" || pass != "" {
			opts = append(opts, wallet.WithDigestAuth(user, pass))
		}
		walletClient := wallet.NewMoneroWalletRPC(addr, opts...)

		dcfg := disburse.Config{
			Wallet:                  walletClient,
			MaxDestinationsPerBatch: cfg.disburseMaxDestinationsPerBatch,
			MinPayoutAtomic:         cfg.disburseMinPayoutAtomic,
			ForcePayoutFeeAtomic:    cfg.forcePayoutFeeAtomic,
			Metrics:                 m,
			Debug:                   debug,
		}
		engines[ticker] = disburse.New(disburseRepositoryAdapter{repo: repo}, dcfg)
		clients[ticker] = walletClient
	}

	return engines, clients
}

// startDisburseLoop runs the money-critical startup check for one
// disbursement engine and then starts its RunLoop for only the
// (algo, network) targets that passed.
//
// The check (disburse.Engine.CheckTargets) refuses any pair that
// already has an unresolved PENDING or AMBIGUOUS `payouts` row. Both
// statuses mean "a real Transfer was attempted and this process does
// not know whether coin moved":
//
//   - PENDING -- recorded immediately before the Transfer RPC call
//     and never resolved, i.e. the previous process died mid-call.
//     Before this change nothing anywhere read PENDING rows, so a
//     crash mid-transfer silently left the balance payable and the
//     next cycle sent the same coin again.
//   - AMBIGUOUS -- the Transfer (or the bookkeeping write after a
//     SUCCESSFUL Transfer) failed in a way that cannot rule out a
//     real broadcast. See
//     migrations/0010_payouts_ambiguous_status.up.sql.
//
// Resuming disbursement for such a pair on restart is precisely how
// the same coin gets sent twice, so this refuses to start the loop
// for it and tells the operator exactly what is stuck and which
// command resolves it. Other pairs are unaffected: one stuck algo
// must not stop payouts for the rest.
//
// A failure to RUN the check at all is fatal for the whole process
// (returned as an error, not logged-and-continued): "I could not
// determine whether a payout is unresolved" is not "there are none",
// and guessing wrong moves real money.
func startDisburseLoop(ctx context.Context, engine *disburse.Engine, label string, targets []disburse.Target, interval time.Duration) error {
	safe, blocked, err := engine.CheckTargets(ctx, targets)
	if err != nil {
		return fmt.Errorf("%s: startup check for unresolved payouts failed: %w", label, err)
	}

	for _, b := range blocked {
		log.Printf("backend: %s: REFUSING to start disbursement for %s/%s: %d unresolved payout row(s) block it",
			label, b.Target.Algo, b.Target.Network, len(b.Unresolved))
		for _, p := range b.Unresolved {
			log.Printf("backend: %s: %s/%s: payout id=%d status=%s amount=%d balance_ids=%v tx_hash=%q created=%s error=%q",
				label, b.Target.Algo, b.Target.Network, p.ID, p.Status, p.Amount, p.BalanceIDs, p.TxHash,
				p.Created.UTC().Format(time.RFC3339), p.Error)
		}
		log.Printf("backend: %s: %s/%s: WHY: an unresolved PENDING/AMBIGUOUS payout means a real on-chain transfer was attempted and this backend does not know whether the coin actually moved. "+
			"Paying those balances again would double-spend real funds, so disbursement for this algo/network stays stopped until a human resolves it.",
			label, b.Target.Algo, b.Target.Network)
		log.Printf("backend: %s: %s/%s: HOW TO RESOLVE: (1) `backend payout show -id=<id>` to inspect the row; "+
			"(2) confirm on-chain/in wallet history whether that transfer really broadcast; "+
			"(3a) it DID: `backend payout resolve-sent -id=<id> -tx-hash=<hash> [-fee=<atomic>] -reason=... -by=... -yes` (records it and debits the balances -- the miner is NOT paid twice); "+
			"(3b) it did NOT: `backend payout resolve-not-sent -id=<id> -reason=... -by=... -yes` (leaves balances untouched so they become payable again). "+
			"Then restart the backend to resume disbursement for this algo/network.",
			label, b.Target.Algo, b.Target.Network)
	}

	if len(safe) == 0 {
		log.Printf("backend: %s: no (algo, network) targets are clear to disburse for; disbursement loop not started", label)
		return nil
	}
	log.Printf("backend: %s enabled, polling every %s for %v", label, interval, safe)
	go engine.RunLoop(ctx, safe, interval)
	return nil
}

// logUnresolvedBlockPayouts is the startup survey for stuck
// matured-block payouts, the block-payout sibling of
// startDisburseLoop's unresolved-`payouts` check.
//
// A PENDING `block_payouts` row means a payout run was claimed for
// that block and has no recorded outcome, i.e. an unknown subset of
// its miners may already hold its credit. db.Repository.ApplyBlockPayout
// refuses to run for such a block, so the unlocker will retry and
// fail it on every poll tick until a human resolves it (see
// migrations/0013_block_payouts.up.sql).
//
// Unlike the disbursement check, this deliberately does NOT stop
// anything from starting: a stuck block payout is scoped to that ONE
// block and is already blocked at the database level by its own claim
// row. Halting the whole unlocker (and so every other block's
// maturity tracking and payout) over it would be strictly worse. So
// this surfaces the incident loudly at startup — the one moment an
// operator is definitely reading logs — and lets the rest of the
// process run.
//
// A failure to RUN the survey is likewise logged rather than fatal,
// for the same reason: it blocks nothing, so it cannot cause the
// double-credit it reports on.
func logUnresolvedBlockPayouts(ctx context.Context, repo *db.Repository) {
	rows, err := repo.UnresolvedBlockPayouts(ctx, "", "")
	if err != nil {
		log.Printf("backend: WARNING: could not check for unresolved block payouts: %v — inspect manually with `backend block-payout list-unresolved`", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	log.Printf("backend: WARNING: %d block payout(s) are UNRESOLVED (PENDING) — each of those blocks is BLOCKED from any further automatic payout and will fail on every unlocker poll tick until a human resolves it", len(rows))
	for _, b := range rows {
		log.Printf("backend: unresolved block payout: block_id=%d algo=%s network=%s pool_type=%s height=%d reward=%d claimed=%s error=%q",
			b.BlockID, b.Algo, b.Network, b.PoolType, b.Height, b.Reward, b.CreatedAt.UTC().Format(time.RFC3339), derefString(b.Error))
	}
	log.Print("backend: WHY: a PENDING block_payouts row means that block's payout run was claimed but never recorded an outcome, so an unknown subset of its miners may already hold its credit. " +
		"Re-running the payout blindly would credit those miners a second time, so it is refused until the truth is established.")
	log.Print("backend: HOW TO RESOLVE: (1) `backend block-payout show -block-id=<id>` to see the itemised credits that run did record; " +
		"(2) check those miners' balances against that ledger; " +
		"(3a) the recorded credits are correct and complete: `backend block-payout resolve-credited -block-id=<id> -reason=... -by=... -yes` (marks it APPLIED, credits nobody again); " +
		"(3b) nothing landed, or you have already reversed what did: `backend block-payout resolve-not-credited -block-id=<id> -reason=... -by=... -yes` (hands the block back to the unlocker to pay out from scratch).")
}

// main runs the backend server by default (no args, or any args not
// matching one of the manual ops subcommands below) -- unchanged from
// before those subcommands were added, so existing deployments
// invoking this binary with no arguments keep working exactly as
// before.
//
// `backend block invalidate ...` / `backend block relock ...` are a
// separate, manual ops-triggered CLI path (see blockcli.go) that never
// starts the HTTP server or any background poll loop -- they open a
// DB connection, make one SetBlockStatus call, print the result, and
// exit. `backend payout ...` (see payoutcli.go) and `backend
// block-payout ...` (see blockpayoutcli.go) follow the same pattern
// for resolving unresolved/ambiguous disbursement payouts and stuck
// matured-block payouts respectively.
func main() {
	if len(os.Args) > 1 && os.Args[1] == "block" {
		if err := runBlockCommand(os.Args[2:]); err != nil {
			log.Fatalf("backend: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "block-payout" {
		if err := runBlockPayoutCommand(os.Args[2:]); err != nil {
			log.Fatalf("backend: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "retention" {
		if err := runRetentionCommand(os.Args[2:]); err != nil {
			log.Fatalf("backend: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "address" {
		if err := runAddressCommand(os.Args[2:]); err != nil {
			log.Fatalf("backend: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := runMigrateCommand(os.Args[2:]); err != nil {
			log.Fatalf("backend: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "payout" {
		if err := runPayoutCommand(os.Args[2:]); err != nil {
			log.Fatalf("backend: %v", err)
		}
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("backend: %v", err)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("backend: %v", err)
	}
}

// walletStatsTarget pairs a coin-agnostic wallet.WalletClient with
// the algo/network/currency labels its GetBalance results should be
// reported under on the shared WalletBalance gauge. currency (see
// migrations/0014_balance_payouts_currency.up.sql) is what lets
// ALGO_RXM's two independent real wallet connections -- the Monero
// wallet backing its primary/XMR leg and the Tari wallet backing its
// secondary/XTM leg -- report under the same algo/network pair
// without one gauge overwriting the other.
type walletStatsTarget struct {
	algo     string
	network  string
	currency string
	client   wallet.WalletClient
}

// walletBalanceKind* are the four real, distinct balance components
// this codebase reports (see metrics.Metrics.WalletBalance's doc
// comment). Monero's own wallet.Balance only ever populates
// available/pending_outgoing (see MoneroWalletRPC.GetBalance/
// TariWalletGRPC.GetBalance's respective Total/Unlocked mappings);
// exposing the full four-kind label set uniformly, even when a given
// coin's WalletClient can't populate all of them, keeps every
// wallet's balance queryable with the same PromQL regardless of coin
// — a deployment scraping wallet_balance_atomic doesn't need to know
// which coin backs which algo to write one dashboard panel.
const (
	walletBalanceKindAvailable       = "available"
	walletBalanceKindPendingIncoming = "pending_incoming"
	walletBalanceKindPendingOutgoing = "pending_outgoing"
	walletBalanceKindTimelocked      = "timelocked"
)

// runWalletStatsPoller periodically calls GetBalance on every real
// configured wallet and records the result on m.WalletBalance, until
// ctx is canceled. This is deliberately independent of
// disburse.Engine's own internal GetBalance calls (see
// disburse.go's insufficient-funds check) — that check only runs
// once per disbursement cycle and is not exported anywhere callers
// outside the engine can observe, whereas this poller exists purely
// to keep wallet_balance_atomic fresh on GET /metrics regardless of
// how often (or whether) a disbursement cycle actually runs.
//
// Real field coverage: a target whose client additionally satisfies
// wallet.DetailedBalanceClient (today: *wallet.TariWalletGRPC) is
// polled via GetDetailedBalance and reports its real, independently
// meaningful available/pending_incoming/pending_outgoing/timelocked
// values -- pending_incoming and timelocked are REAL numbers here,
// not the permanent 0 this poller used to hardcode for every target
// (Zabbix-to-Grafana dashboard migration, Alex: Tari wallet
// breakdown was one of the migration's gaps). A target whose client
// does NOT satisfy that interface (today: *wallet.MoneroWalletRPC,
// whose get_balance RPC genuinely only ever reports a Total/Unlocked
// pair) falls back to the plain WalletClient.GetBalance split:
// Unlocked as "available", (Total-Unlocked) as "pending_outgoing",
// and pending_incoming/timelocked reported as 0 (correctly -- Monero
// truly does not distinguish those from Total).
func runWalletStatsPoller(ctx context.Context, m *metrics.Metrics, targets []walletStatsTarget, interval time.Duration) {
	if interval <= 0 {
		log.Print("backend: wallet-stats poller: interval <= 0, not starting")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	pollOnce := func() {
		for _, t := range targets {
			if detailed, ok := t.client.(wallet.DetailedBalanceClient); ok {
				bal, err := detailed.GetDetailedBalance(ctx)
				if err != nil {
					m.WalletBalancePollErrorsTotal.WithLabelValues(t.algo, t.network, t.currency).Inc()
					log.Printf("backend: wallet-stats poller: %s/%s/%s: GetDetailedBalance: %v", t.algo, t.network, t.currency, err)
					continue
				}
				m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindAvailable).Set(float64(bal.Available))
				m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindPendingOutgoing).Set(float64(bal.PendingOutgoing))
				m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindPendingIncoming).Set(float64(bal.PendingIncoming))
				m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindTimelocked).Set(float64(bal.Timelocked))
				continue
			}

			bal, err := t.client.GetBalance(ctx)
			if err != nil {
				m.WalletBalancePollErrorsTotal.WithLabelValues(t.algo, t.network, t.currency).Inc()
				log.Printf("backend: wallet-stats poller: %s/%s/%s: GetBalance: %v", t.algo, t.network, t.currency, err)
				continue
			}
			m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindAvailable).Set(float64(bal.Unlocked))
			m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindPendingOutgoing).Set(float64(bal.Total - bal.Unlocked))
			m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindPendingIncoming).Set(0)
			m.WalletBalance.WithLabelValues(t.algo, t.network, t.currency, walletBalanceKindTimelocked).Set(0)
		}
	}

	pollOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollOnce()
		}
	}
}

// runPendingBalancePoller periodically queries repo for the current
// outstanding pending_balance total per (algo, network) and reports
// it on m.PendingBalanceOutstanding, until ctx is canceled. See
// PROD_HARDENING_REVIEW.md finding #19: existing coverage tracks
// payout/disburse/unlocker/wallet-balance ACTIVITY, but nothing
// previously reported the outstanding liability itself.
//
// Every (algo, network) combination in db.ValidAlgos x db.ValidNetworks
// is explicitly reset to 0 at the START of every poll, before the
// real query results are applied on top -- otherwise a pair whose
// balance later drains to exactly zero would simply stop appearing
// in db.Repository.PendingBalanceTotals' result set (it only returns
// rows with a positive sum) and its gauge would be left at a stale
// non-zero value forever. This mirrors unlocker.observePending's own
// same-pass-reset rationale for an identical staleness concern.
func runPendingBalancePoller(ctx context.Context, repo *db.Repository, m *metrics.Metrics, interval time.Duration) {
	if interval <= 0 {
		log.Print("backend: pending-balance poller: interval <= 0, not starting")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	pollOnce := func() {
		for _, algo := range db.ValidAlgos {
			for _, network := range db.ValidNetworks {
				m.PendingBalanceOutstanding.WithLabelValues(algo, network).Set(0)
			}
		}
		totals, err := repo.PendingBalanceTotals(ctx)
		if err != nil {
			log.Printf("backend: pending-balance poller: querying totals: %v", err)
			return
		}
		for _, t := range totals {
			m.PendingBalanceOutstanding.WithLabelValues(t.Algo, t.Network).Set(float64(t.Total))
		}
	}

	pollOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollOnce()
		}
	}
}

// validateIngestionAuthConfig enforces that the share/block ingestion
// endpoints (POST /api/v1/share, POST /api/v1/block) are never started
// unauthenticated by default. internal/backend/api.Handler's own
// checkAuth/authConfigured (see that package's doc comment) correctly
// treats "AuthHeaderName and AuthHeaderValue both empty" as "no auth
// check performed" once given that config — this function's job is
// narrower and lives entirely at this command's startup-wiring layer:
// it decides whether "both empty" is ever allowed to reach that
// Handler as the RESOLVED config in the first place.
//
// Per PROD_HARDENING_REVIEW.md finding #1, the safe default is
// "refuse to start" — the operator must either configure both
// GCPOOL_AUTH_HEADER_NAME/GCPOOL_AUTH_HEADER_VALUE (production), or
// explicitly pass -insecure-allow-unauthenticated-ingestion (env
// GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION=true) to opt into
// unauthenticated ingestion for local/dev use only. There is
// deliberately no partial-config allowance here: exactly one of
// AuthHeaderName/AuthHeaderValue being set is already handled (and
// already effectively enforced, if oddly) by api.Handler's own
// checkAuth once config reaches it — this function only ever blocks
// startup on the fully-unauthenticated "both empty, no override"
// case.
func validateIngestionAuthConfig(cfg config) error {
	if cfg.authHeaderName == "" && cfg.authHeaderValue == "" && !cfg.insecureAllowUnauthenticatedIngestion {
		return errors.New("refusing to start: GCPOOL_AUTH_HEADER_NAME/GCPOOL_AUTH_HEADER_VALUE (or -auth-header-name/-auth-header-value) are not set. " +
			"POST /api/v1/share and /api/v1/block are the leaf-to-backend trust boundary carrying real payout-triggering data and MUST be authenticated. " +
			"Set both -auth-header-name/-auth-header-value (or their GCPOOL_AUTH_HEADER_NAME/GCPOOL_AUTH_HEADER_VALUE env vars), " +
			"or pass -insecure-allow-unauthenticated-ingestion (env GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION=true) " +
			"to explicitly opt into unauthenticated ingestion for LOCAL/DEV USE ONLY")
	}
	return nil
}

func run(cfg config) error {
	if cfg.dbDSN == "" {
		return errors.New("GCPOOL_DB_DSN (or -db-dsn) is required")
	}
	if strings.TrimSpace(cfg.jwtSecret) == "" {
		return errors.New("GCPOOL_JWT_SECRET (or -jwt-secret) is required")
	}
	if err := validateIngestionAuthConfig(cfg); err != nil {
		return err
	}
	if cfg.authHeaderName == "" && cfg.authHeaderValue == "" && cfg.insecureAllowUnauthenticatedIngestion {
		log.Print("backend: WARNING: -insecure-allow-unauthenticated-ingestion (GCPOOL_INSECURE_ALLOW_UNAUTHENTICATED_INGESTION) is set -- POST /api/v1/share and /api/v1/block are running COMPLETELY UNAUTHENTICATED. This is for local/dev use only. Anyone with network reach to this backend can submit fabricated shares/blocks and trigger real payouts. Do NOT use this in production.")
	}

	listenAddr := cfg.listenAddr
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	network, err := parseNetwork(cfg.network)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// debugLogger is constructed exactly once per process (never a
	// global/package-level singleton -- see
	// internal/leaflib/debuglog.go's doc comment) and threaded down
	// via unlocker.Config.Debug/networkpoller.Config.Debug/
	// disburse.Config.Debug below. Wraps log.Default() -- the SAME
	// underlying writer/flags every existing log.Printf/log.Print
	// call in this file already uses (this command has no
	// per-instance *log.Logger of its own, unlike the 3 leaf
	// binaries -- see this file's own doc comment on why every
	// existing call site uses the global log package), so
	// [DEBUG]-tagged lines interleave naturally with the existing
	// log stream.
	debugLogger := leaflib.NewDebugLogger(log.Default(), cfg.debug)
	if cfg.debug {
		log.Print("backend: debug logging ENABLED (-debug/GCPOOL_DEBUG) -- verbose [DEBUG]-tagged poll-cycle output follows for the block unlocker/disbursement engines/network-state poller")
	}

	pool, err := db.Open(ctx, db.Config{DSN: cfg.dbDSN})
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer pool.Close()

	repo := db.NewRepository(pool)

	// m is shared across the HTTP API handler, the unlocker, and the
	// payout calculator so every real Prometheus metric this process
	// produces (shares/blocks ingestion, unlocker poll passes, payout
	// cycles) is served on the one GET /metrics endpoint api.Handler
	// already exposes, rather than standing up a second registry/
	// listener just for the backend's internal poll loops.
	m := metrics.New(Version)
	handler := api.NewHandler(repositoryAdapter{repo: repo}, api.Config{
		AuthHeaderName:     cfg.authHeaderName,
		AuthHeaderValue:    cfg.authHeaderValue,
		Network:            network,
		Version:            Version,
		Metrics:            m,
		IngestionRateLimit: cfg.ingestionRateLimit,
		IngestionRateBurst: cfg.ingestionRateBurst,
	})

	// statsHandler serves the read-only, unauthenticated miner stats
	// API (GET /api/v1/stats/*) on the same listener as the
	// ingestion API above — see internal/backend/statsapi's package
	// doc comment for why this is a genuinely separate Handler/
	// trust-boundary rather than new routes bolted onto handler
	// itself.
	statsHandler := statsapi.NewHandler(statsRepositoryAdapter{repo: repo}, statsapi.Config{
		Network: network,
		Metrics: m,
	})

	// addressMapHandler serves the SXMR merge-mining system's real
	// XMR-to-Tari address-mapping endpoints (POST/GET
	// /api/v1/address-map) on the same listener -- see
	// internal/backend/addressmap's package doc comment for why
	// this is its own Handler/trust-boundary, independent of both
	// the ingestion API and the miner stats API above.
	addressMapHandler := addressmap.NewHandler(addressMapRepositoryAdapter{repo: repo}, addressmap.Config{Metrics: m})

	// networkAPIHandler serves the real, read-only pool-wide network/
	// topology endpoints (GET /api/v1/network/pools,
	// GET /api/v1/network/stats) -- see internal/backend/networkapi's
	// package doc comment for how this differs in scope from
	// statsHandler above (whole-pool vs. single-miner).
	networkAPIHandler := networkapi.NewHandler(networkAPIRepositoryAdapter{repo: repo})

	// leafFlagsHandler serves the real, read-only GET
	// /api/v1/leaf/address-flags endpoint leaf-direct polls to learn
	// about manually-flagged (banned / forced-minimum-difficulty)
	// payment addresses -- see internal/backend/leafflagsapi's
	// package doc comment for how this differs from (and does NOT
	// replace) the address_flags CLI's own write-side, which stays
	// CLI-only/-yes-gated. leaf-solo, which has no backend connection
	// at all, uses a local file-based source instead (see
	// internal/leaflib/addressflags.FileSource) and never talks to
	// this endpoint.
	leafFlagsHandler := leafflagsapi.NewHandler(leafFlagsRepositoryAdapter{repo: repo})

	// legacyAPIHandler serves the SXMR-legacy-shaped wrapper routes
	// (bare, non-/api/v1-prefixed paths like GET /pool/stats,
	// GET /miner/:address/stats, POST /user/updateTariAddress, etc.)
	// that reshape statsHandler/networkAPIHandler/addressMapHandler's
	// own real data into the exact field-name/casing/nesting shape
	// the legacy nodejs-pool-sxmr stack's lib/api.js served -- see
	// internal/backend/legacyapi's package doc comment for the full
	// rationale and the real, explicitly flagged gaps (fields with no
	// backing query anywhere in this repo) it deliberately does not
	// paper over. Purely additive: it reuses statsHandler/
	// networkAPIHandler/addressMapHandler's own exported Repository
	// interfaces directly (no new dependency on internal/backend/db
	// beyond the three small additive read methods in
	// internal/backend/db/legacyapi_reads.go), and registers only
	// routes no existing handler in this file already owns.
	legacyAPIHandler := legacyapi.NewHandler(
		networkAPIRepositoryAdapter{repo: repo},
		statsRepositoryAdapter{repo: repo},
		addressMapRepositoryAdapter{repo: repo},
		legacyBlocksRepositoryAdapter{repo: repo},
		legacyPayoutsRepositoryAdapter{repo: repo},
		legacyIdentifiersRepositoryAdapter{repo: repo},
		legacyapi.Config{
			Network:         network,
			PPSFeePercent:   cfg.payoutPPSFeePercent,
			PPLNSFeePercent: cfg.payoutPPLNSFeePercent,
			SoloFeePercent:  cfg.payoutSoloFeePercent,
		},
	)

	// authHandler serves the SXMR-legacy authentication/account-
	// settings endpoints (POST /authenticate, GET/POST /authed/*,
	// POST/GET /user/*) on the same listener -- see
	// internal/backend/authapi's package doc comment for why this is
	// its own Handler/trust-boundary, independent of every other
	// handler wired above. NewHandler fails (and so does run(), via
	// this err check) if cfg.jwtSecret is somehow empty here despite
	// the earlier fail-fast check at the top of run() -- defense in
	// depth, not reachable in practice.
	authHandler, err := authapi.NewHandler(authRepositoryAdapter{repo: repo}, authapi.Config{
		JWTSecret: cfg.jwtSecret,
		Network:   network,
		Metrics:   m,
	})
	if err != nil {
		return fmt.Errorf("configuring authapi: %w", err)
	}

	// legacyConfigHandler serves the SXMR-legacy small/cheap
	// standalone endpoints (GET /config, GET /pool/motd,
	// GET /pool/ports, GET /pool/address_type/{address}) -- see
	// internal/backend/legacyconfig's package doc comment. It
	// composes networkAPIHandler's own ListFlatPorts (an additive
	// method on the same Handler constructed above, not a second
	// query path) to serve GET /pool/ports without duplicating
	// networkapi's ListPools query.
	legacyConfigHandler := legacyconfig.NewHandler(legacyConfigRepositoryAdapter{repo: repo}, networkAPIHandler, legacyconfig.Config{
		PPSFeePercent:          cfg.payoutPPSFeePercent,
		SoloFeePercent:         cfg.payoutSoloFeePercent,
		DevDonationPercent:     cfg.payoutDonationPercent,
		PoolDevDonationPercent: cfg.payoutDonationPercent,
		MinWalletPayoutAtomic:  cfg.disburseMinPayoutAtomic,
		MaturityDepth:          cfg.unlockerTariMaturity,
	})

	unlockerCfg, unlockerEnabled, err := buildUnlockerConfig(cfg, debugLogger)
	if err != nil {
		return fmt.Errorf("configuring block unlocker: %w", err)
	}
	unlockerCfg.Metrics = m

	payoutCalc, payoutEnabled, err := buildPayoutCalculator(cfg, repo, m)
	if err != nil {
		return fmt.Errorf("configuring payout calculator: %w", err)
	}
	if payoutEnabled {
		unlockerCfg.PayoutTrigger = payoutTrigger{calc: payoutCalc, network: networkDBString(network)}
		log.Print("backend: payout calculation enabled, wired into the block unlocker's matured-block trigger")
		// Surface any block whose payout is claimed-but-unresolved
		// before the unlocker starts hammering it. See this
		// function's doc comment for why this reports rather than
		// halts.
		logUnresolvedBlockPayouts(ctx, repo)
	} else {
		log.Print("backend: payout calculation disabled (neither GCPOOL_PAYOUT_TARI_FEE_ADDRESS nor GCPOOL_PAYOUT_MONERO_FEE_ADDRESS set); blocks will still be marked matured/unlocked, just never auto-paid out")
	}

	if unlockerEnabled {
		u := unlocker.New(unlockerRepositoryAdapter{repo: repo}, unlockerCfg)
		log.Printf("backend: block unlocker enabled, polling every %s for algos %v", unlockerCfg.PollInterval, sortedKeys(unlockerCfg.Coins))
		go u.RunLoop(ctx)
	} else {
		log.Print("backend: block unlocker disabled (neither GCPOOL_TARI_GRPC_ADDR nor GCPOOL_MONERO_RPC_ADDR is set)")
	}

	// networkPollerCfg/networkPollerEnabled: the real, live upstream
	// chain-state poll loop (internal/backend/networkpoller) --
	// deliberately built AFTER buildUnlockerConfig/unlockerEnabled
	// above, since that call is what performs this process' one
	// real nodeGRPC.InitNodeGRPC call for GCPOOL_TARI_GRPC_ADDR (see
	// buildNetworkPollerConfig's own doc comment).
	networkPollerCfg, networkPollerEnabled, err := buildNetworkPollerConfig(cfg, network, m, debugLogger)
	if err != nil {
		return fmt.Errorf("configuring network-state poller: %w", err)
	}
	if networkPollerEnabled {
		np := networkpoller.New(networkPollerRepositoryAdapter{repo: repo}, networkPollerCfg)
		log.Printf("backend: network-state poller enabled, polling every %s for %d target(s)", networkPollerCfg.PollInterval, len(networkPollerCfg.Targets))
		go np.RunLoop(ctx)
	} else {
		log.Print("backend: network-state poller disabled (neither GCPOOL_TARI_GRPC_ADDR nor GCPOOL_MONERO_RPC_ADDR is set); network_state stays empty and networkapi's Network* stats fields simply read back as nil")
	}

	retentionCfg, retentionEnabled, err := buildRetentionConfig(cfg)
	if err != nil {
		return fmt.Errorf("configuring share retention/cleanup: %w", err)
	}
	if retentionEnabled {
		retentionCfg.Metrics = m
		rr := retention.New(retentionRepositoryAdapter{pool: pool}, retentionCfg)
		log.Printf("backend: share retention/cleanup enabled, polling every %s for %d target(s): %v", retentionCfg.PollInterval, len(retentionCfg.Targets), retentionCfg.Targets)
		go rr.RunLoop(ctx)
	} else {
		log.Print("backend: share retention/cleanup disabled (no GCPOOL_RETENTION_BLOCKS or GCPOOL_RETENTION_<ALGO>_<POOL_TYPE>_BLOCKS set); shares accumulate forever until an operator configures a retention window")
	}

	disburseEngine, moneroWalletClient, disburseInterval, disburseEnabled, err := buildDisburseEngine(cfg, repo, m, debugLogger)
	if err != nil {
		return fmt.Errorf("configuring payout disbursement engine: %w", err)
	}
	if disburseEnabled {
		// Currency: "XMR" -- this engine wraps moneroWalletClient
		// (a real monero-wallet-rpc connection), so it can only ever
		// legitimately move ALGO_RXM's primary/Monero leg's balance
		// (see migrations/0014_balance_payouts_currency.up.sql). The
		// secondary/Tari leg's XTM balance is a genuinely separate
		// wallet and is not disbursed by this engine at all today.
		targets := []disburse.Target{{Algo: "RXM", Network: networkDBString(network), Currency: "XMR"}}
		if err := startDisburseLoop(ctx, disburseEngine, "payout disbursement engine", targets, disburseInterval); err != nil {
			return err
		}
	} else {
		log.Print("backend: payout disbursement engine disabled (GCPOOL_MONERO_WALLET_RPC_ADDR not set); pending_balance will still accrue, it just won't be auto-paid out on-chain")
	}

	tariDisburseEngine, tariWalletClient, tariDisburseInterval, tariDisburseEnabled, err := buildTariDisburseEngine(cfg, repo, m, debugLogger)
	if err != nil {
		return fmt.Errorf("configuring Tari payout disbursement engine: %w", err)
	}
	if tariDisburseEnabled {
		targets := make([]disburse.Target, 0, len(tariAlgos))
		for _, algo := range tariAlgos {
			// Currency: "XTM" for every Tari-family algo -- these
			// never have any other leg/currency (see
			// migrations/0014_balance_payouts_currency.up.sql).
			targets = append(targets, disburse.Target{Algo: algo, Network: networkDBString(network), Currency: "XTM"})
		}
		if err := startDisburseLoop(ctx, tariDisburseEngine, "Tari payout disbursement engine (max 1 destination/batch, see buildTariDisburseEngine)", targets, tariDisburseInterval); err != nil {
			return err
		}
	} else {
		log.Print("backend: Tari payout disbursement engine disabled (GCPOOL_TARI_WALLET_GRPC_ADDR not set); pending_balance will still accrue, it just won't be auto-paid out on-chain")
	}

	// Standalone monerod-family coins (internal/coinprofile.Registry:
	// XMR, ARQ, XEQ, GRFT, SFX, ZEPH, SAL) -- one genuinely separate
	// *disburse.Engine per coin that has a GCPOOL_<TICKER>_WALLET_RPC_ADDR
	// configured, exactly like the Monero/Tari engines above but built
	// via a single generalized loop (see buildCoinDisburseEngines'
	// doc comment). Every one of Algo/Currency here is that coin's
	// own Ticker (matches fix #1/#2 elsewhere in this change-set:
	// blockPayoutCurrency/db.ValidCurrencies both key on exactly the
	// same string).
	coinDisburseEngines, coinWalletClients := buildCoinDisburseEngines(cfg, repo, m, debugLogger)
	if len(coinDisburseEngines) == 0 {
		log.Print("backend: no standalone-coin (ARQ/XEQ/GRFT/SFX/ZEPH/SAL/XMR) payout disbursement engines enabled (no GCPOOL_<TICKER>_WALLET_RPC_ADDR set for any of them); their balances will still accrue, they just won't be auto-paid out on-chain")
	} else {
		enabledTickers := make([]string, 0, len(coinDisburseEngines))
		for ticker := range coinDisburseEngines {
			enabledTickers = append(enabledTickers, ticker)
		}
		sort.Strings(enabledTickers)
		for _, ticker := range enabledTickers {
			targets := []disburse.Target{{Algo: ticker, Network: networkDBString(network), Currency: ticker}}
			label := fmt.Sprintf("%s payout disbursement engine", ticker)
			if err := startDisburseLoop(ctx, coinDisburseEngines[ticker], label, targets, cfg.disbursePollInterval); err != nil {
				return err
			}
		}
	}

	var walletStatsTargets []walletStatsTarget
	if moneroWalletClient != nil {
		walletStatsTargets = append(walletStatsTargets, walletStatsTarget{algo: "RXM", network: networkDBString(network), currency: "XMR", client: moneroWalletClient})
	}
	if tariWalletClient != nil {
		for _, algo := range tariAlgos {
			walletStatsTargets = append(walletStatsTargets, walletStatsTarget{algo: algo, network: networkDBString(network), currency: "XTM", client: tariWalletClient})
		}
		// ALGO_RXM's secondary/Tari leg (see
		// migrations/0012_blocks_merge_mine_chain.up.sql and
		// migrations/0014_balance_payouts_currency.up.sql) is paid
		// out of THIS SAME Tari wallet gRPC connection, not the
		// Monero one above -- a genuinely separate real wallet from
		// RXM's primary/XMR leg, which previously had no wallet
		// target registered here at all. currency: "XTM" (not
		// "XMR") is what keeps this series distinct from the RXM/XMR
		// one on the shared WalletBalance/WalletBalancePollErrorsTotal
		// gauges above, even though both share the algo="RXM" label.
		walletStatsTargets = append(walletStatsTargets, walletStatsTarget{algo: "RXM", network: networkDBString(network), currency: "XTM", client: tariWalletClient})
	}
	if len(coinWalletClients) > 0 {
		coinTickers := make([]string, 0, len(coinWalletClients))
		for ticker := range coinWalletClients {
			coinTickers = append(coinTickers, ticker)
		}
		sort.Strings(coinTickers)
		for _, ticker := range coinTickers {
			walletStatsTargets = append(walletStatsTargets, walletStatsTarget{algo: ticker, network: networkDBString(network), currency: ticker, client: coinWalletClients[ticker]})
		}
	}
	if len(walletStatsTargets) > 0 {
		walletStatsInterval := cfg.walletStatsPollInterval
		log.Printf("backend: wallet-stats poller enabled, polling every %s for %d target(s)", walletStatsInterval, len(walletStatsTargets))
		go runWalletStatsPoller(ctx, m, walletStatsTargets, walletStatsInterval)
	} else {
		log.Print("backend: wallet-stats poller disabled (no wallet RPC configured for either coin)")
	}

	// pending-balance poller: unconditional, unlike every other
	// poller above -- the outstanding pending_balance liability
	// exists regardless of whether any wallet/unlocker/disburse
	// feature is configured at all (see runPendingBalancePoller's
	// doc comment). Reuses cfg.walletStatsPollInterval rather than
	// introducing a new, separately-tunable knob for what is a very
	// cheap, always-relevant query.
	log.Printf("backend: pending-balance poller enabled, polling every %s", cfg.walletStatsPollInterval)
	go runPendingBalancePoller(ctx, repo, m, cfg.walletStatsPollInterval)

	mux := http.NewServeMux()
	// RegisterIngestionRoutes deliberately excludes GET /metrics --
	// see metricsSrv below and PROD_HARDENING_REVIEW.md finding #12.
	handler.RegisterIngestionRoutes(mux)

	// statsAPIMux carries the public, unauthenticated, read-only
	// route groups this backend's own rate limiter protects (see
	// internal/backend/ratelimit's package doc comment and
	// defaultStatsAPIRateLimitPerSecond's doc comment above for why):
	// statsHandler/networkAPIHandler/legacyConfigHandler ONLY.
	// addressMapHandler/leafFlagsHandler/legacyAPIHandler/authHandler
	// are deliberately registered directly on mux below, NOT through
	// this sub-mux, and so are never subject to this limiter.
	statsAPILimiter := ratelimit.New(cfg.statsAPIRateLimitPerSecond, cfg.statsAPIRateLimitBurst)
	if statsAPILimiter.Enabled() {
		log.Printf("backend: public stats/network/legacy-config API rate limiting ENABLED: %.2f req/s per source IP, burst %d (-stats-api-rate-limit-per-second/-stats-api-rate-limit-burst)", cfg.statsAPIRateLimitPerSecond, cfg.statsAPIRateLimitBurst)
		go statsAPILimiter.RunJanitor(ctx, statsAPIRateLimitJanitorInterval, statsAPIRateLimitJanitorMaxAge)
	} else {
		log.Print("backend: public stats/network/legacy-config API rate limiting DISABLED (-stats-api-rate-limit-per-second/GCPOOL_STATS_API_RATE_LIMIT_PER_SECOND <= 0)")
	}
	statsAPIMux := http.NewServeMux()
	statsHandler.RegisterRoutes(statsAPIMux)
	networkAPIHandler.RegisterRoutes(statsAPIMux)
	legacyConfigHandler.RegisterRoutes(statsAPIMux)
	mux.Handle("/", ratelimit.Middleware(statsAPIMux, statsAPILimiter))

	addressMapHandler.RegisterRoutes(mux)
	leafFlagsHandler.RegisterRoutes(mux)
	legacyAPIHandler.RegisterRoutes(mux)
	authHandler.RegisterRoutes(mux)

	// HTTP server hardening (PROD_HARDENING_REVIEW.md finding #12):
	// ReadHeaderTimeout alone (5s, unchanged from before this fix)
	// only bounds reading the request LINE+HEADERS -- it does
	// nothing to stop a slow body-trickle client from pinning a
	// goroutine indefinitely, even though the body's SIZE is already
	// capped (1 MiB via http.MaxBytesReader, see api/api.go's
	// readBody). ReadTimeout (30s) bounds reading the WHOLE request
	// (headers + body); WriteTimeout (30s) bounds writing the
	// response -- every real response this process ever sends is a
	// small JSON/protobuf body, so 30s is generous, not tight, for
	// either direction. IdleTimeout (120s) bounds how long an idle
	// keep-alive connection may sit between requests -- long enough
	// for a legitimate low-frequency polling client (e.g. a leaf's
	// own periodic GET /api/v1/leaf/address-flags poll), short
	// enough that a client opening many idle connections cannot pin
	// them open forever.
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// ln/netutil.LimitListener: the main listener's connection cap
	// (PROD_HARDENING_REVIEW.md finding #12 -- the leaf binaries
	// already have an analogous cap for their own listeners via
	// internal/leaflib/manager.go's ConnectionManager.MaxConnections,
	// this backend previously had none at all). Built via a raw
	// net.Listen + srv.Serve(ln) rather than srv.ListenAndServe()
	// specifically so the cap can wrap the listener itself.
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}
	if cfg.maxConnections > 0 {
		ln = netutil.LimitListener(ln, cfg.maxConnections)
		log.Printf("backend: main HTTP listener connection cap ENABLED: max %d concurrent connection(s) on %s", cfg.maxConnections, listenAddr)
	} else {
		log.Print("backend: main HTTP listener connection cap DISABLED (-max-connections/GCPOOL_MAX_CONNECTIONS <= 0)")
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("backend: listening on %s", listenAddr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// metricsSrv serves GET /metrics ALONE, on its own listener,
	// deliberately separate from srv above -- see
	// defaultMetricsListenAddr's doc comment and
	// PROD_HARDENING_REVIEW.md finding #12 for why: /metrics exposes
	// wallet_balance_atomic (the real, current hot-wallet balance)
	// and previously shared the SAME public, wildcard-bindable
	// listener as share/block ingestion. Loopback-default, matching
	// the leaf binaries' own -metrics-listen-address convention. An
	// empty -metrics-listen-addr/GCPOOL_METRICS_LISTEN_ADDR disables
	// this ENTIRELY -- GET /metrics is then not served by this
	// process at all, not silently folded back onto the main
	// listener.
	var metricsSrv *http.Server
	if cfg.metricsListenAddr != "" {
		metricsMux := http.NewServeMux()
		handler.RegisterMetricsRoute(metricsMux)
		metricsSrv = &http.Server{
			Addr:              cfg.metricsListenAddr,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			log.Printf("backend: /metrics listening on %s (separate from the main %s ingestion/API listener -- see -metrics-listen-addr/GCPOOL_METRICS_LISTEN_ADDR)", cfg.metricsListenAddr, listenAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("backend: metrics HTTP server error: %v", err)
			}
		}()
	} else {
		log.Print("backend: /metrics HTTP listener DISABLED (-metrics-listen-addr/GCPOOL_METRICS_LISTEN_ADDR is empty) -- this process will not serve /metrics anywhere")
	}

	select {
	case <-ctx.Done():
		log.Print("backend: shutdown signal received, draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if metricsSrv != nil {
			if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
				log.Printf("backend: shutting down metrics http server: %v", err)
			}
		}
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down http server: %w", err)
		}
		return <-errCh
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	}
}
