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
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/direct"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
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
	monerodURL      string
	algo            string
	poolType        string

	randomXServiceURL string

	startingDifficulty uint64
	portsRaw           string
	minDifficulty      uint64
	maxDifficulty      uint64
	vardiffTargetTime  int
	vardiffInterval    time.Duration

	refreshInterval time.Duration
	tipPollInterval time.Duration
	jobMaxAge       time.Duration

	maxConnections int
	idleTimeout    time.Duration

	metricsListenAddress string
	maxAddressLabels     int

	// backendBaseURL / backendAuth* configure the real
	// HTTPProtobufTransport this leaf forwards every validated share/
	// block to — this leaf's whole reason for existing (see this
	// binary's own doc comment).
	backendBaseURL      string
	backendAuthHeader   string
	backendAuthValue    string
	backendShareTimeout time.Duration
	backendBlockTimeout time.Duration

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
}

func loadConfig() config {
	cfg := config{}

	flag.StringVar(&cfg.nodeGRPCAddress, "node-grpc-address", envOr("LEAF_NODE_GRPC_ADDRESS", ""), "Tari base node GRPC address (host:port); also the primary template-source AND is always included in the multi-node submit set. REQUIRED when -coin=tari (the default); ignored for -coin=monero. Env: LEAF_NODE_GRPC_ADDRESS")
	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_DIRECT_LISTEN_ADDRESS", ":4444"), "miner-facing TCP listen address. Env: LEAF_DIRECT_LISTEN_ADDRESS")
	flag.StringVar(&cfg.payoutAddress, "payout-address", envOr("LEAF_DIRECT_PAYOUT_ADDRESS", ""), "pool payout/coinbase address for fetched block templates. Env: LEAF_DIRECT_PAYOUT_ADDRESS")
	flag.StringVar(&cfg.network, "network", envOr("LEAF_DIRECT_NETWORK", "testnet"), "network tag for share/block records: mainnet|testnet. Env: LEAF_DIRECT_NETWORK")
	flag.StringVar(&cfg.coin, "coin", envOr("LEAF_DIRECT_COIN", "tari"), "which coin/PoW family this leaf-direct process serves: tari (default, unchanged behavior) or monero (real MoneroNodeClient against a real monerod JSON-RPC daemon -- see -monerod-url). Env: LEAF_DIRECT_COIN")
	flag.StringVar(&cfg.monerodURL, "monerod-url", envOr("LEAF_DIRECT_MONEROD_URL", ""), "real monerod JSON-RPC base URL (e.g. http://148.163.90.157:28081). REQUIRED when -coin=monero; ignored for -coin=tari. Env: LEAF_DIRECT_MONEROD_URL")
	flag.BoolVar(&cfg.trustEnabled, "trust-enabled", envOr("LEAF_DIRECT_TRUST_ENABLED", "false") == "true", "enable the real, legacy-ported probabilistic RandomX-validation-skip mechanism for RXT/RXM shares (see internal/leaflib/solo/trust.go) -- mirrors leaf-solo's identical flag exactly. Disabled by default. Env: LEAF_DIRECT_TRUST_ENABLED (\"true\" to enable)")
	flag.IntVar(&cfg.trustThreshold, "trust-threshold", envOrInt("LEAF_DIRECT_TRUST_THRESHOLD", 0), "real trust-ramp threshold gate -- 0/unset uses the documented default (10). Env: LEAF_DIRECT_TRUST_THRESHOLD")
	flag.IntVar(&cfg.trustPenalty, "trust-penalty", envOrInt("LEAF_DIRECT_TRUST_PENALTY", 0), "real trust-ramp penalty gate, re-armed after any rejected share -- 0/unset uses the documented default (30). Env: LEAF_DIRECT_TRUST_PENALTY")
	flag.IntVar(&cfg.trustChange, "trust-change", envOrInt("LEAF_DIRECT_TRUST_CHANGE", 0), "real per-accepted-share probability decrement -- 0/unset uses the documented default (1). Env: LEAF_DIRECT_TRUST_CHANGE")
	flag.IntVar(&cfg.trustMin, "trust-min", envOrInt("LEAF_DIRECT_TRUST_MIN", 0), "real probability floor -- 0/unset uses the documented default (20). Env: LEAF_DIRECT_TRUST_MIN")
	flag.StringVar(&cfg.algo, "algo", envOr("LEAF_DIRECT_ALGO", "sha3x"), "which single mining algorithm this leaf-direct process serves: sha3x (default), c29, or rxt -- for -coin=tari only. Ignored (always ALGO_RXM/plain RandomX) when -coin=monero. Env: LEAF_DIRECT_ALGO")
	flag.StringVar(&cfg.poolType, "pool-type", envOr("LEAF_DIRECT_POOL_TYPE", ""), "real pool payout model stamped onto every share/block forwarded to the backend: pplns|pps|prop|solo. REQUIRED (no safe silent default -- determines real payout accounting semantics). Env: LEAF_DIRECT_POOL_TYPE")
	flag.StringVar(&cfg.randomXServiceURL, "randomx-service-url", envOr("LEAF_DIRECT_RANDOMX_SERVICE_URL", "http://127.0.0.1:39093"), "RandomX-verification HTTP daemon address (only consulted when -algo=rxt). Env: LEAF_DIRECT_RANDOMX_SERVICE_URL")

	flag.Uint64Var(&cfg.startingDifficulty, "starting-difficulty", envOrUint64("LEAF_DIRECT_STARTING_DIFFICULTY", 10000), "starting share difficulty for a newly-connected session. Env: LEAF_DIRECT_STARTING_DIFFICULTY")
	flag.StringVar(&cfg.portsRaw, "ports", envOr("LEAF_DIRECT_PORTS", ""), "comma-separated list of address:difficulty[:desc] port tiers. When unset, -listen-address/-starting-difficulty are used as a single implicit tier. Env: LEAF_DIRECT_PORTS")
	flag.Uint64Var(&cfg.minDifficulty, "min-difficulty", envOrUint64("LEAF_DIRECT_MIN_DIFFICULTY", 100), "absolute floor vardiff will never retarget below. Env: LEAF_DIRECT_MIN_DIFFICULTY")
	flag.Uint64Var(&cfg.maxDifficulty, "max-difficulty", envOrUint64("LEAF_DIRECT_MAX_DIFFICULTY", 1_000_000_000), "absolute ceiling vardiff will never retarget above. Env: LEAF_DIRECT_MAX_DIFFICULTY")
	flag.IntVar(&cfg.vardiffTargetTime, "vardiff-target-time", envOrInt("LEAF_DIRECT_VARDIFF_TARGET_TIME", 30), "seconds between shares vardiff aims for. Env: LEAF_DIRECT_VARDIFF_TARGET_TIME")
	flag.DurationVar(&cfg.vardiffInterval, "vardiff-retarget-interval", envOrDuration("LEAF_DIRECT_VARDIFF_RETARGET_INTERVAL", 60*time.Second), "how often each session's own vardiff retarget timer fires. Env: LEAF_DIRECT_VARDIFF_RETARGET_INTERVAL")

	flag.DurationVar(&cfg.refreshInterval, "refresh-interval", envOrDuration("LEAF_DIRECT_REFRESH_INTERVAL", 30*time.Second), "unconditional block-template refresh interval. Env: LEAF_DIRECT_REFRESH_INTERVAL")
	flag.DurationVar(&cfg.tipPollInterval, "tip-poll-interval", envOrDuration("LEAF_DIRECT_TIP_POLL_INTERVAL", 5*time.Second), "chain-tip poll interval. Env: LEAF_DIRECT_TIP_POLL_INTERVAL")
	flag.DurationVar(&cfg.jobMaxAge, "job-max-age", envOrDuration("LEAF_DIRECT_JOB_MAX_AGE", 6*time.Minute), "real per-job expiry threshold, independent of tip-invalidation. Env: LEAF_DIRECT_JOB_MAX_AGE")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_DIRECT_MAX_CONNECTIONS", 0), "max concurrent miner connections, 0 = unlimited. Env: LEAF_DIRECT_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_DIRECT_IDLE_TIMEOUT", 2*time.Minute), "rolling per-connection idle timeout. Env: LEAF_DIRECT_IDLE_TIMEOUT")

	flag.StringVar(&cfg.metricsListenAddress, "metrics-listen-address", envOr("LEAF_DIRECT_METRICS_LISTEN_ADDRESS", ":9601"), "HTTP listen address for /metrics. Empty disables it. Env: LEAF_DIRECT_METRICS_LISTEN_ADDRESS")
	flag.IntVar(&cfg.maxAddressLabels, "max-address-labels", envOrInt("LEAF_DIRECT_MAX_ADDRESS_LABELS", 0), "cap on distinct payment-address labels tracked by metrics (0 = package default). Env: LEAF_DIRECT_MAX_ADDRESS_LABELS")

	flag.StringVar(&cfg.backendBaseURL, "backend-base-url", envOr("LEAF_DIRECT_BACKEND_BASE_URL", ""), "real backend base URL every validated share/block is forwarded to over HTTP+Protobuf. REQUIRED. Env: LEAF_DIRECT_BACKEND_BASE_URL")
	flag.StringVar(&cfg.backendAuthHeader, "backend-auth-header", envOr("LEAF_DIRECT_BACKEND_AUTH_HEADER", ""), "optional shared-secret/bearer auth header name sent with every backend request. Env: LEAF_DIRECT_BACKEND_AUTH_HEADER")
	flag.StringVar(&cfg.backendAuthValue, "backend-auth-value", envOr("LEAF_DIRECT_BACKEND_AUTH_VALUE", ""), "value for -backend-auth-header. Env: LEAF_DIRECT_BACKEND_AUTH_VALUE")
	flag.DurationVar(&cfg.backendShareTimeout, "backend-share-timeout", envOrDuration("LEAF_DIRECT_BACKEND_SHARE_TIMEOUT", 5*time.Second), "per-call timeout forwarding a share to the backend. Env: LEAF_DIRECT_BACKEND_SHARE_TIMEOUT")
	flag.DurationVar(&cfg.backendBlockTimeout, "backend-block-timeout", envOrDuration("LEAF_DIRECT_BACKEND_BLOCK_TIMEOUT", 10*time.Second), "per-call timeout reporting a found block to the backend. Env: LEAF_DIRECT_BACKEND_BLOCK_TIMEOUT")
	flag.DurationVar(&cfg.addressFlagsPollInterval, "address-flags-poll-interval", envOrDuration("LEAF_DIRECT_ADDRESS_FLAGS_POLL_INTERVAL", 30*time.Second), "how often the backend's GET /api/v1/leaf/address-flags endpoint is polled for manual ban/forced-minimum-difficulty state (see internal/leaflib/addressflags). Env: LEAF_DIRECT_ADDRESS_FLAGS_POLL_INTERVAL")

	flag.StringVar(&cfg.submitNodesRaw, "submit-nodes", envOr("LEAF_DIRECT_SUBMIT_NODES", ""), "comma-separated list of ADDITIONAL Tari base node GRPC addresses (beyond -node-grpc-address, which is always included) to submit a genuine block find to, in real parallel. Env: LEAF_DIRECT_SUBMIT_NODES")

	flag.StringVar(&cfg.relayNATSURL, "relay-nats-url", envOr("LEAF_DIRECT_RELAY_NATS_URL", ""), "NATS server URL for the best-effort found-block relay broadcast/resubmit mechanism. Empty (default) fully disables the relay -- a complete no-op, never required. Env: LEAF_DIRECT_RELAY_NATS_URL")
	flag.StringVar(&cfg.relaySubject, "relay-subject", envOr("LEAF_DIRECT_RELAY_SUBJECT", ""), "NATS subject for the relay (empty = relay package default). Env: LEAF_DIRECT_RELAY_SUBJECT")

	flag.Parse()
	return cfg
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
	if len(fields) < 2 {
		return solo.PortConfig{}, errors.New(`expected "address:difficulty" or "address:difficulty:desc"`)
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
	return solo.PortConfig{Address: address, Difficulty: difficulty, PortDesc: desc}, nil
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

// isMoneroCoin mirrors leaf-solo's own isMoneroCoin exactly -- see
// that function's doc comment.
func isMoneroCoin(coin string) bool {
	return strings.EqualFold(strings.TrimSpace(coin), "monero")
}

// resolveAlgo mirrors leaf-solo's own resolveAlgo exactly: for
// -coin=monero, always ALGO_RXM regardless of -algo; for -coin=tari
// (the default), algoFromString(cfg.algo) exactly as before Monero
// support existed.
func resolveAlgo(cfg config) poolpb.Algo {
	if isMoneroCoin(cfg.coin) {
		return poolpb.Algo_ALGO_RXM
	}
	return algoFromString(cfg.algo)
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

func main() {
	cfg := loadConfig()
	logger := log.New(os.Stdout, "leaf-direct: ", log.LstdFlags|log.Lmicroseconds)

	if isMoneroCoin(cfg.coin) {
		if strings.TrimSpace(cfg.monerodURL) == "" {
			logger.Fatal("LEAF_DIRECT_MONEROD_URL (or -monerod-url) is required when -coin=monero")
		}
		if cfg.nodeGRPCAddress != "" {
			logger.Printf("note: -coin=monero -- ignoring -node-grpc-address/LEAF_NODE_GRPC_ADDRESS (%s); no Tari GRPC daemon is involved", cfg.nodeGRPCAddress)
		}
		if cfg.submitNodesRaw != "" {
			logger.Printf("note: -coin=monero -- ignoring -submit-nodes/LEAF_DIRECT_SUBMIT_NODES (%s); real multi-node Monero block submission is a known, deferred gap (MultiNodeSubmitter is Tari-GRPC-specific) -- see this leaf's own doc comment. Monero block finds submit via a single real MoneroNodeClient.SubmitBlock call instead.", cfg.submitNodesRaw)
		}
	} else if cfg.nodeGRPCAddress == "" {
		logger.Fatal("LEAF_NODE_GRPC_ADDRESS (or -node-grpc-address) is required")
	}
	if cfg.payoutAddress == "" {
		logger.Fatal("LEAF_DIRECT_PAYOUT_ADDRESS (or -payout-address) is required")
	}
	if cfg.backendBaseURL == "" {
		logger.Fatal("LEAF_DIRECT_BACKEND_BASE_URL (or -backend-base-url) is required -- leaf-direct's whole purpose is forwarding validated shares/blocks to the real backend")
	}
	poolType, ok := poolTypeFromString(cfg.poolType)
	if !ok {
		logger.Fatalf("LEAF_DIRECT_POOL_TYPE (or -pool-type) is required and must be one of pplns|pps|prop|solo, got %q -- the backend correctly rejects any share/block whose pool_type is left unset", cfg.poolType)
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

	// Real coin-conditional NodeClient construction. For -coin=tari
	// (default), this is direct.NewNodeClient's own real
	// per-call-injectable GRPC client (unchanged). For -coin=monero,
	// this is solo.NewMoneroNodeClient -- the SAME real implementation
	// leaf-solo uses, satisfying the identical coin-agnostic
	// solo.NodeClient interface direct.NodeClient also implements, so
	// JobManager/Server/session.go's handleSubmit are unaffected by
	// which one gets constructed here.
	var node solo.NodeClient
	if isMoneroCoin(cfg.coin) {
		logger.Printf("connecting to Monero daemon (monerod JSON-RPC) at %s", cfg.monerodURL)
		node = solo.NewMoneroNodeClient(cfg.monerodURL)
	} else {
		logger.Printf("connecting to primary Tari base node GRPC at %s", cfg.nodeGRPCAddress)
		tariNode, err := direct.NewNodeClient(cfg.nodeGRPCAddress)
		if err != nil {
			logger.Fatalf("failed to construct primary node client for %s: %v", cfg.nodeGRPCAddress, err)
		}
		node = tariNode
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	jobManager := solo.NewJobManager(solo.JobManagerConfig{
		Node: node, PayoutAddress: cfg.payoutAddress, Algo: resolveAlgo(cfg),
		StaticDifficulty: ports[0].Difficulty, RefreshInterval: cfg.refreshInterval,
		TipPollInterval: cfg.tipPollInterval, JobMaxAge: cfg.jobMaxAge, Logger: logger,
	})

	logger.Println("probing base node connectivity...")
	if err := jobManager.Probe(ctx); err != nil {
		logger.Fatalf("base node connectivity probe failed: %v", err)
	}
	jobManager.Start(ctx)

	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{
		MaxConnections: cfg.maxConnections, IdleTimeout: cfg.idleTimeout,
	})

	validators := validator.NewRegistry(cfg.randomXServiceURL)
	vardiffCfg := solo.VardiffConfig{
		MinDifficulty: cfg.minDifficulty, MaxDifficulty: cfg.maxDifficulty,
		TargetTime: cfg.vardiffTargetTime, RetargetInterval: cfg.vardiffInterval,
	}

	// Real backend transport -- the genuinely new wiring point vs.
	// leaf-solo (see this binary's own doc comment).
	backendTransport, err := transport.NewHTTPProtobufTransport(transport.HTTPProtobufTransportConfig{
		BaseURL: cfg.backendBaseURL, AuthHeaderName: cfg.backendAuthHeader, AuthHeaderValue: cfg.backendAuthValue,
		ShareTimeout: cfg.backendShareTimeout, BlockTimeout: cfg.backendBlockTimeout,
	})
	if err != nil {
		logger.Fatalf("failed to construct backend transport: %v", err)
	}
	defer func() { _ = backendTransport.Close() }()
	logger.Printf("forwarding validated shares/blocks to backend at %s", cfg.backendBaseURL)

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
	if !isMoneroCoin(cfg.coin) {
		submitAddrs := resolveSubmitNodes(cfg.nodeGRPCAddress, cfg.submitNodesRaw)
		var err error
		multiSubmit, err = direct.NewMultiNodeSubmitter(submitAddrs, logger)
		if err != nil {
			logger.Fatalf("failed to construct multi-node block submitter: %v", err)
		}
		logger.Printf("multi-node block submit configured for %d node(s): %v", len(submitAddrs), submitAddrs)
	} else {
		logger.Printf("multi-node block submit disabled for -coin=monero (known, deferred gap -- single-node MoneroNodeClient.SubmitBlock is the real, working priority path)")
	}
	defer func() {
		if multiSubmit != nil {
			_ = multiSubmit.Close()
		}
	}()

	// Optional, best-effort NATS relay -- a complete no-op if
	// LEAF_DIRECT_RELAY_NATS_URL is unset (see internal/leaflib/relay).
	blockRelay := relay.NewRelay(relay.Config{URL: cfg.relayNATSURL, Subject: cfg.relaySubject, Logger: logger})
	defer func() { _ = blockRelay.Close() }()
	if blockRelay.Enabled() {
		logger.Printf("NATS relay enabled at %s", cfg.relayNATSURL)
	} else {
		logger.Printf("NATS relay disabled (LEAF_DIRECT_RELAY_NATS_URL is empty) -- complete no-op, never required for correctness")
	}

	server := direct.NewServer(direct.ServerConfig{
		ConnectionManager: cm, JobManager: jobManager, Node: node, Validators: validators,
		Network: networkFromString(cfg.network), Logger: logger, Vardiff: vardiffCfg,
		Transport: backendTransport, MultiSubmit: multiSubmit, Relay: blockRelay,
		Algo: algoFromString(cfg.algo), PoolType: poolType,
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

	// Real, manual ban/forced-minimum-difficulty enforcement (see
	// internal/leaflib/addressflags's package doc comment). Unlike
	// leaf-solo (which has no backend to poll), leaf-direct always
	// polls the real backend it is already configured to forward
	// shares/blocks to.
	addressFlagsCache := addressflags.NewCache(
		addressflags.NewHTTPSource(cfg.backendBaseURL, cfg.backendAuthHeader, cfg.backendAuthValue),
		cfg.addressFlagsPollInterval, logger,
	)
	addressFlagsCache.Start(ctx)
	server.EnableAddressFlags(addressFlagsCache)
	logger.Printf("manual ban/forced-minimum-difficulty enforcement ENABLED, polling %s%s every %s", cfg.backendBaseURL, "/api/v1/leaf/address-flags", cfg.addressFlagsPollInterval)

	if cfg.metricsListenAddress != "" {
		server.EnableMetrics(version, cfg.maxAddressLabels)
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
	for _, p := range ports {
		ln, err := net.Listen("tcp", p.Address)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			logger.Fatalf("failed to listen on %s: %v", p.Address, err)
		}
		listeners = append(listeners, ln)
		logger.Printf("listening for miners on %s (starting difficulty %d)", p.Address, p.Difficulty)
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
