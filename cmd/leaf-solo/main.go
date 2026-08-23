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

	// trustEnabled/trustThreshold/trustPenalty/trustChange/trustMin
	// configure the real, legacy-ported probabilistic
	// RandomX-validation-skip mechanism for RXT/RXM shares (see
	// internal/leaflib/solo/trust.go's doc comment for the full
	// reference algorithm and citation). Disabled by default (every
	// share always fully validated, identical to this mechanism not
	// existing). Only ever consulted for RXT/RXM jobs; a SHA3X/C29
	// leaf-solo process can enable this flag with zero effect, since
	// isRandomXFamily gates it at the actual submit-handling call
	// site, not here.
	trustEnabled   bool
	trustThreshold int
	trustPenalty   int
	trustChange    int
	trustMin       int

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
}

func loadConfig() config {
	cfg := config{}

	flag.StringVar(&cfg.nodeGRPCAddress, "node-grpc-address", envOr("LEAF_NODE_GRPC_ADDRESS", ""), "Tari base node GRPC address (host:port). REQUIRED when -coin=tari (the default); ignored for -coin=monero. Env: LEAF_NODE_GRPC_ADDRESS")
	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_SOLO_LISTEN_ADDRESS", ":4444"), "miner-facing TCP listen address. Env: LEAF_SOLO_LISTEN_ADDRESS")
	flag.StringVar(&cfg.payoutAddress, "payout-address", envOr("LEAF_SOLO_PAYOUT_ADDRESS", ""), "solo payout address; found-block coinbase rewards go here. Env: LEAF_SOLO_PAYOUT_ADDRESS")
	flag.StringVar(&cfg.network, "network", envOr("LEAF_SOLO_NETWORK", "testnet"), "network tag for share/diagnostic records: mainnet|testnet. Env: LEAF_SOLO_NETWORK")
	flag.StringVar(&cfg.coin, "coin", envOr("LEAF_SOLO_COIN", "tari"), "which coin/PoW family this leaf-solo process serves: tari (default, unchanged behavior) or monero (real MoneroNodeClient against a real monerod JSON-RPC daemon -- see -monerod-url). Env: LEAF_SOLO_COIN")
	flag.StringVar(&cfg.monerodURL, "monerod-url", envOr("LEAF_SOLO_MONEROD_URL", ""), "real monerod JSON-RPC base URL (e.g. http://148.163.90.157:28081), no trailing slash or /json_rpc suffix required. REQUIRED when -coin=monero; ignored for -coin=tari. Env: LEAF_SOLO_MONEROD_URL")
	flag.BoolVar(&cfg.trustEnabled, "trust-enabled", envOr("LEAF_SOLO_TRUST_ENABLED", "false") == "true", "enable the real, legacy-ported probabilistic RandomX-validation-skip mechanism for RXT/RXM shares (see internal/leaflib/solo/trust.go). Disabled by default -- every share is always fully, cryptographically validated. Has no effect for SHA3X/C29. Env: LEAF_SOLO_TRUST_ENABLED (\"true\" to enable)")
	flag.IntVar(&cfg.trustThreshold, "trust-threshold", envOrInt("LEAF_SOLO_TRUST_THRESHOLD", 0), "real trust-ramp threshold gate (see trust.go's TrustConfig.Threshold) -- 0/unset uses the documented default (10). Env: LEAF_SOLO_TRUST_THRESHOLD")
	flag.IntVar(&cfg.trustPenalty, "trust-penalty", envOrInt("LEAF_SOLO_TRUST_PENALTY", 0), "real trust-ramp penalty gate, re-armed after any rejected share (see trust.go's TrustConfig.Penalty) -- 0/unset uses the documented default (30). Env: LEAF_SOLO_TRUST_PENALTY")
	flag.IntVar(&cfg.trustChange, "trust-change", envOrInt("LEAF_SOLO_TRUST_CHANGE", 0), "real per-accepted-share probability decrement (see trust.go's TrustConfig.Change) -- 0/unset uses the documented default (1). Env: LEAF_SOLO_TRUST_CHANGE")
	flag.IntVar(&cfg.trustMin, "trust-min", envOrInt("LEAF_SOLO_TRUST_MIN", 0), "real probability floor, ensuring full validation never stops occurring entirely once ramped in (see trust.go's TrustConfig.Min) -- 0/unset uses the documented default (20). Env: LEAF_SOLO_TRUST_MIN")
	flag.StringVar(&cfg.algo, "algo", envOr("LEAF_SOLO_ALGO", "sha3x"), "which single mining algorithm this leaf-solo process serves: sha3x (default), c29, or rxt -- for -coin=tari only. Ignored (always ALGO_RXM/plain RandomX) when -coin=monero. Env: LEAF_SOLO_ALGO")
	flag.StringVar(&cfg.randomXServiceURL, "randomx-service-url", envOr("LEAF_SOLO_RANDOMX_SERVICE_URL", "http://127.0.0.1:39093"), "RandomX-verification HTTP daemon address (consulted for -algo=rxt, and for -coin=monero's real RandomX/rx validation -- both share the same real randomx-service-backed RandomXValidator). Env: LEAF_SOLO_RANDOMX_SERVICE_URL")

	// LEAF_SOLO_STARTING_DIFFICULTY replaces the old, now-removed
	// LEAF_SOLO_DIFFICULTY (which used to be THE only difficulty any
	// session ever had). It's still read as a fallback below for a
	// smooth migration, but LEAF_SOLO_STARTING_DIFFICULTY takes
	// precedence when both are set.
	flag.Uint64Var(&cfg.startingDifficulty, "starting-difficulty", envOrUint64Fallback("LEAF_SOLO_STARTING_DIFFICULTY", "LEAF_SOLO_DIFFICULTY", 10000), "starting share difficulty for a newly-connected session; vardiff adjusts it from here based on that session's own accept history. Env: LEAF_SOLO_STARTING_DIFFICULTY (falls back to legacy LEAF_SOLO_DIFFICULTY if unset)")
	flag.StringVar(&cfg.portsRaw, "ports", envOr("LEAF_SOLO_PORTS", ""), "comma-separated list of address:difficulty[:desc] port tiers, e.g. ':4444:10000:low-diff,:4445:1000000:high-diff'. When set, this REPLACES -listen-address/-starting-difficulty entirely (they are ignored). When unset (the default), -listen-address/-starting-difficulty are used as a single implicit port tier, preserving the pre-multi-port behavior exactly. Env: LEAF_SOLO_PORTS")
	flag.Uint64Var(&cfg.minDifficulty, "min-difficulty", envOrUint64("LEAF_SOLO_MIN_DIFFICULTY", 100), "absolute floor vardiff will never retarget below. Env: LEAF_SOLO_MIN_DIFFICULTY")
	flag.Uint64Var(&cfg.maxDifficulty, "max-difficulty", envOrUint64("LEAF_SOLO_MAX_DIFFICULTY", 1_000_000_000), "absolute ceiling vardiff will never retarget above. Env: LEAF_SOLO_MAX_DIFFICULTY")
	flag.IntVar(&cfg.vardiffTargetTime, "vardiff-target-time", envOrInt("LEAF_SOLO_VARDIFF_TARGET_TIME", 30), "seconds between shares vardiff aims for. Env: LEAF_SOLO_VARDIFF_TARGET_TIME")
	flag.DurationVar(&cfg.vardiffInterval, "vardiff-retarget-interval", envOrDuration("LEAF_SOLO_VARDIFF_RETARGET_INTERVAL", 60*time.Second), "how often each session's own vardiff retarget timer fires (also the minimum connection age before a session's first retarget). Env: LEAF_SOLO_VARDIFF_RETARGET_INTERVAL")

	flag.DurationVar(&cfg.refreshInterval, "refresh-interval", envOrDuration("LEAF_SOLO_REFRESH_INTERVAL", 30*time.Second), "unconditional block-template refresh interval. Env: LEAF_SOLO_REFRESH_INTERVAL")
	flag.DurationVar(&cfg.tipPollInterval, "tip-poll-interval", envOrDuration("LEAF_SOLO_TIP_POLL_INTERVAL", 5*time.Second), "chain-tip poll interval (forces an immediate refresh on tip movement). Env: LEAF_SOLO_TIP_POLL_INTERVAL")

	// LEAF_SOLO_JOB_MAX_AGE is the SECURITY-FIX real per-job expiry
	// threshold (see solo.JobManagerConfig.JobMaxAge's doc comment):
	// a submit against a job older than this, independent of whether
	// InvalidateAll has run, is rejected outright. Mirrors
	// go-tari-sha3x-solo-stratum's CleanMinerJobs default of 6
	// minutes.
	flag.DurationVar(&cfg.jobMaxAge, "job-max-age", envOrDuration("LEAF_SOLO_JOB_MAX_AGE", 6*time.Minute), "real per-job expiry threshold, independent of tip-invalidation; a submit against an older job is rejected as expired. Env: LEAF_SOLO_JOB_MAX_AGE")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_SOLO_MAX_CONNECTIONS", 0), "max concurrent miner connections, 0 = unlimited. Env: LEAF_SOLO_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_SOLO_IDLE_TIMEOUT", 2*time.Minute), "rolling per-connection idle timeout. Env: LEAF_SOLO_IDLE_TIMEOUT")

	flag.StringVar(&cfg.metricsListenAddress, "metrics-listen-address", envOr("LEAF_SOLO_METRICS_LISTEN_ADDRESS", ":9600"), "HTTP listen address for /metrics (Prometheus) and the stats page. Separate from -listen-address (the miner-facing stratum port). Set to empty string to disable. Env: LEAF_SOLO_METRICS_LISTEN_ADDRESS")
	flag.IntVar(&cfg.maxAddressLabels, "max-address-labels", envOrInt("LEAF_SOLO_MAX_ADDRESS_LABELS", 0), "cap on distinct payment-address labels tracked by leaf_miners_by_address and the stats page's per-address breakdown (0 = package default). Env: LEAF_SOLO_MAX_ADDRESS_LABELS")

	flag.Parse()
	return cfg
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
// "address:difficulty:desc" entry. address itself is free to contain
// colons (bare ":4444", "0.0.0.0:4444", "[::1]:4444") — difficulty
// (and an optional trailing desc) are peeled off the END of the
// colon-separated fields rather than assuming address has no colons of
// its own.
func parsePortEntry(raw string) (solo.PortConfig, error) {
	fields := strings.Split(raw, ":")
	if len(fields) < 2 {
		return solo.PortConfig{}, errors.New(`expected "address:difficulty" or "address:difficulty:desc"`)
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

func main() {
	cfg := loadConfig()
	logger := log.New(os.Stdout, "leaf-solo: ", log.LstdFlags|log.Lmicroseconds)

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

	// Real coin-conditional NodeClient construction: both
	// implementations satisfy the exact same coin-agnostic
	// solo.NodeClient interface (node.go), so everything downstream
	// (JobManager, Server, session.go's handleSubmit) is unaffected by
	// which one gets constructed here.
	var node solo.NodeClient
	if isMoneroCoin(cfg.coin) {
		logger.Printf("connecting to Monero daemon (monerod JSON-RPC) at %s", cfg.monerodURL)
		node = solo.NewMoneroNodeClient(cfg.monerodURL)
	} else {
		logger.Printf("connecting to Tari base node GRPC at %s", cfg.nodeGRPCAddress)
		node = solo.NewGRPCNodeClient(cfg.nodeGRPCAddress)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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
		Logger:           logger,
	})

	logger.Println("probing base node connectivity...")
	if err := jobManager.Probe(ctx); err != nil {
		logger.Fatalf("base node connectivity probe failed: %v", err)
	}
	jobManager.Start(ctx)

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

	if cfg.metricsListenAddress != "" {
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
