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

	flag.StringVar(&cfg.nodeGRPCAddress, "node-grpc-address", envOr("LEAF_NODE_GRPC_ADDRESS", ""), "Tari base node GRPC address (host:port). Env: LEAF_NODE_GRPC_ADDRESS")
	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_SOLO_LISTEN_ADDRESS", ":4444"), "miner-facing TCP listen address. Env: LEAF_SOLO_LISTEN_ADDRESS")
	flag.StringVar(&cfg.payoutAddress, "payout-address", envOr("LEAF_SOLO_PAYOUT_ADDRESS", ""), "solo payout address; found-block coinbase rewards go here. Env: LEAF_SOLO_PAYOUT_ADDRESS")
	flag.StringVar(&cfg.network, "network", envOr("LEAF_SOLO_NETWORK", "testnet"), "network tag for share/diagnostic records: mainnet|testnet. Env: LEAF_SOLO_NETWORK")

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

func main() {
	cfg := loadConfig()
	logger := log.New(os.Stdout, "leaf-solo: ", log.LstdFlags|log.Lmicroseconds)

	if cfg.nodeGRPCAddress == "" {
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
	logger.Printf("connecting to Tari base node GRPC at %s", cfg.nodeGRPCAddress)

	node := solo.NewGRPCNodeClient(cfg.nodeGRPCAddress)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	jobManager := solo.NewJobManager(solo.JobManagerConfig{
		Node:          node,
		PayoutAddress: cfg.payoutAddress,
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

	sha3xValidator := validator.NewSHA3XValidator()
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
	server := solo.NewServer(cm, jobManager, node, sha3xValidator, networkFromString(cfg.network), logger, vardiffCfg)
	defer server.Shutdown()

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
