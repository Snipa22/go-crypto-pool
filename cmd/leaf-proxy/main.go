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
// NOT ported from the legacy xmr-node-proxy reference (per explicit
// instruction): the 1% developer-donation-pool skim (devPool), and
// the Node.js cluster/worker multi-process architecture — this is a
// single Go process using goroutines + internal/leaflib's
// ConnectionManager, which comfortably out-scales the legacy's
// per-worker sharding model without needing to replicate it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy"
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
	minDifficulty      uint64
	maxDifficulty      uint64
	vardiffTargetTime  int
	vardiffInterval    time.Duration
	jobMaxAge          time.Duration

	randomXServiceURL string

	maxConnections int
	idleTimeout    time.Duration

	dialTimeout    time.Duration
	requestTimeout time.Duration
}

func loadConfig() config {
	cfg := config{}

	flag.StringVar(&cfg.upstreamHost, "upstream-host", envOr("LEAF_PROXY_UPSTREAM_HOST", "pool.supportxmr.com"), "real upstream Monero-family pool hostname. Env: LEAF_PROXY_UPSTREAM_HOST")
	flag.IntVar(&cfg.upstreamPort, "upstream-port", envOrInt("LEAF_PROXY_UPSTREAM_PORT", 7777), "real upstream pool stratum port (SupportXMR: 3333 low-diff, 5555 medium-diff, 7777 high-diff, 9000 TLS -- see this file's doc comment). Env: LEAF_PROXY_UPSTREAM_PORT")
	flag.BoolVar(&cfg.upstreamTLS, "upstream-tls", envOrBool("LEAF_PROXY_UPSTREAM_TLS", false), "dial the upstream pool over TLS. Env: LEAF_PROXY_UPSTREAM_TLS")
	flag.BoolVar(&cfg.upstreamInsecure, "upstream-tls-insecure-skip-verify", envOrBool("LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY", false), "skip TLS certificate verification for the upstream pool (testing only). Env: LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY")
	flag.StringVar(&cfg.upstreamLogin, "upstream-login", envOr("LEAF_PROXY_UPSTREAM_LOGIN", ""), "real XMR payout address to log in to the upstream pool with. Env: LEAF_PROXY_UPSTREAM_LOGIN")
	flag.StringVar(&cfg.upstreamPass, "upstream-pass", envOr("LEAF_PROXY_UPSTREAM_PASS", "go-crypto-pool-leaf-proxy"), "real upstream pool worker identifier/password. Env: LEAF_PROXY_UPSTREAM_PASS")
	flag.StringVar(&cfg.upstreamAgent, "upstream-agent", envOr("LEAF_PROXY_UPSTREAM_AGENT", fmt.Sprintf("go-crypto-pool-leaf-proxy/%s", version)), "advanced-mining-client agent string sent on upstream login. Env: LEAF_PROXY_UPSTREAM_AGENT")

	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_PROXY_LISTEN_ADDRESS", ":5555"), "downstream miner-facing TCP listen address. Env: LEAF_PROXY_LISTEN_ADDRESS")
	flag.Uint64Var(&cfg.startingDifficulty, "starting-difficulty", envOrUint64("LEAF_PROXY_STARTING_DIFFICULTY", 10000), "starting downstream share difficulty; vardiff adjusts it from here. Env: LEAF_PROXY_STARTING_DIFFICULTY")
	flag.Uint64Var(&cfg.minDifficulty, "min-difficulty", envOrUint64("LEAF_PROXY_MIN_DIFFICULTY", 100), "absolute floor vardiff will never retarget below. Env: LEAF_PROXY_MIN_DIFFICULTY")
	flag.Uint64Var(&cfg.maxDifficulty, "max-difficulty", envOrUint64("LEAF_PROXY_MAX_DIFFICULTY", 1_000_000_000), "absolute ceiling vardiff will never retarget above. Env: LEAF_PROXY_MAX_DIFFICULTY")
	flag.IntVar(&cfg.vardiffTargetTime, "vardiff-target-time", envOrInt("LEAF_PROXY_VARDIFF_TARGET_TIME", 30), "seconds between shares vardiff aims for. Env: LEAF_PROXY_VARDIFF_TARGET_TIME")
	flag.DurationVar(&cfg.vardiffInterval, "vardiff-retarget-interval", envOrDuration("LEAF_PROXY_VARDIFF_RETARGET_INTERVAL", 60*time.Second), "how often each downstream session's own vardiff retarget timer fires. Env: LEAF_PROXY_VARDIFF_RETARGET_INTERVAL")
	flag.DurationVar(&cfg.jobMaxAge, "job-max-age", envOrDuration("LEAF_PROXY_JOB_MAX_AGE", 6*time.Minute), "real per-job expiry threshold; a submit against an older job is rejected. Env: LEAF_PROXY_JOB_MAX_AGE")

	flag.StringVar(&cfg.randomXServiceURL, "randomx-service-url", envOr("LEAF_PROXY_RANDOMX_SERVICE_URL", "http://127.0.0.1:39093"), "RandomX-verification HTTP daemon address used for real local re-validation. Env: LEAF_PROXY_RANDOMX_SERVICE_URL")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_PROXY_MAX_CONNECTIONS", 0), "max concurrent downstream miner connections, 0 = unlimited. Env: LEAF_PROXY_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_PROXY_IDLE_TIMEOUT", 2*time.Minute), "rolling per-downstream-connection idle timeout. Env: LEAF_PROXY_IDLE_TIMEOUT")

	flag.DurationVar(&cfg.dialTimeout, "upstream-dial-timeout", envOrDuration("LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT", 10*time.Second), "timeout for dialing the upstream pool. Env: LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT")
	flag.DurationVar(&cfg.requestTimeout, "upstream-request-timeout", envOrDuration("LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT", 15*time.Second), "timeout for a single upstream request/response round-trip. Env: LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT")

	flag.Parse()
	return cfg
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

func main() {
	cfg := loadConfig()
	logger := log.New(os.Stdout, "leaf-proxy: ", log.LstdFlags|log.Lmicroseconds)

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

	if err := upstream.Connect(ctx); err != nil {
		logger.Fatalf("failed to connect/login to upstream pool: %v", err)
	}
	defer upstream.Close()

	tmpl := upstream.CurrentTemplate()
	logger.Printf("upstream login succeeded: session_id=%s height=%d reserved_offset=%d client_nonce_offset_present=%v target_diff=%d seed_hash=%s",
		upstream.SessionID(), tmpl.Height, tmpl.ReservedOffset, tmpl.ClientNonceOffset >= 0, tmpl.TargetDiff, tmpl.SeedHashHex())

	jobManager := proxy.NewJobManager(upstream, logger)

	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{
		MaxConnections: cfg.maxConnections,
		IdleTimeout:    cfg.idleTimeout,
	})

	rxValidator := validator.NewRandomXValidator(cfg.randomXServiceURL)

	vardiffCfg := leaflib.VardiffConfig{
		MinDifficulty:    cfg.minDifficulty,
		MaxDifficulty:    cfg.maxDifficulty,
		TargetTime:       cfg.vardiffTargetTime,
		RetargetInterval: cfg.vardiffInterval,
	}

	server := proxy.NewServer(cm, jobManager, rxValidator, upstream, logger, vardiffCfg, cfg.jobMaxAge)
	defer server.Shutdown()

	ln, err := net.Listen("tcp", cfg.listenAddress)
	if err != nil {
		logger.Fatalf("failed to listen on %s: %v", cfg.listenAddress, err)
	}
	logger.Printf("listening for downstream miners on %s (starting difficulty %d)", cfg.listenAddress, cfg.startingDifficulty)

	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx, ln, cfg.startingDifficulty) }()

	select {
	case <-ctx.Done():
		logger.Println("shutdown signal received, draining connections...")
		_ = ln.Close()
		cm.Shutdown()
	case err := <-errCh:
		if err != nil {
			logger.Fatalf("listener error: %v", err)
		}
	}
}
