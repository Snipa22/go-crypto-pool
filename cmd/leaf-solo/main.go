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
// Known simplification (explicitly in scope per the task): difficulty
// is static and leaf-configured (LEAF_SOLO_DIFFICULTY / -difficulty).
// Vardiff (adaptive per-miner difficulty retargeting) is out of scope
// for this pass.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

type config struct {
	nodeGRPCAddress string
	listenAddress   string
	payoutAddress   string
	network         string

	staticDifficulty uint64
	refreshInterval  time.Duration
	tipPollInterval  time.Duration

	maxConnections int
	idleTimeout    time.Duration
}

func loadConfig() config {
	cfg := config{}

	flag.StringVar(&cfg.nodeGRPCAddress, "node-grpc-address", envOr("LEAF_NODE_GRPC_ADDRESS", ""), "Tari base node GRPC address (host:port). Env: LEAF_NODE_GRPC_ADDRESS")
	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_SOLO_LISTEN_ADDRESS", ":4444"), "miner-facing TCP listen address. Env: LEAF_SOLO_LISTEN_ADDRESS")
	flag.StringVar(&cfg.payoutAddress, "payout-address", envOr("LEAF_SOLO_PAYOUT_ADDRESS", ""), "solo payout address; found-block coinbase rewards go here. Env: LEAF_SOLO_PAYOUT_ADDRESS")
	flag.StringVar(&cfg.network, "network", envOr("LEAF_SOLO_NETWORK", "testnet"), "network tag for share/diagnostic records: mainnet|testnet. Env: LEAF_SOLO_NETWORK")

	flag.Uint64Var(&cfg.staticDifficulty, "difficulty", envOrUint64("LEAF_SOLO_DIFFICULTY", 10000), "static share difficulty (vardiff is out of scope for this pass). Env: LEAF_SOLO_DIFFICULTY")
	flag.DurationVar(&cfg.refreshInterval, "refresh-interval", envOrDuration("LEAF_SOLO_REFRESH_INTERVAL", 30*time.Second), "unconditional block-template refresh interval. Env: LEAF_SOLO_REFRESH_INTERVAL")
	flag.DurationVar(&cfg.tipPollInterval, "tip-poll-interval", envOrDuration("LEAF_SOLO_TIP_POLL_INTERVAL", 5*time.Second), "chain-tip poll interval (forces an immediate refresh on tip movement). Env: LEAF_SOLO_TIP_POLL_INTERVAL")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_SOLO_MAX_CONNECTIONS", 0), "max concurrent miner connections, 0 = unlimited. Env: LEAF_SOLO_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_SOLO_IDLE_TIMEOUT", 2*time.Minute), "rolling per-connection idle timeout. Env: LEAF_SOLO_IDLE_TIMEOUT")

	flag.Parse()
	return cfg
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

	logger.Printf("static difficulty: %d (vardiff not implemented in this pass — see main.go doc comment)", cfg.staticDifficulty)
	logger.Printf("connecting to Tari base node GRPC at %s", cfg.nodeGRPCAddress)

	node := solo.NewGRPCNodeClient(cfg.nodeGRPCAddress)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	jobManager := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    cfg.payoutAddress,
		StaticDifficulty: cfg.staticDifficulty,
		RefreshInterval:  cfg.refreshInterval,
		TipPollInterval:  cfg.tipPollInterval,
		Logger:           logger,
	})

	logger.Println("fetching initial block template...")
	if _, err := jobManager.Refresh(ctx); err != nil {
		logger.Fatalf("initial block template fetch failed: %v", err)
	}
	jobManager.Start(ctx)

	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{
		MaxConnections: cfg.maxConnections,
		IdleTimeout:    cfg.idleTimeout,
	})

	sha3xValidator := validator.NewSHA3XValidator()
	server := solo.NewServer(cm, jobManager, node, sha3xValidator, networkFromString(cfg.network), logger)
	defer server.Shutdown()

	ln, err := net.Listen("tcp", cfg.listenAddress)
	if err != nil {
		logger.Fatalf("failed to listen on %s: %v", cfg.listenAddress, err)
	}
	logger.Printf("listening for miners on %s", cfg.listenAddress)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx, ln)
	}()

	select {
	case <-ctx.Done():
		logger.Println("shutdown signal received, draining connections...")
		cm.Shutdown()
	case err := <-errCh:
		if err != nil {
			logger.Fatalf("listener error: %v", err)
		}
	}
}
