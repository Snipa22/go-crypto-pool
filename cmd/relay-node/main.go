// Command relay-node is a standalone, deliberately light daemon: it
// is NOT a pool leaf (no miner-facing TCP/Stratum port, no session/
// vardiff/share-validation code, no HTTP+Protobuf backend transport,
// no wallet/payout code -- see relay-node-brief.md, the design brief
// this binary was built from). It watches exactly ONE configured
// upstream node (Tari GRPC, standalone Monero RPC, or Tari-merge-mine/
// RXM via a minotari_merge_mining_proxy listener -- one coin/algo per
// daemon instance, see -coin/-algo below) and does exactly two jobs:
//
//  1. Template push: on every genuine chain-tip height increase,
//     fetch a real, fresh block template from the configured node and
//     relay.PublishTemplate it (with the real, coin-specific upstream
//     template payload -- see daemon.go's templateDataForJob for the
//     real design decision here) onto the shared NATS relay
//     (internal/leaflib/relay), tagged with this instance's own
//     Algo/Network so multi-format consumers can dispatch correctly.
//  2. Found-block resubmission relay: subscribes to the SAME relay's
//     found-block broadcast (relay.BlockMessage), filters to messages
//     matching this instance's own configured Algo/Network, and on a
//     match attempts a real local resubmission against ITS OWN
//     configured node via NodeClient.SubmitBlock -- mirrors the
//     existing (currently-inert, Tari-only) leaf-direct subscribe-
//     and-resubmit pattern (internal/leaflib/direct/server.go's
//     handleRelayedBlock), just running standalone.
//
// Deployment shape: ONE lightweight instance per physical node (an
// explicit choice -- more redundancy over fewer, heavier watchers).
// Config is designed to make it trivial to run many of these side by
// side pointed at different nodes, all sharing one NATS relay.
// -relay-nats-url is fully optional: relay.Relay is a complete no-op
// with an empty URL (see internal/leaflib/relay's own doc comment),
// so this daemon's poll loop and node connectivity are fully
// functional and independently verifiable even with no NATS server
// deployed at all.
//
// SETTLED DESIGN DECISIONS (previously listed here as open questions
// -- now resolved, per Alex's explicit direction):
//   - -payout-address stays exactly what it already is: a plain
//     required CLI flag/env var. No dedicated "relay observer address"
//     convention was added -- this daemon does no payouts of its own,
//     and reusing the existing plain-flag convention was confirmed
//     sufficient.
//   - BlockMessage.BlockData's wire format for every Monero-family
//     algo is CLOSED: internal/leaflib/direct/session.go's ALGO_RXM/
//     ALGO_XMR/etc block-find branch now publishes the raw,
//     already-nonce-patched solo.MoneroCandidate.TemplateBlob bytes
//     (see that file's handleSubmit doc comment), and this binary's
//     own handleFoundBlock (daemon.go) decodes that back into a
//     *solo.MoneroCandidate and resubmits it via NodeClient.SubmitBlock
//     -- mirroring the Tari path exactly.
//
// OPEN DESIGN QUESTIONS still remaining:
//   - TemplateMessage.TemplateData's real encoding (see daemon.go's
//     templateDataForJob doc comment for the choice made and why).
//   - No pre-existing systemd unit convention was found anywhere in
//     this repository (checked: no .service files, no deploy/
//     directory) -- relay-node.service (this package's own directory)
//     is a genuinely NEW convention, not a reuse of an established
//     one.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/cfgfile"
	monerozmq "github.com/Snipa22/go-crypto-pool/internal/leaflib/monero/zmq"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// version is a build-time-overridable identifier -- override via
// -ldflags "-X main.version=...".
var version = "dev"

// coinTari/coinMonero are this binary's own two supported -coin
// values (a deliberately narrower set than leaf-solo/leaf-direct's
// full internal/coinprofile.Registry-driven ticker list -- the brief
// scopes -algo to exactly RXT/C29/SHA3X/RXM/XMR, so relay-node has no
// need for the wider coin-ticker dispatch those two binaries carry).
const (
	coinTari   = "tari"
	coinMonero = "monero"
)

type config struct {
	coin string
	algo string

	nodeGRPCAddress string
	monerodURL      string
	moneroZMQURL    string

	payoutAddress    string
	network          string
	coinbaseExtraTag string

	pollInterval time.Duration

	relayNATSURL         string
	relaySubject         string
	relayNATSUsername    string
	relayNATSPassword    string
	relayNATSTLSCAFile   string
	relayNATSTLSCertFile string
	relayNATSTLSKeyFile  string
	templateRelaySubject string

	configFile string
}

func loadConfig() (config, error) {
	cfg := config{}

	flag.StringVar(&cfg.coin, "coin", envOr("RELAY_NODE_COIN", "tari"), "which coin/PoW family this instance watches: tari or monero. Determines which -algo values are valid (tari: rxt|c29|sha3x; monero: rxm|xmr) and which of -node-grpc-address/-monerod-url is required. Env: RELAY_NODE_COIN")
	flag.StringVar(&cfg.algo, "algo", envOr("RELAY_NODE_ALGO", ""), "which single algo this instance watches: rxt|c29|sha3x (requires -coin=tari) or rxm|xmr (requires -coin=monero). REQUIRED -- no safe default across two coin families. Env: RELAY_NODE_ALGO")

	flag.StringVar(&cfg.nodeGRPCAddress, "node-grpc-address", envOr("LEAF_NODE_GRPC_ADDRESS", ""), "Tari base node GRPC address (host:port). REQUIRED when -coin=tari; ignored for -coin=monero. Deliberately the SAME flag name/env var every other leaf in this repo uses (LEAF_NODE_GRPC_ADDRESS is shared/unprefixed by existing convention, unlike every other flag below) so one physical Tari node's address can be configured once and reused across leaf-solo/leaf-direct/relay-node without duplicating it under a per-binary env var. Env: LEAF_NODE_GRPC_ADDRESS")
	flag.StringVar(&cfg.monerodURL, "monerod-url", envOr("RELAY_NODE_MONEROD_URL", ""), "real monerod-JSON-RPC-compatible base URL (e.g. http://148.163.90.157:28081), no trailing slash or /json_rpc suffix required. REQUIRED when -coin=monero. For -algo=rxm, this must point at a local minotari_merge_mining_proxy listener, NOT raw monerod (mirrors leaf-solo/leaf-direct's identical -monerod-url convention and warning -- pointing at raw monerod for -algo=rxm would mine Monero-only with zero Tari merge-mine revenue). For -algo=xmr, point this at raw monerod directly. Ignored for -coin=tari. Env: RELAY_NODE_MONEROD_URL")
	flag.StringVar(&cfg.moneroZMQURL, "monero-zmq-url", envOr("RELAY_NODE_MONERO_ZMQ_URL", ""), "real monerod ZMQ endpoint (e.g. tcp://127.0.0.1:28082) for an ADDITIONAL, faster tip-poll trigger on top of the existing -poll-interval baseline (see internal/leaflib/monero/zmq). Empty (default) disables this entirely -- a complete no-op. Ignored for -coin=tari. Env: RELAY_NODE_MONERO_ZMQ_URL")

	flag.StringVar(&cfg.payoutAddress, "payout-address", envOr("RELAY_NODE_PAYOUT_ADDRESS", ""), "payout address passed to every GetBlockTemplate call -- REQUIRED by solo.NodeClient's interface contract even though this daemon does no payouts of its own (see this binary's own doc comment for the explicit, unresolved real-address-convention design question). Env: RELAY_NODE_PAYOUT_ADDRESS")
	flag.StringVar(&cfg.network, "network", envOr("RELAY_NODE_NETWORK", "testnet"), "network tag stamped on every published/matched relay message: mainnet|testnet. Env: RELAY_NODE_NETWORK")
	flag.StringVar(&cfg.coinbaseExtraTag, "coinbase-extra-tag", envOr("RELAY_NODE_COINBASE_EXTRA_TAG", ""), "coinbase-extra ownership tag appended to every fetched Tari block template (identifies this instance's fetched templates on-chain -- only meaningful for -coin=tari, ignored for -coin=monero). Left unset (the default), a per-algo default is computed: relay-node-rxt / relay-node-c29 / relay-node-sha3x. Env: RELAY_NODE_COINBASE_EXTRA_TAG")

	flag.DurationVar(&cfg.pollInterval, "poll-interval", envOrDuration("RELAY_NODE_POLL_INTERVAL", 5*time.Second), "chain-tip poll interval -- matches leaf-solo's own -tip-poll-interval default (5s). Env: RELAY_NODE_POLL_INTERVAL")

	flag.StringVar(&cfg.relayNATSURL, "relay-nats-url", envOr("RELAY_NODE_RELAY_NATS_URL", ""), "NATS server URL for the shared best-effort relay (template push + found-block subscribe/resubmit). Empty (default) fully disables the relay -- a complete no-op; this daemon's node-connectivity/poll-loop behavior is fully functional and independently verifiable without one. Env: RELAY_NODE_RELAY_NATS_URL")
	flag.StringVar(&cfg.relaySubject, "relay-subject", envOr("RELAY_NODE_RELAY_SUBJECT", ""), "NATS subject for the found-block relay (empty = relay.DefaultSubject). Env: RELAY_NODE_RELAY_SUBJECT")
	flag.StringVar(&cfg.relayNATSUsername, "relay-nats-username", envOr("RELAY_NODE_RELAY_NATS_USERNAME", ""), "optional NATS username for the relay connection above (mirrors nats.UserInfo). Empty (default) connects with no auth. Env: RELAY_NODE_RELAY_NATS_USERNAME")
	flag.StringVar(&cfg.relayNATSPassword, "relay-nats-password", envOr("RELAY_NODE_RELAY_NATS_PASSWORD", ""), "optional NATS password paired with -relay-nats-username (mirrors nats.UserInfo). Never logged. Env: RELAY_NODE_RELAY_NATS_PASSWORD")
	flag.StringVar(&cfg.relayNATSTLSCAFile, "relay-nats-tls-ca-file", envOr("RELAY_NODE_RELAY_NATS_TLS_CA_FILE", ""), "optional CA bundle file to verify the NATS server's TLS certificate against (mirrors nats.RootCAs). Empty (default) appends no TLS CA option. Env: RELAY_NODE_RELAY_NATS_TLS_CA_FILE")
	flag.StringVar(&cfg.relayNATSTLSCertFile, "relay-nats-tls-cert-file", envOr("RELAY_NODE_RELAY_NATS_TLS_CERT_FILE", ""), "optional client certificate file for mutual TLS against the NATS server (mirrors nats.ClientCert; must be set together with -relay-nats-tls-key-file). Env: RELAY_NODE_RELAY_NATS_TLS_CERT_FILE")
	flag.StringVar(&cfg.relayNATSTLSKeyFile, "relay-nats-tls-key-file", envOr("RELAY_NODE_RELAY_NATS_TLS_KEY_FILE", ""), "optional client private key file paired with -relay-nats-tls-cert-file (mirrors nats.ClientCert). Env: RELAY_NODE_RELAY_NATS_TLS_KEY_FILE")
	flag.StringVar(&cfg.templateRelaySubject, "template-relay-subject", envOr("RELAY_NODE_TEMPLATE_RELAY_SUBJECT", ""), "NATS subject for the template (new-tip) relay broadcast (empty = relay.DefaultTemplateSubject). Reuses the SAME -relay-nats-url connection above -- no second NATS URL flag. Env: RELAY_NODE_TEMPLATE_RELAY_SUBJECT")

	flag.StringVar(&cfg.configFile, "config", envOr("RELAY_NODE_CONFIG_FILE", ""), "optional path to a TOML config file providing defaults for any flag above not explicitly set via CLI flag or environment variable. See relay-node.example.toml. Env: RELAY_NODE_CONFIG_FILE")

	flag.Parse()

	if err := applyConfigFile(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// fileConfig mirrors config field-for-field (excluding configFile
// itself) with pointer types, matching every other binary's identical
// cfgfile.Decode convention (see cmd/leaf-direct/main.go's own
// fileConfig doc comment).
type fileConfig struct {
	CoinValue *string `toml:"coin"`
	Algo      *string `toml:"algo"`

	NodeGRPCAddress *string `toml:"node_grpc_address"`
	MonerodURL      *string `toml:"monerod_url"`
	MoneroZMQURL    *string `toml:"monero_zmq_url"`

	PayoutAddress    *string `toml:"payout_address"`
	Network          *string `toml:"network"`
	CoinbaseExtraTag *string `toml:"coinbase_extra_tag"`

	PollIntervalSeconds *int `toml:"poll_interval_seconds"`

	RelayNATSURL         *string `toml:"relay_nats_url"`
	RelaySubject         *string `toml:"relay_subject"`
	RelayNATSUsername    *string `toml:"relay_nats_username"`
	RelayNATSPassword    *string `toml:"relay_nats_password"`
	RelayNATSTLSCAFile   *string `toml:"relay_nats_tls_ca_file"`
	RelayNATSTLSCertFile *string `toml:"relay_nats_tls_cert_file"`
	RelayNATSTLSKeyFile  *string `toml:"relay_nats_tls_key_file"`
	TemplateRelaySubject *string `toml:"template_relay_subject"`
}

// applyConfigFile merges cfg.configFile (if set) into cfg, honoring
// the flag > env > file > hardcoded-default precedence rule owned by
// internal/leaflib/cfgfile. No-op when cfg.configFile == "".
func applyConfigFile(cfg *config) error {
	if cfg.configFile == "" {
		return nil
	}
	visited := cfgfile.VisitedFlags(flag.CommandLine)

	var fc fileConfig
	if err := cfgfile.Decode(cfg.configFile, &fc); err != nil {
		return fmt.Errorf("relay-node: loading -config %s: %w", cfg.configFile, err)
	}

	cfgfile.ApplyString(&cfg.coin, fc.CoinValue, visited, "coin", "RELAY_NODE_COIN")
	cfgfile.ApplyString(&cfg.algo, fc.Algo, visited, "algo", "RELAY_NODE_ALGO")

	cfgfile.ApplyString(&cfg.nodeGRPCAddress, fc.NodeGRPCAddress, visited, "node-grpc-address", "LEAF_NODE_GRPC_ADDRESS")
	cfgfile.ApplyString(&cfg.monerodURL, fc.MonerodURL, visited, "monerod-url", "RELAY_NODE_MONEROD_URL")
	cfgfile.ApplyString(&cfg.moneroZMQURL, fc.MoneroZMQURL, visited, "monero-zmq-url", "RELAY_NODE_MONERO_ZMQ_URL")

	cfgfile.ApplyString(&cfg.payoutAddress, fc.PayoutAddress, visited, "payout-address", "RELAY_NODE_PAYOUT_ADDRESS")
	cfgfile.ApplyString(&cfg.network, fc.Network, visited, "network", "RELAY_NODE_NETWORK")
	cfgfile.ApplyString(&cfg.coinbaseExtraTag, fc.CoinbaseExtraTag, visited, "coinbase-extra-tag", "RELAY_NODE_COINBASE_EXTRA_TAG")

	if fc.PollIntervalSeconds != nil {
		d := time.Duration(*fc.PollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.pollInterval, &d, visited, "poll-interval", "RELAY_NODE_POLL_INTERVAL")
	}

	cfgfile.ApplyString(&cfg.relayNATSURL, fc.RelayNATSURL, visited, "relay-nats-url", "RELAY_NODE_RELAY_NATS_URL")
	cfgfile.ApplyString(&cfg.relaySubject, fc.RelaySubject, visited, "relay-subject", "RELAY_NODE_RELAY_SUBJECT")
	cfgfile.ApplyString(&cfg.relayNATSUsername, fc.RelayNATSUsername, visited, "relay-nats-username", "RELAY_NODE_RELAY_NATS_USERNAME")
	cfgfile.ApplyString(&cfg.relayNATSPassword, fc.RelayNATSPassword, visited, "relay-nats-password", "RELAY_NODE_RELAY_NATS_PASSWORD")
	cfgfile.ApplyString(&cfg.relayNATSTLSCAFile, fc.RelayNATSTLSCAFile, visited, "relay-nats-tls-ca-file", "RELAY_NODE_RELAY_NATS_TLS_CA_FILE")
	cfgfile.ApplyString(&cfg.relayNATSTLSCertFile, fc.RelayNATSTLSCertFile, visited, "relay-nats-tls-cert-file", "RELAY_NODE_RELAY_NATS_TLS_CERT_FILE")
	cfgfile.ApplyString(&cfg.relayNATSTLSKeyFile, fc.RelayNATSTLSKeyFile, visited, "relay-nats-tls-key-file", "RELAY_NODE_RELAY_NATS_TLS_KEY_FILE")
	cfgfile.ApplyString(&cfg.templateRelaySubject, fc.TemplateRelaySubject, visited, "template-relay-subject", "RELAY_NODE_TEMPLATE_RELAY_SUBJECT")

	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
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

// normalizeCoin lowercases/trims cfg.coin -- the only two accepted
// values are "tari" and "monero" (see this binary's own doc comment
// on why relay-node's -coin is deliberately narrower than leaf-solo/
// leaf-direct's full coinprofile.Registry-driven ticker list).
func normalizeCoin(coin string) string {
	return strings.ToLower(strings.TrimSpace(coin))
}

// algoFromString parses -algo/RELAY_NODE_ALGO into the real
// poolpb.Algo value. Returns ok=false for any unrecognized string --
// callers must treat that as a fatal startup misconfiguration (there
// is no safe default across two entirely different coin families).
func algoFromString(s string) (poolpb.Algo, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "rxt":
		return poolpb.Algo_ALGO_RXT, true
	case "c29":
		return poolpb.Algo_ALGO_C29, true
	case "sha3x":
		return poolpb.Algo_ALGO_SHA3X, true
	case "rxm":
		return poolpb.Algo_ALGO_RXM, true
	case "xmr":
		return poolpb.Algo_ALGO_XMR, true
	default:
		return poolpb.Algo_ALGO_UNSPECIFIED, false
	}
}

// algoTagSuffix returns algo's lowercase tag suffix, used only for
// this instance's default coinbase-extra tag (relay-node-<suffix>) --
// mirrors leaf-solo/leaf-direct's own identical algoTagSuffix
// convention, narrowed to this binary's own 5 supported algo values.
func algoTagSuffix(algo poolpb.Algo) string {
	switch algo {
	case poolpb.Algo_ALGO_RXT:
		return "rxt"
	case poolpb.Algo_ALGO_C29:
		return "c29"
	case poolpb.Algo_ALGO_RXM:
		return "rxm"
	case poolpb.Algo_ALGO_XMR:
		return "xmr"
	default:
		return "sha3x"
	}
}

// validateCoinAlgo enforces the brief's own explicit combination
// rule: RXT/C29/SHA3X require -coin=tari, RXM/XMR require
// -coin=monero. Returns the parsed poolpb.Algo and the normalized
// coin string on success, or a descriptive error identifying exactly
// which combination was rejected and why -- never silently falls back
// to a default for either flag.
func validateCoinAlgo(coinRaw, algoRaw string) (coin string, algo poolpb.Algo, err error) {
	coin = normalizeCoin(coinRaw)
	if coin != coinTari && coin != coinMonero {
		return "", poolpb.Algo_ALGO_UNSPECIFIED, fmt.Errorf("relay-node: -coin/RELAY_NODE_COIN must be %q or %q, got %q", coinTari, coinMonero, coinRaw)
	}

	algo, ok := algoFromString(algoRaw)
	if !ok {
		return "", poolpb.Algo_ALGO_UNSPECIFIED, fmt.Errorf("relay-node: -algo/RELAY_NODE_ALGO is required and must be one of rxt|c29|sha3x|rxm|xmr, got %q", algoRaw)
	}

	switch algo {
	case poolpb.Algo_ALGO_RXT, poolpb.Algo_ALGO_C29, poolpb.Algo_ALGO_SHA3X:
		if coin != coinTari {
			return "", poolpb.Algo_ALGO_UNSPECIFIED, fmt.Errorf("relay-node: -algo=%s requires -coin=%s, got -coin=%s", algoRaw, coinTari, coinRaw)
		}
	case poolpb.Algo_ALGO_RXM, poolpb.Algo_ALGO_XMR:
		if coin != coinMonero {
			return "", poolpb.Algo_ALGO_UNSPECIFIED, fmt.Errorf("relay-node: -algo=%s requires -coin=%s, got -coin=%s", algoRaw, coinMonero, coinRaw)
		}
	}
	return coin, algo, nil
}

func networkFromString(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "mainnet") {
		return "mainnet"
	}
	return "testnet"
}

func defaultCoinbaseExtraTag(algo poolpb.Algo) string {
	return "relay-node-" + algoTagSuffix(algo)
}

func resolveCoinbaseExtraTag(cfg config, algo poolpb.Algo) string {
	if strings.TrimSpace(cfg.coinbaseExtraTag) != "" {
		return cfg.coinbaseExtraTag
	}
	return defaultCoinbaseExtraTag(algo)
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("relay-node: %v", err)
	}
	logger := log.New(os.Stdout, "relay-node: ", log.LstdFlags|log.Lmicroseconds)

	coin, algo, err := validateCoinAlgo(cfg.coin, cfg.algo)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	network := networkFromString(cfg.network)

	if cfg.payoutAddress == "" {
		logger.Fatal("-payout-address/RELAY_NODE_PAYOUT_ADDRESS is required")
	}
	if cfg.pollInterval <= 0 {
		logger.Fatal("-poll-interval/RELAY_NODE_POLL_INTERVAL must be > 0")
	}

	var node solo.NodeClient
	switch coin {
	case coinTari:
		if cfg.nodeGRPCAddress == "" {
			logger.Fatal("-node-grpc-address/LEAF_NODE_GRPC_ADDRESS is required for -coin=tari")
		}
		coinbaseExtraTagStr := resolveCoinbaseExtraTag(cfg, algo)
		coinbaseExtraTag := solo.NormalizeCoinbaseExtraTag(coinbaseExtraTagStr, defaultCoinbaseExtraTag(algo))
		logger.Printf("coinbase-extra tag: %q (%d bytes)", string(coinbaseExtraTag), len(coinbaseExtraTag))
		logger.Printf("connecting to Tari base node GRPC at %s", cfg.nodeGRPCAddress)
		node = solo.NewGRPCNodeClient(cfg.nodeGRPCAddress, coinbaseExtraTag)
	case coinMonero:
		if cfg.monerodURL == "" {
			logger.Fatal("-monerod-url/RELAY_NODE_MONEROD_URL is required for -coin=monero")
		}
		if algo == poolpb.Algo_ALGO_RXM {
			logger.Printf("NOTE: for RXM/merge-mining revenue, -monerod-url must point at a local minotari_merge_mining_proxy listener, NOT raw monerod")
		}
		logger.Printf("connecting to monerod-compatible daemon at %s", cfg.monerodURL)
		node = solo.NewMoneroNodeClient(cfg.monerodURL)
	}

	if cfg.moneroZMQURL != "" && coin != coinMonero {
		logger.Printf("note: -monero-zmq-url is set but -coin=%s is not monero -- ignoring it (%s); no ZMQ subscription started", coin, cfg.moneroZMQURL)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	blockRelay := relay.NewRelay(relay.Config{
		URL: cfg.relayNATSURL, Subject: cfg.relaySubject, TemplateSubject: cfg.templateRelaySubject, Logger: logger,
		Username: cfg.relayNATSUsername, Password: cfg.relayNATSPassword,
		TLSCAFile: cfg.relayNATSTLSCAFile, TLSCertFile: cfg.relayNATSTLSCertFile, TLSKeyFile: cfg.relayNATSTLSKeyFile,
	})
	defer func() { _ = blockRelay.Close() }()
	if blockRelay.Enabled() {
		logger.Printf("NATS relay enabled at %s", cfg.relayNATSURL)
	} else {
		logger.Printf("NATS relay disabled (-relay-nats-url/RELAY_NODE_RELAY_NATS_URL is empty) -- complete no-op, never required for correctness")
	}

	daemon := NewDaemon(node, blockRelay, algo, coin, network, cfg.payoutAddress, logger)

	logger.Println("probing node connectivity (fetching one real block template)...")
	if _, err := node.GetBlockTemplate(ctx, cfg.payoutAddress, algo); err != nil {
		logger.Fatalf("node connectivity probe (GetBlockTemplate) failed: %v", err)
	}
	logger.Println("node connectivity probe succeeded")

	unsubscribe, err := daemon.SubscribeFoundBlocks()
	if err != nil {
		logger.Printf("relay found-block subscribe failed (non-fatal, primary poll loop unaffected): %v", err)
	} else {
		defer unsubscribe()
	}

	if coin == coinMonero && cfg.moneroZMQURL != "" {
		zmqClient := monerozmq.NewClient(cfg.moneroZMQURL, zmqOnBlockFunc(ctx, daemon, logger), logger)
		go zmqClient.Start(ctx)
		logger.Printf("real monerod ZMQ fast re-poll trigger enabled at %s (topic %q)", cfg.moneroZMQURL, monerozmq.TopicNewBlock)
	}

	logger.Printf("relay-node started: coin=%s algo=%s network=%s poll-interval=%s", coin, cfg.algo, network, cfg.pollInterval)
	daemon.Run(ctx, cfg.pollInterval)
	logger.Println("relay-node shutting down")
}

// zmqOnBlockFunc returns the real ZMQ onBlock callback wired into
// monerozmq.NewClient: an immediate, synchronous extra PollOnce call
// (bounded by its own short timeout, independent of ctx's own
// lifetime beyond cancellation) on top of the existing ticker-driven
// baseline in Daemon.Run. Factored into its own named function
// (rather than an inline closure in main) purely so it is directly
// unit-testable without a real ZMQ socket (see daemon_test.go) --
// zmq4's own real Dial/Recv loop is exercised only by this package's
// live-verification run against a real monerod ZMQ endpoint, never by
// a unit test.
func zmqOnBlockFunc(ctx context.Context, d *Daemon, logger *log.Logger) func() {
	return func() {
		pollCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := d.PollOnce(pollCtx); err != nil {
			logger.Printf("relay-node: ZMQ-triggered re-poll failed (non-fatal): %v", err)
		}
	}
}
