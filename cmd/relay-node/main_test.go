// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestValidateCoinAlgo_ValidCombinations covers every one of the
// brief's own explicitly required valid combinations: RXT/C29/SHA3X
// require -coin=tari, RXM/XMR require -coin=monero.
func TestValidateCoinAlgo_ValidCombinations(t *testing.T) {
	cases := []struct {
		coin, algo string
		wantAlgo   poolpb.Algo
		wantCoin   string
	}{
		{"tari", "rxt", poolpb.Algo_ALGO_RXT, coinTari},
		{"tari", "c29", poolpb.Algo_ALGO_C29, coinTari},
		{"tari", "sha3x", poolpb.Algo_ALGO_SHA3X, coinTari},
		{"TARI", "SHA3X", poolpb.Algo_ALGO_SHA3X, coinTari}, // case-insensitive
		{"monero", "rxm", poolpb.Algo_ALGO_RXM, coinMonero},
		{"monero", "xmr", poolpb.Algo_ALGO_XMR, coinMonero},
		{" monero ", " xmr ", poolpb.Algo_ALGO_XMR, coinMonero}, // trims whitespace
	}
	for _, tc := range cases {
		coin, algo, err := validateCoinAlgo(tc.coin, tc.algo)
		if err != nil {
			t.Errorf("validateCoinAlgo(%q, %q) returned unexpected error: %v", tc.coin, tc.algo, err)
			continue
		}
		if algo != tc.wantAlgo {
			t.Errorf("validateCoinAlgo(%q, %q) algo = %v, want %v", tc.coin, tc.algo, algo, tc.wantAlgo)
		}
		if coin != tc.wantCoin {
			t.Errorf("validateCoinAlgo(%q, %q) coin = %q, want %q", tc.coin, tc.algo, coin, tc.wantCoin)
		}
	}
}

// TestValidateCoinAlgo_RejectsMismatchedCombinations proves every
// cross-family mismatch (a Tari-only algo with -coin=monero, or a
// Monero-only algo with -coin=tari) fails fast with a real error,
// rather than silently defaulting to a workable combination.
func TestValidateCoinAlgo_RejectsMismatchedCombinations(t *testing.T) {
	cases := []struct{ coin, algo string }{
		{"monero", "rxt"},
		{"monero", "c29"},
		{"monero", "sha3x"},
		{"tari", "rxm"},
		{"tari", "xmr"},
		{"bitcoin", "sha3x"},
		{"tari", "notanalgo"},
		{"tari", ""},
	}
	for _, tc := range cases {
		if _, _, err := validateCoinAlgo(tc.coin, tc.algo); err == nil {
			t.Errorf("validateCoinAlgo(%q, %q) = nil error, want a real rejection", tc.coin, tc.algo)
		}
	}
}

// TestNetworkFromString mirrors every other binary's identical
// mainnet/testnet-default convention.
func TestNetworkFromString(t *testing.T) {
	if got := networkFromString("mainnet"); got != "mainnet" {
		t.Errorf("networkFromString(mainnet) = %q, want mainnet", got)
	}
	if got := networkFromString("MAINNET"); got != "mainnet" {
		t.Errorf("networkFromString(MAINNET) = %q, want mainnet", got)
	}
	if got := networkFromString("testnet"); got != "testnet" {
		t.Errorf("networkFromString(testnet) = %q, want testnet", got)
	}
	if got := networkFromString(""); got != "testnet" {
		t.Errorf("networkFromString(\"\") = %q, want testnet (safe default)", got)
	}
	if got := networkFromString("garbage"); got != "testnet" {
		t.Errorf("networkFromString(garbage) = %q, want testnet (safe default)", got)
	}
}

// TestResolveCoinbaseExtraTag proves the operator override takes
// precedence and the computed per-algo default is used otherwise.
func TestResolveCoinbaseExtraTag(t *testing.T) {
	cfg := config{coinbaseExtraTag: ""}
	if got := resolveCoinbaseExtraTag(cfg, poolpb.Algo_ALGO_C29); got != "relay-node-c29" {
		t.Errorf("resolveCoinbaseExtraTag (default) = %q, want relay-node-c29", got)
	}
	cfg.coinbaseExtraTag = "custom-tag"
	if got := resolveCoinbaseExtraTag(cfg, poolpb.Algo_ALGO_C29); got != "custom-tag" {
		t.Errorf("resolveCoinbaseExtraTag (override) = %q, want custom-tag", got)
	}
}

// runLoadConfig resets flag.CommandLine/os.Args, runs loadConfig(),
// and restores both afterward -- mirrors cmd/leaf-solo/main_test.go's
// own runPrecedenceCase helper exactly (loadConfig registers its
// flags on the package-level flag.CommandLine).
func runLoadConfig(t *testing.T, args []string, env map[string]string, toml string) config {
	t.Helper()

	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	flag.CommandLine = flag.NewFlagSet("relay-node-test", flag.ContinueOnError)

	fullArgs := append([]string{"relay-node"}, args...)
	if toml != "" {
		dir := t.TempDir()
		path := filepath.Join(dir, "cfg.toml")
		if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
			t.Fatalf("writing test config file: %v", err)
		}
		fullArgs = append(fullArgs, "-config="+path)
	}
	os.Args = fullArgs

	for k, v := range env {
		t.Setenv(k, v)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() returned unexpected error: %v", err)
	}
	return cfg
}

// TestLoadConfig_FlagBeatsEnvBeatsFileBeatsDefault proves the
// documented flag > env > file > hardcoded-default precedence (owned
// by internal/leaflib/cfgfile) holds for relay-node's own config,
// exactly like every sibling binary's own precedence test.
func TestLoadConfig_FlagBeatsEnvBeatsFileBeatsDefault(t *testing.T) {
	toml := `
coin = "monero"
algo = "xmr"
monerod_url = "http://from-file:28081"
payout_address = "from-file-address"
poll_interval_seconds = 9
`
	// File value alone.
	cfg := runLoadConfig(t, nil, nil, toml)
	if cfg.coin != "monero" || cfg.algo != "xmr" || cfg.monerodURL != "http://from-file:28081" {
		t.Errorf("file-sourced config = %+v, want coin=monero algo=xmr monerod_url=http://from-file:28081", cfg)
	}
	if cfg.pollInterval != 9*time.Second {
		t.Errorf("file-sourced poll interval = %s, want 9s", cfg.pollInterval)
	}

	// Env beats file.
	cfg = runLoadConfig(t, nil, map[string]string{"RELAY_NODE_MONEROD_URL": "http://from-env:28081"}, toml)
	if cfg.monerodURL != "http://from-env:28081" {
		t.Errorf("env-sourced monerod-url = %q, want http://from-env:28081 (env must beat file)", cfg.monerodURL)
	}

	// Flag beats env beats file.
	cfg = runLoadConfig(t, []string{"-monerod-url=http://from-flag:28081"}, map[string]string{"RELAY_NODE_MONEROD_URL": "http://from-env:28081"}, toml)
	if cfg.monerodURL != "http://from-flag:28081" {
		t.Errorf("flag-sourced monerod-url = %q, want http://from-flag:28081 (flag must beat env and file)", cfg.monerodURL)
	}

	// Hardcoded default (poll-interval) when nothing else set.
	cfg = runLoadConfig(t, nil, nil, "")
	if cfg.pollInterval != 5*time.Second {
		t.Errorf("default poll interval = %s, want 5s", cfg.pollInterval)
	}
	if cfg.coin != "tari" {
		t.Errorf("default coin = %q, want tari", cfg.coin)
	}
}

// TestLoadConfig_SharedNodeGRPCAddressEnvVar proves -node-grpc-address
// really does reuse the SAME unprefixed LEAF_NODE_GRPC_ADDRESS env
// var every other leaf in this repo uses (a deliberate choice, see
// main.go's own doc comment on that flag) rather than a
// RELAY_NODE_-prefixed one.
func TestLoadConfig_SharedNodeGRPCAddressEnvVar(t *testing.T) {
	cfg := runLoadConfig(t, nil, map[string]string{"LEAF_NODE_GRPC_ADDRESS": "127.0.0.1:18142"}, "")
	if cfg.nodeGRPCAddress != "127.0.0.1:18142" {
		t.Errorf("nodeGRPCAddress = %q, want 127.0.0.1:18142 (from the shared LEAF_NODE_GRPC_ADDRESS env var)", cfg.nodeGRPCAddress)
	}
}

// TestLoadConfig_RelayNATSFlagsUseRelayNodePrefix proves every
// -relay-nats-*/-*-relay-subject flag's env var carries the new
// RELAY_NODE_ prefix (per the brief's explicit instruction), mirroring
// leaf-direct's exact flag names with a different prefix.
func TestLoadConfig_RelayNATSFlagsUseRelayNodePrefix(t *testing.T) {
	env := map[string]string{
		"RELAY_NODE_RELAY_NATS_URL":           "nats://127.0.0.1:4222",
		"RELAY_NODE_RELAY_SUBJECT":            "custom.blocks",
		"RELAY_NODE_RELAY_NATS_USERNAME":      "user1",
		"RELAY_NODE_RELAY_NATS_PASSWORD":      "pass1",
		"RELAY_NODE_RELAY_NATS_TLS_CA_FILE":   "/tmp/ca.pem",
		"RELAY_NODE_RELAY_NATS_TLS_CERT_FILE": "/tmp/cert.pem",
		"RELAY_NODE_RELAY_NATS_TLS_KEY_FILE":  "/tmp/key.pem",
		"RELAY_NODE_TEMPLATE_RELAY_SUBJECT":   "custom.templates",
	}
	cfg := runLoadConfig(t, nil, env, "")
	if cfg.relayNATSURL != "nats://127.0.0.1:4222" {
		t.Errorf("relayNATSURL = %q", cfg.relayNATSURL)
	}
	if cfg.relaySubject != "custom.blocks" {
		t.Errorf("relaySubject = %q", cfg.relaySubject)
	}
	if cfg.relayNATSUsername != "user1" || cfg.relayNATSPassword != "pass1" {
		t.Errorf("relayNATSUsername/Password = %q/%q", cfg.relayNATSUsername, cfg.relayNATSPassword)
	}
	if cfg.relayNATSTLSCAFile != "/tmp/ca.pem" || cfg.relayNATSTLSCertFile != "/tmp/cert.pem" || cfg.relayNATSTLSKeyFile != "/tmp/key.pem" {
		t.Errorf("relay TLS fields = %q/%q/%q", cfg.relayNATSTLSCAFile, cfg.relayNATSTLSCertFile, cfg.relayNATSTLSKeyFile)
	}
	if cfg.templateRelaySubject != "custom.templates" {
		t.Errorf("templateRelaySubject = %q", cfg.templateRelaySubject)
	}
}
