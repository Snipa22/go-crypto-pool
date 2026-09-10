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
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/cfgfile"
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

	// tlsListenAddress is -tls-listen-address/LEAF_PROXY_TLS_LISTEN_ADDRESS:
	// a SECOND, optional downstream-facing listen address served over
	// TLS, alongside (never instead of) the existing plain
	// listenAddress above. Empty (the default) disables it entirely
	// -- a complete no-op, zero behavior change for every existing
	// deployment. leaf-proxy has no multi-port-tier mechanism (unlike
	// leaf-solo/leaf-direct); this is deliberately a single extra
	// listener, not a list, matching this binary's existing
	// single-listen-address shape.
	tlsListenAddress string

	// tlsCertFile / tlsKeyFile / tlsCertPersistPath mirror leaf-solo/
	// leaf-direct's identical trio exactly (see
	// internal/leaflib.LoadOrGenerateCert's doc comment for the full
	// design rationale) -- only ever consulted if tlsListenAddress is
	// non-empty.
	tlsCertFile        string
	tlsKeyFile         string
	tlsCertPersistPath string

	maxConnections int
	idleTimeout    time.Duration

	dialTimeout    time.Duration
	requestTimeout time.Duration

	// randomxWorkers/invalidShareDisconnectEnabled/
	// invalidShareDisconnectThreshold mirror cmd/leaf-solo's own
	// identical fields exactly — see that file's doc comments for the
	// full DISPATCH_BRIEF.md 2026-09-10 Fix 2a/Fix 2b rationale.
	randomxWorkers                  int
	invalidShareDisconnectEnabled   bool
	invalidShareDisconnectThreshold int

	// metricsListenAddress/maxAddressLabels follow cmd/leaf-solo's
	// exact established convention for this flag pair (see
	// leaf-solo's identical -metrics-listen-address/
	// -max-address-labels doc comments) -- ported to this sibling
	// binary unchanged, just with the LEAF_PROXY_ prefix.
	metricsListenAddress string
	maxAddressLabels     int

	// hideRemoteAddress mirrors cmd/leaf-solo's identical flag
	// exactly (see solo.Server.SetHideRemoteAddress's doc comment
	// -- proxy.Server has an identical method). Defaults to false.
	hideRemoteAddress bool

	// addressFlagsFile / addressFlagsPollInterval configure the real,
	// manual ban enforcement described in
	// internal/leaflib/addressflags's package doc comment. Mirrors
	// cmd/leaf-solo's identical flag pair exactly: addressFlagsFile
	// empty (the default) disables the feature entirely --
	// leaf-proxy has no go-crypto-pool backend to poll instead (see
	// this binary's own doc comment: it emulates an advanced mining
	// CLIENT to an upstream Monero-family POOL, not a backend
	// connection this repo controls), so a local, operator-
	// maintained JSON file is the only real Source available to it,
	// exactly like leaf-solo.
	addressFlagsFile         string
	addressFlagsPollInterval time.Duration

	// configFile is the optional path to a TOML file providing
	// defaults for any flag above that the operator did not set
	// explicitly via CLI flag or environment variable. See
	// leaf-proxy.example.toml and internal/leaflib/cfgfile for the
	// exact precedence rule (flag > env > file > hardcoded default).
	configFile string
}

func loadConfig() (config, error) {
	cfg := config{}

	flag.StringVar(&cfg.upstreamHost, "upstream-host", envOr("LEAF_PROXY_UPSTREAM_HOST", "pool.supportxmr.com"), "real upstream Monero-family pool hostname. Env: LEAF_PROXY_UPSTREAM_HOST")
	flag.IntVar(&cfg.upstreamPort, "upstream-port", envOrInt("LEAF_PROXY_UPSTREAM_PORT", 7777), "real upstream pool stratum port (SupportXMR: 3333 low-diff, 5555 medium-diff, 7777 high-diff, 9000 TLS -- see this file's doc comment). Env: LEAF_PROXY_UPSTREAM_PORT")
	flag.BoolVar(&cfg.upstreamTLS, "upstream-tls", envOrBool("LEAF_PROXY_UPSTREAM_TLS", false), "dial the upstream pool over TLS. Env: LEAF_PROXY_UPSTREAM_TLS")
	flag.BoolVar(&cfg.upstreamInsecure, "upstream-tls-insecure-skip-verify", envOrBool("LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY", false), "skip TLS certificate verification for the upstream pool (testing only). Env: LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY")
	flag.StringVar(&cfg.upstreamLogin, "upstream-login", envOr("LEAF_PROXY_UPSTREAM_LOGIN", ""), "real XMR payout address to log in to the upstream pool with. Env: LEAF_PROXY_UPSTREAM_LOGIN")
	flag.StringVar(&cfg.upstreamPass, "upstream-pass", envOr("LEAF_PROXY_UPSTREAM_PASS", "go-crypto-pool-leaf-proxy"), "real upstream pool worker identifier/password. Env: LEAF_PROXY_UPSTREAM_PASS")
	// Default agent string deliberately DOES contain the literal
	// substring "xmr-node-proxy". Confirmed from the real pool-server
	// source (nodejs-pool-sxmr's lib/pool.js: `if (agent &&
	// agent.includes("xmr-node-proxy")) { this.proxy = true; }`, a
	// plain substring check, not an exact-version match), that
	// substring is what gates a real pool granting the "advanced
	// xmr-node-proxy client" protocol extension -- which, in turn, is
	// what makes a real pool (confirmed against
	// pool.supportxmr.com) publish client_nonce_offset/
	// client_pool_offset on its jobs at all.
	//
	// REVERSED (this pass, live production incident): this used to
	// deliberately AVOID that substring, because at the time the
	// advanced dialect meant a raw, untrimmed, arbitrarily-large
	// blocktemplate_blob field (no ordinary "blob" field at all),
	// which overflowed downstream xmrig's login buffer (error code:
	// 4). internal/leaflib/proxy's applyJob now has a real conversion
	// path for blocktemplate_blob (go-xmr-lib/support's
	// ParseBlockFromTemplateBlob + GetBlockHashingBlob -- see that
	// package's upstream.go doc comment), which made receiving that
	// raw blob safe -- but NOT opting into the advanced dialect
	// turned out to be its own, worse hazard: without
	// client_nonce_offset/client_pool_offset, every downstream miner
	// behind this leaf gets a byte-identical blob, so independent
	// miners routinely submit the exact same (job_id, nonce, result)
	// triple at low share difficulty. The upstream pool flags that as
	// a duplicate share, and enough of those within
	// nodejs-pool-sxmr's banThreshold/banPercent window got this
	// leaf's public IP banned for "using an invalid mining protocol"
	// in production. This flag/env var remains configurable -- an
	// operator who genuinely needs the ordinary, non-advanced dialect
	// instead can opt out by setting this to an agent string that
	// does NOT contain "xmr-node-proxy".
	flag.StringVar(&cfg.upstreamAgent, "upstream-agent", envOr("LEAF_PROXY_UPSTREAM_AGENT", "go-crypto-pool-leaf-proxy/xmr-node-proxy-1.0"), "mining-client agent string sent on upstream login -- defaults to an identifier containing the literal substring \"xmr-node-proxy\" (see this flag's doc comment) so the upstream pool grants the advanced xmr-node-proxy-client dialect and publishes client_nonce_offset/client_pool_offset, which this leaf needs to give downstream miners non-colliding blobs; the resulting raw blocktemplate_blob is safely handled via a real blocktemplate_blob->hashing-blob conversion path. Env: LEAF_PROXY_UPSTREAM_AGENT")

	flag.StringVar(&cfg.listenAddress, "listen-address", envOr("LEAF_PROXY_LISTEN_ADDRESS", ":5555"), "downstream miner-facing TCP listen address. Env: LEAF_PROXY_LISTEN_ADDRESS")
	flag.StringVar(&cfg.tlsListenAddress, "tls-listen-address", envOr("LEAF_PROXY_TLS_LISTEN_ADDRESS", ""), "optional SECOND downstream miner-facing TCP listen address, served over TLS using the shared self-signed-or-operator-supplied cert (see -tls-cert-file/-tls-key-file/-tls-cert-persist-path), alongside (never instead of) -listen-address. Empty (default) disables it entirely -- zero behavior change. Env: LEAF_PROXY_TLS_LISTEN_ADDRESS")
	flag.Uint64Var(&cfg.startingDifficulty, "starting-difficulty", envOrUint64("LEAF_PROXY_STARTING_DIFFICULTY", 10000), "starting downstream share difficulty; vardiff adjusts it from here. Env: LEAF_PROXY_STARTING_DIFFICULTY")
	flag.Uint64Var(&cfg.minDifficulty, "min-difficulty", envOrUint64("LEAF_PROXY_MIN_DIFFICULTY", 100), "absolute floor vardiff will never retarget below. Env: LEAF_PROXY_MIN_DIFFICULTY")
	flag.Uint64Var(&cfg.maxDifficulty, "max-difficulty", envOrUint64("LEAF_PROXY_MAX_DIFFICULTY", 1_000_000_000), "absolute ceiling vardiff will never retarget above. Env: LEAF_PROXY_MAX_DIFFICULTY")
	flag.IntVar(&cfg.vardiffTargetTime, "vardiff-target-time", envOrInt("LEAF_PROXY_VARDIFF_TARGET_TIME", 30), "seconds between shares vardiff aims for. Env: LEAF_PROXY_VARDIFF_TARGET_TIME")
	flag.DurationVar(&cfg.vardiffInterval, "vardiff-retarget-interval", envOrDuration("LEAF_PROXY_VARDIFF_RETARGET_INTERVAL", 60*time.Second), "how often each downstream session's own vardiff retarget timer fires. Env: LEAF_PROXY_VARDIFF_RETARGET_INTERVAL")
	flag.DurationVar(&cfg.jobMaxAge, "job-max-age", envOrDuration("LEAF_PROXY_JOB_MAX_AGE", 6*time.Minute), "real per-job expiry threshold; a submit against an older job is rejected. Env: LEAF_PROXY_JOB_MAX_AGE")

	flag.StringVar(&cfg.tlsCertFile, "tls-cert-file", envOr("LEAF_PROXY_TLS_CERT_FILE", ""), "optional PEM-encoded TLS certificate file for the shared, process-wide self-signed-or-operator-supplied cert used by -tls-listen-address. Empty (default) auto-generates a self-signed cert instead -- see -tls-cert-persist-path. Ignored entirely if -tls-listen-address is unset. Env: LEAF_PROXY_TLS_CERT_FILE")
	flag.StringVar(&cfg.tlsKeyFile, "tls-key-file", envOr("LEAF_PROXY_TLS_KEY_FILE", ""), "optional PEM-encoded TLS private key file paired with -tls-cert-file. Env: LEAF_PROXY_TLS_KEY_FILE")
	flag.StringVar(&cfg.tlsCertPersistPath, "tls-cert-persist-path", envOr("LEAF_PROXY_TLS_CERT_PERSIST_PATH", ""), "where to persist an auto-generated self-signed TLS cert/key pair so restarts reload it instead of rotating it. Empty (default) means in-memory only -- a fresh self-signed cert is generated on every restart. Ignored if -tls-cert-file/-tls-key-file are set. Env: LEAF_PROXY_TLS_CERT_PERSIST_PATH")

	flag.IntVar(&cfg.maxConnections, "max-connections", envOrInt("LEAF_PROXY_MAX_CONNECTIONS", 0), "max concurrent downstream miner connections, 0 = unlimited. Env: LEAF_PROXY_MAX_CONNECTIONS")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", envOrDuration("LEAF_PROXY_IDLE_TIMEOUT", 2*time.Minute), "rolling per-downstream-connection idle timeout. Env: LEAF_PROXY_IDLE_TIMEOUT")

	flag.DurationVar(&cfg.dialTimeout, "upstream-dial-timeout", envOrDuration("LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT", 10*time.Second), "timeout for dialing the upstream pool. Env: LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT")
	flag.DurationVar(&cfg.requestTimeout, "upstream-request-timeout", envOrDuration("LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT", 15*time.Second), "timeout for a single upstream request/response round-trip. Env: LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT")

	flag.IntVar(&cfg.randomxWorkers, "randomx-workers", envOrInt("LEAF_PROXY_RANDOMX_WORKERS", 0), "RandomX async validation worker pool size (see internal/leaflib/solo/asyncvalidation.go). 0/unset uses the documented default, runtime.NumCPU() -- NOT a hardcoded literal. Env: LEAF_PROXY_RANDOMX_WORKERS")
	flag.BoolVar(&cfg.invalidShareDisconnectEnabled, "invalid-share-disconnect-enabled", envOr("LEAF_PROXY_INVALID_SHARE_DISCONNECT_ENABLED", "true") == "true", "disconnect a downstream session after too many CONSECUTIVE real RandomX validation failures (see internal/leaflib.InvalidShareGuard) -- a security-hardening default, enabled unless explicitly turned off. Env: LEAF_PROXY_INVALID_SHARE_DISCONNECT_ENABLED (\"false\" to disable)")
	flag.IntVar(&cfg.invalidShareDisconnectThreshold, "invalid-share-disconnect-threshold", envOrInt("LEAF_PROXY_INVALID_SHARE_DISCONNECT_THRESHOLD", 0), "consecutive-invalid-share threshold before a downstream session is disconnected (see -invalid-share-disconnect-enabled). 0/unset uses the documented default (20). Env: LEAF_PROXY_INVALID_SHARE_DISCONNECT_THRESHOLD")

	flag.StringVar(&cfg.metricsListenAddress, "metrics-listen-address", envOr("LEAF_PROXY_METRICS_LISTEN_ADDRESS", "127.0.0.1:9601"), "HTTP listen address for /metrics (Prometheus) and the stats page. Separate from -listen-address (the downstream-facing stratum port). Defaults to loopback-only (127.0.0.1) -- an operator must explicitly set this to a wildcard/public address to expose stats/metrics publicly. Set to empty string to disable. Env: LEAF_PROXY_METRICS_LISTEN_ADDRESS")
	flag.BoolVar(&cfg.hideRemoteAddress, "hide-remote-address", envOrBool("LEAF_PROXY_HIDE_REMOTE_ADDRESS", false), "omit the \"Remote address\" column from the stats HTML page entirely -- recommended for public-facing deployments. Disabled by default. Env: LEAF_PROXY_HIDE_REMOTE_ADDRESS")
	flag.IntVar(&cfg.maxAddressLabels, "max-address-labels", envOrInt("LEAF_PROXY_MAX_ADDRESS_LABELS", 0), "cap on distinct payment-address labels tracked by leaf_proxy_miners_by_address and the stats page's per-address breakdown (0 = package default). Env: LEAF_PROXY_MAX_ADDRESS_LABELS")

	flag.StringVar(&cfg.addressFlagsFile, "address-flags-file", envOr("LEAF_PROXY_ADDRESS_FLAGS_FILE", ""), "path to a local, operator-maintained JSON file of manually banned payment addresses (see internal/leaflib/addressflags.FileSource's doc comment for the file format). Empty (default) disables the feature entirely -- leaf-proxy has no go-crypto-pool backend to poll instead. Env: LEAF_PROXY_ADDRESS_FLAGS_FILE")
	flag.DurationVar(&cfg.addressFlagsPollInterval, "address-flags-poll-interval", envOrDuration("LEAF_PROXY_ADDRESS_FLAGS_POLL_INTERVAL", 30*time.Second), "how often -address-flags-file is re-read. Ignored if -address-flags-file is unset. Env: LEAF_PROXY_ADDRESS_FLAGS_POLL_INTERVAL")

	flag.StringVar(&cfg.configFile, "config", envOr("LEAF_PROXY_CONFIG_FILE", ""), "optional path to a TOML config file providing defaults for any flag below that is not explicitly set via CLI flag or environment variable. See leaf-proxy.example.toml. Env: LEAF_PROXY_CONFIG_FILE")

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
	UpstreamHost     *string `toml:"upstream_host"`
	UpstreamPort     *int    `toml:"upstream_port"`
	UpstreamTLS      *bool   `toml:"upstream_tls"`
	UpstreamInsecure *bool   `toml:"upstream_tls_insecure_skip_verify"`
	UpstreamLogin    *string `toml:"upstream_login"`
	UpstreamPass     *string `toml:"upstream_pass"`
	UpstreamAgent    *string `toml:"upstream_agent"`

	ListenAddress          *string `toml:"listen_address"`
	TLSListenAddress       *string `toml:"tls_listen_address"`
	StartingDifficulty     *uint64 `toml:"starting_difficulty"`
	MinDifficulty          *uint64 `toml:"min_difficulty"`
	MaxDifficulty          *uint64 `toml:"max_difficulty"`
	VardiffTargetTime      *int    `toml:"vardiff_target_time_seconds"`
	VardiffIntervalSeconds *int    `toml:"vardiff_retarget_interval_seconds"`
	JobMaxAgeSeconds       *int    `toml:"job_max_age_seconds"`

	TLSCertFile        *string `toml:"tls_cert_file"`
	TLSKeyFile         *string `toml:"tls_key_file"`
	TLSCertPersistPath *string `toml:"tls_cert_persist_path"`

	MaxConnections     *int `toml:"max_connections"`
	IdleTimeoutSeconds *int `toml:"idle_timeout_seconds"`

	DialTimeoutSeconds    *int `toml:"upstream_dial_timeout_seconds"`
	RequestTimeoutSeconds *int `toml:"upstream_request_timeout_seconds"`

	RandomXWorkers                  *int  `toml:"randomx_workers"`
	InvalidShareDisconnectEnabled   *bool `toml:"invalid_share_disconnect_enabled"`
	InvalidShareDisconnectThreshold *int  `toml:"invalid_share_disconnect_threshold"`

	MetricsListenAddress *string `toml:"metrics_listen_address"`
	MaxAddressLabels     *int    `toml:"max_address_labels"`
	HideRemoteAddress    *bool   `toml:"hide_remote_address"`

	AddressFlagsFile                *string `toml:"address_flags_file"`
	AddressFlagsPollIntervalSeconds *int    `toml:"address_flags_poll_interval_seconds"`
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
		return fmt.Errorf("leaf-proxy: loading -config %s: %w", cfg.configFile, err)
	}

	cfgfile.ApplyString(&cfg.upstreamHost, fc.UpstreamHost, visited, "upstream-host", "LEAF_PROXY_UPSTREAM_HOST")
	cfgfile.ApplyInt(&cfg.upstreamPort, fc.UpstreamPort, visited, "upstream-port", "LEAF_PROXY_UPSTREAM_PORT")
	cfgfile.ApplyBool(&cfg.upstreamTLS, fc.UpstreamTLS, visited, "upstream-tls", "LEAF_PROXY_UPSTREAM_TLS")
	cfgfile.ApplyBool(&cfg.upstreamInsecure, fc.UpstreamInsecure, visited, "upstream-tls-insecure-skip-verify", "LEAF_PROXY_UPSTREAM_TLS_INSECURE_SKIP_VERIFY")
	cfgfile.ApplyString(&cfg.upstreamLogin, fc.UpstreamLogin, visited, "upstream-login", "LEAF_PROXY_UPSTREAM_LOGIN")
	cfgfile.ApplyString(&cfg.upstreamPass, fc.UpstreamPass, visited, "upstream-pass", "LEAF_PROXY_UPSTREAM_PASS")
	cfgfile.ApplyString(&cfg.upstreamAgent, fc.UpstreamAgent, visited, "upstream-agent", "LEAF_PROXY_UPSTREAM_AGENT")

	cfgfile.ApplyString(&cfg.listenAddress, fc.ListenAddress, visited, "listen-address", "LEAF_PROXY_LISTEN_ADDRESS")
	cfgfile.ApplyString(&cfg.tlsListenAddress, fc.TLSListenAddress, visited, "tls-listen-address", "LEAF_PROXY_TLS_LISTEN_ADDRESS")
	cfgfile.ApplyUint64(&cfg.startingDifficulty, fc.StartingDifficulty, visited, "starting-difficulty", "LEAF_PROXY_STARTING_DIFFICULTY")
	cfgfile.ApplyUint64(&cfg.minDifficulty, fc.MinDifficulty, visited, "min-difficulty", "LEAF_PROXY_MIN_DIFFICULTY")
	cfgfile.ApplyUint64(&cfg.maxDifficulty, fc.MaxDifficulty, visited, "max-difficulty", "LEAF_PROXY_MAX_DIFFICULTY")
	cfgfile.ApplyInt(&cfg.vardiffTargetTime, fc.VardiffTargetTime, visited, "vardiff-target-time", "LEAF_PROXY_VARDIFF_TARGET_TIME")

	if fc.VardiffIntervalSeconds != nil {
		d := time.Duration(*fc.VardiffIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.vardiffInterval, &d, visited, "vardiff-retarget-interval", "LEAF_PROXY_VARDIFF_RETARGET_INTERVAL")
	}
	if fc.JobMaxAgeSeconds != nil {
		d := time.Duration(*fc.JobMaxAgeSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.jobMaxAge, &d, visited, "job-max-age", "LEAF_PROXY_JOB_MAX_AGE")
	}

	cfgfile.ApplyString(&cfg.tlsCertFile, fc.TLSCertFile, visited, "tls-cert-file", "LEAF_PROXY_TLS_CERT_FILE")
	cfgfile.ApplyString(&cfg.tlsKeyFile, fc.TLSKeyFile, visited, "tls-key-file", "LEAF_PROXY_TLS_KEY_FILE")
	cfgfile.ApplyString(&cfg.tlsCertPersistPath, fc.TLSCertPersistPath, visited, "tls-cert-persist-path", "LEAF_PROXY_TLS_CERT_PERSIST_PATH")

	cfgfile.ApplyInt(&cfg.maxConnections, fc.MaxConnections, visited, "max-connections", "LEAF_PROXY_MAX_CONNECTIONS")
	if fc.IdleTimeoutSeconds != nil {
		d := time.Duration(*fc.IdleTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.idleTimeout, &d, visited, "idle-timeout", "LEAF_PROXY_IDLE_TIMEOUT")
	}

	if fc.DialTimeoutSeconds != nil {
		d := time.Duration(*fc.DialTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.dialTimeout, &d, visited, "upstream-dial-timeout", "LEAF_PROXY_UPSTREAM_DIAL_TIMEOUT")
	}
	if fc.RequestTimeoutSeconds != nil {
		d := time.Duration(*fc.RequestTimeoutSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.requestTimeout, &d, visited, "upstream-request-timeout", "LEAF_PROXY_UPSTREAM_REQUEST_TIMEOUT")
	}

	cfgfile.ApplyInt(&cfg.randomxWorkers, fc.RandomXWorkers, visited, "randomx-workers", "LEAF_PROXY_RANDOMX_WORKERS")
	cfgfile.ApplyBool(&cfg.invalidShareDisconnectEnabled, fc.InvalidShareDisconnectEnabled, visited, "invalid-share-disconnect-enabled", "LEAF_PROXY_INVALID_SHARE_DISCONNECT_ENABLED")
	cfgfile.ApplyInt(&cfg.invalidShareDisconnectThreshold, fc.InvalidShareDisconnectThreshold, visited, "invalid-share-disconnect-threshold", "LEAF_PROXY_INVALID_SHARE_DISCONNECT_THRESHOLD")

	cfgfile.ApplyString(&cfg.metricsListenAddress, fc.MetricsListenAddress, visited, "metrics-listen-address", "LEAF_PROXY_METRICS_LISTEN_ADDRESS")
	cfgfile.ApplyInt(&cfg.maxAddressLabels, fc.MaxAddressLabels, visited, "max-address-labels", "LEAF_PROXY_MAX_ADDRESS_LABELS")
	cfgfile.ApplyBool(&cfg.hideRemoteAddress, fc.HideRemoteAddress, visited, "hide-remote-address", "LEAF_PROXY_HIDE_REMOTE_ADDRESS")

	cfgfile.ApplyString(&cfg.addressFlagsFile, fc.AddressFlagsFile, visited, "address-flags-file", "LEAF_PROXY_ADDRESS_FLAGS_FILE")
	if fc.AddressFlagsPollIntervalSeconds != nil {
		d := time.Duration(*fc.AddressFlagsPollIntervalSeconds) * time.Second
		cfgfile.ApplyDuration(&cfg.addressFlagsPollInterval, &d, visited, "address-flags-poll-interval", "LEAF_PROXY_ADDRESS_FLAGS_POLL_INTERVAL")
	}

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
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("leaf-proxy: %v", err)
	}
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

	// Real, in-process, pure-Go RandomX validator -- NO external
	// randomx-service HTTP daemon dependency. leaf-proxy's local
	// re-validation gate (internal/leaflib/proxy/session.go's
	// handleSubmit) only calls ValidateBlobSeedResult on a genuine
	// block-level find (a submit that already meets the real upstream
	// pool's block target), not on every ordinary sub-block share -- at
	// that call frequency, pure-Go RandomX's real ~258ms/hash cost
	// (benchmarked separately, git.gammaspectra.live/P2Pool/go-randomx
	// @v1.0.0) is genuinely acceptable, and removing the external
	// daemon dependency simplifies leaf-proxy's deployment. See
	// internal/leaflib/validator/randomx_puregolang.go's doc comment
	// for the full honest writeup, including why leaf-solo's RXT
	// support (a real per-share hot path) still uses the external-
	// daemon-backed RandomXValidator instead.
	rxValidator := validator.NewPureGoRandomXValidator()

	vardiffCfg := leaflib.VardiffConfig{
		MinDifficulty:    cfg.minDifficulty,
		MaxDifficulty:    cfg.maxDifficulty,
		TargetTime:       cfg.vardiffTargetTime,
		RetargetInterval: cfg.vardiffInterval,
	}

	server := proxy.NewServer(cm, jobManager, rxValidator, upstream, logger, vardiffCfg, cfg.jobMaxAge)
	defer server.Shutdown()

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2a): worker
	// count is runtime.NumCPU() by DEFAULT (proxy.NewServer's own
	// construction already applies this), not a hardcoded literal 8;
	// an operator who wants a different fixed count can still get one
	// via -randomx-workers.
	if cfg.randomxWorkers > 0 {
		server.SetRandomXWorkerPoolSize(cfg.randomxWorkers, 0)
		logger.Printf("RandomX async validation worker pool size overridden to %d (default would have been runtime.NumCPU()=%d)", cfg.randomxWorkers, runtime.NumCPU())
	}

	// HARDENING FIX (DISPATCH_BRIEF.md, 2026-09-10, Fix 2b): disconnect
	// a downstream session after too many consecutive real RandomX
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

	// Real, manual ban enforcement (see internal/leaflib/addressflags's
	// package doc comment). Disabled (server.addressFlags stays nil)
	// unless -address-flags-file/LEAF_PROXY_ADDRESS_FLAGS_FILE is set
	// -- leaf-proxy has no go-crypto-pool backend to poll instead, so
	// a local file is the only real Source, mirroring cmd/leaf-solo's
	// identical wiring exactly.
	if cfg.addressFlagsFile != "" {
		flagsCache := addressflags.NewCache(addressflags.NewFileSource(cfg.addressFlagsFile), cfg.addressFlagsPollInterval, logger)
		flagsCache.Start(ctx)
		server.EnableAddressFlags(flagsCache)
		logger.Printf("manual ban enforcement ENABLED, polling %s every %s", cfg.addressFlagsFile, cfg.addressFlagsPollInterval)
	}

	// Real Prometheus /metrics + basic stats HTML page, exactly
	// mirroring cmd/leaf-solo/main.go's already-working
	// EnableMetrics/MetricsHandler/StatsHTMLHandler wiring pattern
	// (see that file for the reference implementation this was
	// ported from) -- ported unchanged aside from the LEAF_PROXY_
	// flag/env prefix and leaf-proxy's own metrics.Metrics type.
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

	ln, err := net.Listen("tcp", cfg.listenAddress)
	if err != nil {
		logger.Fatalf("failed to listen on %s: %v", cfg.listenAddress, err)
	}
	logger.Printf("listening for downstream miners on %s (starting difficulty %d)", cfg.listenAddress, cfg.startingDifficulty)

	// listeners mirrors leaf-direct/leaf-solo's own []net.Listener
	// shape (see those binaries' identical multi-listener fan-out)
	// even though leaf-proxy only ever has at most 2 listeners here:
	// the always-present plain one, plus an optional TLS one below.
	listeners := []net.Listener{ln}

	// Optional SECOND, TLS-wrapped downstream listener, alongside
	// (never instead of) the plain one above -- a complete no-op
	// when -tls-listen-address/LEAF_PROXY_TLS_LISTEN_ADDRESS is
	// unset (the default), matching every other optional feature's
	// contract in this repo.
	if cfg.tlsListenAddress != "" {
		cert, err := leaflib.LoadOrGenerateCert(cfg.tlsCertFile, cfg.tlsKeyFile, cfg.tlsCertPersistPath, cfg.tlsListenAddress, logger)
		if err != nil {
			logger.Fatalf("failed to load/generate shared TLS certificate: %v", err)
		}
		plainTLSLn, err := net.Listen("tcp", cfg.tlsListenAddress)
		if err != nil {
			_ = ln.Close()
			logger.Fatalf("failed to listen on %s: %v", cfg.tlsListenAddress, err)
		}
		tlsLn := tls.NewListener(plainTLSLn, &tls.Config{Certificates: []tls.Certificate{cert}})
		listeners = append(listeners, tlsLn)
		logger.Printf("listening for downstream miners on %s (TLS) (starting difficulty %d)", cfg.tlsListenAddress, cfg.startingDifficulty)
	} else {
		logger.Printf("TLS downstream listener disabled (-tls-listen-address is empty)")
	}

	errCh := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(l net.Listener) { errCh <- server.Serve(ctx, l, cfg.startingDifficulty) }(l)
	}

	select {
	case <-ctx.Done():
		logger.Println("shutdown signal received, draining connections...")
		for _, l := range listeners {
			_ = l.Close()
		}
		cm.Shutdown()
	case err := <-errCh:
		if err != nil {
			logger.Fatalf("listener error: %v", err)
		}
	}
}
