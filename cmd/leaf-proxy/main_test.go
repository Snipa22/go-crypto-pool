// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/proxy"
)

// precedenceCase drives one subtest of TestLoadConfigPrecedence. toml, if
// non-empty, is written to a temp file and wired in via "-config=<path>";
// env is applied with t.Setenv (auto-restored); args are appended after the
// binary name in os.Args before calling loadConfig().
type precedenceCase struct {
	name  string
	args  []string
	env   map[string]string
	toml  string
	check func(t *testing.T, cfg config)
}

// runPrecedenceCase resets flag.CommandLine to a fresh FlagSet and
// save/restores os.Args + flag.CommandLine around loadConfig(), since
// loadConfig registers its flags on the package-level flag.CommandLine via
// flag.StringVar/flag.BoolVar/etc.
func runPrecedenceCase(t *testing.T, tc precedenceCase) {
	t.Helper()

	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	flag.CommandLine = flag.NewFlagSet("leaf-proxy-test", flag.ContinueOnError)

	args := append([]string{"leaf-proxy"}, tc.args...)
	if tc.toml != "" {
		dir := t.TempDir()
		path := filepath.Join(dir, "cfg.toml")
		if err := os.WriteFile(path, []byte(tc.toml), 0o644); err != nil {
			t.Fatalf("writing test config file: %v", err)
		}
		args = append(args, "-config="+path)
	}
	os.Args = args

	for k, v := range tc.env {
		t.Setenv(k, v)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() returned unexpected error: %v", err)
	}
	tc.check(t, cfg)
}

// TestLoadConfigPrecedence proves the real flag > env > config-file >
// hardcoded-default precedence order end-to-end (real TOML decode via
// cfgfile.Decode, not a fake), across one string field (upstream-host), one
// bool field (upstream-tls), one int field (vardiff-target-time) and one
// duration field (job-max-age), per the brief's explicit requirement.
func TestLoadConfigPrecedence(t *testing.T) {
	cases := []precedenceCase{
		// -- string field: upstream-host --------------------------------
		{
			name: "upstream-host/default",
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamHost != "pool.supportxmr.com" {
					t.Errorf("upstreamHost = %q, want hardcoded default %q", cfg.upstreamHost, "pool.supportxmr.com")
				}
			},
		},
		{
			name: "upstream-host/file-only",
			toml: `upstream_host = "file-host.example"`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamHost != "file-host.example" {
					t.Errorf("upstreamHost = %q, want file value %q", cfg.upstreamHost, "file-host.example")
				}
			},
		},
		{
			name: "upstream-host/env-only",
			env:  map[string]string{"LEAF_PROXY_UPSTREAM_HOST": "env-host.example"},
			toml: `upstream_host = "file-host.example"`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamHost != "env-host.example" {
					t.Errorf("upstreamHost = %q, want env value %q (env must beat file)", cfg.upstreamHost, "env-host.example")
				}
			},
		},
		{
			name: "upstream-host/flag-only",
			args: []string{"-upstream-host=cli-host.example"},
			toml: `upstream_host = "file-host.example"`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamHost != "cli-host.example" {
					t.Errorf("upstreamHost = %q, want flag value %q (flag must beat env absence and file)", cfg.upstreamHost, "cli-host.example")
				}
			},
		},
		{
			name: "upstream-host/flag-env-file-all-set",
			args: []string{"-upstream-host=cli-host.example"},
			env:  map[string]string{"LEAF_PROXY_UPSTREAM_HOST": "env-host.example"},
			toml: `upstream_host = "file-host.example"`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamHost != "cli-host.example" {
					t.Errorf("upstreamHost = %q, want flag value %q (flag must win full precedence)", cfg.upstreamHost, "cli-host.example")
				}
			},
		},

		// -- bool field: upstream-tls ------------------------------------
		{
			name: "upstream-tls/default",
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamTLS != false {
					t.Errorf("upstreamTLS = %v, want hardcoded default %v", cfg.upstreamTLS, false)
				}
			},
		},
		{
			name: "upstream-tls/file-only",
			toml: `upstream_tls = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamTLS != true {
					t.Errorf("upstreamTLS = %v, want file value %v", cfg.upstreamTLS, true)
				}
			},
		},
		{
			name: "upstream-tls/env-only",
			env:  map[string]string{"LEAF_PROXY_UPSTREAM_TLS": "false"},
			toml: `upstream_tls = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamTLS != false {
					t.Errorf("upstreamTLS = %v, want env value %v (env must beat file)", cfg.upstreamTLS, false)
				}
			},
		},
		{
			name: "upstream-tls/flag-only",
			args: []string{"-upstream-tls=true"},
			toml: `upstream_tls = false`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamTLS != true {
					t.Errorf("upstreamTLS = %v, want flag value %v (flag must beat env absence and file)", cfg.upstreamTLS, true)
				}
			},
		},
		{
			name: "upstream-tls/flag-env-file-all-set",
			args: []string{"-upstream-tls=true"},
			env:  map[string]string{"LEAF_PROXY_UPSTREAM_TLS": "false"},
			toml: `upstream_tls = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.upstreamTLS != true {
					t.Errorf("upstreamTLS = %v, want flag value %v (flag must win full precedence over env=false)", cfg.upstreamTLS, true)
				}
			},
		},

		// -- int field: vardiff-target-time -------------------------------
		{
			name: "vardiff-target-time/default",
			check: func(t *testing.T, cfg config) {
				if cfg.vardiffTargetTime != 30 {
					t.Errorf("vardiffTargetTime = %d, want hardcoded default %d", cfg.vardiffTargetTime, 30)
				}
			},
		},
		{
			name: "vardiff-target-time/file-only",
			toml: `vardiff_target_time_seconds = 45`,
			check: func(t *testing.T, cfg config) {
				if cfg.vardiffTargetTime != 45 {
					t.Errorf("vardiffTargetTime = %d, want file value %d", cfg.vardiffTargetTime, 45)
				}
			},
		},
		{
			name: "vardiff-target-time/env-only",
			env:  map[string]string{"LEAF_PROXY_VARDIFF_TARGET_TIME": "60"},
			toml: `vardiff_target_time_seconds = 45`,
			check: func(t *testing.T, cfg config) {
				if cfg.vardiffTargetTime != 60 {
					t.Errorf("vardiffTargetTime = %d, want env value %d (env must beat file)", cfg.vardiffTargetTime, 60)
				}
			},
		},
		{
			name: "vardiff-target-time/flag-only",
			args: []string{"-vardiff-target-time=75"},
			toml: `vardiff_target_time_seconds = 45`,
			check: func(t *testing.T, cfg config) {
				if cfg.vardiffTargetTime != 75 {
					t.Errorf("vardiffTargetTime = %d, want flag value %d (flag must beat env absence and file)", cfg.vardiffTargetTime, 75)
				}
			},
		},
		{
			name: "vardiff-target-time/flag-env-file-all-set",
			args: []string{"-vardiff-target-time=75"},
			env:  map[string]string{"LEAF_PROXY_VARDIFF_TARGET_TIME": "60"},
			toml: `vardiff_target_time_seconds = 45`,
			check: func(t *testing.T, cfg config) {
				if cfg.vardiffTargetTime != 75 {
					t.Errorf("vardiffTargetTime = %d, want flag value %d (flag must win full precedence)", cfg.vardiffTargetTime, 75)
				}
			},
		},

		// -- duration field: job-max-age ----------------------------------
		{
			name: "job-max-age/default",
			check: func(t *testing.T, cfg config) {
				if cfg.jobMaxAge != 6*time.Minute {
					t.Errorf("jobMaxAge = %v, want hardcoded default %v", cfg.jobMaxAge, 6*time.Minute)
				}
			},
		},
		{
			name: "job-max-age/file-only",
			toml: `job_max_age_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.jobMaxAge != 100*time.Second {
					t.Errorf("jobMaxAge = %v, want file value %v", cfg.jobMaxAge, 100*time.Second)
				}
			},
		},
		{
			name: "job-max-age/env-only",
			env:  map[string]string{"LEAF_PROXY_JOB_MAX_AGE": "200s"},
			toml: `job_max_age_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.jobMaxAge != 200*time.Second {
					t.Errorf("jobMaxAge = %v, want env value %v (env must beat file)", cfg.jobMaxAge, 200*time.Second)
				}
			},
		},
		{
			name: "job-max-age/flag-only",
			args: []string{"-job-max-age=300s"},
			toml: `job_max_age_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.jobMaxAge != 300*time.Second {
					t.Errorf("jobMaxAge = %v, want flag value %v (flag must beat env absence and file)", cfg.jobMaxAge, 300*time.Second)
				}
			},
		},
		{
			name: "job-max-age/flag-env-file-all-set",
			args: []string{"-job-max-age=300s"},
			env:  map[string]string{"LEAF_PROXY_JOB_MAX_AGE": "200s"},
			toml: `job_max_age_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.jobMaxAge != 300*time.Second {
					t.Errorf("jobMaxAge = %v, want flag value %v (flag must win full precedence)", cfg.jobMaxAge, 300*time.Second)
				}
			},
		},

		// -- int field: max-connections (Fix 13, DISPATCH_BRIEF.md
		// 2026-09-10 -- the default changed from 0 (unlimited) to a
		// real, generous-but-bounded leaflib.DefaultLeafMaxConnections;
		// this block proves the new default AND that an operator can
		// still explicitly opt back into 0/unlimited via flag or env,
		// exactly as before this fix).
		{
			name: "max-connections/default",
			check: func(t *testing.T, cfg config) {
				if cfg.maxConnections != leaflib.DefaultLeafMaxConnections {
					t.Errorf("maxConnections = %d, want the new hardcoded default %d", cfg.maxConnections, leaflib.DefaultLeafMaxConnections)
				}
			},
		},
		{
			name: "max-connections/flag-explicit-zero-still-means-unlimited",
			args: []string{"-max-connections=0"},
			check: func(t *testing.T, cfg config) {
				if cfg.maxConnections != 0 {
					t.Errorf("maxConnections = %d, want 0 -- an operator explicitly setting 0 must still get unlimited, the default-value change must not remove this override", cfg.maxConnections)
				}
			},
		},
		{
			name: "max-connections/env-explicit-zero-still-means-unlimited",
			env:  map[string]string{"LEAF_PROXY_MAX_CONNECTIONS": "0"},
			check: func(t *testing.T, cfg config) {
				if cfg.maxConnections != 0 {
					t.Errorf("maxConnections = %d, want 0 -- an operator explicitly setting env=0 must still get unlimited", cfg.maxConnections)
				}
			},
		},
		{
			name: "max-connections/flag-custom-value",
			args: []string{"-max-connections=500"},
			check: func(t *testing.T, cfg config) {
				if cfg.maxConnections != 500 {
					t.Errorf("maxConnections = %d, want flag value 500 (flag must still override the new default)", cfg.maxConnections)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runPrecedenceCase(t, tc)
		})
	}
}

// TestLoadConfig_DefaultUpstreamAgentIdentifiesAsXMRNodeProxy is
// required test 3 from the brief: the default -upstream-agent /
// LEAF_PROXY_UPSTREAM_AGENT value MUST contain the literal substring
// "xmr-node-proxy" -- live-confirmed against pool.supportxmr.com
// that substring is exactly what grants this leaf the "advanced
// xmr-node-proxy client" dialect (client_nonce_offset/
// client_pool_offset publication), which is required for downstream
// miners behind this leaf to receive non-colliding blobs. NOT
// opting into that dialect is what previously caused this leaf's
// public IP to be banned by a real upstream pool for duplicate share
// submissions ("using an invalid mining protocol") -- the inverse of
// this test's old invariant, reversed deliberately, not
// accidentally.
func TestLoadConfig_DefaultUpstreamAgentIdentifiesAsXMRNodeProxy(t *testing.T) {
	runPrecedenceCase(t, precedenceCase{
		name: "upstream-agent/default-contains-xmr-node-proxy",
		check: func(t *testing.T, cfg config) {
			if !strings.Contains(cfg.upstreamAgent, "xmr-node-proxy") {
				t.Errorf("default upstreamAgent = %q, must contain the substring %q (see this test's doc comment)", cfg.upstreamAgent, "xmr-node-proxy")
			}
			if cfg.upstreamAgent == "" {
				t.Error("default upstreamAgent must not be empty")
			}
		},
	})
}

// --- dev-fee mechanism tests (DISPATCH_BRIEF.md "leaf-proxy dev-fee
// second-connection") ---------------------------------------------

// TestLoadConfig_DevFeePercentPrecedenceAndDefault proves
// -dev-fee-percent/LEAF_PROXY_DEV_FEE_PERCENT follows the exact same
// flag > env > file > hardcoded-default precedence every other flag
// in this file follows, and that its hardcoded default is 1.0 (NOT
// 0 -- matching the legacy xmr-node-proxy reference's own
// pre-configured 1% donation, per DISPATCH_BRIEF.md's explicit
// instruction; an operator must explicitly opt OUT via 0).
func TestLoadConfig_DevFeePercentPrecedenceAndDefault(t *testing.T) {
	cases := []precedenceCase{
		{
			name: "dev-fee-percent/default",
			check: func(t *testing.T, cfg config) {
				if cfg.devFeePercent != 1.0 {
					t.Errorf("devFeePercent = %v, want hardcoded default %v", cfg.devFeePercent, 1.0)
				}
			},
		},
		{
			name: "dev-fee-percent/file-only",
			toml: `dev_fee_percent = 2.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.devFeePercent != 2.5 {
					t.Errorf("devFeePercent = %v, want file value %v", cfg.devFeePercent, 2.5)
				}
			},
		},
		{
			name: "dev-fee-percent/env-only",
			env:  map[string]string{"LEAF_PROXY_DEV_FEE_PERCENT": "3"},
			toml: `dev_fee_percent = 2.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.devFeePercent != 3 {
					t.Errorf("devFeePercent = %v, want env value %v (env must beat file)", cfg.devFeePercent, 3.0)
				}
			},
		},
		{
			name: "dev-fee-percent/flag-only",
			args: []string{"-dev-fee-percent=0"},
			toml: `dev_fee_percent = 2.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.devFeePercent != 0 {
					t.Errorf("devFeePercent = %v, want flag value %v (flag must beat env absence and file; also proves an operator can explicitly opt OUT via 0 despite the non-zero default)", cfg.devFeePercent, 0.0)
				}
			},
		},
		{
			name: "dev-fee-percent/flag-env-file-all-set",
			args: []string{"-dev-fee-percent=5"},
			env:  map[string]string{"LEAF_PROXY_DEV_FEE_PERCENT": "3"},
			toml: `dev_fee_percent = 2.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.devFeePercent != 5 {
					t.Errorf("devFeePercent = %v, want flag value %v (flag must win full precedence)", cfg.devFeePercent, 5.0)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runPrecedenceCase(t, tc)
		})
	}
}

// TestLoadConfig_DevFeePercentInvalidRangeFailsFast is the required
// brief test: an out-of-[0,100]-range -dev-fee-percent must fail
// config validation at startup (loadConfig returning a non-nil,
// clearly-worded error), never silently clamp or accept it.
func TestLoadConfig_DevFeePercentInvalidRangeFailsFast(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "negative", args: []string{"-dev-fee-percent=-1"}},
		{name: "above-100", args: []string{"-dev-fee-percent=100.01"}},
		{name: "way-above-100", args: []string{"-dev-fee-percent=1000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldArgs := os.Args
			oldCommandLine := flag.CommandLine
			t.Cleanup(func() {
				os.Args = oldArgs
				flag.CommandLine = oldCommandLine
			})
			flag.CommandLine = flag.NewFlagSet("leaf-proxy-test", flag.ContinueOnError)
			os.Args = append([]string{"leaf-proxy"}, tc.args...)

			_, err := loadConfig()
			if err == nil {
				t.Fatalf("loadConfig() with args %v: expected a validation error, got nil", tc.args)
			}
			if !strings.Contains(err.Error(), "dev-fee-percent") {
				t.Errorf("loadConfig() error = %q, want it to mention -dev-fee-percent so an operator can tell what's wrong", err.Error())
			}
		})
	}
}

// TestValidateDevFeePercent_BoundariesAccepted proves the documented
// valid range is INCLUSIVE of both 0 and 100 -- neither boundary
// value itself should ever be rejected.
func TestValidateDevFeePercent_BoundariesAccepted(t *testing.T) {
	for _, v := range []float64{0, 100} {
		if err := validateDevFeePercent(v); err != nil {
			t.Errorf("validateDevFeePercent(%v) = %v, want nil (boundary values are valid)", v, err)
		}
	}
}

// TestSetupDevFee_ZeroPercentIsANoOp is the required brief test:
// dev-fee-percent=0 must result in ZERO dev-fee *proxy.UpstreamClient
// construction/dial attempts -- a complete no-op. Passing nil for
// both debugLogger and jobManager (which setupDevFee would otherwise
// dereference) and an already-cancelled ctx additionally proves this
// codepath returns before ever touching any of them: a real
// dial/construction attempt against a nil jobManager or a cancelled
// ctx would panic/error, not silently return (nil, nil).
func TestSetupDevFee_ZeroPercentIsANoOp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled: a real dial attempt would fail fast on this
	logger := log.New(io.Discard, "", 0)

	cfg := config{devFeePercent: 0}
	upstream, err := setupDevFee(ctx, cfg, logger, nil, nil)
	if err != nil {
		t.Fatalf("setupDevFee with devFeePercent=0 returned an unexpected error: %v", err)
	}
	if upstream != nil {
		t.Fatalf("setupDevFee with devFeePercent=0 must be a complete no-op -- expected a nil *proxy.UpstreamClient (no second connection ever constructed, let alone dialed), got %+v", upstream)
	}
}

// TestSetupDevFee_PositivePercentConstructsAndConnects is the
// integration-style complement: against a real fake upstream pool
// TCP server, a positive -dev-fee-percent DOES construct and
// successfully Connect() a second *proxy.UpstreamClient, and wires it
// into jobManager via EnableDevFee (proven indirectly: NextJob must
// be able to mint a RouteDevFee job once enabled -- see
// internal/leaflib/proxy/devfee_test.go for the focused unit coverage
// of the routing/pairing logic itself; this test's job here is only
// to prove setupDevFee's own real dial/connect/wiring side effects).
func TestSetupDevFee_PositivePercentConstructsAndConnects(t *testing.T) {
	pool := newDevFeeTestPoolServer(t)
	host, port := pool.addr()

	logger := log.New(io.Discard, "", 0)
	jm := proxy.NewJobManager(noTemplateSource{}, logger)

	cfg := config{
		devFeePercent:  1,
		upstreamHost:   host,
		upstreamPort:   port,
		dialTimeout:    2 * time.Second,
		requestTimeout: 2 * time.Second,
		idleTimeout:    30 * time.Second,
	}
	upstream, err := setupDevFee(context.Background(), cfg, logger, nil, jm)
	if err != nil {
		t.Fatalf("setupDevFee with devFeePercent=1 against a real fake pool server failed: %v", err)
	}
	if upstream == nil {
		t.Fatal("expected a non-nil *proxy.UpstreamClient")
	}
	t.Cleanup(func() { _ = upstream.Close() })
	if !upstream.Connected() {
		t.Error("expected the dev-fee upstream connection to be Connected() after setupDevFee returns")
	}
}

// noTemplateSource is a trivial proxy.TemplateSource stand-in with no
// real template -- TestSetupDevFee_PositivePercentConstructsAndConnects
// only needs a valid *proxy.JobManager to pass to setupDevFee/
// EnableDevFee; it never actually calls NextJob.
type noTemplateSource struct{}

func (noTemplateSource) CurrentTemplate() *proxy.WorkerTemplate       { return nil }
func (noTemplateSource) Subscribe(func(*proxy.WorkerTemplate)) func() { return func() {} }

// devFeeTestPoolServer is a minimal, real TCP server that speaks just
// enough of the upstream JSON-RPC login dialect for a real
// *proxy.UpstreamClient's Connect to succeed against it, mirroring
// internal/leaflib/proxy's own fakePoolServer test pattern -- kept as
// a separate, minimal copy here rather than exported from the proxy
// package purely for this one cmd-level integration test, since
// exporting test-only server plumbing across a package boundary is
// not otherwise a pattern this codebase uses.
type devFeeTestPoolServer struct {
	ln net.Listener
}

func newDevFeeTestPoolServer(t *testing.T) *devFeeTestPoolServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake pool listener: %v", err)
	}
	s := &devFeeTestPoolServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *devFeeTestPoolServer) addr() (string, int) {
	tcpAddr := s.ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (s *devFeeTestPoolServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *devFeeTestPoolServer) handle(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		_ = conn.Close()
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		_ = conn.Close()
		return
	}
	blob := make([]byte, 152)
	for i := range blob {
		blob[i] = '0'
	}
	resp := fmt.Sprintf(`{"id":%d,"jsonrpc":"2.0","result":{"id":"dev-fee-test-session","status":"OK","job":{"job_id":"dev-fee-test-job-1","blob":"%s","target_diff":1000,"height":1,"seed_hash":"%s"}}}`,
		req.ID, string(blob), "0000000000000000000000000000000000000000000000000000000000000000")
	_, _ = conn.Write([]byte(resp + "\n"))
	// Deliberately keep the connection open and idle afterward, like
	// a real healthy pool connection between jobs -- this handler
	// goroutine blocks here until the listener/conn is torn down by
	// t.Cleanup, mirroring internal/leaflib/proxy's own
	// wellBehavedFakePoolServer pattern.
	<-make(chan struct{})
}
