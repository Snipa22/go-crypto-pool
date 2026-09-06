// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runPrecedenceCase(t, tc)
		})
	}
}

// TestLoadConfig_DefaultUpstreamAgentDoesNotIdentifyAsXMRNodeProxy is
// required test 3 from the brief: the default -upstream-agent /
// LEAF_PROXY_UPSTREAM_AGENT value must NOT contain the literal
// substring "xmr-node-proxy" -- live-confirmed against
// pool.supportxmr.com that substring is exactly what flips the pool
// into its incompatible "advanced xmr-node-proxy client" dialect
// (raw, untrimmed blocktemplate_blob instead of the ordinary,
// correctly-sized blob field), which is what caused leaf-proxy to
// relay an oversized blob to downstream xmrig miners (login error
// code: 4).
func TestLoadConfig_DefaultUpstreamAgentDoesNotIdentifyAsXMRNodeProxy(t *testing.T) {
	runPrecedenceCase(t, precedenceCase{
		name: "upstream-agent/default-does-not-contain-xmr-node-proxy",
		check: func(t *testing.T, cfg config) {
			if strings.Contains(cfg.upstreamAgent, "xmr-node-proxy") {
				t.Errorf("default upstreamAgent = %q, must NOT contain the substring %q (see this test's doc comment)", cfg.upstreamAgent, "xmr-node-proxy")
			}
			if cfg.upstreamAgent == "" {
				t.Error("default upstreamAgent must not be empty")
			}
		},
	})
}
