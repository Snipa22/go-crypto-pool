// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"flag"
	"os"
	"path/filepath"
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
	flag.CommandLine = flag.NewFlagSet("leaf-solo-test", flag.ContinueOnError)

	args := append([]string{"leaf-solo"}, tc.args...)
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
// cfgfile.Decode, not a fake), across one string field (network), one bool
// field (trust-enabled), one int field (vardiff-target-time) and one
// duration field (idle-timeout), per the brief's explicit requirement.
func TestLoadConfigPrecedence(t *testing.T) {
	cases := []precedenceCase{
		// -- string field: network ---------------------------------------
		{
			name: "network/default",
			check: func(t *testing.T, cfg config) {
				if cfg.network != "testnet" {
					t.Errorf("network = %q, want hardcoded default %q", cfg.network, "testnet")
				}
			},
		},
		{
			name: "network/file-only",
			toml: `network = "mainnet"`,
			check: func(t *testing.T, cfg config) {
				if cfg.network != "mainnet" {
					t.Errorf("network = %q, want file value %q", cfg.network, "mainnet")
				}
			},
		},
		{
			name: "network/env-only",
			env:  map[string]string{"LEAF_SOLO_NETWORK": "mainnet"},
			toml: `network = "testnet"`,
			check: func(t *testing.T, cfg config) {
				if cfg.network != "mainnet" {
					t.Errorf("network = %q, want env value %q (env must beat file)", cfg.network, "mainnet")
				}
			},
		},
		{
			name: "network/flag-only",
			args: []string{"-network=mainnet"},
			toml: `network = "testnet"`,
			check: func(t *testing.T, cfg config) {
				if cfg.network != "mainnet" {
					t.Errorf("network = %q, want flag value %q (flag must beat env absence and file)", cfg.network, "mainnet")
				}
			},
		},
		{
			name: "network/flag-env-file-all-set",
			args: []string{"-network=mainnet"},
			env:  map[string]string{"LEAF_SOLO_NETWORK": "testnet"},
			toml: `network = "testnet"`,
			check: func(t *testing.T, cfg config) {
				if cfg.network != "mainnet" {
					t.Errorf("network = %q, want flag value %q (flag must win full precedence)", cfg.network, "mainnet")
				}
			},
		},

		// -- bool field: trust-enabled ------------------------------------
		{
			name: "trust-enabled/default",
			check: func(t *testing.T, cfg config) {
				if cfg.trustEnabled != false {
					t.Errorf("trustEnabled = %v, want hardcoded default %v", cfg.trustEnabled, false)
				}
			},
		},
		{
			name: "trust-enabled/file-only",
			toml: `trust_enabled = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.trustEnabled != true {
					t.Errorf("trustEnabled = %v, want file value %v", cfg.trustEnabled, true)
				}
			},
		},
		{
			name: "trust-enabled/env-only",
			env:  map[string]string{"LEAF_SOLO_TRUST_ENABLED": "false"},
			toml: `trust_enabled = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.trustEnabled != false {
					t.Errorf("trustEnabled = %v, want env value %v (env must beat file)", cfg.trustEnabled, false)
				}
			},
		},
		{
			name: "trust-enabled/flag-only",
			args: []string{"-trust-enabled=true"},
			toml: `trust_enabled = false`,
			check: func(t *testing.T, cfg config) {
				if cfg.trustEnabled != true {
					t.Errorf("trustEnabled = %v, want flag value %v (flag must beat env absence and file)", cfg.trustEnabled, true)
				}
			},
		},
		{
			name: "trust-enabled/flag-env-file-all-set",
			args: []string{"-trust-enabled=true"},
			env:  map[string]string{"LEAF_SOLO_TRUST_ENABLED": "false"},
			toml: `trust_enabled = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.trustEnabled != true {
					t.Errorf("trustEnabled = %v, want flag value %v (flag must win full precedence over env=false)", cfg.trustEnabled, true)
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
			env:  map[string]string{"LEAF_SOLO_VARDIFF_TARGET_TIME": "60"},
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
			env:  map[string]string{"LEAF_SOLO_VARDIFF_TARGET_TIME": "60"},
			toml: `vardiff_target_time_seconds = 45`,
			check: func(t *testing.T, cfg config) {
				if cfg.vardiffTargetTime != 75 {
					t.Errorf("vardiffTargetTime = %d, want flag value %d (flag must win full precedence)", cfg.vardiffTargetTime, 75)
				}
			},
		},

		// -- duration field: idle-timeout ---------------------------------
		{
			name: "idle-timeout/default",
			check: func(t *testing.T, cfg config) {
				if cfg.idleTimeout != 2*time.Minute {
					t.Errorf("idleTimeout = %v, want hardcoded default %v", cfg.idleTimeout, 2*time.Minute)
				}
			},
		},
		{
			name: "idle-timeout/file-only",
			toml: `idle_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.idleTimeout != 100*time.Second {
					t.Errorf("idleTimeout = %v, want file value %v", cfg.idleTimeout, 100*time.Second)
				}
			},
		},
		{
			name: "idle-timeout/env-only",
			env:  map[string]string{"LEAF_SOLO_IDLE_TIMEOUT": "200s"},
			toml: `idle_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.idleTimeout != 200*time.Second {
					t.Errorf("idleTimeout = %v, want env value %v (env must beat file)", cfg.idleTimeout, 200*time.Second)
				}
			},
		},
		{
			name: "idle-timeout/flag-only",
			args: []string{"-idle-timeout=300s"},
			toml: `idle_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.idleTimeout != 300*time.Second {
					t.Errorf("idleTimeout = %v, want flag value %v (flag must beat env absence and file)", cfg.idleTimeout, 300*time.Second)
				}
			},
		},
		{
			name: "idle-timeout/flag-env-file-all-set",
			args: []string{"-idle-timeout=300s"},
			env:  map[string]string{"LEAF_SOLO_IDLE_TIMEOUT": "200s"},
			toml: `idle_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.idleTimeout != 300*time.Second {
					t.Errorf("idleTimeout = %v, want flag value %v (flag must win full precedence)", cfg.idleTimeout, 300*time.Second)
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
