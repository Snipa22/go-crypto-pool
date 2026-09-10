// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
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
// duration field (idle-timeout), per the brief's explicit requirement, plus
// a dedicated block for the one field with a special-cased precedence rule,
// starting-difficulty (see that block's own comment below for why it gets
// more than the single representative case every other field above does).
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

		// -- bool field: invalid-share-disconnect-enabled -----------------
		{
			name: "invalid-share-disconnect-enabled/default",
			check: func(t *testing.T, cfg config) {
				if cfg.invalidShareDisconnectEnabled != true {
					t.Errorf("invalidShareDisconnectEnabled = %v, want hardcoded default %v", cfg.invalidShareDisconnectEnabled, true)
				}
			},
		},
		{
			name: "invalid-share-disconnect-enabled/file-only",
			toml: `invalid_share_disconnect_enabled = false`,
			check: func(t *testing.T, cfg config) {
				if cfg.invalidShareDisconnectEnabled != false {
					t.Errorf("invalidShareDisconnectEnabled = %v, want file value %v", cfg.invalidShareDisconnectEnabled, false)
				}
			},
		},
		{
			name: "invalid-share-disconnect-enabled/env-only",
			env:  map[string]string{"LEAF_SOLO_INVALID_SHARE_DISCONNECT_ENABLED": "false"},
			toml: `invalid_share_disconnect_enabled = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.invalidShareDisconnectEnabled != false {
					t.Errorf("invalidShareDisconnectEnabled = %v, want env value %v (env must beat file)", cfg.invalidShareDisconnectEnabled, false)
				}
			},
		},
		{
			name: "invalid-share-disconnect-enabled/flag-only",
			args: []string{"-invalid-share-disconnect-enabled=false"},
			toml: `invalid_share_disconnect_enabled = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.invalidShareDisconnectEnabled != false {
					t.Errorf("invalidShareDisconnectEnabled = %v, want flag value %v (flag must beat env absence and file)", cfg.invalidShareDisconnectEnabled, false)
				}
			},
		},
		{
			name: "invalid-share-disconnect-enabled/flag-env-file-all-set",
			args: []string{"-invalid-share-disconnect-enabled=false"},
			env:  map[string]string{"LEAF_SOLO_INVALID_SHARE_DISCONNECT_ENABLED": "true"},
			toml: `invalid_share_disconnect_enabled = false`,
			check: func(t *testing.T, cfg config) {
				if cfg.invalidShareDisconnectEnabled != false {
					t.Errorf("invalidShareDisconnectEnabled = %v, want flag value %v (flag must win full precedence over env=true)", cfg.invalidShareDisconnectEnabled, false)
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
			env:  map[string]string{"LEAF_SOLO_MAX_CONNECTIONS": "0"},
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

		// -- uint64 field with a special-cased precedence rule:
		// starting-difficulty. Unlike every other field above, the
		// underlying flag is fed by envOrUint64Fallback with TWO env var
		// names (LEAF_SOLO_STARTING_DIFFICULTY primary, legacy
		// LEAF_SOLO_DIFFICULTY fallback -- see loadConfig's own comment),
		// and applyConfigFile's ShouldApplyFile check ORs in the legacy
		// var explicitly (see applyConfigFile's "startingDifficultySrc"
		// comment) so a config-file value must not override an explicit
		// setting of EITHER env var. This gets its own dedicated block
		// (rather than the single representative-per-type case above)
		// specifically to exercise that hand-rolled OR logic end-to-end.
		{
			name: "starting-difficulty/default",
			check: func(t *testing.T, cfg config) {
				if cfg.startingDifficulty != 10000 {
					t.Errorf("startingDifficulty = %d, want hardcoded default %d", cfg.startingDifficulty, 10000)
				}
			},
		},
		{
			name: "starting-difficulty/file-only",
			toml: `starting_difficulty = 20000`,
			check: func(t *testing.T, cfg config) {
				if cfg.startingDifficulty != 20000 {
					t.Errorf("startingDifficulty = %d, want file value %d", cfg.startingDifficulty, 20000)
				}
			},
		},
		{
			name: "starting-difficulty/primary-env-only",
			env:  map[string]string{"LEAF_SOLO_STARTING_DIFFICULTY": "30000"},
			toml: `starting_difficulty = 20000`,
			check: func(t *testing.T, cfg config) {
				if cfg.startingDifficulty != 30000 {
					t.Errorf("startingDifficulty = %d, want primary env value %d (env must beat file)", cfg.startingDifficulty, 30000)
				}
			},
		},
		{
			name: "starting-difficulty/legacy-env-only",
			env:  map[string]string{"LEAF_SOLO_DIFFICULTY": "40000"},
			toml: `starting_difficulty = 20000`,
			check: func(t *testing.T, cfg config) {
				if cfg.startingDifficulty != 40000 {
					t.Errorf("startingDifficulty = %d, want legacy env value %d (legacy LEAF_SOLO_DIFFICULTY must also beat file, per the OR'd Source check)", cfg.startingDifficulty, 40000)
				}
			},
		},
		{
			name: "starting-difficulty/primary-env-beats-legacy-env",
			env:  map[string]string{"LEAF_SOLO_STARTING_DIFFICULTY": "30000", "LEAF_SOLO_DIFFICULTY": "40000"},
			toml: `starting_difficulty = 20000`,
			check: func(t *testing.T, cfg config) {
				if cfg.startingDifficulty != 30000 {
					t.Errorf("startingDifficulty = %d, want primary env value %d (envOrUint64Fallback checks the primary var first)", cfg.startingDifficulty, 30000)
				}
			},
		},
		{
			name: "starting-difficulty/flag-only",
			args: []string{"-starting-difficulty=50000"},
			toml: `starting_difficulty = 20000`,
			check: func(t *testing.T, cfg config) {
				if cfg.startingDifficulty != 50000 {
					t.Errorf("startingDifficulty = %d, want flag value %d (flag must beat env absence and file)", cfg.startingDifficulty, 50000)
				}
			},
		},
		{
			name: "starting-difficulty/flag-beats-legacy-env-and-file",
			args: []string{"-starting-difficulty=50000"},
			env:  map[string]string{"LEAF_SOLO_DIFFICULTY": "40000"},
			toml: `starting_difficulty = 20000`,
			check: func(t *testing.T, cfg config) {
				if cfg.startingDifficulty != 50000 {
					t.Errorf("startingDifficulty = %d, want flag value %d (flag must win full precedence over legacy env + file)", cfg.startingDifficulty, 50000)
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
