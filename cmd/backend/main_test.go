package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

func TestParseNetwork(t *testing.T) {
	cases := []struct {
		raw     string
		want    poolpb.Network
		wantErr bool
	}{
		{raw: "mainnet", want: poolpb.Network_NETWORK_MAINNET},
		{raw: "MAINNET", want: poolpb.Network_NETWORK_MAINNET},
		{raw: "MainNet", want: poolpb.Network_NETWORK_MAINNET},
		{raw: " mainnet ", want: poolpb.Network_NETWORK_MAINNET},
		{raw: "testnet", want: poolpb.Network_NETWORK_TESTNET},
		{raw: "TESTNET", want: poolpb.Network_NETWORK_TESTNET},
		{raw: "", wantErr: true},
		{raw: "regtest", wantErr: true},
		{raw: "main", wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, err := parseNetwork(c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseNetwork(%q) = %v, nil; want error", c.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNetwork(%q) unexpected error: %v", c.raw, err)
			}
			if got != c.want {
				t.Fatalf("parseNetwork(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

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
// flag.StringVar/flag.Int64Var/etc.
func runPrecedenceCase(t *testing.T, tc precedenceCase) {
	t.Helper()

	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	flag.CommandLine = flag.NewFlagSet("backend-test", flag.ContinueOnError)

	args := append([]string{"backend"}, tc.args...)
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
// cfgfile.Decode, not a fake), across two string fields (db-dsn and
// jwt-secret -- the latter added specifically because it is the
// authapi-required secret documented in this file's package doc comment),
// one int64 field (unlocker-tari-maturity), one duration field
// (unlocker-poll-interval), and one float64 field (payout-pps-fee-percent,
// substituted for a bool field per the brief's instruction -- backend
// genuinely has no bool-typed setting among its current env vars) per the
// brief's explicit requirement.
func TestLoadConfigPrecedence(t *testing.T) {
	cases := []precedenceCase{
		// -- string field: db-dsn ----------------------------------------
		{
			name: "db-dsn/default",
			check: func(t *testing.T, cfg config) {
				if cfg.dbDSN != "" {
					t.Errorf("dbDSN = %q, want hardcoded default %q", cfg.dbDSN, "")
				}
			},
		},
		{
			name: "db-dsn/file-only",
			toml: `db_dsn = "postgres://file/db"`,
			check: func(t *testing.T, cfg config) {
				if cfg.dbDSN != "postgres://file/db" {
					t.Errorf("dbDSN = %q, want file value %q", cfg.dbDSN, "postgres://file/db")
				}
			},
		},
		{
			name: "db-dsn/env-only",
			env:  map[string]string{"GCPOOL_DB_DSN": "postgres://env/db"},
			toml: `db_dsn = "postgres://file/db"`,
			check: func(t *testing.T, cfg config) {
				if cfg.dbDSN != "postgres://env/db" {
					t.Errorf("dbDSN = %q, want env value %q (env must beat file)", cfg.dbDSN, "postgres://env/db")
				}
			},
		},
		{
			name: "db-dsn/flag-only",
			args: []string{"-db-dsn=postgres://cli/db"},
			toml: `db_dsn = "postgres://file/db"`,
			check: func(t *testing.T, cfg config) {
				if cfg.dbDSN != "postgres://cli/db" {
					t.Errorf("dbDSN = %q, want flag value %q (flag must beat env absence and file)", cfg.dbDSN, "postgres://cli/db")
				}
			},
		},
		{
			name: "db-dsn/flag-env-file-all-set",
			args: []string{"-db-dsn=postgres://cli/db"},
			env:  map[string]string{"GCPOOL_DB_DSN": "postgres://env/db"},
			toml: `db_dsn = "postgres://file/db"`,
			check: func(t *testing.T, cfg config) {
				if cfg.dbDSN != "postgres://cli/db" {
					t.Errorf("dbDSN = %q, want flag value %q (flag must win full precedence)", cfg.dbDSN, "postgres://cli/db")
				}
			},
		},

		// -- int64 field: unlocker-tari-maturity ---------------------------
		{
			name: "unlocker-tari-maturity/default",
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerTariMaturity != 60 {
					t.Errorf("unlockerTariMaturity = %d, want hardcoded default %d", cfg.unlockerTariMaturity, 60)
				}
			},
		},
		{
			name: "unlocker-tari-maturity/file-only",
			toml: `unlocker_tari_maturity = 90`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerTariMaturity != 90 {
					t.Errorf("unlockerTariMaturity = %d, want file value %d", cfg.unlockerTariMaturity, 90)
				}
			},
		},
		{
			name: "unlocker-tari-maturity/env-only",
			env:  map[string]string{"GCPOOL_UNLOCKER_TARI_MATURITY": "120"},
			toml: `unlocker_tari_maturity = 90`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerTariMaturity != 120 {
					t.Errorf("unlockerTariMaturity = %d, want env value %d (env must beat file)", cfg.unlockerTariMaturity, 120)
				}
			},
		},
		{
			name: "unlocker-tari-maturity/flag-only",
			args: []string{"-unlocker-tari-maturity=150"},
			toml: `unlocker_tari_maturity = 90`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerTariMaturity != 150 {
					t.Errorf("unlockerTariMaturity = %d, want flag value %d (flag must beat env absence and file)", cfg.unlockerTariMaturity, 150)
				}
			},
		},
		{
			name: "unlocker-tari-maturity/flag-env-file-all-set",
			args: []string{"-unlocker-tari-maturity=150"},
			env:  map[string]string{"GCPOOL_UNLOCKER_TARI_MATURITY": "120"},
			toml: `unlocker_tari_maturity = 90`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerTariMaturity != 150 {
					t.Errorf("unlockerTariMaturity = %d, want flag value %d (flag must win full precedence)", cfg.unlockerTariMaturity, 150)
				}
			},
		},

		// -- duration field: unlocker-poll-interval ------------------------
		{
			name: "unlocker-poll-interval/default",
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerPollInterval != 60*time.Second {
					t.Errorf("unlockerPollInterval = %v, want hardcoded default %v", cfg.unlockerPollInterval, 60*time.Second)
				}
			},
		},
		{
			name: "unlocker-poll-interval/file-only",
			toml: `unlocker_poll_interval_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerPollInterval != 100*time.Second {
					t.Errorf("unlockerPollInterval = %v, want file value %v", cfg.unlockerPollInterval, 100*time.Second)
				}
			},
		},
		{
			name: "unlocker-poll-interval/env-only",
			env:  map[string]string{"GCPOOL_UNLOCKER_POLL_INTERVAL": "200s"},
			toml: `unlocker_poll_interval_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerPollInterval != 200*time.Second {
					t.Errorf("unlockerPollInterval = %v, want env value %v (env must beat file)", cfg.unlockerPollInterval, 200*time.Second)
				}
			},
		},
		{
			name: "unlocker-poll-interval/flag-only",
			args: []string{"-unlocker-poll-interval=300s"},
			toml: `unlocker_poll_interval_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerPollInterval != 300*time.Second {
					t.Errorf("unlockerPollInterval = %v, want flag value %v (flag must beat env absence and file)", cfg.unlockerPollInterval, 300*time.Second)
				}
			},
		},
		{
			name: "unlocker-poll-interval/flag-env-file-all-set",
			args: []string{"-unlocker-poll-interval=300s"},
			env:  map[string]string{"GCPOOL_UNLOCKER_POLL_INTERVAL": "200s"},
			toml: `unlocker_poll_interval_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.unlockerPollInterval != 300*time.Second {
					t.Errorf("unlockerPollInterval = %v, want flag value %v (flag must win full precedence)", cfg.unlockerPollInterval, 300*time.Second)
				}
			},
		},

		// -- float64 field: payout-pps-fee-percent -------------------------
		// (substituted for a bool field per the brief's instruction: backend
		// genuinely has no bool-typed setting among its current env vars.)
		{
			name: "payout-pps-fee-percent/default",
			check: func(t *testing.T, cfg config) {
				if cfg.payoutPPSFeePercent != 0 {
					t.Errorf("payoutPPSFeePercent = %v, want hardcoded default %v", cfg.payoutPPSFeePercent, 0.0)
				}
			},
		},
		{
			name: "payout-pps-fee-percent/file-only",
			toml: `payout_pps_fee_percent = 1.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.payoutPPSFeePercent != 1.5 {
					t.Errorf("payoutPPSFeePercent = %v, want file value %v", cfg.payoutPPSFeePercent, 1.5)
				}
			},
		},
		{
			name: "payout-pps-fee-percent/env-only",
			env:  map[string]string{"GCPOOL_PAYOUT_PPS_FEE_PERCENT": "2.5"},
			toml: `payout_pps_fee_percent = 1.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.payoutPPSFeePercent != 2.5 {
					t.Errorf("payoutPPSFeePercent = %v, want env value %v (env must beat file)", cfg.payoutPPSFeePercent, 2.5)
				}
			},
		},
		{
			name: "payout-pps-fee-percent/flag-only",
			args: []string{"-payout-pps-fee-percent=3.5"},
			toml: `payout_pps_fee_percent = 1.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.payoutPPSFeePercent != 3.5 {
					t.Errorf("payoutPPSFeePercent = %v, want flag value %v (flag must beat env absence and file)", cfg.payoutPPSFeePercent, 3.5)
				}
			},
		},
		{
			name: "payout-pps-fee-percent/flag-env-file-all-set",
			args: []string{"-payout-pps-fee-percent=3.5"},
			env:  map[string]string{"GCPOOL_PAYOUT_PPS_FEE_PERCENT": "2.5"},
			toml: `payout_pps_fee_percent = 1.5`,
			check: func(t *testing.T, cfg config) {
				if cfg.payoutPPSFeePercent != 3.5 {
					t.Errorf("payoutPPSFeePercent = %v, want flag value %v (flag must win full precedence)", cfg.payoutPPSFeePercent, 3.5)
				}
			},
		},

		// -- string field: jwt-secret --------------------------------------
		{
			name: "jwt-secret/default",
			check: func(t *testing.T, cfg config) {
				if cfg.jwtSecret != "" {
					t.Errorf("jwtSecret = %q, want hardcoded default %q", cfg.jwtSecret, "")
				}
			},
		},
		{
			name: "jwt-secret/file-only",
			toml: `jwt_secret = "file-secret"`,
			check: func(t *testing.T, cfg config) {
				if cfg.jwtSecret != "file-secret" {
					t.Errorf("jwtSecret = %q, want file value %q", cfg.jwtSecret, "file-secret")
				}
			},
		},
		{
			name: "jwt-secret/env-only",
			env:  map[string]string{"GCPOOL_JWT_SECRET": "env-secret"},
			toml: `jwt_secret = "file-secret"`,
			check: func(t *testing.T, cfg config) {
				if cfg.jwtSecret != "env-secret" {
					t.Errorf("jwtSecret = %q, want env value %q (env must beat file)", cfg.jwtSecret, "env-secret")
				}
			},
		},
		{
			name: "jwt-secret/flag-only",
			args: []string{"-jwt-secret=flag-secret"},
			toml: `jwt_secret = "file-secret"`,
			check: func(t *testing.T, cfg config) {
				if cfg.jwtSecret != "flag-secret" {
					t.Errorf("jwtSecret = %q, want flag value %q (flag must beat env absence and file)", cfg.jwtSecret, "flag-secret")
				}
			},
		},
		{
			name: "jwt-secret/flag-env-file-all-set",
			args: []string{"-jwt-secret=flag-secret"},
			env:  map[string]string{"GCPOOL_JWT_SECRET": "env-secret"},
			toml: `jwt_secret = "file-secret"`,
			check: func(t *testing.T, cfg config) {
				if cfg.jwtSecret != "flag-secret" {
					t.Errorf("jwtSecret = %q, want flag value %q (flag must win full precedence)", cfg.jwtSecret, "flag-secret")
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
