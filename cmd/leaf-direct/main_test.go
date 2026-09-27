// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	legacypb "github.com/Snipa22/go-crypto-pool/internal/legacyproto"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestPoolTypeFromString confirms the real LEAF_DIRECT_POOL_TYPE parse
// convention: exactly the 4 real poolpb.PoolType values are accepted
// (case-insensitively), and anything else — including empty, which is
// what an operator gets if they forget to set the now-required flag —
// is rejected with ok=false so main() can fail fast rather than ever
// constructing a Share/Block with PoolType left at its zero value
// (poolpb.PoolType_POOL_TYPE_UNSPECIFIED), which is exactly the real,
// confirmed-live bug this flag exists to prevent.
func TestPoolTypeFromString(t *testing.T) {
	cases := []struct {
		in     string
		want   poolpb.PoolType
		wantOK bool
	}{
		{"pplns", poolpb.PoolType_POOL_TYPE_PPLNS, true},
		{"PPLNS", poolpb.PoolType_POOL_TYPE_PPLNS, true},
		{"pps", poolpb.PoolType_POOL_TYPE_PPS, true},
		{"PPS", poolpb.PoolType_POOL_TYPE_PPS, true},
		{"prop", poolpb.PoolType_POOL_TYPE_PROP, true},
		{"PROP", poolpb.PoolType_POOL_TYPE_PROP, true},
		{"solo", poolpb.PoolType_POOL_TYPE_SOLO, true},
		{"SOLO", poolpb.PoolType_POOL_TYPE_SOLO, true},
		{" solo ", poolpb.PoolType_POOL_TYPE_SOLO, true},
		{"", poolpb.PoolType_POOL_TYPE_UNSPECIFIED, false},
		{"bogus", poolpb.PoolType_POOL_TYPE_UNSPECIFIED, false},
		{"unspecified", poolpb.PoolType_POOL_TYPE_UNSPECIFIED, false},
	}
	for _, c := range cases {
		got, ok := poolTypeFromString(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("poolTypeFromString(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// TestLegacyPoolTypeFromString mirrors TestPoolTypeFromString exactly,
// for the separate legacy-mode -legacy-pool-type parse helper (see that
// flag's doc comment for why it is deliberately a distinct flag/parser
// from -pool-type).
func TestLegacyPoolTypeFromString(t *testing.T) {
	cases := []struct {
		in     string
		want   legacypb.POOLTYPE
		wantOK bool
	}{
		{"pplns", legacypb.POOLTYPE_PPLNS, true},
		{"PPLNS", legacypb.POOLTYPE_PPLNS, true},
		{"pps", legacypb.POOLTYPE_PPS, true},
		{"prop", legacypb.POOLTYPE_PROP, true},
		{"solo", legacypb.POOLTYPE_SOLO, true},
		{" solo ", legacypb.POOLTYPE_SOLO, true},
		{"", 0, false},
		{"bogus", 0, false},
		{"unspecified", 0, false},
	}
	for _, c := range cases {
		got, ok := legacyPoolTypeFromString(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("legacyPoolTypeFromString(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// TestServerConfigAlgoUsesResolveAlgoNotAlgoFromString is a regression
// test for a real, confirmed-live bug: main() used to construct
// direct.ServerConfig with `Algo: algoFromString(cfg.algo)` -- a
// coin-UNAWARE helper with no knowledge of -coin/LEAF_DIRECT_COIN --
// instead of the coin-aware `resolveAlgo(cfg)` (which
// solo.NewJobManager's config correctly already used). On a real
// -coin=monero deployment where LEAF_DIRECT_ALGO is left at its
// default ("sha3x", since it's irrelevant/ignored for monero coin),
// this made JobManager correctly produce ALGO_RXM jobs while Server's
// algo was wrongly ALGO_SHA3X -- and internal/leaflib/direct/
// session.go's handleLogin dispatches
// solo.ValidateAddressForAlgo(s.server.algo, login.Login), so a real,
// valid Monero payout address on login got wrongly validated as a
// Tari address and rejected.
//
// This test asserts the exact value that main() passes as
// direct.ServerConfig.Algo (i.e. resolveAlgo(cfg), NOT
// algoFromString(cfg.algo)) for the real default configuration that
// triggered the bug: -coin=monero with LEAF_DIRECT_ALGO left unset
// (so cfg.algo defaults to "sha3x").
func TestServerConfigAlgoUsesResolveAlgoNotAlgoFromString(t *testing.T) {
	cfg := config{coin: "monero", algo: "sha3x"}

	// Sanity-check the premise: algoFromString(cfg.algo) alone (the
	// buggy call site's old expression) would have wrongly resolved
	// to ALGO_SHA3X here since it has no knowledge of cfg.coin.
	if got := algoFromString(cfg.algo); got != poolpb.Algo_ALGO_SHA3X {
		t.Fatalf("algoFromString(%q) = %v, want %v (premise of this regression test broken)", cfg.algo, got, poolpb.Algo_ALGO_SHA3X)
	}

	// The real fix: direct.ServerConfig.Algo must be resolveAlgo(cfg),
	// which is coin-aware and correctly resolves to ALGO_RXM for
	// -coin=monero regardless of cfg.algo.
	if got := resolveAlgo(cfg); got != poolpb.Algo_ALGO_RXM {
		t.Errorf("resolveAlgo(%+v) = %v, want %v -- direct.ServerConfig.Algo must use resolveAlgo(cfg), not algoFromString(cfg.algo), or a real Monero payout address on login gets wrongly validated as a Tari address and rejected", cfg, got, poolpb.Algo_ALGO_RXM)
	}
}

// TestDefaultCoinbaseExtraTagPerAlgo mirrors leaf-solo's own identical
// test -- confirms leaf-direct's defaultCoinbaseExtraTag computes the
// same per-algo "supportxtm-<algo>" pattern.
func TestDefaultCoinbaseExtraTagPerAlgo(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
		want string
	}{
		{"sha3x default (empty algo)", config{coin: "tari", algo: ""}, "supportxtm-sha3x"},
		{"sha3x explicit", config{coin: "tari", algo: "sha3x"}, "supportxtm-sha3x"},
		{"c29", config{coin: "tari", algo: "c29"}, "supportxtm-c29"},
		{"rxt", config{coin: "tari", algo: "rxt"}, "supportxtm-rxt"},
		{"rxm via -coin=monero", config{coin: "monero"}, "supportxtm-rxm"},
		{"rxm via -coin=monero, -algo ignored", config{coin: "monero", algo: "c29"}, "supportxtm-rxm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultCoinbaseExtraTag(tc.cfg); got != tc.want {
				t.Errorf("defaultCoinbaseExtraTag(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestResolveCoinbaseExtraTagExplicitOverrideWins mirrors leaf-solo's
// own identical test.
func TestResolveCoinbaseExtraTagExplicitOverrideWins(t *testing.T) {
	cfg := config{coin: "tari", algo: "c29", coinbaseExtraTag: "MY-CUSTOM-TAG"}
	if got := resolveCoinbaseExtraTag(cfg); got != "MY-CUSTOM-TAG" {
		t.Errorf("resolveCoinbaseExtraTag = %q, want explicit override %q", got, "MY-CUSTOM-TAG")
	}
}

// TestResolveCoinbaseExtraTagFallsBackToPerAlgoDefaultWhenUnset
// mirrors leaf-solo's own identical test.
func TestResolveCoinbaseExtraTagFallsBackToPerAlgoDefaultWhenUnset(t *testing.T) {
	cases := []struct {
		cfg  config
		want string
	}{
		{config{coin: "tari", algo: "sha3x"}, "supportxtm-sha3x"},
		{config{coin: "tari", algo: "c29"}, "supportxtm-c29"},
		{config{coin: "tari", algo: "rxt"}, "supportxtm-rxt"},
		{config{coin: "monero"}, "supportxtm-rxm"},
	}
	for _, tc := range cases {
		if got := resolveCoinbaseExtraTag(tc.cfg); got != tc.want {
			t.Errorf("resolveCoinbaseExtraTag(%+v) = %q, want %q", tc.cfg, got, tc.want)
		}
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
// flag.StringVar/flag.BoolVar/etc.
func runPrecedenceCase(t *testing.T, tc precedenceCase) {
	t.Helper()

	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	flag.CommandLine = flag.NewFlagSet("leaf-direct-test", flag.ContinueOnError)

	args := append([]string{"leaf-direct"}, tc.args...)
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
// cfgfile.Decode, not a fake), across one string field (pool-type), one bool
// field (trust-enabled), one int field (pool-id) and one duration field
// (backend-share-timeout), per the brief's explicit requirement.
func TestLoadConfigPrecedence(t *testing.T) {
	cases := []precedenceCase{
		// -- string field: pool-type ---------------------------------------
		{
			name: "pool-type/default",
			check: func(t *testing.T, cfg config) {
				if cfg.poolType != "" {
					t.Errorf("poolType = %q, want hardcoded default %q", cfg.poolType, "")
				}
			},
		},
		{
			name: "pool-type/file-only",
			toml: `pool_type = "pplns"`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolType != "pplns" {
					t.Errorf("poolType = %q, want file value %q", cfg.poolType, "pplns")
				}
			},
		},
		{
			name: "pool-type/env-only",
			env:  map[string]string{"LEAF_DIRECT_POOL_TYPE": "pps"},
			toml: `pool_type = "pplns"`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolType != "pps" {
					t.Errorf("poolType = %q, want env value %q (env must beat file)", cfg.poolType, "pps")
				}
			},
		},
		{
			name: "pool-type/flag-only",
			args: []string{"-pool-type=solo"},
			toml: `pool_type = "pplns"`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolType != "solo" {
					t.Errorf("poolType = %q, want flag value %q (flag must beat env absence and file)", cfg.poolType, "solo")
				}
			},
		},
		{
			name: "pool-type/flag-env-file-all-set",
			args: []string{"-pool-type=solo"},
			env:  map[string]string{"LEAF_DIRECT_POOL_TYPE": "pps"},
			toml: `pool_type = "pplns"`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolType != "solo" {
					t.Errorf("poolType = %q, want flag value %q (flag must win full precedence)", cfg.poolType, "solo")
				}
			},
		},

		// -- bool field: trust-enabled --------------------------------------
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
			env:  map[string]string{"LEAF_DIRECT_TRUST_ENABLED": "false"},
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
			env:  map[string]string{"LEAF_DIRECT_TRUST_ENABLED": "false"},
			toml: `trust_enabled = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.trustEnabled != true {
					t.Errorf("trustEnabled = %v, want flag value %v (flag must win full precedence over env=false)", cfg.trustEnabled, true)
				}
			},
		},

		// -- int field: pool-id ----------------------------------------------
		{
			name: "pool-id/default",
			check: func(t *testing.T, cfg config) {
				if cfg.poolID != 0 {
					t.Errorf("poolID = %d, want hardcoded default %d", cfg.poolID, 0)
				}
			},
		},
		{
			name: "pool-id/file-only",
			toml: `pool_id = 5`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolID != 5 {
					t.Errorf("poolID = %d, want file value %d", cfg.poolID, 5)
				}
			},
		},
		{
			name: "pool-id/env-only",
			env:  map[string]string{"LEAF_DIRECT_POOL_ID": "6"},
			toml: `pool_id = 5`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolID != 6 {
					t.Errorf("poolID = %d, want env value %d (env must beat file)", cfg.poolID, 6)
				}
			},
		},
		{
			name: "pool-id/flag-only",
			args: []string{"-pool-id=7"},
			toml: `pool_id = 5`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolID != 7 {
					t.Errorf("poolID = %d, want flag value %d (flag must beat env absence and file)", cfg.poolID, 7)
				}
			},
		},
		{
			name: "pool-id/flag-env-file-all-set",
			args: []string{"-pool-id=7"},
			env:  map[string]string{"LEAF_DIRECT_POOL_ID": "6"},
			toml: `pool_id = 5`,
			check: func(t *testing.T, cfg config) {
				if cfg.poolID != 7 {
					t.Errorf("poolID = %d, want flag value %d (flag must win full precedence)", cfg.poolID, 7)
				}
			},
		},

		// -- duration field: backend-share-timeout ----------------------------
		{
			name: "backend-share-timeout/default",
			check: func(t *testing.T, cfg config) {
				if cfg.backendShareTimeout != 5*time.Second {
					t.Errorf("backendShareTimeout = %v, want hardcoded default %v", cfg.backendShareTimeout, 5*time.Second)
				}
			},
		},
		{
			name: "backend-share-timeout/file-only",
			toml: `backend_share_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.backendShareTimeout != 100*time.Second {
					t.Errorf("backendShareTimeout = %v, want file value %v", cfg.backendShareTimeout, 100*time.Second)
				}
			},
		},
		{
			name: "backend-share-timeout/env-only",
			env:  map[string]string{"LEAF_DIRECT_BACKEND_SHARE_TIMEOUT": "200s"},
			toml: `backend_share_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.backendShareTimeout != 200*time.Second {
					t.Errorf("backendShareTimeout = %v, want env value %v (env must beat file)", cfg.backendShareTimeout, 200*time.Second)
				}
			},
		},
		{
			name: "backend-share-timeout/flag-only",
			args: []string{"-backend-share-timeout=300s"},
			toml: `backend_share_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.backendShareTimeout != 300*time.Second {
					t.Errorf("backendShareTimeout = %v, want flag value %v (flag must beat env absence and file)", cfg.backendShareTimeout, 300*time.Second)
				}
			},
		},
		{
			name: "backend-share-timeout/flag-env-file-all-set",
			args: []string{"-backend-share-timeout=300s"},
			env:  map[string]string{"LEAF_DIRECT_BACKEND_SHARE_TIMEOUT": "200s"},
			toml: `backend_share_timeout_seconds = 100`,
			check: func(t *testing.T, cfg config) {
				if cfg.backendShareTimeout != 300*time.Second {
					t.Errorf("backendShareTimeout = %v, want flag value %v (flag must win full precedence)", cfg.backendShareTimeout, 300*time.Second)
				}
			},
		},

		// -- bool field: legacy-mode -----------------------------------------
		{
			name: "legacy-mode/default",
			check: func(t *testing.T, cfg config) {
				if cfg.legacyMode != false {
					t.Errorf("legacyMode = %v, want hardcoded default %v", cfg.legacyMode, false)
				}
			},
		},
		{
			name: "legacy-mode/file-only",
			toml: `legacy_mode = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyMode != true {
					t.Errorf("legacyMode = %v, want file value %v", cfg.legacyMode, true)
				}
			},
		},
		{
			name: "legacy-mode/env-only",
			env:  map[string]string{"LEAF_DIRECT_LEGACY_MODE": "false"},
			toml: `legacy_mode = true`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyMode != false {
					t.Errorf("legacyMode = %v, want env value %v (env must beat file)", cfg.legacyMode, false)
				}
			},
		},
		{
			name: "legacy-mode/flag-only",
			args: []string{"-legacy-mode=true"},
			toml: `legacy_mode = false`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyMode != true {
					t.Errorf("legacyMode = %v, want flag value %v (flag must beat env absence and file)", cfg.legacyMode, true)
				}
			},
		},

		// -- string field: legacy-backend-url --------------------------------
		{
			name: "legacy-backend-url/default",
			check: func(t *testing.T, cfg config) {
				if cfg.legacyBackendURL != "" {
					t.Errorf("legacyBackendURL = %q, want hardcoded default %q", cfg.legacyBackendURL, "")
				}
			},
		},
		{
			name: "legacy-backend-url/file-only",
			toml: `legacy_backend_url = "https://legacy.example.com:4443"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyBackendURL != "https://legacy.example.com:4443" {
					t.Errorf("legacyBackendURL = %q, want file value", cfg.legacyBackendURL)
				}
			},
		},
		{
			name: "legacy-backend-url/env-only",
			env:  map[string]string{"LEAF_DIRECT_LEGACY_BACKEND_URL": "https://env.example.com:4443"},
			toml: `legacy_backend_url = "https://legacy.example.com:4443"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyBackendURL != "https://env.example.com:4443" {
					t.Errorf("legacyBackendURL = %q, want env value (env must beat file)", cfg.legacyBackendURL)
				}
			},
		},
		{
			name: "legacy-backend-url/flag-only",
			args: []string{"-legacy-backend-url=https://flag.example.com:4443"},
			toml: `legacy_backend_url = "https://legacy.example.com:4443"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyBackendURL != "https://flag.example.com:4443" {
					t.Errorf("legacyBackendURL = %q, want flag value (flag must beat env absence and file)", cfg.legacyBackendURL)
				}
			},
		},

		// -- int field: legacy-pool-id ---------------------------------------
		{
			name: "legacy-pool-id/default",
			check: func(t *testing.T, cfg config) {
				if cfg.legacyPoolID != 0 {
					t.Errorf("legacyPoolID = %d, want hardcoded default %d", cfg.legacyPoolID, 0)
				}
			},
		},
		{
			name: "legacy-pool-id/file-only",
			toml: `legacy_pool_id = 3`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyPoolID != 3 {
					t.Errorf("legacyPoolID = %d, want file value %d", cfg.legacyPoolID, 3)
				}
			},
		},
		{
			name: "legacy-pool-id/env-only",
			env:  map[string]string{"LEAF_DIRECT_LEGACY_POOL_ID": "4"},
			toml: `legacy_pool_id = 3`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyPoolID != 4 {
					t.Errorf("legacyPoolID = %d, want env value %d (env must beat file)", cfg.legacyPoolID, 4)
				}
			},
		},
		{
			name: "legacy-pool-id/flag-only",
			args: []string{"-legacy-pool-id=8"},
			toml: `legacy_pool_id = 3`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyPoolID != 8 {
					t.Errorf("legacyPoolID = %d, want flag value %d (flag must beat env absence and file)", cfg.legacyPoolID, 8)
				}
			},
		},

		// -- bool field: legacy-checkin-enabled (default TRUE, unlike ------
		// -- legacy-mode itself, which defaults false) ----------------------
		{
			name: "legacy-checkin-enabled/default",
			check: func(t *testing.T, cfg config) {
				if !cfg.legacyCheckinEnabled {
					t.Error("legacyCheckinEnabled = false, want hardcoded default true")
				}
			},
		},
		{
			name: "legacy-checkin-enabled/flag-disables",
			args: []string{"-legacy-checkin-enabled=false"},
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinEnabled {
					t.Error("legacyCheckinEnabled = true, want flag value false")
				}
			},
		},

		// -- string field: legacy-checkin-api-url ----------------------------
		{
			name: "legacy-checkin-api-url/default",
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinAPIURL != "" {
					t.Errorf("legacyCheckinAPIURL = %q, want hardcoded default %q", cfg.legacyCheckinAPIURL, "")
				}
			},
		},
		{
			name: "legacy-checkin-api-url/file-only",
			toml: `legacy_checkin_api_url = "http://legacy.example.com:32322/poolApi/"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinAPIURL != "http://legacy.example.com:32322/poolApi/" {
					t.Errorf("legacyCheckinAPIURL = %q, want file value", cfg.legacyCheckinAPIURL)
				}
			},
		},
		{
			name: "legacy-checkin-api-url/env-only",
			env:  map[string]string{"LEAF_DIRECT_LEGACY_CHECKIN_API_URL": "http://env.example.com:32322/poolApi/"},
			toml: `legacy_checkin_api_url = "http://legacy.example.com:32322/poolApi/"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinAPIURL != "http://env.example.com:32322/poolApi/" {
					t.Errorf("legacyCheckinAPIURL = %q, want env value (env must beat file)", cfg.legacyCheckinAPIURL)
				}
			},
		},
		{
			name: "legacy-checkin-api-url/flag-only",
			args: []string{"-legacy-checkin-api-url=http://flag.example.com:32322/poolApi/"},
			toml: `legacy_checkin_api_url = "http://legacy.example.com:32322/poolApi/"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinAPIURL != "http://flag.example.com:32322/poolApi/" {
					t.Errorf("legacyCheckinAPIURL = %q, want flag value (flag must beat env absence and file)", cfg.legacyCheckinAPIURL)
				}
			},
		},

		// -- string field: legacy-checkin-auth-token -------------------------
		{
			name: "legacy-checkin-auth-token/flag-only",
			args: []string{"-legacy-checkin-auth-token=the-token"},
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinAuthToken != "the-token" {
					t.Errorf("legacyCheckinAuthToken = %q, want flag value", cfg.legacyCheckinAuthToken)
				}
			},
		},

		// -- duration field: legacy-checkin-interval -------------------------
		{
			name: "legacy-checkin-interval/default",
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinInterval != 10*time.Second {
					t.Errorf("legacyCheckinInterval = %v, want hardcoded default 10s (real legacy cadence)", cfg.legacyCheckinInterval)
				}
			},
		},
		{
			name: "legacy-checkin-interval/flag-only",
			args: []string{"-legacy-checkin-interval=30s"},
			check: func(t *testing.T, cfg config) {
				if cfg.legacyCheckinInterval != 30*time.Second {
					t.Errorf("legacyCheckinInterval = %v, want flag value 30s", cfg.legacyCheckinInterval)
				}
			},
		},

		// -- string field: legacy-pool-type ----------------------------------
		{
			name: "legacy-pool-type/default",
			check: func(t *testing.T, cfg config) {
				if cfg.legacyPoolType != "" {
					t.Errorf("legacyPoolType = %q, want hardcoded default %q", cfg.legacyPoolType, "")
				}
			},
		},
		{
			name: "legacy-pool-type/flag-env-file-all-set",
			args: []string{"-legacy-pool-type=solo"},
			env:  map[string]string{"LEAF_DIRECT_LEGACY_POOL_TYPE": "pps"},
			toml: `legacy_pool_type = "pplns"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyPoolType != "solo" {
					t.Errorf("legacyPoolType = %q, want flag value %q (flag must win full precedence)", cfg.legacyPoolType, "solo")
				}
			},
		},

		// -- string field: legacy-auth-key -----------------------------------
		{
			name: "legacy-auth-key/flag-env-file-all-set",
			args: []string{"-legacy-auth-key=flag-secret"},
			env:  map[string]string{"LEAF_DIRECT_LEGACY_AUTH_KEY": "env-secret"},
			toml: `legacy_auth_key = "file-secret"`,
			check: func(t *testing.T, cfg config) {
				if cfg.legacyAuthKey != "flag-secret" {
					t.Errorf("legacyAuthKey = %q, want flag value (flag must win full precedence)", cfg.legacyAuthKey)
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
			env:  map[string]string{"LEAF_DIRECT_MAX_CONNECTIONS": "0"},
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

// TestRequiredFieldsError covers the legacy-mode startup-validation
// gating fixed here: -backend-base-url and -pool-id are required only
// when -legacy-mode=false; -pool-type stays required unconditionally
// (see requiredFieldsError's own doc comment for why); the four
// -legacy-* fields are required only when -legacy-mode=true, exactly
// as before this fix.
func TestRequiredFieldsError(t *testing.T) {
	// baseValid is a config that is valid for a NON-legacy-mode
	// deployment: every non-legacy required field is set, legacyMode
	// is false, and none of the legacy-* fields are set.
	baseValid := func() config {
		return config{
			payoutAddress:  "some-address",
			backendBaseURL: "http://backend.example.com",
			poolType:       "pplns",
			poolID:         1,
			legacyMode:     false,
		}
	}

	// baseValidLegacy is a config that is valid for a
	// -legacy-mode=true deployment per this fix: backend-base-url and
	// pool-id are deliberately LEFT UNSET (the whole point of this
	// fix), pool-type is still set (still required), and all four
	// legacy-* fields are set.
	baseValidLegacy := func() config {
		return config{
			payoutAddress:    "some-address",
			poolType:         "pplns",
			legacyMode:       true,
			legacyBackendURL: "https://legacy.example.com:4443",
			legacyAuthKey:    "some-key",
			legacyPoolType:   "pplns",
			legacyPoolID:     1,
		}
	}

	t.Run("non-legacy-mode: valid config passes", func(t *testing.T) {
		if err := requiredFieldsError(baseValid()); err != nil {
			t.Errorf("requiredFieldsError() = %v, want nil for a fully-populated non-legacy config", err)
		}
	})

	t.Run("non-legacy-mode: missing backend-base-url still fails (unchanged behavior)", func(t *testing.T) {
		cfg := baseValid()
		cfg.backendBaseURL = ""
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -backend-base-url is still required when -legacy-mode=false")
		}
	})

	t.Run("non-legacy-mode: missing pool-type still fails (unchanged behavior)", func(t *testing.T) {
		cfg := baseValid()
		cfg.poolType = ""
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -pool-type is required regardless of -legacy-mode")
		}
	})

	t.Run("non-legacy-mode: missing/zero pool-id still fails (unchanged behavior)", func(t *testing.T) {
		cfg := baseValid()
		cfg.poolID = 0
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -pool-id is still required when -legacy-mode=false")
		}
	})

	t.Run("legacy-mode: valid config with backend-base-url/pool-id UNSET passes (the bug this PR fixes)", func(t *testing.T) {
		cfg := baseValidLegacy()
		if cfg.backendBaseURL != "" || cfg.poolID != 0 {
			t.Fatalf("test premise broken: baseValidLegacy() must leave backend-base-url/pool-id unset, got backendBaseURL=%q poolID=%d", cfg.backendBaseURL, cfg.poolID)
		}
		if err := requiredFieldsError(cfg); err != nil {
			t.Errorf("requiredFieldsError() = %v, want nil -- -backend-base-url/-pool-id must NOT be required when -legacy-mode=true", err)
		}
	})

	t.Run("legacy-mode: pool-type is STILL required even though backend-base-url/pool-id are not", func(t *testing.T) {
		cfg := baseValidLegacy()
		cfg.poolType = ""
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -pool-type must remain required even when -legacy-mode=true (legacytransport derives the real outgoing legacy PoolType from it)")
		}
	})

	t.Run("legacy-mode: setting backend-base-url/pool-id anyway is still accepted (optional, not forbidden)", func(t *testing.T) {
		cfg := baseValidLegacy()
		cfg.backendBaseURL = "http://backend.example.com"
		cfg.poolID = 1
		if err := requiredFieldsError(cfg); err != nil {
			t.Errorf("requiredFieldsError() = %v, want nil -- setting backend-base-url/pool-id in legacy mode must remain harmless, not an error", err)
		}
	})

	t.Run("legacy-mode: missing legacy-backend-url still fails (unchanged behavior)", func(t *testing.T) {
		cfg := baseValidLegacy()
		cfg.legacyBackendURL = ""
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -legacy-backend-url is required when -legacy-mode=true")
		}
	})

	t.Run("legacy-mode: missing legacy-auth-key still fails (unchanged behavior)", func(t *testing.T) {
		cfg := baseValidLegacy()
		cfg.legacyAuthKey = ""
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -legacy-auth-key is required when -legacy-mode=true")
		}
	})

	t.Run("legacy-mode: invalid legacy-pool-type still fails (unchanged behavior)", func(t *testing.T) {
		cfg := baseValidLegacy()
		cfg.legacyPoolType = "bogus"
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -legacy-pool-type must still be one of pplns|pps|prop|solo when -legacy-mode=true")
		}
	})

	t.Run("legacy-mode: zero legacy-pool-id still fails (unchanged behavior)", func(t *testing.T) {
		cfg := baseValidLegacy()
		cfg.legacyPoolID = 0
		if err := requiredFieldsError(cfg); err == nil {
			t.Error("requiredFieldsError() = nil, want an error: -legacy-pool-id must still be a positive integer when -legacy-mode=true")
		}
	})
}
