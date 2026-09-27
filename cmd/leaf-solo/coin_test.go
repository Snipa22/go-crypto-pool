// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestValidateCoinFlag proves validateCoinFlag accepts tari, the
// empty string, and every registered internal/coinprofile.Registry
// ticker (case-insensitively, and via the "monero"->"xmr" alias), and
// fails fast (a real error) for anything else.
func TestValidateCoinFlag(t *testing.T) {
	valid := []string{"tari", "", "monero", "MONERO", "xmr", "XMR", "arq", "xeq", "grft", "sfx", "zeph", "sal"}
	for _, coin := range valid {
		if err := validateCoinFlag(coin); err != nil {
			t.Errorf("validateCoinFlag(%q) = %v, want nil", coin, err)
		}
	}
	invalid := []string{"notacoin", "btc", "eth"}
	for _, coin := range invalid {
		if err := validateCoinFlag(coin); err == nil {
			t.Errorf("validateCoinFlag(%q) = nil, want error", coin)
		}
	}
}

// TestResolveAlgo_TariUnchanged proves -coin=tari (and empty, matching
// the flag's own default) is completely unaffected by the CoinProfile
// generalization: resolveAlgo still delegates straight to
// algoFromString(cfg.algo), exactly as before any Monero/multi-coin
// support existed.
func TestResolveAlgo_TariUnchanged(t *testing.T) {
	cases := []struct {
		coin, algo string
		want       poolpb.Algo
	}{
		{"tari", "", poolpb.Algo_ALGO_SHA3X},
		{"tari", "sha3x", poolpb.Algo_ALGO_SHA3X},
		{"tari", "c29", poolpb.Algo_ALGO_C29},
		{"tari", "rxt", poolpb.Algo_ALGO_RXT},
		{"", "rxt", poolpb.Algo_ALGO_RXT},
	}
	for _, tc := range cases {
		cfg := config{coin: tc.coin, algo: tc.algo}
		if got := resolveAlgo(cfg); got != tc.want {
			t.Errorf("resolveAlgo(coin=%q, algo=%q) = %v, want %v", tc.coin, tc.algo, got, tc.want)
		}
	}
}

// TestResolveAlgo_MoneroAliasUnchanged proves -coin=monero (and
// -coin=xmr without -standalone) resolve to the EXACT pre-existing
// ALGO_RXM behavior, regardless of -algo and regardless of case/
// whitespace on -coin -- no existing RXM deployment's behavior may
// change.
func TestResolveAlgo_MoneroAliasUnchanged(t *testing.T) {
	cases := []config{
		{coin: "monero"},
		{coin: "Monero"},
		{coin: "MONERO"},
		{coin: " monero "},
		{coin: "monero", algo: "c29"},
		{coin: "monero", algo: "rxt"},
		{coin: "xmr"},
		{coin: "XMR"},
		{coin: "xmr", algo: "c29"},
	}
	for _, cfg := range cases {
		if got := resolveAlgo(cfg); got != poolpb.Algo_ALGO_RXM {
			t.Errorf("resolveAlgo(%+v) = %v, want %v (unchanged RXM behavior)", cfg, got, poolpb.Algo_ALGO_RXM)
		}
	}
}

// TestResolveAlgo_StandaloneXMRUsesNewAlgo is the genuinely NEW
// capability this dispatch adds: -coin=xmr WITH -standalone must
// resolve to the new, dedicated poolpb.Algo_ALGO_XMR value -- NOT
// silently folded into ALGO_RXM.
func TestResolveAlgo_StandaloneXMRUsesNewAlgo(t *testing.T) {
	cfg := config{coin: "xmr", standalone: true}
	if got := resolveAlgo(cfg); got != poolpb.Algo_ALGO_XMR {
		t.Errorf("resolveAlgo(coin=xmr, standalone=true) = %v, want %v", got, poolpb.Algo_ALGO_XMR)
	}
	// "monero" alias + standalone behaves identically to "xmr" +
	// standalone (the alias only ever affects ticker normalization,
	// never the standalone/merge-mine decision).
	cfg2 := config{coin: "monero", standalone: true}
	if got := resolveAlgo(cfg2); got != poolpb.Algo_ALGO_XMR {
		t.Errorf("resolveAlgo(coin=monero, standalone=true) = %v, want %v", got, poolpb.Algo_ALGO_XMR)
	}
}

// TestResolveAlgo_OtherRegisteredCoinsAreAlwaysStandalone proves every
// OTHER internal/coinprofile.Registry ticker (no merge-mine concept at
// all) resolves to its own dedicated algo regardless of -standalone.
func TestResolveAlgo_OtherRegisteredCoinsAreAlwaysStandalone(t *testing.T) {
	cases := []struct {
		coin string
		want poolpb.Algo
	}{
		{"arq", poolpb.Algo_ALGO_ARQ},
		{"ARQ", poolpb.Algo_ALGO_ARQ},
		{"xeq", poolpb.Algo_ALGO_XEQ},
		{"grft", poolpb.Algo_ALGO_GRFT},
		{"sfx", poolpb.Algo_ALGO_SFX},
		{"zeph", poolpb.Algo_ALGO_ZEPH},
		{"sal", poolpb.Algo_ALGO_SAL},
	}
	for _, tc := range cases {
		for _, standalone := range []bool{false, true} {
			cfg := config{coin: tc.coin, standalone: standalone}
			if got := resolveAlgo(cfg); got != tc.want {
				t.Errorf("resolveAlgo(coin=%q, standalone=%v) = %v, want %v", tc.coin, standalone, got, tc.want)
			}
		}
	}
}

// TestResolveAlgo_UnknownTickerFallsBackDefensively proves resolveAlgo
// itself never panics/crashes on an unregistered ticker (real
// startup-time fail-fast validation lives in main(), not here -- see
// this function's own doc comment).
func TestResolveAlgo_UnknownTickerFallsBackDefensively(t *testing.T) {
	cfg := config{coin: "notacoin", algo: "rxt"}
	if got := resolveAlgo(cfg); got != poolpb.Algo_ALGO_RXT {
		t.Errorf("resolveAlgo(coin=notacoin) = %v, want defensive algoFromString(cfg.algo) fallback %v", got, poolpb.Algo_ALGO_RXT)
	}
}

// TestIsMoneroFamilyCoin covers the generalized isMoneroFamilyCoin
// (formerly isMoneroCoin, which only ever recognized the literal
// string "monero") across every registered ticker plus tari/unknown.
func TestIsMoneroFamilyCoin(t *testing.T) {
	cases := []struct {
		coin string
		want bool
	}{
		{"tari", false},
		{"", false},
		{"monero", true},
		{"MONERO", true},
		{"xmr", true},
		{"arq", true},
		{"xeq", true},
		{"grft", true},
		{"sfx", true},
		{"zeph", true},
		{"sal", true},
		{"notacoin", false},
	}
	for _, tc := range cases {
		if got := isMoneroFamilyCoin(tc.coin); got != tc.want {
			t.Errorf("isMoneroFamilyCoin(%q) = %v, want %v", tc.coin, got, tc.want)
		}
	}
}

// TestAlgoTagSuffix_NewCoinsUseOwnTicker proves algoTagSuffix (and
// therefore defaultCoinbaseExtraTag's "supportxtm-<suffix>") uses each
// new coin's own lowercase ticker, read back out of
// internal/coinprofile.Registry via ByAlgo, rather than a hardcoded
// per-coin switch arm.
func TestAlgoTagSuffix_NewCoinsUseOwnTicker(t *testing.T) {
	for key, profile := range coinprofile.Registry {
		if profile.Ticker == "XMR" {
			// XMR is handled separately below since it needs
			// -standalone to reach ALGO_XMR at all.
			continue
		}
		cfg := config{coin: key}
		if got := algoTagSuffix(cfg); got != key {
			t.Errorf("algoTagSuffix(coin=%q) = %q, want %q", key, got, key)
		}
		if got := defaultCoinbaseExtraTag(cfg); got != profile.CoinbaseExtraTagDefault {
			t.Errorf("defaultCoinbaseExtraTag(coin=%q) = %q, want %q", key, got, profile.CoinbaseExtraTagDefault)
		}
	}

	standaloneXMR := config{coin: "xmr", standalone: true}
	if got := algoTagSuffix(standaloneXMR); got != "xmr" {
		t.Errorf("algoTagSuffix(coin=xmr, standalone=true) = %q, want %q", got, "xmr")
	}
	if got := defaultCoinbaseExtraTag(standaloneXMR); got != "supportxtm-xmr" {
		t.Errorf("defaultCoinbaseExtraTag(coin=xmr, standalone=true) = %q, want %q", got, "supportxtm-xmr")
	}
}

// TestNormalizeCoinTicker_MoneroAlias proves the single normalization
// point every coin-conditional branch consults applies the
// "monero"->"xmr" alias and lowercases/trims consistently.
func TestNormalizeCoinTicker_MoneroAlias(t *testing.T) {
	cases := map[string]string{
		"monero":   "xmr",
		"Monero":   "xmr",
		"MONERO":   "xmr",
		" monero ": "xmr",
		"xmr":      "xmr",
		"XMR":      "xmr",
		"tari":     "tari",
		"ARQ":      "arq",
		"":         "",
	}
	for in, want := range cases {
		if got := normalizeCoinTicker(in); got != want {
			t.Errorf("normalizeCoinTicker(%q) = %q, want %q", in, got, want)
		}
	}
}
