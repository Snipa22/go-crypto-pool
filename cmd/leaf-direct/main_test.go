package main

import (
	"testing"

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
