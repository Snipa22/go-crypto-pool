// Copyright and license: see repository LICENSE (MIT).
package main

import "testing"

func TestResolvePortsFallsBackToLegacySingleValueFields(t *testing.T) {
	cfg := config{listenAddress: ":4444", startingDifficulty: 10000}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("len(ports) = %d, want 1", len(ports))
	}
	if ports[0].Address != ":4444" || ports[0].Difficulty != 10000 {
		t.Errorf("got %+v, want Address=:4444 Difficulty=10000", ports[0])
	}
}

func TestResolvePortsParsesLEAFSOLOPORTS(t *testing.T) {
	cfg := config{portsRaw: ":4444:10000:low-diff,:4445:1000000:high-diff"}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("len(ports) = %d, want 2", len(ports))
	}
	if ports[0].Address != ":4444" || ports[0].Difficulty != 10000 || ports[0].PortDesc != "low-diff" {
		t.Errorf("ports[0] = %+v, want {:4444 10000 low-diff}", ports[0])
	}
	if ports[1].Address != ":4445" || ports[1].Difficulty != 1000000 || ports[1].PortDesc != "high-diff" {
		t.Errorf("ports[1] = %+v, want {:4445 1000000 high-diff}", ports[1])
	}
}

func TestResolvePortsParsesEntryWithoutDesc(t *testing.T) {
	cfg := config{portsRaw: ":4444:10000"}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 1 || ports[0].Address != ":4444" || ports[0].Difficulty != 10000 || ports[0].PortDesc != "" {
		t.Errorf("got %+v, want {:4444 10000 \"\"}", ports)
	}
}

func TestResolvePortsRejectsInvalidEntries(t *testing.T) {
	cases := []string{
		":4444",
		":4444:notanumber",
		":4444:0",
		"::0:desc",
	}
	for _, raw := range cases {
		cfg := config{portsRaw: raw}
		if _, err := resolvePorts(cfg); err == nil {
			t.Errorf("resolvePorts(%q): expected an error, got nil", raw)
		}
	}
}

// TestDefaultCoinbaseExtraTagPerAlgo confirms defaultCoinbaseExtraTag
// computes the per-algo "supportxtm-<algo>" pattern Alex asked for
// (distinct per algo/coin, not one single blended tag) -- reusing
// resolveAlgo/isMoneroCoin's real resolution logic, not a separate
// hardcoded mapping.
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
		{"rxm via -coin=Monero case-insensitive", config{coin: "Monero"}, "supportxtm-rxm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultCoinbaseExtraTag(tc.cfg); got != tc.want {
				t.Errorf("defaultCoinbaseExtraTag(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestResolveCoinbaseExtraTagExplicitOverrideWins confirms an
// explicitly-set -coinbase-extra-tag/LEAF_SOLO_COINBASE_EXTRA_TAG
// value wins over the per-algo default, verbatim.
func TestResolveCoinbaseExtraTagExplicitOverrideWins(t *testing.T) {
	cfg := config{coin: "tari", algo: "c29", coinbaseExtraTag: "MY-CUSTOM-TAG"}
	if got := resolveCoinbaseExtraTag(cfg); got != "MY-CUSTOM-TAG" {
		t.Errorf("resolveCoinbaseExtraTag = %q, want explicit override %q", got, "MY-CUSTOM-TAG")
	}
}

// TestResolveCoinbaseExtraTagFallsBackToPerAlgoDefaultWhenUnset
// confirms the empty (unset) case falls through to the per-algo
// default, for every algo/coin combination.
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

// TestResolveCoinbaseExtraTagIgnoresWhitespaceOnlyOverride confirms a
// whitespace-only explicit value is treated as unset (falls back to
// the per-algo default), matching every other string flag's
// strings.TrimSpace-based emptiness convention in this codebase.
func TestResolveCoinbaseExtraTagIgnoresWhitespaceOnlyOverride(t *testing.T) {
	cfg := config{coin: "tari", algo: "rxt", coinbaseExtraTag: "   "}
	if got := resolveCoinbaseExtraTag(cfg); got != "supportxtm-rxt" {
		t.Errorf("resolveCoinbaseExtraTag(whitespace override) = %q, want per-algo default %q", got, "supportxtm-rxt")
	}
}
