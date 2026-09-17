// Copyright and license: see repository LICENSE (MIT).
package coinprofile

import (
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

func TestLookup_CaseInsensitive(t *testing.T) {
	cases := []string{"xmr", "XMR", "Xmr", " xmr ", "\tXMR\n"}
	for _, tc := range cases {
		p, ok := Lookup(tc)
		if !ok {
			t.Fatalf("Lookup(%q): expected ok, got not-found", tc)
		}
		if p.Ticker != "XMR" {
			t.Fatalf("Lookup(%q): got ticker %q, want XMR", tc, p.Ticker)
		}
	}
}

func TestLookup_UnknownTicker(t *testing.T) {
	if _, ok := Lookup("notacoin"); ok {
		t.Fatal("Lookup(\"notacoin\"): expected not-found, got ok")
	}
	if _, ok := Lookup(""); ok {
		t.Fatal("Lookup(\"\"): expected not-found, got ok")
	}
}

func TestMustLookup_ErrorShape(t *testing.T) {
	_, err := MustLookup("notacoin")
	if err == nil {
		t.Fatal("MustLookup(\"notacoin\"): expected error, got nil")
	}
	var unkErr *ErrUnknownTicker
	if !asErrUnknownTicker(err, &unkErr) {
		t.Fatalf("MustLookup(\"notacoin\"): expected *ErrUnknownTicker, got %T: %v", err, err)
	}
	if unkErr.Ticker != "notacoin" {
		t.Fatalf("ErrUnknownTicker.Ticker = %q, want %q", unkErr.Ticker, "notacoin")
	}
}

func asErrUnknownTicker(err error, target **ErrUnknownTicker) bool {
	if e, ok := err.(*ErrUnknownTicker); ok {
		*target = e
		return true
	}
	return false
}

func TestMustLookup_KnownTicker(t *testing.T) {
	p, err := MustLookup("arq")
	if err != nil {
		t.Fatalf("MustLookup(\"arq\"): unexpected error: %v", err)
	}
	if p.Ticker != "ARQ" || p.Algo != poolpb.Algo_ALGO_ARQ {
		t.Fatalf("MustLookup(\"arq\") = %+v, want ticker ARQ / ALGO_ARQ", p)
	}
}

func TestRegistry_EveryEntryIsMonerodCompatibleAndSelfConsistent(t *testing.T) {
	for key, p := range Registry {
		if NormalizeTicker(p.Ticker) != key {
			t.Errorf("Registry[%q]: Ticker %q does not normalize back to its own map key", key, p.Ticker)
		}
		if !p.MonerodCompatible {
			t.Errorf("Registry[%q]: MonerodCompatible is false -- every Registry entry must be a confirmed monerod-RPC-compatible fork", key)
		}
		if p.Decimals == 0 {
			t.Errorf("Registry[%q]: Decimals is zero", key)
		}
		if len(p.AddressNetworkBytes) == 0 {
			t.Errorf("Registry[%q]: AddressNetworkBytes is empty", key)
		}
		if p.DefaultRPCPort <= 0 {
			t.Errorf("Registry[%q]: DefaultRPCPort is not positive", key)
		}
		wantTag := "supportxtm-" + key
		if p.CoinbaseExtraTagDefault != wantTag {
			t.Errorf("Registry[%q]: CoinbaseExtraTagDefault = %q, want %q", key, p.CoinbaseExtraTagDefault, wantTag)
		}
		if p.Algo == 0 {
			t.Errorf("Registry[%q]: Algo is ALGO_UNSPECIFIED", key)
		}
	}
}

func TestRegistry_DistinctAlgoPerEntry(t *testing.T) {
	seen := make(map[int]string)
	for key, p := range Registry {
		if other, dup := seen[int(p.Algo)]; dup {
			t.Fatalf("Registry[%q] and Registry[%q] both use Algo=%v -- every coin must get its own independent Algo enum value", key, other, p.Algo)
		}
		seen[int(p.Algo)] = key
	}
}

func TestByAlgo_RoundTrips(t *testing.T) {
	for key, want := range Registry {
		got, ok := ByAlgo(want.Algo)
		if !ok {
			t.Fatalf("ByAlgo(%v) for %q: not found", want.Algo, key)
		}
		if got.Ticker != want.Ticker {
			t.Fatalf("ByAlgo(%v) = %+v, want ticker %q", want.Algo, got, want.Ticker)
		}
	}
}
