// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// TestParsePortEntry_TLSSuffixEnablesTLS confirms the new, optional
// trailing ":tls" marker (case-insensitive, always the LAST
// colon-separated field) is stripped off FIRST and sets
// PortConfig.TLS -- the existing difficulty/desc peeling logic is
// otherwise untouched.
func TestParsePortEntry_TLSSuffixEnablesTLS(t *testing.T) {
	got, err := parsePortEntry("0.0.0.0:4443:1000:sha3x-tls:tls")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "0.0.0.0:4443", Difficulty: 1000, PortDesc: "sha3x-tls", TLS: true}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestParsePortEntry_TLSSuffixCaseInsensitive confirms the ":tls"
// literal is matched case-insensitively (":TLS", ":Tls", etc.).
func TestParsePortEntry_TLSSuffixCaseInsensitive(t *testing.T) {
	for _, suffix := range []string{"tls", "TLS", "Tls", "tLs"} {
		got, err := parsePortEntry("0.0.0.0:4443:1000:" + suffix)
		if err != nil {
			t.Fatalf("parsePortEntry with suffix %q: %v", suffix, err)
		}
		if !got.TLS {
			t.Errorf("parsePortEntry with suffix %q: TLS = false, want true", suffix)
		}
		if got.Address != "0.0.0.0:4443" || got.Difficulty != 1000 {
			t.Errorf("parsePortEntry with suffix %q: Address/Difficulty = %q/%d, want 0.0.0.0:4443/1000", suffix, got.Address, got.Difficulty)
		}
	}
}

// TestParsePortEntry_NoTLSSuffixBackwardCompatible is the explicit
// backward-compat regression guard: an entry with no trailing ":tls"
// field must parse EXACTLY as before this feature existed, producing
// PortConfig{..., TLS: false}. This exact entry shape
// ("0.0.0.0:4444:60000000") matches the real, live CT106
// leaf-direct-sha3x config values (LEAF_DIRECT_LISTEN_ADDRESS=
// 0.0.0.0:4444, LEAF_DIRECT_STARTING_DIFFICULTY=60000000) confirmed
// via the fallback (non -ports) path -- its equivalent explicit-ports
// form must round-trip identically.
func TestParsePortEntry_NoTLSSuffixBackwardCompatible(t *testing.T) {
	got, err := parsePortEntry("0.0.0.0:4444:60000000")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "0.0.0.0:4444", Difficulty: 60000000, PortDesc: "", TLS: false}
	if got != want {
		t.Fatalf("parsePortEntry(%q) = %+v, want %+v (backward-compat regression)", "0.0.0.0:4444:60000000", got, want)
	}
}

// TestParsePortEntry_NoTLSSuffixWithDescBackwardCompatible covers the
// "address:difficulty:desc" (no :tls) shape, confirming a real desc
// field is not confused with the ":tls" marker (a literal desc value
// of "tls" would be, but any OTHER desc string must round-trip with
// TLS: false).
func TestParsePortEntry_NoTLSSuffixWithDescBackwardCompatible(t *testing.T) {
	got, err := parsePortEntry("0.0.0.0:4443:1000:sha3x-plain")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "0.0.0.0:4443", Difficulty: 1000, PortDesc: "sha3x-plain", TLS: false}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestResolvePorts_MixedPlainAndTLSEntries confirms a comma-separated
// -ports value can mix plain and TLS-suffixed entries in the same
// list, exactly as the brief's example
// ("0.0.0.0:4444:1000:sha3x-plain,0.0.0.0:4443:1000:sha3x-tls:tls")
// describes.
func TestResolvePorts_MixedPlainAndTLSEntries(t *testing.T) {
	cfg := config{portsRaw: "0.0.0.0:4444:1000:sha3x-plain,0.0.0.0:4443:1000:sha3x-tls:tls"}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("resolvePorts returned %d ports, want 2", len(ports))
	}
	if ports[0].TLS {
		t.Errorf("ports[0].TLS = true, want false (plain entry)")
	}
	if !ports[1].TLS {
		t.Errorf("ports[1].TLS = false, want true (:tls entry)")
	}
}
