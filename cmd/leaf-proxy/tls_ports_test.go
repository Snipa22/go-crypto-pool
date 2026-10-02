// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// TestParsePortEntry_TLSSuffixEnablesTLS confirms the new, optional
// trailing ":tls" marker (case-insensitive, always the LAST
// colon-separated field) is stripped off FIRST and sets
// PortConfig.TLS -- the existing difficulty/desc peeling logic is
// otherwise untouched. Mirrors cmd/leaf-direct/tls_ports_test.go's
// identical test exactly, using leaf-proxy's own default listen
// address (:5555) in place of leaf-direct's :4443/:4444.
func TestParsePortEntry_TLSSuffixEnablesTLS(t *testing.T) {
	got, err := parsePortEntry("0.0.0.0:5556:1000:medium-tls:tls")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "0.0.0.0:5556", Difficulty: 1000, PortDesc: "medium-tls", TLS: true}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestParsePortEntry_TLSSuffixCaseInsensitive confirms the ":tls"
// literal is matched case-insensitively (":TLS", ":Tls", etc.).
func TestParsePortEntry_TLSSuffixCaseInsensitive(t *testing.T) {
	for _, suffix := range []string{"tls", "TLS", "Tls", "tLs"} {
		got, err := parsePortEntry("0.0.0.0:5556:1000:" + suffix)
		if err != nil {
			t.Fatalf("parsePortEntry with suffix %q: %v", suffix, err)
		}
		if !got.TLS {
			t.Errorf("parsePortEntry with suffix %q: TLS = false, want true", suffix)
		}
		if got.Address != "0.0.0.0:5556" || got.Difficulty != 1000 {
			t.Errorf("parsePortEntry with suffix %q: Address/Difficulty = %q/%d, want 0.0.0.0:5556/1000", suffix, got.Address, got.Difficulty)
		}
	}
}

// TestParsePortEntry_NoTLSSuffixBackwardCompatible is the explicit
// backward-compat regression guard: an entry with no trailing ":tls"
// field must parse EXACTLY as before this feature existed, producing
// PortConfig{..., TLS: false}.
func TestParsePortEntry_NoTLSSuffixBackwardCompatible(t *testing.T) {
	got, err := parsePortEntry("0.0.0.0:5555:10000")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "0.0.0.0:5555", Difficulty: 10000, PortDesc: "", TLS: false}
	if got != want {
		t.Fatalf("parsePortEntry(%q) = %+v, want %+v (backward-compat regression)", "0.0.0.0:5555:10000", got, want)
	}
}

// TestParsePortEntry_NoTLSSuffixWithDescBackwardCompatible covers the
// "address:difficulty:desc" (no :tls) shape, confirming a real desc
// field is not confused with the ":tls" marker (a literal desc value
// of "tls" would be, but any OTHER desc string must round-trip with
// TLS: false).
func TestParsePortEntry_NoTLSSuffixWithDescBackwardCompatible(t *testing.T) {
	got, err := parsePortEntry("0.0.0.0:5556:1000:medium-plain")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "0.0.0.0:5556", Difficulty: 1000, PortDesc: "medium-plain", TLS: false}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestResolvePorts_MixedPlainAndTLSEntries confirms a comma-separated
// -ports value can mix plain and TLS-suffixed entries in the same
// list.
func TestResolvePorts_MixedPlainAndTLSEntries(t *testing.T) {
	cfg := config{portsRaw: "0.0.0.0:5555:1000:medium-plain,0.0.0.0:5556:1000:medium-tls:tls"}
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

// TestParsePortEntry_InvalidDifficultyNonNumeric confirms a
// non-numeric difficulty field produces an error (leaf-direct has no
// dedicated coverage for this -- added fresh per this feature's own
// test requirements). Only a 2-field entry ("address:garbage") is
// unambiguous here -- a 3+ field entry with a non-numeric LAST field
// is deliberately reinterpreted as "address:difficulty:desc" by the
// existing peeling logic (see parsePortEntry's own doc comment), so
// that shape is not itself an error case.
func TestParsePortEntry_InvalidDifficultyNonNumeric(t *testing.T) {
	_, err := parsePortEntry("0.0.0.0:not-a-number")
	if err == nil {
		t.Fatal("parsePortEntry: expected an error for a non-numeric difficulty, got nil")
	}
}

// TestParsePortEntry_EmptyAddressPortion confirms an empty address
// portion is rejected explicitly.
func TestParsePortEntry_EmptyAddressPortion(t *testing.T) {
	_, err := parsePortEntry(":1000")
	if err == nil {
		t.Fatal("parsePortEntry: expected an error for an empty address portion, got nil")
	}
	if !strings.Contains(err.Error(), "address portion is empty") {
		t.Errorf("parsePortEntry error = %v, want it to mention %q", err, "address portion is empty")
	}
}

// TestParsePortEntry_ZeroDifficultyRejected confirms a difficulty of
// exactly 0 is rejected with the documented "difficulty must be > 0"
// message.
func TestParsePortEntry_ZeroDifficultyRejected(t *testing.T) {
	_, err := parsePortEntry("0.0.0.0:5555:0")
	if err == nil {
		t.Fatal("parsePortEntry: expected an error for a zero difficulty, got nil")
	}
	if !strings.Contains(err.Error(), "difficulty must be > 0") {
		t.Errorf("parsePortEntry error = %v, want it to mention %q", err, "difficulty must be > 0")
	}
}

// TestResolvePorts_MultipleValidEntries confirms resolvePorts handles
// 3+ valid entries in one -ports string.
func TestResolvePorts_MultipleValidEntries(t *testing.T) {
	cfg := config{portsRaw: "0.0.0.0:3333:100:low,0.0.0.0:5555:1000:medium,0.0.0.0:7777:10000:high,0.0.0.0:9000:10000:tls-tier:tls"}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 4 {
		t.Fatalf("resolvePorts returned %d ports, want 4", len(ports))
	}
	wantAddrs := []string{"0.0.0.0:3333", "0.0.0.0:5555", "0.0.0.0:7777", "0.0.0.0:9000"}
	wantDiffs := []uint64{100, 1000, 10000, 10000}
	for i, p := range ports {
		if p.Address != wantAddrs[i] {
			t.Errorf("ports[%d].Address = %q, want %q", i, p.Address, wantAddrs[i])
		}
		if p.Difficulty != wantDiffs[i] {
			t.Errorf("ports[%d].Difficulty = %d, want %d", i, p.Difficulty, wantDiffs[i])
		}
	}
	if ports[3].TLS != true {
		t.Errorf("ports[3].TLS = false, want true")
	}
}

// TestResolvePorts_UnsetFallsBackToListenAddressAndStartingDifficulty
// confirms that when -ports/LEAF_PROXY_PORTS is unset, resolvePorts
// falls back to -listen-address/-starting-difficulty as a single
// implicit tier -- the fully-backward-compatible default path.
func TestResolvePorts_UnsetFallsBackToListenAddressAndStartingDifficulty(t *testing.T) {
	cfg := config{listenAddress: ":5555", startingDifficulty: 10000}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("resolvePorts returned %d ports, want 1 (fallback tier)", len(ports))
	}
	want := solo.PortConfig{Address: ":5555", Difficulty: 10000, PortDesc: "default"}
	if ports[0] != want {
		t.Fatalf("resolvePorts()[0] = %+v, want %+v", ports[0], want)
	}
}

// --- DISPATCH_BRIEF.md section 6 ("IPv6 support") -----------------
//
// parsePortEntry used to split the WHOLE raw entry string on ":",
// unconditionally -- which breaks for any IPv6 literal host, since
// the address itself contains colons. These tests pin down the fix
// (parseIPv6PortEntry, routed to via a leading "[" check) for the
// brief's own required cases, plus confirm the pre-existing IPv4
// cases above still pass completely unchanged (they do -- see every
// other Test* in this file, none of which were touched by the fix).

// TestParsePortEntry_IPv6Loopback covers "[::1]:5555:20000" (loopback
// IPv6, no desc/tls) -- the brief's own first required case.
func TestParsePortEntry_IPv6Loopback(t *testing.T) {
	got, err := parsePortEntry("[::1]:5555:20000")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "[::1]:5555", Difficulty: 20000, PortDesc: "", TLS: false}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestParsePortEntry_IPv6WildcardWithDesc covers
// "[::]:5555:20000:dual-stack" (wildcard IPv6, with desc) -- the
// brief's own second required case.
func TestParsePortEntry_IPv6WildcardWithDesc(t *testing.T) {
	got, err := parsePortEntry("[::]:5555:20000:dual-stack")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "[::]:5555", Difficulty: 20000, PortDesc: "dual-stack", TLS: false}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestParsePortEntry_IPv6WildcardWithTLS covers "[::]:5556:20000:tls"
// (wildcard IPv6, TLS marker) -- the brief's own third required
// case.
func TestParsePortEntry_IPv6WildcardWithTLS(t *testing.T) {
	got, err := parsePortEntry("[::]:5556:20000:tls")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "[::]:5556", Difficulty: 20000, PortDesc: "", TLS: true}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestParsePortEntry_IPv6WildcardWithDescAndTLS covers the
// combination of a desc AND a trailing ":tls" marker on an IPv6
// entry, mirroring TestParsePortEntry_TLSSuffixEnablesTLS's IPv4
// coverage of the same combination.
func TestParsePortEntry_IPv6WildcardWithDescAndTLS(t *testing.T) {
	got, err := parsePortEntry("[::]:5557:20000:dual-stack-tls:tls")
	if err != nil {
		t.Fatalf("parsePortEntry: %v", err)
	}
	want := solo.PortConfig{Address: "[::]:5557", Difficulty: 20000, PortDesc: "dual-stack-tls", TLS: true}
	if got != want {
		t.Fatalf("parsePortEntry(...) = %+v, want %+v", got, want)
	}
}

// TestParsePortEntry_IPv6MissingClosingBracket confirms a malformed
// IPv6 entry missing its closing "]" is rejected with a clear error
// rather than silently mis-parsing.
func TestParsePortEntry_IPv6MissingClosingBracket(t *testing.T) {
	_, err := parsePortEntry("[::1:5555:20000")
	if err == nil {
		t.Fatal("parsePortEntry: expected an error for a missing closing ']', got nil")
	}
}

// TestParsePortEntry_IPv6MissingPort confirms an IPv6 entry with no
// ":port" immediately after the closing "]" is rejected.
func TestParsePortEntry_IPv6MissingPort(t *testing.T) {
	_, err := parsePortEntry("[::1]20000")
	if err == nil {
		t.Fatal(`parsePortEntry: expected an error for a missing ":port" after the IPv6 literal, got nil`)
	}
}

// TestResolvePorts_IPv6AndIPv4Mixed confirms a comma-separated -ports
// value can mix an IPv4 tier and an IPv6 tier in the same list (the
// TOML example file's own documented use case).
func TestResolvePorts_IPv6AndIPv4Mixed(t *testing.T) {
	cfg := config{portsRaw: "0.0.0.0:5555:20000:v4-tier,[::]:5555:20000:v6-tier"}
	ports, err := resolvePorts(cfg)
	if err != nil {
		t.Fatalf("resolvePorts: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("resolvePorts returned %d ports, want 2", len(ports))
	}
	if ports[0].Address != "0.0.0.0:5555" || ports[1].Address != "[::]:5555" {
		t.Fatalf("resolvePorts addresses = %q, %q, want 0.0.0.0:5555, [::]:5555", ports[0].Address, ports[1].Address)
	}
}
