// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"strings"
	"testing"
)

// TestGRPCNodeClientBuildCoinbaseExtraContainsConfiguredTag verifies
// the exact bytes GetBlockTemplate would submit as CoinbaseExtra
// (via buildCoinbaseExtra) start with this instance's configured
// coinbaseExtraTag, without needing a real GRPC connection.
func TestGRPCNodeClientBuildCoinbaseExtraContainsConfiguredTag(t *testing.T) {
	tag := []byte("supportxtm-sha3x")
	c := &GRPCNodeClient{coinbaseExtraTag: tag}

	extra := c.buildCoinbaseExtra()

	if !bytes.HasPrefix(extra, tag) {
		t.Fatalf("buildCoinbaseExtra() = %q, want prefix %q", extra, tag)
	}
	// tag + 8-byte per-xn random nonce.
	if len(extra) != len(tag)+8 {
		t.Errorf("len(buildCoinbaseExtra()) = %d, want %d", len(extra), len(tag)+8)
	}
}

// TestGRPCNodeClientBuildCoinbaseExtraDiffersPerCall confirms the
// per-xn random nonce still varies call-to-call after this refactor
// (mirrors the pre-existing randomization guarantee GetBlockTemplate's
// own doc comment describes).
func TestGRPCNodeClientBuildCoinbaseExtraDiffersPerCall(t *testing.T) {
	c := &GRPCNodeClient{coinbaseExtraTag: []byte("supportxtm-c29")}
	a := c.buildCoinbaseExtra()
	b := c.buildCoinbaseExtra()
	if bytes.Equal(a, b) {
		t.Errorf("two calls to buildCoinbaseExtra() produced identical bytes %q -- nonce is no longer randomized", a)
	}
}

func TestNormalizeCoinbaseExtraTagUsesExplicitValueVerbatim(t *testing.T) {
	got := NormalizeCoinbaseExtraTag("my-custom-tag", "supportxtm-sha3x")
	if string(got) != "my-custom-tag" {
		t.Errorf("NormalizeCoinbaseExtraTag = %q, want %q", got, "my-custom-tag")
	}
}

func TestNormalizeCoinbaseExtraTagFallsBackWhenEmpty(t *testing.T) {
	for _, tag := range []string{"", "   "} {
		got := NormalizeCoinbaseExtraTag(tag, "supportxtm-rxt")
		if string(got) != "supportxtm-rxt" {
			t.Errorf("NormalizeCoinbaseExtraTag(%q, ...) = %q, want fallback %q", tag, got, "supportxtm-rxt")
		}
	}
}

func TestNormalizeCoinbaseExtraTagTruncatesOverlongInput(t *testing.T) {
	overlong := strings.Repeat("A", MaxCoinbaseExtraTagLen+50)
	got := NormalizeCoinbaseExtraTag(overlong, "supportxtm-sha3x")
	if len(got) != MaxCoinbaseExtraTagLen {
		t.Fatalf("len(NormalizeCoinbaseExtraTag(overlong, ...)) = %d, want %d", len(got), MaxCoinbaseExtraTagLen)
	}
	if string(got) != overlong[:MaxCoinbaseExtraTagLen] {
		t.Errorf("truncated tag does not match the expected prefix")
	}
}

func TestNormalizeCoinbaseExtraTagAcceptsExactMaxLength(t *testing.T) {
	exact := strings.Repeat("B", MaxCoinbaseExtraTagLen)
	got := NormalizeCoinbaseExtraTag(exact, "supportxtm-sha3x")
	if len(got) != MaxCoinbaseExtraTagLen {
		t.Errorf("len(got) = %d, want %d (exact-length input must not be truncated further)", len(got), MaxCoinbaseExtraTagLen)
	}
}
