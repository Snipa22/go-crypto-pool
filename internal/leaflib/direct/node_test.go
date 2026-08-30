// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bytes"
	"testing"
)

// TestNodeClientBuildCoinbaseExtraContainsConfiguredTag mirrors
// solo's own TestGRPCNodeClientBuildCoinbaseExtraContainsConfiguredTag
// for leaf-direct's independent NodeClient implementation -- verifies
// the exact bytes GetBlockTemplate would submit as CoinbaseExtra start
// with this instance's configured coinbaseExtraTag, without needing a
// real GRPC connection.
func TestNodeClientBuildCoinbaseExtraContainsConfiguredTag(t *testing.T) {
	tag := []byte("supportxtm-rxt")
	c := &NodeClient{coinbaseExtraTag: tag}

	extra := c.buildCoinbaseExtra()

	if !bytes.HasPrefix(extra, tag) {
		t.Fatalf("buildCoinbaseExtra() = %q, want prefix %q", extra, tag)
	}
}

func TestNodeClientBuildCoinbaseExtraDiffersPerCall(t *testing.T) {
	c := &NodeClient{coinbaseExtraTag: []byte("supportxtm-sha3x")}
	a := c.buildCoinbaseExtra()
	b := c.buildCoinbaseExtra()
	if bytes.Equal(a, b) {
		t.Errorf("two calls to buildCoinbaseExtra() produced identical bytes %q -- nonce is no longer randomized", a)
	}
}
