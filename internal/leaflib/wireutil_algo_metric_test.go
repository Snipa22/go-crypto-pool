// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestAlgoMetricLabel_DistinctFromAlgoWireName pins down
// AlgoMetricLabel's small, fixed label set -- in particular that,
// unlike AlgoWireName, RXT and RXM report DISTINCT values (see
// AlgoMetricLabel's own doc comment for why: the submit-latency
// metrics this label backs need to tell a validator regression for
// one specific RandomX-family algo apart from another).
func TestAlgoMetricLabel_DistinctFromAlgoWireName(t *testing.T) {
	tests := []struct {
		algo poolpb.Algo
		want string
	}{
		{poolpb.Algo_ALGO_SHA3X, "sha3x"},
		{poolpb.Algo_ALGO_C29, "c29"},
		{poolpb.Algo_ALGO_RXT, "rxt"},
		{poolpb.Algo_ALGO_RXM, "rxm"},
		{poolpb.Algo_ALGO_XMR, "rxm"},
		{poolpb.Algo_ALGO_ARQ, "rxm"},
		{poolpb.Algo_ALGO_UNSPECIFIED, "sha3x"},
	}
	for _, tc := range tests {
		if got := AlgoMetricLabel(tc.algo); got != tc.want {
			t.Errorf("AlgoMetricLabel(%v) = %q, want %q", tc.algo, got, tc.want)
		}
	}

	// RXT and RXM must collapse to the SAME AlgoWireName ("rx/0")
	// but DIFFERENT AlgoMetricLabel values -- the whole point of
	// having a separate helper.
	if AlgoWireName(poolpb.Algo_ALGO_RXT) != AlgoWireName(poolpb.Algo_ALGO_RXM) {
		t.Fatalf("test premise broken: AlgoWireName(RXT) != AlgoWireName(RXM)")
	}
	if AlgoMetricLabel(poolpb.Algo_ALGO_RXT) == AlgoMetricLabel(poolpb.Algo_ALGO_RXM) {
		t.Errorf("AlgoMetricLabel(RXT) == AlgoMetricLabel(RXM) == %q, want distinct values", AlgoMetricLabel(poolpb.Algo_ALGO_RXT))
	}
}
