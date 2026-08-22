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
