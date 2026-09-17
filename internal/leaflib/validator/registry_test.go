// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

func TestNewValidator(t *testing.T) {
	tests := []struct {
		name    string
		algo    poolpb.Algo
		wantErr bool
	}{
		{name: "C29", algo: poolpb.Algo_ALGO_C29, wantErr: false},
		{name: "SHA3X", algo: poolpb.Algo_ALGO_SHA3X, wantErr: false},
		{name: "RXT", algo: poolpb.Algo_ALGO_RXT, wantErr: false},
		{name: "RXM", algo: poolpb.Algo_ALGO_RXM, wantErr: false},
		{name: "XMR (standalone, new)", algo: poolpb.Algo_ALGO_XMR, wantErr: false},
		{name: "ARQ (new)", algo: poolpb.Algo_ALGO_ARQ, wantErr: false},
		{name: "SAL (new)", algo: poolpb.Algo_ALGO_SAL, wantErr: false},
		{name: "unspecified", algo: poolpb.Algo_ALGO_UNSPECIFIED, wantErr: true},
		{name: "invalid/out-of-range", algo: poolpb.Algo(999), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewValidator(tt.algo, "")
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected an error for algo %v, got none", tt.algo)
				}
				if v != nil {
					t.Errorf("expected nil validator alongside error, got %T", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for algo %v: %v", tt.algo, err)
			}
			if v == nil {
				t.Fatalf("expected a non-nil validator for algo %v", tt.algo)
			}
		})
	}
}

func TestNewValidator_ReturnsCorrectConcreteType(t *testing.T) {
	c29, err := NewValidator(poolpb.Algo_ALGO_C29, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c29.(*C29Validator); !ok {
		t.Errorf("expected *C29Validator for ALGO_C29, got %T", c29)
	}

	sha3x, err := NewValidator(poolpb.Algo_ALGO_SHA3X, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := sha3x.(*SHA3XValidator); !ok {
		t.Errorf("expected *SHA3XValidator for ALGO_SHA3X, got %T", sha3x)
	}

	rxt, err := NewValidator(poolpb.Algo_ALGO_RXT, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := rxt.(*RandomXValidator); !ok {
		t.Errorf("expected *RandomXValidator for ALGO_RXT, got %T", rxt)
	}

	rxm, err := NewValidator(poolpb.Algo_ALGO_RXM, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := rxm.(*RandomXValidator); !ok {
		t.Errorf("expected *RandomXValidator for ALGO_RXM, got %T", rxm)
	}
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry("")

	wantAlgos := []poolpb.Algo{
		poolpb.Algo_ALGO_C29,
		poolpb.Algo_ALGO_SHA3X,
		poolpb.Algo_ALGO_RXT,
		poolpb.Algo_ALGO_RXM,
		poolpb.Algo_ALGO_XMR,
		poolpb.Algo_ALGO_ARQ,
		poolpb.Algo_ALGO_XEQ,
		poolpb.Algo_ALGO_GRFT,
		poolpb.Algo_ALGO_SFX,
		poolpb.Algo_ALGO_ZEPH,
		poolpb.Algo_ALGO_SAL,
	}
	for _, algo := range wantAlgos {
		v, err := reg.Get(algo)
		if err != nil {
			t.Errorf("Get(%v): unexpected error: %v", algo, err)
			continue
		}
		if v == nil {
			t.Errorf("Get(%v): expected non-nil validator", algo)
		}
	}

	t.Run("RXT and RXM share the same RandomXValidator instance", func(t *testing.T) {
		// Per the architecture decision that RXM behaves like a Monero
		// daemon protocol-wise and can reuse RXT's validation approach --
		// NewRegistry constructs ONE RandomXValidator and registers it
		// under both algos, not two independent instances.
		rxt, err := reg.Get(poolpb.Algo_ALGO_RXT)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rxm, err := reg.Get(poolpb.Algo_ALGO_RXM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rxt != rxm {
			t.Errorf("expected RXT and RXM to resolve to the same *RandomXValidator instance")
		}
	})

	t.Run("unknown algo returns ErrUnsupportedAlgo", func(t *testing.T) {
		_, err := reg.Get(poolpb.Algo_ALGO_UNSPECIFIED)
		if err == nil {
			t.Errorf("expected an error for ALGO_UNSPECIFIED")
		}
	})

	t.Run("every new coin algo shares the same RandomXValidator instance as RXT/RXM", func(t *testing.T) {
		rxt, err := reg.Get(poolpb.Algo_ALGO_RXT)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, algo := range []poolpb.Algo{
			poolpb.Algo_ALGO_XMR, poolpb.Algo_ALGO_ARQ, poolpb.Algo_ALGO_XEQ,
			poolpb.Algo_ALGO_GRFT, poolpb.Algo_ALGO_SFX, poolpb.Algo_ALGO_ZEPH, poolpb.Algo_ALGO_SAL,
		} {
			v, err := reg.Get(algo)
			if err != nil {
				t.Fatalf("Get(%v): unexpected error: %v", algo, err)
			}
			if v != rxt {
				t.Errorf("Get(%v) did not resolve to the same *RandomXValidator instance as RXT", algo)
			}
		}
	})
}
