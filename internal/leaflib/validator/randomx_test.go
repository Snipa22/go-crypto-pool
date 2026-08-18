// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// These tests exercise RandomXValidator against an httptest server that
// implements go-xmr-lib's real RXVerifier HTTP protocol (POST /seed to
// prime a seed, per hashValidation/randomx.go's NewSeed/Hash) -- they do
// NOT exercise real RandomX hashing (no such implementation exists in this
// process; see randomx.go's top-of-file honest-status doc comment). This
// is exactly the gap that same doc comment calls out: before this
// validator is trusted in production it needs an end-to-end pass against
// a real randomx-service daemon, which is not available in this sandbox.

func randomXShare(blob, seed []byte, resultHex string, blockDiff int64) *poolpb.Share {
	return &poolpb.Share{
		BlockDiff: blockDiff,
		RawProof: &poolpb.Share_RandomxProof{
			RandomxProof: &poolpb.RandomXProof{
				Blob:      blob,
				SeedHash:  seed,
				ResultHex: resultHex,
			},
		},
	}
}

func TestRandomXValidator_Validate_MockService(t *testing.T) {
	realHash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	mux := http.NewServeMux()
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		// NewSeed: expects 204 on success.
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/hash", func(w http.ResponseWriter, r *http.Request) {
		// Hash(): real go-xmr-lib v0.2.5+ issues POST /hash (fixed from an
		// earlier v0.2.4 bug where it hit /seed with a malformed request --
		// see the go-xmr-lib PR #8/#9 fix and randomx.go's own top-of-file
		// doc comment for the full history; go-crypto-pool's go.mod pins
		// the fixed v0.2.5).
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(hex.EncodeToString(realHash)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewRandomXValidator(srv.URL)
	ctx := context.Background()

	t.Run("claimed hash matches real service response", func(t *testing.T) {
		valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), hex.EncodeToString(realHash), 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Errorf("expected valid=true when claimed hash matches service response")
		}
	})

	t.Run("claimed hash does not match real service response", func(t *testing.T) {
		valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "0000000000000000", 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false for a claimed hash that doesn't match")
		}
	})

	t.Run("malformed claimed hex is rejected, not an infra error", func(t *testing.T) {
		valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "not-hex!!", 0))
		if err != nil {
			t.Fatalf("expected no error for malformed hex (should be a rejected share, not an infra failure), got: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false for malformed claimed hex")
		}
	})

	t.Run("nil share", func(t *testing.T) {
		_, err := v.Validate(ctx, nil)
		if err == nil {
			t.Errorf("expected error for nil share")
		}
	})

	t.Run("wrong proof type", func(t *testing.T) {
		wrong := &poolpb.Share{RawProof: &poolpb.Share_C29Proof{C29Proof: &poolpb.C29Proof{}}}
		_, err := v.Validate(ctx, wrong)
		if err != ErrWrongProofType {
			t.Errorf("expected ErrWrongProofType, got %v", err)
		}
	})
}

func TestRandomXValidator_Validate_ServiceUnreachable(t *testing.T) {
	// A validator pointed at a genuinely unreachable service must return a
	// real (non-nil) error -- NOT silently accept or reject the share.
	// This is the "honest failure mode" the top-of-file doc comment on
	// randomx.go describes, and it's the single most important behavior
	// to regression-test here: a silent wrong answer in either direction
	// has real financial consequences in a payout system.
	v := NewRandomXValidator("http://127.0.0.1:1") // reserved, nothing listens here
	ctx := context.Background()

	valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "deadbeef", 0))
	if err == nil {
		t.Fatalf("expected a real error when the randomx-service is unreachable, got valid=%v, err=nil", valid)
	}
	if valid {
		t.Errorf("expected valid=false alongside the error (never silently accept on infra failure)")
	}
}
