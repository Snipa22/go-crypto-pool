// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"context"
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestSHA3XHeaderDiff_LegacyVectors reuses the inputs from go-tari-sha3x-solo-stratum's
// subsystems/blockTemplateCache/blockTemplate_test.go TestGetHeaderDiff (see
// /workspace/omni-pool-review/go-tari-sha3x-solo-stratum) — not synthetic
// data. NOTE ON EXPECTED VALUES: the legacy test file's own `want` for its
// second case (13645861923) does NOT match the legacy GetHeaderDiff
// function's actual real output for those inputs — verified directly by
// running the legacy function itself (go test against a temporary harness
// calling blockTemplateCache.GetHeaderDiff with these exact args returns 2,
// not 13645861923; this is a pre-existing, stale/broken assertion in the
// legacy repo's own test, not a defect in this port). This test's `want`
// values below are the REAL legacy function's actual output, confirmed by
// direct execution — not the legacy test file's (wrong) assertions. The
// legacy header.Nonce field is passed straight through as this validator's
// sha3xHeaderDiff's nonce argument, since that's the only header field
// GetHeaderDiff's math consumes beyond miningHash and the fixed PowAlgo
// byte (both fixtures use PowAlgo: 1, matching sha3xPowAlgoByte).
func TestSHA3XHeaderDiff_LegacyVectors(t *testing.T) {
	tests := []struct {
		name       string
		nonce      uint64
		miningHash []byte
		want       uint64
	}{
		{
			name:       "legacy: Verify Tari result with a static block template - Height 0",
			nonce:      4,
			miningHash: []byte{85, 245, 225, 251, 80, 199, 20, 111, 84, 189, 23, 31, 200, 188, 30, 182, 88, 191, 240, 123, 123, 239, 229, 209, 64, 221, 204, 255, 229, 175, 244, 28},
			want:       4,
		},
		{
			// Legacy test file asserts want=13645861923 for this input, but
			// that assertion does not match the legacy GetHeaderDiff
			// function's real output (confirmed by direct execution — see
			// comment above). The real value is 2, and this port correctly
			// reproduces it.
			name:       "legacy: Generate known tari result w/ target verification from daemon",
			nonce:      12238891555,
			miningHash: []byte{153, 120, 61, 169, 149, 9, 184, 83, 201, 15, 60, 16, 190, 168, 164, 224, 5, 241, 68, 141, 124, 192, 137, 75, 255, 62, 93, 82, 170, 71, 65, 82},
			want:       2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sha3xHeaderDiff(tt.nonce, tt.miningHash); got != tt.want {
				t.Errorf("sha3xHeaderDiff() = %v, want %v", got, tt.want)
			}
		})
	}
}

func sha3xShare(nonce uint64, header []byte, blockDiff int64) *poolpb.Share {
	return &poolpb.Share{
		BlockDiff: blockDiff,
		RawProof: &poolpb.Share_Sha3XProof{
			Sha3XProof: &poolpb.SHA3XProof{
				Header: header,
				Nonce:  nonce,
			},
		},
	}
}

func TestSHA3XValidator_Validate(t *testing.T) {
	v := NewSHA3XValidator()
	ctx := context.Background()

	header := []byte{85, 245, 225, 251, 80, 199, 20, 111, 84, 189, 23, 31, 200, 188, 30, 182, 88, 191, 240, 123, 123, 239, 229, 209, 64, 221, 204, 255, 229, 175, 244, 28}

	t.Run("legacy vector, difficulty met (BlockDiff <= 4)", func(t *testing.T) {
		valid, err := v.Validate(ctx, sha3xShare(4, header, 4))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Errorf("expected valid=true")
		}
	})

	t.Run("legacy vector, difficulty NOT met (BlockDiff > 4)", func(t *testing.T) {
		valid, err := v.Validate(ctx, sha3xShare(4, header, 5))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false when derived diff (4) < BlockDiff (5)")
		}
	})

	t.Run("BlockDiff<=0 skips the difficulty check", func(t *testing.T) {
		valid, err := v.Validate(ctx, sha3xShare(4, header, 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Errorf("expected valid=true when BlockDiff is 0 (no threshold)")
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
