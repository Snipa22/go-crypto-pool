// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Real, primary-source-cited addresses -- see
// internal/coinprofile/address_test.go's identical constants for the
// exact provenance of each one (genesis-embedded governance/treasury
// wallet addresses baked directly into each coin's own
// cryptonote_config.h).
const (
	realARQAddressForSoloTest = "ar2dJ21SCuNiJndoQBf5ojhbdA7K8B3sREpnWSg4pHedXcwMbvUkYREAapZJMn3cVRj6VqDqDkj9bFoXLJViCmFs2qWkdufHt"
	realXEQAddressForSoloTest = "TvziQSEi93chTMViBzw8Y4eerEjmGq2Q6ajekvgyTyqkGcsj97YJDzF8TMnTWdv7NXQ2ZXfeWJPwRAbVHUjbgFcN2AvU35KfX"
)

// TestValidateAddressForAlgo_NewCoinAlgosUseCoinProfile proves
// ValidateAddressForAlgo's generalized default branch (added for the
// new poolpb.Algo_ALGO_XMR and below values) genuinely reads each
// coin's OWN real network-byte table via internal/coinprofile,
// instead of the old hardcoded-Monero-only byte list -- a real ARQ
// address must validate against ALGO_ARQ but be REJECTED against
// ALGO_XEQ (different coin, different network bytes), and vice versa.
func TestValidateAddressForAlgo_NewCoinAlgosUseCoinProfile(t *testing.T) {
	if err := ValidateAddressForAlgo(poolpb.Algo_ALGO_ARQ, realARQAddressForSoloTest); err != nil {
		t.Errorf("ValidateAddressForAlgo(ALGO_ARQ, real ARQ address) = %v, want nil", err)
	}
	if err := ValidateAddressForAlgo(poolpb.Algo_ALGO_XEQ, realXEQAddressForSoloTest); err != nil {
		t.Errorf("ValidateAddressForAlgo(ALGO_XEQ, real XEQ address) = %v, want nil", err)
	}

	if err := ValidateAddressForAlgo(poolpb.Algo_ALGO_XEQ, realARQAddressForSoloTest); err == nil {
		t.Error("ValidateAddressForAlgo(ALGO_XEQ, real ARQ address) = nil, want error (wrong coin's network bytes)")
	}
	if err := ValidateAddressForAlgo(poolpb.Algo_ALGO_ARQ, realXEQAddressForSoloTest); err == nil {
		t.Error("ValidateAddressForAlgo(ALGO_ARQ, real XEQ address) = nil, want error (wrong coin's network bytes)")
	}
}

// TestValidateAddressForAlgo_RXMUnchanged proves ALGO_RXM's existing
// Monero-specific validator (validateMoneroLoginAddress,
// go-xmr-lib-backed) is completely untouched by the CoinProfile
// generalization -- it does not go through the new default branch at
// all.
func TestValidateAddressForAlgo_RXMUnchanged(t *testing.T) {
	if err := ValidateAddressForAlgo(poolpb.Algo_ALGO_RXM, ""); err == nil {
		t.Error("ValidateAddressForAlgo(ALGO_RXM, \"\") = nil, want error (empty address)")
	}
	// A real ARQ address is NOT a valid Monero address (different
	// network bytes) -- ALGO_RXM must still reject it via its own
	// unchanged Monero-only validator.
	if err := ValidateAddressForAlgo(poolpb.Algo_ALGO_RXM, realARQAddressForSoloTest); err == nil {
		t.Error("ValidateAddressForAlgo(ALGO_RXM, real ARQ address) = nil, want error")
	}
}

// TestValidateAddressForAlgo_UnregisteredAlgoRejected proves an algo
// with no validator at all (neither the Tari/Monero switch cases nor
// a registered CoinProfile) is refused, not silently accepted.
func TestValidateAddressForAlgo_UnregisteredAlgoRejected(t *testing.T) {
	const bogusAlgo = poolpb.Algo(9999)
	if err := ValidateAddressForAlgo(bogusAlgo, realARQAddressForSoloTest); err == nil {
		t.Error("ValidateAddressForAlgo(bogus algo, ...) = nil, want error")
	}
}

// TestIsMoneroFamilyAlgo covers every algo this leaf's NodeClient
// dispatch cares about: ALGO_RXM (unchanged) and every registered
// internal/coinprofile.Registry algo route to the real
// MoneroNodeClient; Tari's native algos and unregistered values do
// not.
func TestIsMoneroFamilyAlgo(t *testing.T) {
	moneroFamily := []poolpb.Algo{
		poolpb.Algo_ALGO_RXM,
		poolpb.Algo_ALGO_XMR,
		poolpb.Algo_ALGO_ARQ,
		poolpb.Algo_ALGO_XEQ,
		poolpb.Algo_ALGO_GRFT,
		poolpb.Algo_ALGO_SFX,
		poolpb.Algo_ALGO_ZEPH,
		poolpb.Algo_ALGO_SAL,
	}
	for _, algo := range moneroFamily {
		if !IsMoneroFamilyAlgo(algo) {
			t.Errorf("IsMoneroFamilyAlgo(%v) = false, want true", algo)
		}
	}

	notMoneroFamily := []poolpb.Algo{
		poolpb.Algo_ALGO_UNSPECIFIED,
		poolpb.Algo_ALGO_SHA3X,
		poolpb.Algo_ALGO_C29,
		poolpb.Algo_ALGO_RXT,
		poolpb.Algo(9999),
	}
	for _, algo := range notMoneroFamily {
		if IsMoneroFamilyAlgo(algo) {
			t.Errorf("IsMoneroFamilyAlgo(%v) = true, want false", algo)
		}
	}
}
