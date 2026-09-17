// Copyright and license: see repository LICENSE (MIT).
package coinprofile

import "testing"

// Real, primary-source-cited addresses (genesis-embedded governance/
// treasury/dev wallet addresses baked directly into each confirmed
// coin's own cryptonote_config.h) -- used to prove ValidateAddress's
// base58-decode + Keccak-256-checksum + network-byte-prefix check is
// reading each coin's OWN real per-coin byte table, not a leftover
// hardcoded Monero-only list. Not derived/fabricated: each was copied
// verbatim from that coin's own official GitHub source (see
// coinprofile.go's per-entry doc comments for the exact URL).
const (
	realARQGovAddress      = "ar2dJ21SCuNiJndoQBf5ojhbdA7K8B3sREpnWSg4pHedXcwMbvUkYREAapZJMn3cVRj6VqDqDkj9bFoXLJViCmFs2qWkdufHt"
	realXEQGovAddress      = "TvziQSEi93chTMViBzw8Y4eerEjmGq2Q6ajekvgyTyqkGcsj97YJDzF8TMnTWdv7NXQ2ZXfeWJPwRAbVHUjbgFcN2AvU35KfX"
	realZEPHGovAddress     = "ZEPHYR2jZrZXenfKejCcCmEkRzUYwXjgWfJF4yzdCznKQ8yQ3g3PsWUbZjzfzHbeTPMgXVmEuDKQUB9rPkgtVwyWRh9knU4EpfJ57"
	realSALTreasuryAddress = "SaLvdZR6w1A21sf2Wh6jYEh1wzY4GSbT7RX6FjyPsnLsffWLrzFQeXUXJcmBLRWDzZC2YXeYe5t7qKsnrg9FpmxmEcxPHsEYfqA"
)

func TestValidateAddress_RealARQAddress(t *testing.T) {
	profile, ok := Lookup("arq")
	if !ok {
		t.Fatal("ARQ not registered")
	}
	if err := ValidateAddress(profile, realARQGovAddress); err != nil {
		t.Fatalf("ValidateAddress(ARQ, real gov address) = %v, want nil", err)
	}
}

func TestValidateAddress_RealXEQAddress(t *testing.T) {
	profile, ok := Lookup("xeq")
	if !ok {
		t.Fatal("XEQ not registered")
	}
	if err := ValidateAddress(profile, realXEQGovAddress); err != nil {
		t.Fatalf("ValidateAddress(XEQ, real gov address) = %v, want nil", err)
	}
}

func TestValidateAddress_RealZEPHAddress(t *testing.T) {
	profile, ok := Lookup("zeph")
	if !ok {
		t.Fatal("ZEPH not registered")
	}
	if err := ValidateAddress(profile, realZEPHGovAddress); err != nil {
		t.Fatalf("ValidateAddress(ZEPH, real gov address) = %v, want nil", err)
	}
}

func TestValidateAddress_RealSALAddress(t *testing.T) {
	profile, ok := Lookup("sal")
	if !ok {
		t.Fatal("SAL not registered")
	}
	if err := ValidateAddress(profile, realSALTreasuryAddress); err != nil {
		t.Fatalf("ValidateAddress(SAL, real treasury address) = %v, want nil", err)
	}
}

// TestValidateAddress_CrossCoinRejected proves the per-coin byte table
// is actually being consulted (not a shared/ignored check): a real
// XEQ address must be REJECTED when validated against ARQ's profile
// (different network-tag bytes), and vice versa.
func TestValidateAddress_CrossCoinRejected(t *testing.T) {
	arq, _ := Lookup("arq")
	xeq, _ := Lookup("xeq")

	if err := ValidateAddress(arq, realXEQGovAddress); err == nil {
		t.Error("ValidateAddress(ARQ profile, real XEQ address) = nil, want a network-byte mismatch error")
	}
	if err := ValidateAddress(xeq, realARQGovAddress); err == nil {
		t.Error("ValidateAddress(XEQ profile, real ARQ address) = nil, want a network-byte mismatch error")
	}
}

func TestValidateAddress_CorruptedChecksumRejected(t *testing.T) {
	profile, _ := Lookup("xeq")
	// Flip the last character, which (with overwhelming probability)
	// invalidates the trailing base58 block's decoded checksum bytes.
	corrupted := realXEQGovAddress[:len(realXEQGovAddress)-1] + "9"
	if corrupted == realXEQGovAddress {
		t.Fatal("corruption produced an identical string, fix the test")
	}
	if err := ValidateAddress(profile, corrupted); err == nil {
		t.Error("ValidateAddress(XEQ, corrupted address) = nil, want a checksum error")
	}
}

func TestValidateAddress_EmptyAndGarbageRejected(t *testing.T) {
	profile, _ := Lookup("xmr")
	for _, bad := range []string{"", "not a real address at all", "0000000000000000000000000000000000000000000000000000000000000000000"} {
		if err := ValidateAddress(profile, bad); err == nil {
			t.Errorf("ValidateAddress(XMR, %q) = nil, want error", bad)
		}
	}
}

func TestValidateAddressForTicker_UnknownTickerFailsFast(t *testing.T) {
	err := ValidateAddressForTicker("notacoin", realARQGovAddress)
	if err == nil {
		t.Fatal("ValidateAddressForTicker(\"notacoin\", ...) = nil, want error")
	}
	if _, ok := err.(*ErrUnknownTicker); !ok {
		t.Fatalf("ValidateAddressForTicker(\"notacoin\", ...) error type = %T, want *ErrUnknownTicker", err)
	}
}

func TestValidateAddressForTicker_KnownTickerDelegates(t *testing.T) {
	if err := ValidateAddressForTicker("arq", realARQGovAddress); err != nil {
		t.Fatalf("ValidateAddressForTicker(\"arq\", real address) = %v, want nil", err)
	}
}

func TestDecodeMoneroBase58_RoundTripLength(t *testing.T) {
	decoded, err := DecodeMoneroBase58(realARQGovAddress)
	if err != nil {
		t.Fatalf("DecodeMoneroBase58: unexpected error: %v", err)
	}
	// 2-byte varint prefix + 32-byte spend key + 32-byte view key + 4-byte checksum = 70.
	if len(decoded) != 70 {
		t.Fatalf("DecodeMoneroBase58(realARQGovAddress): decoded length = %d, want 70", len(decoded))
	}
}
