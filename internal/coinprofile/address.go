// Copyright and license: see repository LICENSE (MIT).
package coinprofile

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// checksumSize is the trailing Keccak-256-derived checksum length
// every CryptoNote-family address payload carries (4 bytes), per the
// real cryptonote::get_account_address_as_str implementation shared
// by Monero and every fork in Registry.
const checksumSize = 4

// minPayloadSize is the minimum plausible decoded-address payload
// size: a 1-byte network-tag prefix (the smallest real prefix any
// confirmed coin here uses) + two 32-byte Ed25519/Ristretto255 public
// keys (spend + view) + the 4-byte checksum. Real addresses are
// usually larger (multi-byte prefixes, or an extra 8-byte payment ID
// for integrated addresses), but this is a safe, cheap floor to reject
// obviously-truncated input before doing any real work.
const minPayloadSize = 1 + 32 + 32 + checksumSize

// ValidateAddress verifies that address is a real, checksum-valid
// CryptoNote-family address whose leading network-tag bytes match
// profile.AddressNetworkBytes exactly -- the coin-agnostic replacement
// for the old hardcoded-Monero-only byte check (see
// internal/leaflib/solo/address.go and
// internal/backend/addressmap/addressmap.go's own doc comments for
// where ALGO_RXM's existing, untouched Monero validator lives
// separately from this one).
//
// This intentionally checks ONLY the mainnet standard-address prefix
// (profile.AddressNetworkBytes) -- integrated-address and subaddress
// prefixes are distinct per-coin values this CoinProfile does not
// carry (see that field's own doc comment), matching the brief's
// literal ask for "valid mainnet network byte(s)". A coin's testnet
// addresses are intentionally NOT accepted here, unlike the legacy
// Monero-only validator (internal/leaflib/solo.validateMoneroLoginAddress),
// since none of the new CoinProfile entries have had their testnet
// prefixes verified against a primary source as part of this pass.
func ValidateAddress(profile CoinProfile, address string) error {
	if len(profile.AddressNetworkBytes) == 0 {
		return fmt.Errorf("coinprofile: CoinProfile for %s has no AddressNetworkBytes configured", profile.Ticker)
	}

	decoded, err := DecodeMoneroBase58(address)
	if err != nil {
		return fmt.Errorf("invalid address provided: not a valid %s address (%w)", profile.Name, err)
	}
	if len(decoded) < minPayloadSize {
		return fmt.Errorf("invalid address provided: not a valid %s address (too short)", profile.Name)
	}

	payload := decoded[:len(decoded)-checksumSize]
	wantChecksum := decoded[len(decoded)-checksumSize:]

	h := sha3.NewLegacyKeccak256()
	h.Write(payload)
	gotChecksum := h.Sum(nil)[:checksumSize]
	if !bytes.Equal(gotChecksum, wantChecksum) {
		return fmt.Errorf("invalid address provided: not a valid %s address (bad checksum)", profile.Name)
	}

	if len(payload) < len(profile.AddressNetworkBytes) ||
		!bytes.Equal(payload[:len(profile.AddressNetworkBytes)], profile.AddressNetworkBytes) {
		return fmt.Errorf("invalid address provided: not a valid %s address (unrecognized network byte)", profile.Name)
	}

	return nil
}

// ValidateAddressForTicker resolves ticker via Lookup and delegates to
// ValidateAddress -- convenience wrapper for callers that only have a
// ticker string (e.g. from -coin) rather than an already-resolved
// CoinProfile value.
func ValidateAddressForTicker(ticker, address string) error {
	profile, ok := Lookup(ticker)
	if !ok {
		return &ErrUnknownTicker{Ticker: ticker}
	}
	return ValidateAddress(profile, address)
}
