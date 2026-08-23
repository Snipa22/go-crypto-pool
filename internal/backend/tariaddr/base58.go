// Copyright and license: see repository LICENSE (MIT).
package tariaddr

import "github.com/mr-tron/base58"

// This file factors out the base58 network/features/rest splitting
// logic that appears three times, byte-for-byte identical, in the
// real Rust source: TariAddress::from_base58/to_base58
// (tari_address/mod.rs), SingleAddress::from_base58/to_base58
// (single_address.rs), and DualAddress::from_base58/to_base58
// (dual_address.rs). Every one of those Rust functions:
//
//   - encodes byte 0 (network) and byte 1 (features) as their OWN,
//     independent base58 strings and concatenates them with the
//     base58 encoding of the remaining bytes, rather than base58-
//     encoding the whole buffer in one pass; and
//   - decodes by literally splitting the input string at
//     "first 2 characters" / "first 1 character of those 2", base58-
//     decoding each of the three pieces separately, and
//     concatenating the results.
//
// This only round-trips correctly because Network's real byte values
// (0x00, 0x01, 0x02, 0x10, 0x24, 0x26) and every valid
// TariAddressFeatures byte value (0-7) are all < 58, so bs58 always
// encodes each of them as exactly one base58 character — see
// encodeSingleByte's doc comment.

// encodeSingleByte base58-encodes a single byte, matching Rust's
// bs58::encode(&[byte]).into_string(). Bitcoin-alphabet base58
// encodes any value in [0, 58) as exactly one character (with 0
// specifically encoding to the alphabet's zero digit '1' via the
// standard leading-zero-byte rule), which is exactly the byte range
// Network's and TariAddressFeatures' real values occupy — see this
// file's doc comment.
func encodeSingleByte(b byte) string {
	return base58.Encode([]byte{b})
}

// decodeToSingleByte base58-decodes a string that is expected to
// decode to exactly one byte, matching the network/features half of
// TariAddress::from_base58 (and the Single/Dual equivalents), which
// simply appends whatever bs58::decode produces without itself
// re-checking the length — a malformed 2+-byte decode would still be
// concatenated with the rest of the buffer and later rejected by
// the overall length check in FromBytes.
func decodeBytes(s string) ([]byte, error) {
	return base58.Decode(s)
}

// splitNetworkFeaturesRest mirrors the exact split every from_base58
// implementation performs:
//
//	let (first, rest) = s.split_at_checked(2)...
//	let (network, features) = first.split_at_checked(1)...
//
// returning ErrInvalidCharacter if s has fewer than 2 bytes (mirroring
// split_at_checked returning None).
func splitNetworkFeaturesRest(s string) (network, features, rest string, err error) {
	if len(s) < 2 {
		return "", "", "", ErrInvalidCharacter
	}
	first := s[:2]
	rest = s[2:]
	network, features = first[:1], first[1:2]
	return network, features, rest, nil
}
