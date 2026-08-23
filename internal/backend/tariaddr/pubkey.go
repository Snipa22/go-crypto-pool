// Copyright and license: see repository LICENSE (MIT).
package tariaddr

import "github.com/gtank/ristretto255"

// PublicKeySize is the size, in bytes, of a compressed public key
// inside a TariAddress — 32 bytes, matching
// tari_crypto::ristretto::RistrettoPublicKey (a compressed
// Ristretto255 point) via ByteArray::as_bytes().len().
const PublicKeySize = 32

// CompressedPublicKey is a 32-byte compressed Ristretto255 public
// key, matching tari_common_types::types::CompressedPublicKey (an
// alias for tari_crypto's RistrettoPublicKey/CompressedPublicKey,
// itself a wrapper around curve25519-dalek's CompressedRistretto).
//
// The zero value is NOT a valid public key encoding (an all-zero
// 32-byte string does not decode to a Ristretto255 group element —
// see FromCanonicalBytes) but is kept as the type's zero value only
// to mirror #[derive(Default)] on the Rust struct, which likewise
// produces a CompressedPublicKey that is only ever valid as a
// placeholder (TariAddress::default() itself is never a spendable
// address).
type CompressedPublicKey [PublicKeySize]byte

// Bytes returns the 32-byte compressed encoding, matching
// ByteArray::as_bytes().
func (k CompressedPublicKey) Bytes() []byte {
	b := make([]byte, PublicKeySize)
	copy(b, k[:])
	return b
}

// PublicKeyFromCanonicalBytes mirrors
// CompressedPublicKey::from_canonical_bytes: it requires exactly 32
// bytes that form the CANONICAL encoding of a valid Ristretto255
// group element (RFC 9496 §4.3.1's Decode operation), rejecting
// malformed points and non-canonical field-element encodings alike —
// exactly the check the real Rust performs via
// curve25519-dalek's CompressedRistretto::decompress(), which bakes
// canonicity checking into Ristretto255 decoding itself.
//
// On success, the returned CompressedPublicKey stores the original
// input bytes verbatim: because the check above only ever accepts
// bytes that are already the canonical encoding of the decoded
// point, the input and the "re-encoded" point are byte-identical, so
// no re-encode-and-compare step is needed (unlike a scheme where
// non-canonical inputs could decode successfully to a different
// canonical encoding).
func PublicKeyFromCanonicalBytes(b []byte) (CompressedPublicKey, error) {
	var out CompressedPublicKey
	if len(b) != PublicKeySize {
		return out, ErrCannotRecoverPublicKey
	}
	if _, err := new(ristretto255.Element).SetCanonicalBytes(b); err != nil {
		return out, ErrCannotRecoverPublicKey
	}
	copy(out[:], b)
	return out, nil
}
