// Copyright and license: see repository LICENSE (MIT).

// Package tariaddr is a byte-exact Go port of the real Tari Base Layer
// "tari_address" implementation (tari/base_layer/common_types/src/
// tari_address/{mod,dual_address,single_address}.rs), its DammSum
// checksum helper (tari/base_layer/common_types/src/dammsum.rs), its
// emoji table (tari/base_layer/common_types/src/emoji.rs), and the
// subset of tari/common/src/configuration/network.rs needed to encode
// and decode a TariAddress's network byte.
//
// This package is deliberately standalone: it does not depend on any
// Tari crate and reimplements every byte-level rule (sizes, checksum
// polynomial, base58 splitting, emoji dictionary, network byte
// values, TariAddressFeatures bit layout) directly from the extracted
// Rust source rather than approximating it. The one place this port
// cannot be a literal transliteration is public-key canonicity:
// CompressedPublicKey::from_canonical_bytes in the real Rust decodes
// a compressed Ristretto255 point and rejects non-canonical
// encodings (RFC 9496 decode rules) — this package reproduces that
// exact check using github.com/gtank/ristretto255 (built on
// filippo.io/edwards25519), a real, independent Ristretto255
// implementation, rather than skipping validation or inventing a
// weaker substitute.
//
// Supported encodings, matching the Rust API 1:1:
//   - TariAddress.Bytes()/FromBytes (internal binary representation)
//   - TariAddress.Base58()/FromBase58 (network+features+rest base58,
//     split exactly like Rust's split_at_checked(1)/(2))
//   - TariAddress.Hex()/FromHex
//   - TariAddress.EmojiString()/FromEmojiString (33-char single / 67+
//     char dual emoji IDs using the real 256-entry EMOJI table)
//   - ParseTariAddress (FromStr equivalent: try emoji, then base58,
//     then hex, exactly mirroring impl FromStr for TariAddress)
package tariaddr
