// Copyright and license: see repository LICENSE (MIT).
package tariaddr

import (
	"encoding/hex"
	"strings"

	"github.com/mr-tron/base58"
)

// singleBase58MinSizeForParse mirrors
// TariAddress::from_base58's own INTERNAL_SINGLE_MIN_BASE58_SIZE
// length check (the top-level TariAddress::from_base58 checks
// against the single-address minimum, not the dual one, before
// delegating the real size decision to TariAddress::from_bytes).
const singleBase58MinSizeForParse = INTERNAL_SINGLE_MIN_BASE58_SIZE

// These four constants mirror mod.rs's private module-level
// constants used only by TariAddress::from_base58/to_base58 (the
// Single/Dual types have their own byte-identical copies, ported
// separately in single_address.go/dual_address.go — see mod.rs
// itself defining them once and both dual_address.rs/
// single_address.rs importing them from crate::tari_address).
const (
	INTERNAL_SINGLE_MIN_BASE58_SIZE = 45
)

// Kind distinguishes the two TariAddress variants, matching the
// Dual/Single arms of Rust's `pub enum TariAddress`.
type Kind int

const (
	// KindDual matches TariAddress::Dual.
	KindDual Kind = iota
	// KindSingle matches TariAddress::Single.
	KindSingle
)

// Address is a byte-exact port of
// tari_common_types::tari_address::TariAddress — a tagged union of a
// DualAddress or a SingleAddress. It is deliberately a struct (not a
// Go interface) so its zero value is well-defined and matches
// impl Default for TariAddress (Self::Dual(Box::default())).
type Address struct {
	kind   Kind
	dual   DualAddress
	single SingleAddress
}

// Kind reports whether the address is dual or single.
func (a Address) Kind() Kind { return a.kind }

// AsDual returns the underlying DualAddress and true if a.Kind() ==
// KindDual.
func (a Address) AsDual() (DualAddress, bool) { return a.dual, a.kind == KindDual }

// AsSingle returns the underlying SingleAddress and true if a.Kind()
// == KindSingle.
func (a Address) AsSingle() (SingleAddress, bool) { return a.single, a.kind == KindSingle }

// NewDual matches TariAddress::new_dual_address.
func NewDual(viewKey, spendKey CompressedPublicKey, network Network, features Features, memoFieldPaymentID []byte) (Address, error) {
	d, err := NewDualAddress(viewKey, spendKey, network, features, memoFieldPaymentID)
	if err != nil {
		return Address{}, err
	}
	return Address{kind: KindDual, dual: d}, nil
}

// NewSingle matches TariAddress::new_single_address.
func NewSingle(spendKey CompressedPublicKey, network Network, features Features) Address {
	return Address{kind: KindSingle, single: NewSingleAddress(spendKey, network, features)}
}

// NewDualWithDefaultFeatures matches
// TariAddress::new_dual_address_with_default_features.
func NewDualWithDefaultFeatures(viewKey, spendKey CompressedPublicKey, network Network) (Address, error) {
	d, err := NewDualAddressWithDefaultFeatures(viewKey, spendKey, network)
	if err != nil {
		return Address{}, err
	}
	return Address{kind: KindDual, dual: d}, nil
}

// NewSingleInteractiveOnly matches
// TariAddress::new_single_address_with_interactive_only.
func NewSingleInteractiveOnly(spendKey CompressedPublicKey, network Network) Address {
	return Address{kind: KindSingle, single: NewSingleAddressInteractiveOnly(spendKey, network)}
}

// Network matches TariAddress::network.
func (a Address) Network() Network {
	if a.kind == KindDual {
		return a.dual.Network()
	}
	return a.single.Network()
}

// Features matches TariAddress::features.
func (a Address) Features() Features {
	if a.kind == KindDual {
		return a.dual.Features()
	}
	return a.single.Features()
}

// PublicViewKey matches TariAddress::public_view_key: returns
// (key, true) for a dual address, (zero, false) for single, exactly
// like the Rust Option<&CompressedPublicKey>.
func (a Address) PublicViewKey() (CompressedPublicKey, bool) {
	if a.kind == KindDual {
		return a.dual.PublicViewKey(), true
	}
	return CompressedPublicKey{}, false
}

// PublicSpendKey matches TariAddress::public_spend_key.
func (a Address) PublicSpendKey() CompressedPublicKey {
	if a.kind == KindDual {
		return a.dual.PublicSpendKey()
	}
	return a.single.PublicSpendKey()
}

// CommsPublicKey matches TariAddress::comms_public_key (always the
// spend key, for both variants).
func (a Address) CommsPublicKey() CompressedPublicKey { return a.PublicSpendKey() }

// GetSize matches TariAddress::get_size.
func (a Address) GetSize() int {
	if a.kind == KindDual {
		if a.dual.Features().Contains(FeaturePaymentID) {
			return len(a.dual.Bytes())
		}
		return DualAddressInternalSize
	}
	return SingleAddressInternalSize
}

// GetMemoFieldPaymentIDBytes matches
// TariAddress::get_memo_field_payment_id_bytes.
func (a Address) GetMemoFieldPaymentIDBytes() []byte {
	if a.kind == KindDual {
		return a.dual.GetMemoFieldPaymentIDBytes()
	}
	return []byte{}
}

// WithMemoFieldPaymentID matches TariAddress::with_memo_field_payment_id.
func (a Address) WithMemoFieldPaymentID(data []byte) (Address, error) {
	if a.kind != KindDual {
		return Address{}, ErrPaymentIDNotSupported
	}
	d := a.dual
	if err := d.AddMemoFieldPaymentID(data); err != nil {
		return Address{}, err
	}
	return Address{kind: KindDual, dual: d}, nil
}

// CalculateChecksum matches TariAddress::calculate_checksum.
func (a Address) CalculateChecksum() byte {
	b := a.Bytes()
	return b[len(b)-1]
}

// Bytes matches TariAddress::to_vec.
func (a Address) Bytes() []byte {
	if a.kind == KindDual {
		return a.dual.Bytes()
	}
	return a.single.Bytes()
}

// FromBytes matches TariAddress::from_bytes.
func FromBytes(b []byte) (Address, error) {
	if !(len(b) == SingleAddressInternalSize ||
		(len(b) >= DualAddressInternalSize && len(b) <= DualAddressInternalSize+MaxEncryptedDataSize)) {
		return Address{}, ErrInvalidSize
	}
	if len(b) == SingleAddressInternalSize {
		s, err := SingleAddressFromBytes(b)
		if err != nil {
			return Address{}, err
		}
		return Address{kind: KindSingle, single: s}, nil
	}
	d, err := DualAddressFromBytes(b)
	if err != nil {
		return Address{}, err
	}
	return Address{kind: KindDual, dual: d}, nil
}

// emojiToBytes matches TariAddress::emoji_to_bytes: it dispatches on
// the emoji string's character count, exactly like the Rust source
// (a single address's emoji string always has exactly
// TARI_ADDRESS_INTERNAL_SINGLE_SIZE == 35 characters; anything else
// is treated as a dual address's emoji string, whose own length
// check happens inside dualEmojiToBytes).
func emojiToBytes(emoji string) ([]byte, error) {
	runes := []rune(emoji)
	if len(runes) == SingleAddressInternalSize {
		return singleEmojiToBytes(runes)
	}
	return dualEmojiToBytes(runes)
}

// FromEmojiString matches TariAddress::from_emoji_string.
func FromEmojiString(emoji string) (Address, error) {
	bytes, err := emojiToBytes(emoji)
	if err != nil {
		return Address{}, err
	}
	return FromBytes(bytes)
}

// EmojiString matches TariAddress::to_emoji_string.
func (a Address) EmojiString() string {
	if a.kind == KindDual {
		return a.dual.EmojiString()
	}
	return a.single.EmojiString()
}

// FromBase58 matches TariAddress::from_base58.
func FromBase58(s string) (Address, error) {
	if len(s) < singleBase58MinSizeForParse {
		return Address{}, ErrInvalidSize
	}
	networkStr, featuresStr, rest, err := splitNetworkFeaturesRest(s)
	if err != nil {
		return Address{}, err
	}
	networkBytes, err := decodeBytes(networkStr)
	if err != nil {
		return Address{}, ErrCannotRecoverNetwork
	}
	featuresBytes, err := decodeBytes(featuresStr)
	if err != nil {
		return Address{}, ErrCannotRecoverFeature
	}
	restBytes, err := decodeBytes(rest)
	if err != nil {
		return Address{}, ErrCannotRecoverPublicKey
	}
	result := append(append(networkBytes, featuresBytes...), restBytes...)
	return FromBytes(result)
}

// Base58 matches TariAddress::to_base58.
func (a Address) Base58() string {
	bytes := a.Bytes()
	network := encodeSingleByte(bytes[0])
	features := encodeSingleByte(bytes[1])
	rest := base58.Encode(bytes[2:])
	return network + features + rest
}

// Hex matches TariAddress::to_hex.
func (a Address) Hex() string { return hex.EncodeToString(a.Bytes()) }

// FromHex matches TariAddress::from_hex.
func FromHex(s string) (Address, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return Address{}, ErrCannotRecoverPublicKey
	}
	return FromBytes(buf)
}

// Parse matches `impl FromStr for TariAddress`: it tries the emoji
// encoding first (after trimming whitespace and stripping '|'
// separators, exactly like the Rust source's
// key.trim().replace('|', "")), then base58, then hex, returning
// ErrInvalidAddressString only if all three fail.
func Parse(s string) (Address, error) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(s), "|", "")
	if a, err := FromEmojiString(cleaned); err == nil {
		return a, nil
	}
	if a, err := FromBase58(s); err == nil {
		return a, nil
	}
	if a, err := FromHex(s); err == nil {
		return a, nil
	}
	return Address{}, ErrInvalidAddressString
}

// String matches `impl Display for TariAddress` (which writes the
// emoji string).
func (a Address) String() string { return a.EmojiString() }

// CombineAddresses matches TariAddress::combine_addresses.
func CombineAddresses(one, two Address) (Address, error) {
	if one.PublicSpendKey() != two.PublicSpendKey() {
		return Address{}, newCreationError("Public keys do not match")
	}
	if one.Network() != two.Network() {
		return Address{}, newCreationError("Networks do not match")
	}
	if oneDual, oneIsDual := one.AsDual(); oneIsDual {
		if twoDual, twoIsDual := two.AsDual(); twoIsDual {
			if oneDual.PublicViewKey() != twoDual.PublicViewKey() {
				return Address{}, newCreationError("View keys do not match")
			}
		}
	}

	if oneDual, ok := one.AsDual(); ok {
		return NewDual(oneDual.PublicViewKey(), oneDual.PublicSpendKey(), one.Network(), one.Features().Combine(two.Features()), nil)
	}
	if twoDual, ok := two.AsDual(); ok {
		return NewDual(twoDual.PublicViewKey(), one.PublicSpendKey(), one.Network(), one.Features().Combine(two.Features()), nil)
	}
	return NewSingle(one.PublicSpendKey(), one.Network(), one.Features().Combine(two.Features())), nil
}
