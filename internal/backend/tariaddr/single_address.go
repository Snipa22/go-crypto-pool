// Copyright and license: see repository LICENSE (MIT).
package tariaddr

import (
	"encoding/hex"

	"github.com/mr-tron/base58"
)

// SingleAddressInternalSize mirrors
// TARI_ADDRESS_INTERNAL_SINGLE_SIZE: network(1) + features(1) +
// public_spend_key(32) + checksum(1).
const SingleAddressInternalSize = 35

// singleBase58MinSize/singleBase58MaxSize mirror
// INTERNAL_SINGLE_MIN_BASE58_SIZE / INTERNAL_SINGLE_MAX_BASE58_SIZE:
// depending on the leading-zero-byte content of the 35-byte buffer,
// its base58 encoding can be 45, 46, 47 or 48 characters.
const (
	singleBase58MinSize = 45
	singleBase58MaxSize = 48
)

// SingleAddress is a byte-exact port of
// tari_common_types::tari_address::single_address::SingleAddress.
type SingleAddress struct {
	network        Network
	features       Features
	publicSpendKey CompressedPublicKey
}

// NewSingleAddress matches SingleAddress::new.
func NewSingleAddress(spendKey CompressedPublicKey, network Network, features Features) SingleAddress {
	return SingleAddress{network: network, features: features, publicSpendKey: spendKey}
}

// NewSingleAddressInteractiveOnly matches
// SingleAddress::new_with_interactive_only.
func NewSingleAddressInteractiveOnly(spendKey CompressedPublicKey, network Network) SingleAddress {
	return NewSingleAddress(spendKey, network, FeaturesInteractiveOnly())
}

// Network matches SingleAddress::network.
func (a SingleAddress) Network() Network { return a.network }

// Features matches SingleAddress::features.
func (a SingleAddress) Features() Features { return a.features }

// PublicSpendKey matches SingleAddress::public_spend_key.
func (a SingleAddress) PublicSpendKey() CompressedPublicKey { return a.publicSpendKey }

// singleEmojiToBytes matches SingleAddress::emoji_to_bytes.
func singleEmojiToBytes(emoji []rune) ([]byte, error) {
	if len(emoji) != SingleAddressInternalSize {
		return nil, ErrInvalidSize
	}
	bytes := make([]byte, 0, SingleAddressInternalSize)
	for _, c := range emoji {
		b, ok := ReverseEmoji[c]
		if !ok {
			return nil, ErrInvalidEmoji
		}
		bytes = append(bytes, b)
	}
	return bytes, nil
}

// SingleAddressFromEmojiString matches
// SingleAddress::from_emoji_string.
func SingleAddressFromEmojiString(emoji string) (SingleAddress, error) {
	bytes, err := singleEmojiToBytes([]rune(emoji))
	if err != nil {
		return SingleAddress{}, err
	}
	return SingleAddressFromBytes(bytes)
}

// EmojiString matches SingleAddress::to_emoji_string.
func (a SingleAddress) EmojiString() string {
	bytes := a.Bytes()
	out := make([]rune, len(bytes))
	for i, b := range bytes {
		out[i] = Emoji[b]
	}
	return string(out)
}

// SingleAddressFromBytes matches SingleAddress::from_bytes.
func SingleAddressFromBytes(b []byte) (SingleAddress, error) {
	if len(b) != SingleAddressInternalSize {
		return SingleAddress{}, ErrInvalidSize
	}
	if _, err := ValidateChecksum(b); err != nil {
		return SingleAddress{}, ErrInvalidChecksum
	}
	network, err := NetworkFromByte(b[0])
	if err != nil {
		return SingleAddress{}, ErrInvalidNetwork
	}
	features, ok := featuresFromBits(b[1])
	if !ok {
		return SingleAddress{}, ErrInvalidFeatures
	}
	spendKey, err := PublicKeyFromCanonicalBytes(b[2:34])
	if err != nil {
		return SingleAddress{}, ErrCannotRecoverPublicKey
	}
	return SingleAddress{network: network, features: features, publicSpendKey: spendKey}, nil
}

// Bytes matches SingleAddress::to_vec.
func (a SingleAddress) Bytes() []byte {
	buf := make([]byte, SingleAddressInternalSize)
	buf[0] = a.network.AsByte()
	buf[1] = a.features.AsU8()
	copy(buf[2:34], a.publicSpendKey.Bytes())
	buf[34] = ComputeChecksum(buf[0:34])
	return buf
}

// SingleAddressFromBase58 matches SingleAddress::from_base58.
func SingleAddressFromBase58(s string) (SingleAddress, error) {
	if len(s) < singleBase58MinSize || len(s) > singleBase58MaxSize {
		return SingleAddress{}, ErrInvalidSize
	}
	networkStr, featuresStr, rest, err := splitNetworkFeaturesRest(s)
	if err != nil {
		return SingleAddress{}, err
	}
	networkBytes, err := decodeBytes(networkStr)
	if err != nil {
		return SingleAddress{}, ErrCannotRecoverNetwork
	}
	featuresBytes, err := decodeBytes(featuresStr)
	if err != nil {
		return SingleAddress{}, ErrCannotRecoverFeature
	}
	restBytes, err := decodeBytes(rest)
	if err != nil {
		return SingleAddress{}, ErrCannotRecoverPublicKey
	}
	result := append(append(networkBytes, featuresBytes...), restBytes...)
	return SingleAddressFromBytes(result)
}

// Base58 matches SingleAddress::to_base58.
func (a SingleAddress) Base58() string {
	bytes := a.Bytes()
	network := encodeSingleByte(bytes[0])
	features := encodeSingleByte(bytes[1])
	rest := base58.Encode(bytes[2:])
	return network + features + rest
}

// Hex matches SingleAddress::to_hex.
func (a SingleAddress) Hex() string { return hex.EncodeToString(a.Bytes()) }

// SingleAddressFromHex matches SingleAddress::from_hex.
func SingleAddressFromHex(s string) (SingleAddress, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return SingleAddress{}, ErrCannotRecoverPublicKey
	}
	return SingleAddressFromBytes(buf)
}
