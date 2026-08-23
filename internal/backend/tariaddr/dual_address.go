// Copyright and license: see repository LICENSE (MIT).
package tariaddr

import (
	"encoding/hex"

	"github.com/mr-tron/base58"
)

// DualAddressInternalSize mirrors TARI_ADDRESS_INTERNAL_DUAL_SIZE:
// network(1) + features(1) + public_view_key(32) +
// public_spend_key(32) + checksum(1).
const DualAddressInternalSize = 67

// MaxEncryptedDataSize mirrors MAX_ENCRYPTED_DATA_SIZE — the max size
// of the memo-field payment-id bytes appended after the two public
// keys.
const MaxEncryptedDataSize = 256

// dualBase58MinSize/dualBase58MaxSize mirror
// INTERNAL_DUAL_BASE58_MIN_SIZE / INTERNAL_DUAL_BASE58_MAX_SIZE.
const (
	dualBase58MinSize = 89
	dualBase58MaxSize = 443
)

// DualAddress is a byte-exact port of
// tari_common_types::tari_address::dual_address::DualAddress.
type DualAddress struct {
	network            Network
	features           Features
	publicViewKey      CompressedPublicKey
	publicSpendKey     CompressedPublicKey
	memoFieldPaymentID []byte
}

// NewDualAddress matches DualAddress::new. memoFieldPaymentID may be
// nil, matching a None payment_id_user_data; if longer than
// MaxEncryptedDataSize it returns ErrPaymentIDTooLarge, exactly as
// the Rust source does before ever setting the PAYMENT_ID feature
// bit.
func NewDualAddress(viewKey, spendKey CompressedPublicKey, network Network, features Features, memoFieldPaymentID []byte) (DualAddress, error) {
	if memoFieldPaymentID != nil {
		if len(memoFieldPaymentID) > MaxEncryptedDataSize {
			return DualAddress{}, ErrPaymentIDTooLarge
		}
		features = features.Combine(FeaturePaymentID)
		data := make([]byte, len(memoFieldPaymentID))
		copy(data, memoFieldPaymentID)
		return DualAddress{network: network, features: features, publicViewKey: viewKey, publicSpendKey: spendKey, memoFieldPaymentID: data}, nil
	}
	return DualAddress{network: network, features: features, publicViewKey: viewKey, publicSpendKey: spendKey}, nil
}

// NewDualAddressWithDefaultFeatures matches
// DualAddress::new_with_default_features.
func NewDualAddressWithDefaultFeatures(viewKey, spendKey CompressedPublicKey, network Network) (DualAddress, error) {
	return NewDualAddress(viewKey, spendKey, network, DefaultFeatures(), nil)
}

// AddMemoFieldPaymentID matches DualAddress::add_memo_field_payment_id.
func (a *DualAddress) AddMemoFieldPaymentID(data []byte) error {
	if len(data) > MaxEncryptedDataSize {
		return ErrPaymentIDTooLarge
	}
	a.features = a.features.Combine(FeaturePaymentID)
	buf := make([]byte, len(data))
	copy(buf, data)
	a.memoFieldPaymentID = buf
	return nil
}

// GetMemoFieldPaymentIDBytes matches
// DualAddress::get_memo_field_payment_id_bytes.
func (a DualAddress) GetMemoFieldPaymentIDBytes() []byte {
	out := make([]byte, len(a.memoFieldPaymentID))
	copy(out, a.memoFieldPaymentID)
	return out
}

// Network matches DualAddress::network.
func (a DualAddress) Network() Network { return a.network }

// Features matches DualAddress::features.
func (a DualAddress) Features() Features { return a.features }

// PublicViewKey matches DualAddress::public_view_key.
func (a DualAddress) PublicViewKey() CompressedPublicKey { return a.publicViewKey }

// PublicSpendKey matches DualAddress::public_spend_key.
func (a DualAddress) PublicSpendKey() CompressedPublicKey { return a.publicSpendKey }

// dualEmojiToBytes matches DualAddress::emoji_to_bytes.
func dualEmojiToBytes(emoji []rune) ([]byte, error) {
	length := len(emoji)
	if length < DualAddressInternalSize || length > DualAddressInternalSize+MaxEncryptedDataSize {
		return nil, ErrInvalidSize
	}
	bytes := make([]byte, 0, DualAddressInternalSize)
	for _, c := range emoji {
		b, ok := ReverseEmoji[c]
		if !ok {
			return nil, ErrInvalidEmoji
		}
		bytes = append(bytes, b)
	}
	return bytes, nil
}

// DualAddressFromEmojiString matches DualAddress::from_emoji_string.
func DualAddressFromEmojiString(emoji string) (DualAddress, error) {
	bytes, err := dualEmojiToBytes([]rune(emoji))
	if err != nil {
		return DualAddress{}, err
	}
	return DualAddressFromBytes(bytes)
}

// EmojiString matches DualAddress::to_emoji_string.
func (a DualAddress) EmojiString() string {
	bytes := a.Bytes()
	out := make([]rune, len(bytes))
	for i, b := range bytes {
		out[i] = Emoji[b]
	}
	return string(out)
}

// DualAddressFromBytes matches DualAddress::from_bytes.
func DualAddressFromBytes(b []byte) (DualAddress, error) {
	length := len(b)
	if length < DualAddressInternalSize || length > DualAddressInternalSize+MaxEncryptedDataSize {
		return DualAddress{}, ErrInvalidSize
	}
	if _, err := ValidateChecksum(b); err != nil {
		return DualAddress{}, ErrInvalidChecksum
	}
	network, err := NetworkFromByte(b[0])
	if err != nil {
		return DualAddress{}, ErrInvalidNetwork
	}
	features, ok := featuresFromBits(b[1])
	if !ok {
		return DualAddress{}, ErrInvalidFeatures
	}
	viewKey, err := PublicKeyFromCanonicalBytes(b[2:34])
	if err != nil {
		return DualAddress{}, ErrCannotRecoverPublicKey
	}
	spendKey, err := PublicKeyFromCanonicalBytes(b[34:66])
	if err != nil {
		return DualAddress{}, ErrCannotRecoverPublicKey
	}
	memo := make([]byte, length-1-66)
	copy(memo, b[66:length-1])
	return DualAddress{
		network:            network,
		features:           features,
		publicViewKey:      viewKey,
		publicSpendKey:     spendKey,
		memoFieldPaymentID: memo,
	}, nil
}

// Bytes matches DualAddress::to_vec.
func (a DualAddress) Bytes() []byte {
	length := DualAddressInternalSize + len(a.memoFieldPaymentID)
	buf := make([]byte, length)
	buf[0] = a.network.AsByte()
	buf[1] = a.features.AsU8()
	copy(buf[2:34], a.publicViewKey.Bytes())
	copy(buf[34:66], a.publicSpendKey.Bytes())
	copy(buf[66:length-1], a.memoFieldPaymentID)
	buf[length-1] = ComputeChecksum(buf[0 : length-1])
	return buf
}

// DualAddressFromBase58 matches DualAddress::from_base58.
func DualAddressFromBase58(s string) (DualAddress, error) {
	if len(s) < dualBase58MinSize || len(s) > dualBase58MaxSize {
		return DualAddress{}, ErrInvalidSize
	}
	networkStr, featuresStr, rest, err := splitNetworkFeaturesRest(s)
	if err != nil {
		return DualAddress{}, err
	}
	networkBytes, err := decodeBytes(networkStr)
	if err != nil {
		return DualAddress{}, ErrCannotRecoverNetwork
	}
	featuresBytes, err := decodeBytes(featuresStr)
	if err != nil {
		return DualAddress{}, ErrCannotRecoverFeature
	}
	restBytes, err := decodeBytes(rest)
	if err != nil {
		return DualAddress{}, ErrCannotRecoverPublicKey
	}
	result := append(append(networkBytes, featuresBytes...), restBytes...)
	return DualAddressFromBytes(result)
}

// Base58 matches DualAddress::to_base58.
func (a DualAddress) Base58() string {
	bytes := a.Bytes()
	network := encodeSingleByte(bytes[0])
	features := encodeSingleByte(bytes[1])
	rest := base58.Encode(bytes[2:])
	return network + features + rest
}

// Hex matches DualAddress::to_hex.
func (a DualAddress) Hex() string { return hex.EncodeToString(a.Bytes()) }

// DualAddressFromHex matches DualAddress::from_hex.
func DualAddressFromHex(s string) (DualAddress, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return DualAddress{}, ErrCannotRecoverPublicKey
	}
	return DualAddressFromBytes(buf)
}
