// Copyright and license: see repository LICENSE (MIT).
package tariaddr

// Features mirrors tari_common_types::tari_address::TariAddressFeatures
// (tari_address/mod.rs), a bitflags!-defined u8 wrapper. The bit
// layout is exactly the real one:
//
//	PAYMENT_ID  = 0b0000_0100
//	INTERACTIVE = 0b0000_0010
//	ONE_SIDED   = 0b0000_0001
type Features uint8

const (
	// FeaturePaymentID forces a transaction to include the
	// following payment id, matching
	// TariAddressFeatures::PAYMENT_ID.
	FeaturePaymentID Features = 0b0000_0100
	// FeatureInteractive matches TariAddressFeatures::INTERACTIVE.
	FeatureInteractive Features = 0b0000_0010
	// FeatureOneSided is a one-sided payment, matching
	// TariAddressFeatures::ONE_SIDED.
	FeatureOneSided Features = 0b0000_0001

	// validFeatureBits is every bit bitflags! actually defines;
	// TariAddressFeatures::from_bits (which
	// SingleAddress::from_bytes/DualAddress::from_bytes call)
	// rejects any input byte with a bit set outside this mask,
	// exactly like the derived bitflags! from_bits.
	validFeatureBits = FeaturePaymentID | FeatureInteractive | FeatureOneSided
)

// FeaturesInteractiveOnly matches
// TariAddressFeatures::create_interactive_only().
func FeaturesInteractiveOnly() Features { return FeatureInteractive }

// FeaturesOneSidedOnly matches
// TariAddressFeatures::create_one_sided_only().
func FeaturesOneSidedOnly() Features { return FeatureOneSided }

// FeaturesInteractiveAndOneSided matches
// TariAddressFeatures::create_interactive_and_one_sided().
func FeaturesInteractiveAndOneSided() Features { return FeatureInteractive | FeatureOneSided }

// DefaultFeatures matches impl Default for TariAddressFeatures,
// which is INTERACTIVE | ONE_SIDED.
func DefaultFeatures() Features { return FeatureInteractive | FeatureOneSided }

// AsU8 matches TariAddressFeatures::as_u8.
func (f Features) AsU8() uint8 { return uint8(f) }

// Contains reports whether f has every bit set in other, matching
// bitflags!'s generated Flags::contains.
func (f Features) Contains(other Features) bool { return f&other == other }

// Combine matches TariAddressFeatures::combine_features.
func (f Features) Combine(other Features) Features { return f | other }

// featuresFromBits mirrors bitflags!'s derived
// TariAddressFeatures::from_bits: it succeeds only if v has no bits
// set outside the known flag bits, returning (0, false) otherwise —
// the same validity rule
// SingleAddress::from_bytes/DualAddress::from_bytes rely on to
// produce TariAddressError::InvalidFeatures.
func featuresFromBits(v byte) (Features, bool) {
	if Features(v)&^validFeatureBits != 0 {
		return 0, false
	}
	return Features(v), true
}

// String matches impl fmt::Display for TariAddressFeatures.
func (f Features) String() string {
	s := ""
	if f.Contains(FeatureInteractive) {
		s += "Interactive,"
	}
	if f.Contains(FeatureOneSided) {
		s += "One-sided,"
	}
	if f.Contains(FeaturePaymentID) {
		s += "Payment-id,"
	}
	return s
}
