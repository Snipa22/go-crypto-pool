// Copyright and license: see repository LICENSE (MIT).
package tariaddr

// This file is a byte-exact port of
// tari/base_layer/common_types/src/dammsum.rs: the DammSum checksum
// algorithm Tari uses to protect every encoded TariAddress against
// single substitutions and transpositions.

// ChecksumBytes is the number of bytes used for the checksum, mirroring
// dammsum::CHECKSUM_BYTES.
const ChecksumBytes = 1

// checksumCoefficients and checksumMask reproduce dammsum.rs's
// COEFFICIENTS = [4, 3, 1] and the MASK computed from them for a
// dictionary size of 2^8 == 256:
//
//	mask = 1 + 2^4 + 2^3 + 2^1 = 1 + 16 + 8 + 2 = 27
//
// computed here as a constant instead of a lazily-initialized value,
// since Go has no analogue to needing runtime overflow checks for a
// fixed-width literal.
const checksumMask byte = 27

// ComputeChecksum computes the DammSum checksum for data, matching
// dammsum::compute_checksum byte-for-byte.
func ComputeChecksum(data []byte) byte {
	var result byte
	for _, digit := range data {
		result ^= digit // add
		overflow := result&(1<<7) != 0
		result <<= 1 // double
		if overflow {
			result ^= checksumMask // reduce
		}
	}
	return result
}

// ValidateChecksum mirrors dammsum::validate_checksum: it treats the
// last byte of data as a DammSum checksum of the preceding bytes and,
// if valid, returns the data without that trailing checksum byte.
func ValidateChecksum(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, ErrInvalidChecksum // dammsum::ChecksumError::InputDataTooShort
	}
	if ComputeChecksum(data) != 0 {
		return nil, ErrInvalidChecksum
	}
	return data[:len(data)-1], nil
}
