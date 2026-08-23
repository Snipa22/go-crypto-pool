// Copyright and license: see repository LICENSE (MIT).
package tariaddr

import "errors"

// TariAddressError values mirror, one-for-one, the variants of Rust's
// tari_common_types::tari_address::TariAddressError enum
// (tari_address/mod.rs). Callers that need to distinguish a specific
// failure mode can compare with errors.Is against these sentinels.
var (
	ErrInvalidSize            = errors.New("tariaddr: invalid size")
	ErrInvalidNetwork         = errors.New("tariaddr: invalid network")
	ErrInvalidFeatures        = errors.New("tariaddr: invalid features")
	ErrInvalidChecksum        = errors.New("tariaddr: invalid checksum")
	ErrInvalidEmoji           = errors.New("tariaddr: invalid emoji character")
	ErrInvalidCharacter       = errors.New("tariaddr: invalid text character")
	ErrCannotRecoverPublicKey = errors.New("tariaddr: cannot recover public key")
	ErrCannotRecoverNetwork   = errors.New("tariaddr: cannot recover network")
	ErrCannotRecoverFeature   = errors.New("tariaddr: cannot recover feature")
	ErrInvalidAddressString   = errors.New("tariaddr: could not recover TariAddress from string")
	ErrPaymentIDTooLarge      = errors.New("tariaddr: too large payment_id")
	ErrPaymentIDNotSupported  = errors.New("tariaddr: payment_id not supported on single addresses")
)

// creationError mirrors TariAddressError::CreationError(String), which
// carries a dynamic message in the real Rust enum.
type creationError struct {
	msg string
}

func (e *creationError) Error() string { return "tariaddr: could not create TariAddress: " + e.msg }

func newCreationError(msg string) error { return &creationError{msg: msg} }
