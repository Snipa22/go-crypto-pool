// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"crypto/sha512"

	"github.com/Snipa22/go-tari-lib/address"
	"github.com/gtank/ristretto255"
)

// realTariTestAddress deterministically derives a REAL, byte-exact,
// canonical Tari single address from an arbitrary test label, so
// existing tests can keep using short, readable, distinct labels
// ("addr-one", "flood-addr-3", ...) as inputs while every login this
// test package sends over the wire is still a genuinely valid Tari
// address that round-trips through address.Parse -- required now
// that session.go's handleLogin calls the real
// ValidateAddressForAlgo(algo, login.Login) on every login (see
// address.go).
//
// This is NOT a cryptographic key-generation shortcut used anywhere
// outside tests: label is SHA-512-hashed into 64 bytes, which
// ristretto255.Scalar.SetUniformBytes reduces into a uniformly
// distributed scalar (mirroring a real wallet's private-key
// generation, just deterministic instead of CSPRNG-sourced for test
// reproducibility), and the corresponding PUBLIC point
// (ScalarBaseMult) is what actually gets embedded in the address --
// this never fabricates a public key that doesn't decode to a real
// canonical Ristretto255 group element, so it cannot round-trip a bug
// that only a non-canonical/malformed key would catch.
func realTariTestAddress(label string) string {
	sum := sha512.Sum512([]byte(label))
	scalar, err := ristretto255.NewScalar().SetUniformBytes(sum[:])
	if err != nil {
		// sha512 always yields exactly 64 bytes; SetUniformBytes can
		// only fail on a wrong-length input.
		panic("solo: realTariTestAddress: SetUniformBytes: " + err.Error())
	}
	point := ristretto255.NewElement().ScalarBaseMult(scalar)

	var pubKey address.CompressedPublicKey
	copy(pubKey[:], point.Bytes())

	addr := address.NewSingleAddressInteractiveOnly(pubKey, address.Esmeralda)
	return addr.Base58()
}
