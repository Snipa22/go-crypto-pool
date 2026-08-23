// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"crypto/sha512"

	"github.com/Snipa22/go-tari-lib/address"
	"github.com/gtank/ristretto255"
)

// realTariTestAddress is direct's copy of solo's identically-named
// test helper (internal/leaflib/solo/address_helper_test.go) --
// deterministically derives a REAL, byte-exact, canonical Tari
// single address from an arbitrary test label, so existing tests can
// keep using short, readable, distinct labels as inputs while every
// login this test package sends over the wire is still a genuinely
// valid Tari address that round-trips through address.Parse --
// required now that session.go's handleLogin calls the real
// ValidateAddressForAlgo(algo, login.Login) on every login. Kept as a
// separate, duplicated file rather than a shared exported helper
// because Go test files cannot easily share code across packages
// without adding a non-test production export purely for tests to
// use -- see solo's copy for the identical real-key-derivation
// rationale (SHA-512 -> uniform scalar -> real ScalarBaseMult point,
// never a fabricated/non-canonical key).
func realTariTestAddress(label string) string {
	sum := sha512.Sum512([]byte(label))
	scalar, err := ristretto255.NewScalar().SetUniformBytes(sum[:])
	if err != nil {
		panic("direct: realTariTestAddress: SetUniformBytes: " + err.Error())
	}
	point := ristretto255.NewElement().ScalarBaseMult(scalar)

	var pubKey address.CompressedPublicKey
	copy(pubKey[:], point.Bytes())

	addr := address.NewSingleAddressInteractiveOnly(pubKey, address.Esmeralda)
	return addr.Base58()
}
