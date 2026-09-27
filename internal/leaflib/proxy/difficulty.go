// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"errors"

	"github.com/holiman/uint256"
)

// errHashIsZero mirrors the real "divide by zero has no sound
// difficulty" guard already used for RXT (internal/leaflib/solo/
// rxt.go's errRXTHashIsZero) — an all-zero hash never legitimately
// occurs from a real RandomX computation and must be rejected as an
// error, not silently treated as an infinite/maximum difficulty.
var errHashIsZero = errors.New("proxy: hash is all-zero, cannot derive a difficulty (division by zero)")

// littleEndianDifficulty computes a RandomX/CryptoNote-family PoW
// hash's difficulty using the same well-known, universal
// Cryptonote-derived formula already used for Tari's RXT in this
// codebase (internal/leaflib/solo/rxt.go's
// rxtLittleEndianDifficulty): interpret the 32-byte hash as a
// LITTLE-ENDIAN unsigned 256-bit integer, then
// difficulty = floor(2^256-1 / hash), clamped to uint64. This is the
// real, standard relationship between a CryptoNote/RandomX PoW hash
// and its difficulty (Monero's own check_hash is mathematically
// equivalent: it multiplies the little-endian hash by the target
// difficulty and checks the high 64 bits are zero, i.e.
// hash * difficulty < 2^256, i.e. difficulty <= 2^256/hash) — RXT and
// XMR-family RandomX share the exact same target/difficulty
// relationship, they just differ in which bytes get hashed and with
// which seed (that part is genuinely different, and IS its own
// distinct code path — see blockheader.go). This helper is a small,
// independently-implemented instance of that shared, well-known
// public formula (not extracted from solo's own unexported function,
// to avoid touching the leaf-solo package for an unrelated leaf mode
// — see AGENTS.md-style guidance on not modifying leaf-solo's own
// behavior for this pass).
func littleEndianDifficulty(hash []byte) (uint64, error) {
	if len(hash) == 0 {
		return 0, errHashIsZero
	}
	buf := make([]byte, 32)
	n := len(hash)
	if n > 32 {
		n = 32
	}
	for i := 0; i < n; i++ {
		buf[31-i] = hash[i]
	}
	scalar := new(uint256.Int).SetBytes32(buf)
	if scalar.IsZero() {
		return 0, errHashIsZero
	}
	maxU256 := new(uint256.Int).SetAllOne()
	result := new(uint256.Int).Div(maxU256, scalar)
	if !result.IsUint64() {
		return ^uint64(0), nil
	}
	return result.Uint64(), nil
}
