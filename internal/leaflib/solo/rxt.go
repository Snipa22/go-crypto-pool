// Copyright and license: see repository LICENSE (MIT).
package solo

import "github.com/Snipa22/go-crypto-pool/internal/leaflib"

// rxtPowAlgoByte, tariMiningBlobSize, rxtXmrigNonceOffset/Size,
// createTariMiningBlob, errRXTHashIsZero, and rxtLittleEndianDifficulty
// are now thin aliases/wrappers over internal/leaflib's identically
// named exported symbols (EXTRACTED there so internal/leaflib/direct
// — which used to hand-derive a byte-for-byte duplicate of every one
// of these in its own wireutil.go — can reuse the exact same real,
// confirmed-from-the-real-Tari-Rust-source implementations instead of
// carrying a second copy; see leaflib/wireutil.go's doc comment for
// the full rationale). This is a clean, behavior-preserving move: every
// existing solo test (rxt_test.go, job_test.go, session_test.go, ...)
// keeps referencing these exact same in-package, unexported names,
// unmodified — see internal/leaflib/vardiff.go's own identical
// extraction pattern (solo/vardiff.go's VardiffConfig/computeRetarget
// wrappers), which this follows exactly.
const (
	rxtPowAlgoByte      = leaflib.RXTPowAlgoByte
	tariMiningBlobSize  = leaflib.TariMiningBlobSize
	rxtXmrigNonceOffset = leaflib.RXTXmrigNonceOffset
	rxtXmrigNonceSize   = leaflib.RXTXmrigNonceSize
)

// errRXTHashIsZero delegates to leaflib.ErrRXTHashIsZero — see that
// var's doc comment for the full rationale (ported from the real Rust
// DifficultyError::DivideByZero).
var errRXTHashIsZero = leaflib.ErrRXTHashIsZero

// createTariMiningBlob delegates to leaflib.CreateTariMiningBlob — see
// that function's doc comment for the full, byte-for-byte-ported
// real Tari create_tari_mining_blob provenance.
func createTariMiningBlob(miningHash []byte, nonce uint64, powAlgo byte, powData []byte) []byte {
	return leaflib.CreateTariMiningBlob(miningHash, nonce, powAlgo, powData)
}

// rxtLittleEndianDifficulty delegates to leaflib.RXTLittleEndianDifficulty
// — see that function's doc comment for the full, byte-for-byte-ported
// real Tari Difficulty::little_endian_difficulty provenance.
func rxtLittleEndianDifficulty(hash []byte) (uint64, error) {
	return leaflib.RXTLittleEndianDifficulty(hash)
}
