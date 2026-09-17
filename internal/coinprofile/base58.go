// Copyright and license: see repository LICENSE (MIT).
package coinprofile

import (
	"errors"
	"fmt"
	"math/big"
)

// moneroBase58Alphabet is the real Monero/CryptoNote base58 alphabet --
// identical ordering to Bitcoin's base58 alphabet (digits 1-9, then
// uppercase A-Z excluding I/O, then lowercase a-z excluding l). Every
// CryptoNote-codebase fork (including every confirmed entry in
// Registry) uses this same alphabet; only the block-chunking scheme
// below (not the alphabet) is CryptoNote-specific.
const moneroBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// fullBlockSize/fullEncodedBlockSize and encodedBlockSizes mirror the
// real Monero base58 implementation's block-chunking table
// (monero-project/monero's src/common/base58.cpp): a full 8-byte block
// encodes to 11 base58 characters; a final short block of N raw bytes
// (1..7) encodes to encodedBlockSizes[N] characters. This chunking is
// what makes CryptoNote's base58 flavor different from a plain
// big-integer base58 encoding.
const (
	fullBlockSize        = 8
	fullEncodedBlockSize = 11
)

// encodedBlockSizes[n] is the base58-encoded character count for a
// raw block of n bytes (n in 1..8); index 0 is unused.
var encodedBlockSizes = [9]int{0, 2, 3, 5, 6, 7, 9, 10, 11}

var base58Alphabet [256]int8

func init() {
	for i := range base58Alphabet {
		base58Alphabet[i] = -1
	}
	for i, c := range []byte(moneroBase58Alphabet) {
		base58Alphabet[c] = int8(i)
	}
}

// decodedBlockSize returns the raw byte count for an encoded block of
// exactly encodedLen characters, per encodedBlockSizes -- an
// encodedLen with no matching raw size (i.e. not one of
// encodedBlockSizes' entries) is a malformed/truncated address.
func decodedBlockSize(encodedLen int) (int, error) {
	if encodedLen == 0 {
		return 0, nil
	}
	for raw, enc := range encodedBlockSizes {
		if enc == encodedLen {
			return raw, nil
		}
	}
	return 0, fmt.Errorf("coinprofile: invalid base58 final block length %d", encodedLen)
}

// decodeBase58Block decodes exactly one base58 block (big-endian,
// big-integer semantics within the block) into exactly rawSize bytes,
// left-zero-padded. Returns an error if any character is outside the
// alphabet or the decoded integer does not fit in rawSize bytes (both
// real malformed-input cases, not just style nits -- the real Monero
// decoder rejects both the same way).
func decodeBase58Block(block string, rawSize int) ([]byte, error) {
	if len(block) == 0 && rawSize == 0 {
		return nil, nil
	}
	acc := new(big.Int)
	base := big.NewInt(58)
	for i := 0; i < len(block); i++ {
		idx := base58Alphabet[block[i]]
		if idx < 0 {
			return nil, fmt.Errorf("coinprofile: invalid base58 character %q", block[i])
		}
		acc.Mul(acc, base)
		acc.Add(acc, big.NewInt(int64(idx)))
	}
	raw := acc.Bytes()
	if len(raw) > rawSize {
		return nil, errors.New("coinprofile: base58 block overflows its raw byte size (malformed address)")
	}
	out := make([]byte, rawSize)
	copy(out[rawSize-len(raw):], raw)
	return out, nil
}

// DecodeMoneroBase58 decodes s using the real Monero/CryptoNote base58
// flavor (see the block-chunking doc comment above) -- the SAME
// encoding every confirmed monerod-compatible fork in Registry uses
// for its wallet addresses, since none of them have modified this
// low-level encoding (only the address payload's own network-tag
// prefix byte(s) differ between coins, which is exactly what
// CoinProfile.AddressNetworkBytes exists to capture).
func DecodeMoneroBase58(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("coinprofile: empty address")
	}
	fullBlocks := len(s) / fullEncodedBlockSize
	lastLen := len(s) % fullEncodedBlockSize
	lastRawSize, err := decodedBlockSize(lastLen)
	if err != nil {
		return nil, err
	}

	out := make([]byte, fullBlocks*fullBlockSize+lastRawSize)
	for i := 0; i < fullBlocks; i++ {
		block := s[i*fullEncodedBlockSize : (i+1)*fullEncodedBlockSize]
		decoded, err := decodeBase58Block(block, fullBlockSize)
		if err != nil {
			return nil, err
		}
		copy(out[i*fullBlockSize:], decoded)
	}
	if lastLen > 0 {
		block := s[fullBlocks*fullEncodedBlockSize:]
		decoded, err := decodeBase58Block(block, lastRawSize)
		if err != nil {
			return nil, err
		}
		copy(out[fullBlocks*fullBlockSize:], decoded)
	}
	return out, nil
}
