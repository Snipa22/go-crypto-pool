// Copyright and license: see repository LICENSE (MIT).
package proxy

import "fmt"

// blockHeaderNonceOffset locates the real, standard Monero/CryptoNote
// block_header nonce field's byte offset within a raw
// blocktemplate_blob, so that a downstream miner's claimed 4-byte
// nonce can be written into the SAME per-worker blob copy
// (WorkerTemplate.BlobForWorker's output) that already carries this
// leaf's own worker-nonce at reserved_offset/client_nonce_offset,
// before that combined blob is fed to RandomXValidator for real local
// re-validation.
//
// This is a real, honest port of the CryptoNote block_header wire
// format (the same format XMRig itself parses client-side to find
// this same field, since — unlike Tari's fixed-size headers — a
// Monero-family header has a genuinely VARIABLE offset to its own
// nonce field depending on the varint-encoded lengths of the fields
// before it):
//
//	major_version   varint
//	minor_version    varint
//	timestamp        varint
//	prev_id          32 raw bytes (FIXED size)
//	nonce            4 raw bytes  <- this is what we're locating
//	... (miner_tx, tx_hashes, etc. follow; not needed here)
//
// varint here is CryptoNote's own LEB128-style unsigned varint
// (7 payload bits per byte, MSB is the continuation flag) — the exact
// same encoding tools::get_varint uses in the real Monero/Tari C++
// reference. major_version/minor_version are single-byte varints for
// every block height that has ever existed on real Monero-family
// chains (both are small integers, well under 128), and timestamp
// (a unix epoch second count, currently ~1.7-1.8 billion) needs
// multiple varint bytes — so this offset is NOT a fixed constant in
// general, and computing it by proper varint-skip (rather than
// assuming a fixed byte count) is required for correctness.
func blockHeaderNonceOffset(blob []byte) (int, error) {
	pos := 0
	for i := 0; i < 3; i++ { // major_version, minor_version, timestamp
		n, err := skipVarint(blob, pos)
		if err != nil {
			return 0, fmt.Errorf("proxy: parsing block header field %d: %w", i, err)
		}
		pos = n
	}
	pos += 32 // prev_id, fixed size
	if pos+4 > len(blob) {
		return 0, fmt.Errorf("proxy: block header nonce field (offset %d) does not fit in a %d-byte blob", pos, len(blob))
	}
	return pos, nil
}

// skipVarint advances past one CryptoNote-style LEB128 unsigned
// varint starting at blob[pos], returning the position of the byte
// immediately after it.
func skipVarint(blob []byte, pos int) (int, error) {
	for {
		if pos >= len(blob) {
			return 0, fmt.Errorf("proxy: truncated varint at end of blob")
		}
		b := blob[pos]
		pos++
		if b&0x80 == 0 {
			return pos, nil
		}
	}
}

// writeMinerNonce returns a FRESH COPY of blob with the miner's
// claimed 4-byte nonce written, BIG-ENDIAN (matching cnUtil's
// construct_block_blob / the standard CryptoNote on-wire nonce byte
// order — the same convention XMRig submits its "nonce" hex field in:
// 8 hex chars = 4 raw bytes), at the real block_header nonce offset
// located by blockHeaderNonceOffset. blob is never mutated.
func writeMinerNonce(blob []byte, nonce uint32) ([]byte, error) {
	offset, err := blockHeaderNonceOffset(blob)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(blob))
	copy(out, blob)
	out[offset] = byte(nonce >> 24)
	out[offset+1] = byte(nonce >> 16)
	out[offset+2] = byte(nonce >> 8)
	out[offset+3] = byte(nonce)
	return out, nil
}
