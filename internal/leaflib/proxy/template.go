// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

// WorkerTemplate is leaf-proxy's port of xmr-node-proxy's real
// lib/xmr.js BlockTemplate/MasterBlockTemplate constructors — the
// mechanism this leaf uses to hand every downstream miner a genuinely
// distinct, non-overlapping search space while all of them share ONE
// upstream connection to the real pool.
//
// THIS IS STRUCTURALLY DIFFERENT FROM THE EXISTING SHA3X/C29 LEAF-SOLO
// "xn" HEX-PREFIX CONVENTION (internal/leaflib/solo/protocol.go's
// JobPayload.XN / session.go's xn-prefix check) — do not conflate the
// two. leaf-solo's xn is a 2-byte value the MINER is expected to
// prefix its own nonce hex string with, checked as a string-prefix at
// submit time. leaf-proxy's worker-nonce partitioning instead WRITES a
// 4-byte value directly INTO the raw block template blob's bytes, at
// a byte OFFSET the pool told us about (reserved_offset — always
// published on a real Monero-family GetBlockTemplate result — or, if
// the upstream pool recognizes us as an "advanced client" per its own
// agent-string sniffing and grants us the xmr-node-proxy extension,
// the dedicated client_nonce_offset it publishes instead). Confirmed
// from the real reference source, lib/xmr.js:
//
//	function BlockTemplate(template) {
//	  this.reservedOffset = template.reserved_offset;
//	  this.workerOffset = template.worker_offset; // clientNonceLocation
//	  ...
//	  this.nextBlob = function () {
//	    if (this.solo) {
//	      this.buffer.writeUInt32BE(++this.workerNonce, this.reservedOffset);
//	    } else {
//	      this.buffer.writeUInt32BE(++this.workerNonce, this.workerOffset);
//	    }
//	    return cnUtil.convert_blob(this.buffer).toString('hex');
//	  };
//	}
//
// (this.solo here means "the upstream pool did NOT grant us the
// advanced-client worker_offset extension", not "leaf-solo mode" —
// unrelated, confusingly-overlapping terminology in the legacy
// codebase; leaf-proxy always falls back to writing at reservedOffset
// in that case, exactly like the legacy "solo" branch above.)
type WorkerTemplate struct {
	// Blob is the real, hex-decoded blocktemplate_blob the upstream
	// pool published for this job (before any worker-nonce has been
	// written into it).
	Blob []byte

	// ReservedOffset is the real, standard GetBlockTemplate
	// reserved_offset field — published by a Monero-family DAEMON's
	// own GetBlockTemplate RPC (and by a pool that passes it through
	// when acting as a lightweight solo relay), used for the
	// miner's/proxy's own nonce-space reservation when no
	// advanced-client extension is available. -1 means this leaf's
	// upstream did not publish it at all (see below) — CONFIRMED,
	// from a real live capture against pool.supportxmr.com (this
	// pass's smoke test), that a real production pool serving
	// ordinary stratum clients frequently publishes NEITHER this NOR
	// ClientNonceOffset: the real wire job SupportXMR returned was
	// `{"blob":...,"job_id":...,"target":...,"height":...,
	// "seed_hash":...}` — no reserved_offset, no client_nonce_offset
	// at all. That trio is a monerod-daemon-direct-RPC/advanced-
	// client-extension concept, not something every real pool
	// grants — see workerNonceOffset's doc comment for how this
	// leaf behaves when neither is available.
	ReservedOffset int

	// ClientNonceOffset is the pool's advanced-client
	// ("xmr-node-proxy"-aware) worker_offset/client_nonce_offset
	// extension field, if the upstream pool actually granted it.
	// -1 means "not granted / not present on this job" — see
	// workerNonceOffset's fallback to ReservedOffset in that case.
	ClientNonceOffset int

	// SeedHash is the real RandomX seed for this job (empty for a
	// pre-RandomX/legacy CryptoNight job, which this leaf does not
	// support — RandomX-only, per the task).
	SeedHash []byte

	// Height/JobID/TargetDiff/Difficulty are carried through from the
	// pool's own job for bookkeeping/wire-payload construction; see
	// job.go.
	Height     uint64
	JobID      string // the pool's OWN job_id -- echoed back on upstream submit
	TargetDiff uint64 // real block-level target difficulty
	Difficulty uint64 // pool-suggested share difficulty (informational only; downstream vardiff owns the real per-session value)

	// nextWorkerNonce is a per-template monotonically-incrementing
	// counter, ported exactly from the legacy `++this.workerNonce`
	// above: every single job issuance (to any downstream miner)
	// consumes the next value, so no two issued jobs ever carry the
	// same worker-nonce for the lifetime of this WorkerTemplate (i.e.
	// until the upstream pool pushes a new job and this leaf swaps in
	// a fresh WorkerTemplate for it).
	nextWorkerNonce atomic.Uint32
}

// workerNonceOffset returns which byte offset THIS template actually
// writes per-issuance worker-nonce values at: ClientNonceOffset if the
// upstream pool granted the real xmr-node-proxy advanced-client
// extension, else ReservedOffset if THAT was published (the standard
// daemon-GBT field), else -1 — meaning NEITHER was published, the
// real, confirmed behavior of production pools serving ordinary
// stratum clients (pool.supportxmr.com, per this pass's live smoke
// test capture) rather than an XNP-aware daemon/pool. Ported exactly
// from the legacy nextBlob's this.solo branch for the
// ClientNonceOffset-present/absent split (see type doc comment); the
// -1/"neither available" case is NOT present in the legacy reference
// (which always assumed reserved_offset exists, since it was written
// assuming XNP's OWN daemon connection or a cooperating pool) and is
// this leaf's own honest extension for the real-world case where a
// downstream miner's per-worker nonce space cannot be byte-partitioned
// by this leaf at all — see BlobForWorker's doc comment for how that
// is handled without corrupting the blob.
func (t *WorkerTemplate) workerNonceOffset() int {
	if t.ClientNonceOffset >= 0 {
		return t.ClientNonceOffset
	}
	return t.ReservedOffset
}

// ErrOffsetOutOfRange is returned by BlobForWorker/NextBlobForWorker
// when the pool-published offset doesn't leave room for a 4-byte
// write inside the actual template blob -- a real, if rare,
// pool-misconfiguration/protocol-mismatch failure mode that must
// reject rather than silently corrupt/truncate the blob.
var ErrOffsetOutOfRange = fmt.Errorf("proxy: worker-nonce offset is out of range for this template's blob")

// BlobForWorker returns a FRESH COPY of Blob with workerNonce written,
// BIG-ENDIAN, as 4 raw bytes, at workerNonceOffset() — ported exactly
// from the legacy nextBlob's `buffer.writeUInt32BE(nonce, offset)`
// (Node's Buffer.writeUInt32BE is big-endian). The input template's
// own Blob is never mutated (mirrors processShare's own
// `let template = new Buffer(...); blockTemplate.buffer.copy(template)`
// defensive-copy pattern), so concurrent downstream sessions each
// requesting a job against the same WorkerTemplate never race on a
// shared buffer.
//
// If workerNonceOffset() is -1 (neither ClientNonceOffset nor
// ReservedOffset was published by the upstream — the REAL, confirmed
// behavior of pool.supportxmr.com's ordinary stratum job responses,
// per this pass's live smoke test), there is genuinely no
// pool-sanctioned byte offset this leaf can safely write a
// per-worker value into without risking corrupting real block-header
// fields it doesn't control the layout of. In that case this method
// returns an UNMODIFIED COPY of Blob (workerNonce is still allocated
// and returned by NextBlobForWorker for bookkeeping/logging, it is
// simply not written into the blob) — every downstream miner gets an
// identical copy of the pool's own job, and non-collision degrades
// to relying on each miner's own randomized nonce starting point
// (the same real-world fallback ordinary, non-advanced-client-aware
// Monero proxies rely on) rather than a guaranteed byte-level
// partition. This is a deliberate, honest degradation, not silent
// data corruption.
func (t *WorkerTemplate) BlobForWorker(workerNonce uint32) ([]byte, error) {
	offset := t.workerNonceOffset()
	out := make([]byte, len(t.Blob))
	copy(out, t.Blob)
	if offset < 0 {
		return out, nil
	}
	if offset+4 > len(t.Blob) {
		return nil, fmt.Errorf("%w: offset=%d blob_len=%d", ErrOffsetOutOfRange, offset, len(t.Blob))
	}
	binary.BigEndian.PutUint32(out[offset:offset+4], workerNonce)
	return out, nil
}

// NextBlobForWorker allocates the NEXT worker-nonce value from this
// template's own counter (see nextWorkerNonce's doc comment) and
// returns the resulting per-worker blob copy alongside it — this is
// the real call every downstream job issuance (login, getjob, a
// vardiff-driven repush) makes, ported exactly from the legacy
// getJob()'s `let blob = activeBlockTemplate.nextBlob(); ...
// extraNonce: activeBlockTemplate.workerNonce`.
func (t *WorkerTemplate) NextBlobForWorker() (blob []byte, workerNonce uint32, err error) {
	workerNonce = t.nextWorkerNonce.Add(1)
	blob, err = t.BlobForWorker(workerNonce)
	return blob, workerNonce, err
}

// SeedHashHex/BlobHex are small formatting conveniences used by the
// downstream-facing job payload builder (session.go) and logging.
func (t *WorkerTemplate) SeedHashHex() string { return hex.EncodeToString(t.SeedHash) }
