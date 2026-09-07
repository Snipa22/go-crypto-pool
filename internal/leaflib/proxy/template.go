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
	// Blob is the real, correctly-sized RandomX hashing blob for this
	// job (before any worker-nonce has been written into it) — either
	// the pool's own already-correctly-sized "blob" field, decoded
	// directly (ordinary-client dialect), or, when this template was
	// derived from a raw blocktemplate_blob (advanced-client dialect),
	// the result of running that raw blob through
	// support.ParseBlockFromTemplateBlob +
	// support.GetBlockHashingBlob (see RawBlob below and
	// upstream.go's applyJob).
	Blob []byte

	// RawBlob is the full, untrimmed raw blocktemplate_blob bytes for
	// this template, present ONLY when this template was derived via
	// the real blocktemplate_blob->hashing-blob conversion path
	// (applyJob's BlocktemplateBlob branch); nil when the upstream
	// pool published an already-correctly-sized "blob" field directly
	// (ordinary-client dialect) -- in that case there is no full raw
	// template to patch worker-nonces into, so worker-nonce
	// partitioning falls back to writing directly into the (small)
	// hashing blob copy, exactly as before this change. See
	// BlobForWorker for how RawBlob, when present, changes the
	// worker-nonce-patch strategy (patch the FULL raw blob, then
	// RE-DERIVE the hashing blob, because a coinbase-tx-affecting
	// patch changes the merkle root, which is baked into the hashing
	// blob).
	RawBlob []byte

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

	// PoolOffset is the pool-published client_pool_offset — the
	// POOL-level peer of ReservedOffset/ClientNonceOffset's
	// WORKER-level offsets, confirmed from the real reference,
	// lib/xmr.js's MasterBlockTemplate constructor:
	//
	//	this.poolOffset = template.client_pool_offset; // clientPoolLocation
	//	this.poolNonce = 0;
	//	this.blobForWorker = function () {
	//	  this.buffer.writeUInt32BE(++this.poolNonce, this.poolOffset);
	//	  return this.buffer.toString('hex');
	//	};
	//
	// (note the legacy reference's own confusing naming: THIS
	// blobForWorker -- MasterBlockTemplate's -- patches the POOL
	// nonce, not a worker nonce; it is unrelated to, and not to be
	// confused with, this file's OWN BlobForWorker method above,
	// which patches the WORKER nonce at ReservedOffset/
	// ClientNonceOffset instead.) -1 means "not published" --
	// mirrors ReservedOffset/ClientNonceOffset's own -1 convention
	// exactly (see those fields' doc comments); unlike
	// ClientNonceOffset, there is no secondary/fallback field this
	// leaf falls back to when PoolOffset is absent -- the real
	// reference has no equivalent fallback for the pool-level offset
	// either, it is read directly from client_pool_offset with
	// nothing else to fall back to.
	PoolOffset int

	// nextPoolNonce is a per-template monotonically-incrementing
	// counter, the exact peer of nextWorkerNonce above but for the
	// POOL-level nonce — ported exactly from the legacy
	// blobForWorker's own `++this.poolNonce`. Deliberately a
	// SEPARATE, independent counter from nextWorkerNonce (not the
	// same value reused for both): in the real reference these are
	// two genuinely distinct counters living on different layers
	// (workerNonce on the per-sub-worker nested BlockTemplate,
	// poolNonce on the master-template MasterBlockTemplate) that
	// merely happen to both advance once per job issuance in this
	// leaf's simpler, non-nested architecture — see NextPoolNonce.
	nextPoolNonce atomic.Uint32
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

// BlobForWorker returns a FRESH per-worker hashing blob with
// workerNonce written, BIG-ENDIAN, as 4 raw bytes, at
// workerNonceOffset() — ported exactly from the legacy nextBlob's
// `buffer.writeUInt32BE(nonce, offset)` (Node's Buffer.writeUInt32BE
// is big-endian). The input template's own Blob/RawBlob are never
// mutated (mirrors processShare's own
// `let template = new Buffer(...); blockTemplate.buffer.copy(template)`
// defensive-copy pattern), so concurrent downstream sessions each
// requesting a job against the same WorkerTemplate never race on a
// shared buffer.
//
// Two distinct strategies, depending on whether RawBlob is present:
//
//   - t.RawBlob != nil (this template was derived via the real
//     blocktemplate_blob->hashing-blob conversion path — see
//     upstream.go's applyJob): the worker-nonce offset is meaningful
//     against the FULL raw blob (reserved_offset/client_nonce_offset
//     both refer to byte positions within the coinbase transaction's
//     tx_extra field, which only exists in the full raw blob — the
//     reduced hashing blob doesn't even contain the coinbase tx's raw
//     bytes, only a merkle hash derived from it). So: copy RawBlob,
//     bounds-check, patch the 4 bytes into the COPY, hex-encode it,
//     re-parse it with support.ParseBlockFromTemplateBlob, and
//     RE-DERIVE the hashing blob with support.GetBlockHashingBlob
//     (changing the coinbase tx bytes changes the merkle root, which
//     is part of the hashing blob, so the old Blob value is stale
//     the moment RawBlob is patched). That freshly re-derived hashing
//     blob is what's returned — never the raw blob itself.
//   - t.RawBlob == nil (the upstream pool published an
//     already-correctly-sized "blob" field directly — ordinary-client
//     dialect): keep the exact existing behavior, patching directly
//     into a copy of Blob.
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

	// The real conversion path only applies when there is BOTH a raw
	// blob to patch AND an offset to patch it at -- if RawBlob is nil
	// (ordinary-client dialect) OR offset is -1 (upstream published
	// neither ReservedOffset nor ClientNonceOffset, RawBlob or not),
	// there is nothing to patch into the raw blob, so this falls
	// through to the exact pre-existing Blob-only behavior below,
	// which already returns an unmodified copy of Blob when offset is
	// -1 -- Blob already holds the correct (unpatched) hashing blob
	// derived from RawBlob at applyJob time in that case, so no
	// re-parse/re-derive is needed.
	if t.RawBlob != nil && offset >= 0 {
		if offset+4 > len(t.RawBlob) {
			return nil, fmt.Errorf("%w: offset=%d blob_len=%d", ErrOffsetOutOfRange, offset, len(t.RawBlob))
		}
		rawOut := make([]byte, len(t.RawBlob))
		copy(rawOut, t.RawBlob)
		binary.BigEndian.PutUint32(rawOut[offset:offset+4], workerNonce)

		// convertTemplateBlobToHashingBlob (upstream.go) re-parses
		// the patched raw blob and re-derives the hashing blob via
		// support.ParseBlockFromTemplateBlob +
		// support.GetBlockHashingBlob, wrapped in a panic-recovery
		// net -- see that function's doc comment for why the
		// recovery is needed even though the pre-patch RawBlob was
		// already validated by applyJob (a worker-nonce patch
		// landing on an unexpected byte, e.g. a pool-misreported
		// offset, must not be able to crash this process either).
		hashingBlob, err := convertTemplateBlobToHashingBlob(hex.EncodeToString(rawOut))
		if err != nil {
			return nil, fmt.Errorf("proxy: re-deriving hashing blob from worker-nonce-patched raw blocktemplate_blob: %w", err)
		}
		return hashingBlob, nil
	}

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

// BlobForPool returns a FRESH copy of blob with poolNonce written,
// BIG-ENDIAN, as 4 raw bytes, at t.PoolOffset — the POOL-level peer
// of BlobForWorker's WORKER-level patch, ported exactly from the
// legacy MasterBlockTemplate.blobForWorker's
// `this.buffer.writeUInt32BE(++this.poolNonce, this.poolOffset)`
// (see PoolOffset's doc comment for the full lib/xmr.js citation).
// Same non-mutating-copy / bounds-checking / big-endian-4-byte-write
// discipline as BlobForWorker: the input blob is never mutated, and
// if t.PoolOffset is -1 (the upstream pool never published
// client_pool_offset at all on this job), this simply returns an
// unmodified copy of blob — mirroring BlobForWorker's own
// degrade-gracefully-when-offset-absent behavior for the analogous
// ReservedOffset/ClientNonceOffset case.
//
// Takes blob as an explicit parameter, rather than always reading
// t.Blob/t.RawBlob itself: this is deliberately a small, composable
// patch step meant to be applied to WHATEVER blob a caller already
// has in hand (in production, BlobForWorker's own output — see
// JobManager.NextJob, job.go, the real, single call site that
// allocates and patches BOTH nonces into the SAME per-issuance blob
// copy before returning it, exactly matching the real reference's
// per-job-issuance cadence: getMasterJob calls blobForWorker() once
// per job handed to a downstream connection, capturing the poolNonce
// value it just baked in alongside the job — see Job.PoolNonce's doc
// comment, job.go). Worker-nonce and pool-nonce are deliberately
// independent counters/patches (see nextPoolNonce's doc comment) —
// this method only ever touches t.PoolOffset, never
// ReservedOffset/ClientNonceOffset.
func (t *WorkerTemplate) BlobForPool(blob []byte, poolNonce uint32) ([]byte, error) {
	out := make([]byte, len(blob))
	copy(out, blob)
	if t.PoolOffset < 0 {
		return out, nil
	}
	if t.PoolOffset+4 > len(blob) {
		return nil, fmt.Errorf("%w: offset=%d blob_len=%d", ErrOffsetOutOfRange, t.PoolOffset, len(blob))
	}
	binary.BigEndian.PutUint32(out[t.PoolOffset:t.PoolOffset+4], poolNonce)
	return out, nil
}

// NextPoolNonce allocates the NEXT pool-nonce value from this
// template's own counter (see nextPoolNonce's doc comment) — the
// exact peer of NextBlobForWorker's `t.nextWorkerNonce.Add(1)`,
// ported from the legacy blobForWorker's own `++this.poolNonce`.
// Unlike NextBlobForWorker, this does not also return a patched blob
// itself — see BlobForPool/JobManager.NextJob for how the returned
// value is combined with a blob.
func (t *WorkerTemplate) NextPoolNonce() uint32 {
	return t.nextPoolNonce.Add(1)
}

// SeedHashHex/BlobHex are small formatting conveniences used by the
// downstream-facing job payload builder (session.go) and logging.
func (t *WorkerTemplate) SeedHashHex() string { return hex.EncodeToString(t.SeedHash) }
