// Copyright and license: see repository LICENSE (MIT).
//
// Package solo implements the leaf-solo vertical slice: a miner-facing
// TCP protocol (see protocol.go/session.go), a coin-agnostic
// NodeClient/Job/JobManager pipeline (this file + job.go) with a real
// Tari base-node GRPC implementation (GRPCNodeClient, below) and a
// real Monero daemon JSON-RPC implementation (monero_node.go), and
// wiring (server.go) that ties both to the already-merged
// internal/leaflib.ConnectionManager and
// internal/leaflib/validator.SHA3XValidator/RandomXValidator. There is
// no backend connection in this mode — see cmd/leaf-solo/main.go's doc
// comment.
package solo

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/nodeGRPC"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"github.com/Snipa22/go-xmr-lib/support"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// SubmitProof carries whatever a submitted share's proof genuinely
// has that is shared, at the NodeClient boundary, across every algo
// this codebase supports (SHA3X, C29, RXT, and Monero's own RandomX
// variant): the C29 edge cycle (nil for every other algo) and the
// already-hex-decoded claimed RandomX result hash (empty for SHA3X/
// C29, populated for RXT and Monero). The nonce itself is passed as
// BuildCandidateBlock's own separate, explicit parameter rather than
// folded into this struct, since every algo has exactly one nonce and
// it is never coin-specific in shape (a bare uint64).
type SubmitProof struct {
	// Cycle is the C29 42-edge Cuckaroo29 cycle (poolpb.SubmitRequest.POW,
	// pre-decoded). nil/empty for every other algo.
	Cycle []uint64

	// ResultHex is the miner's claimed RandomX result hash, hex
	// encoded, EXACTLY as it rode the wire (poolpb.SubmitRequest.Result)
	// — used by RXT and by Monero's own RandomX PoW. Empty for SHA3X/
	// C29, which have no separate claimed-result-hash wire field (their
	// hash is re-derived by the validator from the header+nonce
	// instead of trusted from the miner).
	ResultHex string
}

// NodeClient is the coin-agnostic set of block-source operations
// leaf-solo (and leaf-direct, which supplies its own implementation —
// see internal/leaflib/direct/node.go) needs, independent of which
// coin/PoW family the owning process is configured for. Each concrete
// implementation owns:
//
//   - its own real block-template-fetch/parsing logic, populating a
//     fully-formed *Job directly (GetBlockTemplate) rather than handing
//     JobManager a coin-typed result to parse itself;
//   - its own real candidate-block construction (BuildCandidateBlock),
//     given a validated share's nonce/proof, returning an opaque
//     candidate value only that SAME implementation's SubmitBlock
//     knows how to interpret;
//   - its own real block-submission RPC (SubmitBlock).
//
// GRPCNodeClient (below) is the production Tari implementation, backed
// by go-tari-grpc-lib/v3's nodeGRPC package (the real, current API
// surface for this library as of v3.4.0: a package-level
// InitNodeGRPC(address) call followed by package-level RPC wrapper
// functions operating on that connection — there is no per-call
// injectable *Client type in this version, so GRPCNodeClient wraps the
// package-level singleton behind this interface instead of assuming an
// API shape that doesn't exist yet). MoneroNodeClient (monero_node.go)
// is the production Monero implementation, backed by a real monerod
// JSON-RPC 2.0 connection. internal/leaflib/direct's own NodeClient is
// a second, independently-connected Tari implementation (real
// per-call-injectable GRPC client, for leaf-direct's own multi-node
// submission needs).
type NodeClient interface {
	// GetBlockTemplate fetches a fresh block template for algo with a
	// single coinbase output paying payoutAddress, and returns it as a
	// fully-formed *Job (ID/Height/Header/BlockHash/
	// NetworkTargetDifficulty/TemplateData/VmKey/CreatedAt all
	// populated by this call — StaticDifficulty is deliberately left
	// at its zero value; JobManager stamps that itself, since it is a
	// per-session/per-request concern, not a template-fetch concern).
	// algo is required (not defaulted here); callers that want the
	// pre-multi-algo SHA3X-only behavior pass poolpb.Algo_ALGO_SHA3X
	// explicitly — see job.go's JobManagerConfig.Algo, which is what
	// normalizes an unconfigured/zero-value Algo to SHA3X for backward
	// compatibility before it ever reaches this method.
	GetBlockTemplate(ctx context.Context, payoutAddress string, algo poolpb.Algo) (*Job, error)

	// GetTipInfo fetches the current chain tip height, mirroring
	// go-tari-sha3x-solo-stratum's subsystems/tipDataCache/tip.go
	// (Tari) or a real monerod get_last_block_header/get_info call
	// (Monero). Returning a bare height (rather than a coin-typed
	// response) keeps JobManager's own tip-poll loop (job.go's
	// tipPollLoop) coin-agnostic.
	GetTipInfo(ctx context.Context) (height uint64, err error)

	// BuildCandidateBlock computes the real, algo-appropriate
	// difficulty of an already-validated share (nonce + proof) against
	// job, and the real candidate block that would be submitted if
	// that difficulty turns out to meet job.NetworkTargetDifficulty
	// (the caller — session.go's handleSubmit — decides whether to
	// actually call SubmitBlock with it). candidate is opaque to every
	// caller outside this SAME NodeClient implementation; only its own
	// SubmitBlock ever type-asserts it back to a concrete type (for
	// Tari, *tari_generated.Block; for Monero, the nonce-patched
	// blocktemplate_blob bytes).
	BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (diff uint64, candidate any, err error)

	// SubmitBlock submits a completed candidate block (as produced by
	// this SAME NodeClient's own BuildCandidateBlock) to the real node.
	SubmitBlock(ctx context.Context, candidate any) error
}

// TariPowDataFromJob is the explicitly-named escape hatch for RXT's
// own proof construction (session.go's handleSubmit, building the
// real 76-byte Tari mining blob via rxt.go's createTariMiningBlob):
// RXT's blob format needs the job's current real
// ProofOfWork.pow_data bytes, which is genuinely Tari-protocol-specific
// (see rxt.go's doc comment) and is not part of the coin-agnostic
// Job/NodeClient shell. This extracts those bytes IF job.TemplateData
// holds a real *tari_generated.GetNewBlockResult with a populated
// Block/Header/Pow chain (true for every Tari NodeClient
// implementation — GRPCNodeClient here and direct.NodeClient), and
// returns nil otherwise (job.TemplateData is nil, holds some other
// coin's payload, or the chain is incomplete) — callers should treat a
// nil return exactly as they treated an empty/absent pow_data before
// this refactor (rxt.go's createTariMiningBlob already zero-pads a
// nil/short powData correctly).
func TariPowDataFromJob(job *Job) []byte {
	if job == nil {
		return nil
	}
	result, ok := job.TemplateData.(*tari_generated.GetNewBlockResult)
	if !ok || result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return nil
	}
	return result.GetBlock().GetHeader().GetPow().GetPowData()
}

// MoneroHashingBlobForSubmit is the explicitly-named escape hatch
// (mirroring TariPowDataFromJob above) that session-level submit
// handling (this package's own session.go, and leaf-direct's
// internal/leaflib/direct/session.go) uses to build the real RandomX
// verification input for an ALGO_RXM (Monero) submit.
//
// WHY THIS EXISTS: job.Header for a Monero job holds the UNPATCHED
// blockhashing_blob (nonce field still zero — see MoneroNodeClient's
// GetBlockTemplate, monero_node.go) because BuildCandidateBlock patches
// the nonce into the SEPARATE full blocktemplate_blob for submission,
// not into job.Header. validator.RandomXValidator needs the nonce
// actually patched into the hashing blob (the real pre-image Monero's
// own RandomX hashes) to verify a miner's claimed result hash — so this
// function re-derives job's real nonce offset (via the SAME real,
// never-hardcoded varint walk documented on monero_node.go) and returns
// a patched COPY, leaving job/job.TemplateData untouched.
//
// Returns an error if job.TemplateData does not hold a real
// *moneroTemplateData (i.e. this is not actually a Monero job) so
// callers can distinguish "not applicable" from "applicable but
// malformed" exactly like TariPowDataFromJob's nil-vs-error contract
// for Tari's RXT.
//
// This is the ORDINARY xmrig-class miner path ONLY: it patches the
// plain miner nonce alone. An XNP-class multi-tier proxy submit ALSO
// carries workerNonce/poolNonce params that must be patched into the
// raw template BEFORE the plain nonce is applied — see this
// function's counterpart, MoneroHashingBlobForXNPSubmit, below.
// session.go's/direct's handleSubmit picks between the two based on
// whether the submit's WorkerNonce/PoolNonce fields are present.
func MoneroHashingBlobForSubmit(job *Job, nonce uint64) ([]byte, error) {
	if job == nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForSubmit: nil job")
	}
	data, ok := job.TemplateData.(*moneroTemplateData)
	if !ok || data == nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForSubmit: job.TemplateData does not hold a real *moneroTemplateData (algo %v)", job.Algo)
	}
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(data.HashingBlob)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: re-parsing nonce offset for RandomX verification blob: %w", err)
	}
	if nonceOffset+4 > len(data.HashingBlob) {
		return nil, fmt.Errorf("solo: monero: nonce offset %d + 4 exceeds hashing blob length %d", nonceOffset, len(data.HashingBlob))
	}
	blob := make([]byte, len(data.HashingBlob))
	copy(blob, data.HashingBlob)
	var nonceBuf [4]byte
	binary.LittleEndian.PutUint32(nonceBuf[:], uint32(nonce))
	copy(blob[nonceOffset:nonceOffset+4], nonceBuf[:])
	return blob, nil
}

// xnpConvertTemplateBlobTimeout bounds how long
// convertRawTemplateBlobToHashingBlob will wait for
// support.ParseBlockFromTemplateBlob + support.GetBlockHashingBlob to
// complete before giving up and returning an error. This is the SAME
// timeout value and the SAME rationale as
// internal/leaflib/proxy/upstream.go's own
// convertTemplateBlobTimeout — see that constant's doc comment for
// the full explanation (a real, well-formed template parses in
// low-single-digit milliseconds; this is a generous multiple of that).
const xnpConvertTemplateBlobTimeout = 2 * time.Second

// convertRawTemplateBlobToHashingBlob converts a raw hex
// blocktemplate_blob into the real, correctly-sized RandomX hashing
// blob via go-xmr-lib/support's ParseBlockFromTemplateBlob +
// GetBlockHashingBlob, wrapped in BOTH a panic-recovery net AND a
// hard wall-clock timeout.
//
// THIS IS A DELIBERATE, IMPORT-CYCLE-DRIVEN DUPLICATE of
// internal/leaflib/proxy/upstream.go's convertTemplateBlobToHashingBlob
// — read THAT function's full doc comment for the complete citation
// of the genuine, confirmed go-xmr-lib v0.2.5 bug this timeout guards
// against (serialization.ConstructTXExtra's tx_extra tag-byte switch
// has no default case and can spin forever on malformed input, not
// just panic) and for the real panic-based failure modes the recover
// below guards against (corrupt/truncated length-prefixed fields
// consumed via direct slicing rather than a bounds-checked read).
//
// This package (internal/leaflib/solo) cannot import
// internal/leaflib/proxy to reuse that function directly:
// internal/leaflib/proxy already imports internal/leaflib/solo
// (protocol.go, session.go, for the shared XNP-proxy detection/job
// types), so solo importing proxy back would create a real import
// cycle. Duplicating this small wrapper locally is the correct
// choice here — see this task's own brief for the explicit
// import-cycle check this duplication was verified against. DO NOT
// "clean up" this apparent duplication by having one call the other,
// or by hoisting it to a shared package, without re-checking that
// cycle first.
func convertRawTemplateBlobToHashingBlob(blobHex string) ([]byte, error) {
	type outcome struct {
		blob []byte
		err  error
	}
	ch := make(chan outcome, 1)
	go func() {
		var out outcome
		defer func() {
			if r := recover(); r != nil {
				out = outcome{nil, fmt.Errorf("solo: recovered from a panic while parsing/converting a blocktemplate_blob (malformed or truncated input): %v", r)}
			}
			ch <- out
		}()
		parsedBlock, perr := support.ParseBlockFromTemplateBlob(blobHex)
		if perr != nil {
			out = outcome{nil, perr}
			return
		}
		hashingBlob, perr := support.GetBlockHashingBlob(parsedBlock)
		out = outcome{hashingBlob, perr}
	}()
	select {
	case out := <-ch:
		return out.blob, out.err
	case <-time.After(xnpConvertTemplateBlobTimeout):
		return nil, fmt.Errorf("solo: parsing/converting a blocktemplate_blob did not complete within %s -- likely triggered the known go-xmr-lib v0.2.5 ConstructTXExtra infinite-loop bug on malformed tx_extra data (see proxy/upstream.go's convertTemplateBlobToHashingBlob doc comment); giving up and treating this as a failed conversion rather than blocking forever", xnpConvertTemplateBlobTimeout)
	}
}

// patchMoneroXNPReservedOffsets returns a FRESH COPY of raw with
// poolNonce written BIG-ENDIAN at raw[reservedOffset+8:] and
// workerNonce written BIG-ENDIAN at raw[reservedOffset+12:] — the
// exact byte-level offset math MoneroHashingBlobForXNPSubmit needs,
// factored out into its own small, directly-testable function (see
// node_test.go) so the offset/bounds-checking logic can be verified
// against a synthetic buffer without needing a genuinely
// library-parseable Monero block for every test case. raw itself is
// never mutated. Returns a clear error (never panics) if
// reservedOffset+16 does not fit within len(raw) — covers both the
// +8 and +12 four-byte writes.
func patchMoneroXNPReservedOffsets(raw []byte, reservedOffset int, workerNonce, poolNonce uint32) ([]byte, error) {
	if reservedOffset+16 > len(raw) {
		return nil, fmt.Errorf("reserved_offset %d + 16 exceeds raw template blob length %d", reservedOffset, len(raw))
	}
	buf := make([]byte, len(raw))
	copy(buf, raw)
	binary.BigEndian.PutUint32(buf[reservedOffset+8:], poolNonce)
	binary.BigEndian.PutUint32(buf[reservedOffset+12:], workerNonce)
	return buf, nil
}

// MoneroHashingBlobForXNPSubmit is MoneroHashingBlobForSubmit's
// XNP-proxy-aware counterpart: in addition to patching the plain
// miner nonce, it ALSO patches workerNonce/poolNonce into a fresh
// copy of job.RawTemplateBlob at the real reserved_offset+12/
// reserved_offset+8 byte locations (mirroring lib/pool.js's
// processShare + lib/coins/xmr.js's BlockTemplate.clientNonceLocation/
// clientPoolLocation exactly — see protocol.go's SubmitRequest.
// WorkerNonce/PoolNonce doc comment, and this package's
// IsXNPProxyAgent/ReservedOffset doc comments, for the full
// XNP-proxy job-delivery rationale this submit-side logic completes),
// then re-derives the real RandomX hashing blob from that patched raw
// template via go-xmr-lib/support's ParseBlockFromTemplateBlob +
// GetBlockHashingBlob (the same real conversion path
// internal/leaflib/proxy's upstream.go already uses for this exact
// raw-blob-to-hashing-blob problem — see convertRawTemplateBlobToHashingBlob
// above for why this package duplicates rather than reuses that
// helper).
//
// Requires job.RawTemplateBlob to be non-empty and job.ReservedOffset
// to be greater than 0 (a real Monero reserved_size/reserve_size is
// never 0 when reservation is in use in this codebase — see
// monero_node.go's GetBlockTemplate, which always requests
// reserve_size: 60): an XNP submit against a job that never got a
// reservation is a real, reportable misconfiguration, not something
// to silently paper over.
//
// job.RawTemplateBlob is copied before any writes — the shared job's
// own slice is never mutated, matching MoneroHashingBlobForSubmit's
// own discipline for HashingBlob.
//
// BIG-ENDIAN — this is deliberately a DIFFERENT byte order than this
// same function's own plain-nonce patch below (which stays
// little-endian, matching MoneroHashingBlobForSubmit/
// BuildCandidateBlock's existing convention for the real Monero
// block-header nonce field). Do NOT "fix" this to match: workerNonce/
// poolNonce are patched via writeUInt32BE in the real reference
// (lib/pool.js processShare, quoted in full on protocol.go's
// SubmitRequest.WorkerNonce/PoolNonce doc comment) — a genuinely
// different wire convention for a genuinely different field, not an
// inconsistency to reconcile.
func MoneroHashingBlobForXNPSubmit(job *Job, nonce uint64, workerNonce, poolNonce uint32) ([]byte, error) {
	if job == nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForXNPSubmit: nil job")
	}
	if len(job.RawTemplateBlob) == 0 {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForXNPSubmit: job.RawTemplateBlob is empty -- an XNP-proxy submit against a job with no raw template is a real misconfiguration, not silently ignorable")
	}
	if job.ReservedOffset <= 0 {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForXNPSubmit: job.ReservedOffset is %d (must be > 0) -- an XNP-proxy submit against a job that never got a real reservation is a real misconfiguration, not silently ignorable", job.ReservedOffset)
	}

	buf, err := patchMoneroXNPReservedOffsets(job.RawTemplateBlob, job.ReservedOffset, workerNonce, poolNonce)
	if err != nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForXNPSubmit: %w", err)
	}

	hashingBlob, err := convertRawTemplateBlobToHashingBlob(hex.EncodeToString(buf))
	if err != nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForXNPSubmit: re-deriving hashing blob from nonce-patched raw blocktemplate_blob: %w", err)
	}

	// Re-parse the nonce offset in the FRESHLY re-derived hashing
	// blob rather than assuming it's identical to job.TemplateData's
	// cached NonceOffset -- see this function's doc comment (and
	// GetBlockTemplate's own defensive header-prefix comparison,
	// monero_node.go) for why re-parsing keeps this function
	// self-contained and correct even if that invariant ever changes
	// upstream.
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(hashingBlob)
	if err != nil {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForXNPSubmit: parsing nonce offset from re-derived hashing blob: %w", err)
	}
	if nonceOffset+4 > len(hashingBlob) {
		return nil, fmt.Errorf("solo: MoneroHashingBlobForXNPSubmit: nonce offset %d + 4 exceeds re-derived hashing blob length %d", nonceOffset, len(hashingBlob))
	}
	var nonceBuf [4]byte
	binary.LittleEndian.PutUint32(nonceBuf[:], uint32(nonce))
	copy(hashingBlob[nonceOffset:nonceOffset+4], nonceBuf[:])
	return hashingBlob, nil
}

// GRPCNodeClient is the production NodeClient, backed by
// go-tari-grpc-lib/v3's nodeGRPC package against a real Tari base node.
type GRPCNodeClient struct {
	// coinbaseExtraTag is this instance's configured coinbase-extra
	// ownership tag (see NewGRPCNodeClient's doc comment and
	// MaxCoinbaseExtraTagLen/NormalizeCoinbaseExtraTag below for the
	// real safety bound). Runtime-configurable per-process (was
	// formerly a single hardcoded package-level "GCPOOL-SOLO"
	// constant) so cmd/leaf-solo can set it to a per-algo default
	// (e.g. "supportxtm-sha3x") or an explicit operator override —
	// see cmd/leaf-solo/main.go's -coinbase-extra-tag flag.
	coinbaseExtraTag []byte
}

// NewGRPCNodeClient dials address (host:port) via nodeGRPC.InitNodeGRPC
// and returns a ready-to-use GRPCNodeClient. nodeGRPC's connection is a
// package-level singleton (see doc comment on NodeClient), so only one
// GRPCNodeClient should be constructed per process. coinbaseExtraTag is
// already-normalized (see NormalizeCoinbaseExtraTag) and is appended to
// every fetched block template's coinbase-extra field ahead of the
// per-xn random nonce (see GetBlockTemplate).
//
// As of go-tari-grpc-lib/v3 v3.3.0, InitNodeGRPC itself returns an
// error (previously void) — a real dial-time failure (e.g. malformed
// address) is now reported here instead of surfacing later as a
// confusing failure from the first real RPC call made against an
// unusable connection. Callers must check err and fail fast (see
// cmd/leaf-solo/main.go's call site) rather than proceeding with a
// half-constructed GRPCNodeClient.
func NewGRPCNodeClient(address string, coinbaseExtraTag []byte) (*GRPCNodeClient, error) {
	if err := nodeGRPC.InitNodeGRPC(address); err != nil {
		return nil, fmt.Errorf("solo: NewGRPCNodeClient: dialing %s: %w", address, err)
	}
	return &GRPCNodeClient{coinbaseExtraTag: coinbaseExtraTag}, nil
}

// MaxCoinbaseExtraTagLen is the real safety bound for a user-configured
// coinbase-extra ownership tag. Tari's actual consensus constant
// coinbase_output_features_extra_max_length is 256 bytes across every
// network (confirmed in tari-project/tari's
// base_layer/transaction_components/src/consensus/consensus_constants.rs
// — every Consensus::*() constructor, mainnet/nextnet/esmeralda/igor/
// localnet, sets this field to 256). GetBlockTemplate additionally
// appends an 8-byte per-xn random nonce INTO THE SAME coinbase_extra
// field alongside the tag (see nonceBuf below), so the tag itself must
// leave headroom for that: 256 - 8 = 248.
//
// Within that same 248-byte budget, NormalizeCoinbaseExtraTag (below)
// ALSO reserves 5 bytes for its own NUL-delimited random-suffix scheme
// (1 literal 0x00 delimiter + 4 crypto/rand bytes) — the base-tag
// string portion is truncated to MaxCoinbaseExtraTagLen-5 bytes before
// that suffix is appended. This 5-byte reservation and the 8-byte
// per-xn-nonce reservation above do NOT stack against each other: both
// exist within the same 248-byte (256-8) base-tag budget; 248 itself
// is unchanged by the new suffix.
const MaxCoinbaseExtraTagLen = 256 - 8

// coinbaseExtraRandomSuffixOnce/coinbaseExtraRandomSuffixValue cache
// the process-lifetime-scoped 4-byte random suffix NormalizeCoinbaseExtraTag
// appends after its NUL delimiter — see coinbaseExtraRandomSuffix's doc
// comment for the full rationale.
var (
	coinbaseExtraRandomSuffixOnce  sync.Once
	coinbaseExtraRandomSuffixValue [4]byte
)

// coinbaseExtraRandomSuffix returns this process's cached 4-byte
// cryptographically-random coinbase-extra-tag suffix, generating it
// via crypto/rand (NOT math/rand — math/rand is used elsewhere in this
// file for the per-xn nonce, which has different randomness
// requirements) exactly once per process, the first time it's needed,
// and reusing that same value for every subsequent call for the rest
// of the process's lifetime. This is deliberately NOT persisted
// anywhere (no disk/env/config) — a fresh process restart must get a
// fresh random suffix. Guarded by sync.Once (rather than a call-count
// assumption) so the caching is correct even if callers other than
// today's single-call-per-process pattern ever emerge.
//
// A companion go-tari-explorer repo (out of scope for this codebase)
// splits NormalizeCoinbaseExtraTag's returned bytes on the NUL
// delimiter this suffix follows to recover the original tag prefix
// for its own pool-attribution table.
func coinbaseExtraRandomSuffix() [4]byte {
	coinbaseExtraRandomSuffixOnce.Do(func() {
		if _, err := cryptorand.Read(coinbaseExtraRandomSuffixValue[:]); err != nil {
			// crypto/rand.Read failing is effectively unrecoverable
			// (the OS's CSPRNG is unavailable) — panic rather than
			// silently falling back to a predictable/zero suffix,
			// which would defeat this scheme's purpose.
			panic(fmt.Sprintf("solo: crypto/rand.Read failed while generating the coinbase-extra-tag random suffix: %v", err))
		}
	})
	return coinbaseExtraRandomSuffixValue
}

// resetCoinbaseExtraRandomSuffixForTest resets the sync.Once guard and
// cached suffix so a test can simulate a fresh OS process (which would
// otherwise generate its own fresh suffix) within a single test
// binary. Test-only — never called from production code.
func resetCoinbaseExtraRandomSuffixForTest() {
	coinbaseExtraRandomSuffixOnce = sync.Once{}
	coinbaseExtraRandomSuffixValue = [4]byte{}
}

// NormalizeCoinbaseExtraTag validates/sanitizes a user-supplied
// coinbase-extra tag string: an empty/whitespace-only tag falls back to
// fallback (the caller's computed per-algo default), and anything over
// MaxCoinbaseExtraTagLen-5 bytes is truncated — this leaf never
// silently submits a block template whose coinbase_extra would exceed
// the real base node's consensus-enforced max length (which would get
// the whole template/block rejected).
//
// The returned []byte is always <base-tag-string bytes> + one literal
// 0x00 NUL delimiter byte + 4 cryptographically-random bytes (see
// coinbaseExtraRandomSuffix): this lets a separate repo
// (go-tari-explorer, out of scope here) split on the NUL byte to
// recover the original tag prefix for its own pool-attribution table,
// while the trailing random bytes keep every process's on-chain tag
// genuinely distinct even when two processes share the identical
// configured/default tag string. The random suffix is generated once
// per process and reused for every call — see coinbaseExtraRandomSuffix.
func NormalizeCoinbaseExtraTag(tag, fallback string) []byte {
	t := tag
	if strings.TrimSpace(t) == "" {
		t = fallback
	}
	b := []byte(t)
	const maxBaseTagLen = MaxCoinbaseExtraTagLen - 5 // reserve 1 NUL + 4 random bytes
	if len(b) > maxBaseTagLen {
		b = b[:maxBaseTagLen]
	}
	suffix := coinbaseExtraRandomSuffix()
	out := make([]byte, 0, len(b)+1+len(suffix))
	out = append(out, b...)
	out = append(out, 0x00)
	out = append(out, suffix[:]...)
	return out
}

// tariPowAlgo maps this codebase's poolpb.Algo onto the real
// tari_generated.PowAlgo_PowAlgos wire value GetNewBlockTemplateWithCoinbases
// expects. Confirmed against go-tari-grpc-lib/v3's own generated enum
// (tari_generated/block.pb.go): the real C29/Cuckaroo29 value is
// POW_ALGOS_CUCKAROO (= 3), NOT some "C29"-named constant — there is no
// enum value with "C29" in its name in this library. ALGO_UNSPECIFIED
// maps to SHA3X for defensive backward compatibility (JobManagerConfig.Algo
// already normalizes this before it ever reaches here — see job.go — but
// this method doesn't assume that normalization has definitely happened).
// ALGO_RXT (Tari's own native RandomX PoW — NOT merge-mining RXM, which
// remains explicitly out of scope for this leaf) maps to the real
// tari_generated.PowAlgo_POW_ALGOS_RANDOMXT value — confirmed = 2 in this
// session's research (go-tari-grpc-lib/v3's block.pb.go), matching the
// real Tari Rust source's own PowAlgorithm::RandomXT discriminant (also
// 2, base_layer/transaction_components/src/tari_proof_of_work/
// proof_of_work_algorithm.rs). Do NOT confuse this with
// PowAlgo_POW_ALGOS_RANDOMXM (value 0) — that is RXM/merge-mining,
// explicitly out of scope.
// ALGO_RXM is not supported by this leaf's block-template fetch — RXM
// (Monero merge-mining) requires an entirely different
// minotari_merge_mining_proxy-style pipeline this leaf does not
// implement.
func tariPowAlgo(algo poolpb.Algo) (tari_generated.PowAlgo_PowAlgos, error) {
	switch algo {
	case poolpb.Algo_ALGO_UNSPECIFIED, poolpb.Algo_ALGO_SHA3X:
		return tari_generated.PowAlgo_POW_ALGOS_SHA3X, nil
	case poolpb.Algo_ALGO_C29:
		return tari_generated.PowAlgo_POW_ALGOS_CUCKAROO, nil
	case poolpb.Algo_ALGO_RXT:
		return tari_generated.PowAlgo_POW_ALGOS_RANDOMXT, nil
	default:
		return 0, fmt.Errorf("solo: leaf-solo does not support fetching Tari block templates for algo %v (only SHA3X, C29, and RXT are supported via GRPCNodeClient — RXM merge-mining is explicitly out of scope, and Monero has its own MoneroNodeClient)", algo)
	}
}

// GetBlockTemplate implements NodeClient. This is a faithful port of
// go-tari-sha3x-solo-stratum's GetBlockSha3 (subsystems/blockTemplateCache/
// blockTemplate.go) / go-tari-c29-solo-stratum's equivalent (both call the
// exact same GetNewBlockTemplateWithCoinbases GRPC method, varying only the
// requested PowAlgo — see tariPowAlgo above), adapted for solo mode: a
// single coinbase output paying the leaf's configured solo payout address
// gets 100% of the coinbase share (Value: 100 mirrors the legacy code's
// coinbase-share weighting field, not an absolute currency amount — the
// base node computes the actual reward split from this), instead of the
// legacy per-miner multi-coinbase pool scheme.
//
// IMPORTANT for per-xn extranonce support (job.go's JobManager.JobForXN):
// this already appends a FRESH, cryptographically-independent random
// 8-byte nonce buffer to the coinbase-extra field on EVERY call — see
// nonceBuf below — mirroring the legacy GetBlockSha3's own
// `binary.LittleEndian.PutUint64(buf, rand.Uint64())` coinbase-extra
// randomization exactly. That random data flows into the coinbase
// transaction, which changes the resulting block's MergeMiningHash, so
// two calls to this method (e.g. for two different sessions' xn values)
// already produce genuinely distinct, non-overlapping hash pre-images
// even at the same chain height — this method did NOT need any new
// randomization logic added for per-xn support; JobManager only needed
// to call it once per newly-seen xn and cache the result (see job.go).
func (c *GRPCNodeClient) GetBlockTemplate(ctx context.Context, payoutAddress string, algo poolpb.Algo) (*Job, error) {
	powAlgo, err := tariPowAlgo(algo)
	if err != nil {
		return nil, err
	}

	coinbaseExtra := c.buildCoinbaseExtra()

	coinbases := []*tari_generated.NewBlockCoinbase{
		{
			Address:            payoutAddress,
			Value:              100,
			StealthPayment:     false,
			RevealedValueProof: true,
			CoinbaseExtra:      coinbaseExtra,
		},
	}

	result, err := nodeGRPC.GetNewBlockTemplateWithCoinbases(ctx, &tari_generated.GetNewBlockTemplateWithCoinbasesRequest{
		Algo:      &tari_generated.PowAlgo{PowAlgo: powAlgo},
		Coinbases: coinbases,
	})
	if err != nil {
		return nil, err
	}
	return tariJobFromResult(result, algo)
}

// buildCoinbaseExtra combines this instance's configured
// coinbaseExtraTag with a fresh, cryptographically-independent random
// 8-byte per-xn nonce buffer into the exact []byte GetBlockTemplate
// submits as CoinbaseExtra (see that method's doc comment for the full
// per-xn randomization rationale). Factored out of GetBlockTemplate so
// tests can exercise the exact tag-inclusion logic without a real GRPC
// connection (see node_test.go).
func (c *GRPCNodeClient) buildCoinbaseExtra() []byte {
	nonceBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBuf, rand.Uint64())
	coinbaseExtra := make([]byte, 0, len(c.coinbaseExtraTag)+len(nonceBuf))
	coinbaseExtra = append(coinbaseExtra, c.coinbaseExtraTag...)
	coinbaseExtra = append(coinbaseExtra, nonceBuf...)
	return coinbaseExtra
}

// tariJobFromResult builds a coin-agnostic *Job from a real Tari
// GetNewBlockResult — shared by GRPCNodeClient here and reusable (by
// package copy, following this codebase's own established
// duplicate-small-helpers-across-packages convention — see
// internal/leaflib/direct/wireutil.go's doc comment) by
// direct.NodeClient's own GetBlockTemplate.
//
// job_id must be a purely random, opaque wire token, NEVER derived
// from BlockHash (or any other template content) — this used to call
// jobIDFromBlockHash, which was CONFIRMED unsafe on two independent
// axes (see monero_node.go's GetBlockTemplate doc comment for the
// concrete production incident that surfaced this on RXM, whose
// prevHash+height can repeat across genuinely distinct templates):
// (1) two genuinely different templates can share a content-derived
// ID, and (2) RestampDifficulty (job.go) deliberately reuses the
// SAME job_id for the SAME template on purpose when only difficulty
// changes, so a content-derived scheme was never doing real
// collision-avoidance work in the first place — for SHA3X/Tari it
// merely APPEARED safe because BlockHash happens to change almost
// every GetNewBlockTemplateWithCoinbases call (coinbase-extra is
// randomized per call, see buildCoinbaseExtra), which is an
// incidental side effect, not a designed guarantee. newRandomHexID
// (the same helper proxy/job.go's JobManager.NextJob already uses)
// has no such reliance.
func tariJobFromResult(result *tari_generated.GetNewBlockResult, algo poolpb.Algo) (*Job, error) {
	if result == nil || result.GetBlock() == nil || result.GetBlock().GetHeader() == nil {
		return nil, fmt.Errorf("solo: GetBlockTemplate returned an incomplete result")
	}
	id, err := newRandomHexID()
	if err != nil {
		return nil, fmt.Errorf("solo: generating random job id: %w", err)
	}
	return &Job{
		ID:                      id,
		Algo:                    algo,
		Height:                  result.GetBlock().GetHeader().GetHeight(),
		Header:                  result.GetMergeMiningHash(),
		BlockHash:               result.GetBlockHash(),
		NetworkTargetDifficulty: result.GetMinerData().GetTargetDifficulty(),
		TemplateData:            result,
		VmKey:                   result.GetVmKey(),
		CreatedAt:               time.Now(),
	}, nil
}

// GetTipInfo implements NodeClient, wrapping nodeGRPC.GetTipInfo.
func (c *GRPCNodeClient) GetTipInfo(ctx context.Context) (uint64, error) {
	tip, err := nodeGRPC.GetTipInfo(ctx)
	if err != nil {
		return 0, err
	}
	return tip.GetMetadata().GetBestBlockHeight(), nil
}

// BuildCandidateBlock implements NodeClient. This is the real,
// per-algo candidate-construction logic that used to live directly in
// session.go's own blockCandidate method — moved here so that ALL of
// this leaf's real Tari-specific block-cloning/nonce-patching/
// difficulty-derivation logic lives inside the NodeClient
// implementation that owns the Tari-shaped template data, not in the
// coin-agnostic session/wire-handling layer.
func (c *GRPCNodeClient) BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (uint64, any, error) {
	return tariBuildCandidateBlock(job, nonce, proof)
}

// tariBuildCandidateBlock is BuildCandidateBlock's real implementation,
// factored out so both GRPCNodeClient (production) and this package's
// own test doubles (job_test.go's fakeNodeClient) exercise the exact
// same real difficulty/candidate-construction logic — a fake NodeClient
// that reimplemented a SHADOW of this logic would defeat the point of
// session-level regression tests.
func tariBuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (diff uint64, candidate any, err error) {
	result, ok := job.TemplateData.(*tari_generated.GetNewBlockResult)
	if !ok || result == nil || result.GetBlock() == nil {
		return 0, nil, fmt.Errorf("solo: job.TemplateData does not hold a real Tari GetNewBlockResult with a populated Block (algo %v)", job.Algo)
	}
	switch job.Algo {
	case poolpb.Algo_ALGO_C29:
		diff, err = validator.C29Difficulty(proof.Cycle, c29SubmitEdgeBits)
		if err != nil {
			return 0, nil, err
		}
		return diff, cloneBlockWithC29Proof(result.GetBlock(), nonce, proof.Cycle), nil
	case poolpb.Algo_ALGO_RXT:
		hashBytes, hexErr := hex.DecodeString(proof.ResultHex)
		if hexErr != nil {
			return 0, nil, fmt.Errorf("solo: rxt claimed result hash is not valid hex: %w", hexErr)
		}
		diff, err = rxtLittleEndianDifficulty(hashBytes)
		if err != nil {
			return 0, nil, err
		}
		// RXT has no supplemental on-chain pow_data to stamp (unlike
		// C29's edge-packed cycle) — the template's own Header.Pow
		// (pow_algo=RandomXT, whatever pow_data the base node already
		// populated it with) is left exactly as fetched; only
		// Header.Nonce is mutated, same as SHA3X/cloneBlockWithNonce.
		return diff, cloneBlockWithNonce(result.GetBlock(), nonce), nil
	default:
		diff = validator.SHA3XHeaderDiff(nonce, job.Header)
		return diff, cloneBlockWithNonce(result.GetBlock(), nonce), nil
	}
}

// SubmitBlock implements NodeClient, wrapping nodeGRPC.SubmitBlock.
// candidate must be a *tari_generated.Block produced by this SAME
// implementation's own BuildCandidateBlock.
func (c *GRPCNodeClient) SubmitBlock(ctx context.Context, candidate any) error {
	block, ok := candidate.(*tari_generated.Block)
	if !ok {
		return fmt.Errorf("solo: SubmitBlock: candidate is not a *tari_generated.Block (got %T)", candidate)
	}
	_, err := nodeGRPC.SubmitBlock(ctx, block)
	return err
}
