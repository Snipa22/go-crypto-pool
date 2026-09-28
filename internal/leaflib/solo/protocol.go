// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"encoding/json"
	"strings"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// Wire protocol: newline-delimited JSON objects in both directions,
// speaking the real Monero-style JSON-RPC 2.0 stratum dialect used by
// actual SHA3X miner software (XMRig-class tools, the tari-project/
// graxil GPU miner, etc.) — ported byte-shape-for-byte-shape from the
// legacy go-tari-sha3x-solo-stratum reference implementation
// (subsystems/messages/minerStructs.go, subsystems/poolStratum/
// miner.go, subsystems/minerTracking/structs.go), NOT the custom
// JSON-line protocol this file previously defined (see PR #7). This
// replaces that custom protocol outright: no real miner speaks it, so
// nothing about it survives except the underlying validator/JobManager
// wiring, which is untouched.
//
// Confirmed against the reference's actual dispatch loop
// (subsystems/poolStratum/server.go, ~line 139-152): EVERY client->server
// message — including login — arrives wrapped in the same envelope
// below; login is not a bare/unwrapped object on the wire. Only the
// reference's internal Go convenience unmarshal (MinerRPCLogin) is
// unwrapped from Request.Params, not the wire message itself.
//
//	Miner -> Server (envelope, all methods):
//	  {"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"<address>","pass":"x","agent":"XMRig/6.21.0","algo":["sha3x"]}}
//	  {"id":2,"jsonrpc":"2.0","method":"submit","params":{"id":"<session id>","job_id":"<job_id>","nonce":"<hex le8>","result":"<hex>"}}
//	  {"id":3,"jsonrpc":"2.0","method":"getjob"}
//
//	Server -> Miner, login response:
//	  {"id":1,"jsonrpc":"2.0","result":{"id":"<session id>","job":{...},"status":"OK"},"status":"OK"}
//
//	Server -> Miner, unsolicited new job push (e.g. on tip movement):
//	  {"jsonrpc":"2.0","method":"job","params":{...}}
//
//	Server -> Miner, submit (share) response — bare boolean result:
//	  {"id":2,"jsonrpc":"2.0","result":true}
//
//	Server -> Miner, general/login error response — STRING result
//	(distinct shape from the share response above; result here is
//	always a string, never a bool):
//	  {"id":1,"jsonrpc":"2.0","error":"invalid address provided","result":""}
//
// Ported and REQUIRED (see task description, and this package's job.go
// doc comment for the full rationale — a real production crash: the
// graxil GPU miner panicked on a missing "xn" field, and "solo" means
// "single payout address", NOT "single miner"):
//   - XNonce ("xn") extranonce assignment (one random 2-byte value per
//     connecting session, see job.go's newSessionXN) and wire exposure
//     (JobPayload.XN below) so multiple miners hitting the same solo
//     leaf search genuinely different, non-overlapping template spaces
//     instead of colliding on one global job.
//   - Submit-time xn-prefix rejection (session.go's handleSubmit),
//     ported from go-tari-sha3x-solo-stratum's miner.go SubmitJob
//     (`strings.HasPrefix(strings.ToLower(submittedWork.Nonce), m.xn)`).
//
// Now PORTED: "." / "+" login-field suffix parsing for payment-ID /
// worker identifier / miner-requested fixed difficulty -- see
// loginfields.go's ParseLoginFields for the verbatim legacy source
// citation and for every scoping decision (the "+" difficulty split is
// algo-agnostic; the "." payment-ID/identifier split is Monero-family
// only, matching the legacy reference's own Monero-only scope). The
// previous note here ("deliberately still NOT ported ... the address
// is taken as-is") described a real bug: the RAW, unstripped login
// string was handed to the byte-exact address validators, which
// correctly rejected it, so every miner using that completely standard
// convention was locked out of this leaf entirely.
//
// Ported and REQUIRED (see task description): per-job used-nonce
// tracking, so a miner can't replay the same nonce twice for credit —
// implemented on Job itself (job.go). Since jobs are now per-xn (see
// job.go's doc comment), this dedup set is naturally per-xn too.

// Request is one client->server envelope. Every method — login,
// getjob, submit — arrives wrapped in this shape; see this file's doc
// comment for how that was confirmed against the reference dispatch
// loop.
type Request struct {
	ID      int             `json:"id"`
	JsonRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// LoginRequest is the real "login" method's params shape
// (messages.MinerRPCLogin in the reference).
type LoginRequest struct {
	Login string   `json:"login"`
	Pass  string   `json:"pass"`
	Agent string   `json:"agent"`
	Algo  []string `json:"algo"`
	RigID string   `json:"rigid"`
}

// SubmitRequest is the real "submit" method's params shape
// (messages.MinerRPCSubmit in the reference). ID here is the
// session/connection id the miner was handed at login (echoed back,
// not separately validated — the reference doesn't authenticate on it
// either, see miner.go's SubmitJob), JobID matches a previously-sent
// job_id, Nonce is hex-encoded 8 bytes and MUST be prefixed
// (case-insensitively) with the session's own assigned xn — see
// session.go's handleSubmit, ported from go-tari-sha3x-solo-stratum's
// miner.go SubmitJob xn-prefix check — and Result is the miner's
// claimed hex-encoded hash (accepted on the wire, but not required for
// validation since the server recomputes it for real via the
// algo-appropriate validator).
//
// The Nonce field's BYTE ORDER when decoded is algo-dependent — see
// session.go's handleSubmit: SHA3X decodes it little-endian
// (go-tari-sha3x-solo-stratum's miner.go), C29 decodes it BIG-ENDIAN
// (go-tari-c29-solo-stratum's miner.go SubmitJob:
// `nonce := binary.BigEndian.Uint64(b)`) — confirmed from source, not
// assumed to be the same just because the envelope shape is shared.
//
// POW carries the real C29-only submit field (messages.MinerRPCSubmit's
// `POW []uint64` in go-tari-c29-solo-stratum): the 42-edge Cuckaroo29
// cycle being submitted. Absent (omitempty) on every SHA3X submit,
// which never carries this field on the real wire either.
type SubmitRequest struct {
	ID     string   `json:"id"`
	JobID  string   `json:"job_id"`
	Nonce  string   `json:"nonce"`
	POW    []uint64 `json:"pow,omitempty"`
	Result string   `json:"result"`

	// WorkerNonce and PoolNonce are the real, camelCase (NOT
	// snake_case) wire params an XNP-class multi-tier proxy client
	// sends on every ALGO_RXM submit — confirmed from a live wire
	// capture this session:
	//
	//	C->S submit: {"id":87,"jsonrpc":"2.0","method":"submit","params":{"job_id":"...","nonce":"59280000","result":"...","workerNonce":9,"poolNonce":9,"id":"..."}}
	//
	// and from the real reference's own submit handling
	// (lib/pool.js processShare, ~line 1026) and the real
	// blocktemplate_blob offsets those two values get patched into
	// (lib/coins/xmr.js's BlockTemplate ctor):
	//
	//	// lib/coins/xmr.js BlockTemplate ctor:
	//	this.clientNonceLocation = this.reserveOffset + 12;  // worker nonce write offset
	//	this.clientPoolLocation  = this.reserveOffset + 8;   // pool nonce write offset
	//
	//	// lib/pool.js processShare:
	//	let template = new Buffer(blockTemplate.buffer.length);
	//	if (!miner.proxy) {
	//	    blockTemplate.buffer.copy(template);
	//	    template.writeUInt32BE(job.extraNonce, blockTemplate.reserveOffset);
	//	} else {
	//	    blockTemplate.buffer.copy(template);
	//	    template.writeUInt32BE(job.extraNonce, blockTemplate.reserveOffset);
	//	    template.writeUInt32BE(params.poolNonce, job.clientPoolLocation);   // BIG-ENDIAN
	//	    template.writeUInt32BE(params.workerNonce, job.clientNonceLocation); // BIG-ENDIAN
	//	}
	//
	// Pointer-typed (like JobPayload's own ReservedOffset/
	// ClientNonceOffset/ClientPoolOffset above) specifically so
	// "field absent" (an ordinary xmrig-class RXM/RXT submit, which
	// has no code path that would ever send these) is distinguishable
	// from "field present with value 0" (a real proxy sub-worker
	// nonce that happens to be zero) — session.go's handleSubmit
	// gates the XNP-aware patching path on both being non-nil, not on
	// either being non-zero.
	WorkerNonce *uint32 `json:"workerNonce,omitempty"`
	PoolNonce   *uint32 `json:"poolNonce,omitempty"`
}

// JobPayload is the real job object shape (messages.MinerJobJSON in the
// reference, INCLUDING the "xn" extranonce field — see this file's doc
// comment for why this is required, not optional: graxil and other
// real miner software hard-requires it and panics on a missing/absent
// field). It is used both nested inside a login response's "job" field
// and as a standalone unsolicited "job" push's "params".
//
// Target/blob/job_id encodings (see minerTracking/structs.go's
// diffToTarget/GetJobJSON, ported exactly in jobPayload below):
//   - Blob is hex(job.Header), where Header is the real
//     MergeMiningHash pre-image material.
//   - Target is uint64(2^64-1)/difficulty, encoded as 8 raw bytes in
//     LITTLE-ENDIAN order, then hex-encoded as a string.
//   - JobID is hex(BlockHash)[0:16] — the first 16 HEX CHARACTERS of
//     the hex-encoded raw block hash.
//   - XN is the session's own assigned extranonce (job.go's
//     newSessionXN), 4 hex characters (2 bytes) — the SAME value on
//     every job sent to a given session, since xn is assigned once at
//     connect time — see the xn field's doc comment. Field name/tag
//     matches the legacy messages.MinerJobJSON.XNonce field exactly.
//   - SeedHash is RXT-only: the real Tari RandomX seed/key for this
//     job (job.go's Job.VmKey, taken directly from
//     GetNewBlockResult.VmKey), hex-encoded. Mirrors XMRig's own
//     stratum job-JSON convention for RandomX-family coins (a
//     "seed_hash" field the miner needs to (re)prime its own RandomX
//     VM against). Absent (omitempty) for SHA3X/C29 jobs, which have
//     no seed concept.
//
// XNP-PROXY SHAPE (BlocktemplateBlob/ReservedOffset/ClientNonceOffset/
// ClientPoolOffset): real nodejs-pool-sxmr (lib/pool.js ~211-231,
// ~478-548) gates an entirely different job-payload shape on a login
// "agent" string substring check (`agent.includes('xmr-node-proxy')`):
// an XNP-class multi-tier proxy client is handed the RAW, UNCONVERTED
// block template blob (not the hashing blob every other field above
// derives from) plus the real Monero get_block_template
// reserved_offset/client_nonce_offset/client_pool_offset byte offsets
// (lib/coins/xmr.js ~137-152: client_nonce_offset = reserved_offset+12,
// client_pool_offset = reserved_offset+8) — the receiving proxy does
// its OWN raw-blob-to-hashing-blob conversion and nonce/pool-tag
// patching downstream, this server does not attempt any blob
// conversion for this path. Field JSON key names are reused
// byte-for-byte from this repo's OWN existing upstream-client shape
// for this exact real convention (proxy/protocol.go's
// UpstreamJobPayload) rather than invented fresh.
//
// All four fields are pointer-typed with omitempty specifically so
// they are PROVABLY ABSENT from the wire for the overwhelming majority
// of real logins (anything whose agent does not contain the
// case-insensitive substring "xmr-node-proxy" — see IsXNPProxyAgent's
// own doc comment below for why this is case-insensitive) — see
// session.go's jobPayload for the detection/branch logic and
// protocol_xnp_test.go for a real marshaled-JSON non-regression diff
// proving this. Only
// ever populated for ALGO_RXM and ALGO_RXT jobs on an XNP-proxy-
// detected session; every other algo/session combination leaves all
// four nil.
//
// XNP-PROXY SHAPE, DIFFICULTY HALF (Difficulty/TargetDiff/
// TargetDiffHex): the same real proxy-class job shape also carries the
// difficulty under its own key names instead of a bare "target" —
// their absence here caused a real, confirmed "job difficulty of 1"
// production incident. Same pointer/omitempty/additive convention as
// the four offset fields; see those three fields' own doc comment
// below for the full legacy source citation, the affected client's
// exact fallback-to-1 code path, and the value each one carries.
type JobPayload struct {
	Algo     string `json:"algo"`
	Blob     string `json:"blob"`
	Height   uint64 `json:"height"`
	JobID    string `json:"job_id"`
	Target   string `json:"target"`
	XN       string `json:"xn,omitempty"`
	SeedHash string `json:"seed_hash,omitempty"`

	// BlocktemplateBlob is the hex-encoded RAW, UNCONVERTED Monero/Tari
	// block template blob for an XNP-proxy-detected RXM/RXT job — see
	// this type's XNP-PROXY SHAPE doc comment above. For RXM this is
	// genuinely distinct from Blob (job.go's Job.RawTemplateBlob, the
	// real monerod blocktemplate_blob, vs. Blob's already-converted
	// blockhashing_blob). For RXT there is no real raw-template/
	// hashing-blob distinction in Tari's protocol (see session.go's
	// jobPayload RXT branch doc comment for the full investigation
	// finding), so it is set numerically identical to Blob there,
	// included only for shape-parity with the RXM convention.
	BlocktemplateBlob *string `json:"blocktemplate_blob,omitempty"`

	// ReservedOffset is the real Monero get_block_template
	// reserved_offset (job.go's Job.ReservedOffset, itself parsed from
	// monerod's own result.ReservedOffset in monero_node.go) for an
	// XNP-proxy-detected RXM job — the byte offset, within
	// BlocktemplateBlob, of the reserve_size-byte coinbase area a
	// multi-tier proxy is expected to patch its own sub-pool
	// extranonce/tag data into before forwarding. RXT-only: always
	// nil — Tari's protocol has no real analog of Monero's
	// reserve_size/coinbase-tx-reservation mechanism (confirmed: no
	// reserved coinbase-extra byte range is ever returned by the Tari
	// base node's GetNewBlockResult/MinerData), so fabricating a value
	// here for RXT would be dishonest, not just harmlessly redundant —
	// see session.go's jobPayload RXT branch doc comment.
	ReservedOffset *int `json:"reserved_offset,omitempty"`

	// ClientNonceOffset is reserved_offset+12 for an XNP-proxy-detected
	// RXM job (lib/coins/xmr.js ~137-152's real convention). For RXT it
	// is instead the real, already-existing rxtXmrigNonceOffset
	// constant (39) — the one genuinely meaningful byte offset a
	// multi-tier RXT proxy would need to patch a sub-miner's nonce into
	// before forwarding (see rxt.go's rxtXmrigNonceOffset doc comment
	// for the confirmed-from-XMRig's-real-source provenance of that
	// constant) — NOT reserved_offset-derived, since RXT has no
	// reserved_offset concept at all (see ReservedOffset's doc
	// comment).
	ClientNonceOffset *int `json:"client_nonce_offset,omitempty"`

	// ClientPoolOffset is reserved_offset+8 for an XNP-proxy-detected
	// RXM job (lib/coins/xmr.js ~137-152). RXT-only: always nil, same
	// rationale as ReservedOffset above — there is no real reserved
	// coinbase area for RXT to report an offset within.
	ClientPoolOffset *int `json:"client_pool_offset,omitempty"`

	// Difficulty, TargetDiff, and TargetDiffHex are the difficulty half
	// of the SAME real XNP-proxy job shape as the four offset fields
	// above, and their absence was the confirmed, mechanical root cause
	// of a real production incident: a MoneroOcean-fork
	// xmr-node-proxy user reported "getting a job difficulty of 1" from
	// this leaf.
	//
	// The real legacy reference's proxy-class cachedJob (nodejs-pool-
	// sxmr lib/pool.js, Miner.getJob ~654-736 — the exact shape put on
	// the wire to an XNP-class client) carries NO bare "target" key at
	// all; it uses these three instead:
	//
	//	this.cachedJob = {
	//	    blocktemplate_blob:  blob,
	//	    difficulty:          activeBlockTemplate.difficulty,
	//	    height:              activeBlockTemplate.height,
	//	    reserved_offset:     activeBlockTemplate.reserveOffset,
	//	    client_nonce_offset: activeBlockTemplate.clientNonceLocation,
	//	    client_pool_offset:  activeBlockTemplate.clientPoolLocation,
	//	    seed_hash:           ...,
	//	    target_diff:         this.difficulty,
	//	    target_diff_hex:     this.diffHex,
	//	    job_id:              newJob.id,
	//	    id:                  this.id,
	//	    blockHash:           activeBlockTemplate.idHash
	//	};
	//
	// and every xmr-node-proxy-family client reads exactly those keys,
	// never a bare "target", for a proxy-class upstream connection:
	// the original Snipa22/xmr-node-proxy's lib/xmr.js and the affected
	// user's MoneroOcean/xmr-node-proxy fork's coins/template.js
	// (MasterBlockTemplate ctor) both take template.target_diff /
	// template.difficulty directly. This repo's OWN leaf-proxy is that
	// same class of client on the other end of this same hop and does
	// the identical thing — see proxy/protocol.go's UpstreamJobPayload
	// (`Difficulty uint64 \`json:"difficulty"\``, `TargetDiff uint64
	// \`json:"target_diff"\``, `TargetDiffHex string
	// \`json:"target_diff_hex,omitempty"\``), ported field-for-field
	// from lib/xmr.js.
	//
	// The MoneroOcean fork's own normalizeDifficulty helper is where
	// the incident's "1" came from:
	//
	//	function normalizeDifficulty(value, fallback = 1) {
	//	    const numericValue = Number(value);
	//	    if (Number.isFinite(numericValue) && numericValue > 0) return Math.max(1, Math.floor(numericValue));
	//	    const fallbackValue = Number(fallback);
	//	    if (Number.isFinite(fallbackValue) && fallbackValue > 0) return Math.max(1, Math.floor(fallbackValue));
	//	    return 1;
	//	}
	//
	// called as normalizeDifficulty(template.target_diff,
	// this.difficulty) where this.difficulty itself came from
	// normalizeDifficulty(template.difficulty). With neither key ever
	// emitted, BOTH calls got undefined and fell through to the final
	// hardcoded `return 1`.
	//
	// Values (see session.go's jobPayload, both here and in
	// internal/leaflib/direct):
	//   - Difficulty and TargetDiff are BOTH the session's own real,
	//     current stamped difficulty (job.StaticDifficulty) — the same
	//     value Target above is derived from. Legacy itself sends one
	//     plain numeric difficulty under two different keys
	//     (`target_diff: this.difficulty`), so these deliberately carry
	//     the identical value rather than two separately-computed ones.
	//   - TargetDiffHex is the byte-for-byte SAME hex string already
	//     computed for Target on the SAME job (legacy:
	//     `target_diff_hex: this.diffHex`, and this.diffHex is the
	//     identical value this.getTargetHex() produces for `target`
	//     too) — two wire key names for one encoding, NOT two different
	//     width/endianness encodings.
	//
	// Pointer-typed with omitempty on the SAME convention as the four
	// offset fields above: nil, and provably absent from the marshaled
	// wire JSON, for every non-XNP-proxy session (see
	// protocol_xnp_test.go's real byte-diff non-regression tests). And
	// like those four, these are strictly ADDITIVE — Target is left
	// completely unchanged and always present, since ordinary
	// xmrig-class clients still need it.
	Difficulty    *uint64 `json:"difficulty,omitempty"`
	TargetDiff    *uint64 `json:"target_diff,omitempty"`
	TargetDiffHex *string `json:"target_diff_hex,omitempty"`
}

// xnpProxyAgentSubstring is the lowercase substring real
// nodejs-pool-sxmr gates its own proxy-vs-ordinary-miner job-payload
// shape on (lib/pool.js ~211-231: `if (agent &&
// agent.includes('xmr-node-proxy')) { this.proxy = true; }`). The
// legacy reference's own check is case-sensitive; this leaf's
// IsXNPProxyAgent below deliberately matches case-INsensitively
// instead, per explicit product-owner direction — see that function's
// doc comment for the full rationale. This constant itself stays
// lowercase; IsXNPProxyAgent lowercases the input agent string before
// comparing against it.
const xnpProxyAgentSubstring = "xmr-node-proxy"

// IsXNPProxyAgent reports whether agent (a login's self-reported
// LoginRequest.Agent string, e.g. "xmr-node-proxy/0.0.3") identifies
// the connecting client as an XNP-class multi-tier proxy, matching the
// xnpProxyAgentSubstring literal CASE-INSENSITIVELY (agent is
// lowercased via strings.ToLower before the strings.Contains check).
//
// This is a DELIBERATE divergence from the real legacy nodejs-pool-sxmr
// reference, which gates the identical detection on JavaScript's
// case-sensitive String.prototype.includes
// (`agent.includes('xmr-node-proxy')`) — under that reference, an
// agent like "XMR-NODE-PROXY/0.0.3" would NOT be detected as a proxy.
// This leaf's product owner (Alex) explicitly directed broadening this
// check ("Remove case sensitive for the XNP check."), so it now also
// matches "XMR-NODE-PROXY", "Xmr-Node-Proxy", and any other casing of
// the same substring, anywhere in the agent string.
//
// Exported so both leaf-solo's own session.go and leaf-direct's
// session.go (which has no protocol.go/job.go of its own — see this
// package's doc comment on why leaf-direct reuses these types directly
// rather than duplicating them) share one single implementation of
// this detection, rather than two copies that could drift.
func IsXNPProxyAgent(agent string) bool {
	return strings.Contains(strings.ToLower(agent), xnpProxyAgentSubstring)
}

// IsGenericProxyAgent reports whether agent contains the substring
// "proxy" case-insensitively, EXCLUDING agents already identified as
// XNP (xmr-node-proxy) by IsXNPProxyAgent -- XNP has its own, separate,
// untouched detection and handling above. This is a broader, generic
// "self-identifies as some kind of proxy" signal, additive to (never a
// replacement for) IsXNPProxyAgent, used ONLY to unpin a fixed-diff
// request from its permanent pin (never to deny/alter the requested
// starting difficulty itself) -- see
// LoginFields.GenericProxyExemptFromFixedDiffPin (loginfields.go) for
// the call site.
func IsGenericProxyAgent(agent string) bool {
	if IsXNPProxyAgent(agent) {
		return false
	}
	return strings.Contains(strings.ToLower(agent), "proxy")
}

// LoginResult is the real login response's nested "result" object.
type LoginResult struct {
	ID     string     `json:"id"`
	Job    JobPayload `json:"job"`
	Status string     `json:"status"`
}

// LoginResponse is the real "login" response envelope
// (messages.MinerRPCLoginResponse in the reference) — note the
// top-level "status" field duplicated alongside the nested one, ported
// exactly as the reference has it.
type LoginResponse struct {
	ID      int         `json:"id"`
	JsonRPC string      `json:"jsonrpc"`
	Result  LoginResult `json:"result"`
	Status  string      `json:"status"`
}

// JobPush is the real unsolicited new-job push envelope
// (messages.MinerRPCPush in the reference).
type JobPush struct {
	JsonRPC string     `json:"jsonrpc"`
	Method  string     `json:"method"`
	Params  JobPayload `json:"params"`
}

// RPCError, ShareResult, ErrorResponse, ShareResponse,
// LegacyErrorResponse, and LegacyShareResponse are now defined ONCE,
// in internal/leaflib (see leaflib/wireshape.go), and aliased here so
// every existing reference to solo.RPCError/solo.ShareResponse/etc.
// (including direct's and proxy's own, which import these directly)
// keeps working completely unchanged. EXTRACTED per the real,
// repeated production incident this exact wire-shape logic caused
// (see commits b3c8716, 0339d81, 0253b57 in this repo's history: a
// bugfix landing in solo and having to be manually, separately
// re-applied to direct) — see leaflib.IsLegacyWireAlgo/
// WriteGeneralResponse/WriteShareResponse for the shared dispatch
// logic that now lives in exactly one place, and each of these
// aliased types' full original doc comments there.
type (
	RPCError            = leaflib.RPCError
	ShareResult         = leaflib.ShareResult
	ErrorResponse       = leaflib.ErrorResponse
	ShareResponse       = leaflib.ShareResponse
	LegacyErrorResponse = leaflib.LegacyErrorResponse
	LegacyShareResponse = leaflib.LegacyShareResponse
)
