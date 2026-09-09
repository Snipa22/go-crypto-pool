// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"encoding/json"
	"strings"
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
// Deliberately still NOT ported: "." / "+" login-address suffix parsing
// for payment-ID/custom-difficulty (go-crypto-pool's solo leaf uses one
// static, leaf-configured difficulty for everyone — see
// JobManagerConfig.StaticDifficulty in job.go) — the address is taken
// as-is.
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
// of real logins (anything whose agent does not contain the literal,
// case-sensitive substring "xmr-node-proxy") — see session.go's
// jobPayload for the detection/branch logic and protocol_xnp_test.go
// for a real marshaled-JSON non-regression diff proving this. Only
// ever populated for ALGO_RXM and ALGO_RXT jobs on an XNP-proxy-
// detected session; every other algo/session combination leaves all
// four nil.
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
}

// xnpProxyAgentSubstring is the exact, case-sensitive substring real
// nodejs-pool-sxmr gates its own proxy-vs-ordinary-miner job-payload
// shape on (lib/pool.js ~211-231: `if (agent &&
// agent.includes('xmr-node-proxy')) { this.proxy = true; }`).
const xnpProxyAgentSubstring = "xmr-node-proxy"

// IsXNPProxyAgent reports whether agent (a login's self-reported
// LoginRequest.Agent string, e.g. "xmr-node-proxy/0.0.3") identifies
// the connecting client as an XNP-class multi-tier proxy, using the
// SAME case-sensitive substring check the real reference uses
// (JavaScript's String.prototype.includes is case-sensitive — this
// deliberately uses strings.Contains, NOT strings.EqualFold or any
// other case-insensitive comparison, to match that exactly: an agent
// containing "XMR-NODE-PROXY" in the wrong case must NOT be detected
// as a proxy). Exported so both leaf-solo's own session.go and
// leaf-direct's session.go (which has no protocol.go/job.go of its
// own — see this package's doc comment on why leaf-direct reuses
// these types directly rather than duplicating them) share one single
// implementation of this detection, rather than two copies that could
// drift.
func IsXNPProxyAgent(agent string) bool {
	return strings.Contains(agent, xnpProxyAgentSubstring)
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

// RPCError is the real object-or-null error shape xmrig's parseResponse
// requires (error.IsObject() must be true, or error must be absent/null;
// a bare string is silently treated as "not an error").
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ShareResult is the real object shape xmrig's parseResponse requires for
// result on a submit response (result.IsObject() must be true for
// handleSubmitResponse to ever be called; a bare bool is silently dropped).
type ShareResult struct {
	Status string `json:"status"`
}

// ShareResponse is the real submit/share response shape
// (messages.MinerRPCShareResponse in the reference), corrected to the
// real xmrig-compatible wire shape (see Client.cpp::parseResponse and
// nodejs-pool/lib/pool.js's sendReply): on accept, Error is literal
// `null` and Result is an object `{"status":"OK"}`; on reject, Error
// is an object `{"code":-1,"message":"..."}` and the "result" key is
// entirely absent from the wire (omitempty). A bare boolean/string
// pair (the previous shape here) is NOT recognized by real miners.
//
// ALGO-SCOPED: this shape is for RXT/RXM ONLY (the real xmrig-class
// client family — confirmed working, per Alex: "Lolminer is working
// with sha3x fine" — NOTE: that report predates the SHA3X regression
// below and no longer describes SHA3X's current dispatch, see
// LegacyShareResponse). C29's own real ecosystem client (lolMiner/
// graxil29 against go-tari-c29-solo-stratum's actual wire dialect)
// does NOT tolerate this shape — confirmed via a real production
// regression: lolMiner's own diagnostic "Received a defect stratum
// message: conversion of data to type 'b' failed" (lolMiner's error
// for a missing/wrong-shaped boolean field) appeared on the live C29
// port immediately after this shape was introduced, and Alex
// confirmed "it was working fine before the changes". The identical
// regression was later confirmed against SHA3X too (Alex's lolMiner
// client mining SHA3X hit the exact same "conversion of data to type
// 'b' failed" defect against this object/null shape). C29 and SHA3X
// use LegacyShareResponse below instead — see session.go's
// writeShareResponse for the algo dispatch.
type ShareResponse struct {
	ID      int          `json:"id"`
	JsonRPC string       `json:"jsonrpc"`
	Error   *RPCError    `json:"error"`            // NOT omitempty: on accept this must be literal `null`, never omitted (matches nodejs-pool's `error: error ? {...} : null`, which always includes the key)
	Result  *ShareResult `json:"result,omitempty"` // omitempty IS correct here: on reject the real reference has NO "result" key at all
}

// ErrorResponse is the real general-purpose response shape
// (messages.MinerRPCResponse in the reference), used for login errors,
// unknown methods, keepalive acks, and anything else that is not a
// share/submit outcome. Result here is a STRING, not a boolean (this
// field is unaffected by the ShareResponse wire-shape bug fix). Error
// follows the same object-or-null rule as ShareResponse above.
//
// ALGO-SCOPED: same RXT/RXM-only scoping as ShareResponse above
// — see that type's doc comment. C29 and SHA3X use LegacyErrorResponse
// below.
type ErrorResponse struct {
	ID      int       `json:"id"`
	JsonRPC string    `json:"jsonrpc"`
	Error   *RPCError `json:"error"` // NOT omitempty — same object-or-null rule as ShareResponse
	Result  string    `json:"result"`
}

// LegacyShareResponse is the pre-PR-#56 submit/share response shape,
// preserved verbatim for ALGO_C29 and ALGO_SHA3X. Restored EXACTLY from
// this repo's own git history immediately prior to PR #56 (commit
// 0c01157, the direct parent of b3c8716 "fix(leaflib): send real
// object-shaped error/result in JSON-RPC submit responses") — NOT
// reconstructed from memory. This shape matches C29's own real, actual
// ecosystem client dialect: go-tari-c29-solo-stratum's
// messages.MinerRPCShareResponse (github.com/Snipa22/go-tari-c29-solo-stratum,
// subsystems/messages/minerStructs.go) field-for-field:
//
//	type MinerRPCShareResponse struct {
//		ID      int    `json:"id"`
//		JsonRPC string `json:"jsonrpc"`
//		Error   string `json:"error,omitempty"`
//		Result  bool   `json:"result"`
//	}
//
// It ALSO matches SHA3X's own real reference implementation's dialect
// exactly, field-for-field: go-tari-sha3x-solo-stratum's
// subsystems/messages/minerStructs.go MinerRPCShareResponse has the
// identical shape (bare bool Result `json:"result"`, bare string Error
// `json:"error,omitempty"`) — SHA3X's real ecosystem clients (lolMiner/
// graxil-class) require this dialect just as much as C29's do, and the
// production regression confirming this is identical to C29's: Alex's
// lolMiner client mining SHA3X hit "Received a defect stratum message:
// conversion of data to type 'b' failed" against the object/null
// ShareResponse shape, the same defect as the C29/PR #57 regression.
//
// Result is a bare BOOLEAN (not an object) and Error is a bare STRING
// (not an object/null) — the genuinely different, older wire dialect
// lolMiner/graxil-class C29/SHA3X GPU miners require. See
// ShareResponse's doc comment above for the regression this fixes.
type LegacyShareResponse struct {
	ID      int    `json:"id"`
	JsonRPC string `json:"jsonrpc"`
	Error   string `json:"error,omitempty"`
	Result  bool   `json:"result"`
}

// LegacyErrorResponse is the pre-PR-#56 general-purpose response
// shape, preserved verbatim for ALGO_C29 and ALGO_SHA3X — same
// provenance and rationale as LegacyShareResponse above. Matches
// go-tari-c29-solo-stratum's messages.MinerRPCResponse exactly (bare
// string Error, bare string Result — Result here was never a boolean,
// on either dialect, so only Error's shape actually differs by algo in
// practice; this type is kept for exact wire-format parity with the
// real C29 reference implementation and so the C29/SHA3X path never
// touches the RXT/RXM-only *RPCError type at all). It also matches
// SHA3X's own real reference implementation exactly:
// go-tari-sha3x-solo-stratum's subsystems/messages/minerStructs.go
// MinerRPCResponse has the identical shape (Result string
// `json:"result"`, Error string `json:"error,omitempty"`) — SHA3X's
// own real dialect requires this shape too, same as C29's.
type LegacyErrorResponse struct {
	ID      int    `json:"id"`
	JsonRPC string `json:"jsonrpc"`
	Error   string `json:"error,omitempty"`
	Result  string `json:"result"`
}
