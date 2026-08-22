// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
)

// Downstream (miner-facing) wire dialect: leaf-proxy's downstream
// miners speak the EXACT SAME real Monero-family JSON-RPC 2.0 stratum
// dialect leaf-solo's miners already do (login/getjob/submit,
// LoginResponse/JobPush/ShareResponse/ErrorResponse envelopes — see
// internal/leaflib/solo/protocol.go's own doc comment for the full
// wire-shape confirmation). There is nothing algo-specific about that
// envelope/shape that differs for RandomX/XMR, so leaf-proxy directly
// REUSES those types rather than redefining byte-identical structs —
// see this package's session.go for where each is used.
type (
	Request       = solo.Request
	LoginRequest  = solo.LoginRequest
	SubmitRequest = solo.SubmitRequest
	JobPayload    = solo.JobPayload
	LoginResult   = solo.LoginResult
	LoginResponse = solo.LoginResponse
	JobPush       = solo.JobPush
	ShareResponse = solo.ShareResponse
	ErrorResponse = solo.ErrorResponse
)

// Upstream (pool-facing) wire dialect: leaf-proxy is the STRATUM
// CLIENT here (the inverse role from leaf-solo/downstream — see
// upstream.go's doc comment), emulating an "advanced" XMR-Node-Proxy
// mining client to a real upstream Monero-family pool
// (pool.supportxmr.com). The outbound envelope (id/jsonrpc/method/
// params) is the identical JSON-RPC 2.0 shape as solo.Request, so
// UpstreamClient constructs outbound requests using solo.Request
// directly (see upstream.go). The INBOUND shapes below are genuinely
// different from solo's own miner-facing LoginResponse/JobPush
// (confirmed from the real reference, lib/xmr.js's
// BlockTemplate/MasterBlockTemplate constructors): a pool's job object
// carries reserved_offset/client_nonce_offset/client_pool_offset/
// target_diff/target_diff_hex fields that never appear on the
// leaf-solo miner-facing wire, and vice versa (xn has no upstream
// pool-side equivalent) — these are NOT interchangeable structs
// despite superficially similar field names like "blob"/"height"/
// "job_id"/"seed_hash", so they are defined here rather than
// shoehorned into solo.JobPayload.

// UpstreamJobPayload is the real upstream pool job object shape,
// ported field-for-field from lib/xmr.js's
// BlockTemplate/MasterBlockTemplate constructors:
//
//	this.blob = template.blocktemplate_blob;
//	this.difficulty = template.difficulty;
//	this.height = template.height;
//	this.reservedOffset = template.reserved_offset;
//	this.workerOffset = template.worker_offset; // == client_nonce_offset on the MasterBlockTemplate variant
//	this.targetDiff = template.target_diff;
//	this.targetHex = template.target_diff_hex;
//	this.seedHash = template.seed_hash ...
//
// This same shape is used whether the job arrived nested inside a
// login response's "job" field, as a bare "getjob" result, or as an
// unsolicited "job" method push (handleNewBlockTemplate) — all three
// carry an object with these same keys in the real protocol.
type UpstreamJobPayload struct {
	JobID             string `json:"job_id,omitempty"`
	BlocktemplateBlob string `json:"blocktemplate_blob,omitempty"`
	Blob              string `json:"blob,omitempty"` // some pools (e.g. pool.supportxmr.com) key the same field as "blob" instead of "blocktemplate_blob" -- see UpstreamJobPayload doc comment
	Difficulty        uint64 `json:"difficulty"`
	Height            uint64 `json:"height"`
	ReservedOffset    *int   `json:"reserved_offset,omitempty"`     // pointer: distinguishes "genuinely offset 0" from "not published at all" -- CONFIRMED not published by pool.supportxmr.com's real job responses (see this pass's live smoke test capture)
	WorkerOffset      *int   `json:"worker_offset,omitempty"`       // == client_nonce_offset extension, absent unless the pool grants it
	ClientNonceOffset *int   `json:"client_nonce_offset,omitempty"` // some pool implementations use this name instead of worker_offset
	ClientPoolOffset  *int   `json:"client_pool_offset,omitempty"`
	TargetDiff        uint64 `json:"target_diff"`
	TargetDiffHex     string `json:"target_diff_hex,omitempty"`
	Target            string `json:"target,omitempty"` // pool.supportxmr.com's real job field: a hex-encoded LITTLE-ENDIAN share target, the standard miner-facing shape (NOT the daemon's own target_diff/target_diff_hex pair) -- see applyJob's doc comment for how this leaf derives a usable target_diff from it when target_diff itself is absent
	SeedHash          string `json:"seed_hash,omitempty"`
	Algo              string `json:"algo,omitempty"`
}

// UpstreamLoginResult is the real "login" response's nested "result"
// object shape (proxy.js's handlePoolMessage: `pool.id =
// jsonData.result.id; handleNewBlockTemplate(jsonData.result.job, ...)`).
type UpstreamLoginResult struct {
	ID     string             `json:"id"`
	Job    UpstreamJobPayload `json:"job"`
	Status string             `json:"status,omitempty"`
}

// UpstreamRPCError is the real JSON-RPC 2.0 error object shape a pool
// sends on a login/getjob/submit failure (proxy.js's
// handlePoolMessage: `jsonData.error.message`).
type UpstreamRPCError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message"`
}

// UpstreamResponse is the generic inbound response envelope for
// anything that is NOT an unsolicited "job" push — i.e. a reply to one
// of OUR outbound requests (login/getjob/submit), correlated by ID
// against UpstreamClient's own pending-request table (mirrors
// proxy.js's `pool.sendLog[jsonData.id]` lookup). Result is left as
// json.RawMessage because its real shape depends entirely on which
// outbound method this is replying to (login -> UpstreamLoginResult,
// getjob -> UpstreamJobPayload directly, submit -> no meaningful
// result payload at all) — exactly mirroring the real reference's own
// dispatch-by-original-method-name logic in handlePoolMessage.
type UpstreamResponse struct {
	ID      int               `json:"id"`
	JsonRPC string            `json:"jsonrpc,omitempty"`
	Result  json.RawMessage   `json:"result,omitempty"`
	Error   *UpstreamRPCError `json:"error,omitempty"`
}

// UpstreamJobPush is the real unsolicited new-job push envelope a
// pool sends on tip movement (proxy.js's handlePoolMessage: `if
// (jsonData.method === 'job') handleNewBlockTemplate(jsonData.params, ...)`).
type UpstreamJobPush struct {
	JsonRPC string             `json:"jsonrpc,omitempty"`
	Method  string             `json:"method"`
	Params  UpstreamJobPayload `json:"params"`
}

// UpstreamSubmitParams is the real "submit" request's params shape
// sent TO the upstream pool (proxy.js's Pool.sendShare):
//
//	this.sendData('submit', {
//	    job_id: job.masterJobID,
//	    nonce: shareData.nonce,
//	    result: shareData.resultHash,
//	    workerNonce: shareData.workerNonce,
//	    poolNonce: job.poolNonce
//	});
//
// This is a genuinely different shape from solo.SubmitRequest (which
// additionally carries a session "id" and, for C29, a "pow" cycle —
// neither of which exists on this upstream-facing submit).
type UpstreamSubmitParams struct {
	JobID       string `json:"job_id"`
	Nonce       string `json:"nonce"`
	Result      string `json:"result"`
	WorkerNonce uint32 `json:"workerNonce,omitempty"`
	PoolNonce   uint32 `json:"poolNonce,omitempty"`
}

// UpstreamLoginParams is the real "login" request's params shape sent
// TO the upstream pool (proxy.js's Pool.login):
//
//	this.sendData('login', {
//	    login: this.username,
//	    pass: this.password,
//	    agent: 'xmr-node-proxy/0.0.3'
//	});
type UpstreamLoginParams struct {
	Login string `json:"login"`
	Pass  string `json:"pass"`
	Agent string `json:"agent"`
}
