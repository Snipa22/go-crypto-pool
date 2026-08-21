// Copyright and license: see repository LICENSE (MIT).
package solo

import "encoding/json"

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
type JobPayload struct {
	Algo     string `json:"algo"`
	Blob     string `json:"blob"`
	Height   uint64 `json:"height"`
	JobID    string `json:"job_id"`
	Target   string `json:"target"`
	XN       string `json:"xn,omitempty"`
	SeedHash string `json:"seed_hash,omitempty"`
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

// ShareResponse is the real submit/share response shape
// (messages.MinerRPCShareResponse in the reference) — Result is a bare
// BOOLEAN. This is a genuinely different shape from ErrorResponse
// below (whose Result is a string); real miners parse these
// differently, so they must not be conflated.
type ShareResponse struct {
	ID      int    `json:"id"`
	JsonRPC string `json:"jsonrpc"`
	Error   string `json:"error,omitempty"`
	Result  bool   `json:"result"`
}

// ErrorResponse is the real general-purpose response shape
// (messages.MinerRPCResponse in the reference), used for login errors,
// unknown methods, keepalive acks, and anything else that is not a
// share/submit outcome. Result here is a STRING, not a boolean.
type ErrorResponse struct {
	ID      int    `json:"id"`
	JsonRPC string `json:"jsonrpc"`
	Error   string `json:"error,omitempty"`
	Result  string `json:"result"`
}
