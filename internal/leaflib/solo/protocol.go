// Copyright and license: see repository LICENSE (MIT).
package solo

import "encoding/json"

// Wire protocol: newline-delimited JSON objects in both directions.
// This is a new, intentionally minimal protocol for go-crypto-pool (not
// required to match the legacy go-tari-sha3x-solo-stratum JSON-RPC wire
// format byte-for-byte), loosely inspired by it:
//
//   Client -> Server (request):
//     {"id":1,"method":"login","params":{"address":"...","worker":"rig1"}}
//     {"id":2,"method":"getjob"}
//     {"id":3,"method":"submit","params":{"job_id":"...","nonce":"..hex.."}}
//
//   Server -> Client (response to a request, echoes id):
//     {"id":1,"result":{...},"error":null}
//
//   Server -> Client (unsolicited push, id omitted/zero):
//     {"method":"job","params":{...}}

// Request is one client->server line.
type Request struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is one server->client reply to a Request (Method omitted; ID
// echoes the request it answers).
type Response struct {
	ID     int    `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Push is one server->client unsolicited message (new job broadcast).
type Push struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

// LoginParams is the "login" request body: the address rewards/shares
// are attributed to locally (diagnostic only in solo mode — there is no
// backend payout scheme, see cmd/leaf-solo's doc comment) and an
// optional worker/rig name.
type LoginParams struct {
	Address string `json:"address"`
	Worker  string `json:"worker,omitempty"`
}

// JobPayload is the wire shape of a Job (job.go) pushed to a miner,
// either as part of a login response or an unsolicited "job" push.
type JobPayload struct {
	JobID      string `json:"job_id"`
	Height     uint64 `json:"height"`
	Header     string `json:"header"` // hex-encoded merge-mining-hash pre-image material
	Difficulty uint64 `json:"difficulty"`
	Algo       string `json:"algo"`
}

// LoginResult is the "login" response body.
type LoginResult struct {
	Status    string     `json:"status"`
	SessionID string     `json:"session_id"`
	Job       JobPayload `json:"job"`
}

// SubmitParams is the "submit" request body: the job this proof is
// against, and the nonce the miner found, hex-encoded (little-endian
// uint64, matching internal/leaflib/validator.SHA3XValidator's expected
// nonce encoding via SHA3XProof.Nonce — see sha3x.go).
type SubmitParams struct {
	JobID string `json:"job_id"`
	Nonce string `json:"nonce"`
}

// Share-outcome status strings returned in a "submit" Response.Result.
const (
	StatusOK            = "ok"             // valid share, below block difficulty
	StatusBlockFound    = "block_found"    // valid share, met block difficulty, submitted
	StatusRejected      = "rejected"       // invalid share (bad nonce encoding, wrong job, or failed PoW check)
	StatusBlockRejected = "block_rejected" // met block difficulty locally but the node rejected SubmitBlock
)

// SubmitResult is the "submit" response body.
type SubmitResult struct {
	Status     string `json:"status"`
	Difficulty uint64 `json:"difficulty"`
}
