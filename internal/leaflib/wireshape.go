// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"encoding/json"
	"log"
	"sync"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// This file is the EXTRACTION target for the exact bug class that
// motivated this dispatch: a real, live-production wire-shape
// regression (see commits b3c8716, 0339d81, 0253b57 in this repo's
// history) that had to be independently rediscovered/re-applied
// across internal/leaflib/{solo,direct}/session.go because the two
// packages each carried their own hand-copied writeGeneralResponse/
// writeShareResponse dispatch and response-shape structs. There is
// now exactly ONE implementation of the algo-conditional wire-shape
// dispatch (WriteGeneralResponse/WriteShareResponse below) and of the
// response-shape wire types themselves (RPCError...LegacyShareResponse
// below) — solo/protocol.go now type-aliases these rather than
// redefining them (direct and proxy already referenced solo's copies
// directly/via alias, so they pick up this change for free).
//
// Also extracted here: writeJSON (WriteJSON), the unsolicited-job-push
// envelope (PushJob), the per-session "was this exact job already
// delivered" dedup check (AlreadyDelivered — Alex's live "duplicate
// jobs down the wire" report), and the per-session bounded job-
// ownership history (JobHistory — the real, structural
// session-can-only-submit-against-its-own-jobs security boundary,
// ported identically into leaf-proxy from the start and now shared
// rather than each package keeping its own copy of the same bounded
// FIFO-with-eviction bookkeeping).

// IsLegacyWireAlgo reports whether algo requires the legacy bare-bool/
// bare-string wire shape (LegacyErrorResponse/LegacyShareResponse) —
// true for ALGO_C29 and ALGO_SHA3X, the two lolMiner/graxil-class
// dialects that do NOT tolerate the xmrig-compatible object/null shape
// (see LegacyShareResponse's doc comment for the full, confirmed-live
// regression history) — rather than the object/null shape
// (ErrorResponse/ShareResponse) every other algo (RXT/RXM, genuinely
// xmrig-family clients) requires.
func IsLegacyWireAlgo(algo poolpb.Algo) bool {
	return algo == poolpb.Algo_ALGO_C29 || algo == poolpb.Algo_ALGO_SHA3X
}

// RPCError is the real object-or-null error shape xmrig's
// parseResponse requires (error.IsObject() must be true, or error
// must be absent/null; a bare string is silently treated as "not an
// error").
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ShareResult is the real object shape xmrig's parseResponse requires
// for result on a submit response (result.IsObject() must be true for
// handleSubmitResponse to ever be called; a bare bool is silently
// dropped).
type ShareResult struct {
	Status string `json:"status"`
}

// ShareResponse is the real submit/share response shape, corrected to
// the real xmrig-compatible wire shape (Client.cpp::parseResponse and
// nodejs-pool/lib/pool.js's sendReply): on accept, Error is literal
// `null` and Result is an object `{"status":"OK"}`; on reject, Error
// is an object `{"code":-1,"message":"..."}` and the "result" key is
// entirely absent from the wire (omitempty).
//
// ALGO-SCOPED: this shape is for RXT/RXM ONLY (genuinely xmrig-family
// clients — see LegacyShareResponse for C29/SHA3X, which do NOT
// tolerate this shape; confirmed via a real production regression:
// lolMiner's "conversion of data to type 'b' failed" diagnostic).
type ShareResponse struct {
	ID      int          `json:"id"`
	JsonRPC string       `json:"jsonrpc"`
	Error   *RPCError    `json:"error"`            // NOT omitempty: on accept this must be literal `null`
	Result  *ShareResult `json:"result,omitempty"` // omitempty IS correct: on reject there is no "result" key at all
}

// ErrorResponse is the real general-purpose response shape, used for
// login errors, unknown methods, keepalive acks, and anything else
// that is not a share/submit outcome. Result here is a STRING, not a
// boolean. Error follows the same object-or-null rule as
// ShareResponse above.
//
// ALGO-SCOPED: same RXT/RXM-only scoping as ShareResponse above — see
// LegacyErrorResponse for C29/SHA3X.
type ErrorResponse struct {
	ID      int       `json:"id"`
	JsonRPC string    `json:"jsonrpc"`
	Error   *RPCError `json:"error"` // NOT omitempty — same object-or-null rule as ShareResponse
	Result  string    `json:"result"`
}

// LegacyShareResponse is the pre-PR-#56 submit/share response shape,
// preserved verbatim for ALGO_C29 and ALGO_SHA3X (both are
// lolMiner/graxil-class clients requiring this dialect — confirmed
// against both go-tari-c29-solo-stratum's and
// go-tari-sha3x-solo-stratum's own real
// messages.MinerRPCShareResponse: bare bool Result, bare string
// Error). Restored exactly from this repo's own git history
// immediately prior to PR #56 (commit 0c01157) — NOT reconstructed
// from memory. A real, live production regression (Alex: "Received a
// defect stratum message: conversion of data to type 'b' failed")
// confirmed both C29 and SHA3X require this bare shape, not the
// xmrig-compatible object/null ShareResponse shape above.
type LegacyShareResponse struct {
	ID      int    `json:"id"`
	JsonRPC string `json:"jsonrpc"`
	Error   string `json:"error,omitempty"`
	Result  bool   `json:"result"`
}

// LegacyErrorResponse is the pre-PR-#56 general-purpose response
// shape, preserved verbatim for ALGO_C29 and ALGO_SHA3X — same
// provenance and rationale as LegacyShareResponse above.
type LegacyErrorResponse struct {
	ID      int    `json:"id"`
	JsonRPC string `json:"jsonrpc"`
	Error   string `json:"error,omitempty"`
	Result  string `json:"result"`
}

// WriteJSON marshals v to JSON, appends a trailing newline (the wire
// protocol's newline-delimited-JSON framing), and writes it via mc.Write.
// A marshal error is logged (via logger, prefixed with prefix and
// sessionID) and nothing is written; a write error is silently
// swallowed — the connection is going away, and the caller's own read
// loop will observe the resulting read error/EOF and exit.
func WriteJSON(mc *ManagedConnection, logger *log.Logger, prefix, sessionID string, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		logger.Printf("%s: failed to marshal response for session %s: %v", prefix, sessionID, err)
		return
	}
	buf = append(buf, '\n')
	if err := mc.Write(buf); err != nil {
		_ = err
	}
}

// WriteGeneralResponse implements the shared, algo-conditional
// general-purpose-response wire-shape dispatch (see IsLegacyWireAlgo)
// — the exact logic that previously had to be hand-copied between
// solo.Session.writeGeneralResponse and direct.Session's identical
// method, and is now callable directly from leaf-proxy's own
// (never-legacy) Session too. write is the caller's own writeJSON
// (so the marshal/log-prefix/mc.Write plumbing above stays
// per-session).
func WriteGeneralResponse(write func(any), legacy bool, id int, errMsg, result string) {
	if legacy {
		write(LegacyErrorResponse{ID: id, JsonRPC: "2.0", Error: errMsg, Result: result})
		return
	}
	var rpcErr *RPCError
	if errMsg != "" {
		rpcErr = &RPCError{Code: -1, Message: errMsg}
	}
	write(ErrorResponse{ID: id, JsonRPC: "2.0", Error: rpcErr, Result: result})
}

// WriteShareResponse is WriteGeneralResponse's submit/share-response
// counterpart — see that function's doc comment for the full
// rationale, which applies identically here.
func WriteShareResponse(write func(any), legacy bool, id int, accepted bool, errMsg string) {
	if legacy {
		write(LegacyShareResponse{ID: id, JsonRPC: "2.0", Error: errMsg, Result: accepted})
		return
	}
	var rpcErr *RPCError
	var result *ShareResult
	if accepted {
		result = &ShareResult{Status: "OK"}
	} else {
		rpcErr = &RPCError{Code: -1, Message: errMsg}
	}
	write(ShareResponse{ID: id, JsonRPC: "2.0", Error: rpcErr, Result: result})
}

// jobPushEnvelope is the real unsolicited new-job push envelope
// (solo.JobPush's own shape: {"jsonrpc","method":"job","params":{...}}).
// Params is typed `any` here purely so PushJob below can accept any
// package's own concrete JobPayload-shaped value without this shared
// package needing to depend on one — encoding/json marshals an `any`
// field holding a struct value identically to that struct value typed
// directly, so this produces byte-identical wire JSON to each
// package's own (formerly hand-copied) JobPush{...} literal.
type jobPushEnvelope struct {
	JsonRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// PushJob implements the shared "send an unsolicited job push, but
// only to a logged-in session" gate every one of solo/direct/proxy's
// own pushJob methods duplicated identically. buildPayload is called
// (and its side effects — recording the job into this session's own
// job history, updating its delivery-dedup bookkeeping — take effect)
// ONLY when loggedIn is true, exactly preserving every existing
// pushJob's own short-circuit (a not-yet-logged-in session's pushJob
// call was always a complete no-op, including no recordJob call).
func PushJob(write func(any), loggedIn bool, buildPayload func() any) {
	if !loggedIn {
		return
	}
	write(jobPushEnvelope{JsonRPC: "2.0", Method: "job", Params: buildPayload()})
}

// AlreadyDelivered reports whether a job identified by (jobID,
// jobDifficulty) is identical to the last job actually delivered to a
// session, as tracked by that session's own
// (lastDeliveredJobID, lastDeliveredDifficulty) — ported from
// solo.Session.alreadyDelivered (the original, most-detailed version
// of this bug fix's rationale — Alex's live "we're sending duplicate
// jobs down the wire" report): job.ID alone is not enough because it
// is derived purely from the block hash and does not depend on
// difficulty, so a dedup keyed on ID alone would silently swallow a
// legitimate vardiff-driven difficulty/target update sharing the same
// job.ID as the last push.
//
// Callers pass jobID == "" for "no job" (mirrors every existing
// alreadyDelivered's own `if job == nil { return false }` guard,
// which this function reproduces via the lastDeliveredJobID == ""
// check below never matching an empty jobID either).
func AlreadyDelivered(jobID string, jobDifficulty uint64, lastDeliveredJobID string, lastDeliveredDifficulty uint64) bool {
	if jobID == "" || lastDeliveredJobID == "" || lastDeliveredJobID != jobID {
		return false
	}
	return lastDeliveredDifficulty == jobDifficulty
}

// JobHistory is the shared, generic implementation of the per-session
// bounded job-ownership history (jobList/jobLog in solo/direct's own
// git history; ported identically into leaf-proxy from the start) —
// the REAL, structural security boundary a submit's job_id is checked
// against: a session can only ever look up a job_id that was actually
// recorded into ITS OWN JobHistory (see Own below), never any other
// session's or any shared/global map (see solo.Session's own SECURITY
// FIX doc comment, in git history, for the full incident this
// originally fixed). J is deliberately just `comparable` (not an
// interface requiring accessor methods): callers already have their
// own job's ID string on hand at every call site, so no reflection
// or method-set constraint on the job type itself is needed.
type JobHistory[J comparable] struct {
	mu   sync.Mutex
	list []string     // oldest-first job_ids actually issued
	log  map[string]J // job_id -> job, mirrors list
	size int          // bound on len(list)
}

// defaultJobHistorySize mirrors every existing package's own
// defaultSessionJobHistorySize/defaultProxySessionJobHistorySize
// constant (8) — see solo.Session's git history doc comment for the
// full "why 8" rationale (tolerating a brief multi-push race window
// without growing unbounded).
const defaultJobHistorySize = 8

// NewJobHistory constructs a JobHistory bounded to size entries
// (defaultJobHistorySize if size <= 0).
func NewJobHistory[J comparable](size int) *JobHistory[J] {
	if size <= 0 {
		size = defaultJobHistorySize
	}
	return &JobHistory[J]{log: make(map[string]J), size: size}
}

// Record inserts job under id, evicting the oldest entry once the
// bounded history size is exceeded. A zero-value job (e.g. a nil
// *Job) is a documented no-op, mirroring every existing recordJob's
// own `if job == nil { return }` guard. If id is already present
// (e.g. RestampDifficulty producing a new *Job with the SAME ID), the
// stored value is refreshed in place without growing the history, so
// a restamp doesn't consume a slot.
func (h *JobHistory[J]) Record(id string, job J) {
	var zero J
	if job == zero {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.log == nil {
		h.log = make(map[string]J)
	}
	if _, exists := h.log[id]; !exists {
		h.list = append(h.list, id)
	}
	h.log[id] = job

	size := h.size
	if size <= 0 {
		size = defaultJobHistorySize
	}
	for len(h.list) > size {
		oldest := h.list[0]
		h.list = h.list[1:]
		delete(h.log, oldest)
	}
}

// Own returns the job matching id ONLY IF it was actually recorded
// into THIS JobHistory (via Record) — see this type's own doc comment
// for the real, structural security guarantee this provides.
func (h *JobHistory[J]) Own(id string) (J, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	job, ok := h.log[id]
	return job, ok
}

// Len reports how many entries are currently held (test/diagnostic
// use — production code has no need to know this).
func (h *JobHistory[J]) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.list)
}
