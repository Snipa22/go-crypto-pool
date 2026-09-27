// Copyright and license: see repository LICENSE (MIT).
//
// This file's tests cover the two share/general-response wire shapes
// this package supports: the legacy bare-bool/bare-string shape
// (LegacyShareResponse/LegacyErrorResponse), now shared by BOTH
// ALGO_C29 and ALGO_SHA3X (both are lolMiner/graxil-class clients
// requiring this dialect), and the object/null shape (ShareResponse/
// ErrorResponse), used ONLY by ALGO_RXT/ALGO_RXM (genuinely
// xmrig-family clients). See protocol.go's doc comments on each type
// for the full rationale and provenance.
package solo

import (
	"encoding/json"
	"testing"
)

// TestC29ShareResponseUsesBareBoolAndBareStringOnTheWire is the
// explicit regression guard for the confirmed C29 wire-shape
// regression introduced by PR #56 and fixed by this change: a real
// C29 miner (lolMiner/graxil29) requires "result" to be a literal
// JSON boolean and "error" to be a literal JSON string (or absent),
// matching go-tari-c29-solo-stratum's real MinerRPCShareResponse
// exactly. This test marshals LegacyShareResponse directly and
// inspects the RAW JSON bytes (not just Go-side field types) so a
// future accidental change back to the object/null shape for C29
// fails loudly here. This LegacyShareResponse type is now shared by
// C29 and SHA3X (see TestSHA3XShareResponseUsesBareBoolAndBareStringOnTheWire
// below for the SHA3X-specific coverage of the exact same type).
func TestC29ShareResponseUsesBareBoolAndBareStringOnTheWire(t *testing.T) {
	// Reject case: bare string error, bare bool result (false).
	rejectBuf, err := json.Marshal(LegacyShareResponse{ID: 1, JsonRPC: "2.0", Error: "Invalid XNonce", Result: false})
	if err != nil {
		t.Fatalf("marshal reject: %v", err)
	}
	var rejectRaw map[string]json.RawMessage
	if err := json.Unmarshal(rejectBuf, &rejectRaw); err != nil {
		t.Fatalf("unmarshal reject into raw map: %v", err)
	}
	if got := string(rejectRaw["result"]); got != "false" {
		t.Errorf("reject \"result\" must be the literal JSON boolean false, got raw bytes %q (an object/null shape would break lolMiner)", got)
	}
	var rejectErrStr string
	if err := json.Unmarshal(rejectRaw["error"], &rejectErrStr); err != nil {
		t.Errorf("reject \"error\" must decode as a bare JSON string, got raw bytes %q: %v (an object shape would break lolMiner -- this is the exact confirmed regression)", string(rejectRaw["error"]), err)
	}

	// Accept case: bare bool result (true), no error key at all
	// (Error field has `omitempty` on the string type, matching the
	// real go-tari-c29-solo-stratum reference).
	acceptBuf, err := json.Marshal(LegacyShareResponse{ID: 2, JsonRPC: "2.0", Result: true})
	if err != nil {
		t.Fatalf("marshal accept: %v", err)
	}
	var acceptRaw map[string]json.RawMessage
	if err := json.Unmarshal(acceptBuf, &acceptRaw); err != nil {
		t.Fatalf("unmarshal accept into raw map: %v", err)
	}
	if got := string(acceptRaw["result"]); got != "true" {
		t.Errorf("accept \"result\" must be the literal JSON boolean true, got raw bytes %q", got)
	}
	if _, present := acceptRaw["error"]; present {
		t.Errorf("accept response must have NO \"error\" key at all (omitempty), got raw bytes %q", string(acceptBuf))
	}
}

// TestSHA3XShareResponseUsesBareBoolAndBareStringOnTheWire mirrors
// TestC29ShareResponseUsesBareBoolAndBareStringOnTheWire's structure
// exactly, proving LegacyShareResponse's wire shape is correct for
// SHA3X's own needs, not just C29's -- LegacyShareResponse itself
// doesn't carry an algo, so this is a direct-type-marshal test (not
// algo-conditional), the same way the C29 test above proves the
// TYPE's wire shape, not any particular dispatch branch. SHA3X's real
// ecosystem client (lolMiner/graxil-class) requires "result" to be a
// literal JSON boolean and "error" to be a literal JSON string (or
// absent), matching go-tari-sha3x-solo-stratum's real
// MinerRPCShareResponse (subsystems/messages/minerStructs.go)
// exactly, identically to C29's own dialect.
func TestSHA3XShareResponseUsesBareBoolAndBareStringOnTheWire(t *testing.T) {
	// Reject case: bare string error, bare bool result (false).
	rejectBuf, err := json.Marshal(LegacyShareResponse{ID: 1, JsonRPC: "2.0", Error: "Invalid XNonce", Result: false})
	if err != nil {
		t.Fatalf("marshal reject: %v", err)
	}
	var rejectRaw map[string]json.RawMessage
	if err := json.Unmarshal(rejectBuf, &rejectRaw); err != nil {
		t.Fatalf("unmarshal reject into raw map: %v", err)
	}
	if got := string(rejectRaw["result"]); got != "false" {
		t.Errorf("SHA3X reject \"result\" must be the literal JSON boolean false, got raw bytes %q (an object/null shape would break lolMiner)", got)
	}
	var rejectErrStr string
	if err := json.Unmarshal(rejectRaw["error"], &rejectErrStr); err != nil {
		t.Errorf("SHA3X reject \"error\" must decode as a bare JSON string, got raw bytes %q: %v (an object shape would break lolMiner -- this is the exact confirmed regression)", string(rejectRaw["error"]), err)
	}

	// Accept case: bare bool result (true), no error key at all
	// (Error field has `omitempty` on the string type, matching the
	// real go-tari-sha3x-solo-stratum reference).
	acceptBuf, err := json.Marshal(LegacyShareResponse{ID: 2, JsonRPC: "2.0", Result: true})
	if err != nil {
		t.Fatalf("marshal accept: %v", err)
	}
	var acceptRaw map[string]json.RawMessage
	if err := json.Unmarshal(acceptBuf, &acceptRaw); err != nil {
		t.Fatalf("unmarshal accept into raw map: %v", err)
	}
	if got := string(acceptRaw["result"]); got != "true" {
		t.Errorf("SHA3X accept \"result\" must be the literal JSON boolean true, got raw bytes %q", got)
	}
	if _, present := acceptRaw["error"]; present {
		t.Errorf("SHA3X accept response must have NO \"error\" key at all (omitempty), got raw bytes %q", string(acceptBuf))
	}
}

// TestRXTRXMShareResponseStillUsesObjectShapeOnTheWire is the
// companion regression guard against RE-BREAKING the PR #56 xmrig
// compatibility fix while fixing C29/SHA3X: confirms ShareResponse
// (used by RXT/RXM ONLY, both confirmed working with real
// xmrig-class clients -- NOT SHA3X, which now uses LegacyShareResponse
// above) still marshals "error" as a real object or null, and
// "result" as a real object (or an absent key on reject) -- never a
// bare bool/string.
func TestRXTRXMShareResponseStillUsesObjectShapeOnTheWire(t *testing.T) {
	// Accept case: error is literal null, result is {"status":"OK"}.
	acceptBuf, err := json.Marshal(ShareResponse{ID: 1, JsonRPC: "2.0", Error: nil, Result: &ShareResult{Status: "OK"}})
	if err != nil {
		t.Fatalf("marshal accept: %v", err)
	}
	var acceptRaw map[string]json.RawMessage
	if err := json.Unmarshal(acceptBuf, &acceptRaw); err != nil {
		t.Fatalf("unmarshal accept into raw map: %v", err)
	}
	if got := string(acceptRaw["error"]); got != "null" {
		t.Errorf("RXT/RXM accept \"error\" must be the literal JSON null, got raw bytes %q", got)
	}
	var resultObj map[string]json.RawMessage
	if err := json.Unmarshal(acceptRaw["result"], &resultObj); err != nil {
		t.Errorf("RXT/RXM accept \"result\" must decode as a JSON OBJECT, got raw bytes %q: %v (a bare bool would break xmrig -- this is exactly the bug PR #56 fixed)", string(acceptRaw["result"]), err)
	}

	// Reject case: error is a real object, "result" key entirely absent.
	rejectBuf, err := json.Marshal(ShareResponse{ID: 2, JsonRPC: "2.0", Error: &RPCError{Code: -1, Message: "Duplicate share"}})
	if err != nil {
		t.Fatalf("marshal reject: %v", err)
	}
	var rejectRaw map[string]json.RawMessage
	if err := json.Unmarshal(rejectBuf, &rejectRaw); err != nil {
		t.Fatalf("unmarshal reject into raw map: %v", err)
	}
	var errObj map[string]json.RawMessage
	if err := json.Unmarshal(rejectRaw["error"], &errObj); err != nil {
		t.Errorf("RXT/RXM reject \"error\" must decode as a JSON OBJECT, got raw bytes %q: %v (a bare string would break xmrig)", string(rejectRaw["error"]), err)
	}
	if _, present := rejectRaw["result"]; present {
		t.Errorf("RXT/RXM reject response must have NO \"result\" key at all (omitempty), got raw bytes %q", string(rejectBuf))
	}
}
