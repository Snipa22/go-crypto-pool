// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- BRIEF_xn_relogin_fix.md required test coverage for leaf-direct,
// mirroring internal/leaflib/solo/xn_relogin_test.go's identical
// coverage exactly, adapted to this package's own harness
// conventions (newRejectionReasonHarness/directLogin/directRelogin/
// directLoginRXM). See that file's own doc comments for the full
// false-duplicate_nonce-on-re-login root-cause rationale -- not
// repeated here. ---

// stubDeterministicDirectSessionXN mirrors solo package's identical
// helper exactly -- overrides this package's own newSessionXN
// func-var (session.go) with a deterministic, never-repeating
// sequence for the calling test's lifetime, restoring the real
// leaflib.NewSessionXN implementation on cleanup.
func stubDeterministicDirectSessionXN(t *testing.T) {
	t.Helper()
	orig := newSessionXN
	var n int
	newSessionXN = func() (string, error) {
		n++
		return fmt.Sprintf("%08x", n), nil
	}
	t.Cleanup(func() { newSessionXN = orig })
}

// TestDirectSessionReloginRollsFreshXN is required test #1.
func TestDirectSessionReloginRollsFreshXN(t *testing.T) {
	stubDeterministicDirectSessionXN(t)
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	sessionID, xn1 := directLogin(t, h.directTestHarness, realTariTestAddress("direct-xn-relogin-fresh"))
	if xn1 == "" {
		t.Fatal("setup: first login's xn is empty")
	}

	resp := directRelogin(t, h.directTestHarness, realTariTestAddress("direct-xn-relogin-fresh-2"), "rig2", "XMRig/6.22.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", resp.Result.Status)
	}
	xn2 := directSessionXN(t, h.directTestHarness, sessionID)
	if xn2 == xn1 {
		t.Fatalf("BUG: xn after re-login (%q) == xn before re-login (%q), want a genuinely fresh value", xn2, xn1)
	}

	resp2 := directRelogin(t, h.directTestHarness, realTariTestAddress("direct-xn-relogin-fresh-3"), "rig3", "XMRig/6.23.0")
	if resp2.Result.Status != "OK" {
		t.Fatalf("second re-login failed: status=%q", resp2.Result.Status)
	}
	xn3 := directSessionXN(t, h.directTestHarness, sessionID)
	if xn3 == xn1 || xn3 == xn2 {
		t.Fatalf("BUG: xn after second re-login (%q) collides with an earlier value (xn1=%q, xn2=%q)", xn3, xn1, xn2)
	}
}

// TestDirectSessionReloginWireXNReflectsNewValueSHA3X is required
// test #4: after a re-login, LoginResponse.Job.XN must reflect the
// NEW xn, not the old one.
func TestDirectSessionReloginWireXNReflectsNewValueSHA3X(t *testing.T) {
	stubDeterministicDirectSessionXN(t)
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: realTariTestAddress("direct-xn-wire-sha3x-a"), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"},
	})})
	first := h.recvLoginResponse()
	if first.Result.Status != "OK" {
		t.Fatalf("first login failed: status=%q", first.Result.Status)
	}
	oldXN := first.Result.Job.XN
	if oldXN == "" {
		t.Fatal("setup: SHA3X job payload's XN is empty on first login")
	}

	resp := directRelogin(t, h.directTestHarness, realTariTestAddress("direct-xn-wire-sha3x-b"), "rig2", "XMRig/6.21.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", resp.Result.Status)
	}
	newXN := resp.Result.Job.XN
	if newXN == "" {
		t.Fatal("re-login's job payload XN is empty")
	}
	if newXN == oldXN {
		t.Fatalf("BUG: re-login's wire LoginResponse.Job.XN (%q) == the FIRST login's wire XN (%q), want the NEW rolled value", newXN, oldXN)
	}

	sessionID := resp.Result.ID
	if live := directSessionXN(t, h.directTestHarness, sessionID); live != newXN {
		t.Errorf("session's live xn (%q) != the wire LoginResponse.Job.XN (%q) it just returned", live, newXN)
	}
}

// directRxtRelogin performs a second (or Nth) "login" on an
// already-open RXT directTestHarness connection h -- mirrors solo
// package's own rxtRelogin exactly (see that function's doc comment
// for why RXT is the right vehicle for the "same raw nonce" core
// regression test: no xn-prefix wire constraint at all).
func directRxtRelogin(t *testing.T, h *directTestHarness, id int, addressLabel, pass string) solo.LoginResponse {
	t.Helper()
	h.send(solo.Request{ID: id, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: realTariTestAddress(addressLabel), Pass: pass, Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
	})})
	return h.recvLoginResponse()
}

// TestDirectSessionRXTReloginPreventsFalseDuplicateNonce is required
// test #2 (the CORE regression test) -- mirrors solo package's
// identical TestSessionRXTReloginPreventsFalseDuplicateNonce exactly,
// adapted to this package's own harness.
func TestDirectSessionRXTReloginPreventsFalseDuplicateNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)

	firstResp := directRxtRelogin(t, h.directTestHarness, 1, "direct-rxt-relogin-nonce-a", "rigA")
	if firstResp.Result.Status != "OK" {
		t.Fatalf("worker A login failed: status=%q", firstResp.Result.Status)
	}
	sessionID := firstResp.Result.ID
	jobIDA := firstResp.Result.Job.JobID

	const nonce = "00000001"
	claimHex := hex.EncodeToString(directLargeResultHash(1))

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobIDA, Nonce: nonce, Result: claimHex,
	})})
	firstSubmit := h.recvShareResponse()
	if firstSubmit.Result == nil {
		msg := ""
		if firstSubmit.Error != nil {
			msg = firstSubmit.Error.Message
		}
		t.Fatalf("expected worker A's first submit of nonce %s to be ACCEPTED, got rejected: %q", nonce, msg)
	}

	secondResp := directRxtRelogin(t, h.directTestHarness, 3, "direct-rxt-relogin-nonce-b", "rigB")
	if secondResp.Result.Status != "OK" {
		t.Fatalf("worker B re-login failed: status=%q", secondResp.Result.Status)
	}
	jobIDB := secondResp.Result.Job.JobID
	if jobIDB == jobIDA {
		t.Fatalf("BUG: worker B's post-relogin job_id (%s) == worker A's job_id (%s), want a genuinely fresh job", jobIDB, jobIDA)
	}

	h.send(solo.Request{ID: 4, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobIDB, Nonce: nonce, Result: claimHex,
	})})
	secondSubmit := h.recvShareResponse()
	if secondSubmit.Result == nil {
		msg := ""
		if secondSubmit.Error != nil {
			msg = secondSubmit.Error.Message
		}
		t.Fatalf("BUG REGRESSION: worker B's submit of the SAME raw nonce (%s), already used by worker A pre-relogin, was rejected: %q (expected ACCEPTED -- this is exactly the false-positive duplicate_nonce this fix closes)", nonce, msg)
	}
}

// TestDirectSessionRXTGenuineReplayWithoutReloginStillRejected is
// required test #3 -- mirrors solo package's identical test exactly.
func TestDirectSessionRXTGenuineReplayWithoutReloginStillRejected(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62,
		validator.Registry{poolpb.Algo_ALGO_RXT: &fakeControllableValidator{valid: true}}, nil, nil)

	resp := directRxtRelogin(t, h.directTestHarness, 1, "direct-rxt-genuine-replay", "rigA")
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	sessionID := resp.Result.ID
	jobID := resp.Result.Job.JobID

	const nonce = "00000042"
	claimHex := hex.EncodeToString(directLargeResultHash(1))

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce, Result: claimHex,
	})})
	first := h.recvShareResponse()
	if first.Result == nil {
		t.Fatalf("expected the first submission of nonce %s to be accepted, got %#v", nonce, first)
	}

	// NO re-login here -- same identity, same job, same connection.
	h.send(solo.Request{ID: 3, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce, Result: claimHex,
	})})
	second := h.recvShareResponse()
	if second.Result != nil {
		t.Fatalf("BUG: a genuine replay of the same nonce within ONE identity's own job (no re-login) was accepted, want rejected as duplicate_nonce: %#v", second)
	}
}

// directRxmReloginTestLogin performs a login (first or Nth) on h
// using the SAME fixed real Monero mainnet test address
// (realDirectXMRMainnetAddr, session_test.go) for every call -- a
// re-login does not require a different address, only a second
// "login" message on an already-logged-in connection.
func directRxmReloginTestLogin(t *testing.T, h *directTestHarness, id int, pass string) solo.LoginResponse {
	t.Helper()
	h.send(solo.Request{ID: id, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: realDirectXMRMainnetAddr, Pass: pass, Agent: "XMRig/6.21.0", Algo: []string{"rx/0"},
	})})
	return h.recvLoginResponse()
}

// TestDirectSessionRXMReloginPreventsFalseDuplicateNonce is required
// test #5: RXM is covered by the same fix via the internal
// JobForXNAtDifficulty cache key, even though its wire job payload
// never carries an "xn" field. Uses the REAL solo.MoneroNodeClient
// against a mock monerod daemon (newDirectRXMBlockFindHarness,
// session_rxm_blockhash_test.go) rather than the XNP-only fixture
// double (fakeDirectMoneroXNPNodeClient): unlike leaf-solo, leaf-direct
// has no "ordinary sub-block share credited on claim alone" shortcut
// at all -- handleSubmit's finishSubmit closure ALWAYS calls the real
// validator AND solo.MoneroNodeClient.BuildCandidateBlock for every
// RXM/RXT submit regardless of whether it crosses
// job.NetworkTargetDifficulty (every validated share is forwarded to
// the backend, this leaf's whole reason for existing) -- and
// BuildCandidateBlock requires a genuine *moneroTemplateData, an
// unexported solo type this package cannot construct by hand (see
// fakeDirectMoneroXNPNodeClient's own doc comment). The mock daemon +
// real solo.MoneroNodeClient combination is this package's own
// already-established way of getting a genuinely real
// *moneroTemplateData without a live monerod.
//
// Uses directLargeResultHash (numerically large hash -> SMALL derived
// difficulty, see that function's doc comment), deliberately kept
// BELOW the mock daemon's difficulty=1000 job.NetworkTargetDifficulty,
// so this is an ORDINARY accepted share, NOT a block find -- a block
// find would trigger a real, asynchronous
// `go s.server.jobManager.InvalidateAll(...)` (session.go) that can
// race an unsolicited "job" push onto the wire at any point after its
// own share response, which would non-deterministically interleave
// with this test's own strict recvLoginResponse() calls on the
// re-login below (confirmed by an earlier version of this test using
// a genuine block-find claim, which flaked under `go test -race` for
// exactly that reason). MarkNonceUsed's collision check runs at the
// same call site regardless of ordinary-vs-block-find (see
// handleSubmit's own code, both packages), so an ordinary share
// exercises exactly the mechanism this fix is about, without that
// unrelated race.
func TestDirectSessionRXMReloginPreventsFalseDuplicateNonce(t *testing.T) {
	daemon := &moneroDirectMockDaemon{height: 500, difficulty: 1000}
	srv := httptest.NewServer(daemon.handler(t))
	defer srv.Close()

	h := newDirectRXMBlockFindHarness(t, srv, 1)

	firstResp := directRxmReloginTestLogin(t, h, 1, "rigA")
	if firstResp.Result.Status != "OK" {
		t.Fatalf("worker A login failed: status=%q", firstResp.Result.Status)
	}
	sessionID := firstResp.Result.ID
	jobIDA := firstResp.Result.Job.JobID
	if firstResp.Result.Job.XN != "" {
		t.Errorf("RXM job payload carries a non-empty XN (%q), want it omitted entirely", firstResp.Result.Job.XN)
	}

	const nonce = "01000000"
	claimHex := hex.EncodeToString(directLargeResultHash(1))

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobIDA, Nonce: nonce, Result: claimHex,
	})})
	firstSubmit := h.recvShareResponse()
	if firstSubmit.Result == nil {
		msg := ""
		if firstSubmit.Error != nil {
			msg = firstSubmit.Error.Message
		}
		t.Fatalf("expected worker A's first submit of nonce %s to be ACCEPTED, got rejected: %q", nonce, msg)
	}
	if daemon.submitCalls.Load() != 0 {
		t.Fatalf("setup bug: expected an ORDINARY accepted share (no real submit_block call), got %d submit_block calls -- adjust the claim so it stays below the mock daemon's difficulty", daemon.submitCalls.Load())
	}

	secondResp := directRxmReloginTestLogin(t, h, 3, "rigB")
	if secondResp.Result.Status != "OK" {
		t.Fatalf("worker B re-login failed: status=%q", secondResp.Result.Status)
	}
	jobIDB := secondResp.Result.Job.JobID
	if jobIDB == jobIDA {
		t.Fatalf("BUG: worker B's post-relogin RXM job_id (%s) == worker A's job_id (%s), want a genuinely fresh job", jobIDB, jobIDA)
	}

	h.send(solo.Request{ID: 4, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobIDB, Nonce: nonce, Result: claimHex,
	})})
	secondSubmit := h.recvShareResponse()
	if secondSubmit.Result == nil {
		msg := ""
		if secondSubmit.Error != nil {
			msg = secondSubmit.Error.Message
		}
		t.Fatalf("BUG REGRESSION (RXM): worker B's submit of the SAME raw nonce (%s), already used by worker A pre-relogin, was rejected: %q (expected ACCEPTED)", nonce, msg)
	}
}
