// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/moneroblob"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- BRIEF_xn_relogin_fix.md required test coverage: a re-login must
// roll fresh per-session state so a genuinely different physical miner
// reusing the same TCP connection (xmrig-proxy's `simple`-mode
// `--reuse-timeout` slot rotation) never inherits the PREVIOUS
// worker's partially-used nonce space on the still-cached job, which
// caused a real, live production false "duplicate_nonce" rejection.
//
// WHICH VALUE THE FIX NOW RESTS ON: originally, rolling the xn WAS the
// mechanism, because xn was also solo.JobManager's job-cache key.
// That dual role has since been removed as a genuine correctness bug
// in its own right (two unrelated sessions drawing the same 2-byte xn
// shared one *Job and one usedNonces map -- see
// leaflib.NewJobCacheKey and job_cache_key_test.go). handleLogin now
// rolls BOTH values on a re-login, each for its own reason:
// Session.jobKey because it is what the job cache is keyed by (so the
// re-login lookup is a guaranteed MISS -- this is what preserves every
// false-duplicate_nonce assertion in this file), and Session.xn
// because it is the new downstream worker's own SHA3X/C29 submit-time
// nonce-prefix partition and is published on the wire. The wire-xn
// tests below therefore still assert the xn roll, and the
// duplicate-nonce tests below still assert the resulting behavior;
// only the internal value doing the cache-miss work changed. ---

// stubDeterministicSessionXN overrides the package-level newSessionXN
// func-var (job.go) with a deterministic, monotonically-incrementing
// sequence for the lifetime of the calling test, restoring the real
// leaflib.NewSessionXN implementation on cleanup. Needed because
// newSessionXN's real output is only 2 random bytes (65536 possible
// values): a naive "assert two independently-rolled xn values differ"
// test would have a real, non-negligible flake probability at that
// space, especially run repeatedly in CI. Every returned value is
// unique for the lifetime of one test (an 8-hex-char, never-repeating
// string), so any two calls within the same test are GUARANTEED
// distinct, not just probably distinct.
func stubDeterministicSessionXN(t *testing.T) {
	t.Helper()
	orig := newSessionXN
	var n int
	newSessionXN = func() (string, error) {
		n++
		return fmt.Sprintf("%08x", n), nil
	}
	t.Cleanup(func() { newSessionXN = orig })
}

// TestSessionReloginRollsFreshXN is required test #1: a second login
// on an already-logged-in session must roll a genuinely different xn
// than the first login's -- proving the fix's core mechanism (xn is
// no longer fixed for the connection's whole life).
func TestSessionReloginRollsFreshXN(t *testing.T) {
	stubDeterministicSessionXN(t)
	h := newReloginHarness(t, VardiffConfig{})

	sessionID, xn1 := login(t, h.testHarness, "xn-relogin-fresh")
	if xn1 == "" {
		t.Fatal("setup: first login's xn is empty")
	}

	resp := relogin(t, h.testHarness, "xn-relogin-fresh-2", "rig2", "XMRig/6.22.0")
	if resp.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", resp.Result.Status)
	}
	xn2 := sessionXN(t, h.testHarness, sessionID)

	if xn2 == xn1 {
		t.Fatalf("BUG: xn after re-login (%q) == xn before re-login (%q), want a genuinely fresh value", xn2, xn1)
	}

	// A THIRD login (a second re-login) must roll yet ANOTHER fresh
	// xn, distinct from BOTH previous values -- proving this is not a
	// one-time "first re-login only" fix.
	resp2 := relogin(t, h.testHarness, "xn-relogin-fresh-3", "rig3", "XMRig/6.23.0")
	if resp2.Result.Status != "OK" {
		t.Fatalf("second re-login failed: status=%q", resp2.Result.Status)
	}
	xn3 := sessionXN(t, h.testHarness, sessionID)
	if xn3 == xn1 || xn3 == xn2 {
		t.Fatalf("BUG: xn after second re-login (%q) collides with an earlier value (xn1=%q, xn2=%q)", xn3, xn1, xn2)
	}
}

// TestSessionReloginWireXNReflectsNewValueSHA3X is required test #4
// (SHA3X half): after a re-login, the LoginResponse.Job.XN the wire
// actually carries must be the NEW xn, not the old one -- confirming
// jobPayload's payload.XN = s.XN() read (which now goes through the
// mutable atomic.Value) picks up the freshly-rolled value in the SAME
// handleLogin call that rolled it, not a stale snapshot.
func TestSessionReloginWireXNReflectsNewValueSHA3X(t *testing.T) {
	stubDeterministicSessionXN(t)
	h := newReloginHarness(t, VardiffConfig{})

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress("xn-wire-sha3x-a"), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"},
	})})
	first := h.recvLoginResponse()
	if first.Result.Status != "OK" {
		t.Fatalf("first login failed: status=%q", first.Result.Status)
	}
	oldXN := first.Result.Job.XN
	if oldXN == "" {
		t.Fatal("setup: SHA3X job payload's XN is empty on first login")
	}

	resp := relogin(t, h.testHarness, "xn-wire-sha3x-b", "rig2", "XMRig/6.21.0")
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

	// Confirm it is genuinely the session's OWN current xn, not some
	// other unrelated value.
	sessionID := resp.Result.ID
	if live := sessionXN(t, h.testHarness, sessionID); live != newXN {
		t.Errorf("session's live xn (%q) != the wire LoginResponse.Job.XN (%q) it just returned", live, newXN)
	}
}

// TestSessionReloginWireXNReflectsNewValueC29 is required test #4's
// C29 half -- same assertion as the SHA3X version above, against a
// C29-configured leaf, confirming this is not an SHA3X-only fix.
func TestSessionReloginWireXNReflectsNewValueC29(t *testing.T) {
	stubDeterministicSessionXN(t)
	h := newC29TestHarness(t, 1, 1<<62)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress("xn-wire-c29-a"), Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"c29"},
	})})
	first := h.recvLoginResponse()
	if first.Result.Status != "OK" {
		t.Fatalf("first login failed: status=%q", first.Result.Status)
	}
	oldXN := first.Result.Job.XN
	if oldXN == "" {
		t.Fatal("setup: C29 job payload's XN is empty on first login")
	}

	h.send(Request{ID: 2, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress("xn-wire-c29-b"), Pass: "rig2", Agent: "XMRig/6.21.0", Algo: []string{"c29"},
	})})
	second := h.recvLoginResponse()
	if second.Result.Status != "OK" {
		t.Fatalf("re-login failed: status=%q", second.Result.Status)
	}
	newXN := second.Result.Job.XN
	if newXN == "" {
		t.Fatal("re-login's job payload XN is empty")
	}
	if newXN == oldXN {
		t.Fatalf("BUG: re-login's wire LoginResponse.Job.XN (%q) == the FIRST login's wire XN (%q), want the NEW rolled value", newXN, oldXN)
	}
}

// rxtRelogin performs a second (or Nth) "login" on an already-open RXT
// testHarness connection h, mirroring relogin_test.go's own SHA3X-only
// relogin helper but for ALGO_RXT (which has no xn hex-prefix
// wire-nonce convention at all -- see IsRandomXFamily -- so its own
// job.XN wire field, unlike SHA3X/C29, is deliberately never sent;
// this is exactly why the false-duplicate_nonce fix must be proven at
// the internal job-cache-key level (Session.jobKey, rolled by
// handleLogin) rather than via any wire-visible xn assertion for this
// algo).
func rxtRelogin(t *testing.T, h *testHarness, id int, addressLabel, pass string) LoginResponse {
	t.Helper()
	h.send(Request{ID: id, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realTariTestAddress(addressLabel), Pass: pass, Agent: "XMRig/6.25.0", Algo: []string{"rx/0"},
	})})
	return h.recvLoginResponse()
}

// TestSessionRXTReloginPreventsFalseDuplicateNonce is required test #2
// (the CORE regression test), run against ALGO_RXT: RXT's nonce has
// NO xn-prefix constraint at all (IsRandomXFamily is exempt from the
// xn-prefix check -- see handleSubmit's own doc comment), so unlike
// SHA3X/C29 (where a genuinely-different xn on the wire would ALSO,
// incidentally, prevent two sessions from ever literally submitting the
// byte-identical nonce string at the wire-protocol level, making the
// "same raw nonce" scenario impossible to construct honestly), RXT
// lets this test submit the LITERAL SAME nonce string for both
// identities and prove the fix operates purely through the internal
// per-session job-cache key (Session.jobKey, rolled on every re-login
// -- see this file's own header comment), exactly as
// BRIEF_xn_relogin_fix.md's test #2 asks for.
func TestSessionRXTReloginPreventsFalseDuplicateNonce(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, 0,
		validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)

	// Worker A logs in and submits a real, accepted ordinary share
	// using nonce N.
	firstResp := rxtRelogin(t, h.testHarness, 1, "rxt-relogin-nonce-a", "rigA")
	if firstResp.Result.Status != "OK" {
		t.Fatalf("worker A login failed: status=%q", firstResp.Result.Status)
	}
	sessionID := firstResp.Result.ID
	jobIDA := firstResp.Result.Job.JobID

	const nonce = "00000001"
	claimHex := hex.EncodeToString(largeResultHash(1))

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobIDA, Nonce: nonce, Result: claimHex,
	})})
	firstSubmit := h.recvShareResponse()
	if firstSubmit.Result == nil {
		t.Fatalf("expected worker A's first submit of nonce %s to be ACCEPTED, got rejected: %#v", nonce, firstSubmit)
	}

	// Worker B re-logs in on the SAME connection (xmrig-proxy
	// connection-reuse scenario) -- must get a genuinely fresh xn and
	// therefore a genuinely fresh job (different job_id).
	secondResp := rxtRelogin(t, h.testHarness, 3, "rxt-relogin-nonce-b", "rigB")
	if secondResp.Result.Status != "OK" {
		t.Fatalf("worker B re-login failed: status=%q", secondResp.Result.Status)
	}
	jobIDB := secondResp.Result.Job.JobID
	if jobIDB == jobIDA {
		t.Fatalf("BUG: worker B's post-relogin job_id (%s) == worker A's job_id (%s), want a genuinely fresh job (proves the xn cache lookup was a HIT, not the required MISS)", jobIDB, jobIDA)
	}

	// Worker B submits the EXACT SAME raw nonce string against the
	// NEW job the re-login minted. Pre-fix, this would have been
	// rejected as a false duplicate_nonce (same xn -> same cached Job
	// -> same usedNonces map already containing this nonce from worker
	// A). Post-fix, this MUST be accepted.
	h.send(Request{ID: 4, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobIDB, Nonce: nonce, Result: claimHex,
	})})
	secondSubmit := h.recvShareResponse()
	if secondSubmit.Result == nil {
		t.Fatalf("BUG REGRESSION: worker B's submit of the SAME raw nonce (%s), already used by worker A pre-relogin, was rejected: %#v (expected ACCEPTED -- this is exactly the false-positive duplicate_nonce this fix closes)", nonce, secondSubmit)
	}
}

// TestSessionRXTGenuineReplayWithoutReloginStillRejected is required
// test #3: a genuine replay of the same nonce, within ONE identity's
// own job, with NO re-login in between, must still be correctly
// rejected as duplicate_nonce -- proving the fix did not accidentally
// weaken real replay detection (test #2 above proves it closes the
// FALSE positive; this proves it does not introduce a false NEGATIVE).
func TestSessionRXTGenuineReplayWithoutReloginStillRejected(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_RXT, 1, 1<<62, 0,
		validator.Registry{poolpb.Algo_ALGO_RXT: &fakeDelayedRandomXValidator{}}, nil)

	resp := rxtRelogin(t, h.testHarness, 1, "rxt-genuine-replay", "rigA")
	if resp.Result.Status != "OK" {
		t.Fatalf("login failed: status=%q", resp.Result.Status)
	}
	sessionID := resp.Result.ID
	jobID := resp.Result.Job.JobID

	const nonce = "00000042"
	claimHex := hex.EncodeToString(largeResultHash(1))

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce, Result: claimHex,
	})})
	first := h.recvShareResponse()
	if first.Result == nil {
		t.Fatalf("expected the first submission of nonce %s to be accepted, got %#v", nonce, first)
	}

	// NO re-login here -- same identity, same job, same connection.
	h.send(Request{ID: 3, Method: "submit", Params: mustJSON(t, SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: nonce, Result: claimHex,
	})})
	second := h.recvShareResponse()
	if second.Result != nil {
		t.Fatalf("BUG: a genuine replay of the same nonce within ONE identity's own job (no re-login) was accepted, want rejected as duplicate_nonce: %#v", second)
	}
}

// TestSessionRXMReloginPreventsFalseDuplicateNonce is required test #5:
// RXM (ALGO_RXM) is covered by the SAME fix via the internal
// per-session job-cache key, even though RXM's wire job payload
// never carries an "xn" field at all (jobPayload's `if
// !IsRandomXFamily(job.Algo) { payload.XN = s.XN() }` -- RXM is
// RandomX-family, so this is always skipped for it). This is
// otherwise an exact structural mirror of
// TestSessionRXTReloginPreventsFalseDuplicateNonce above, proving the
// fix is not accidentally scoped to only the algos that happen to
// expose xn on the wire.
//
// Uses the real-Monero-template-shaped harness
// (newFakeMoneroXNPNodeClient/newRXMXNPTestHarness,
// session_xnp_rxm_submit_test.go) rather than newRXMTestHarness's own
// Tari-shaped fakeNodeClient: handleSubmit's Monero-family branch
// calls MoneroHashingBlobForSubmit UNCONDITIONALLY (for both an
// ordinary share and a block-find candidate alike, to build the
// Share's own RawProof), which requires a genuine
// *moneroTemplateData -- a Tari-shaped job fails that type assertion
// before ever reaching the ordinary-accept path this test needs to
// exercise (see newRXMTestHarness's own doc comment, and
// TestSessionRXMAccepts4ByteNonce, which explicitly only proves "not
// rejected by the length gate" for exactly this reason, never a full
// accept). moneroblob.GlobalBreaker is a process-wide singleton
// shared with every other test in this package (see
// TestSessionRXMXNPSubmitPatchesWorkerAndPoolNonce's identical
// reset), so it must be reset before AND after this test to avoid
// cross-test interference in either direction.
func TestSessionRXMReloginPreventsFalseDuplicateNonce(t *testing.T) {
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	node := newFakeMoneroXNPNodeClient(t)
	h := newRXMXNPTestHarness(t, 1, 1<<62, node)

	firstResp := rxmReloginTestLogin(t, h, 1, "rigA")
	if firstResp.Result.Status != "OK" {
		t.Fatalf("worker A login failed: status=%q", firstResp.Result.Status)
	}
	sessionID := firstResp.Result.ID
	jobIDA := firstResp.Result.Job.JobID
	if firstResp.Result.Job.XN != "" {
		t.Errorf("RXM job payload carries a non-empty XN (%q), want it omitted entirely -- see jobPayload's IsRandomXFamily gate", firstResp.Result.Job.XN)
	}

	const nonce = "818d1a00" // real xmrig-capture-shaped 4-byte nonce (session_test.go)
	claimHex := hex.EncodeToString(largeResultHash(1))

	h.send(Request{ID: 2, Method: "submit", Params: mustJSON(t, SubmitRequest{
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

	secondResp := rxmReloginTestLogin(t, h, 3, "rigB")
	if secondResp.Result.Status != "OK" {
		t.Fatalf("worker B re-login failed: status=%q", secondResp.Result.Status)
	}
	jobIDB := secondResp.Result.Job.JobID
	if jobIDB == jobIDA {
		t.Fatalf("BUG: worker B's post-relogin RXM job_id (%s) == worker A's job_id (%s), want a genuinely fresh job", jobIDB, jobIDA)
	}

	h.send(Request{ID: 4, Method: "submit", Params: mustJSON(t, SubmitRequest{
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

// rxmReloginTestLogin performs a login (first or Nth) on h using the
// SAME fixed real Monero mainnet test address (realXMRMainnetAddr,
// session_test.go) for every call -- a re-login does not require a
// DIFFERENT address, only a second "login" message on an
// already-logged-in connection; pass distinguishes the two identities
// exactly as ResolveWorkerIdentifier already does elsewhere in this
// test package.
func rxmReloginTestLogin(t *testing.T, h *testHarness, id int, pass string) LoginResponse {
	t.Helper()
	h.send(Request{ID: id, Method: "login", Params: mustJSON(t, LoginRequest{
		Login: realXMRMainnetAddr, Pass: pass, Agent: "XMRig/6.21.0", Algo: []string{"rx/0"},
	})})
	return h.recvLoginResponse()
}
