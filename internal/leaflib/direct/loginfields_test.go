// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"math"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- real login-field address/+diff/.paymentID/.identifier parsing ---
//
// The parser itself (solo.ParseLoginFields) is unit-tested exhaustively
// in internal/leaflib/solo/loginfields_test.go; this file covers
// leaf-direct's OWN handleLogin integration of it, including the one
// thing only leaf-direct has: real poolpb.Share.PaymentId stamping on
// every forwarded share, which leaf-solo (no share table, no backend,
// no payout accounting) has no equivalent of.

// newDirectLoginParseHarness is newDirectTestHarness with an explicit
// algo AND an explicit solo.VardiffConfig (newDirectTestHarness/
// newRejectionReasonHarness both hardcode SHA3X and leave Vardiff at
// its zero value, and these tests need to vary both -- the
// -min-difficulty/-max-difficulty clamp bounds handleLogin applies to
// a "+"-requested fixed difficulty come from exactly that config).
func newDirectLoginParseHarness(t *testing.T, algo poolpb.Algo, startingDiff uint64, vardiff solo.VardiffConfig) *directTestHarness {
	t.Helper()
	node := &fakeDirectNodeClient{
		height:          42,
		mergeMiningHash: []byte("direct-test-merge-mining-hash-3"),
		vmKey:           []byte("test key 000"),
	}
	node.targetDifficulty = 1 << 62
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: startingDiff,
		Algo:             algo,
	})

	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}
	tr := &fakeShareTransport{}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())

	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET, Transport: tr, MultiSubmit: multi,
		Algo: algo, PoolType: poolpb.PoolType_POOL_TYPE_SOLO, PoolID: 42,
		Vardiff: vardiff,
	})

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, startingDiff)

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr, submit: sub,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
	})
	return h
}

// directLoginRawFields performs a real login handshake with a
// caller-supplied RAW login string / pass / agent (no fixed params,
// no address mapping) and returns the real server-side *Session, or
// nil if the server rejected the login.
func directLoginRawFields(t *testing.T, h *directTestHarness, login, pass, agent, wireAlgo string) *Session {
	t.Helper()
	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: login, Pass: pass, Agent: agent, Algo: []string{wireAlgo},
	})})
	raw := h.recvRaw()
	var resp solo.LoginResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal login response %s: %v", raw, err)
	}
	if resp.Result.Status != "OK" {
		return nil
	}
	return directSessionByID(t, h, resp.Result.ID)
}

// TestDirectLoginFixedDifficultySuffixIsHonoredAndVardiffIsSkipped is
// the core login-field-parsing integration test for leaf-direct: a login of
// "<realaddress>+50000" must pass real address validation against the
// STRIPPED address, start at difficulty 50000 rather than the port
// tier's default, and never be retargeted by vardiff afterward.
func TestDirectLoginFixedDifficultySuffixIsHonoredAndVardiffIsSkipped(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("direct-login-fixed-diff")
	sess := directLoginRawFields(t, h, addr+"+50000", "rig1", "XMRig/6.21.0", "sha3x")
	if sess == nil {
		t.Fatal("login with a +fixed-difficulty suffix was rejected")
	}

	if got := sess.Identity().Address; got != addr {
		t.Errorf("session address = %q, want the STRIPPED address %q (never the raw login string)", got, addr)
	}
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested fixed 50000", got)
	}
	if !sess.fixedDiff.Load() {
		t.Error("session fixedDiff = false, want true")
	}

	// Vardiff must be a complete no-op for this session. Safe to run
	// synchronously against net.Pipe precisely BECAUSE no push may be
	// produced (a push would block on an absent reader, so a hang here
	// would itself be the bug under test).
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Fatalf("BUG: a fixed-difficulty session was retargeted to %d; vardiff must be skipped entirely for its lifetime", got)
	}
	sess.hashesAccumulated.Store(0)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Fatalf("BUG: a fixed-difficulty session was retargeted (idle-reduction path) to %d", got)
	}
}

// TestDirectLoginFixedDifficultySuffixIsClampedByBothBounds covers the
// real clamp against leaf-direct's OWN configured -min-difficulty/
// -max-difficulty values (ServerConfig.Vardiff), on both ends.
func TestDirectLoginFixedDifficultySuffixIsClampedByBothBounds(t *testing.T) {
	const minDiff, maxDiff = 5000, 100_000
	cases := []struct {
		name   string
		suffix string
		want   uint64
	}{
		{"below-min/clamped-up", "+1", minDiff},
		{"above-max/clamped-down", "+99999999", maxDiff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
				MinDifficulty:    minDiff,
				MaxDifficulty:    maxDiff,
				TargetTime:       30,
				RetargetInterval: 60 * time.Second,
			})
			addr := realTariTestAddress("direct-login-clamp-" + tc.name)
			sess := directLoginRawFields(t, h, addr+tc.suffix, "rig1", "XMRig/6.21.0", "sha3x")
			if sess == nil {
				t.Fatal("login rejected")
			}
			if got := sess.currentDifficulty.Load(); got != tc.want {
				t.Errorf("session currentDifficulty = %d, want the clamped %d", got, tc.want)
			}
			if !sess.fixedDiff.Load() {
				t.Error("session fixedDiff = false, want true (a clamped request is still a fixed-difficulty request)")
			}
		})
	}
}

// TestDirectLoginTooManyPlusOptionsIsRejected: more than one "+" in
// the login field fails the login outright with the verbatim legacy
// "Too many options in the login field" message.
func TestDirectLoginTooManyPlusOptionsIsRejected(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{RetargetInterval: 60 * time.Second})
	addr := realTariTestAddress("direct-login-too-many-options")

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{
		Login: addr + "+5000+9000", Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"},
	})})
	// SHA3X uses the legacy bare-string general-response shape.
	resp := h.recvLegacyErrorResponse()
	if want := "Too many options in the login field"; resp.Error != want {
		t.Fatalf("login error = %q, want the verbatim legacy message %q", resp.Error, want)
	}
}

// TestDirectLoginPaymentIDIsStampedOnForwardedShares is the real,
// end-to-end proof that leaf-direct genuinely wires a login-field
// payment ID through to payout accounting -- unlike leaf-solo, which
// has no share table/backend at all and documents that as a known gap
// (see solo.Session's paymentID field doc comment). The value must
// land on poolpb.Share.PaymentId, which
// internal/backend/api's ingestion handler already reads into
// db.Share.PaymentID and internal/backend/db keys its balance/
// miner_identifiers rows on.
func TestDirectLoginPaymentIDIsStampedOnForwardedShares(t *testing.T) {
	const paymentID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1, solo.VardiffConfig{RetargetInterval: 60 * time.Second})

	// SHA3X is not Monero-family, so the ".paymentID" split does not
	// apply there (SCOPING DECISION 2, solo/loginfields.go) -- this
	// test therefore drives the SHA3X share-forwarding path with the
	// session's paymentID set directly, which is exactly what
	// handleLogin does for a Monero-family login. That keeps the
	// assertion focused on the real thing only leaf-direct has (the
	// Share.PaymentId stamping through a real fakeShareTransport)
	// without needing a Monero-shaped job template a
	// fakeDirectNodeClient cannot produce.
	sessionID, xn := directLogin(t, h, realTariTestAddress("direct-login-payment-id"))
	sess := directSessionByID(t, h, sessionID)
	updated := *sess.Identity()
	updated.PaymentID = paymentID
	sess.identity.Store(&updated)

	jobID := directCurrentJobIDForSession(t, h, xn)
	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	if resp := h.recvLegacyShareResponse(); !resp.Result {
		t.Fatalf("expected the share to be accepted, got %#v", resp)
	}
	waitForShareCount(t, h.transport, 1)

	share := h.transport.shareAt(0)
	if share.PaymentId == nil {
		t.Fatal("BUG: forwarded Share.PaymentId is nil -- a real login-field payment ID never reached payout accounting")
	}
	if got := share.GetPaymentId(); got != paymentID {
		t.Errorf("forwarded Share.PaymentId = %q, want %q", got, paymentID)
	}
}

// TestDirectLoginNoPaymentIDLeavesShareFieldNil is the regression-proof
// for the common case: a login with no payment ID must forward shares
// with PaymentId left entirely unset (nil), byte-for-byte identical to
// before this field was wired at all.
func TestDirectLoginNoPaymentIDLeavesShareFieldNil(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1, solo.VardiffConfig{RetargetInterval: 60 * time.Second})
	sessionID, xn := directLogin(t, h, realTariTestAddress("direct-login-no-payment-id"))
	jobID := directCurrentJobIDForSession(t, h, xn)

	h.send(solo.Request{ID: 2, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID, Nonce: directXNPrefixedNonceHex(xn, 1),
	})})
	if resp := h.recvLegacyShareResponse(); !resp.Result {
		t.Fatalf("expected the share to be accepted, got %#v", resp)
	}
	waitForShareCount(t, h.transport, 1)

	if pid := h.transport.shareAt(0).PaymentId; pid != nil {
		t.Errorf("forwarded Share.PaymentId = %q, want nil (no payment ID was supplied)", *pid)
	}
}

// TestDirectLoginDotIdentifierFeedsWorkerWithLegacyPrecedence covers
// the non-64-hex dot-segment identifier path and the exact legacy
// precedence rule (pool.js lines 419-423): the password/rigid field
// wins unless it is literally "x".
func TestDirectLoginDotIdentifierFeedsWorkerWithLegacyPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		pass       string
		wantWorker string
	}{
		{"password-x/dot-identifier-wins", "x", "someworkername"},
		{"real-password/password-wins", "myrealrig", "myrealrig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, solo.VardiffConfig{RetargetInterval: 60 * time.Second})
			sess := directLoginRawFields(t, h, realDirectXMRMainnetAddr+".someworkername", tc.pass, "XMRig/6.21.0", "rx/0")
			if sess == nil {
				t.Fatal("login with a .identifier suffix was rejected")
			}
			if got := sess.Identity().Address; got != realDirectXMRMainnetAddr {
				t.Errorf("session address = %q, want the STRIPPED address %q", got, realDirectXMRMainnetAddr)
			}
			if got := sess.Identity().Worker; got != tc.wantWorker {
				t.Errorf("session worker = %q, want %q", got, tc.wantWorker)
			}
			if got := sess.Identity().PaymentID; got != "" {
				t.Errorf("session paymentID = %q, want empty (a non-64-hex segment is a worker name)", got)
			}
		})
	}
}

// TestDirectLoginNiceHashAgentGetsFixedDifficulty covers the real,
// Monero-family-scoped NiceHash path at the cited 400000 constant,
// including the vardiff skip a fixed difficulty implies.
func TestDirectLoginNiceHashAgentGetsFixedDifficulty(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, solo.VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	sess := directLoginRawFields(t, h, realDirectXMRMainnetAddr, "rig1", "NiceHashMiner/3.0", "rx/0")
	if sess == nil {
		t.Fatal("NiceHash login was rejected")
	}
	if !sess.fixedDiff.Load() {
		t.Error("session fixedDiff = false, want true for a NiceHash agent")
	}
	if got := sess.currentDifficulty.Load(); got != solo.LegacyNiceHashDifficulty {
		t.Errorf("session currentDifficulty = %d, want the cited NiceHash constant %d", got, solo.LegacyNiceHashDifficulty)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != solo.LegacyNiceHashDifficulty {
		t.Fatalf("BUG: a NiceHash fixed-difficulty session was retargeted to %d", got)
	}
}

// TestDirectLoginOrdinaryAddressIsByteForByteUnchanged is the explicit
// regression-proof for the common case: an ordinary login with no "+"
// and no "." behaves exactly as it did before this fix, and vardiff
// remains fully live for it.
func TestDirectLoginOrdinaryAddressIsByteForByteUnchanged(t *testing.T) {
	h := newDirectLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, solo.VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("direct-login-ordinary-unchanged")
	sess := directLoginRawFields(t, h, addr, "rig1", "XMRig/6.21.0", "sha3x")
	if sess == nil {
		t.Fatal("ordinary login was rejected")
	}
	if got := sess.Identity().Address; got != addr {
		t.Errorf("session address = %q, want %q", got, addr)
	}
	if got := sess.Identity().Worker; got != "rig1" {
		t.Errorf("session worker = %q, want %q", got, "rig1")
	}
	if got := sess.Identity().PaymentID; got != "" {
		t.Errorf("session paymentID = %q, want empty", got)
	}
	if sess.fixedDiff.Load() {
		t.Error("session fixedDiff = true, want false for an ordinary login")
	}
	if got := sess.currentDifficulty.Load(); got != 1000 {
		t.Errorf("session currentDifficulty = %d, want the port tier's configured 1000", got)
	}

	// Vardiff must still be fully live: the same accept-history/age
	// setup the fixed-difficulty test above proves is ignored MUST
	// produce a real retarget (1000 -> 1500 per the step clamp) plus a
	// real job push here.
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	push := h.recvJobPush()
	<-done
	if got := sess.currentDifficulty.Load(); got != 1500 {
		t.Fatalf("currentDifficulty = %d, want 1500 -- vardiff must remain fully live for a non-fixed-difficulty session", got)
	}
	if want := leaflib.DiffToTargetHex(1500); push.Params.Target != want {
		t.Errorf("pushed job target = %q, want %q", push.Params.Target, want)
	}
}
