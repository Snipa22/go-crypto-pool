// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- ParseLoginFields: pure parser tests ---
//
// These pin the exact, cited legacy semantics ParseLoginFields ports
// (see loginfields.go for the verbatim nodejs-pool-sxmr
// lib/pool.js source it was derived from).

// TestParseLoginFieldsPlainAddressIsUnchanged is the regression-proof
// for the overwhelmingly common case: a login with no "+" and no "."
// must come out byte-for-byte as it went in, with no fixed difficulty
// and no payment ID/identifier -- i.e. handleLogin behaves exactly as
// it did before this fix existed.
func TestParseLoginFieldsPlainAddressIsUnchanged(t *testing.T) {
	const addr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
	for _, algo := range []poolpb.Algo{poolpb.Algo_ALGO_RXM, poolpb.Algo_ALGO_SHA3X, poolpb.Algo_ALGO_C29, poolpb.Algo_ALGO_RXT} {
		got, err := ParseLoginFields(algo, addr, "XMRig/6.21.0", 5000, 100, 1_000_000)
		if err != nil {
			t.Fatalf("algo=%v: unexpected error: %v", algo, err)
		}
		want := LoginFields{Address: addr, Difficulty: 5000}
		if got != want {
			t.Errorf("algo=%v: got %+v, want %+v", algo, got, want)
		}
	}
}

// TestParseLoginFieldsFixedDiffIsAlgoAgnostic pins SCOPING DECISION 1
// (loginfields.go): the "+" fixed-difficulty split applies to EVERY
// algo, Tari included, because no real Tari address encoding can
// contain a literal "+".
func TestParseLoginFieldsFixedDiffIsAlgoAgnostic(t *testing.T) {
	tariAddr := realTariTestAddress("parse-fixed-diff-tari")
	for _, algo := range []poolpb.Algo{poolpb.Algo_ALGO_SHA3X, poolpb.Algo_ALGO_C29, poolpb.Algo_ALGO_RXT, poolpb.Algo_ALGO_RXM} {
		got, err := ParseLoginFields(algo, tariAddr+"+50000", "XMRig/6.21.0", 5000, 100, 1_000_000)
		if err != nil {
			t.Fatalf("algo=%v: unexpected error: %v", algo, err)
		}
		if got.Address != tariAddr {
			t.Errorf("algo=%v: Address = %q, want the stripped address %q", algo, got.Address, tariAddr)
		}
		if !got.FixedDiff {
			t.Errorf("algo=%v: FixedDiff = false, want true", algo)
		}
		if got.Difficulty != 50000 {
			t.Errorf("algo=%v: Difficulty = %d, want 50000", algo, got.Difficulty)
		}
	}
}

// TestParseLoginFieldsFixedDiffClamps pins the exact legacy clamp
// (pool.js lines 404-411) against this leaf's own configured
// -min-difficulty/-max-difficulty bounds, on both ends, plus the
// negative-value case legacy also clamps up.
func TestParseLoginFieldsFixedDiffClamps(t *testing.T) {
	addr := realTariTestAddress("parse-clamp")
	const minDiff, maxDiff = 1000, 200_000

	cases := []struct {
		suffix string
		want   uint64
	}{
		{"+1", minDiff},                          // below the floor -> clamped up
		{"+1000", minDiff},                       // exactly the floor -> unchanged
		{"+50000", 50000},                        // inside the band -> honored verbatim
		{"+200000", maxDiff},                     // exactly the ceiling -> unchanged
		{"+999999", maxDiff},                     // above the ceiling -> clamped down
		{"+0", minDiff},                          // zero -> clamped up (legacy: 0 < minDifficulty)
		{"+-5", minDiff},                         // negative -> clamped up, matching legacy's Number("-5")
		{"+99999999999999999999999999", maxDiff}, // out of int64 range -> saturates, then clamps down
	}
	for _, tc := range cases {
		got, err := ParseLoginFields(poolpb.Algo_ALGO_SHA3X, addr+tc.suffix, "XMRig/6.21.0", 5000, minDiff, maxDiff)
		if err != nil {
			t.Fatalf("suffix %q: unexpected error: %v", tc.suffix, err)
		}
		if !got.FixedDiff {
			t.Errorf("suffix %q: FixedDiff = false, want true", tc.suffix)
		}
		if got.Difficulty != tc.want {
			t.Errorf("suffix %q: Difficulty = %d, want %d", tc.suffix, got.Difficulty, tc.want)
		}
	}
}

// TestParseLoginFieldsTooManyOptions pins the legacy "Too many options
// in the login field" reject (pool.js lines 405-409) verbatim.
func TestParseLoginFieldsTooManyOptions(t *testing.T) {
	addr := realTariTestAddress("parse-too-many")
	_, err := ParseLoginFields(poolpb.Algo_ALGO_SHA3X, addr+"+5000+9000", "XMRig/6.21.0", 5000, 100, 1_000_000)
	if !errors.Is(err, ErrTooManyLoginOptions) {
		t.Fatalf("err = %v, want ErrTooManyLoginOptions", err)
	}
	if got, want := err.Error(), "Too many options in the login field"; got != want {
		t.Errorf("err.Error() = %q, want the verbatim legacy message %q", got, want)
	}
}

// TestParseLoginFieldsNonNumericFixedDiffIsRejected pins the one
// DELIBERATE DIVERGENCE from legacy: legacy's `Number("abc")` is NaN
// and every subsequent comparison silently fails, leaving a
// structurally broken session; this rejects the login instead.
func TestParseLoginFieldsNonNumericFixedDiffIsRejected(t *testing.T) {
	addr := realTariTestAddress("parse-nan-diff")
	_, err := ParseLoginFields(poolpb.Algo_ALGO_SHA3X, addr+"+notanumber", "XMRig/6.21.0", 5000, 100, 1_000_000)
	if err == nil {
		t.Fatal("expected a non-numeric +suffix to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid fixed difficulty") {
		t.Errorf("err = %q, want a clear 'invalid fixed difficulty' message", err)
	}
}

// TestParseLoginFieldsDotSplitIsMoneroFamilyOnly pins SCOPING DECISION
// 2 (loginfields.go): the "." payment-ID/identifier split is applied
// ONLY for Monero-family algos, matching the legacy reference's own
// Monero-only scope. A Tari login keeps its whole string as the
// address (which the real Tari validator will then reject -- there is
// no dot-suffix convention to honor for Tari, and none of Tari's three
// real address encodings can contain a ".").
func TestParseLoginFieldsDotSplitIsMoneroFamilyOnly(t *testing.T) {
	const paymentID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tariAddr := realTariTestAddress("parse-dot-tari")
	got, err := ParseLoginFields(poolpb.Algo_ALGO_SHA3X, tariAddr+"."+paymentID, "XMRig/6.21.0", 5000, 100, 1_000_000)
	if err != nil {
		t.Fatalf("SHA3X: unexpected error: %v", err)
	}
	if got.Address != tariAddr+"."+paymentID {
		t.Errorf("SHA3X: Address = %q, want the UNSPLIT login %q", got.Address, tariAddr+"."+paymentID)
	}
	if got.PaymentID != "" || got.Identifier != "" {
		t.Errorf("SHA3X: PaymentID=%q Identifier=%q, want both empty (dot split is Monero-family only)", got.PaymentID, got.Identifier)
	}

	xmr, err := ParseLoginFields(poolpb.Algo_ALGO_RXM, realXMRMainnetAddr+"."+paymentID, "XMRig/6.21.0", 5000, 100, 1_000_000)
	if err != nil {
		t.Fatalf("RXM: unexpected error: %v", err)
	}
	if xmr.Address != realXMRMainnetAddr {
		t.Errorf("RXM: Address = %q, want the stripped address %q", xmr.Address, realXMRMainnetAddr)
	}
	if xmr.PaymentID != paymentID {
		t.Errorf("RXM: PaymentID = %q, want %q", xmr.PaymentID, paymentID)
	}
	if xmr.Identifier != "" {
		t.Errorf("RXM: Identifier = %q, want empty (a 64-hex segment is a payment ID, not a rig name)", xmr.Identifier)
	}
}

// TestParseLoginFieldsDotSegmentClassification pins pool.js lines
// 416-423's exact payment-ID-vs-identifier classification, including
// the near-miss cases (63 hex chars, 64 chars with a non-hex
// character, uppercase hex) that legacy's own
// `length === 64 && hexMatch.test(...)` treats as identifiers rather
// than payment IDs.
func TestParseLoginFieldsDotSegmentClassification(t *testing.T) {
	const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name           string
		suffix         string
		wantPaymentID  string
		wantIdentifier string
	}{
		{"64-lowercase-hex/payment-id", "." + hex64, hex64, ""},
		{"63-hex/identifier", "." + hex64[:63], "", hex64[:63]},
		{"64-chars-with-non-hex/identifier", "." + hex64[:63] + "z", "", hex64[:63] + "z"},
		{"64-uppercase-hex/identifier", "." + strings.ToUpper(hex64), "", strings.ToUpper(hex64)},
		{"plain-worker-name/identifier", ".myrig01", "", "myrig01"},
		{"payment-id-then-worker/both", "." + hex64 + ".myrig01", hex64, "myrig01"},
		{"worker-then-worker/third-wins", ".first.second", "", "second"},
		{"empty-second-segment/identifier-empty", ".", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseLoginFields(poolpb.Algo_ALGO_RXM, realXMRMainnetAddr+tc.suffix, "XMRig/6.21.0", 5000, 100, 1_000_000)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Address != realXMRMainnetAddr {
				t.Errorf("Address = %q, want %q", got.Address, realXMRMainnetAddr)
			}
			if got.PaymentID != tc.wantPaymentID {
				t.Errorf("PaymentID = %q, want %q", got.PaymentID, tc.wantPaymentID)
			}
			if got.Identifier != tc.wantIdentifier {
				t.Errorf("Identifier = %q, want %q", got.Identifier, tc.wantIdentifier)
			}
		})
	}
}

// TestParseLoginFieldsNiceHashIsMoneroFamilyOnly pins SCOPING DECISION
// 3 (loginfields.go / LegacyNiceHashDifficulty): a "NiceHash" agent
// gets the real, cited 400000 fixed difficulty on Monero-family algos
// only -- there is no NiceHash-difficulty constant anywhere in this
// repo for Tari, and NiceHash runs no Tari hashpower market, so
// applying it universally would be fabricating a value.
func TestParseLoginFieldsNiceHashIsMoneroFamilyOnly(t *testing.T) {
	xmr, err := ParseLoginFields(poolpb.Algo_ALGO_RXM, realXMRMainnetAddr, "NiceHash/1.0", 5000, 100, 1_000_000_000)
	if err != nil {
		t.Fatalf("RXM: unexpected error: %v", err)
	}
	if !xmr.FixedDiff {
		t.Error("RXM/NiceHash: FixedDiff = false, want true")
	}
	if xmr.Difficulty != LegacyNiceHashDifficulty {
		t.Errorf("RXM/NiceHash: Difficulty = %d, want the cited %d (lib/coins/xmr.js line 49)", xmr.Difficulty, LegacyNiceHashDifficulty)
	}
	if LegacyNiceHashDifficulty != 400000 {
		t.Errorf("LegacyNiceHashDifficulty = %d, want the real cited XMR value 400000", LegacyNiceHashDifficulty)
	}

	tariAddr := realTariTestAddress("parse-nicehash-tari")
	tari, err := ParseLoginFields(poolpb.Algo_ALGO_SHA3X, tariAddr, "NiceHash/1.0", 5000, 100, 1_000_000_000)
	if err != nil {
		t.Fatalf("SHA3X: unexpected error: %v", err)
	}
	if tari.FixedDiff {
		t.Error("SHA3X/NiceHash: FixedDiff = true, want false (NiceHash diff is Monero-family only)")
	}
	if tari.Difficulty != 5000 {
		t.Errorf("SHA3X/NiceHash: Difficulty = %d, want the untouched starting difficulty 5000", tari.Difficulty)
	}
}

// TestParseLoginFieldsExplicitDiffOverridesNiceHash pins the legacy
// ORDERING (pool.js lines 392-411): NiceHash sets a fixed difficulty
// first, and an explicit "+" request then overrides it AND gets
// clamped.
func TestParseLoginFieldsExplicitDiffOverridesNiceHash(t *testing.T) {
	got, err := ParseLoginFields(poolpb.Algo_ALGO_RXM, realXMRMainnetAddr+"+12345", "NiceHash/1.0", 5000, 100, 1_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.FixedDiff || got.Difficulty != 12345 {
		t.Errorf("got FixedDiff=%v Difficulty=%d, want true/12345 (explicit +suffix must override the NiceHash default)", got.FixedDiff, got.Difficulty)
	}
}

// --- Session-level integration: handleLogin ---

// loginParseHarness is a lighter-weight, algo- and vardiff-configurable
// harness for the real handleLogin path -- newVardiffHarness
// (vardiff_test.go) hardcodes its JobManager to the default (SHA3X)
// algo and hardcodes its login params, both of which these tests need
// to vary. It reuses vardiff_test.go's own vardiffClient wire helper
// verbatim (same package) rather than duplicating a third read/write
// helper.
type loginParseHarness struct {
	t            *testing.T
	server       *Server
	jm           *JobManager
	node         *fakeNodeClient
	startingDiff uint64
}

func newLoginParseHarness(t *testing.T, algo poolpb.Algo, startingDiff uint64, vardiff VardiffConfig) *loginParseHarness {
	t.Helper()
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: 1 << 62,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
		vmKey:            []byte("test key 000"),
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: startingDiff,
		Algo:             algo,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 30 * time.Second})
	registry := validator.Registry{
		poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator(),
		poolpb.Algo_ALGO_C29:   validator.NewC29Validator(),
	}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, vardiff)
	t.Cleanup(cancel)
	return &loginParseHarness{t: t, server: server, jm: jm, node: node, startingDiff: startingDiff}
}

// loginRaw performs a real login handshake with a caller-supplied RAW
// login string / pass / agent (no realTariTestAddress mapping, no
// fixed params) and returns the wire client, the real server-side
// *Session, and the login response exactly as the server wrote it.
// sess is nil when the server rejected the login (no session state was
// established).
func (h *loginParseHarness) loginRaw(login, pass, agent string) (*vardiffClient, *Session, LoginResponse) {
	h.t.Helper()
	serverConn, clientConn := net.Pipe()
	go h.server.handleConn(context.Background(), serverConn, h.startingDiff)
	c := &vardiffClient{
		t:      h.t,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
	}
	h.t.Cleanup(func() { _ = clientConn.Close() })

	params, err := json.Marshal(LoginRequest{Login: login, Pass: pass, Agent: agent, Algo: []string{"sha3x"}})
	if err != nil {
		h.t.Fatalf("marshal login params: %v", err)
	}
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: params})

	raw := c.recvRaw()
	var resp LoginResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		h.t.Fatalf("unmarshal login response %s: %v", raw, err)
	}
	if resp.Result.Status != "OK" {
		return c, nil, resp
	}
	return c, h.sessionByID(resp.Result.ID), resp
}

func (h *loginParseHarness) sessionByID(sessionID string) *Session {
	h.t.Helper()
	h.server.mu.RLock()
	defer h.server.mu.RUnlock()
	for _, sess := range h.server.sessions {
		if sess.sessionID == sessionID {
			return sess
		}
	}
	h.t.Fatalf("could not find server-side Session for id %q after login", sessionID)
	return nil
}

// decodeGeneralError extracts the real error string from a rejected
// login. handleLogin's reject path goes through writeGeneralResponse,
// whose wire shape is algo-dependent (leaflib.WriteGeneralResponse):
// a bare string for the legacy C29/SHA3X dialects, an object for
// every other algo. Both shapes are handled here so this helper works
// regardless of the harness's configured algo.
func decodeGeneralError(t *testing.T, raw []byte) string {
	t.Helper()
	var legacy LegacyErrorResponse
	if err := json.Unmarshal(raw, &legacy); err == nil {
		return legacy.Error
	}
	var obj ErrorResponse
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal general error response %s: %v", raw, err)
	}
	if obj.Error == nil {
		return ""
	}
	return obj.Error.Message
}

// TestLoginFixedDifficultySuffixIsHonoredAndVardiffIsSkipped is the
// core login-field-parsing integration test: a login of
// "<realaddress>+50000" must
//
//  1. pass real address validation against the STRIPPED address (the
//     raw string is not a valid Tari address at all, so a successful
//     login proves the strip happened),
//  2. start the session at difficulty 50000 rather than the port
//     tier's configured default, and
//  3. never be retargeted by vardiff afterward, no matter how much
//     accept history it accumulates.
func TestLoginFixedDifficultySuffixIsHonoredAndVardiffIsSkipped(t *testing.T) {
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    1_000_000,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("login-fixed-diff")
	_, sess, resp := h.loginRaw(addr+"+50000", "rig1", "XMRig/6.21.0")
	if sess == nil {
		t.Fatalf("login with a +fixed-difficulty suffix was rejected: %#v", resp)
	}

	if got := sess.address.Load().(string); got != addr {
		t.Errorf("session address = %q, want the STRIPPED address %q (never the raw login string)", got, addr)
	}
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Errorf("session currentDifficulty = %d, want the requested fixed 50000", got)
	}
	if !sess.fixedDiff.Load() {
		t.Error("session fixedDiff = false, want true")
	}
	if got := resp.Result.Job.Target; got != leaflib.DiffToTargetHex(50000) {
		t.Errorf("login job target = %q, want %q (difficulty 50000)", got, leaflib.DiffToTargetHex(50000))
	}

	// The vardiff retarget must be a complete no-op for this session,
	// forever -- seed accept history and connection age that WOULD
	// otherwise produce a large retarget, then call maybeRetarget
	// directly (exactly as vardiff_test.go's own session-level tests
	// do). Running this synchronously against net.Pipe is safe
	// precisely BECAUSE no push may be produced: maybeRetarget's own
	// pushJob would block on a reader that isn't there, so a hang here
	// would itself be the bug being tested for.
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Fatalf("BUG: a fixed-difficulty session was retargeted to %d; vardiff must be skipped entirely for its lifetime", got)
	}

	// Also exercise the zero-accept-history branch (legacy's 10%
	// reduction fallback), which is the retarget path a genuinely idle
	// fixed-difficulty miner would otherwise hit on every single tick.
	sess.hashesAccumulated.Store(0)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != 50000 {
		t.Fatalf("BUG: a fixed-difficulty session was retargeted (idle-reduction path) to %d", got)
	}
}

// TestLoginFixedDifficultySuffixIsClampedByBothBounds covers the real
// clamp at the session level (not just in the pure parser): the
// requested value is clamped to this leaf's OWN configured
// -min-difficulty/-max-difficulty before it ever becomes the session's
// starting difficulty.
func TestLoginFixedDifficultySuffixIsClampedByBothBounds(t *testing.T) {
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
			h := newLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, VardiffConfig{
				MinDifficulty:    minDiff,
				MaxDifficulty:    maxDiff,
				TargetTime:       30,
				RetargetInterval: 60 * time.Second,
			})
			addr := realTariTestAddress("login-clamp-" + tc.name)
			_, sess, resp := h.loginRaw(addr+tc.suffix, "rig1", "XMRig/6.21.0")
			if sess == nil {
				t.Fatalf("login rejected: %#v", resp)
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

// TestLoginTooManyPlusOptionsIsRejected: a login field with more than
// one "+" must fail the login outright with the verbatim legacy
// message, and must NOT establish any session state.
func TestLoginTooManyPlusOptionsIsRejected(t *testing.T) {
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, VardiffConfig{RetargetInterval: 60 * time.Second})
	addr := realTariTestAddress("login-too-many-options")

	serverConn, clientConn := net.Pipe()
	go h.server.handleConn(context.Background(), serverConn, h.startingDiff)
	c := &vardiffClient{t: t, client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn)}
	t.Cleanup(func() { _ = clientConn.Close() })

	params, err := json.Marshal(LoginRequest{Login: addr + "+5000+9000", Pass: "rig1", Agent: "XMRig/6.21.0"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: params})

	raw := c.recvRaw()
	if got, want := decodeGeneralError(t, raw), "Too many options in the login field"; got != want {
		t.Fatalf("login error = %q, want the verbatim legacy message %q", got, want)
	}

	var resp LoginResponse
	if err := json.Unmarshal(raw, &resp); err == nil && resp.Result.Status == "OK" {
		t.Fatal("BUG: login with >2 +-separated options reported status OK")
	}
}

// TestLoginPaymentIDIsCapturedForMoneroFamily covers the
// Monero-family-only payment-ID path end-to-end through the real
// handleLogin: validation succeeds against the STRIPPED address and
// the payment ID lands on the session.
//
// leaf-solo has NO share table, backend, or payout accounting at all,
// so there is deliberately nothing further to assert here -- see
// Session.paymentID's own doc comment for that explicit, documented
// gap (leaf-direct, which does forward every share to the real
// backend, stamps the same value onto poolpb.Share.PaymentId for real;
// see that package's own test).
func TestLoginPaymentIDIsCapturedForMoneroFamily(t *testing.T) {
	const paymentID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, VardiffConfig{RetargetInterval: 60 * time.Second})

	_, sess, resp := h.loginRaw(realXMRMainnetAddr+"."+paymentID, "x", "XMRig/6.21.0")
	if sess == nil {
		t.Fatalf("login with a .paymentID suffix was rejected: %#v", resp)
	}
	if got := sess.address.Load().(string); got != realXMRMainnetAddr {
		t.Errorf("session address = %q, want the STRIPPED address %q", got, realXMRMainnetAddr)
	}
	if got := sess.paymentID.Load().(string); got != paymentID {
		t.Errorf("session paymentID = %q, want %q", got, paymentID)
	}
	// A 64-hex segment is a payment ID, never a worker name -- the
	// password field still supplies the worker.
	if got := sess.worker.Load().(string); got != "x" {
		t.Errorf("session worker = %q, want the password-supplied %q", got, "x")
	}
}

// TestLoginDotIdentifierFeedsWorkerWithLegacyPrecedence covers the
// non-64-hex dot-segment identifier path and the exact legacy
// precedence rule it follows (pool.js lines 419-423): the password/
// rigid field wins unless it is literally "x".
func TestLoginDotIdentifierFeedsWorkerWithLegacyPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		pass       string
		wantWorker string
	}{
		{"password-x/dot-identifier-wins", "x", "someworkername"},
		{"real-password/password-wins", "myrealrig", "myrealrig"},
		{"empty-password/dot-identifier-wins", "", "someworkername"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, VardiffConfig{RetargetInterval: 60 * time.Second})
			_, sess, resp := h.loginRaw(realXMRMainnetAddr+".someworkername", tc.pass, "XMRig/6.21.0")
			if sess == nil {
				t.Fatalf("login with a .identifier suffix was rejected: %#v", resp)
			}
			if got := sess.address.Load().(string); got != realXMRMainnetAddr {
				t.Errorf("session address = %q, want the STRIPPED address %q", got, realXMRMainnetAddr)
			}
			if got := sess.worker.Load().(string); got != tc.wantWorker {
				t.Errorf("session worker = %q, want %q", got, tc.wantWorker)
			}
			if got := sess.paymentID.Load().(string); got != "" {
				t.Errorf("session paymentID = %q, want empty (a non-64-hex segment is a worker name)", got)
			}
		})
	}
}

// TestLoginNiceHashAgentGetsFixedDifficulty covers the real,
// Monero-family-scoped NiceHash path end-to-end, at the cited 400000
// constant, including the vardiff skip that a fixed difficulty implies.
func TestLoginNiceHashAgentGetsFixedDifficulty(t *testing.T) {
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_RXM, 1000, VardiffConfig{
		MinDifficulty:    100,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	_, sess, resp := h.loginRaw(realXMRMainnetAddr, "rig1", "NiceHashMiner/3.0")
	if sess == nil {
		t.Fatalf("NiceHash login was rejected: %#v", resp)
	}
	if !sess.fixedDiff.Load() {
		t.Error("session fixedDiff = false, want true for a NiceHash agent")
	}
	if got := sess.currentDifficulty.Load(); got != LegacyNiceHashDifficulty {
		t.Errorf("session currentDifficulty = %d, want the cited NiceHash constant %d", got, LegacyNiceHashDifficulty)
	}

	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	sess.maybeRetarget()
	if got := sess.currentDifficulty.Load(); got != LegacyNiceHashDifficulty {
		t.Fatalf("BUG: a NiceHash fixed-difficulty session was retargeted to %d", got)
	}
}

// TestLoginOrdinaryAddressIsByteForByteUnchanged is the explicit
// regression-proof for the common case: an
// ordinary login with no "+" and no "." must behave exactly as it did
// before this fix -- same address, same starting difficulty, no fixed
// diff, no payment ID, worker still resolved purely from pass/rigid,
// and vardiff still fully live.
func TestLoginOrdinaryAddressIsByteForByteUnchanged(t *testing.T) {
	h := newLoginParseHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, VardiffConfig{
		MinDifficulty:    1,
		MaxDifficulty:    math.MaxUint64,
		TargetTime:       30,
		RetargetInterval: 60 * time.Second,
	})
	addr := realTariTestAddress("login-ordinary-unchanged")
	c, sess, resp := h.loginRaw(addr, "rig1", "XMRig/6.21.0")
	if sess == nil {
		t.Fatalf("ordinary login was rejected: %#v", resp)
	}
	if got := sess.address.Load().(string); got != addr {
		t.Errorf("session address = %q, want %q", got, addr)
	}
	if got := sess.worker.Load().(string); got != "rig1" {
		t.Errorf("session worker = %q, want %q", got, "rig1")
	}
	if got := sess.paymentID.Load().(string); got != "" {
		t.Errorf("session paymentID = %q, want empty", got)
	}
	if sess.fixedDiff.Load() {
		t.Error("session fixedDiff = true, want false for an ordinary login")
	}
	if got := sess.currentDifficulty.Load(); got != 1000 {
		t.Errorf("session currentDifficulty = %d, want the port tier's configured 1000", got)
	}
	if got := resp.Result.Job.Target; got != leaflib.DiffToTargetHex(1000) {
		t.Errorf("login job target = %q, want %q", got, leaflib.DiffToTargetHex(1000))
	}

	// Vardiff must still be fully live for this session: the same
	// accept-history/age setup the fixed-difficulty test above proves
	// is ignored MUST produce a real retarget here (1000 -> 1500 per
	// the step clamp), with a real job push.
	sess.connectedAt = time.Now().Add(-90 * time.Second)
	sess.hashesAccumulated.Store(600_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.maybeRetarget()
	}()
	push := c.recvJobPush()
	<-done
	if got := sess.currentDifficulty.Load(); got != 1500 {
		t.Fatalf("currentDifficulty = %d, want 1500 -- vardiff must remain fully live for a non-fixed-difficulty session", got)
	}
	if want := leaflib.DiffToTargetHex(1500); push.Params.Target != want {
		t.Errorf("pushed job target = %q, want %q", push.Params.Target, want)
	}
}
