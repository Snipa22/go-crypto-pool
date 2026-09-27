// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// controllableValidator is a validator.AlgoValidator test double
// whose Validate outcome is set directly by the test (setValid),
// letting session_classification_test.go's "validated"/"invalid"
// cases drive a REAL accept/reject decision through finishSubmit's
// real (non-skipped) validation branch without depending on an
// actual RandomX daemon (unlike trust_integration_test.go's
// real-but-deliberately-unreachable validator.RandomXValidator,
// which only ever exercises the trust-SKIP branch).
type controllableValidator struct {
	mu    sync.Mutex
	valid bool
}

func (c *controllableValidator) setValid(v bool) {
	c.mu.Lock()
	c.valid = v
	c.mu.Unlock()
}

func (c *controllableValidator) Validate(_ context.Context, _ *poolpb.Share) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.valid, nil
}

var _ validator.AlgoValidator = (*controllableValidator)(nil)

// classificationTestHarness mirrors trust_integration_test.go's own
// manually-built harness exactly (same real reason: EnableTrust/
// EnableMetrics must be called BEFORE Server.handleConn's goroutine
// starts, or go test -race correctly reports a real data race), but
// wires a controllableValidator instead of a real (deliberately
// unreachable) validator.RandomXValidator, so both the trust-skip AND
// the real-validation branches of finishSubmit can be exercised
// deterministically.
type classificationTestHarness struct {
	*directTestHarness
	fakeValidator *controllableValidator
	metrics       *directmetrics.Metrics
}

func newClassificationTestHarness(t *testing.T, enableTrust bool) *classificationTestHarness {
	t.Helper()
	const staticDiff, networkTargetDiff = uint64(1), uint64(1) << 62
	node := &fakeDirectNodeClient{
		height:          42,
		mergeMiningHash: []byte("direct-test-merge-mining-hash-3"),
		vmKey:           []byte("test key 000"),
	}
	node.targetDifficulty = networkTargetDiff
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:             node,
		PayoutAddress:    "direct-test-address",
		StaticDifficulty: staticDiff,
		Algo:             poolpb.Algo_ALGO_RXT,
	})
	fv := &controllableValidator{}
	registry := validator.Registry{poolpb.Algo_ALGO_RXT: fv}
	tr := &fakeShareTransport{}
	sub := &fakeAcceptingBlockClient{}
	multi := newMultiNodeSubmitterForTest(map[string]blockSubmitClient{"fake-node:18102": sub}, log.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 260 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm, JobManager: jm, Node: node, Validators: registry,
		Network: poolpb.Network_NETWORK_TESTNET, Transport: tr, MultiSubmit: multi,
		Algo: poolpb.Algo_ALGO_RXT, PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
	})

	m := server.EnableMetrics("dev", 0)

	if enableTrust {
		// Same real state-machine parameters as
		// trust_integration_test.go's identical setup -- see
		// forceDirectTrustReady's own doc comment.
		server.EnableTrust(solo.TrustConfig{Enabled: true, Threshold: 1, Penalty: 1, Change: 300, Min: 1})
	}

	serverConn, clientConn := net.Pipe()
	go server.handleConn(ctx, serverConn, staticDiff)
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &directTestHarness{
		t: t, server: server, jm: jm, node: node, transport: tr, submit: sub,
		client: clientConn, reader: bufio.NewReader(clientConn), writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}
	return &classificationTestHarness{directTestHarness: h, fakeValidator: fv, metrics: m}
}

// classificationRXTResultHex is a real-shaped, nonzero 32-byte claimed
// result hash mirroring trust_integration_test.go's own fakeResult --
// RXTLittleEndianDifficulty("ab" repeated 32 times) derives a
// difficulty comfortably above this harness's staticDiff=1, so an
// accepted (valid=true) submit also clears BuildCandidateBlock's own
// claimed-difficulty-floor check (session.go's handleSubmit's second
// RecordOutcome(false)/classification=invalid call site -- that
// branch is, for RXT specifically, only ever reachable if the
// pre-dispatch cheap filter's claimed-difficulty computation
// (ClaimedRandomXFamilyDifficulty) and this same real derived value
// diverge, which they structurally cannot for RXT since both derive
// from the exact same submit.Result via the exact same
// RXTLittleEndianDifficulty formula -- so this file does not attempt
// to exercise that specific branch separately from the FIRST
// RecordOutcome(false) call site TestDirectSessionRXTClassification_
// Invalid already covers).
const classificationRXTResultHex = "abababababababababababababababababababababababababababababab"

// classificationRXTNonceHex is a real-shaped 4-byte hex nonce for an
// RXT submit -- RXT's xn-prefix check is skipped entirely (see
// handleSubmit's doc comment), so, unlike SHA3X/C29, no xn-prefix
// gymnastics are needed here.
func classificationRXTNonceHex(n uint32) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return hex.EncodeToString(buf)
}

// TestDirectSessionRXTClassification_Validated proves a REAL accepted
// RXT submit WITHOUT trust-skip enabled increments
// leaf_direct_shares_by_classification_total{classification="validated"}.
func TestDirectSessionRXTClassification_Validated(t *testing.T) {
	h := newClassificationTestHarness(t, false)
	h.fakeValidator.setValid(true)

	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("addr-classification-validated"))
	jobID := directCurrentJobIDForXN(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 10, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID,
		Nonce:  classificationRXTNonceHex(1),
		Result: classificationRXTResultHex,
	})})
	resp := h.recvShareResponse()
	if resp.Error != nil {
		t.Fatalf("expected a real accepted submit, got error: %+v", resp.Error)
	}

	if got := testutil.ToFloat64(h.metrics.SharesByClassificationTotal.WithLabelValues(directmetrics.ClassificationValidated)); got != 1 {
		t.Errorf("classification=validated counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.SharesByClassificationTotal.WithLabelValues(directmetrics.ClassificationTrusted)); got != 0 {
		t.Errorf("classification=trusted counter = %v, want 0 (trust not enabled)", got)
	}
	if got := testutil.ToFloat64(h.metrics.SharesByClassificationTotal.WithLabelValues(directmetrics.ClassificationInvalid)); got != 0 {
		t.Errorf("classification=invalid counter = %v, want 0", got)
	}
}

// TestDirectSessionRXTClassification_Invalid proves a REAL rejected
// RXT submit (the real validator says the share is cryptographically
// invalid) increments
// leaf_direct_shares_by_classification_total{classification="invalid"}.
func TestDirectSessionRXTClassification_Invalid(t *testing.T) {
	h := newClassificationTestHarness(t, false)
	h.fakeValidator.setValid(false)

	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("addr-classification-invalid"))
	jobID := directCurrentJobIDForXN(t, h.directTestHarness, xn)

	h.send(solo.Request{ID: 11, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
		ID: sessionID, JobID: jobID,
		Nonce:  classificationRXTNonceHex(2),
		Result: classificationRXTResultHex,
	})})
	resp := h.recvShareResponse()
	if resp.Error == nil {
		t.Fatalf("expected a real rejected submit, got an accepted result: %+v", resp.Result)
	}

	if got := testutil.ToFloat64(h.metrics.SharesByClassificationTotal.WithLabelValues(directmetrics.ClassificationInvalid)); got != 1 {
		t.Errorf("classification=invalid counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.SharesByClassificationTotal.WithLabelValues(directmetrics.ClassificationValidated)); got != 0 {
		t.Errorf("classification=validated counter = %v, want 0", got)
	}
	if got := testutil.ToFloat64(h.metrics.SharesByClassificationTotal.WithLabelValues(directmetrics.ClassificationTrusted)); got != 0 {
		t.Errorf("classification=trusted counter = %v, want 0", got)
	}
}

// TestDirectSessionRXTClassification_Trusted proves a REAL accepted
// RXT submit WITH trust-skip enabled AND actually exercised increments
// leaf_direct_shares_by_classification_total{classification="trusted"}
// -- mirrors trust_integration_test.go's own real end-to-end proof
// that the trust-skip mechanism is wired, retrying a bounded number
// of times for the same real reason that test does: the skip is a
// genuine per-share coin flip (solo/trust.go's ShouldSkipValidation),
// not a deterministic switch, even once threshold/penalty are forced
// clear (forceDirectTrustReady) and probability is floored at Min=1.
func TestDirectSessionRXTClassification_Trusted(t *testing.T) {
	h := newClassificationTestHarness(t, true)
	// The fake validator would also accept if the real (non-skipped)
	// validation branch ran instead of skipping -- setting it to
	// valid=true means EVERY attempt below is accepted regardless of
	// which branch actually ran, so this test can retry purely to hit
	// the "trusted" classification specifically, without any
	// interfering rejected/duplicate-nonce noise.
	h.fakeValidator.setValid(true)

	sessionID, xn := directLogin(t, h.directTestHarness, realTariTestAddress("addr-classification-trusted"))
	jobID := directCurrentJobIDForXN(t, h.directTestHarness, xn)

	h.server.mu.RLock()
	var sess *Session
	for _, s := range h.server.sessions {
		if s.sessionID == sessionID {
			sess = s
			break
		}
	}
	h.server.mu.RUnlock()
	if sess == nil {
		t.Fatalf("could not find session %q on server after login", sessionID)
	}
	if sess.trust == nil {
		t.Fatal("session.trust is nil despite EnableTrust having been called before this session was created")
	}
	forceDirectTrustReady(sess.trust)

	trustedCounter := h.metrics.SharesByClassificationTotal.WithLabelValues(directmetrics.ClassificationTrusted)
	const maxAttempts = 30
	for attempt := 0; attempt < maxAttempts; attempt++ {
		h.send(solo.Request{ID: 12, Method: "submit", Params: mustDirectJSON(t, solo.SubmitRequest{
			ID: sessionID, JobID: jobID,
			Nonce:  classificationRXTNonceHex(uint32(100 + attempt)),
			Result: classificationRXTResultHex,
		})})
		resp := h.recvShareResponse()
		if resp.Error != nil {
			t.Fatalf("attempt %d: expected a real accepted submit (fake validator always returns valid=true), got error: %+v", attempt, resp.Error)
		}
		if testutil.ToFloat64(trustedCounter) >= 1 {
			break
		}
		// Re-force readiness between attempts: RecordOutcome(true) on
		// an already-cleared threshold/penalty is a no-op floor, so
		// this is defensive, not strictly required, but mirrors
		// trust_integration_test.go's own retry loop exactly.
		forceDirectTrustReady(sess.trust)
	}

	if got := testutil.ToFloat64(trustedCounter); got < 1 {
		t.Fatalf("expected at least one trusted-share skip to be classified within %d attempts; classification=trusted counter = %v", maxAttempts, got)
	}
}
