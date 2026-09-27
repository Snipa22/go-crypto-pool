// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// assertOnlyDirectLoginRejectionReason mirrors
// session_rejection_reason_test.go's own assertOnlyDirectRejectionReason
// exactly, just against LoginRejectionsTotal instead of
// ShareRejectionReasonTotal.
func assertOnlyDirectLoginRejectionReason(t *testing.T, m *directmetrics.Metrics, want string) {
	t.Helper()
	for _, reason := range directmetrics.AllLoginRejectionReasons {
		got := testutil.ToFloat64(m.LoginRejectionsTotal.WithLabelValues(reason))
		if reason == want {
			if got != 1 {
				t.Errorf("reason=%s counter = %v, want 1", reason, got)
			}
		} else if got != 0 {
			t.Errorf("reason=%s counter = %v, want 0 (only reason=%s should have incremented)", reason, got, want)
		}
	}
}

// recvDirectGenericLoginRejection reads one raw login-rejection wire
// line and decodes it against the minimal status/error shape shared
// by both the object/null and legacy bare-string ErrorResponse wire
// shapes, exactly like addressflags_enforcement_test.go's own
// TestSessionLogin_RejectsBannedAddress decode.
func recvDirectGenericLoginRejection(t *testing.T, h *directTestHarness) {
	t.Helper()
	raw := h.recvRaw()
	var generic struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected login to be rejected, got status=OK (raw=%s)", raw)
	}
}

// TestDirectSessionLoginRejectionReason_InvalidParams covers
// handleLogin's json.Unmarshal(req.Params, &login) failure call site.
func TestDirectSessionLoginRejectionReason_InvalidParams(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	h.send(solo.Request{ID: 1, Method: "login", Params: json.RawMessage(`"not-an-object"`)})
	recvDirectGenericLoginRejection(t, h.directTestHarness)

	assertOnlyDirectLoginRejectionReason(t, h.metrics, directmetrics.LoginRejectionReasonInvalidParams)
}

// TestDirectSessionLoginRejectionReason_EmptyAddress covers
// handleLogin's login.Login == "" call site.
func TestDirectSessionLoginRejectionReason_EmptyAddress(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: "", Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	recvDirectGenericLoginRejection(t, h.directTestHarness)

	assertOnlyDirectLoginRejectionReason(t, h.metrics, directmetrics.LoginRejectionReasonEmptyAddress)
}

// TestDirectSessionLoginRejectionReason_InvalidAddressFormat covers
// handleLogin's solo.ValidateAddressForAlgo call site.
func TestDirectSessionLoginRejectionReason_InvalidAddressFormat(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: "not-a-valid-tari-address", Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	recvDirectGenericLoginRejection(t, h.directTestHarness)

	assertOnlyDirectLoginRejectionReason(t, h.metrics, directmetrics.LoginRejectionReasonInvalidAddressFormat)
}

// TestDirectSessionLoginRejectionReason_Banned covers handleLogin's
// s.server.addressFlags.Get(...).Banned call site -- the category
// Alex specifically asked this metric to quantify against the
// others.
func TestDirectSessionLoginRejectionReason_Banned(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil, nil)

	addr := realTariTestAddress("direct-login-rejection-banned")
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {Banned: true},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	recvDirectGenericLoginRejection(t, h.directTestHarness)

	assertOnlyDirectLoginRejectionReason(t, h.metrics, directmetrics.LoginRejectionReasonBanned)

	// Explicit /metrics HTTP-scrape confirmation, mirroring solo
	// package's identical scrapeSoloMetrics-based assertion exactly
	// (see that test's doc comment for the full rationale).
	body := scrapeDirectMetrics(t, h.server)
	if !strings.Contains(body, `leaf_direct_login_rejections_total{reason="banned"} 1`) {
		t.Errorf("expected leaf_direct_login_rejections_total{reason=\"banned\"} 1 to be exposed on /metrics, got:\n%s", body)
	}
}

// scrapeDirectMetrics performs a real HTTP GET against
// s.MetricsHandler() via httptest and returns the raw Prometheus
// text-exposition body -- mirrors solo package's identical
// scrapeSoloMetrics exactly.
func scrapeDirectMetrics(t *testing.T, s *Server) string {
	t.Helper()
	srv := httptest.NewServer(s.MetricsHandler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	return string(body)
}

// TestDirectSessionLoginRejectionReason_NoJobTemplate covers
// fetchAndDeliverLoginJob's s.server.jobManager.JobForXNAtDifficulty
// failure call site -- a real, valid, unbanned login that still
// can't be issued a job because the node's GetBlockTemplate call
// itself fails.
func TestDirectSessionLoginRejectionReason_NoJobTemplate(t *testing.T) {
	node := &fakeDirectNodeClient{
		height:              42,
		mergeMiningHash:     []byte("direct-test-merge-mining-hash-3"),
		getBlockTemplateErr: errors.New("direct-login-rejection-test: no template available"),
	}
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, node, nil)

	addr := realTariTestAddress("direct-login-rejection-no-job-template")
	h.send(solo.Request{ID: 1, Method: "login", Params: mustDirectJSON(t, solo.LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	recvDirectGenericLoginRejection(t, h.directTestHarness)

	assertOnlyDirectLoginRejectionReason(t, h.metrics, directmetrics.LoginRejectionReasonNoJobTemplate)
}
