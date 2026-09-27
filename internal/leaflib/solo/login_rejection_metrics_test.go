// Copyright and license: see repository LICENSE (MIT).
package solo

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
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// assertOnlyLoginRejectionReason confirms exactly one
// leaf_solo_login_rejections_total{reason=want} sample equals 1 and
// every OTHER reason in the full, closed metrics.AllLoginRejectionReasons
// enumeration is still 0 -- mirrors session_rejection_reason_test.go's
// own assertOnlyRejectionReason exactly, just against
// LoginRejectionsTotal instead of ShareRejectionReasonTotal.
func assertOnlyLoginRejectionReason(t *testing.T, m *metrics.Metrics, want string) {
	t.Helper()
	for _, reason := range metrics.AllLoginRejectionReasons {
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

// TestSessionLoginRejectionReason_InvalidParams covers handleLogin's
// json.Unmarshal(req.Params, &login) failure call site.
func TestSessionLoginRejectionReason_InvalidParams(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)

	h.send(Request{ID: 1, Method: "login", Params: json.RawMessage(`"not-an-object"`)})
	raw := h.recvRaw()

	var generic struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected malformed login params to be rejected, got status=OK (raw=%s)", raw)
	}

	assertOnlyLoginRejectionReason(t, h.metrics, metrics.LoginRejectionReasonInvalidParams)
}

// TestSessionLoginRejectionReason_EmptyAddress covers handleLogin's
// login.Login == "" call site.
func TestSessionLoginRejectionReason_EmptyAddress(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: "", Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	raw := h.recvRaw()

	var generic struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected an empty login address to be rejected, got status=OK (raw=%s)", raw)
	}

	assertOnlyLoginRejectionReason(t, h.metrics, metrics.LoginRejectionReasonEmptyAddress)
}

// TestSessionLoginRejectionReason_InvalidAddressFormat covers
// handleLogin's ValidateAddressForAlgo call site: a non-empty login
// string that is not a real, byte-exact-valid Tari address for this
// leaf's configured (SHA3X) algo.
func TestSessionLoginRejectionReason_InvalidAddressFormat(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: "not-a-valid-tari-address", Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	raw := h.recvRaw()

	var generic struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected a malformed address to be rejected, got status=OK (raw=%s)", raw)
	}

	assertOnlyLoginRejectionReason(t, h.metrics, metrics.LoginRejectionReasonInvalidAddressFormat)
}

// TestSessionLoginRejectionReason_Banned covers handleLogin's
// s.server.addressFlags.Get(...).Banned call site -- the category
// Alex specifically asked this metric to quantify against the
// others.
func TestSessionLoginRejectionReason_Banned(t *testing.T) {
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, nil)

	addr := realTariTestAddress("login-rejection-banned")
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {Banned: true},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	raw := h.recvRaw()

	var generic struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected a banned address's login to be rejected, got status=OK (raw=%s)", raw)
	}

	assertOnlyLoginRejectionReason(t, h.metrics, metrics.LoginRejectionReasonBanned)

	// Explicit /metrics HTTP-scrape confirmation (DISPATCH_BRIEF.md's
	// own required verification step: a registration mistake, e.g.
	// reusing an already-registered name, fails via the graceful
	// log-and-continue path in registerCounterVec and would otherwise
	// go unnoticed) -- not just registry-internal testutil access.
	body := scrapeSoloMetrics(t, h.server)
	if !strings.Contains(body, `leaf_solo_login_rejections_total{reason="banned"} 1`) {
		t.Errorf("expected leaf_solo_login_rejections_total{reason=\"banned\"} 1 to be exposed on /metrics, got:\n%s", body)
	}
}

// scrapeSoloMetrics performs a real HTTP GET against s.MetricsHandler()
// via httptest and returns the raw Prometheus text-exposition body --
// confirms the new metric is genuinely reachable over the real
// /metrics HTTP surface, not just present in the private registry.
func scrapeSoloMetrics(t *testing.T, s *Server) string {
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

// TestSessionLoginRejectionReason_NoJobTemplate covers handleLogin's
// s.server.jobManager.JobForXNAtDifficulty failure call site -- a
// real, valid, unbanned login that still can't be issued a job
// because the node's GetBlockTemplate call itself fails.
func TestSessionLoginRejectionReason_NoJobTemplate(t *testing.T) {
	node := &fakeNodeClient{
		height:              42,
		mergeMiningHash:     []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:       []byte("test-block-hash-seed-32-bytes!!"),
		getBlockTemplateErr: errors.New("login-rejection-test: no template available"),
	}
	h := newRejectionReasonHarness(t, poolpb.Algo_ALGO_SHA3X, 1000, 1<<62, 0, validator.Registry{poolpb.Algo_ALGO_SHA3X: validator.NewSHA3XValidator()}, node)

	addr := realTariTestAddress("login-rejection-no-job-template")
	h.send(Request{ID: 1, Method: "login", Params: mustJSON(t, LoginRequest{Login: addr, Pass: "rig1", Agent: "XMRig/6.21.0", Algo: []string{"sha3x"}})})
	raw := h.recvRaw()

	var generic struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal login rejection response: %v (raw=%s)", err, raw)
	}
	if generic.Status == "OK" {
		t.Fatalf("expected a login with no job template available to be rejected, got status=OK (raw=%s)", raw)
	}

	assertOnlyLoginRejectionReason(t, h.metrics, metrics.LoginRejectionReasonNoJobTemplate)
}
