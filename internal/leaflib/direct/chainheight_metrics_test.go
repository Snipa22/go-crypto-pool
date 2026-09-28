// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// chainHeightFakeNode is a minimal solo.NodeClient test double
// (mirrors debounce_test.go's debounceFakeNode convention exactly)
// giving TestEnableChainHeightMetrics_* direct, independent control
// over the height GetTipInfo reports, without any real Tari/Monero
// daemon connection.
type chainHeightFakeNode struct {
	height atomic.Uint64
	calls  atomic.Int64
}

func (f *chainHeightFakeNode) GetBlockTemplate(_ context.Context, _ string, algo poolpb.Algo) (*solo.Job, error) {
	return &solo.Job{ID: "chainheight-fake-job", Height: f.height.Load(), Algo: algo}, nil
}

func (f *chainHeightFakeNode) GetTipInfo(_ context.Context) (uint64, error) {
	f.calls.Add(1)
	return f.height.Load(), nil
}

func (f *chainHeightFakeNode) BuildCandidateBlock(_ *solo.Job, _ uint64, _ solo.SubmitProof) (uint64, any, error) {
	return 0, nil, nil
}

func (f *chainHeightFakeNode) SubmitBlock(_ context.Context, _ any) error { return nil }

func (f *chainHeightFakeNode) TemplateBytesForRelay(_ *solo.Job) ([]byte, error) {
	return nil, fmt.Errorf("chainHeightFakeNode: TemplateBytesForRelay not supported by this minimal test double")
}

func (f *chainHeightFakeNode) JobFromTemplateBytes(_ []byte, _ poolpb.Algo) (*solo.Job, error) {
	return nil, fmt.Errorf("chainHeightFakeNode: JobFromTemplateBytes not supported by this minimal test double")
}

var _ solo.NodeClient = (*chainHeightFakeNode)(nil)

func newChainHeightTestServer(t *testing.T, algo poolpb.Algo) (*Server, *chainHeightFakeNode) {
	t.Helper()
	node := &chainHeightFakeNode{}
	node.height.Store(999)

	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:            node,
		PayoutAddress:   "chainheight-test-address",
		Algo:            algo,
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 24 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})

	server := NewServer(ServerConfig{
		ConnectionManager: cm,
		JobManager:        jm,
		Node:              node,
		Network:           poolpb.Network_NETWORK_TESTNET,
		Algo:              algo,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            1,
	})
	t.Cleanup(server.Shutdown)
	return server, node
}

// scrapeMetrics is a small local helper mirroring metrics_test.go's
// own scrape() convention (that helper lives in the metrics package
// and isn't exported), reading directly from the *metrics.Metrics
// HTTP handler this package's server.go wires.
func scrapeMetrics(t *testing.T, s *Server) string {
	t.Helper()
	srv := httptest.NewServer(s.MetricsHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /metrics body: %v", err)
	}
	return string(body)
}

// TestEnableChainHeightMetrics_MoneroFamilyEmitsMoneroGauge proves
// EnableChainHeightMetrics, wired against a Monero-family
// (ALGO_RXM) server, populates leaf_monero_chain_height with the
// real polled height and never leaf_tari_chain_height.
func TestEnableChainHeightMetrics_MoneroFamilyEmitsMoneroGauge(t *testing.T) {
	server, node := newChainHeightTestServer(t, poolpb.Algo_ALGO_RXM)
	node.height.Store(1234567)
	server.EnableMetrics("chainheight-test", 0)
	server.EnableChainHeightMetrics()

	waitForPoll(t, node)

	body := scrapeMetrics(t, server)
	if !strings.Contains(body, "leaf_monero_chain_height 1.234567e+06") {
		t.Errorf("expected leaf_monero_chain_height 1.234567e+06 in output, got:\n%s", body)
	}
	if strings.Contains(body, "leaf_tari_chain_height") {
		t.Errorf("expected no leaf_tari_chain_height for a Monero-family leaf, got:\n%s", body)
	}
}

// TestEnableChainHeightMetrics_TariFamilyEmitsTariGauge is
// TestEnableChainHeightMetrics_MoneroFamilyEmitsMoneroGauge's
// Tari-family (ALGO_RXT) analogue.
func TestEnableChainHeightMetrics_TariFamilyEmitsTariGauge(t *testing.T) {
	server, node := newChainHeightTestServer(t, poolpb.Algo_ALGO_RXT)
	node.height.Store(42)
	server.EnableMetrics("chainheight-test", 0)
	server.EnableChainHeightMetrics()

	waitForPoll(t, node)

	body := scrapeMetrics(t, server)
	if !strings.Contains(body, "leaf_tari_chain_height 42") {
		t.Errorf("expected leaf_tari_chain_height 42 in output, got:\n%s", body)
	}
	if strings.Contains(body, "leaf_monero_chain_height") {
		t.Errorf("expected no leaf_monero_chain_height for a Tari-family leaf, got:\n%s", body)
	}
}

// TestEnableChainHeightMetrics_NoopWithoutEnableMetrics proves the
// documented no-op safety: calling EnableChainHeightMetrics before
// (or without ever calling) EnableMetrics must not panic, and must
// not start a background poller (checked via node.calls staying 0).
func TestEnableChainHeightMetrics_NoopWithoutEnableMetrics(t *testing.T) {
	server, node := newChainHeightTestServer(t, poolpb.Algo_ALGO_RXM)
	server.EnableChainHeightMetrics()

	time.Sleep(50 * time.Millisecond)
	if node.calls.Load() != 0 {
		t.Errorf("expected 0 GetTipInfo calls when EnableMetrics was never called, got %d", node.calls.Load())
	}
}

// waitForPoll polls node.calls until at least one real GetTipInfo
// call has been observed (EnableChainHeightMetrics' Start() polls
// synchronously before returning, so this should succeed
// immediately -- the loop is just a safety margin against
// scheduling jitter, never a fixed sleep).
func waitForPoll(t *testing.T, node *chainHeightFakeNode) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if node.calls.Load() > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("GetTipInfo was never called within 2s of EnableChainHeightMetrics")
}
