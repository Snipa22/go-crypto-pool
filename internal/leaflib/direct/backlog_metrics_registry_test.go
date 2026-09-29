// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport/backlog"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestEnableMetricsWithRegistry_SharesRegistryWithBacklog is the real
// end-to-end regression test for DISPATCH_BRIEF.md's "wire backlog
// metrics into the leaf's real /metrics endpoint" fix: it wires up a
// disk-backed backlog.BacklogTransport (internal/leaflib/transport/
// backlog) and a Server's own EnableMetricsWithRegistry against ONE
// shared *prometheus.Registry -- exactly the real cmd/leaf-direct/
// main.go construction order (registry created before the backlog
// wrap, which happens before direct.NewServer, which happens before
// EnableMetricsWithRegistry) -- and asserts, via a real HTTP GET
// against the merged handler, that BOTH a leaf_backlog_* metric name
// (proving the backlog decorator's own metrics landed on the shared
// registry, not an orphaned private one) AND a pre-existing
// leaf_direct_* metric name (proving no regression to the existing
// leaf-direct observability) appear in the SAME scrape response body.
func TestEnableMetricsWithRegistry_SharesRegistryWithBacklog(t *testing.T) {
	// Step 1: create the shared registry FIRST, exactly mirroring
	// main.go's own ordering fix -- this must happen before the
	// backlog wrap below, since backlog.New needs it at construction
	// time and there is no way to hand it a registry after the fact.
	reg := prometheus.NewRegistry()

	// Step 2: construct backendTransport, then wrap it in a
	// disk-backed backlog.BacklogTransport against the shared
	// registry -- mirrors main.go's backlog.Config.Registry wiring.
	var innerTransport noopShareTransport
	wrapped, err := backlog.New(&innerTransport, backlog.Config{
		Dir:      t.TempDir(),
		Registry: reg,
	})
	if err != nil {
		t.Fatalf("backlog.New: %v", err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })

	// Step 3: construct the Server with the FINAL (backlog-wrapped)
	// transport, mirroring direct.NewServer's real ordering constraint
	// that Transport must already be finalized at construction time
	// (see EnableMetricsWithRegistry's own doc comment).
	node := &chainHeightFakeNode{}
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node:            node,
		PayoutAddress:   "backlog-metrics-registry-test-address",
		Algo:            poolpb.Algo_ALGO_RXT,
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
		Algo:              poolpb.Algo_ALGO_RXT,
		PoolType:          poolpb.PoolType_POOL_TYPE_SOLO,
		PoolID:            1,
		Transport:         wrapped,
	})
	t.Cleanup(server.Shutdown)

	// Step 4: EnableMetricsWithRegistry against the SAME shared
	// registry -- the actual fix under test.
	server.EnableMetricsWithRegistry(reg, "backlog-metrics-registry-test", 0)

	// Step 5: real HTTP GET against the merged handler (server.
	// MetricsHandler serves m.registry, which IS reg, since we handed
	// reg into EnableMetricsWithRegistry above).
	srv := httptest.NewServer(server.MetricsHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /metrics body: %v", err)
	}
	body := string(bodyBytes)

	// leaf_backlog_depth/leaf_backlog_bytes are GaugeVecs unconditionally
	// initialized (both kind labels) by refreshGauges at construction;
	// leaf_backlog_corrupt_drops_total is a plain (non-vec) Counter --
	// all three are always present regardless of whether any real
	// enqueue/drain ever happened, unlike e.g. leaf_backlog_enqueued_total
	// (a CounterVec whose "share"/"block" label time series only start
	// existing once actually incremented).
	if !strings.Contains(body, "leaf_backlog_depth") {
		t.Errorf("expected leaf_backlog_depth (a backlog-package metric) in the merged /metrics output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_backlog_bytes") {
		t.Errorf("expected leaf_backlog_bytes (a backlog-package metric) in the merged /metrics output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_backlog_corrupt_drops_total") {
		t.Errorf("expected leaf_backlog_corrupt_drops_total (a backlog-package metric) in the merged /metrics output, got:\n%s", body)
	}
	if !strings.Contains(body, "leaf_direct_shares_total") {
		t.Errorf("expected leaf_direct_shares_total (a pre-existing directmetrics-owned metric) still present in the merged /metrics output (no regression), got:\n%s", body)
	}
	if !strings.Contains(body, `leaf_direct_build_info{version="backlog-metrics-registry-test"}`) {
		t.Errorf("expected leaf_direct_build_info with this test's version label in the merged /metrics output, got:\n%s", body)
	}

	// Merge-reconciliation regression (fix/backlog-metrics-registry-
	// wiring x main): confirms main's independently-landed Go/process
	// runtime collectors ALSO land on this same shared registry
	// alongside the backlog decorator's metrics, with no duplicate-
	// registration panic -- i.e. NewWithRegistry's merged
	// nil-check-plus-collectors body still registers
	// collectors.NewGoCollector/NewProcessCollector exactly once even
	// when reg is caller-supplied (shared), not a fresh private
	// registry. (main's submit-timing HistogramVecs are NOT checked
	// here: like leaf_backlog_enqueued_total above, a HistogramVec
	// emits no sample for any label combination until actually
	// Observe()'d at least once, and this test never submits a
	// share.)
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("expected go_goroutines (main's Go runtime collector) in the merged /metrics output, got:\n%s", body)
	}
	if !strings.Contains(body, "process_resident_memory_bytes") {
		t.Errorf("expected process_resident_memory_bytes (main's process collector) in the merged /metrics output, got:\n%s", body)
	}
}

// noopShareTransport is a minimal transport.ShareTransport test
// double that always succeeds -- this test only exercises the metrics
// REGISTRATION wiring (both packages' collectors landing on one
// shared registry), not backlog's own enqueue/drain behavior (already
// covered by internal/leaflib/transport/backlog's own tests), so a
// permanently-succeeding inner transport is sufficient and keeps this
// test from ever touching the drain loop's retry/backoff timing.
type noopShareTransport struct{}

func (noopShareTransport) SubmitShare(_ context.Context, _ *poolpb.Share) error { return nil }
func (noopShareTransport) SubmitBlock(_ context.Context, _ *poolpb.Block) error { return nil }
func (noopShareTransport) Close() error                                         { return nil }
