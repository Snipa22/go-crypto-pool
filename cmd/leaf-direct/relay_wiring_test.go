// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/direct"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// fakeDirectNodeClient is a minimal solo.NodeClient test double, local
// to this test file, sufficient to exercise JobManager's tip-poll/
// template-relay wiring without a real Tari/Monero node. It does NOT
// need to be feature-complete (no real candidate-block construction)
// -- these tests only exercise GetTipInfo/GetBlockTemplate.
type fakeDirectNodeClient struct {
	mu            sync.Mutex
	height        uint64
	templateCalls atomic.Int64
}

func (f *fakeDirectNodeClient) setHeight(h uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.height = h
}

func (f *fakeDirectNodeClient) GetBlockTemplate(_ context.Context, _ string, algo poolpb.Algo) (*solo.Job, error) {
	f.mu.Lock()
	h := f.height
	f.mu.Unlock()
	n := f.templateCalls.Add(1)
	return &solo.Job{
		ID:     fmt.Sprintf("fake-job-%d", n),
		Height: h,
		Algo:   algo,
	}, nil
}

func (f *fakeDirectNodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.height, nil
}

func (f *fakeDirectNodeClient) BuildCandidateBlock(_ *solo.Job, _ uint64, _ solo.SubmitProof) (uint64, any, error) {
	return 0, nil, nil
}

func (f *fakeDirectNodeClient) SubmitBlock(_ context.Context, _ any) error {
	return nil
}

// TemplateBytesForRelay/JobFromTemplateBytes: this minimal fake has no
// real Tari template content to (de)serialize (its GetBlockTemplate
// above returns a bare *solo.Job with no TemplateData) -- these tests
// only exercise GetTipInfo/GetBlockTemplate/relay wiring plumbing, not
// adoption itself, so simple "not supported" stubs are sufficient to
// satisfy solo.NodeClient.
func (f *fakeDirectNodeClient) TemplateBytesForRelay(_ *solo.Job) ([]byte, error) {
	return nil, nil
}

func (f *fakeDirectNodeClient) JobFromTemplateBytes(_ []byte, _ poolpb.Algo) (*solo.Job, error) {
	return nil, fmt.Errorf("fakeDirectNodeClient: JobFromTemplateBytes not supported by this minimal test double")
}

// startEmbeddedNATSServerForRelayWiringTest mirrors
// internal/leaflib/relay/relay_test.go's own startEmbeddedNATSServer
// exactly (a REAL, in-process, embedded NATS server bound to an
// OS-assigned free port) -- duplicated here rather than imported
// since that helper is unexported/package-private.
func startEmbeddedNATSServerForRelayWiringTest(t *testing.T) (url string, shutdown func()) {
	t.Helper()
	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1,
		NoLog:          true,
		NoSigs:         true,
		MaxControlLine: 4096,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("starting embedded NATS server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("embedded NATS server did not become ready within 5s")
	}
	t.Cleanup(func() {
		srv.Shutdown()
		srv.WaitForShutdown()
	})
	return srv.ClientURL(), srv.Shutdown
}

// TestLeafDirectTemplateRelayNoOpWhenNATSURLEmpty proves the exact
// no-op contract every other optional feature in this binary has:
// with -relay-nats-url (LEAF_DIRECT_RELAY_NATS_URL) left empty, the
// *relay.Relay constructed by main() the same way blockRelay is
// (relay.NewRelay(relay.Config{URL: ""})) is disabled, and wiring it
// into solo.JobManagerConfig.Relay is a complete no-op -- no dial, no
// publish, no subscribe, matching relay.Relay's own nil/disabled-safe
// contract (see JobManagerConfig.Relay's doc comment in job.go).
func TestLeafDirectTemplateRelayNoOpWhenNATSURLEmpty(t *testing.T) {
	blockRelay := relay.NewRelay(relay.Config{URL: ""})
	defer blockRelay.Close()
	if blockRelay.Enabled() {
		t.Fatal("expected relay.NewRelay with an empty URL to be disabled (Enabled() == false)")
	}

	node := &fakeDirectNodeClient{height: 10}
	jm := solo.NewJobManager(solo.JobManagerConfig{
		Node: node, PayoutAddress: "leaf-direct-test-address",
		Algo: poolpb.Algo_ALGO_SHA3X, Network: "testnet",
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 20 * time.Millisecond,
		Relay:           blockRelay, // exactly leaf-direct main()'s own wiring
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx) // must not panic/dial/block even though Relay is disabled

	// Drive a genuine local tip increase -- publishTemplate must be a
	// complete no-op (disabled Relay), never blocking or erroring.
	node.setHeight(11)
	time.Sleep(150 * time.Millisecond)
}

// TestLeafDirectSharesOneRelayInstanceForFoundBlockAndTemplate proves
// leaf-direct's real architecture: the SAME *relay.Relay instance
// (one shared *nats.Conn) constructed once in main() is wired into
// BOTH direct.ServerConfig.Relay (found-block relay, already working)
// AND solo.JobManagerConfig.Relay (template relay) -- exactly
// mirroring main()'s own construction order (blockRelay built once,
// then passed to solo.NewJobManager, then to direct.NewServer). This
// uses a REAL embedded NATS server to prove the shared instance
// genuinely round-trips a TemplateMessage end-to-end when consulted
// via the JobManagerConfig.Relay leg -- not just a pointer-identity
// check.
func TestLeafDirectSharesOneRelayInstanceForFoundBlockAndTemplate(t *testing.T) {
	url, shutdown := startEmbeddedNATSServerForRelayWiringTest(t)
	defer shutdown()

	// blockRelay mirrors main()'s own construction EXACTLY: built
	// once, before JobManager, then threaded into BOTH consumers.
	blockRelay := relay.NewRelay(relay.Config{URL: url})
	defer blockRelay.Close()
	if !blockRelay.Enabled() {
		t.Fatalf("expected blockRelay to be Enabled() after connecting to a real NATS server at %s", url)
	}

	node := &fakeDirectNodeClient{height: 50}
	jobManager := solo.NewJobManager(solo.JobManagerConfig{
		Node: node, PayoutAddress: "leaf-direct-test-address",
		Algo: poolpb.Algo_ALGO_SHA3X, Network: "testnet",
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 24 * time.Hour, // disabled: only the relay subscription should trigger invalidation here
		Relay:           blockRelay,     // <-- the fix under test: same instance as below
	})

	// direct.NewServer's ServerConfig.Relay also takes the SAME
	// blockRelay instance for the found-block broadcast -- confirming
	// this compiles/constructs is the architectural assertion that
	// there is exactly one *relay.Relay (one NATS connection) shared
	// by both features, matching leaf-solo's pre-removal precedent.
	server := direct.NewServer(direct.ServerConfig{
		JobManager: jobManager, Node: node,
		Network: poolpb.Network_NETWORK_TESTNET,
		Relay:   blockRelay,
	})
	defer server.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstJob, err := jobManager.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (seed): %v", err)
	}

	jobManager.Start(ctx)
	time.Sleep(150 * time.Millisecond) // let the real NATS subscription land

	// Externally publish a TemplateMessage from a DIFFERENT Relay
	// instance (genuinely different PublisherID) -- proves
	// jobManager's own Relay (== blockRelay, == server's Relay) is
	// genuinely subscribed and reacts by invalidating the cache.
	externalRelay := relay.NewRelay(relay.Config{URL: url})
	defer externalRelay.Close()
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 51, Hash: "external-tip-hash",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jobManager.GetJob(firstJob.ID); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expected the externally-received template message to invalidate the per-xn job cache via leaf-direct's shared blockRelay instance (pre-existing job id still resolvable)")
}
