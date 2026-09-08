// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// startEmbeddedNATSServerForJobTest mirrors
// internal/leaflib/relay/relay_test.go's own startEmbeddedNATSServer
// exactly (a REAL, in-process, embedded NATS server bound to an
// OS-assigned free port) — duplicated here rather than imported since
// relay_test.go's helper is unexported and package-private to relay's
// own test package.
func startEmbeddedNATSServerForJobTest(t *testing.T) (url string, shutdown func()) {
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

// TestJobManagerTipIncreasePublishesTemplate proves tipPollLoop's
// real local tip-increase detection genuinely calls PublishTemplate
// over a REAL embedded NATS server — not a mock — and proves the
// negative cases explicitly required by BRIEF.md: no publish on the
// first tip observation (baseline seed), and no publish when height
// is unchanged.
func TestJobManagerTipIncreasePublishesTemplate(t *testing.T) {
	url, shutdown := startEmbeddedNATSServerForJobTest(t)
	defer shutdown()

	publisherRelay := relay.NewRelay(relay.Config{URL: url})
	defer publisherRelay.Close()
	observerRelay := relay.NewRelay(relay.Config{URL: url})
	defer observerRelay.Close()
	if !publisherRelay.Enabled() || !observerRelay.Enabled() {
		t.Fatalf("expected both relays to be Enabled() after connecting to a real NATS server at %s", url)
	}

	received := make(chan relay.TemplateMessage, 8)
	unsub, err := observerRelay.SubscribeTemplate(func(msg relay.TemplateMessage) {
		received <- msg
	})
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsub()
	time.Sleep(100 * time.Millisecond)

	node := &fakeNodeClient{height: 10}
	jm := NewJobManager(JobManagerConfig{
		Node: node, PayoutAddress: "solo-test-address",
		Algo: poolpb.Algo_ALGO_SHA3X, Network: "testnet",
		RefreshInterval: 24 * time.Hour, // effectively disabled for this test
		TipPollInterval: 20 * time.Millisecond,
		Relay:           publisherRelay,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)

	// First tip observation (baseline seed at height 10): must NOT
	// publish anything.
	select {
	case msg := <-received:
		t.Fatalf("expected NO template publish on the first tip observation (baseline seed), got %+v", msg)
	case <-time.After(300 * time.Millisecond):
		// expected: nothing published yet
	}

	// Height unchanged (still 10): must NOT publish anything either.
	select {
	case msg := <-received:
		t.Fatalf("expected NO template publish while height is unchanged, got %+v", msg)
	case <-time.After(200 * time.Millisecond):
		// expected: still nothing published
	}

	// Genuine local tip increase: MUST publish a real TemplateMessage.
	node.setHeight(11)
	select {
	case msg := <-received:
		if msg.Height != 11 {
			t.Errorf("published TemplateMessage.Height = %d, want 11", msg.Height)
		}
		if msg.Algo != "sha3x" {
			t.Errorf("published TemplateMessage.Algo = %q, want %q", msg.Algo, "sha3x")
		}
		if msg.Network != "testnet" {
			t.Errorf("published TemplateMessage.Network = %q, want %q", msg.Network, "testnet")
		}
		if msg.Hash == "" {
			t.Error("published TemplateMessage.Hash must not be empty (dedup key)")
		}
		if msg.PublisherID == "" {
			t.Error("published TemplateMessage.PublisherID must not be empty")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected a real TemplateMessage to be published on genuine local tip increase within 5s")
	}
}

// TestJobManagerReceivingTemplateInvalidatesCache proves a JobManager
// configured with a real relay.Relay, upon RECEIVING an externally-
// published TemplateMessage from a DIFFERENT Relay instance (different
// PublisherID) via the relay, calls InvalidateAll itself — verified by
// confirming a fresh GetBlockTemplate call actually happens (fakeNode
// Client.templateCalls) after the externally-received template
// message, not merely that some internal flag flipped.
func TestJobManagerReceivingTemplateInvalidatesCache(t *testing.T) {
	url, shutdown := startEmbeddedNATSServerForJobTest(t)
	defer shutdown()

	jmRelay := relay.NewRelay(relay.Config{URL: url})
	defer jmRelay.Close()
	externalRelay := relay.NewRelay(relay.Config{URL: url})
	defer externalRelay.Close()
	if !jmRelay.Enabled() || !externalRelay.Enabled() {
		t.Fatalf("expected both relays to be Enabled() after connecting to a real NATS server at %s", url)
	}

	node := &fakeNodeClient{height: 50}
	jm := NewJobManager(JobManagerConfig{
		Node: node, PayoutAddress: "solo-test-address",
		Algo: poolpb.Algo_ALGO_SHA3X, Network: "testnet",
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 24 * time.Hour, // disabled: only the relay subscription should trigger invalidation here
	})
	jm.cfg.Relay = jmRelay // set directly so NewJobManager's own defaulting logic is exercised identically to a real caller passing Relay in JobManagerConfig

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Seed a cached job for xn "aaaa" BEFORE starting/subscribing, so
	// there's something real to observe being invalidated.
	firstJob, err := jm.JobForXN(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForXN (seed): %v", err)
	}
	if node.templateCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 template call after seeding, got %d", node.templateCalls.Load())
	}

	jm.Start(ctx)
	time.Sleep(150 * time.Millisecond) // let the real NATS subscription land

	// Externally publish a TemplateMessage from a DIFFERENT Relay
	// instance (genuinely different PublisherID).
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 51, Hash: "external-tip-hash",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}

	// Poll for the real, observable effect: the pre-existing cached
	// job for "aaaa" must be gone (InvalidateAll actually ran), and a
	// fresh JobForXN call for the SAME xn must trigger a genuinely NEW
	// GetBlockTemplate call (not just return the same cached job).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jm.GetJob(firstJob.ID); !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := jm.GetJob(firstJob.ID); ok {
		t.Fatal("expected the externally-received template message to invalidate the per-xn job cache (pre-existing job id still resolvable)")
	}

	secondJob, err := jm.JobForXN(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForXN (post-invalidate): %v", err)
	}
	if secondJob.ID == firstJob.ID {
		t.Error("expected a freshly-generated job (different ID) for the same xn after relay-triggered invalidation")
	}
	if node.templateCalls.Load() != 2 {
		t.Errorf("expected a genuinely NEW GetBlockTemplate call after relay-triggered invalidation (templateCalls=2), got %d", node.templateCalls.Load())
	}
}
