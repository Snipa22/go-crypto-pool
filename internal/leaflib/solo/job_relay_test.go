// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// syntheticTariResultForAdoptionTest builds a real, minimal-but-valid
// *tari_generated.GetNewBlockResult for the relay-template-adoption
// tests below (TestJobManagerAdopts*/TestJobManagerLocal*): height and
// paddingBytes (via Block.Header.Pow.PowData) are the two knobs these
// tests need to control a candidate's (height, real-serialized-size)
// pair precisely, mirroring the real shape tariJobFromResult requires
// (a populated Block/Header chain).
func syntheticTariResultForAdoptionTest(height uint64, paddingBytes int) *tari_generated.GetNewBlockResult {
	return &tari_generated.GetNewBlockResult{
		BlockHash:       []byte("adoption-test-block-hash-32byte"),
		MergeMiningHash: []byte("adoption-test-merge-mining-hash"),
		Block: &tari_generated.Block{
			Header: &tari_generated.BlockHeader{
				Height: height,
				Pow:    &tari_generated.ProofOfWork{PowData: bytes.Repeat([]byte{0xAB}, paddingBytes)},
			},
		},
		MinerData: &tari_generated.MinerData{TargetDifficulty: 123456},
	}
}

// marshalSyntheticTariResultForAdoptionTest proto.Marshal's result,
// failing the test immediately on any error -- every caller below
// needs real, valid wire bytes, never a partially-built value.
func marshalSyntheticTariResultForAdoptionTest(t *testing.T, result *tari_generated.GetNewBlockResult) []byte {
	t.Helper()
	data, err := proto.Marshal(result)
	if err != nil {
		t.Fatalf("proto.Marshal(synthetic GetNewBlockResult): %v", err)
	}
	return data
}

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

	// Seed a cached job for one session BEFORE starting/subscribing, so
	// there's something real to observe being invalidated.
	firstJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (seed): %v", err)
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
	// fresh JobForSession call for the SAME session must trigger a genuinely NEW
	// GetBlockTemplate call (not just return the same cached job).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jm.GetJob(firstJob.ID); !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := jm.GetJob(firstJob.ID); ok {
		t.Fatal("expected the externally-received template message to invalidate the per-session job cache (pre-existing job id still resolvable)")
	}

	secondJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (post-invalidate): %v", err)
	}
	if secondJob.ID == firstJob.ID {
		t.Error("expected a freshly-generated job (different ID) for the same sessionKey after relay-triggered invalidation")
	}
	if node.templateCalls.Load() != 2 {
		t.Errorf("expected a genuinely NEW GetBlockTemplate call after relay-triggered invalidation (templateCalls=2), got %d", node.templateCalls.Load())
	}
}

// TestJobManagerAdoptsSuperiorRelayTemplateWithoutLocalFetch proves
// requirement (a) of the relay-template-adoption brief: a relay
// message carrying a strictly higher height than what this JobManager
// currently has adopted causes adoption WITHOUT a local
// GetBlockTemplate call being made -- asserted by the fake
// NodeClient's own call counter never incrementing beyond the single
// seed fetch, even after the adopted job is subsequently re-served to
// the SAME session.
func TestJobManagerAdoptsSuperiorRelayTemplateWithoutLocalFetch(t *testing.T) {
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
		TipPollInterval: 24 * time.Hour, // disabled: only the relay subscription should matter here
		Relay:           jmRelay,
	})

	// Seed a cached job for one session BEFORE the relay message arrives
	// -- this is the pre-existing session that must be reseeded directly
	// from the relayed content (no local re-fetch) once a superior
	// template is adopted.
	firstJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (seed): %v", err)
	}
	if node.templateCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 template call after seeding, got %d", node.templateCalls.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)
	time.Sleep(150 * time.Millisecond) // let the real NATS subscription land

	// Externally publish a genuinely superior (strictly higher
	// height) TemplateMessage carrying REAL, reconstructible template
	// content from a DIFFERENT Relay instance.
	result := syntheticTariResultForAdoptionTest(51, 64)
	data := marshalSyntheticTariResultForAdoptionTest(t, result)
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 51,
		TemplateData: data, Size: len(data), Hash: "external-superior-tip-hash",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}

	// Poll for the real, observable adoption effect: the pre-existing
	// job id must be gone (replaced by the reconstructed relay job).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jm.GetJob(firstJob.ID); !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := jm.GetJob(firstJob.ID); ok {
		t.Fatal("expected the superior relayed template to replace the pre-existing job (old job id still resolvable)")
	}

	// The SAME session's next request must be served the reconstructed
	// relayed job directly (a cache HIT against the reseeded entry),
	// with NO additional local GetBlockTemplate call.
	secondJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (post-adopt): %v", err)
	}
	if secondJob.Height != 51 {
		t.Errorf("secondJob.Height = %d, want 51 (the adopted relayed template's height)", secondJob.Height)
	}
	if node.templateCalls.Load() != 1 {
		t.Errorf("expected NO additional local GetBlockTemplate call after relay adoption (templateCalls should still be 1), got %d", node.templateCalls.Load())
	}
}

// TestJobManagerDoesNotAdoptEqualHeightSmallerRelayTemplate proves
// requirement (b): a relay message with equal height but SMALLER
// serialized size than the currently tracked best does NOT get
// adopted and does NOT wipe the existing per-session job cache.
func TestJobManagerDoesNotAdoptEqualHeightSmallerRelayTemplate(t *testing.T) {
	url, shutdown := startEmbeddedNATSServerForJobTest(t)
	defer shutdown()

	jmRelay := relay.NewRelay(relay.Config{URL: url})
	defer jmRelay.Close()
	externalRelay := relay.NewRelay(relay.Config{URL: url})
	defer externalRelay.Close()
	if !jmRelay.Enabled() || !externalRelay.Enabled() {
		t.Fatalf("expected both relays to be Enabled() after connecting to a real NATS server at %s", url)
	}

	// A real-shaped, sizeable local template (lots of PowData padding)
	// so a deliberately tiny relay candidate at the SAME height is
	// unambiguously smaller.
	node := &fakeNodeClient{height: 50, powData: bytes.Repeat([]byte{0x01}, 512)}
	jm := NewJobManager(JobManagerConfig{
		Node: node, PayoutAddress: "solo-test-address",
		Algo: poolpb.Algo_ALGO_SHA3X, Network: "testnet",
		RefreshInterval: 24 * time.Hour,
		TipPollInterval: 24 * time.Hour,
		Relay:           jmRelay,
	})

	firstJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (seed): %v", err)
	}
	firstSize := jm.templateSizeForRelay(firstJob)
	if firstSize == 0 {
		t.Fatal("expected a nonzero real serialized size for the seeded job")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)
	time.Sleep(150 * time.Millisecond)

	// Same height, deliberately tiny (no padding) -- must be smaller
	// than firstSize.
	smallResult := syntheticTariResultForAdoptionTest(50, 0)
	smallData := marshalSyntheticTariResultForAdoptionTest(t, smallResult)
	if len(smallData) >= firstSize {
		t.Fatalf("test setup invariant violated: smallData (%d bytes) must be smaller than the seeded job's real size (%d bytes)", len(smallData), firstSize)
	}
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 50,
		TemplateData: smallData, Size: len(smallData), Hash: "external-equal-height-smaller-hash",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}

	// Give the (non-)adoption a moment to (not) happen, then assert
	// the pre-existing job is still exactly as it was: NOT wiped, NOT
	// replaced, and no extra local fetch was triggered either.
	time.Sleep(300 * time.Millisecond)
	if _, ok := jm.GetJob(firstJob.ID); !ok {
		t.Fatal("expected the equal-height-smaller relay template to be REJECTED -- the pre-existing job must still be resolvable (cache must not have been wiped)")
	}
	sameJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (after rejected relay message): %v", err)
	}
	if sameJob.ID != firstJob.ID {
		t.Errorf("expected the SAME job (id=%s) to still be served for sessionKey 'aaaa' after a rejected relay message, got a different job (id=%s)", firstJob.ID, sameJob.ID)
	}
	if node.templateCalls.Load() != 1 {
		t.Errorf("expected no additional local GetBlockTemplate call after a rejected relay message, got %d calls", node.templateCalls.Load())
	}
}

// TestJobManagerLocalTipPollDoesNotClobberSuperiorAdoptedRelayJob
// proves requirement (c): once a superior relayed template has been
// adopted (height AHEAD of this instance's own local node), a
// subsequent local tip-poll tick that observes a genuine local tip
// increase which is STILL inferior to the adopted best (lower height
// than the adopted job) must NOT clobber it -- the previously-adopted
// job must still be served afterward.
func TestJobManagerLocalTipPollDoesNotClobberSuperiorAdoptedRelayJob(t *testing.T) {
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
		TipPollInterval: 20 * time.Millisecond,
		Relay:           jmRelay,
	})

	firstJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (seed): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)
	time.Sleep(150 * time.Millisecond) // let the first tip-poll tick seed its baseline (height 50), and the NATS subscription land

	// Adopt a superior relayed template well ahead of local (height
	// 60 vs local's own 50).
	result := syntheticTariResultForAdoptionTest(60, 64)
	data := marshalSyntheticTariResultForAdoptionTest(t, result)
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 60,
		TemplateData: data, Size: len(data), Hash: "external-ahead-hash",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}

	var adoptedJob *Job
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jm.GetJob(firstJob.ID); !ok {
			adoptedJob, err = jm.JobForSession(context.Background(), "aaaa")
			if err != nil {
				t.Fatalf("JobForSession (post-adopt): %v", err)
			}
			if adoptedJob.Height == 60 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if adoptedJob == nil || adoptedJob.Height != 60 {
		t.Fatalf("expected the superior relayed template (height 60) to be adopted, got %+v", adoptedJob)
	}

	// Now drive a genuine LOCAL tip increase that is still inferior
	// to the adopted height (50 -> 55, still < 60). This must trigger
	// a local candidate fetch (for the comparison) but must NOT
	// clobber the already-adopted, superior job.
	callsBeforeLocalBump := node.templateCalls.Load()
	node.setHeight(55)

	time.Sleep(300 * time.Millisecond) // several tip-poll ticks

	stillAdopted, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (after inferior local tip bump): %v", err)
	}
	if stillAdopted.ID != adoptedJob.ID {
		t.Errorf("expected the previously-adopted relay job (id=%s height=60) to still be served after an inferior local tip increase (height 55), got a different job (id=%s height=%d)",
			adoptedJob.ID, stillAdopted.ID, stillAdopted.Height)
	}
	if node.templateCalls.Load() <= callsBeforeLocalBump {
		t.Errorf("expected tipPollLoop to have fetched at least one local candidate template to perform the comparison, but templateCalls did not increase (still %d)", node.templateCalls.Load())
	}
}

// TestJobManagerLocalTipPollReplacesAdoptedRelayJobWhenGenuinelyAhead
// proves requirement (d): a subsequent local tip-poll tick that DOES
// produce a genuinely higher height than a previously-adopted relay
// job correctly replaces it -- local can still win when it's actually
// ahead.
func TestJobManagerLocalTipPollReplacesAdoptedRelayJobWhenGenuinelyAhead(t *testing.T) {
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
		TipPollInterval: 20 * time.Millisecond,
		Relay:           jmRelay,
	})

	firstJob, err := jm.JobForSession(context.Background(), "aaaa")
	if err != nil {
		t.Fatalf("JobForSession (seed): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)
	time.Sleep(150 * time.Millisecond)

	// Adopt a relayed template at height 60.
	result := syntheticTariResultForAdoptionTest(60, 64)
	data := marshalSyntheticTariResultForAdoptionTest(t, result)
	if err := externalRelay.PublishTemplate(context.Background(), relay.TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 60,
		TemplateData: data, Size: len(data), Hash: "external-ahead-hash-2",
	}); err != nil {
		t.Fatalf("PublishTemplate (external): %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := jm.GetJob(firstJob.ID); !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := jm.GetJob(firstJob.ID); ok {
		t.Fatal("expected the relayed template (height 60) to be adopted before proceeding")
	}

	// Now drive a genuine LOCAL tip increase that is GENUINELY ahead
	// of the adopted relay job (50 -> 65 > 60). Local must win.
	node.setHeight(65)

	deadline = time.Now().Add(5 * time.Second)
	var winner *Job
	for time.Now().Before(deadline) {
		job, err := jm.JobForSession(context.Background(), "aaaa")
		if err != nil {
			t.Fatalf("JobForSession (post local-ahead): %v", err)
		}
		if job.Height == 65 {
			winner = job
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if winner == nil {
		t.Fatal("expected a genuinely higher local tip (height 65) to eventually replace the previously-adopted relay job (height 60)")
	}
}
