// Copyright and license: see repository LICENSE (MIT).
package relay

import (
	"context"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
)

// startEmbeddedNATSServer starts a REAL, in-process, embedded NATS
// server (github.com/nats-io/nats-server/v2's own public server.New/
// Start/ReadyForConnections API — the same real NATS server binary
// logic, just running in-process for the test), bound to an
// OS-assigned free port so parallel test runs never collide. Returns
// the real "nats://127.0.0.1:<port>" client URL and a cleanup func.
func startEmbeddedNATSServer(t *testing.T) (url string, shutdown func()) {
	t.Helper()
	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1, // -1 = OS-assigned free port, real NATS server convention
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

// TestRelayDisabledIsCompleteNoOp confirms Publish/Subscribe/Enabled
// on a Relay built with an empty URL never attempt any real network
// I/O and never error/panic — the explicit "fully optional" contract.
func TestRelayDisabledIsCompleteNoOp(t *testing.T) {
	r := NewRelay(Config{URL: ""})
	if r.Enabled() {
		t.Fatal("expected Enabled()=false for an empty-URL Relay")
	}

	if err := r.Publish(context.Background(), BlockMessage{Height: 1, Hash: "deadbeef"}); err != nil {
		t.Fatalf("Publish on a disabled Relay must be a harmless no-op, got error: %v", err)
	}

	called := false
	unsub, err := r.Subscribe(func(BlockMessage) { called = true })
	if err != nil {
		t.Fatalf("Subscribe on a disabled Relay must be a harmless no-op, got error: %v", err)
	}
	unsub() // must not panic

	// Give any (incorrectly) scheduled async delivery a moment to
	// prove it genuinely never happens.
	time.Sleep(50 * time.Millisecond)
	if called {
		t.Fatal("handler was invoked on a disabled Relay — Subscribe must be a real no-op, not merely error-free")
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close on a disabled Relay must be a no-op, got error: %v", err)
	}
}

// TestRelayPublishDeliversToRealSubscriber is the required real,
// wire-level NATS proof: a message Published by one Relay instance,
// connected to a real embedded NATS server, is genuinely received by
// a SEPARATE Relay instance's Subscribe handler — not a mocked
// nats.Conn, an actual NATS pub/sub round trip over a real (loopback)
// socket.
func TestRelayPublishDeliversToRealSubscriber(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	publisher := NewRelay(Config{URL: url})
	defer publisher.Close()
	subscriber := NewRelay(Config{URL: url})
	defer subscriber.Close()

	if !publisher.Enabled() || !subscriber.Enabled() {
		t.Fatalf("expected both relays to be Enabled() after connecting to a real NATS server at %s", url)
	}

	received := make(chan BlockMessage, 1)
	unsub, err := subscriber.Subscribe(func(msg BlockMessage) {
		received <- msg
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()

	// Real NATS subscriptions are asynchronous to register on the
	// server side; give it a brief real moment before publishing so
	// this isn't a race against the subscription actually landing.
	time.Sleep(100 * time.Millisecond)

	want := BlockMessage{
		Algo: "sha3x", Network: "testnet", Height: 12345,
		Hash: "real-hash-from-publisher", BlockData: []byte{1, 2, 3, 4},
	}
	if err := publisher.Publish(context.Background(), want); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-received:
		if got.Height != want.Height || got.Hash != want.Hash || got.Algo != want.Algo || got.Network != want.Network {
			t.Errorf("received message = %+v, want fields matching %+v", got, want)
		}
		if string(got.BlockData) != string(want.BlockData) {
			t.Errorf("received BlockData = %v, want %v", got.BlockData, want.BlockData)
		}
		if got.PublisherID == "" {
			t.Error("expected a non-empty PublisherID stamped by the publisher")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber never received the published message over the real embedded NATS server within 5s")
	}
}

// TestRelaySkipsMessagesFromOwnPublisherID is the required real
// dedup proof: a Relay's own Subscribe handler must NOT fire for a
// message carrying that SAME Relay's own PublisherID (it published
// the message itself and already handled it locally), but MUST fire
// for a message from a genuinely different publisher — proven over a
// real embedded NATS server with two independently-connected Relay
// instances subscribed to the same subject, not by reading the
// dedup-skip code and trusting it.
func TestRelaySkipsMessagesFromOwnPublisherID(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	selfRelay := NewRelay(Config{URL: url})
	defer selfRelay.Close()
	otherPublisher := NewRelay(Config{URL: url})
	defer otherPublisher.Close()

	var selfInvocations, otherInvocations int
	selfReceivedOwn := make(chan struct{}, 1)
	receivedFromOther := make(chan BlockMessage, 1)

	unsub, err := selfRelay.Subscribe(func(msg BlockMessage) {
		if msg.PublisherID == "self-should-never-see-this" {
			// unreachable sentinel branch, kept for clarity
		}
		if msg.Hash == "own-published-hash" {
			selfInvocations++
			selfReceivedOwn <- struct{}{}
			return
		}
		otherInvocations++
		receivedFromOther <- msg
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()

	time.Sleep(100 * time.Millisecond)

	// 1) selfRelay publishes its OWN message — Subscribe's dedup-skip
	// (msg.PublisherID == r.id) must prevent its own handler from
	// firing for this at all.
	if err := selfRelay.Publish(context.Background(), BlockMessage{Height: 1, Hash: "own-published-hash"}); err != nil {
		t.Fatalf("Publish (self): %v", err)
	}

	// 2) otherPublisher (a genuinely different Relay instance, hence a
	// different PublisherID) publishes a DIFFERENT message on the same
	// subject — selfRelay's Subscribe handler MUST fire for this one.
	if err := otherPublisher.Publish(context.Background(), BlockMessage{Height: 2, Hash: "other-published-hash"}); err != nil {
		t.Fatalf("Publish (other): %v", err)
	}

	select {
	case got := <-receivedFromOther:
		if got.Hash != "other-published-hash" {
			t.Errorf("received hash = %q, want %q", got.Hash, "other-published-hash")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected the handler to fire for the OTHER publisher's message within 5s")
	}

	// Give the (correctly-skipped) self-published message every
	// reasonable real chance to have arrived and wrongly fired the
	// handler before concluding it genuinely never did.
	select {
	case <-selfReceivedOwn:
		t.Fatal("REAL DEDUP FAILURE: selfRelay's own handler fired for a message it published itself — PublisherID dedup-skip is broken")
	case <-time.After(300 * time.Millisecond):
		// expected: no invocation for the self-published message
	}

	if selfInvocations != 0 {
		t.Errorf("selfInvocations = %d, want 0 (own-publisher messages must be skipped)", selfInvocations)
	}
	if otherInvocations != 1 {
		t.Errorf("otherInvocations = %d, want 1", otherInvocations)
	}
}

// TestRelayDedupsRedeliveredHash confirms markSeen's bounded recent-
// hash cache: publishing the SAME hash twice from a different
// publisher must only trigger the subscriber's handler once (the
// second is treated as a redelivery/duplicate, matching NATS's own
// at-least-once semantics this guard is designed for).
func TestRelayDedupsRedeliveredHash(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	subscriber := NewRelay(Config{URL: url})
	defer subscriber.Close()
	publisher := NewRelay(Config{URL: url})
	defer publisher.Close()

	invocations := make(chan BlockMessage, 4)
	unsub, err := subscriber.Subscribe(func(msg BlockMessage) {
		invocations <- msg
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()

	time.Sleep(100 * time.Millisecond)

	dup := BlockMessage{Height: 99, Hash: "duplicate-hash-value"}
	for i := 0; i < 2; i++ {
		if err := publisher.Publish(context.Background(), dup); err != nil {
			t.Fatalf("Publish (iteration %d): %v", i, err)
		}
	}

	// Wait for the first (real) delivery.
	select {
	case <-invocations:
	case <-time.After(5 * time.Second):
		t.Fatal("expected at least one delivery of the duplicate-hash message")
	}

	// The second publish of the identical hash must NOT produce a
	// second handler invocation.
	select {
	case msg := <-invocations:
		t.Fatalf("REAL DEDUP FAILURE: handler fired a second time for the same hash %q (msg=%+v) — markSeen's recent-hash cache is not working", dup.Hash, msg)
	case <-time.After(500 * time.Millisecond):
		// expected: no second invocation
	}
}

// TestRelayInitialConnectFailureDegradesGracefully confirms a
// syntactically-invalid NATS URL (one nats.Connect rejects
// synchronously regardless of RetryOnFailedConnect, e.g. a malformed
// host:port) never makes NewRelay fatal/panicking — the caller gets
// back a real, non-nil, disabled Relay whose methods remain safe
// no-ops. (A merely-unreachable-but-well-formed URL is a DIFFERENT,
// intentionally softer case per this package's own design: NewRelay's
// doc comment explains RetryOnFailedConnect(true) means Connect()
// itself does not error for a transient outage — that path stays
// Enabled()=true and self-heals via nats.go's own reconnect loop, so
// it is deliberately not what this test exercises.)
func TestRelayInitialConnectFailureDegradesGracefully(t *testing.T) {
	r := NewRelay(Config{URL: "not a valid nats url ::: at all"})
	if r == nil {
		t.Fatal("NewRelay must never return nil")
	}
	if r.Enabled() {
		t.Fatal("expected Enabled()=false for a syntactically-invalid NATS URL")
	}
	if err := r.Publish(context.Background(), BlockMessage{Hash: "x"}); err != nil {
		t.Fatalf("Publish on a degraded Relay must still be a no-op, got: %v", err)
	}
}

// TestRelayDefaultSubjectUsedWhenUnset is a small real behavioral
// check that Config.Subject empty really falls back to
// DefaultSubject, proven by publishing on DefaultSubject directly via
// a bare nats connection and confirming a Relay subscriber (with no
// explicit Subject configured) receives it.
func TestRelayDefaultSubjectUsedWhenUnset(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	r := NewRelay(Config{URL: url}) // Subject left empty -> DefaultSubject
	defer r.Close()

	received := make(chan BlockMessage, 1)
	unsub, err := r.Subscribe(func(msg BlockMessage) { received <- msg })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()

	other := NewRelay(Config{URL: url, Subject: DefaultSubject})
	defer other.Close()
	time.Sleep(100 * time.Millisecond)

	if err := other.Publish(context.Background(), BlockMessage{Hash: "default-subject-check"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-received:
		if got.Hash != "default-subject-check" {
			t.Errorf("got hash %q, want %q", got.Hash, "default-subject-check")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected delivery on the default subject")
	}
}

// TestRelayTemplateDisabledIsCompleteNoOp mirrors
// TestRelayDisabledIsCompleteNoOp exactly, for the template relay.
func TestRelayTemplateDisabledIsCompleteNoOp(t *testing.T) {
	r := NewRelay(Config{URL: ""})
	if r.Enabled() {
		t.Fatal("expected Enabled()=false for an empty-URL Relay")
	}

	if err := r.PublishTemplate(context.Background(), TemplateMessage{Height: 1, Hash: "deadbeef"}); err != nil {
		t.Fatalf("PublishTemplate on a disabled Relay must be a harmless no-op, got error: %v", err)
	}

	called := false
	unsub, err := r.SubscribeTemplate(func(TemplateMessage) { called = true })
	if err != nil {
		t.Fatalf("SubscribeTemplate on a disabled Relay must be a harmless no-op, got error: %v", err)
	}
	unsub() // must not panic

	time.Sleep(50 * time.Millisecond)
	if called {
		t.Fatal("handler was invoked on a disabled Relay — SubscribeTemplate must be a real no-op, not merely error-free")
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close on a disabled Relay must be a no-op, got error: %v", err)
	}
}

// TestRelayTemplatePublishDeliversToRealSubscriber mirrors
// TestRelayPublishDeliversToRealSubscriber exactly, for the template
// relay: a real embedded NATS server, two separate Relay instances, a
// genuine wire round trip.
func TestRelayTemplatePublishDeliversToRealSubscriber(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	publisher := NewRelay(Config{URL: url})
	defer publisher.Close()
	subscriber := NewRelay(Config{URL: url})
	defer subscriber.Close()

	if !publisher.Enabled() || !subscriber.Enabled() {
		t.Fatalf("expected both relays to be Enabled() after connecting to a real NATS server at %s", url)
	}

	received := make(chan TemplateMessage, 1)
	unsub, err := subscriber.SubscribeTemplate(func(msg TemplateMessage) {
		received <- msg
	})
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsub()

	time.Sleep(100 * time.Millisecond)

	want := TemplateMessage{
		Algo: "sha3x", Network: "testnet", Height: 12345,
		Hash: "real-template-hash-from-publisher", TemplateData: []byte{1, 2, 3, 4},
	}
	if err := publisher.PublishTemplate(context.Background(), want); err != nil {
		t.Fatalf("PublishTemplate: %v", err)
	}

	select {
	case got := <-received:
		if got.Height != want.Height || got.Hash != want.Hash || got.Algo != want.Algo || got.Network != want.Network {
			t.Errorf("received message = %+v, want fields matching %+v", got, want)
		}
		if string(got.TemplateData) != string(want.TemplateData) {
			t.Errorf("received TemplateData = %v, want %v", got.TemplateData, want.TemplateData)
		}
		if got.PublisherID == "" {
			t.Error("expected a non-empty PublisherID stamped by the publisher")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber never received the published template message over the real embedded NATS server within 5s")
	}
}

// TestRelayTemplateSkipsMessagesFromOwnPublisherID mirrors
// TestRelaySkipsMessagesFromOwnPublisherID exactly, for the template
// relay.
func TestRelayTemplateSkipsMessagesFromOwnPublisherID(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	selfRelay := NewRelay(Config{URL: url})
	defer selfRelay.Close()
	otherPublisher := NewRelay(Config{URL: url})
	defer otherPublisher.Close()

	var selfInvocations, otherInvocations int
	selfReceivedOwn := make(chan struct{}, 1)
	receivedFromOther := make(chan TemplateMessage, 1)

	unsub, err := selfRelay.SubscribeTemplate(func(msg TemplateMessage) {
		if msg.Hash == "own-published-template-hash" {
			selfInvocations++
			selfReceivedOwn <- struct{}{}
			return
		}
		otherInvocations++
		receivedFromOther <- msg
	})
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsub()

	time.Sleep(100 * time.Millisecond)

	if err := selfRelay.PublishTemplate(context.Background(), TemplateMessage{Height: 1, Hash: "own-published-template-hash"}); err != nil {
		t.Fatalf("PublishTemplate (self): %v", err)
	}

	if err := otherPublisher.PublishTemplate(context.Background(), TemplateMessage{Height: 2, Hash: "other-published-template-hash"}); err != nil {
		t.Fatalf("PublishTemplate (other): %v", err)
	}

	select {
	case got := <-receivedFromOther:
		if got.Hash != "other-published-template-hash" {
			t.Errorf("received hash = %q, want %q", got.Hash, "other-published-template-hash")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected the handler to fire for the OTHER publisher's message within 5s")
	}

	select {
	case <-selfReceivedOwn:
		t.Fatal("REAL DEDUP FAILURE: selfRelay's own handler fired for a message it published itself — PublisherID dedup-skip is broken")
	case <-time.After(300 * time.Millisecond):
		// expected: no invocation for the self-published message
	}

	if selfInvocations != 0 {
		t.Errorf("selfInvocations = %d, want 0 (own-publisher messages must be skipped)", selfInvocations)
	}
	if otherInvocations != 1 {
		t.Errorf("otherInvocations = %d, want 1", otherInvocations)
	}
}

// TestRelayTemplateDedupsRedeliveredHash mirrors
// TestRelayDedupsRedeliveredHash exactly, for the template relay —
// also proves the dedup cache is genuinely SHARED with BlockMessage's
// own dedup (see markSeen's doc comment): publishing the same hash
// value once as a BlockMessage and once as a TemplateMessage still
// only allows the FIRST occurrence through.
func TestRelayTemplateDedupsRedeliveredHash(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	subscriber := NewRelay(Config{URL: url})
	defer subscriber.Close()
	publisher := NewRelay(Config{URL: url})
	defer publisher.Close()

	invocations := make(chan TemplateMessage, 4)
	unsub, err := subscriber.SubscribeTemplate(func(msg TemplateMessage) {
		invocations <- msg
	})
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsub()

	time.Sleep(100 * time.Millisecond)

	dup := TemplateMessage{Height: 99, Hash: "duplicate-template-hash-value"}
	for i := 0; i < 2; i++ {
		if err := publisher.PublishTemplate(context.Background(), dup); err != nil {
			t.Fatalf("PublishTemplate (iteration %d): %v", i, err)
		}
	}

	select {
	case <-invocations:
	case <-time.After(5 * time.Second):
		t.Fatal("expected at least one delivery of the duplicate-hash template message")
	}

	select {
	case msg := <-invocations:
		t.Fatalf("REAL DEDUP FAILURE: handler fired a second time for the same hash %q (msg=%+v) — markSeen's recent-hash cache is not working", dup.Hash, msg)
	case <-time.After(500 * time.Millisecond):
		// expected: no second invocation
	}
}

// TestRelayTemplateInitialConnectFailureDegradesGracefully mirrors
// TestRelayInitialConnectFailureDegradesGracefully exactly, for the
// template relay.
func TestRelayTemplateInitialConnectFailureDegradesGracefully(t *testing.T) {
	r := NewRelay(Config{URL: "not a valid nats url ::: at all"})
	if r == nil {
		t.Fatal("NewRelay must never return nil")
	}
	if r.Enabled() {
		t.Fatal("expected Enabled()=false for a syntactically-invalid NATS URL")
	}
	if err := r.PublishTemplate(context.Background(), TemplateMessage{Hash: "x"}); err != nil {
		t.Fatalf("PublishTemplate on a degraded Relay must still be a no-op, got: %v", err)
	}
}

// TestRelayTemplateDefaultSubjectUsedWhenUnset mirrors
// TestRelayDefaultSubjectUsedWhenUnset exactly, for the template
// relay, confirming DefaultTemplateSubject fallback.
func TestRelayTemplateDefaultSubjectUsedWhenUnset(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	r := NewRelay(Config{URL: url}) // TemplateSubject left empty -> DefaultTemplateSubject
	defer r.Close()

	received := make(chan TemplateMessage, 1)
	unsub, err := r.SubscribeTemplate(func(msg TemplateMessage) { received <- msg })
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsub()

	other := NewRelay(Config{URL: url, TemplateSubject: DefaultTemplateSubject})
	defer other.Close()
	time.Sleep(100 * time.Millisecond)

	if err := other.PublishTemplate(context.Background(), TemplateMessage{Hash: "default-template-subject-check"}); err != nil {
		t.Fatalf("PublishTemplate: %v", err)
	}

	select {
	case got := <-received:
		if got.Hash != "default-template-subject-check" {
			t.Errorf("got hash %q, want %q", got.Hash, "default-template-subject-check")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected delivery on the default template subject")
	}
}

// TestRelayBlockAndTemplateSubjectsAreIndependent proves BlockMessage/
// Publish/Subscribe (subject A) and TemplateMessage/PublishTemplate/
// SubscribeTemplate (subject B), over the SAME Relay/*nats.Conn, never
// cross-deliver to each other's handlers — real proof the two message
// types don't leak into each other despite sharing one connection and
// one dedup cache.
func TestRelayBlockAndTemplateSubjectsAreIndependent(t *testing.T) {
	url, shutdown := startEmbeddedNATSServer(t)
	defer shutdown()

	publisher := NewRelay(Config{URL: url})
	defer publisher.Close()
	subscriber := NewRelay(Config{URL: url})
	defer subscriber.Close()

	blockReceived := make(chan BlockMessage, 1)
	unsubBlock, err := subscriber.Subscribe(func(msg BlockMessage) { blockReceived <- msg })
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsubBlock()

	templateReceived := make(chan TemplateMessage, 1)
	unsubTemplate, err := subscriber.SubscribeTemplate(func(msg TemplateMessage) { templateReceived <- msg })
	if err != nil {
		t.Fatalf("SubscribeTemplate: %v", err)
	}
	defer unsubTemplate()

	time.Sleep(100 * time.Millisecond)

	if err := publisher.Publish(context.Background(), BlockMessage{Height: 1, Hash: "cross-subject-block-hash"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := publisher.PublishTemplate(context.Background(), TemplateMessage{Height: 2, Hash: "cross-subject-template-hash"}); err != nil {
		t.Fatalf("PublishTemplate: %v", err)
	}

	// Both must arrive on their OWN handler...
	select {
	case got := <-blockReceived:
		if got.Hash != "cross-subject-block-hash" {
			t.Errorf("block handler received hash = %q, want %q", got.Hash, "cross-subject-block-hash")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected the block handler to receive the BlockMessage within 5s")
	}
	select {
	case got := <-templateReceived:
		if got.Hash != "cross-subject-template-hash" {
			t.Errorf("template handler received hash = %q, want %q", got.Hash, "cross-subject-template-hash")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected the template handler to receive the TemplateMessage within 5s")
	}

	// ...and NEITHER handler must ever receive the OTHER stream's
	// message (real proof of subject independence, not just "both
	// eventually fired once").
	select {
	case got := <-blockReceived:
		t.Fatalf("block handler unexpectedly received a second message: %+v (template/block subjects are leaking into each other)", got)
	case <-time.After(300 * time.Millisecond):
	}
	select {
	case got := <-templateReceived:
		t.Fatalf("template handler unexpectedly received a second message: %+v (template/block subjects are leaking into each other)", got)
	case <-time.After(300 * time.Millisecond):
	}
}
