// Copyright and license: see repository LICENSE (MIT).
package zmq

import (
	"context"
	"log"
	"sync/atomic"
	"testing"
	"time"

	zmq4 "github.com/go-zeromq/zmq4"
)

// startTestPublisher binds a REAL zmq4 PUB socket to an OS-assigned
// free local TCP port ("tcp://127.0.0.1:0") and returns the real,
// concrete dial-able address a SUB socket can Dial, plus the PUB
// socket itself (for publishing test messages) and a cleanup func.
// This is a real ZMTP PUB/SUB round trip, not a hand-rolled fake
// transport — mirrors internal/leaflib/relay/relay_test.go's own
// "real embedded server, not mocked" philosophy as closely as the
// ZMQ library allows.
func startTestPublisher(t *testing.T) (addr string, pub zmq4.Socket, shutdown func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	pub = zmq4.NewPub(ctx)
	if err := pub.Listen("tcp://127.0.0.1:0"); err != nil {
		cancel()
		t.Fatalf("binding test PUB socket: %v", err)
	}
	a := pub.Addr()
	if a == nil {
		cancel()
		t.Fatalf("test PUB socket has no bound address")
	}
	shutdown = func() {
		_ = pub.Close()
		cancel()
	}
	return "tcp://" + a.String(), pub, shutdown
}

// publishTopic sends a real, multipart [topic, payload] ZMQ message —
// the exact real wire shape zmq4's own PUB/SUB topic-prefix filtering
// (conn.go's subscribed()/HasPrefix) keys off (see this package's own
// client.go doc comment and the confirmed-from-source zmq4 filtering
// semantics: Frames[0] is matched as a PREFIX against each subscribed
// topic string).
func publishTopic(t *testing.T, pub zmq4.Socket, topic string, payload []byte) {
	t.Helper()
	msg := zmq4.NewMsgFrom([]byte(topic), payload)
	if err := pub.SendMulti(msg); err != nil {
		t.Fatalf("publishing topic %q: %v", topic, err)
	}
}

// TestClientReceivesRealMessageOnMatchingTopic proves the client's
// callback fires when a REAL message is published (over a real local
// ZMQ PUB/SUB socket pair, not mocked) on topic TopicNewBlock.
func TestClientReceivesRealMessageOnMatchingTopic(t *testing.T) {
	addr, pub, shutdown := startTestPublisher(t)
	defer shutdown()

	var calls atomic.Int64
	logger := log.New(testLogWriter{t}, "", 0)
	c := NewClient(addr, func() { calls.Add(1) }, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.Start(ctx)
		close(done)
	}()

	// Give the real SUB socket a moment to dial + subscribe before
	// publishing (real ZMTP handshake + subscription propagation is
	// asynchronous, exactly like relay_test.go's own real-NATS tests
	// need a brief real moment before publishing).
	time.Sleep(300 * time.Millisecond)

	publishTopic(t, pub, TopicNewBlock, []byte(`{"height":12345}`))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("expected the client's callback to fire for a real message published on TopicNewBlock within 5s")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("expected Start to return promptly after ctx cancellation")
	}
}

// TestClientDoesNotFireForUnrelatedTopic proves the callback does NOT
// fire for a real message published on a topic that does not match
// (as a prefix) TopicNewBlock — real proof of zmq4's own topic-filter
// semantics being exercised correctly by this client's subscription,
// not an assumption.
func TestClientDoesNotFireForUnrelatedTopic(t *testing.T) {
	addr, pub, shutdown := startTestPublisher(t)
	defer shutdown()

	var calls atomic.Int64
	logger := log.New(testLogWriter{t}, "", 0)
	c := NewClient(addr, func() { calls.Add(1) }, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.Start(ctx)
		close(done)
	}()

	time.Sleep(300 * time.Millisecond)

	publishTopic(t, pub, "some-completely-unrelated-topic", []byte(`{"unrelated":true}`))

	// Give a real, generous window for a (incorrectly) delivered
	// message to have arrived before concluding it genuinely never
	// does.
	time.Sleep(500 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("expected the callback to NEVER fire for an unrelated topic, got %d call(s)", calls.Load())
	}

	// Now prove the SAME client/socket still genuinely works for the
	// real matching topic (i.e. this isn't just "everything is
	// silently broken").
	publishTopic(t, pub, TopicNewBlock, []byte(`{"height":1}`))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("expected the callback to fire for TopicNewBlock after correctly NOT firing for the unrelated topic")
	}
}

// TestClientEmptyURLIsCompleteNoOp confirms Start on a Client
// constructed with an empty url never dials anything, never panics,
// and returns promptly — the explicit "fully optional" contract.
func TestClientEmptyURLIsCompleteNoOp(t *testing.T) {
	var calls atomic.Int64
	c := NewClient("", func() { calls.Add(1) }, log.New(testLogWriter{t}, "", 0))

	done := make(chan struct{})
	go func() {
		c.Start(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected Start to return immediately for an empty URL, it appears to be blocking")
	}
	if calls.Load() != 0 {
		t.Fatalf("expected the callback to never fire on a no-op Client, got %d call(s)", calls.Load())
	}
}

// TestClientUnreachableEndpointNeverPanics confirms Start against a
// real, syntactically-valid endpoint with NOTHING listening (a real
// connection-refused case, not simulated) never panics and correctly
// keeps retrying in the background until ctx is cancelled, at which
// point it returns — proving this real failure mode degrades
// gracefully rather than crashing the calling process.
func TestClientUnreachableEndpointNeverPanics(t *testing.T) {
	// A real TCP port with nothing bound to it -- port 1 is
	// privileged/unassigned and reliably refused/unreachable in this
	// test environment without needing to actually bind-then-close a
	// socket to "reserve" a genuinely free port.
	c := NewClient("tcp://127.0.0.1:1", func() {}, log.New(testLogWriter{t}, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Start panicked against an unreachable endpoint: %v", r)
			}
			close(done)
		}()
		c.Start(ctx)
	}()

	// Let it genuinely attempt (and fail) to connect a few times.
	time.Sleep(1 * time.Second)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("expected Start to return after ctx cancellation even while retrying an unreachable endpoint")
	}
}

// testLogWriter adapts *testing.T into an io.Writer so this file's
// *log.Logger instances route through t.Logf instead of stderr,
// keeping test output attributable to the specific test that produced
// it.
type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
