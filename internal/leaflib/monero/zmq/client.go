// Copyright and license: see repository LICENSE (MIT).

// Package zmq implements a small, deliberately dumb, monerod-specific
// ZMQ SUB client for a real fast-invalidation trigger on the
// standalone (leaf-solo/leaf-direct) -coin=monero path ONLY. It is
// NOT a generic message-relay package like internal/leaflib/relay —
// this is a coin-specific adapter, per this repo's own
// "coin-agnostic core, coin-specific adapter" layering (see that
// package's doc comment for the generic side of that split).
//
// monerod's real --zmq-pub option (see monerod's own documentation)
// binds a ZMQ PUB socket that fires a real JSON payload on topic
// "json-minimal-chain_main" every time a new block lands on the local
// node's active chain. This client dials that endpoint as a SUB
// socket, subscribes to exactly that topic, and invokes a
// caller-supplied callback on every message received — it
// deliberately never parses the JSON payload's own content: the only
// real consumer of this package (internal/leaflib/solo's JobManager,
// via cmd/leaf-solo and cmd/leaf-direct's -coin=monero wiring) only
// needs "something changed, refresh" (JobManager.InvalidateAll), not
// any field inside the payload. Keeping this package dumb/thin means
// it has zero coupling to whatever monerod's own JSON schema happens
// to contain.
//
// This is purely an ADDITIONAL, faster invalidation trigger — it
// never replaces solo.JobManager's own tip-poll loop (tipPollLoop),
// which keeps running as the real fallback/baseline exactly as
// before. A Client constructed with an empty URL (see NewClient) is a
// complete no-op: Start returns immediately without ever dialing
// anything, mirroring this repo's established "empty string disables
// it" convention (see internal/leaflib/relay.Config.URL's doc
// comment).
package zmq

import (
	"context"
	"log"
	"time"

	zmq4 "github.com/go-zeromq/zmq4"
)

// TopicNewBlock is monerod's real ZMQ topic (per --zmq-pub) fired on
// every new block landing on the local node's active chain, carrying
// a JSON payload this client deliberately never parses (see package
// doc comment).
const TopicNewBlock = "json-minimal-chain_main"

// dialerRetryInterval/dialerMaxRetries mirror relay.go's own
// real reconnect/backoff design (nats.MaxReconnects(-1)/
// nats.ReconnectWait) for the exact same reason: this client is meant
// to tolerate a real, transient monerod outage/restart without ever
// giving up or requiring a process restart of its own. zmq4's own SUB
// socket Dial retries internally using these exact options (confirmed
// via `go doc github.com/go-zeromq/zmq4` and direct inspection of
// this module's socket.go's real Dial retry loop, which respects
// context cancellation between attempts) — this package does not
// implement a second, redundant retry loop on top of it.
const (
	dialerRetryInterval = 2 * time.Second
	dialerMaxRetries    = -1 // infinite retries, exactly like relay.go's nats.MaxReconnects(-1)
	recvErrorBackoff    = 500 * time.Millisecond
)

// Client is a small, dumb monerod ZMQ SUB client (see package doc
// comment). The zero value is not usable; construct via NewClient.
type Client struct {
	url     string
	onBlock func()
	logger  *log.Logger
}

// NewClient constructs a Client that will dial url (e.g.
// "tcp://127.0.0.1:28082") as a real ZMQ SUB socket and invoke
// onBlock every time a message is received on TopicNewBlock. onBlock
// is called synchronously from Start's own internal receive loop —
// callers whose callback does meaningful work (e.g.
// solo.JobManager.InvalidateAll) should ensure it returns quickly, or
// dispatch their own work asynchronously, so a slow callback cannot
// delay processing the NEXT real ZMQ message.
//
// An empty url produces a Client whose Start is a complete no-op:
// never dials anything, matching every other optional feature's
// "empty config = disabled" contract in this repo (see
// internal/leaflib/relay.Config.URL's doc comment). logger defaults
// to log.Default() if nil.
func NewClient(url string, onBlock func(), logger *log.Logger) *Client {
	if logger == nil {
		logger = log.Default()
	}
	return &Client{url: url, onBlock: onBlock, logger: logger}
}

// Start dials c.url as a real ZMQ SUB socket, subscribes to
// TopicNewBlock, and invokes c.onBlock for every message received on
// that topic, running until ctx is cancelled. Intended to be run in
// its own goroutine by the caller (see cmd/leaf-solo and
// cmd/leaf-direct's -coin=monero wiring) — this method itself blocks
// for as long as ctx remains live.
//
// Complete no-op (returns immediately, never dials anything) when
// c.url is empty, or when c is nil. Never panics or blocks the
// CALLING process if the configured endpoint is unreachable: zmq4's
// own SUB socket Dial already retries internally (dialerRetryInterval/
// dialerMaxRetries above), respecting ctx cancellation between
// attempts, so an unreachable-but-well-formed endpoint simply means
// this method keeps retrying (inside whatever goroutine the caller
// already runs it in) until either it connects or ctx is cancelled —
// it never returns control to a caller expecting a fast failure, by
// design, mirroring relay.NewRelay's own "self-heals via real
// reconnect/backoff, never fatal" philosophy. Every real connect/
// disconnect/error transition is logged, mirroring relay.go's own
// structured-logging style.
func (c *Client) Start(ctx context.Context) {
	if c == nil || c.url == "" {
		return
	}

	sock := zmq4.NewSub(ctx,
		zmq4.WithAutomaticReconnect(true),
		zmq4.WithDialerRetry(dialerRetryInterval),
		zmq4.WithDialerMaxRetries(dialerMaxRetries),
		zmq4.WithLogger(c.logger),
	)
	defer func() { _ = sock.Close() }()

	c.logger.Printf("monero/zmq: dialing %s (real retry/reconnect enabled, never fatal on failure)...", c.url)
	if err := sock.Dial(c.url); err != nil {
		// Reached only if ctx was cancelled mid-retry (the real
		// infinite-retry loop above only ever returns an error once
		// sck.ctx.Err() != nil — see this method's own doc comment)
		// or some other non-retryable dial error. Either way: log and
		// return, never panic, never propagate as fatal.
		c.logger.Printf("monero/zmq: dial to %q ended without connecting (non-fatal): %v", c.url, err)
		return
	}
	c.logger.Printf("monero/zmq: connected to %s", c.url)

	if err := sock.SetOption(zmq4.OptionSubscribe, TopicNewBlock); err != nil {
		c.logger.Printf("monero/zmq: failed to subscribe to topic %q (non-fatal, no new-block events will be received): %v", TopicNewBlock, err)
		return
	}
	c.logger.Printf("monero/zmq: subscribed to topic %q", TopicNewBlock)

	for {
		if ctx.Err() != nil {
			return
		}
		_, err := sock.Recv()
		if ctx.Err() != nil {
			// Recv can return a zero-value Msg/nil error purely
			// because ctx was cancelled while it was blocked waiting
			// (see zmq4's own qreader.read: a ctx.Done() case falls
			// through without setting an error) — always check
			// ctx.Err() FIRST, before trusting err, so a cancellation
			// is never misread as a genuine (empty) received message.
			return
		}
		if err != nil {
			c.logger.Printf("monero/zmq: recv error (non-fatal, zmq4's own reconnect loop will retry): %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(recvErrorBackoff):
			}
			continue
		}
		if c.onBlock != nil {
			c.onBlock()
		}
	}
}
