// Package relay implements a generic, coin-agnostic best-effort NATS
// pub/sub relay for found-block broadcast/resubmission, ported (in
// concept, not mechanics) from SXMR's real production
// lib/block_repeater.js: a fanout-style publish of a found block to a
// shared subject that any subscribing consumer (potentially other
// pool-leaf instances submitting to their OWN independently
// configured, possibly geographically-distributed nodes) picks up and
// submits to its own local/direct node connections.
//
// This is deliberately generalized beyond Tari: BlockMessage carries
// only algo-tagged raw bytes plus enough identifying metadata for
// logging/dedup, not any Tari-specific field. A future Monero-family
// leaf can publish/consume through this exact same package.
//
// This package also carries a second, independent message stream on
// the SAME shared *nats.Conn: TemplateMessage/PublishTemplate/
// SubscribeTemplate, a best-effort "a sibling leaf instance's tip-poll
// just observed a new chain tip" broadcast (internal/leaflib/solo's
// JobManager is the real consumer/producer) — a latency win, not a
// correctness requirement, exactly like the found-block relay above.
//
// Design/trust notes (see AGENTS.md's "http first, NATS later"
// architecture note and this session's explicit direction from Alex):
//   - This is a SECONDARY, best-effort mechanism. It is never allowed
//     to block or fail the primary HTTP+Protobuf backend submission or
//     the direct multi-node GRPC submission (see
//     internal/leaflib/direct). Publish/Subscribe failures are logged,
//     never propagated as fatal.
//   - Fully optional: an empty URL produces a Relay that is a complete,
//     harmless no-op for every method (see NewRelay/Publish/Subscribe).
//   - Built production-shaped (real reconnect/backoff via nats.go's own
//     options, real structured logging, a real wire message schema)
//     because it is meant to eventually carry primary share/block
//     traffic once the HTTP->NATS migration criteria are met (not this
//     package's concern to decide when).
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
)

// DefaultSubject is the shared fanout subject found-block messages are
// published/subscribed on when Config.Subject is left empty. A single
// shared subject (rather than per-coin/per-algo subjects) is the
// simplest real fanout topology for "any subscribing consumer, of any
// compatible coin/algo, picks up any found block" — consumers that only
// care about one algo/network filter on BlockMessage.Algo/Network
// themselves after receiving a message (see Relay.Subscribe).
const DefaultSubject = "pool.blocks.found"

// DefaultTemplateSubject is the shared fanout subject template
// (new-tip) messages are published/subscribed on when
// Config.TemplateSubject is left empty — mirrors DefaultSubject's
// exact rationale/convention for BlockMessage, just on a SEPARATE
// subject so the two message streams never cross-deliver to each
// other's handlers (see Relay.Subscribe vs Relay.SubscribeTemplate).
const DefaultTemplateSubject = "pool.templates.new"

// dedupCacheSize bounds the recent-message dedup cache (see
// Relay.Subscribe) to a small, fixed number of entries — this is a
// best-effort "don't resubmit a block we just published ourselves, or
// reprocess an at-least-once redelivery" guard, not a permanent ledger.
// Shared, on purpose, by BOTH BlockMessage and TemplateMessage dedup
// (see markSeen's doc comment) — a hash string is a hash string
// regardless of which message type it came from.
const dedupCacheSize = 256

// BlockMessage is the real, coin-agnostic wire schema published on a
// genuine found-block event. Fields are deliberately generic: BlockData
// is whatever raw bytes a receiving leaf's own resubmission logic knows
// how to turn back into a submittable block (for Tari today: a
// proto.Marshal'd tari_generated.Block; for a future Monero-family
// leaf: whatever raw block blob monerod's submitblock RPC needs) — this
// package does not itself know how to interpret BlockData, only how to
// carry it.
type BlockMessage struct {
	// Algo/Network identify which coin/algo/network this block belongs
	// to, using this repo's own poolpb-style string tags (e.g. "sha3x",
	// "c29", "rxt") rather than importing poolpb directly, so this
	// package has zero dependency on any Tari/Monero-specific type.
	Algo    string `json:"algo"`
	Network string `json:"network"`

	// Height is the block height, for logging/dedup context.
	Height uint64 `json:"height"`

	// Hash is a hex-encoded identifying hash for this block (e.g. the
	// real block hash), used for dedup (see Relay.Subscribe) and
	// logging. Not re-validated by this package — the PoW was already
	// validated by the publishing leaf before this message was ever
	// created (see AGENTS.md's trust-boundary rule: leaves own all
	// validation).
	Hash string `json:"hash"`

	// BlockData is the raw bytes a receiving leaf needs to attempt its
	// own local resubmission (see type doc comment).
	BlockData []byte `json:"block_data"`

	// PublisherID identifies which Relay instance published this
	// message (see Relay.id) — used by Subscribe to skip messages this
	// SAME instance just published itself (see NewRelay's doc comment
	// on id generation).
	PublisherID string `json:"publisher_id"`

	// FoundAt is when the publishing leaf found this block, for
	// logging/propagation-lag observability.
	FoundAt time.Time `json:"found_at"`
}

// TemplateMessage is the coin-agnostic wire schema published whenever
// an instance's own chain-tip poll observes a genuine new tip (see
// internal/leaflib/solo's JobManager.tipPollLoop) — a best-effort
// latency win, NOT a correctness requirement: a sibling leaf
// instance's own JobManager can invalidate its per-xn job cache the
// moment it hears about this, instead of waiting out its own next
// poll tick. Mirrors BlockMessage's exact shape/doc-comment style
// (same generalization rationale: this package does not know or care
// what TemplateData holds, only how to carry it).
type TemplateMessage struct {
	// Algo/Network identify which coin/algo/network this observed tip
	// belongs to, using this repo's own poolpb-style string tags (see
	// BlockMessage.Algo's doc comment for the exact same convention).
	Algo    string `json:"algo"`
	Network string `json:"network"`

	// Height is the newly observed tip height.
	Height uint64 `json:"height"`

	// TemplateData is whatever tip/template-identifying bytes the
	// receiving leaf's own JobManager needs (e.g. a tip hash or
	// serialized header) — this package does not itself know or care
	// what's inside, exactly like BlockMessage.BlockData. May be
	// empty; a bare Height is already enough for the real, current
	// consumer (JobManager.InvalidateAll on receipt).
	TemplateData []byte `json:"template_data"`

	// Hash is a hex-encoded identifying value for this observed tip,
	// used for dedup (see Relay.SubscribeTemplate, which reuses the
	// EXACT SAME markSeen/dedup cache as BlockMessage) and logging.
	Hash string `json:"hash"`

	// PublisherID identifies which Relay instance published this
	// message — stamped by PublishTemplate exactly like
	// BlockMessage.PublisherID, used by SubscribeTemplate to skip
	// messages this SAME instance just published itself.
	PublisherID string `json:"publisher_id"`

	// ObservedAt is when the publishing instance observed this new
	// tip (BlockMessage's analogous field is called FoundAt; this is
	// named ObservedAt since "found" doesn't apply to a bare tip-poll
	// observation).
	ObservedAt time.Time `json:"observed_at"`
}

// Config configures a Relay.
type Config struct {
	// URL is the NATS server URL, e.g. "nats://127.0.0.1:4222". Empty
	// (the default, matching this repo's established
	// "empty string disables it" convention for other optional
	// features) disables the relay entirely: NewRelay returns a Relay
	// whose every method is a complete no-op, never attempting to dial
	// anything.
	URL string

	// Subject overrides DefaultSubject.
	Subject string

	// TemplateSubject overrides DefaultTemplateSubject. Empty (the
	// default) falls back to DefaultTemplateSubject, mirroring
	// Subject/DefaultSubject's exact convention. Always a DIFFERENT
	// subject from Subject on the SAME underlying *nats.Conn — see
	// PublishTemplate/SubscribeTemplate.
	TemplateSubject string

	// Username/Password optionally configure NATS username/password
	// auth (mirrors nats.UserInfo). Both empty (the default) preserve
	// today's plaintext-no-auth connect behavior byte-for-byte — see
	// buildNatsOptions. Username alone with an empty Password is
	// still applied (some NATS server auth configurations use a
	// username with no password); the option is only appended at all
	// when Username != "".
	Username string
	Password string

	// TLSCAFile optionally supplies a CA bundle file an operator's
	// NATS server certificate should be verified against (mirrors
	// nats.RootCAs). Empty (the default) does not append any TLS
	// option at all — see buildNatsOptions.
	TLSCAFile string

	// TLSCertFile/TLSKeyFile optionally supply a client certificate/
	// key pair for mutual TLS against a NATS server that requires
	// one (mirrors nats.ClientCert). Both must be non-empty together
	// for the option to be appended — see buildNatsOptions.
	TLSCertFile string
	TLSKeyFile  string

	Logger *log.Logger
}

// buildNatsOptions constructs the []nats.Option slice NewRelay passes
// to nats.Connect, exported as its own small, pure, side-effect-free
// function (rather than left inline in NewRelay) SPECIFICALLY so
// relay_test.go can assert its real output against a Config without
// needing a live NATS server — nats.Option values are opaque
// functions, not inspectable directly, so tests apply each returned
// Option against a fresh nats.Options{} zero value and assert on the
// resulting fields instead.
//
// Auth/TLS options are appended CONDITIONALLY, matching this package's
// existing "empty/zero means disabled, byte-identical to today's
// behavior" convention used throughout (see Config's own field
// comments):
//   - nats.UserInfo(cfg.Username, cfg.Password) is appended only when
//     cfg.Username != "".
//   - nats.RootCAs(cfg.TLSCAFile) is appended only when
//     cfg.TLSCAFile != "".
//   - nats.ClientCert(cfg.TLSCertFile, cfg.TLSKeyFile) is appended
//     only when BOTH cfg.TLSCertFile and cfg.TLSKeyFile are non-empty.
//
// base carries every option NewRelay already applies unconditionally
// (Name/MaxReconnects/ReconnectWait/etc, and the disconnect/reconnect/
// closed handlers) so this function's output is the COMPLETE options
// slice NewRelay passes to nats.Connect, not just the new auth/TLS
// additions.
func buildNatsOptions(cfg Config, base []nats.Option) []nats.Option {
	opts := make([]nats.Option, len(base), len(base)+3)
	copy(opts, base)
	if cfg.Username != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}
	if cfg.TLSCAFile != "" {
		opts = append(opts, nats.RootCAs(cfg.TLSCAFile))
	}
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		opts = append(opts, nats.ClientCert(cfg.TLSCertFile, cfg.TLSKeyFile))
	}
	return opts
}

// Relay is a best-effort NATS pub/sub wrapper for found-block
// broadcast/resubmission. The zero value is not usable; construct via
// NewRelay. Safe for concurrent use.
type Relay struct {
	enabled         bool
	subject         string
	templateSubject string
	id              string
	logger          *log.Logger

	conn *nats.Conn

	dedupMu   sync.Mutex
	dedupSeen map[string]time.Time
	dedupList []string // oldest-first, mirrors dedupSeen's keys, bounds it to dedupCacheSize

	// stats is this Relay's own internal, atomic-counter observability
	// state (see Stats' doc comment) — the single source of truth for
	// every relay-level Prometheus metric a caller (e.g.
	// internal/leaflib/direct's Server.EnableMetrics) wires up, so
	// publish/receive counting is never duplicated between this
	// package and a caller's own instrumentation (see this package's
	// doc comment / this feature's explicit design constraint: prefer
	// exposing internal state over re-counting at the call site).
	// Never nil (see NewRelay) — every method below is safe to call on
	// a disabled Relay too, they simply never get incremented.
	stats *relayStats
}

// relayStats holds Relay's real, atomic (lock-free, concurrency-safe)
// publish/receive/connection-health counters. A single hash string is
// never enough to distinguish found-block from template traffic (see
// markSeen's shared dedup cache), so these are tracked as entirely
// separate counters per message type, mirroring BlockMessage vs
// TemplateMessage's own separate subjects/methods.
//
// All fields are zero-value-safe (a freshly zeroed relayStats reports
// every counter as 0 and Connected as false) — this is exactly the
// "zero-cost/zero-registration when relay disabled" contract this
// feature requires: NewRelay never increments any of these for a
// disabled Relay (every Publish/PublishTemplate/Subscribe/
// SubscribeTemplate call is already an early-return no-op for
// !r.Enabled(), see those methods below), so a disabled Relay's
// Stats() is always the zero RelayStats{} forever.
type relayStats struct {
	blockPublishSuccess atomic.Uint64
	blockPublishError   atomic.Uint64
	blockRecvDispatched atomic.Uint64
	blockRecvDuplicate  atomic.Uint64

	templatePublishSuccess atomic.Uint64
	templatePublishError   atomic.Uint64
	templateRecvDispatched atomic.Uint64
	templateRecvDuplicate  atomic.Uint64

	// connected tracks the CURRENT, live NATS connection state — set
	// true on a successful initial connect or reconnect, false on
	// disconnect/close. This is deliberately a separate signal from
	// Relay.Enabled() (which stays true across a transient
	// disconnect/reconnect cycle, per NewRelay's own
	// RetryOnFailedConnect(true) self-healing design): a dashboard
	// wants to see the real, momentary up/down transitions, not just
	// "was this feature configured at all".
	connected atomic.Bool

	// lastBlockPublishUnix/lastBlockReceiveUnix/
	// lastTemplatePublishUnix/lastTemplateReceiveUnix are Unix-second
	// timestamps (0 = "never") of this Relay's own most recent
	// successful publish/dispatched-receive of each message type —
	// the real staleness/lag signal a per-leaf dashboard needs (see
	// this feature's task description).
	lastBlockPublishUnix    atomic.Int64
	lastBlockReceiveUnix    atomic.Int64
	lastTemplatePublishUnix atomic.Int64
	lastTemplateReceiveUnix atomic.Int64
}

// RelayStats is a point-in-time, immutable snapshot of relayStats,
// returned by Relay.Stats() — see that method's doc comment. Time
// fields are the zero time.Time (IsZero() == true) when the
// corresponding event has never happened (rather than the Unix epoch,
// which would look like a real, very-stale timestamp on a dashboard).
type RelayStats struct {
	Connected bool

	BlockPublishSuccess    uint64
	BlockPublishError      uint64
	BlockReceiveDispatched uint64
	BlockReceiveDuplicate  uint64

	TemplatePublishSuccess    uint64
	TemplatePublishError      uint64
	TemplateReceiveDispatched uint64
	TemplateReceiveDuplicate  uint64

	LastBlockPublish    time.Time
	LastBlockReceive    time.Time
	LastTemplatePublish time.Time
	LastTemplateReceive time.Time
}

// unixOrZero converts an atomic.Int64 Unix-seconds field (0 = never)
// into a time.Time, returning the zero time.Time (not the Unix epoch)
// for "never" — see RelayStats' doc comment on why that distinction
// matters for a dashboard.
func unixOrZero(v *atomic.Int64) time.Time {
	u := v.Load()
	if u == 0 {
		return time.Time{}
	}
	return time.Unix(u, 0)
}

// Stats returns a point-in-time snapshot of this Relay's own
// internal publish/receive/connection-health counters — the single
// source of truth callers (e.g. internal/leaflib/direct's Prometheus
// wiring, see that package's metrics.go) should read rather than
// re-counting relay activity themselves at the call site (this
// feature's explicit design constraint). Safe to call on a nil or
// disabled Relay: both report the zero RelayStats{}.
func (r *Relay) Stats() RelayStats {
	if r == nil || r.stats == nil {
		return RelayStats{}
	}
	s := r.stats
	return RelayStats{
		Connected: s.connected.Load(),

		BlockPublishSuccess:    s.blockPublishSuccess.Load(),
		BlockPublishError:      s.blockPublishError.Load(),
		BlockReceiveDispatched: s.blockRecvDispatched.Load(),
		BlockReceiveDuplicate:  s.blockRecvDuplicate.Load(),

		TemplatePublishSuccess:    s.templatePublishSuccess.Load(),
		TemplatePublishError:      s.templatePublishError.Load(),
		TemplateReceiveDispatched: s.templateRecvDispatched.Load(),
		TemplateReceiveDuplicate:  s.templateRecvDuplicate.Load(),

		LastBlockPublish:    unixOrZero(&s.lastBlockPublishUnix),
		LastBlockReceive:    unixOrZero(&s.lastBlockReceiveUnix),
		LastTemplatePublish: unixOrZero(&s.lastTemplatePublishUnix),
		LastTemplateReceive: unixOrZero(&s.lastTemplateReceiveUnix),
	}
}

// NewRelay constructs a Relay from cfg. If cfg.URL is empty, the
// returned Relay is enabled=false: every method becomes a harmless
// no-op and NO connection attempt is ever made — this is the "fully
// optional/no-op when unconfigured" contract required of this feature.
// If cfg.URL is non-empty but the NATS server is unreachable, NewRelay
// still returns a real, non-nil Relay (nats.Connect below is called
// with real reconnect/backoff options so a transient outage at startup
// self-heals) — connection failures are logged, never fatal to the
// leaf process; see this package's doc comment on why NATS must never
// block the primary path.
func NewRelay(cfg Config) *Relay {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	subject := cfg.Subject
	if subject == "" {
		subject = DefaultSubject
	}
	templateSubject := cfg.TemplateSubject
	if templateSubject == "" {
		templateSubject = DefaultTemplateSubject
	}

	id := newRelayID()

	r := &Relay{
		enabled:         cfg.URL != "",
		subject:         subject,
		templateSubject: templateSubject,
		id:              id,
		logger:          logger,
		dedupSeen:       make(map[string]time.Time),
		stats:           &relayStats{},
	}

	if !r.enabled {
		logger.Printf("relay: disabled (no NATS URL configured) — this is a complete no-op, not an error")
		return r
	}

	// Real, production-shaped reconnect/backoff: nats.go's own
	// documented options for "never give up reconnecting" (-1) with a
	// bounded per-attempt wait, plus real structured logging on every
	// disconnect/reconnect/close transition — this relay is meant to
	// eventually carry primary traffic (see package doc comment), so it
	// is built with real operational visibility from day one, not a
	// throwaway connect-and-hope. Auth/TLS options (Config.Username/
	// Password/TLSCAFile/TLSCertFile/TLSKeyFile) are appended
	// conditionally by buildNatsOptions -- see that function's doc
	// comment for the exact, individually-optional precedence.
	conn, err := nats.Connect(cfg.URL, buildNatsOptions(cfg, []nats.Option{
		nats.Name("go-crypto-pool-leaf-direct"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.RetryOnFailedConnect(true),
		nats.Timeout(5 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			r.stats.connected.Store(false)
			if err != nil {
				logger.Printf("relay: NATS disconnected: %v", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			r.stats.connected.Store(true)
			logger.Printf("relay: NATS reconnected to %s", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			r.stats.connected.Store(false)
			logger.Printf("relay: NATS connection closed")
		}),
	})...)
	if err != nil {
		// Best-effort: log and keep going with a nil conn — Publish/
		// Subscribe below treat a nil conn as "temporarily
		// unavailable" and no-op rather than panicking or blocking the
		// primary path. RetryOnFailedConnect above still gives an
		// async reconnect loop a chance in most real failure modes;
		// this branch is the belt-and-suspenders case where even the
		// initial synchronous attempt errors out immediately.
		logger.Printf("relay: initial NATS connect to %q failed (relay will remain a no-op until reachable): %v", cfg.URL, err)
		r.enabled = false
		return r
	}

	r.conn = conn
	r.stats.connected.Store(true)
	logger.Printf("relay: connected to NATS at %s, subject %q, publisher id %s", cfg.URL, subject, id)
	return r
}

// newRelayID returns a short random hex identifier for this Relay
// instance, used to tag published messages (BlockMessage.PublisherID)
// so Subscribe can skip messages this same instance published (see
// Subscribe's doc comment).
func newRelayID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Exceptionally rare (broken system RNG); a fallback constant
		// merely means this instance's own dedup-skip is slightly less
		// precise (it could, in the worst case, coincide with another
		// instance that also fell back), never a crash.
		return "relay-fallback-id"
	}
	return hex.EncodeToString(buf)
}

// Enabled reports whether this Relay is actually configured/connected.
// Callers may use this purely for logging/diagnostics; Publish/
// Subscribe are already safe no-ops when this is false.
func (r *Relay) Enabled() bool {
	return r != nil && r.enabled && r.conn != nil
}

// Publish best-effort-broadcasts msg on the relay subject. It NEVER
// blocks the caller on network I/O beyond nats.go's own internal
// buffering (Publish is fire-and-forget at the NATS client level), and
// a non-nil error here must NEVER be treated by callers as a reason to
// fail a real share/block submission — see this package's doc comment.
// msg.PublisherID is stamped with this Relay's own id, overwriting
// whatever the caller set (callers are not expected to set it at all).
func (r *Relay) Publish(_ context.Context, msg BlockMessage) error {
	if !r.Enabled() {
		return nil
	}
	msg.PublisherID = r.id
	if msg.FoundAt.IsZero() {
		msg.FoundAt = time.Now()
	}
	data, err := json.Marshal(msg)
	if err != nil {
		r.stats.blockPublishError.Add(1)
		r.logger.Printf("relay: failed to marshal block message for publish (height %d, hash %s): %v", msg.Height, msg.Hash, err)
		return fmt.Errorf("relay: marshal: %w", err)
	}
	if err := r.conn.Publish(r.subject, data); err != nil {
		r.stats.blockPublishError.Add(1)
		r.logger.Printf("relay: publish failed (height %d, hash %s): %v", msg.Height, msg.Hash, err)
		return fmt.Errorf("relay: publish: %w", err)
	}
	r.stats.blockPublishSuccess.Add(1)
	r.stats.lastBlockPublishUnix.Store(time.Now().Unix())
	r.logger.Printf("relay: published found block height=%d hash=%s algo=%s network=%s", msg.Height, msg.Hash, msg.Algo, msg.Network)
	return nil
}

// Subscribe registers handler to be called for every BlockMessage
// received on the relay subject that (a) did NOT originate from this
// same Relay instance (msg.PublisherID != r.id — the real dedup
// guard against resubmitting a block this instance just found/
// published itself) and (b) has not already been seen recently (a
// bounded recent-hash cache, see markSeen — doesn't need to be
// perfect/permanent, just good enough to collapse NATS's
// at-least-once redelivery/duplicate-subscriber-group semantics into a
// single handler invocation per genuinely-new block).
//
// If the relay is disabled/unconfigured, Subscribe is a complete
// no-op: it registers nothing and returns a no-op unsubscribe function
// and a nil error, so callers can unconditionally call this at startup
// without a branch on Enabled().
func (r *Relay) Subscribe(handler func(BlockMessage)) (unsubscribe func(), err error) {
	if !r.Enabled() {
		return func() {}, nil
	}
	sub, err := r.conn.Subscribe(r.subject, func(m *nats.Msg) {
		var msg BlockMessage
		if err := json.Unmarshal(m.Data, &msg); err != nil {
			r.logger.Printf("relay: received unparseable block message, dropping: %v", err)
			return
		}
		if msg.PublisherID == r.id {
			// This is a message we ourselves published — the direct
			// multi-node GRPC submission (internal/leaflib/direct)
			// already handled it locally; resubmitting our own find
			// via the relay path would be pointless (and, worse,
			// indistinguishable-looking log noise from a genuinely
			// distinct relay-sourced block).
			return
		}
		if !r.markSeen(msg.Hash) {
			// Already processed this hash recently (duplicate
			// delivery) — skip re-triggering resubmission.
			r.stats.blockRecvDuplicate.Add(1)
			return
		}
		r.stats.blockRecvDispatched.Add(1)
		r.stats.lastBlockReceiveUnix.Store(time.Now().Unix())
		r.logger.Printf("relay: received found block from another instance (publisher=%s height=%d hash=%s algo=%s network=%s), triggering local resubmission", msg.PublisherID, msg.Height, msg.Hash, msg.Algo, msg.Network)
		handler(msg)
	})
	if err != nil {
		r.logger.Printf("relay: subscribe failed: %v", err)
		return func() {}, fmt.Errorf("relay: subscribe: %w", err)
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

// PublishTemplate best-effort-broadcasts msg on the relay's template
// subject (r.templateSubject — a SEPARATE NATS subject from
// r.subject, but the SAME underlying *nats.Conn; see Config.
// TemplateSubject). Same contract as Publish exactly: never blocks the
// caller beyond nats.go's own internal buffering, a non-nil error here
// must NEVER be treated as a reason to fail any primary path, and a
// no-op (nil error, no dial ever attempted) when !r.Enabled(). msg.
// PublisherID is stamped with this Relay's own id, and msg.ObservedAt
// defaults to time.Now() if left zero.
func (r *Relay) PublishTemplate(_ context.Context, msg TemplateMessage) error {
	if !r.Enabled() {
		return nil
	}
	msg.PublisherID = r.id
	if msg.ObservedAt.IsZero() {
		msg.ObservedAt = time.Now()
	}
	data, err := json.Marshal(msg)
	if err != nil {
		r.stats.templatePublishError.Add(1)
		r.logger.Printf("relay: failed to marshal template message for publish (height %d, hash %s): %v", msg.Height, msg.Hash, err)
		return fmt.Errorf("relay: marshal template: %w", err)
	}
	if err := r.conn.Publish(r.templateSubject, data); err != nil {
		r.stats.templatePublishError.Add(1)
		r.logger.Printf("relay: template publish failed (height %d, hash %s): %v", msg.Height, msg.Hash, err)
		return fmt.Errorf("relay: publish template: %w", err)
	}
	r.stats.templatePublishSuccess.Add(1)
	r.stats.lastTemplatePublishUnix.Store(time.Now().Unix())
	r.logger.Printf("relay: published new-tip template height=%d hash=%s algo=%s network=%s", msg.Height, msg.Hash, msg.Algo, msg.Network)
	return nil
}

// SubscribeTemplate registers handler to be called for every
// TemplateMessage received on the relay's template subject that (a)
// did NOT originate from this same Relay instance (msg.PublisherID !=
// r.id) and (b) has not already been seen recently — reusing the
// EXACT SAME markSeen/dedupSeen/dedupList recent-hash cache
// Subscribe's BlockMessage dedup uses (see markSeen's doc comment:
// mixing block-hash and template-hash strings into one bounded cache
// is fine and intended). Same contract as Subscribe exactly: a
// complete no-op (registers nothing, returns a no-op unsubscribe and a
// nil error) when the relay is disabled/unconfigured.
func (r *Relay) SubscribeTemplate(handler func(TemplateMessage)) (unsubscribe func(), err error) {
	if !r.Enabled() {
		return func() {}, nil
	}
	sub, err := r.conn.Subscribe(r.templateSubject, func(m *nats.Msg) {
		var msg TemplateMessage
		if err := json.Unmarshal(m.Data, &msg); err != nil {
			r.logger.Printf("relay: received unparseable template message, dropping: %v", err)
			return
		}
		if msg.PublisherID == r.id {
			// This is a message we ourselves published — our own
			// tip-poll already handled it locally. See
			// Subscribe's identical self-skip for the full rationale.
			return
		}
		if !r.markSeen(msg.Hash) {
			// Already processed this hash recently (duplicate
			// delivery) — skip re-triggering invalidation.
			r.stats.templateRecvDuplicate.Add(1)
			return
		}
		r.stats.templateRecvDispatched.Add(1)
		r.stats.lastTemplateReceiveUnix.Store(time.Now().Unix())
		r.logger.Printf("relay: received new-tip template from another instance (publisher=%s height=%d hash=%s algo=%s network=%s), triggering local invalidation", msg.PublisherID, msg.Height, msg.Hash, msg.Algo, msg.Network)
		handler(msg)
	})
	if err != nil {
		r.logger.Printf("relay: template subscribe failed: %v", err)
		return func() {}, fmt.Errorf("relay: subscribe template: %w", err)
	}
	return func() { _ = sub.Unsubscribe() }, nil
}

// markSeen records hash as processed and reports whether this is the
// first time it's been seen (true) or a duplicate within the bounded
// recent-cache window (false). Empty hashes are never deduped (always
// reported as "first time") since an empty Hash carries no identifying
// information to dedup against.
func (r *Relay) markSeen(hash string) bool {
	if hash == "" {
		return true
	}
	r.dedupMu.Lock()
	defer r.dedupMu.Unlock()
	if _, seen := r.dedupSeen[hash]; seen {
		return false
	}
	r.dedupSeen[hash] = time.Now()
	r.dedupList = append(r.dedupList, hash)
	for len(r.dedupList) > dedupCacheSize {
		oldest := r.dedupList[0]
		r.dedupList = r.dedupList[1:]
		delete(r.dedupSeen, oldest)
	}
	return true
}

// Close drains and closes the underlying NATS connection, if any. Safe
// to call on a disabled/no-op Relay (no-op in that case).
func (r *Relay) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	r.conn.Close()
	return nil
}
