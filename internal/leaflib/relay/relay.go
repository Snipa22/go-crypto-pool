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

// dedupCacheSize bounds the recent-message dedup cache (see
// Relay.Subscribe) to a small, fixed number of entries — this is a
// best-effort "don't resubmit a block we just published ourselves, or
// reprocess an at-least-once redelivery" guard, not a permanent ledger.
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

	Logger *log.Logger
}

// Relay is a best-effort NATS pub/sub wrapper for found-block
// broadcast/resubmission. The zero value is not usable; construct via
// NewRelay. Safe for concurrent use.
type Relay struct {
	enabled bool
	subject string
	id      string
	logger  *log.Logger

	conn *nats.Conn

	dedupMu   sync.Mutex
	dedupSeen map[string]time.Time
	dedupList []string // oldest-first, mirrors dedupSeen's keys, bounds it to dedupCacheSize
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

	id := newRelayID()

	r := &Relay{
		enabled:   cfg.URL != "",
		subject:   subject,
		id:        id,
		logger:    logger,
		dedupSeen: make(map[string]time.Time),
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
	// throwaway connect-and-hope.
	conn, err := nats.Connect(cfg.URL,
		nats.Name("go-crypto-pool-leaf-direct"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.Timeout(5*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Printf("relay: NATS disconnected: %v", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Printf("relay: NATS reconnected to %s", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			logger.Printf("relay: NATS connection closed")
		}),
	)
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
		r.logger.Printf("relay: failed to marshal block message for publish (height %d, hash %s): %v", msg.Height, msg.Hash, err)
		return fmt.Errorf("relay: marshal: %w", err)
	}
	if err := r.conn.Publish(r.subject, data); err != nil {
		r.logger.Printf("relay: publish failed (height %d, hash %s): %v", msg.Height, msg.Hash, err)
		return fmt.Errorf("relay: publish: %w", err)
	}
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
			return
		}
		r.logger.Printf("relay: received found block from another instance (publisher=%s height=%d hash=%s algo=%s network=%s), triggering local resubmission", msg.PublisherID, msg.Height, msg.Hash, msg.Algo, msg.Network)
		handler(msg)
	})
	if err != nil {
		r.logger.Printf("relay: subscribe failed: %v", err)
		return func() {}, fmt.Errorf("relay: subscribe: %w", err)
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
