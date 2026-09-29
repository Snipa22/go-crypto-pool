// Package backlog implements a disk-backed, crash-durable retry queue
// wrapping a transport.ShareTransport, for the "backend is down for
// 10-15+ minutes" outage class described in DISPATCH_BRIEF.md
// (2026-09-27 nyc03 incident background -- see
// internal/leaflib/transport/http.go's own doc comment). It is a pure
// decorator: BacklogTransport wraps an inner transport.ShareTransport
// (either transport.HTTPProtobufTransport or
// legacytransport.LegacyTransport today) and satisfies the exact same
// interface, so wrapping it changes no call site -- see
// transport.ShareTransport's own package doc comment ("designed to be
// wrapped/extended without call-site changes").
//
// Scope, deliberately: this package does NOT replace or duplicate the
// SHORT-lived retry-with-backoff already built into
// legacytransport.LegacyTransport's postWithRetry (15s for shares, 5
// minutes for blocks -- see that package's
// DefaultShareSubmitRetryBudget/DefaultBlockSubmitRetryBudget doc
// comments). That existing mechanism rides out a brief network hiccup
// INSIDE one call/ctx and is untouched here. This package only takes
// over once an inner transport call has ALREADY exhausted whatever
// retry budget it has and returned a real error -- at that point,
// instead of the caller's pre-existing log-and-drop behavior, the
// failed share/block is durably queued to disk and retried by a
// background drain loop, indefinitely (bounded only by Config.MaxBytes
// disk capacity, never by a time budget), until it succeeds.
//
// Storage: github.com/nsqio/go-diskqueue (a small, MIT-licensed,
// purpose-built FIFO disk queue used in production by NSQ) backs the
// actual on-disk bytes -- rolling segment files, survives a restart by
// re-reading its own metadata file. It was used as-is per
// DISPATCH_BRIEF.md's explicit preference, rather than a custom WAL,
// because it fit cleanly with one real, disclosed limitation this
// package works around deliberately (see New's doc comment): its
// ReadChan() has no explicit ack/nack -- reading an entry off it
// permanently advances the queue's read position (persisted on the
// next metadata sync), so there is no library-level way to "peek and
// hold" an entry while still fully protecting it against a crash
// mid-delivery-attempt. This package's drain loop works around that by
// re-Put()ing a failed entry straight back onto the SAME queue (a
// fresh, immediately-durable append) immediately after a failed
// attempt, before backing off and moving on to the next entry -- this
// leaves a narrow crash window open (the duration of a single failed
// delivery attempt, NOT the whole outage) where an entry could
// theoretically be lost if this process crashes between go-diskqueue
// handing it to us and this package re-Put()ing it. That is an
// accepted, explicitly-disclosed trade-off given the underlying
// library's API shape -- see DISPATCH_BRIEF.md's report-back
// requirements, where this is called out as an open judgment call.
package backlog

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	diskqueue "github.com/nsqio/go-diskqueue"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

const (
	// DefaultMaxBytes is the default total on-disk byte cap for a
	// BacklogTransport's queue (see Config.MaxBytes's doc comment).
	// Chosen as a conservative starting point a deployer explicitly
	// raises for their real fleet via flag/env -- validated safe up
	// to at least 100 GiB per the operator's own sizing direction
	// ("allows for long outage windows cleanly").
	DefaultMaxBytes uint64 = 5 * 1024 * 1024 * 1024 // 5 GiB

	// DefaultDrainWorkers is the default background drain-worker pool
	// size (see Config.DrainWorkers's doc comment).
	DefaultDrainWorkers = 8

	// DefaultMinBackoff/DefaultMaxBackoff bound the drain loop's own
	// per-worker exponential backoff on consecutive delivery failures
	// (reset to DefaultMinBackoff after any success on that worker) --
	// see drainLoop's doc comment. There is deliberately no retry
	// BUDGET pairing these (unlike legacytransport's short-lived retry
	// loop): a queued entry is retried indefinitely as long as it fits
	// within Config.MaxBytes -- 10-15 minutes is the expected recovery
	// window for the outage class this exists for, not a hard cutoff.
	DefaultMinBackoff = 1 * time.Second
	DefaultMaxBackoff = 30 * time.Second

	// DefaultDrainAttemptTimeout bounds a single drain-loop delivery
	// attempt's ctx (via context.WithTimeout), sized comfortably above
	// legacytransport.DefaultBlockSubmitRetryBudget (5 minutes) so a
	// drain attempt against a LegacyTransport inner never clips that
	// package's OWN internal retry loop short -- see this package's
	// doc comment on why that inner retry is never touched/duplicated.
	DefaultDrainAttemptTimeout = 10 * time.Minute

	kindShare byte = 0
	kindBlock byte = 1

	envelopeVersion byte = 1
	// envelopeHeaderLen: version(1) + kind(1) + enqueuedAtUnixNano(8) +
	// attempt(4) = 14 bytes, followed by the raw marshaled
	// poolpb.Share/poolpb.Block payload.
	envelopeHeaderLen = 1 + 1 + 8 + 4

	diskQueueName         = "backlog"
	diskQueueMinMsgSize   = int32(envelopeHeaderLen)
	diskQueueMaxMsgSize   = 16 * 1024 * 1024 // 16 MiB -- comfortably above any real Share/Block.
	diskQueueSegmentBytes = 64 * 1024 * 1024 // Per-file rollover size; independent of Config.MaxBytes.
	diskQueueSyncEvery    = int64(1)         // fsync after every op -- see New's doc comment on durability vs. Put() latency.
	diskQueueSyncTimeout  = 1 * time.Second

	// bytesStateFileName is this package's OWN small sidecar file
	// (separate from go-diskqueue's own metadata file) persisting the
	// total-bytes-used accounting that backs Config.MaxBytes
	// enforcement -- go-diskqueue's Depth() reports entry COUNT, not
	// bytes, and has no per-kind breakdown, so this package tracks
	// both itself. See loadBytesState/persistStateLocked.
	bytesStateFileName = "backlog-bytes.state"
)

// errCorruptEntry marks a queue entry that can never be successfully
// delivered no matter how many times it is retried (a malformed
// envelope header, or a payload that fails to unmarshal as the
// poolpb.Share/poolpb.Block its envelope kind claims) -- drainLoop
// checks for this via errors.Is to drop such entries permanently
// instead of retrying them forever.
var errCorruptEntry = errors.New("backlog: corrupt queue entry")

// Config configures a BacklogTransport. See New's doc comment for the
// full behavioral contract.
type Config struct {
	// Dir is the on-disk directory the backlog's disk queue (and its
	// own small byte-accounting sidecar file) lives in. REQUIRED. This
	// MUST be real, persistent disk -- never a tmpfs/ephemeral
	// directory like /tmp, or this package's entire reason for
	// existing (surviving a leaf process crash/restart mid-outage) is
	// defeated. New creates Dir (via os.MkdirAll) if it does not
	// already exist.
	Dir string

	// MaxBytes bounds the backlog's TOTAL on-disk bytes across both
	// shares and blocks (not entry count -- entries vary in size).
	// Once reached, further enqueues are rejected (falling back to the
	// pre-backlog log-and-drop behavior, with a distinct
	// leaf_backlog_full_drops_total increment) rather than silently
	// evicting the oldest entry to make room. Zero/unset uses
	// DefaultMaxBytes (5 GiB) -- validated safe up to at least 100 GiB
	// by the operator; raise this via the embedding binary's own flag/
	// env for a real fleet's expected outage-window sizing.
	MaxBytes uint64

	// DrainWorkers sizes the background drain-worker pool that
	// continuously retries queued entries against the inner transport.
	// Zero/unset uses DefaultDrainWorkers (8).
	DrainWorkers int

	// MinBackoff/MaxBackoff bound each drain worker's own per-attempt
	// exponential backoff on consecutive delivery failures (see
	// drainLoop's doc comment). Zero/unset uses
	// DefaultMinBackoff/DefaultMaxBackoff (1s/30s).
	MinBackoff time.Duration
	MaxBackoff time.Duration

	// DrainAttemptTimeout bounds a single drain-loop delivery attempt's
	// ctx. Zero/unset uses DefaultDrainAttemptTimeout (10 minutes) --
	// see that constant's doc comment for why it must stay
	// comfortably above legacytransport's own longest internal retry
	// budget (5 minutes for blocks).
	DrainAttemptTimeout time.Duration

	// Logger receives every backlog enqueue/drain/drop log line. Nil
	// uses log.Default(), mirroring legacytransport.Config.Logger's
	// identical convention.
	Logger *log.Logger

	// Registry is an OPTIONAL caller-supplied *prometheus.Registry to
	// register this package's metrics into, so an embedding binary can
	// fold them into its own existing /metrics endpoint. Nil (the
	// default) constructs a fresh, private registry instead (never
	// prometheus.DefaultRegisterer -- a library package should not
	// silently mutate global state), reachable via
	// BacklogTransport.MetricsHandler.
	Registry *prometheus.Registry
}

// BacklogTransport is a transport.ShareTransport decorator: it calls
// through to an inner transport.ShareTransport first (where the inner
// transport's own short-lived retry, if any, already happens
// unchanged), and only on a genuine failure durably queues the
// share/block to disk for indefinite background retry instead of
// dropping it -- see package doc comment for the full contract.
type BacklogTransport struct {
	inner transport.ShareTransport

	dir            string
	maxBytes       uint64
	drainWorkers   int
	minBackoff     time.Duration
	maxBackoff     time.Duration
	attemptTimeout time.Duration
	logger         *log.Logger
	metrics        *Metrics

	dq diskqueue.Interface

	// bytesStatePath persists bytesUsed/depthByKind/bytesByKind below
	// so Config.MaxBytes enforcement survives a restart -- see
	// loadBytesState/persistStateLocked. This is intentionally SEPARATE
	// from go-diskqueue's own metadata file (which persists read/write
	// FILE POSITIONS, not our own byte-quota accounting).
	bytesStatePath string

	// stateMu guards bytesUsed/depthByKind/bytesByKind and their
	// persistence together, so a capacity check-and-reserve is atomic
	// across concurrent SubmitShare/SubmitBlock callers.
	stateMu     sync.Mutex
	bytesUsed   uint64
	depthByKind [2]int64
	bytesByKind [2]int64

	drainCtx    context.Context
	cancelDrain context.CancelFunc
	wg          sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

var _ transport.ShareTransport = (*BacklogTransport)(nil)

// New constructs a BacklogTransport wrapping inner, per cfg. Re-opening
// New against the same Config.Dir after a crash/restart resumes
// draining whatever was left un-acked from before -- go-diskqueue
// itself persists read/write file positions in its own metadata file
// in Dir, and this package's own bytesStateFileName sidecar restores
// this package's separate byte-quota accounting.
//
// KNOWN LIMITATION (disclosed, not a bug): go-diskqueue's ReadChan()
// has no ack/nack -- see package doc comment's "Storage" section for
// the full explanation and the narrow crash window this leaves open
// (bounded by one delivery attempt's duration, not the outage's).
func New(inner transport.ShareTransport, cfg Config) (*BacklogTransport, error) {
	if inner == nil {
		return nil, errors.New("backlog: inner transport.ShareTransport must not be nil")
	}
	if cfg.Dir == "" {
		return nil, errors.New("backlog: Config.Dir must not be empty")
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("backlog: create Config.Dir %s: %w", cfg.Dir, err)
	}

	maxBytes := cfg.MaxBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	drainWorkers := cfg.DrainWorkers
	if drainWorkers <= 0 {
		drainWorkers = DefaultDrainWorkers
	}
	minBackoff := cfg.MinBackoff
	if minBackoff <= 0 {
		minBackoff = DefaultMinBackoff
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = DefaultMaxBackoff
	}
	if maxBackoff < minBackoff {
		maxBackoff = minBackoff
	}
	attemptTimeout := cfg.DrainAttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = DefaultDrainAttemptTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	b := &BacklogTransport{
		inner:          inner,
		dir:            cfg.Dir,
		maxBytes:       maxBytes,
		drainWorkers:   drainWorkers,
		minBackoff:     minBackoff,
		maxBackoff:     maxBackoff,
		attemptTimeout: attemptTimeout,
		logger:         logger,
		metrics:        newMetrics(cfg.Registry),
		bytesStatePath: filepath.Join(cfg.Dir, bytesStateFileName),
	}

	b.loadBytesState()
	b.refreshGauges()

	b.dq = diskqueue.New(diskQueueName, cfg.Dir, diskQueueSegmentBytes, diskQueueMinMsgSize, diskQueueMaxMsgSize,
		diskQueueSyncEvery, diskQueueSyncTimeout, b.diskqueueLogf)

	b.drainCtx, b.cancelDrain = context.WithCancel(context.Background())
	b.wg.Add(drainWorkers)
	for i := 0; i < drainWorkers; i++ {
		go b.drainLoop(i)
	}

	return b, nil
}

// SubmitShare implements transport.ShareTransport. It calls through to
// the inner transport first; on failure, the share is durably queued
// for background retry (see enqueue) rather than being dropped.
func (b *BacklogTransport) SubmitShare(ctx context.Context, share *poolpb.Share) error {
	if err := b.inner.SubmitShare(ctx, share); err != nil {
		return b.enqueue(kindShare, share, err)
	}
	return nil
}

// SubmitBlock implements transport.ShareTransport. Mirrors
// SubmitShare's exact contract for blocks.
func (b *BacklogTransport) SubmitBlock(ctx context.Context, block *poolpb.Block) error {
	if err := b.inner.SubmitBlock(ctx, block); err != nil {
		return b.enqueue(kindBlock, block, err)
	}
	return nil
}

// enqueue durably queues msg (kind share|block) after cause caused the
// initial inner transport call to fail. On success, returns nil (the
// item is now durably accepted for later delivery -- a real, accepted
// outcome, not a failure) and logs/counts a DISTINCT line/metric from
// recordTransportError-style bookkeeping. If the queue is at capacity,
// or the enqueue itself genuinely fails (marshal error, disk I/O
// error), returns cause UNCHANGED so the caller falls back to its
// pre-existing log-and-drop behavior -- this never blocks the caller
// beyond a fast disk write (see package doc comment).
func (b *BacklogTransport) enqueue(kind byte, msg proto.Message, cause error) error {
	payload, merr := proto.Marshal(msg)
	if merr != nil {
		b.logger.Printf("backlog: cannot marshal %s for durable retry, falling back to drop-and-log: %v (original transport error: %v)", kindLabel(kind), merr, cause)
		return cause
	}

	entry := encodeEnvelope(kind, time.Now().UnixNano(), 0, payload)
	size := uint64(len(entry))

	if !b.reserve(kind, size) {
		b.metrics.FullDropsTotal.WithLabelValues(kindLabel(kind)).Inc()
		b.logger.Printf("backlog: queue at capacity (max-bytes=%d), dropping %s after transport error: %v", b.maxBytes, kindLabel(kind), cause)
		return cause
	}

	if err := b.dq.Put(entry); err != nil {
		b.release(kind, size)
		b.logger.Printf("backlog: failed to durably enqueue %s, falling back to drop-and-log: %v (original transport error: %v)", kindLabel(kind), err, cause)
		return cause
	}

	b.metrics.EnqueuedTotal.WithLabelValues(kindLabel(kind)).Inc()
	b.logger.Printf("backlog: queued %s for retry after transport error: %v", kindLabel(kind), cause)
	return nil
}

// drainLoop is one of Config.DrainWorkers background workers
// continuously reading the oldest un-acked entries off the disk queue
// and retrying them against inner. On success, the entry is acked
// (permanently removed -- see release). On failure, it is immediately
// re-queued (see package doc comment's "Storage" section on why this,
// not a held-in-memory delay, is how retries stay durable), then this
// worker backs off (starting at Config.MinBackoff, doubling up to
// Config.MaxBackoff, reset to MinBackoff after any success) before
// picking up the next entry -- there is no outer retry budget; a
// worker keeps doing this indefinitely as long as the process runs.
func (b *BacklogTransport) drainLoop(workerID int) {
	defer b.wg.Done()
	backoff := b.minBackoff
	for {
		select {
		case <-b.drainCtx.Done():
			return
		case data, ok := <-b.dq.ReadChan():
			if !ok {
				return
			}

			env, derr := decodeEnvelope(data)
			if derr != nil {
				b.logger.Printf("backlog: worker %d dropping permanently-corrupt queue entry (cannot decode envelope): %v", workerID, derr)
				b.metrics.CorruptDropsTotal.Inc()
				b.releaseAggregateOnly(uint64(len(data)))
				continue
			}

			attemptErr := b.attempt(env.kind, env.payload)
			if attemptErr == nil {
				b.release(env.kind, uint64(len(data)))
				b.metrics.DrainedTotal.WithLabelValues(kindLabel(env.kind)).Inc()
				backoff = b.minBackoff
				continue
			}

			if errors.Is(attemptErr, errCorruptEntry) {
				b.logger.Printf("backlog: worker %d dropping permanently-corrupt queued %s (payload will never unmarshal): %v", workerID, kindLabel(env.kind), attemptErr)
				b.metrics.CorruptDropsTotal.Inc()
				b.release(env.kind, uint64(len(data)))
				continue
			}

			b.metrics.RetryAttemptsTotal.WithLabelValues(kindLabel(env.kind)).Inc()
			requeued := encodeEnvelope(env.kind, env.enqueuedAtUnixNano, env.attempt+1, env.payload)
			if perr := b.dq.Put(requeued); perr != nil {
				b.logger.Printf("backlog: worker %d FAILED to re-queue %s after retry #%d -- entry lost (disk write error: %v; delivery error: %v)", workerID, kindLabel(env.kind), env.attempt, perr, attemptErr)
				b.metrics.RequeueFailuresTotal.WithLabelValues(kindLabel(env.kind)).Inc()
				b.release(env.kind, uint64(len(data)))
				continue
			}
			b.logger.Printf("backlog: worker %d retry #%d failed for queued %s, will keep retrying: %v", workerID, env.attempt+1, kindLabel(env.kind), attemptErr)

			select {
			case <-time.After(backoff):
			case <-b.drainCtx.Done():
				return
			}
			backoff *= 2
			if backoff > b.maxBackoff {
				backoff = b.maxBackoff
			}
		}
	}
}

// attempt unmarshals payload per kind and retries it against the
// inner transport, bounded by Config.DrainAttemptTimeout. A payload
// that fails to unmarshal returns an error wrapping errCorruptEntry
// (see drainLoop) -- it can never succeed no matter how many times
// retried.
func (b *BacklogTransport) attempt(kind byte, payload []byte) error {
	ctx, cancel := context.WithTimeout(b.drainCtx, b.attemptTimeout)
	defer cancel()

	switch kind {
	case kindShare:
		share := &poolpb.Share{}
		if err := proto.Unmarshal(payload, share); err != nil {
			return fmt.Errorf("%w: unmarshal share payload: %v", errCorruptEntry, err)
		}
		return b.inner.SubmitShare(ctx, share)
	case kindBlock:
		block := &poolpb.Block{}
		if err := proto.Unmarshal(payload, block); err != nil {
			return fmt.Errorf("%w: unmarshal block payload: %v", errCorruptEntry, err)
		}
		return b.inner.SubmitBlock(ctx, block)
	default:
		return fmt.Errorf("%w: unknown entry kind %d", errCorruptEntry, kind)
	}
}

// Close stops the background drain workers, closes the disk queue
// (persisting its metadata for a clean future resume), and closes the
// inner transport -- BacklogTransport is a decorator, so it owns
// tearing down what it wraps, matching transport.ShareTransport's own
// "safe to call exactly once" contract. In-flight drain attempts are
// interrupted via ctx cancellation (their own ctx is derived from the
// same context this cancels), so Close does not hang waiting for a
// currently-stuck inner call.
func (b *BacklogTransport) Close() error {
	b.closeOnce.Do(func() {
		b.cancelDrain()
		b.wg.Wait()

		var errs []error
		if err := b.dq.Close(); err != nil {
			errs = append(errs, fmt.Errorf("backlog: close disk queue: %w", err))
		}
		if err := b.inner.Close(); err != nil {
			errs = append(errs, fmt.Errorf("backlog: close inner transport: %w", err))
		}
		b.closeErr = errors.Join(errs...)
	})
	return b.closeErr
}

// MetricsHandler returns this BacklogTransport's Prometheus /metrics
// HTTP handler (see Config.Registry's doc comment).
func (b *BacklogTransport) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.metrics.Handler().ServeHTTP(w, r)
	}
}

// reserve atomically checks-and-admits size additional bytes for kind
// against Config.MaxBytes, returning false (admitting nothing) if that
// would exceed the cap.
func (b *BacklogTransport) reserve(kind byte, size uint64) bool {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	if b.bytesUsed+size > b.maxBytes {
		return false
	}
	b.bytesUsed += size
	b.depthByKind[kind]++
	b.bytesByKind[kind] += int64(size)
	b.persistStateLocked()
	b.updateGaugesLocked()
	return true
}

// release permanently frees size bytes previously reserve()d for kind
// -- called once an entry is either successfully drained/acked, or
// permanently dropped (corrupt/requeue failure).
func (b *BacklogTransport) release(kind byte, size uint64) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	b.subtractBytesUsedLocked(size)
	b.depthByKind[kind]--
	if b.depthByKind[kind] < 0 {
		b.depthByKind[kind] = 0
	}
	b.bytesByKind[kind] -= int64(size)
	if b.bytesByKind[kind] < 0 {
		b.bytesByKind[kind] = 0
	}
	b.persistStateLocked()
	b.updateGaugesLocked()
}

// releaseAggregateOnly frees size bytes from the total-bytes-used
// accounting WITHOUT attributing it to either kind's own counters --
// used only for an entry whose envelope header itself failed to
// decode, so its real kind is unknown/untrustworthy.
func (b *BacklogTransport) releaseAggregateOnly(size uint64) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	b.subtractBytesUsedLocked(size)
	b.persistStateLocked()
	b.updateGaugesLocked()
}

func (b *BacklogTransport) subtractBytesUsedLocked(size uint64) {
	if size > b.bytesUsed {
		b.bytesUsed = 0
		return
	}
	b.bytesUsed -= size
}

func (b *BacklogTransport) updateGaugesLocked() {
	b.metrics.DepthGauge.WithLabelValues(kindLabel(kindShare)).Set(float64(b.depthByKind[kindShare]))
	b.metrics.DepthGauge.WithLabelValues(kindLabel(kindBlock)).Set(float64(b.depthByKind[kindBlock]))
	b.metrics.BytesGauge.WithLabelValues(kindLabel(kindShare)).Set(float64(b.bytesByKind[kindShare]))
	b.metrics.BytesGauge.WithLabelValues(kindLabel(kindBlock)).Set(float64(b.bytesByKind[kindBlock]))
}

func (b *BacklogTransport) refreshGauges() {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	b.updateGaugesLocked()
}

// persistStateLocked atomically (write-temp-then-rename, mirroring
// go-diskqueue's own persistMetaData convention) writes this package's
// byte-quota accounting to bytesStatePath. Must be called with stateMu
// held. A failure here is logged but non-fatal -- it only risks a
// slightly stale MaxBytes accounting after an ungraceful crash exactly
// in this narrow window, self-correcting as the queue continues to
// drain (see package doc comment).
func (b *BacklogTransport) persistStateLocked() {
	tmp := fmt.Sprintf("%s.%d.tmp", b.bytesStatePath, os.Getpid())
	content := fmt.Sprintf("1\n%d\n%d %d\n%d %d\n",
		b.bytesUsed, b.depthByKind[kindShare], b.depthByKind[kindBlock], b.bytesByKind[kindShare], b.bytesByKind[kindBlock])
	if err := os.WriteFile(tmp, []byte(content), 0o640); err != nil {
		b.logger.Printf("backlog: failed to persist byte-usage state file %s: %v", b.bytesStatePath, err)
		return
	}
	if err := os.Rename(tmp, b.bytesStatePath); err != nil {
		b.logger.Printf("backlog: failed to atomically install byte-usage state file %s: %v", b.bytesStatePath, err)
		_ = os.Remove(tmp)
	}
}

// loadBytesState restores byte-quota accounting from a prior run's
// bytesStatePath, if present and well-formed. A missing or corrupt
// state file (fresh directory, or a crash exactly between writing the
// tmp file and renaming it) starts accounting from zero -- see
// persistStateLocked's doc comment on why that is an acceptable,
// self-correcting trade-off rather than a fatal condition.
func (b *BacklogTransport) loadBytesState() {
	data, err := os.ReadFile(b.bytesStatePath)
	if err != nil {
		return
	}
	var version int
	var bytesUsed uint64
	var depthShare, depthBlock, bytesShare, bytesBlock int64
	n, serr := fmt.Sscanf(string(data), "%d\n%d\n%d %d\n%d %d\n", &version, &bytesUsed, &depthShare, &depthBlock, &bytesShare, &bytesBlock)
	if serr != nil || n != 6 {
		b.logger.Printf("backlog: byte-usage state file %s is unreadable/corrupt, starting byte accounting from zero (self-corrects as the queue drains): %v", b.bytesStatePath, serr)
		return
	}
	b.bytesUsed = bytesUsed
	b.depthByKind[kindShare] = depthShare
	b.depthByKind[kindBlock] = depthBlock
	b.bytesByKind[kindShare] = bytesShare
	b.bytesByKind[kindBlock] = bytesBlock
}

// diskqueueLogf adapts go-diskqueue's own AppLogFunc logging callback
// onto b.logger -- go-diskqueue never calls os.Exit/panics on its own,
// even at its own FATAL level, so this is purely informational.
func (b *BacklogTransport) diskqueueLogf(lvl diskqueue.LogLevel, f string, args ...interface{}) {
	b.logger.Printf("backlog: diskqueue[%s] "+f, append([]interface{}{lvl.String()}, args...)...)
}

// envelope is the decoded form of one on-disk queue entry: a small
// fixed-size header (see envelopeHeaderLen) followed by the raw
// marshaled poolpb.Share/poolpb.Block payload.
type envelope struct {
	kind               byte
	enqueuedAtUnixNano int64
	attempt            int32
	payload            []byte
}

// encodeEnvelope builds one on-disk queue entry. The outer
// go-diskqueue framing already length-prefixes the returned slice, so
// no separate payload-length field is needed here -- payload is simply
// everything after the fixed header.
func encodeEnvelope(kind byte, enqueuedAtUnixNano int64, attempt int32, payload []byte) []byte {
	buf := make([]byte, envelopeHeaderLen+len(payload))
	buf[0] = envelopeVersion
	buf[1] = kind
	binary.BigEndian.PutUint64(buf[2:10], uint64(enqueuedAtUnixNano))
	binary.BigEndian.PutUint32(buf[10:14], uint32(attempt))
	copy(buf[envelopeHeaderLen:], payload)
	return buf
}

// decodeEnvelope parses one on-disk queue entry's header. It does NOT
// unmarshal the inner protobuf payload -- see attempt for that, which
// is where a genuinely corrupt payload (as opposed to a corrupt
// envelope header) is detected.
func decodeEnvelope(data []byte) (envelope, error) {
	if len(data) < envelopeHeaderLen {
		return envelope{}, fmt.Errorf("%w: entry too short (%d bytes)", errCorruptEntry, len(data))
	}
	if data[0] != envelopeVersion {
		return envelope{}, fmt.Errorf("%w: unknown envelope version %d", errCorruptEntry, data[0])
	}
	kind := data[1]
	if kind != kindShare && kind != kindBlock {
		return envelope{}, fmt.Errorf("%w: unknown entry kind %d", errCorruptEntry, kind)
	}
	enqueuedAt := int64(binary.BigEndian.Uint64(data[2:10]))
	attempt := int32(binary.BigEndian.Uint32(data[10:14]))
	payload := data[envelopeHeaderLen:]
	return envelope{kind: kind, enqueuedAtUnixNano: enqueuedAt, attempt: attempt, payload: payload}, nil
}

func kindLabel(kind byte) string {
	if kind == kindBlock {
		return "block"
	}
	return "share"
}
