// Copyright and license: see repository LICENSE (MIT).
//
// Package legacytransport implements transport.ShareTransport against a
// legacy nodejs-pool-sxmr backend's real `/leafApi` HTTP endpoint,
// modeled on the REAL production source of a sibling clone of
// `nodejs-pool` fetched for this task:
//
//   - `nodejs-pool/lib/remoteShare.js`: the real `app.post('/leafApi', ...)`
//     handler. It decodes the raw POST body (a `concat-stream` middleware
//     feeds `req.body` as a raw Buffer -- there is NO JSON body-parser on
//     this route) as a `WSData` protobuf message, checks
//     `msgData.key !== global.config.api.authKey` (403 if mismatched --
//     note this is a plain string field compare, NOT an HTTP header), and
//     dispatches on `msgData.msgType`:
//   - SHARE: decodes `msgData.msg` as a `Share` and forwards it via
//     `process.send(...)`, inside a try/catch that silently swallows
//     a decode failure -- either way it unconditionally responds
//     `res.json({'success': true})` (HTTP 200). This means a 200 for
//     a SHARE submission proves NOTHING about whether the inner Share
//     payload was actually accepted server-side.
//   - BLOCK: decodes/stores via `global.database.storeBlock(msgData.exInt,
//     msgData.msg, ...)` and responds 200 `{'success':true}` on real
//     success or HTTP 400 on real failure -- this msgType DOES have
//     observable success/failure semantics.
//   - INVALIDSHARE: analogous store/respond shape; not currently sent
//     by this package (see legacy.proto's own doc comment -- included
//     there purely for schema completeness).
//     The Node process listens with plain `app.listen(8000, ...)` -- no
//     TLS in the Node process itself; any TLS termination (https) is an
//     external reverse proxy concern, which is why this package's BaseURL
//     config takes the caller's scheme verbatim rather than assuming one.
//   - `nodejs-pool/lib/pool.js` (~line 305): confirms the real `bitcoin`
//     Share flag is `0`/false for a genuine Monero-family payout address
//     and `1`/true only for a validated Bitcoin address used for
//     auto-exchange payout. go-crypto-pool has no bitcoin-payout concept
//     at all, so this transport hardcodes `Bitcoin: false` unconditionally
//     -- see buildLegacyShare below.
//   - `nodejs-pool/lib/pool.js`'s `global.database.storeBlock(job.height,
//     global.protos.Block.encode({...}))` call, forwarded verbatim by
//     remoteShare.js as `msgData.exInt`: confirms `WSData.exInt` on a
//     BLOCK message is the real block height (int32) -- NOT part of the
//     legacy Block message itself, which has no height field at all.
//
// This package satisfies the exact same transport.ShareTransport
// interface as transport.HTTPProtobufTransport (see
// internal/leaflib/transport/transport.go) so cmd/leaf-direct/main.go's
// call sites need zero changes beyond picking which implementation to
// construct at startup.
package legacytransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/transport"
	legacypb "github.com/Snipa22/go-crypto-pool/internal/legacyproto"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
	"google.golang.org/protobuf/proto"
)

// DefaultShareTimeout/DefaultBlockTimeout mirror
// transport.HTTPProtobufTransport's own defaults -- see that package's
// doc comment for the "no timeouts anywhere" rationale (AGENTS.md-
// adjacent review notes).
const (
	DefaultShareTimeout = 5 * time.Second
	DefaultBlockTimeout = 5 * time.Second

	// DefaultBlockSubmitRetryBudget/DefaultBlockSubmitRetryInterval
	// bound SubmitBlock's real retry-with-backoff loop (added
	// 2026-09-23 -- see this const block's own doc comment below and
	// SubmitBlock's doc comment for the full incident this fixes).
	//
	// REAL PRODUCTION INCIDENT (2026-09-23): a genuine mainnet RXT
	// block find (height 351096, hash
	// 0218c4edd0737f4f97f56ae422d71a8fa5f24f02609214dafab0b4def0ef8d86)
	// was permanently lost from the pool's accounting DB because this
	// package's single-attempt SubmitBlock treated the legacy
	// backend's real, transient "my own chain view hasn't synced to
	// this hash yet" HTTP 400 as a permanent failure and gave up.
	// Re-querying the exact same hash against the exact same RPC
	// endpoint minutes later returned a perfectly valid result --
	// this was a genuine timing race, not a data/hash-format bug.
	//
	// The ORIGINAL legacy sender this package replaces
	// (nodejs-pool-tari-internal's lib/remote_comms.js,
	// this.storeBlock) retried the SAME POST indefinitely
	// (`forever: true`, an async.doUntil loop) until it got a 200,
	// specifically to absorb exactly this class of backend-chain-
	// sync-lag race. This package deliberately does NOT reproduce
	// "indefinitely" -- an unbounded retry loop risks hanging this
	// leaf's forward-pool worker forever on a genuinely bad/
	// malformed block that will NEVER succeed -- but it does need a
	// real, generously-sized bounded retry window to absorb the same
	// real-world propagation lag the original sender was built to
	// tolerate.
	//
	// BUDGET (Alex's explicit direction, 2026-09-23, superseding this
	// package's own first-draft 60-120s suggestion): 5 MINUTES, not
	// 60-120 seconds. Real propagation lag on this network is
	// typically a few seconds to low tens of seconds based on the
	// 2026-09-23 incident, but Alex's call is to leave substantially
	// more headroom than that observed range -- a genuinely wedged/
	// unusually-slow-syncing legacy backend should still get a fair
	// shot at catching up before this leaf gives up and the find is
	// lost, and losing one real block's accounting is a far worse
	// outcome than one extra forwardPool worker being tied up for a
	// few minutes on the rare block-find path (forwardBlock already
	// runs on the dedicated, bounded forwardPool -- see
	// direct/session.go's forwardBlock doc comment -- not on any
	// hot/latency-sensitive path).
	//
	// INTERVAL: fixed 5s -- deliberately NOT exponential. The real
	// failure mode here is "the backend's local chain view is a few
	// seconds to low tens of seconds behind", a roughly-fixed-latency
	// condition, not a load/congestion condition where exponential
	// backoff's growing-gap behavior would help; a flat 5s interval
	// gets more attempts into the same total budget while still
	// being gentle enough not to hammer the backend (60 attempts
	// over the full 5-minute budget in the worst case).
	DefaultBlockSubmitRetryBudget   = 5 * time.Minute
	DefaultBlockSubmitRetryInterval = 5 * time.Second

	// leafAPIPath is the real, fixed nodejs-pool-sxmr endpoint path --
	// see lib/remoteShare.js's app.post('/leafApi', ...) registration.
	// Unlike transport.HTTPProtobufTransport's configurable
	// SharePath/BlockPath, this is not configurable: it is the one real
	// path the legacy backend has ever exposed for this purpose.
	leafAPIPath = "/leafApi"
)

// Config configures LegacyTransport.
type Config struct {
	// BackendBaseURL is the legacy backend's base URL (scheme+host+port),
	// e.g. "https://legacy-backend.example.com:4443". LegacyTransport
	// appends leafAPIPath ("/leafApi") itself. No scheme is assumed or
	// hardcoded -- the real target very likely terminates TLS externally
	// in front of the Node process's plain app.listen(8000), so https is
	// the expected common case, but this package takes whatever scheme
	// the operator configures.
	BackendBaseURL string

	// AuthKey is the real WSData.key secret, checked server-side with a
	// plain `!==` string compare against global.config.api.authKey (see
	// package doc comment) -- NOT an HTTP header. Every WSData envelope
	// this transport sends carries this value in its key field.
	AuthKey string

	// LegacyPoolType / LegacyPoolID are this transport's OWN,
	// independently-configured legacy-backend pool type/ID, used to
	// populate every outgoing legacy Share/Block's poolType/poolID
	// fields.
	//
	// IMPORTANT: these are deliberately NOT read from the incoming
	// *poolpb.Share.pool_type/pool_id at SubmitShare/SubmitBlock time.
	// go-crypto-pool's own pool_id/pool_type are this repo's OWN
	// pool-server-source identifiers (see internal/proto/share.proto's
	// Share.pool_id doc comment) and are very likely NOT the same
	// numbering/payout-model space as the legacy backend's pool_id/
	// poolType. This is an OPEN DESIGN QUESTION -- confirm with Alex
	// whether legacy-mode pool-type/pool-id should ever be allowed to
	// just mirror go-crypto-pool's own -pool-type/-pool-id, or whether
	// they must always be independently configured like this.
	// Defaulting to independent config here as the safer assumption
	// (see cmd/leaf-direct/main.go's -legacy-pool-type/-legacy-pool-id
	// flag doc comments, which carry the identical note).
	LegacyPoolType legacypb.POOLTYPE
	LegacyPoolID   int32

	// ShareTimeout/BlockTimeout bound each individual HTTP call via
	// context.WithTimeout, mirroring
	// transport.HTTPProtobufTransportConfig's identical fields exactly.
	// Zero/negative values fall back to the package defaults.
	ShareTimeout time.Duration
	BlockTimeout time.Duration

	// HTTPClient allows injecting a custom *http.Client (e.g. for test
	// doubles). If nil, a client with a conservative default Timeout is
	// constructed.
	HTTPClient *http.Client

	// BlockSubmitRetryBudget bounds the TOTAL wall-clock time
	// SubmitBlock's retry loop is allowed to keep retrying a failed
	// block submission before giving up and returning a real error
	// (see DefaultBlockSubmitRetryBudget's doc comment for the full
	// 2026-09-23 production-incident rationale). This is a SEPARATE,
	// OUTER bound from BlockTimeout above: BlockTimeout still bounds
	// each individual HTTP call exactly as before; this field bounds
	// the whole retry loop wrapping potentially many such calls.
	// Zero/negative falls back to DefaultBlockSubmitRetryBudget.
	// Never applies to SubmitShare -- see that method's doc comment
	// for why a share submission has no meaningful retry semantics.
	BlockSubmitRetryBudget time.Duration

	// BlockSubmitRetryInterval is the fixed delay between retry
	// attempts within BlockSubmitRetryBudget (see
	// DefaultBlockSubmitRetryInterval's doc comment for why this is a
	// flat interval rather than exponential backoff). Zero/negative
	// falls back to DefaultBlockSubmitRetryInterval.
	BlockSubmitRetryInterval time.Duration

	// Logger receives an escalating warning line on every failed
	// SubmitBlock attempt that is about to be retried (never fatal --
	// the loop itself decides whether to give up, see SubmitBlock's
	// doc comment). If nil, log.Default() is used. Mirrors
	// CheckinConfig.Logger's identical convention exactly.
	Logger *log.Logger
}

// LegacyTransport is a transport.ShareTransport implementation that
// POSTs raw-protobuf WSData envelopes to a legacy nodejs-pool-sxmr
// backend's /leafApi endpoint. See package doc comment for the full
// real-source-modeled behavioral contract.
type LegacyTransport struct {
	baseURL      string
	authKey      string
	poolType     legacypb.POOLTYPE
	poolID       int32
	shareTimeout time.Duration
	blockTimeout time.Duration
	client       *http.Client

	// blockRetryBudget/blockRetryInterval/logger back
	// SubmitBlock's retry-with-backoff loop only -- see
	// Config.BlockSubmitRetryBudget's doc comment. Never consulted
	// by SubmitShare.
	blockRetryBudget   time.Duration
	blockRetryInterval time.Duration
	logger             *log.Logger
}

// New constructs a LegacyTransport from cfg. Returns an error if
// BackendBaseURL or AuthKey is empty.
func New(cfg Config) (*LegacyTransport, error) {
	if cfg.BackendBaseURL == "" {
		return nil, errors.New("legacytransport: BackendBaseURL must not be empty")
	}
	if cfg.AuthKey == "" {
		return nil, errors.New("legacytransport: AuthKey must not be empty")
	}

	shareTimeout := cfg.ShareTimeout
	if shareTimeout <= 0 {
		shareTimeout = DefaultShareTimeout
	}
	blockTimeout := cfg.BlockTimeout
	if blockTimeout <= 0 {
		blockTimeout = DefaultBlockTimeout
	}

	client := cfg.HTTPClient
	if client == nil {
		maxTimeout := shareTimeout
		if blockTimeout > maxTimeout {
			maxTimeout = blockTimeout
		}
		client = &http.Client{Timeout: maxTimeout + 5*time.Second}
	}

	blockRetryBudget := cfg.BlockSubmitRetryBudget
	if blockRetryBudget <= 0 {
		blockRetryBudget = DefaultBlockSubmitRetryBudget
	}
	blockRetryInterval := cfg.BlockSubmitRetryInterval
	if blockRetryInterval <= 0 {
		blockRetryInterval = DefaultBlockSubmitRetryInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	return &LegacyTransport{
		baseURL:            trimTrailingSlash(cfg.BackendBaseURL),
		authKey:            cfg.AuthKey,
		poolType:           cfg.LegacyPoolType,
		poolID:             cfg.LegacyPoolID,
		shareTimeout:       shareTimeout,
		blockTimeout:       blockTimeout,
		client:             client,
		blockRetryBudget:   blockRetryBudget,
		blockRetryInterval: blockRetryInterval,
		logger:             logger,
	}, nil
}

// legacyPoolTypeFromPB maps go-crypto-pool's own PoolType enum to the
// legacy POOLTYPE enum, per the brief's exact mapping. POOL_TYPE_UNSPECIFIED
// has no legacy equivalent and returns an error rather than silently
// picking one -- forwarding a legacy Share/Block with an arbitrary/
// default poolType would silently corrupt legacy-side payout accounting.
func legacyPoolTypeFromPB(pt poolpb.PoolType) (legacypb.POOLTYPE, error) {
	switch pt {
	case poolpb.PoolType_POOL_TYPE_PPLNS:
		return legacypb.POOLTYPE_PPLNS, nil
	case poolpb.PoolType_POOL_TYPE_PPS:
		return legacypb.POOLTYPE_PPS, nil
	case poolpb.PoolType_POOL_TYPE_PROP:
		return legacypb.POOLTYPE_PROP, nil
	case poolpb.PoolType_POOL_TYPE_SOLO:
		return legacypb.POOLTYPE_SOLO, nil
	default:
		return 0, fmt.Errorf("legacytransport: pool_type %v has no legacy POOLTYPE equivalent (POOL_TYPE_UNSPECIFIED is not a valid legacy value)", pt)
	}
}

// int32FromInt64 validates v fits in the int32 range, returning a real
// error (never a silent truncate/wrap) if it does not. field is used
// only to build a descriptive error message.
func int32FromInt64(v int64, field string) (int32, error) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("legacytransport: %s value %d does not fit in int32 (legacy wire schema requires int32; this is deliberately a hard error, not a truncate)", field, v)
	}
	return int32(v), nil
}

// buildLegacyShare maps a go-crypto-pool *poolpb.Share to the legacy
// Share message, per the brief's exact field mapping.
func buildLegacyShare(share *poolpb.Share, legacyPoolType legacypb.POOLTYPE, legacyPoolID int32) (*legacypb.Share, error) {
	shares32, err := int32FromInt64(share.GetShares(), "shares")
	if err != nil {
		return nil, err
	}
	blockHeight32, err := int32FromInt64(share.GetBlockHeight(), "block_height")
	if err != nil {
		return nil, err
	}
	poolType, err := legacyPoolTypeFromPB(share.GetPoolType())
	if err != nil {
		return nil, err
	}

	legacyShare := &legacypb.Share{
		Shares:         proto.Int32(shares32),
		PaymentAddress: proto.String(share.GetPaymentAddress()),
		FoundBlock:     proto.Bool(share.GetFoundBlock()),
		TrustedShare:   proto.Bool(share.GetTrustedShare()),
		PoolType:       poolType.Enum(),
		// PoolID/PoolType above are this transport's OWN independently
		// configured legacy pool ID/type (see Config's doc comment) --
		// NOT share.GetPoolId()/share.GetPoolType() (go-crypto-pool's own,
		// separate numbering space).
		PoolID: proto.Int32(legacyPoolID),
		// BlockDiff: the REAL legacy nodejs-pool-sxmr backend's
		// remoteShare.js / payout-effort accounting expects this to be
		// the genuine network/block target difficulty (confirmed via
		// live tcpdump capture + protobuf decode against production,
		// 2026-09-23), NOT go-crypto-pool's own Share.block_diff field
		// (which -- despite its name -- is deliberately the session's
		// own vardiff/share-weight value here, kept that way because
		// internal/backend/db's address-difficulty-floor enforcement
		// depends on it; see poolpb.Share.network_diff's doc comment
		// and internal/leaflib/direct/session.go's handleSubmit for the
		// full rationale). share.GetNetworkDiff() is the correct,
		// additive field for this legacy-only purpose.
		BlockDiff: proto.Int64(share.GetNetworkDiff()),
		// Bitcoin is hardcoded false: this repo has no bitcoin-payout
		// concept at all, and nodejs-pool/lib/pool.js (~line 305) confirms
		// the real flag is 0/false for any genuine Monero-family payout
		// address anyway -- see package doc comment.
		Bitcoin:     proto.Bool(false),
		BlockHeight: proto.Int32(blockHeight32),
		// Timestamp: the real legacy remoteShare.js does
		// `Math.floor(shareData.timestamp / 1000)` before storing to
		// Postgres -- i.e. it ASSUMES the incoming value is Unix
		// MILLISECONDS (matching the original legacy sender's JS
		// `+new Date()`). go-crypto-pool's own poolpb.Share.timestamp
		// is Unix SECONDS (internal/backend/db.Repository.InsertShare
		// does `time.Unix(s.Timestamp, 0)` -- confirmed real, load-
		// bearing normal-path semantics that must not change), so this
		// legacy-only wire path multiplies by 1000 here rather than
		// changing Share.timestamp's unit at the source (see
		// internal/leaflib/direct/session.go's handleSubmit for the
		// same rationale on the BlockDiff/NetworkDiff split above).
		Timestamp:  proto.Int64(share.GetTimestamp() * 1000),
		Identifier: proto.String(share.GetIdentifier()),
	}
	if share.PaymentId != nil {
		legacyShare.PaymentID = proto.String(share.GetPaymentId())
	}
	// algo/network/raw_proof (oneof) fields have no legacy equivalent --
	// dropped entirely, per the brief.

	return legacyShare, nil
}

// buildLegacyBlock maps a go-crypto-pool *poolpb.Block to the legacy
// Block message plus the exInt (height) value that travels via the
// outer WSData envelope, per the brief's exact field mapping.
//
// Note: legacy Block has no height field (height only ever traveled via
// WSData.exInt, confirmed from lib/pool.js's storeBlock(job.height, ...)
// call) -- so height is returned separately here rather than being set
// on the legacypb.Block itself. algo/network/pool_id similarly have no
// legacy Block destination and are dropped.
func buildLegacyBlock(block *poolpb.Block, legacyPoolType legacypb.POOLTYPE) (*legacypb.Block, int32, error) {
	height32, err := int32FromInt64(block.GetHeight(), "height")
	if err != nil {
		return nil, 0, err
	}
	poolType, err := legacyPoolTypeFromPB(block.GetPoolType())
	if err != nil {
		return nil, 0, err
	}

	legacyBlock := &legacypb.Block{
		Hash:       proto.String(block.GetHash()),
		Difficulty: proto.Int64(block.GetDifficulty()),
		Shares:     proto.Int64(block.GetShares()),
		// Timestamp: same bug class as buildLegacyShare's Timestamp
		// fix above (see that field's doc comment for the full
		// rationale) -- the real legacy nodejs-pool-sxmr backend's
		// lib/pool.js storeBlock call does
		// `global.protos.Block.encode({..., timestamp: Date.now(), ...})`,
		// i.e. JS Date.now() is Unix MILLISECONDS, and the real
		// `blocks.block_timestamp` column (confirmed live,
		// 2026-09-23: every historical row is millisecond-scale) is
		// a plain bigint with no SQL-side unit coercion. go-crypto-
		// pool's own poolpb.Block.timestamp is Unix SECONDS
		// (internal/leaflib/direct/session.go's forwardBlock does
		// `time.Now().Unix()`, and the normal, non-legacy backend
		// path -- internal/backend/api's blockToRecord plus
		// internal/backend/db.Repository.InsertBlock -- forwards
		// that same value through as an opaque, unconverted int64
		// with no consumer assuming millisecond semantics, so
		// changing the SOURCE would be safe there but is still
		// unnecessary), so this legacy-only wire path multiplies by
		// 1000 here rather than changing Block.timestamp's unit at
		// the source -- same convert-only-in-legacytransport
		// approach as buildLegacyShare's Timestamp fix.
		Timestamp: proto.Int64(block.GetTimestamp() * 1000),
		PoolType:  poolType.Enum(),
		Unlocked:  proto.Bool(block.GetUnlocked()),
		Valid:     proto.Bool(block.GetValid()),
	}
	if block.Value != nil {
		legacyBlock.Value = proto.Int64(block.GetValue())
	}

	return legacyBlock, height32, nil
}

// SubmitShare implements transport.ShareTransport.
//
// Real legacy behavior (see package doc comment, modeled on
// lib/remoteShare.js): a SHARE submission gets an unconditional HTTP 200
// `{"success":true}` from a well-formed WSData envelope, EVEN IF the
// inner Share fails to decode server-side (a silently swallowed
// try/catch on the Node side). So a nil error return here proves only
// that the outer WSData envelope was delivered and accepted at the
// transport level -- it does NOT prove the inner Share payload was
// actually accepted/processed server-side. Any non-2xx HTTP response, or
// a network/transport-level error, IS treated as a real error.
func (t *LegacyTransport) SubmitShare(ctx context.Context, share *poolpb.Share) error {
	legacyShare, err := buildLegacyShare(share, t.poolType, t.poolID)
	if err != nil {
		return fmt.Errorf("legacytransport: build legacy share: %w", err)
	}

	shareData, err := proto.Marshal(legacyShare)
	if err != nil {
		return fmt.Errorf("legacytransport: marshal legacy share: %w", err)
	}

	// exInt is unused/irrelevant for SHARE messages -- the legacy server
	// ignores it entirely for this msgType (see remoteShare.js's SHARE
	// case, which never reads msgData.exInt). Set to 0 for clarity.
	envelope := &legacypb.WSData{
		MsgType: legacypb.MESSAGETYPE_SHARE.Enum(),
		Key:     proto.String(t.authKey),
		Msg:     shareData,
		ExInt:   proto.Int32(0),
	}

	return t.post(ctx, envelope, t.shareTimeout, "share")
}

// SubmitBlock implements transport.ShareTransport.
//
// Unlike SubmitShare, BLOCK submissions DO have real, observable
// success/failure semantics server-side (see package doc comment: real
// `global.database.storeBlock` failure -> HTTP 400). Any non-2xx HTTP
// response, or a network/transport-level error, is treated as a real
// error here, faithfully surfacing that real semantic.
//
// RETRY-WITH-BACKOFF (added 2026-09-23, real production incident --
// see DefaultBlockSubmitRetryBudget's doc comment for the full
// rationale): a non-2xx response is retried against the SAME POST at
// a fixed interval (blockRetryInterval) until either it succeeds or
// the total outer budget (blockRetryBudget) is exhausted, at which
// point this returns a real, clear error -- it never retries
// unbounded/forever (unlike the original legacy JS sender), and it
// never blocks past ctx's own deadline/cancellation either. Each
// individual HTTP attempt is still bounded by blockTimeout exactly as
// before (t.post's own context.WithTimeout) -- blockRetryBudget is a
// SEPARATE, larger outer bound wrapping potentially many such calls,
// not a replacement for it. Every retried attempt (i.e. every
// attempt after the first) logs an escalating warning via t.logger.
func (t *LegacyTransport) SubmitBlock(ctx context.Context, block *poolpb.Block) error {
	legacyBlock, height32, err := buildLegacyBlock(block, t.poolType)
	if err != nil {
		return fmt.Errorf("legacytransport: build legacy block: %w", err)
	}

	blockData, err := proto.Marshal(legacyBlock)
	if err != nil {
		return fmt.Errorf("legacytransport: marshal legacy block: %w", err)
	}

	envelope := &legacypb.WSData{
		MsgType: legacypb.MESSAGETYPE_BLOCK.Enum(),
		Key:     proto.String(t.authKey),
		Msg:     blockData,
		// exInt on a BLOCK message is the real block height (confirmed
		// from lib/pool.js's storeBlock(job.height, ...) call, forwarded
		// verbatim by remoteShare.js as msgData.exInt) -- see package doc
		// comment.
		ExInt: proto.Int32(height32),
	}

	deadline := time.Now().Add(t.blockRetryBudget)
	var lastErr error
	for attempt := 1; ; attempt++ {
		lastErr = t.post(ctx, envelope, t.blockTimeout, "block")
		if lastErr == nil {
			return nil
		}

		// Give up cleanly (real error, never a hang) once either the
		// caller's own ctx is done, or this attempt's failure already
		// pushed us past the retry budget's deadline -- checked AFTER
		// the attempt (not just before sleeping) so a slow-but-still-
		// failing final attempt cannot itself blow past the budget
		// unnoticed.
		if ctx.Err() != nil {
			return fmt.Errorf("legacytransport: submit block: giving up after %d attempt(s), context done: %w (last attempt error: %v)", attempt, ctx.Err(), lastErr)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("legacytransport: submit block: exhausted retry budget %s after %d attempt(s), giving up (this find needs manual reconciliation against the real chain at this height): %w", t.blockRetryBudget, attempt, lastErr)
		}

		wait := t.blockRetryInterval
		if wait > remaining {
			wait = remaining
		}
		t.logger.Printf("legacytransport: submit block attempt %d failed (retrying in %s, %s left in retry budget): %v", attempt, wait, remaining.Round(time.Second), lastErr)

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("legacytransport: submit block: giving up after %d attempt(s), context done while waiting to retry: %w (last attempt error: %v)", attempt, ctx.Err(), lastErr)
		}
	}
}

// Close implements transport.ShareTransport. LegacyTransport holds no
// long-lived resources beyond the *http.Client's connection pool (which
// net/http manages itself), so Close is a no-op -- mirrors
// transport.HTTPProtobufTransport.Close's identical rationale exactly.
func (t *LegacyTransport) Close() error {
	return nil
}

// post marshals envelope and POSTs the raw protobuf bytes to
// <baseURL>/leafApi, per the real wire contract (no JSON wrapper, no
// body-parser -- see package doc comment). kind is used only for error
// message context ("share"/"block").
func (t *LegacyTransport) post(ctx context.Context, envelope *legacypb.WSData, timeout time.Duration, kind string) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("legacytransport: marshal WSData envelope for %s: %w", kind, err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := t.baseURL + leafAPIPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("legacytransport: build %s request: %w", kind, err)
	}
	// Content-Type is set for well-behaved HTTP hygiene, even though the
	// real legacy server ignores it entirely (no body-parser middleware
	// keys off it for this route -- see package doc comment).
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("legacytransport: submit %s: %w", kind, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("legacytransport: submit %s: backend returned status %d: %s", kind, resp.StatusCode, string(body))
	}

	return nil
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// Compile-time assertion that LegacyTransport satisfies
// transport.ShareTransport.
var _ transport.ShareTransport = (*LegacyTransport)(nil)
