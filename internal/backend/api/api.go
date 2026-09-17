// Package api implements the backend's HTTP + Protobuf share-ingestion
// endpoints. The backend is a trust boundary, not a validator: it accepts
// leaf-validated shares and does not perform hashing/PoW verification
// itself.
//
// Endpoints and wire contract here MUST match
// internal/leaflib/transport.HTTPProtobufTransport exactly, since that is
// the (only) client this package is written against:
//
//   - POST /api/v1/share  — body is a protobuf-marshaled poolpb.Share
//   - POST /api/v1/block  — body is a protobuf-marshaled poolpb.Block
//   - GET  /metrics       — standard Prometheus text-exposition
//     format (promhttp.HandlerFor over this Handler's private
//     registry; see internal/backend/metrics). Not part of the leaf
//     wire contract, ops-only.
//   - Content-Type: application/x-protobuf on both.
//   - Optional shared-secret auth header: if the server is configured
//     with an auth header name+value, requests missing that header (or
//     presenting the wrong value) are rejected with 401 before any
//     decode/DB work happens, and counted on shares_total/blocks_total
//     with result="unauthorized" (see internal/backend/metrics.
//     ResultUnauthorized) — a real, queryable/alertable count of
//     rejected-for-auth ingestion attempts, distinct from every other
//     rejection reason (malformed body, failed validation, network
//     mismatch — all result="rejected"). If no auth is configured
//     (both name and value empty), no auth check is performed at all —
//     this mirrors the transport's "both empty means no auth header
//     sent" v1 story symmetrically on the server side. cmd/backend's
//     own startup wiring refuses to even start with both empty unless
//     an explicit, loudly-logged override is passed — see that
//     command's validateIngestionAuthConfig — so this "no auth
//     configured" state is a deliberate local/dev-only escape hatch at
//     this package's level, not this repo's production default.
package api

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
)

// maxBodyBytes bounds how much of a request body we will read. Shares
// and blocks are small protobuf messages; there is no legitimate reason
// for either to approach this size, and capping it protects the handler
// from unbounded-body-based resource exhaustion.
const maxBodyBytes = 1 << 20 // 1 MiB

// ShareBlockRepository is the narrow persistence surface the handlers
// depend on. It is intentionally an interface (rather than the concrete
// *db.Repository type) so tests can inject a fake/mock without needing a
// real Postgres instance. *db.Repository satisfies this interface as-is.
type ShareBlockRepository interface {
	InsertShare(ctx context.Context, s ShareRecord, bucketSize int64) error
	InsertBlock(ctx context.Context, b BlockRecord) error
}

// ErrAddressBanned is this package's own sentinel for "the submitting
// share's payment_address is operator-banned" -- the api-package-side
// counterpart of internal/backend/db.ErrAddressBanned. It exists
// separately (rather than this package importing db.ErrAddressBanned
// directly) to preserve the same dependency direction ShareRecord/
// BlockRecord already establish: this package depends on
// internal/backend/db only through ShareBlockRepository's structural
// interface shape, never a direct import. cmd/backend's
// repositoryAdapter (the one place both packages meet) is responsible
// for translating a db.ErrAddressBanned returned by the real
// *db.Repository into this sentinel (wrapped, via errors.Is-compatible
// %w) before it reaches handleShare below.
var ErrAddressBanned = errors.New("api: payment address is banned")

// ShareRecord/BlockRecord mirror db.Share/db.Block field-for-field. They
// exist so this package does not need to import internal/backend/db
// directly for its interface definition (keeping the dependency
// direction: db has no knowledge of api, api depends on db only through
// this interface's structural shape). cmd/backend wires a *db.Repository
// in via a small adapter (see NewRepositoryAdapter) since db.Share/
// db.Block already have the identical shape.
type ShareRecord struct {
	Algo           string
	Network        string
	PoolType       string
	PoolID         int32
	BlockHeight    int64
	Shares         int64
	PaymentAddress string
	PaymentID      *string
	FoundBlock     bool
	BlockDiff      int64
	Timestamp      int64
	Identifier     string
	TrustedShare   bool
}

// BlockRecord mirrors db.Block.
type BlockRecord struct {
	Algo       string
	Network    string
	PoolType   string
	Hash       string
	Height     int64
	Difficulty int64
	Shares     int64
	Timestamp  int64
	Unlocked   bool
	Valid      bool
	Value      *int64
	PoolID     int32

	// MergeMineChain mirrors internal/proto.Block.merge_mine_chain /
	// db.Block.MergeMineChain (see those fields' doc comments) -- nil
	// for the primary/Monero leg of an ALGO_RXM find, non-nil (e.g.
	// "TARI") for a secondary merge-mined chain leg.
	MergeMineChain *string
}

// HeightPartitionBucketSize is passed to InsertShare's bucketSize
// parameter. It mirrors db.HeightPartitionBucketSize's value; kept as an
// independent constant here (rather than importing internal/backend/db
// for it) to preserve this package's DB-independence at the interface
// level. cmd/backend's adapter is the only place both packages meet.
const HeightPartitionBucketSize int64 = 100000

// Config configures a Handler.
type Config struct {
	// AuthHeaderName/AuthHeaderValue configure a simple shared-secret
	// header check, symmetric with
	// transport.HTTPProtobufTransportConfig's AuthHeaderName/
	// AuthHeaderValue. Both empty means no auth check is performed.
	AuthHeaderName  string
	AuthHeaderValue string

	// Network is this backend's own configured network
	// (NETWORK_MAINNET or NETWORK_TESTNET). Every submitted Share/Block
	// must carry this exact Network value or it is rejected — this is
	// the guard against a testnet leaf submitting to a mainnet backend
	// (or vice versa) undetected.
	//
	// NETWORK_UNSPECIFIED (the zero value) disables this check, mainly
	// so existing/unit tests that don't care about network enforcement
	// don't need to set it. cmd/backend's production wiring must always
	// set this explicitly (it fails fast at startup if it can't parse a
	// valid network from its environment) — silently defaulting here
	// would reintroduce exactly the cross-network contamination risk
	// this field exists to close.
	Network poolpb.Network

	// Metrics, if non-nil, is the metrics.Metrics instance this
	// Handler's handlers increment/observe and serves on GET
	// /metrics. If nil, NewHandler creates a fresh, private one (see
	// metrics.New's doc comment) — most callers, including
	// cmd/backend, can leave this unset.
	Metrics *metrics.Metrics

	// Version is recorded on the metrics build_info gauge when this
	// Handler creates its own default Metrics (i.e. when Metrics
	// above is left nil). Ignored if Metrics is set explicitly.
	Version string

	// IngestionRateLimit is the sustained requests-per-second rate
	// allowed per source IP, shared across BOTH /api/v1/share and
	// /api/v1/block combined (see rateLimiterFor's doc comment for
	// why a single combined limiter per IP, rather than one per
	// endpoint). <= 0 means "disabled" (no rate limiting at all) —
	// mirrors cmd/backend's -max-connections' own 0 = unlimited
	// convention. This is the only defense in this package against
	// a single misbehaving/malicious leaf flooding
	// /api/v1/share or /api/v1/block as fast as it can open
	// requests — cmd/backend's -max-connections/
	// GCPOOL_MAX_CONNECTIONS caps total concurrent TCP connections
	// across ALL sources combined, not any individual source's
	// request rate.
	IngestionRateLimit float64

	// IngestionRateBurst is the burst size (rate.Limiter's burst
	// parameter) for the same per-source-IP limiter
	// IngestionRateLimit configures. Only consulted when
	// IngestionRateLimit > 0.
	IngestionRateBurst int
}

// Handler implements the backend's share/block ingestion HTTP endpoints.
type Handler struct {
	repo ShareBlockRepository
	cfg  Config
	m    *metrics.Metrics

	// ipLimitersMu guards ipLimiters.
	ipLimitersMu sync.Mutex
	// ipLimiters holds one *rate.Limiter per source IP seen on the
	// ingestion routes, created lazily on first sight of that IP
	// (see rateLimiterFor). This is a per-process, in-memory-only
	// map with no eviction: a stale/unbounded-growth map is an
	// accepted tradeoff at this package's scope (a private/internal
	// pool backend with a bounded, known set of leaf IPs in
	// practice, not an internet-facing service exposed to an
	// unbounded set of source IPs) — do not add eviction here
	// without a real, observed growth problem to justify the added
	// complexity.
	ipLimiters map[string]*rate.Limiter
}

// NewHandler constructs a Handler backed by repo, using cfg for optional
// auth-header configuration.
//
// If cfg.Metrics is nil, a fresh, private metrics.Metrics is created
// for this Handler (see metrics.New's doc comment on why a private
// registry per Handler, rather than the global default one, is the
// right default here — it is what keeps repeated NewHandler calls in
// tests safe).
func NewHandler(repo ShareBlockRepository, cfg Config) *Handler {
	m := cfg.Metrics
	if m == nil {
		m = metrics.New(cfg.Version)
	}
	return &Handler{repo: repo, cfg: cfg, m: m, ipLimiters: make(map[string]*rate.Limiter)}
}

// Metrics returns this Handler's metrics.Metrics instance (the same
// one whose collectors are incremented/observed by handleShare/
// handleBlock), primarily so cmd/backend and tests can reach its
// Handler() for the /metrics route or assert on collected values.
func (h *Handler) Metrics() *metrics.Metrics {
	return h.m
}

// Mux builds an *http.ServeMux with this Handler's routes registered.
// Kept simple deliberately — this repo has exactly two endpoints and
// does not need a web framework for that. /metrics is intentionally
// NOT wrapped by the in-flight-request middleware below — it is not
// part of the share/block ingestion surface that gauge exists to
// describe.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// RegisterRoutes registers this Handler's routes onto mux. Safe to
// call on a mux that already has other, disjoint routes registered
// (e.g. internal/backend/statsapi.Handler's read-only miner stats
// routes, which cmd/backend mounts on the same listener) — this
// package never registers anything under /api/v1/stats/.
//
// Registers BOTH the share/block ingestion routes AND GET /metrics
// on the SAME mux — this is the right default for this package's own
// tests and any caller that genuinely wants everything on one
// listener. cmd/backend does NOT use this method for its production
// wiring: per PROD_HARDENING_REVIEW.md finding #12 (/metrics exposes
// wallet_balance_atomic, the real hot-wallet balance, and must not
// share a public listener with share/block ingestion), it calls
// RegisterIngestionRoutes and RegisterMetricsRoute separately against
// two different muxes/listeners instead. See those two methods' own
// doc comments.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	h.RegisterIngestionRoutes(mux)
	h.RegisterMetricsRoute(mux)
}

// RegisterIngestionRoutes registers ONLY this Handler's share/block
// ingestion routes (POST /api/v1/share, POST /api/v1/block) onto mux
// — deliberately NOT GET /metrics (see RegisterMetricsRoute for
// that). Exists so a caller that wants a physically separate
// listener for /metrics (see cmd/backend's -metrics-listen-addr /
// GCPOOL_METRICS_LISTEN_ADDR) can mount the ingestion surface on its
// own public listener without this package needing to know anything
// about listener topology itself.
func (h *Handler) RegisterIngestionRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/share", h.instrumentInFlight(http.HandlerFunc(h.handleShare)))
	mux.Handle("POST /api/v1/block", h.instrumentInFlight(http.HandlerFunc(h.handleBlock)))
}

// RegisterMetricsRoute registers ONLY GET /metrics onto mux — the
// counterpart to RegisterIngestionRoutes above, for a caller that
// wants /metrics served from a separate mux/listener than the
// ingestion routes.
func (h *Handler) RegisterMetricsRoute(mux *http.ServeMux) {
	mux.Handle("GET /metrics", h.m.Handler())
}

// instrumentInFlight wraps next so http_requests_in_flight tracks
// exactly the requests currently inside /api/v1/share or
// /api/v1/block handling.
func (h *Handler) instrumentInFlight(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.m.HTTPRequestsInFlight.Inc()
		defer h.m.HTTPRequestsInFlight.Dec()
		next.ServeHTTP(w, r)
	})
}

// authConfigured reports whether an auth header check should be
// performed at all.
func (h *Handler) authConfigured() bool {
	return h.cfg.AuthHeaderName != "" || h.cfg.AuthHeaderValue != ""
}

// checkAuth returns true if the request passes the configured auth
// check (or if no auth is configured at all).
//
// The final comparison uses hmac.Equal (constant-time) rather than
// Go's built-in == operator, matching internal/backend/authapi's own
// password-check pattern exactly. A shared-secret leaf-to-backend
// trust-boundary credential compared with == is a real timing side
// channel: == on strings short-circuits on the first mismatched byte,
// so a network-adjacent attacker able to measure response latency can
// recover the secret byte-by-byte. hmac.Equal always compares the
// full length of both inputs in constant time regardless of where
// (or whether) they first differ.
func (h *Handler) checkAuth(r *http.Request) bool {
	if !h.authConfigured() {
		return true
	}
	got := r.Header.Get(h.cfg.AuthHeaderName)
	if got == "" {
		return false
	}
	return hmac.Equal([]byte(got), []byte(h.cfg.AuthHeaderValue))
}

// sourceIP extracts the bare IP (no port) that h's per-IP ingestion
// rate limiter keys on, from r.RemoteAddr. net/http guarantees
// RemoteAddr is normally "IP:port" for a real network connection;
// mirrors this repo's existing net.Addr-based IP-extraction
// convention (see internal/leaflib/metrics.RemoteIPOf) by falling
// back to the raw, unparsed RemoteAddr value on a net.SplitHostPort
// error (e.g. a test transport that sets a bare host with no port)
// rather than collapsing every unparsable RemoteAddr onto a single
// shared "" bucket.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimiterFor returns h's *rate.Limiter for ip, constructing one
// lazily (using h.cfg.IngestionRateLimit/IngestionRateBurst) on first
// sight of that IP and caching it in h.ipLimiters for every
// subsequent call. Safe for concurrent use.
//
// Design choice: ONE combined limiter per source IP, shared across
// BOTH /api/v1/share and /api/v1/block, rather than a separate
// limiter per endpoint. RegisterIngestionRoutes wires both handlers
// as a single ingestion surface for one leaf, and cmd/backend only
// exposes a single -ingestion-rate-limit/-ingestion-rate-burst knob
// pair (not one per endpoint) — a combined bucket per IP is the more
// natural fit for that shape, and it is simpler than maintaining two
// independent limiter maps for what is, from one leaf's perspective,
// one aggregate submit rate.
func (h *Handler) rateLimiterFor(ip string) *rate.Limiter {
	h.ipLimitersMu.Lock()
	defer h.ipLimitersMu.Unlock()
	if lim, ok := h.ipLimiters[ip]; ok {
		return lim
	}
	lim := rate.NewLimiter(rate.Limit(h.cfg.IngestionRateLimit), h.cfg.IngestionRateBurst)
	h.ipLimiters[ip] = lim
	return lim
}

// checkRateLimit reports whether r's source IP is currently within
// its configured per-IP ingestion rate limit. Always true (no
// limiting performed at all, not even bucket construction) when
// h.cfg.IngestionRateLimit <= 0 — mirrors -max-connections' own 0 =
// unlimited convention.
func (h *Handler) checkRateLimit(r *http.Request) bool {
	if h.cfg.IngestionRateLimit <= 0 {
		return true
	}
	return h.rateLimiterFor(sourceIP(r)).Allow()
}

func (h *Handler) handleShare(w http.ResponseWriter, r *http.Request) {
	// Rate limit is checked BEFORE auth: this is a DoS-focused
	// per-source throttle, not part of the auth trust boundary, so
	// either ordering is defensible (see brief/PROD_HARDENING_
	// REVIEW.md finding). Checking it first sheds excess load from
	// a single source as early as possible, before doing any other
	// per-request work (including the auth comparison). Kept
	// consistent with handleBlock below.
	if !h.checkRateLimit(r) {
		h.m.SharesTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultRateLimited).Inc()
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	if !h.checkAuth(r) {
		h.m.SharesTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultUnauthorized).Inc()
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	body, err := readBody(r)
	if err != nil {
		h.m.SharesTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultRejected).Inc()
		writeErr(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}

	share := &poolpb.Share{}
	if err := proto.Unmarshal(body, share); err != nil {
		h.m.SharesTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultRejected).Inc()
		writeErr(w, http.StatusBadRequest, "malformed protobuf Share")
		return
	}

	// From here on the share decoded far enough to know its real
	// algo/network/pool_type (even if one of those fields is itself
	// the reason validation below fails, e.g. algo unspecified —
	// algoString etc. map that to "", which is still a single fixed
	// label value, not per-request data).
	algo, network, poolType := algoString(share.GetAlgo()), networkString(share.GetNetwork()), poolTypeString(share.GetPoolType())

	if err := validateShare(share); err != nil {
		h.m.SharesTotal.WithLabelValues(algo, network, poolType, metrics.ResultRejected).Inc()
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkNetwork(share.GetNetwork()); err != nil {
		h.m.SharesTotal.WithLabelValues(algo, network, poolType, metrics.ResultRejected).Inc()
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	record := shareToRecord(share)
	start := time.Now()
	err = h.repo.InsertShare(r.Context(), record, HeightPartitionBucketSize)
	h.m.ShareInsertDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		if errors.Is(err, ErrAddressBanned) {
			// A banned address is a rejection, not a server error --
			// same bucket as the validateShare/checkNetwork
			// 4xx-mapped rejections above, and the same
			// metrics.ResultRejected label those already use. 403
			// (not 400/404): the caller is authenticated, the
			// request itself is well-formed, the address is simply
			// disallowed.
			h.m.SharesTotal.WithLabelValues(algo, network, poolType, metrics.ResultRejected).Inc()
			writeErr(w, http.StatusForbidden, "payment address is banned")
			return
		}
		h.m.SharesTotal.WithLabelValues(algo, network, poolType, metrics.ResultError).Inc()
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}

	h.m.SharesTotal.WithLabelValues(algo, network, poolType, metrics.ResultAccepted).Inc()
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) handleBlock(w http.ResponseWriter, r *http.Request) {
	// See handleShare's identical rate-limit-before-auth comment
	// above for why this ordering was picked; kept consistent
	// between the two handlers.
	if !h.checkRateLimit(r) {
		h.m.BlocksTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultRateLimited).Inc()
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	if !h.checkAuth(r) {
		h.m.BlocksTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultUnauthorized).Inc()
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	body, err := readBody(r)
	if err != nil {
		h.m.BlocksTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultRejected).Inc()
		writeErr(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}

	block := &poolpb.Block{}
	if err := proto.Unmarshal(body, block); err != nil {
		h.m.BlocksTotal.WithLabelValues(metrics.UnknownLabel, metrics.UnknownLabel, metrics.ResultRejected).Inc()
		writeErr(w, http.StatusBadRequest, "malformed protobuf Block")
		return
	}

	algo, network := algoString(block.GetAlgo()), networkString(block.GetNetwork())

	if err := validateBlock(block); err != nil {
		h.m.BlocksTotal.WithLabelValues(algo, network, metrics.ResultRejected).Inc()
		if errors.Is(err, errEmptyBlockHash) {
			// Distinct, clearly-named metric for THIS specific
			// failure mode (PROD_HARDENING_REVIEW.md finding #13) --
			// see errEmptyBlockHash's doc comment for why an empty
			// hash is worth its own counter separate from the
			// generic blocks_total{result="rejected"} bucket above.
			h.m.BlocksRejectedEmptyHashTotal.WithLabelValues(algo, network).Inc()
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkNetwork(block.GetNetwork()); err != nil {
		h.m.BlocksTotal.WithLabelValues(algo, network, metrics.ResultRejected).Inc()
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	record := blockToRecord(block)
	start := time.Now()
	err = h.repo.InsertBlock(r.Context(), record)
	h.m.BlockInsertDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		h.m.BlocksTotal.WithLabelValues(algo, network, metrics.ResultError).Inc()
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}

	h.m.BlocksTotal.WithLabelValues(algo, network, metrics.ResultAccepted).Inc()
	w.WriteHeader(http.StatusCreated)
}

// checkNetwork enforces that a submitted Share/Block's Network exactly
// matches this backend's own configured network (h.cfg.Network). This
// is deliberately a hard rejection, not a warning: silently accepting a
// mismatched network is exactly how a testnet leaf ends up contaminating
// a mainnet backend's data (or vice versa).
//
// If the backend itself has no configured network (h.cfg.Network ==
// NETWORK_UNSPECIFIED), this check is skipped — mirrors the auth
// header's "not configured means not enforced" pattern, and lets
// callers/tests that don't care about network enforcement omit it.
// Production wiring (cmd/backend) always sets this field and fails
// fast at startup if it cannot, so this escape hatch does not apply
// there.
func (h *Handler) checkNetwork(got poolpb.Network) error {
	if h.cfg.Network == poolpb.Network_NETWORK_UNSPECIFIED {
		return nil
	}
	if got != h.cfg.Network {
		return fmt.Errorf("network mismatch: backend configured for %s, share/block submitted for %s",
			h.cfg.Network, got)
	}
	return nil
}

func readBody(r *http.Request) ([]byte, error) {
	limited := io.LimitReader(r.Body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBodyBytes {
		return nil, errors.New("body too large")
	}
	return data, nil
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// validateShare checks the fields that genuinely matter for a share to
// be actionable: an explicit (non-unspecified) algo, a non-empty
// payment address, and a non-negative block height. Deliberately not
// exhaustive — this is not a full schema validator, just enough to
// reject obviously-broken submissions before they hit the DB.
// maxMinerStringLen caps every miner-supplied, address/worker-name-
// shaped string field validateShare/validateBlock accept before it is
// persisted to a `TEXT` column with no length constraint of its own
// (see migrations/0001_initial_schema.up.sql's shares/blocks
// columns). 256 bytes is a generous ceiling for anything actually
// shaped like a real Monero/Tari address, payment ID, or worker/rig
// identifier -- the longest real address this codebase validates
// anywhere (see internal/backend/addressmap) is well under 128
// bytes -- while still being far short of the 1 MiB overall
// request-body cap (maxBodyBytes) that was previously the ONLY bound
// on any individual field's length. PROD_HARDENING_REVIEW.md finding
// #17.
const maxMinerStringLen = 256

// errEmptyBlockHash is validateBlock's sentinel for the specific
// "hash is required" rejection reason -- kept distinct from a plain
// errors.New so handleBlock can recognize it via errors.Is and bump
// blocks_rejected_empty_hash_total (PROD_HARDENING_REVIEW.md finding
// #13) in addition to the generic blocks_total{result="rejected"}
// counter every other validateBlock failure also increments. This is
// the backend-side half of that finding: internal/leaflib/direct's
// realBlockHashHex can return "" when every accepting node reports an
// empty SubmitBlockResponse.block_hash, which flows through as
// Hash: "" and is rejected here -- previously with only a generic
// log line, silently dropping that block's accounting. The leaf-side
// fix (making that empty case louder at the source) is out of scope
// for this change.
var errEmptyBlockHash = errors.New("block: hash is required")

// validateShare checks the fields that genuinely matter for a share to
// be actionable: an explicit (non-unspecified) algo, a non-empty
// payment address, and a non-negative block height. Deliberately not
// exhaustive — this is not a full schema validator, just enough to
// reject obviously-broken submissions before they hit the DB.
func validateShare(s *poolpb.Share) error {
	if s.GetAlgo() == poolpb.Algo_ALGO_UNSPECIFIED {
		return errors.New("share: algo is required")
	}
	if s.GetNetwork() == poolpb.Network_NETWORK_UNSPECIFIED {
		return errors.New("share: network is required")
	}
	if s.GetPoolType() == poolpb.PoolType_POOL_TYPE_UNSPECIFIED {
		return errors.New("share: pool_type is required")
	}
	if s.GetPaymentAddress() == "" {
		return errors.New("share: payment_address is required")
	}
	if len(s.GetPaymentAddress()) > maxMinerStringLen {
		return fmt.Errorf("share: payment_address exceeds %d bytes", maxMinerStringLen)
	}
	if s.PaymentId != nil && len(s.GetPaymentId()) > maxMinerStringLen {
		return fmt.Errorf("share: payment_id exceeds %d bytes", maxMinerStringLen)
	}
	if len(s.GetIdentifier()) > maxMinerStringLen {
		return fmt.Errorf("share: identifier exceeds %d bytes", maxMinerStringLen)
	}
	if s.GetBlockHeight() < 0 {
		return errors.New("share: block_height must be non-negative")
	}
	return nil
}

// validateBlock mirrors validateShare's genuinely-required-fields
// judgment call for Block.
func validateBlock(b *poolpb.Block) error {
	if b.GetAlgo() == poolpb.Algo_ALGO_UNSPECIFIED {
		return errors.New("block: algo is required")
	}
	if b.GetNetwork() == poolpb.Network_NETWORK_UNSPECIFIED {
		return errors.New("block: network is required")
	}
	if b.GetPoolType() == poolpb.PoolType_POOL_TYPE_UNSPECIFIED {
		return errors.New("block: pool_type is required")
	}
	if b.GetHash() == "" {
		return errEmptyBlockHash
	}
	if len(b.GetHash()) > maxMinerStringLen {
		return fmt.Errorf("block: hash exceeds %d bytes", maxMinerStringLen)
	}
	if b.GetHeight() < 0 {
		return errors.New("block: height must be non-negative")
	}
	return nil
}

// algoString/networkString/poolTypeString map the proto enums to the
// short string codes used as Postgres partition keys (see
// internal/backend/db.ValidAlgos/ValidPoolTypes). These must stay in
// sync with that package's fixed value sets. algoString's default
// case additionally consults internal/coinprofile.ByAlgo for every
// standalone monerod-family coin algo (ALGO_XMR and below) added via
// internal/coinprofile.Registry, rather than returning "" for them --
// without this, real leaf-direct ingestion for any new coin would
// silently label every one of its shares/blocks with an empty algo
// string and fail db.ValidateAlgo downstream (share/block rejected,
// not corrupted, but that new coin's whole ingestion path would be
// completely broken).
func algoString(a poolpb.Algo) string {
	switch a {
	case poolpb.Algo_ALGO_RXT:
		return "RXT"
	case poolpb.Algo_ALGO_C29:
		return "C29"
	case poolpb.Algo_ALGO_SHA3X:
		return "SHA3X"
	case poolpb.Algo_ALGO_RXM:
		return "RXM"
	default:
		if profile, ok := coinprofile.ByAlgo(a); ok {
			return profile.Ticker
		}
		return ""
	}
}

func networkString(n poolpb.Network) string {
	switch n {
	case poolpb.Network_NETWORK_MAINNET:
		return "MAINNET"
	case poolpb.Network_NETWORK_TESTNET:
		return "TESTNET"
	default:
		return ""
	}
}

func poolTypeString(p poolpb.PoolType) string {
	switch p {
	case poolpb.PoolType_POOL_TYPE_PPLNS:
		return "PPLNS"
	case poolpb.PoolType_POOL_TYPE_PPS:
		return "PPS"
	case poolpb.PoolType_POOL_TYPE_PROP:
		return "PROP"
	case poolpb.PoolType_POOL_TYPE_SOLO:
		return "SOLO"
	default:
		return ""
	}
}

func shareToRecord(s *poolpb.Share) ShareRecord {
	var paymentID *string
	if s.PaymentId != nil {
		paymentID = s.PaymentId
	}
	return ShareRecord{
		Algo:           algoString(s.GetAlgo()),
		Network:        networkString(s.GetNetwork()),
		PoolType:       poolTypeString(s.GetPoolType()),
		PoolID:         s.GetPoolId(),
		BlockHeight:    s.GetBlockHeight(),
		Shares:         s.GetShares(),
		PaymentAddress: s.GetPaymentAddress(),
		PaymentID:      paymentID,
		FoundBlock:     s.GetFoundBlock(),
		BlockDiff:      s.GetBlockDiff(),
		Timestamp:      s.GetTimestamp(),
		Identifier:     s.GetIdentifier(),
		TrustedShare:   s.GetTrustedShare(),
	}
}

func blockToRecord(b *poolpb.Block) BlockRecord {
	var value *int64
	if b.Value != nil {
		value = b.Value
	}
	var mergeMineChain *string
	if b.MergeMineChain != nil {
		mergeMineChain = b.MergeMineChain
	}
	return BlockRecord{
		Algo:           algoString(b.GetAlgo()),
		Network:        networkString(b.GetNetwork()),
		PoolType:       poolTypeString(b.GetPoolType()),
		Hash:           b.GetHash(),
		Height:         b.GetHeight(),
		Difficulty:     b.GetDifficulty(),
		Shares:         b.GetShares(),
		Timestamp:      b.GetTimestamp(),
		Unlocked:       b.GetUnlocked(),
		Valid:          b.GetValid(),
		Value:          value,
		PoolID:         b.GetPoolId(),
		MergeMineChain: mergeMineChain,
	}
}
