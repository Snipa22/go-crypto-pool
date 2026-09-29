// Package statsapi implements the backend's read-only, miner-facing
// HTTP stats API: GET endpoints a miner (or their dashboard/monitoring
// script) can hit with their own payment address to see their pending/
// paid balance and a recent hashrate estimate, without needing DB
// access or any authentication. This is deliberately a SEPARATE
// package/Handler from internal/backend/api — that package's Mux is
// the trust-boundary share/block INGESTION surface (leaf -> backend,
// protobuf, optionally shared-secret-authed); this one is a public-ish
// READ surface (miner -> backend, JSON, unauthenticated by design,
// keyed only by information the miner already has: their own payment
// address). Keeping them separate means a bug in one query path can
// never touch the other's write path, and either can be
// disabled/rate-limited independently by whoever fronts this backend
// with a reverse proxy.
//
// Endpoints:
//
//   - GET /api/v1/stats/balance?payment_address=<addr>[&algo=<ALGO>]
//     [&network=<NETWORK>][&payment_id=<id>]
//     Returns every `balance` row (pending_balance/paid_balance) for
//     that payment address, optionally narrowed by algo/network/
//     payment_id. algo/network are optional filters here (a miner may
//     mine more than one algo/coin with the same address across a
//     multi-coin pool operator's backends).
//
//   - GET /api/v1/stats/hashrate?payment_address=<addr>&algo=<ALGO>
//     [&network=<NETWORK>][&payment_id=<id>][&window=<seconds>]
//     Returns a difficulty/elapsed-time hashrate estimate (see
//     EstimateHashrateHS's doc comment) computed from the real
//     `shares` rows accepted for that address in the trailing window
//     (default DefaultWindowSeconds). algo is REQUIRED here (shares
//     is list-partitioned by algo — an unscoped cross-algo sum would
//     be physically meaningless as a single hashrate figure, since
//     different algos' difficulty units aren't comparable).
//
//   - GET /api/v1/stats/hashrate/workers?payment_address=<addr>&algo=<ALGO>
//     [&network=<NETWORK>][&payment_id=<id>][&window=<seconds>]
//     Same computation as /hashrate, but broken out per worker/rig
//     identifier instead of summed across all of an address's workers.
//
//   - GET /api/v1/stats/hashrate/sources?payment_address=<addr>&algo=<ALGO>
//     [&network=<NETWORK>][&payment_id=<id>][&window=<seconds>]
//     Same computation as /hashrate, but broken out per pool_id (the
//     static, operator-assigned pool-server-source identifier every
//     leaf-direct process stamps on its own shares) instead of summed
//     across all sources — lets an operator running more than one
//     leaf-direct process against this backend see hashrate/share
//     volume attributed per physical pool-server instance.
//
//   - GET /api/v1/stats/hashrate/history?payment_address=<addr>&algo=<ALGO>
//     [&network=<NETWORK>][&payment_id=<id>][&worker=<identifier>]
//     [&window_hours=<hours>]
//     Returns the real, bounded time series of periodic hashrate
//     samples cmd/backend's hash-history poller has recorded for this
//     miner (see internal/backend/db/hashhistory.go) — worker-level
//     if `worker` is set, miner-level (summed across every worker
//     that address had active at each sample point) otherwise.
//     window_hours defaults to DefaultHashHistoryWindowHours and is
//     capped at whatever retention window this backend's poller is
//     actually configured to keep (Config.HashHistoryRetention) —
//     a caller can never be told there is more history than is truly
//     retained, but an empty/short-retention deployment simply
//     returns fewer samples, never an error.
//
//   - GET /api/v1/stats/pool/history?algo=<ALGO>[&network=<NETWORK>]
//     [&pool_type=<SOLO|PPS|PPLNS|PROP>][&window_hours=<hours>]
//     Pool-wide (not scoped to any one miner) hashrate history for
//     one of legacy's 5 buckets — pool_type omitted defaults to the
//     GLOBAL pseudo-bucket (the whole pool, every pool_type
//     combined).
//
//   - GET /api/v1/stats/network/history?algo=<ALGO>[&network=<NETWORK>]
//     [&window_hours=<hours>]
//     The real chain's own difficulty history, as periodically
//     snapshotted from network_state by the same hash-history poller
//     (see internal/backend/db.CurrentNetworkDifficulty) — distinct
//     from every hashrate endpoint above exactly the way
//     internal/backend/db/network.go's NetworkStats.NetworkDifficulty
//     is distinct from its own SharesSum-derived figures.
//
// network is optional on every endpoint above ONLY when this Handler
// was constructed with a configured Config.Network (poolpb.Network,
// mirroring api.Config.Network's role) — in that case an omitted
// network query param defaults to the backend's own configured
// network, and an explicitly-provided one that does NOT match it is
// rejected with 400 (the same cross-network-contamination guard
// api.Handler.checkNetwork already applies on the write side, mirrored
// here on the read side). If Config.Network is left unspecified
// (NETWORK_UNSPECIFIED, e.g. in tests), network becomes a required
// query parameter on /hashrate and /hashrate/workers (balance's
// network filter stays optional either way, since it is genuinely
// just a narrowing filter there, not a physical requirement the way
// it is for a single-algo hashrate sum).
package statsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// DefaultWindowSeconds is the hashrate lookback window used when a
// request omits the optional window query parameter. 600s (10
// minutes) mirrors a common pool-stats convention (long enough to
// smooth over variance between individual share submissions, short
// enough to reflect a miner's rig config change within one dashboard
// refresh).
const DefaultWindowSeconds = 600

// MaxWindowSeconds bounds how large a window a caller may request,
// protecting the shares table from an unbounded full-table aggregate
// scan triggered by a single crafted query string.
const MaxWindowSeconds = 7 * 24 * 3600 // 7 days

// DefaultHashHistoryWindowHours is the lookback window, in hours,
// used by /hashrate/history, /pool/history, and /network/history when
// a request omits the optional window_hours query parameter.
const DefaultHashHistoryWindowHours = 1

// globalPoolType is /pool/history's default pool_type value —
// mirrors db.HashHistoryGlobalPoolType's exact string, duplicated
// here (rather than importing internal/backend/db) for the same
// dependency-direction reason validateAlgoParam duplicates
// db.ValidateAlgo's fixed value set instead of importing that
// package directly — see this package's doc comment.
const globalPoolType = "GLOBAL"

// BalanceRecord mirrors db.Balance field-for-field (see that package's
// doc comment on Balance) — kept as this package's own type for the
// same dependency-direction reason api.ShareRecord/BlockRecord mirror
// db.Share/db.Block instead of importing internal/backend/db directly.
type BalanceRecord struct {
	Algo           string
	Network        string
	PaymentAddress string
	PaymentID      *string
	PendingBalance int64
	PaidBalance    int64
	UpdatedAt      time.Time
}

// ShareStatsRecord mirrors db.ShareStats.
type ShareStatsRecord struct {
	SharesSum  int64
	ShareCount int64
}

// WorkerShareStatsRecord mirrors db.WorkerShareStats.
type WorkerShareStatsRecord struct {
	Identifier string
	SharesSum  int64
	ShareCount int64
}

// WorkerShareStatsOtherRecord mirrors db.WorkerShareStatsOther — the
// single collapsed aggregate row representing every identifier
// beyond the cardinality cap db.WorkerShareStatsSince enforces
// server-side. See WorkerShareStatsResultRecord's doc comment.
type WorkerShareStatsOtherRecord struct {
	SharesSum       int64
	ShareCount      int64
	IdentifierCount int
}

// WorkerShareStatsResultRecord mirrors db.WorkerShareStatsResult:
// Rows is the capped set of top-ranked identifiers; Other, if
// non-nil, is the single aggregate row for every identifier beyond
// that cap (nil means nothing was collapsed).
type WorkerShareStatsResultRecord struct {
	Rows  []WorkerShareStatsRecord
	Other *WorkerShareStatsOtherRecord
}

// PoolSourceShareStatsRecord mirrors db.PoolSourceShareStats.
type PoolSourceShareStatsRecord struct {
	PoolID     int32
	SharesSum  int64
	ShareCount int64
}

// PoolSourceShareStatsOtherRecord mirrors db.PoolSourceShareStatsOther
// — see WorkerShareStatsOtherRecord's doc comment.
type PoolSourceShareStatsOtherRecord struct {
	SharesSum   int64
	ShareCount  int64
	PoolIDCount int
}

// PoolSourceShareStatsResultRecord mirrors db.PoolSourceShareStatsResult
// — see WorkerShareStatsResultRecord's doc comment.
type PoolSourceShareStatsResultRecord struct {
	Rows  []PoolSourceShareStatsRecord
	Other *PoolSourceShareStatsOtherRecord
}

// HashSampleRecord mirrors db.HashSample — one hash-history sample's
// (hashrate, sample_time) pair, backing /hashrate/history and
// /pool/history.
type HashSampleRecord struct {
	HashrateHS float64
	SampleTime time.Time
}

// DifficultySampleRecord mirrors db.DifficultySample — one
// hash-history sample's (difficulty, sample_time) pair, backing
// /network/history.
type DifficultySampleRecord struct {
	Difficulty float64
	SampleTime time.Time
}

// Repository is the narrow, read-only persistence surface this
// package's handlers depend on. *db.Repository satisfies this as-is
// (see internal/backend/db/stats.go); tests inject a fake.
type Repository interface {
	MinerBalances(ctx context.Context, paymentAddress, algo, network string, paymentID *string) ([]BalanceRecord, error)
	ShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (ShareStatsRecord, error)
	WorkerShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (WorkerShareStatsResultRecord, error)
	PoolSourceShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (PoolSourceShareStatsResultRecord, error)

	// PoolTypeHashHistory/MinerHashHistory/NetworkDifficultyHistory
	// mirror db.Repository's own methods of the same name (see
	// internal/backend/db/hashhistory.go) — the read-side surface
	// backing handleHashrateHistory/handlePoolHistory/
	// handleNetworkHistory.
	PoolTypeHashHistory(ctx context.Context, algo, network, poolType string, sinceUnix int64) ([]HashSampleRecord, error)
	MinerHashHistory(ctx context.Context, algo, network, paymentAddress string, paymentID *string, worker *string, sinceUnix int64) ([]HashSampleRecord, error)
	NetworkDifficultyHistory(ctx context.Context, algo, network string, sinceUnix int64) ([]DifficultySampleRecord, error)
}

// StatsMetrics is the narrow metrics surface this package's handlers
// increment/observe. A small interface (rather than a direct
// *metrics.Metrics dependency) so this package doesn't force every
// caller/test to construct a full Metrics instance just to exercise a
// handler. *metrics.Metrics satisfies this via the fields added in
// internal/backend/metrics/metrics.go.
type StatsMetrics interface {
	ObserveRequest(endpoint, result string, duration time.Duration)
}

// noopMetrics is used when a Handler is constructed with a nil
// StatsMetrics (mirrors api.Handler's "metrics optional, private
// default" story, minus needing a real prometheus registry for a
// package that has no metrics.Metrics dependency of its own).
type noopMetrics struct{}

func (noopMetrics) ObserveRequest(string, string, time.Duration) {}

// Config configures a Handler.
type Config struct {
	// Network, if set to something other than NETWORK_UNSPECIFIED,
	// is this backend's own configured network. See this package's
	// doc comment for exactly how it changes the network query
	// parameter's required/optional/validated status on each
	// endpoint.
	Network poolpb.Network

	// Metrics, if non-nil, receives ObserveRequest calls for every
	// handled request. If nil, a no-op implementation is used.
	Metrics StatsMetrics

	// HashHistoryRetention, if > 0, is the real retention window
	// cmd/backend's hash-history poller is configured to keep (see
	// that poller's own maxPoints*pollInterval computation) — every
	// /hashrate/history, /pool/history, and /network/history request's
	// window_hours parameter is capped at this value's duration in
	// hours (see parseWindowHours), so a caller can never be told
	// there is more history retained than actually is. Zero (the
	// default) means "no known cap" — a caller-requested window_hours
	// is honored as-is (still bounded by there simply being no older
	// rows to return, since PruneHashHistory will have already
	// deleted them either way; this field only changes what a caller
	// is TOLD they may ask for, not the real data availability).
	HashHistoryRetention time.Duration
}

// Handler implements the backend's read-only miner stats endpoints.
type Handler struct {
	repo Repository
	cfg  Config
	m    StatsMetrics
}

// NewHandler constructs a Handler backed by repo, using cfg for
// optional network-scoping/metrics configuration.
func NewHandler(repo Repository, cfg Config) *Handler {
	m := cfg.Metrics
	if m == nil {
		m = noopMetrics{}
	}
	return &Handler{repo: repo, cfg: cfg, m: m}
}

// Mux builds a fresh *http.ServeMux with this Handler's routes
// registered. Most callers embedding this Handler alongside others
// (e.g. cmd/backend, which also serves internal/backend/api's
// ingestion routes and GET /metrics on the same listener) should use
// RegisterRoutes against a shared mux instead — this exists mainly for
// this package's own tests and any caller that genuinely wants this
// Handler as a stand-alone server.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// RegisterRoutes registers this Handler's routes onto mux. Safe to
// call on a mux that already has other, disjoint routes registered
// (e.g. internal/backend/api.Handler's ingestion routes) — this
// package never registers anything under /api/v1/share, /api/v1/block,
// or /metrics.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/stats/balance", h.handleBalance)
	mux.HandleFunc("GET /api/v1/stats/hashrate", h.handleHashrate)
	mux.HandleFunc("GET /api/v1/stats/hashrate/workers", h.handleHashrateWorkers)
	mux.HandleFunc("GET /api/v1/stats/hashrate/sources", h.handleHashrateSources)
	mux.HandleFunc("GET /api/v1/stats/hashrate/history", h.handleHashrateHistory)
	mux.HandleFunc("GET /api/v1/stats/pool/history", h.handlePoolHistory)
	mux.HandleFunc("GET /api/v1/stats/network/history", h.handleNetworkHistory)
}

// EstimateHashrateHS applies the standard difficulty/elapsed-time
// hashrate approximation to a difficulty-weighted share sum (see
// db.ShareStats.SharesSum's doc comment for why the `shares` column IS
// that difficulty-weighted sum) over a window of the given length:
// sharesSum divided by the window, in seconds. This is the exact same
// formula as internal/leaflib.EstimateHashrateHz, just driven by a
// DB-queried window sum instead of a live in-memory per-session
// accumulator — sharesSum is already a real, direct sum of
// per-accepted-share difficulty values, so no additional
// hashes-per-difficulty-unit multiplier is applied (see that
// function's doc comment and fix history for why an earlier version
// of this formula's `* 2^32` multiplier was wrong: it inflated the
// reported figure by ~4.3 billion x). Returns 0 for a zero/negative
// window or a zero share sum, rather than dividing by (or reporting
// against) a meaningless denominator.
func EstimateHashrateHS(sharesSum int64, windowSeconds int64) float64 {
	if sharesSum <= 0 || windowSeconds <= 0 {
		return 0
	}
	return float64(sharesSum) / float64(windowSeconds)
}

// networkDBString mirrors internal/backend/api's own private
// helper of the same name/purpose — poolpb.Network to this schema's
// exact "MAINNET"/"TESTNET" column string.
func networkDBString(n poolpb.Network) string {
	switch n {
	case poolpb.Network_NETWORK_MAINNET:
		return "MAINNET"
	case poolpb.Network_NETWORK_TESTNET:
		return "TESTNET"
	default:
		return ""
	}
}

// resolveNetwork implements this package's doc-comment-documented
// network-parameter resolution rule: an omitted query value defaults
// to the backend's own configured network (if any); an explicit value
// that mismatches a configured network is rejected; with no configured
// network, requireIfUnconfigured decides whether an omitted value is
// an error (hashrate endpoints, where network is physically load-
// bearing) or simply "no filter" (balance endpoint).
func (h *Handler) resolveNetwork(raw string, requireIfUnconfigured bool) (string, error) {
	configured := networkDBString(h.cfg.Network)
	if raw == "" {
		if configured != "" {
			return configured, nil
		}
		if requireIfUnconfigured {
			return "", errors.New("network is required (this backend has no default configured network)")
		}
		return "", nil
	}
	if configured != "" && raw != configured {
		return "", fmt.Errorf("network mismatch: this backend is configured for %s, request asked for %s", configured, raw)
	}
	return raw, nil
}

// paymentIDParam maps a query parameter's presence/value onto this
// package's payment_id filter convention (see Repository's doc
// comment): the query key must be present at all for filtering to
// apply (mirrors db.MinerBalances/ShareStatsSince's nil-means-any
// convention) — r.URL.Query() distinguishes "key absent" from "key
// present with empty value" via Query().Has, which plain Get cannot.
func paymentIDParam(r *http.Request) *string {
	q := r.URL.Query()
	if !q.Has("payment_id") {
		return nil
	}
	v := q.Get("payment_id")
	return &v
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// parseWindowSeconds parses the optional window query parameter,
// defaulting to DefaultWindowSeconds and rejecting non-positive or
// over-MaxWindowSeconds values.
func parseWindowSeconds(raw string) (int64, error) {
	if raw == "" {
		return DefaultWindowSeconds, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("window: %w", err)
	}
	if v <= 0 {
		return 0, errors.New("window: must be a positive number of seconds")
	}
	if v > MaxWindowSeconds {
		return 0, fmt.Errorf("window: must be <= %d seconds", MaxWindowSeconds)
	}
	return v, nil
}

// balanceResponseRow is the JSON shape one BalanceRecord serializes
// to. A dedicated response type (rather than json-tagging
// BalanceRecord directly) keeps the wire contract stable/intentional
// even if BalanceRecord's own field set changes later.
type balanceResponseRow struct {
	Algo           string  `json:"algo"`
	Network        string  `json:"network"`
	PaymentAddress string  `json:"payment_address"`
	PaymentID      *string `json:"payment_id,omitempty"`
	PendingBalance int64   `json:"pending_balance"`
	PaidBalance    int64   `json:"paid_balance"`
	UpdatedAt      string  `json:"updated_at"`
}

func (h *Handler) handleBalance(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()
	paymentAddress := q.Get("payment_address")
	if paymentAddress == "" {
		h.m.ObserveRequest("balance", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, "payment_address is required")
		return
	}

	algo := q.Get("algo")
	if algo != "" {
		if err := validateAlgoParam(algo); err != nil {
			h.m.ObserveRequest("balance", "rejected", time.Since(start))
			writeJSONErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	network, err := h.resolveNetwork(q.Get("network"), false)
	if err != nil {
		h.m.ObserveRequest("balance", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	rows, err := h.repo.MinerBalances(r.Context(), paymentAddress, algo, network, paymentIDParam(r))
	if err != nil {
		h.m.ObserveRequest("balance", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]balanceResponseRow, 0, len(rows))
	for _, b := range rows {
		out = append(out, balanceResponseRow{
			Algo:           b.Algo,
			Network:        b.Network,
			PaymentAddress: b.PaymentAddress,
			PaymentID:      b.PaymentID,
			PendingBalance: b.PendingBalance,
			PaidBalance:    b.PaidBalance,
			UpdatedAt:      b.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}

	h.m.ObserveRequest("balance", "ok", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{
		"payment_address": paymentAddress,
		"balances":        out,
	})
}

// hashrateResponse is the JSON shape /api/v1/stats/hashrate returns.
type hashrateResponse struct {
	Algo                string  `json:"algo"`
	Network             string  `json:"network"`
	PaymentAddress      string  `json:"payment_address"`
	PaymentID           *string `json:"payment_id,omitempty"`
	WindowSeconds       int64   `json:"window_seconds"`
	ShareCount          int64   `json:"share_count"`
	SharesSum           int64   `json:"shares_sum"`
	EstimatedHashrateHS float64 `json:"estimated_hashrate_hs"`
}

// parseHashrateQuery reads/validates the query parameters common to
// both /hashrate and /hashrate/workers, resolving network per
// resolveNetwork(requireIfUnconfigured=true) — see this package's doc
// comment for why network is load-bearing (not just a filter) for any
// single-algo hashrate sum.
func (h *Handler) parseHashrateQuery(r *http.Request) (algo, network, paymentAddress string, paymentID *string, windowSeconds int64, err error) {
	q := r.URL.Query()
	paymentAddress = q.Get("payment_address")
	if paymentAddress == "" {
		return "", "", "", nil, 0, errors.New("payment_address is required")
	}
	algo = q.Get("algo")
	if algo == "" {
		return "", "", "", nil, 0, errors.New("algo is required")
	}
	if err := validateAlgoParam(algo); err != nil {
		return "", "", "", nil, 0, err
	}
	network, err = h.resolveNetwork(q.Get("network"), true)
	if err != nil {
		return "", "", "", nil, 0, err
	}
	windowSeconds, err = parseWindowSeconds(q.Get("window"))
	if err != nil {
		return "", "", "", nil, 0, err
	}
	return algo, network, paymentAddress, paymentIDParam(r), windowSeconds, nil
}

func (h *Handler) handleHashrate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	algo, network, paymentAddress, paymentID, windowSeconds, err := h.parseHashrateQuery(r)
	if err != nil {
		h.m.ObserveRequest("hashrate", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	since := time.Now().Add(-time.Duration(windowSeconds) * time.Second).Unix()
	stats, err := h.repo.ShareStatsSince(r.Context(), algo, network, paymentAddress, paymentID, since)
	if err != nil {
		h.m.ObserveRequest("hashrate", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	h.m.ObserveRequest("hashrate", "ok", time.Since(start))
	writeJSON(w, http.StatusOK, hashrateResponse{
		Algo:                algo,
		Network:             network,
		PaymentAddress:      paymentAddress,
		PaymentID:           paymentID,
		WindowSeconds:       windowSeconds,
		ShareCount:          stats.ShareCount,
		SharesSum:           stats.SharesSum,
		EstimatedHashrateHS: EstimateHashrateHS(stats.SharesSum, windowSeconds),
	})
}

// workerHashrateRow is one worker/identifier's entry in
// /api/v1/stats/hashrate/workers' response.
type workerHashrateRow struct {
	Identifier          string  `json:"identifier"`
	ShareCount          int64   `json:"share_count"`
	SharesSum           int64   `json:"shares_sum"`
	EstimatedHashrateHS float64 `json:"estimated_hashrate_hs"`
}

// otherWorkersBucket is /api/v1/stats/hashrate/workers' optional
// "other" field: present only when the true distinct-identifier
// count for this query exceeded db.DefaultShareStatsCardinalityCap,
// representing every identifier beyond the "workers" array's own
// (still individually-named, cap-bounded) entries. IsOther is a
// belt-and-suspenders explicit marker for clients that deserialize
// this generically; the field's mere presence in the response is
// already unambiguous against a real identifier literally named
// "other" -- that case only ever appears as its own entry inside the
// "workers" array, never inside this dedicated field.
type otherWorkersBucket struct {
	IsOther             bool    `json:"is_other"`
	IdentifierCount     int     `json:"identifier_count"`
	ShareCount          int64   `json:"share_count"`
	SharesSum           int64   `json:"shares_sum"`
	EstimatedHashrateHS float64 `json:"estimated_hashrate_hs"`
}

func (h *Handler) handleHashrateWorkers(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	algo, network, paymentAddress, paymentID, windowSeconds, err := h.parseHashrateQuery(r)
	if err != nil {
		h.m.ObserveRequest("hashrate_workers", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	since := time.Now().Add(-time.Duration(windowSeconds) * time.Second).Unix()
	result, err := h.repo.WorkerShareStatsSince(r.Context(), algo, network, paymentAddress, paymentID, since)
	if err != nil {
		h.m.ObserveRequest("hashrate_workers", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]workerHashrateRow, 0, len(result.Rows))
	for _, wr := range result.Rows {
		out = append(out, workerHashrateRow{
			Identifier:          wr.Identifier,
			ShareCount:          wr.ShareCount,
			SharesSum:           wr.SharesSum,
			EstimatedHashrateHS: EstimateHashrateHS(wr.SharesSum, windowSeconds),
		})
	}

	h.m.ObserveRequest("hashrate_workers", "ok", time.Since(start))
	resp := map[string]any{
		"algo":            algo,
		"network":         network,
		"payment_address": paymentAddress,
		"payment_id":      paymentID,
		"window_seconds":  windowSeconds,
		"workers":         out,
	}
	if result.Other != nil {
		resp["other"] = otherWorkersBucket{
			IsOther:             true,
			IdentifierCount:     result.Other.IdentifierCount,
			ShareCount:          result.Other.ShareCount,
			SharesSum:           result.Other.SharesSum,
			EstimatedHashrateHS: EstimateHashrateHS(result.Other.SharesSum, windowSeconds),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// poolSourceHashrateRow is one pool-server-source's entry in
// /api/v1/stats/hashrate/sources' response.
type poolSourceHashrateRow struct {
	PoolID              int32   `json:"pool_id"`
	ShareCount          int64   `json:"share_count"`
	SharesSum           int64   `json:"shares_sum"`
	EstimatedHashrateHS float64 `json:"estimated_hashrate_hs"`
}

// otherSourcesBucket is /api/v1/stats/hashrate/sources' optional
// "other" field -- otherWorkersBucket's pool_id analogue, see that
// type's doc comment.
type otherSourcesBucket struct {
	IsOther             bool    `json:"is_other"`
	PoolIDCount         int     `json:"pool_id_count"`
	ShareCount          int64   `json:"share_count"`
	SharesSum           int64   `json:"shares_sum"`
	EstimatedHashrateHS float64 `json:"estimated_hashrate_hs"`
}

// handleHashrateSources implements GET /api/v1/stats/hashrate/sources
// — the pool_id-broken-out analogue of handleHashrateWorkers (see
// PoolSourceShareStatsRecord's doc comment for what pool_id means and
// why this is the endpoint that makes it useful).
func (h *Handler) handleHashrateSources(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	algo, network, paymentAddress, paymentID, windowSeconds, err := h.parseHashrateQuery(r)
	if err != nil {
		h.m.ObserveRequest("hashrate_sources", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	since := time.Now().Add(-time.Duration(windowSeconds) * time.Second).Unix()
	result, err := h.repo.PoolSourceShareStatsSince(r.Context(), algo, network, paymentAddress, paymentID, since)
	if err != nil {
		h.m.ObserveRequest("hashrate_sources", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]poolSourceHashrateRow, 0, len(result.Rows))
	for _, sr := range result.Rows {
		out = append(out, poolSourceHashrateRow{
			PoolID:              sr.PoolID,
			ShareCount:          sr.ShareCount,
			SharesSum:           sr.SharesSum,
			EstimatedHashrateHS: EstimateHashrateHS(sr.SharesSum, windowSeconds),
		})
	}

	h.m.ObserveRequest("hashrate_sources", "ok", time.Since(start))
	resp := map[string]any{
		"algo":            algo,
		"network":         network,
		"payment_address": paymentAddress,
		"payment_id":      paymentID,
		"window_seconds":  windowSeconds,
		"sources":         out,
	}
	if result.Other != nil {
		resp["other"] = otherSourcesBucket{
			IsOther:             true,
			PoolIDCount:         result.Other.PoolIDCount,
			ShareCount:          result.Other.ShareCount,
			SharesSum:           result.Other.SharesSum,
			EstimatedHashrateHS: EstimateHashrateHS(result.Other.SharesSum, windowSeconds),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseWindowHours parses the optional window_hours query parameter,
// defaulting to DefaultHashHistoryWindowHours and rejecting a
// non-positive or unparseable value, then clamps the result down to
// h.cfg.HashHistoryRetention's own duration in hours when that field
// is configured (> 0) and the requested value exceeds it — see
// Config.HashHistoryRetention's doc comment: a caller is never told
// there is more history retained than actually is, but an
// over-large request is silently clamped (returns what's available),
// never rejected with an error.
func (h *Handler) parseWindowHours(raw string) (float64, error) {
	hours := float64(DefaultHashHistoryWindowHours)
	if raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return 0, fmt.Errorf("window_hours: %w", err)
		}
		if v <= 0 {
			return 0, errors.New("window_hours: must be a positive number of hours")
		}
		hours = v
	}
	if h.cfg.HashHistoryRetention > 0 {
		if maxHours := h.cfg.HashHistoryRetention.Hours(); hours > maxHours {
			hours = maxHours
		}
	}
	return hours, nil
}

// hashHistorySampleRow is one hash-history sample's JSON shape,
// shared by /hashrate/history and /pool/history.
type hashHistorySampleRow struct {
	HashrateHS float64 `json:"hashrate_hs"`
	SampleTime string  `json:"sample_time"`
}

// difficultyHistorySampleRow is one network-difficulty sample's JSON
// shape, used by /network/history.
type difficultyHistorySampleRow struct {
	Difficulty float64 `json:"difficulty"`
	SampleTime string  `json:"sample_time"`
}

// handleHashrateHistory implements GET /api/v1/stats/hashrate/history
// — see this package's doc comment for the full query-parameter/
// response-shape contract.
func (h *Handler) handleHashrateHistory(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()

	paymentAddress := q.Get("payment_address")
	if paymentAddress == "" {
		h.m.ObserveRequest("hashrate_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, "payment_address is required")
		return
	}
	algo := q.Get("algo")
	if algo == "" {
		h.m.ObserveRequest("hashrate_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, "algo is required")
		return
	}
	if err := validateAlgoParam(algo); err != nil {
		h.m.ObserveRequest("hashrate_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	network, err := h.resolveNetwork(q.Get("network"), true)
	if err != nil {
		h.m.ObserveRequest("hashrate_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	windowHours, err := h.parseWindowHours(q.Get("window_hours"))
	if err != nil {
		h.m.ObserveRequest("hashrate_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var worker *string
	if q.Has("worker") {
		v := q.Get("worker")
		worker = &v
	}
	paymentID := paymentIDParam(r)

	since := time.Now().Add(-time.Duration(windowHours * float64(time.Hour))).Unix()
	samples, err := h.repo.MinerHashHistory(r.Context(), algo, network, paymentAddress, paymentID, worker, since)
	if err != nil {
		h.m.ObserveRequest("hashrate_history", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]hashHistorySampleRow, 0, len(samples))
	for _, s := range samples {
		out = append(out, hashHistorySampleRow{HashrateHS: s.HashrateHS, SampleTime: s.SampleTime.UTC().Format(time.RFC3339)})
	}

	h.m.ObserveRequest("hashrate_history", "ok", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{
		"algo":            algo,
		"network":         network,
		"payment_address": paymentAddress,
		"payment_id":      paymentID,
		"worker":          worker,
		"window_hours":    windowHours,
		"samples":         out,
	})
}

// validatePoolTypeParam validates poolType against the same fixed
// set as internal/backend/db.ValidPoolTypes plus the globalPoolType
// sentinel -- see globalPoolType's own doc comment for why this is
// duplicated here rather than imported.
func validatePoolTypeParam(poolType string) error {
	switch poolType {
	case "SOLO", "PPS", "PPLNS", "PROP", globalPoolType:
		return nil
	default:
		return fmt.Errorf("pool_type: unknown value %q (want one of SOLO, PPS, PPLNS, PROP, %s)", poolType, globalPoolType)
	}
}

// handlePoolHistory implements GET /api/v1/stats/pool/history — see
// this package's doc comment for the full query-parameter/response-
// shape contract. pool_type is optional; an omitted value defaults to
// globalPoolType (the whole pool, every pool_type combined).
func (h *Handler) handlePoolHistory(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()

	algo := q.Get("algo")
	if algo == "" {
		h.m.ObserveRequest("pool_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, "algo is required")
		return
	}
	if err := validateAlgoParam(algo); err != nil {
		h.m.ObserveRequest("pool_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	network, err := h.resolveNetwork(q.Get("network"), true)
	if err != nil {
		h.m.ObserveRequest("pool_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	poolType := q.Get("pool_type")
	if poolType == "" {
		poolType = globalPoolType
	}
	if err := validatePoolTypeParam(poolType); err != nil {
		h.m.ObserveRequest("pool_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	windowHours, err := h.parseWindowHours(q.Get("window_hours"))
	if err != nil {
		h.m.ObserveRequest("pool_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	since := time.Now().Add(-time.Duration(windowHours * float64(time.Hour))).Unix()
	samples, err := h.repo.PoolTypeHashHistory(r.Context(), algo, network, poolType, since)
	if err != nil {
		h.m.ObserveRequest("pool_history", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]hashHistorySampleRow, 0, len(samples))
	for _, s := range samples {
		out = append(out, hashHistorySampleRow{HashrateHS: s.HashrateHS, SampleTime: s.SampleTime.UTC().Format(time.RFC3339)})
	}

	h.m.ObserveRequest("pool_history", "ok", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{
		"algo":         algo,
		"network":      network,
		"pool_type":    poolType,
		"window_hours": windowHours,
		"samples":      out,
	})
}

// handleNetworkHistory implements GET /api/v1/stats/network/history —
// see this package's doc comment for the full query-parameter/
// response-shape contract.
func (h *Handler) handleNetworkHistory(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := r.URL.Query()

	algo := q.Get("algo")
	if algo == "" {
		h.m.ObserveRequest("network_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, "algo is required")
		return
	}
	if err := validateAlgoParam(algo); err != nil {
		h.m.ObserveRequest("network_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	network, err := h.resolveNetwork(q.Get("network"), true)
	if err != nil {
		h.m.ObserveRequest("network_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	windowHours, err := h.parseWindowHours(q.Get("window_hours"))
	if err != nil {
		h.m.ObserveRequest("network_history", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	since := time.Now().Add(-time.Duration(windowHours * float64(time.Hour))).Unix()
	samples, err := h.repo.NetworkDifficultyHistory(r.Context(), algo, network, since)
	if err != nil {
		h.m.ObserveRequest("network_history", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]difficultyHistorySampleRow, 0, len(samples))
	for _, s := range samples {
		out = append(out, difficultyHistorySampleRow{Difficulty: s.Difficulty, SampleTime: s.SampleTime.UTC().Format(time.RFC3339)})
	}

	h.m.ObserveRequest("network_history", "ok", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{
		"algo":         algo,
		"network":      network,
		"window_hours": windowHours,
		"samples":      out,
	})
}

// validateAlgoParam mirrors internal/backend/db.ValidateAlgo without
// importing that package directly (see Repository's doc comment on
// this package's dependency-direction discipline) — kept as its own
// small fixed set here since it needs to stay in sync with the same
// enum either way, and the alternative (importing internal/backend/db
// just for this one validator) would reintroduce exactly the coupling
// the Repository interface exists to avoid.
func validateAlgoParam(algo string) error {
	switch algo {
	case "RXT", "C29", "SHA3X", "RXM":
		return nil
	default:
		return fmt.Errorf("algo: unknown value %q (want one of RXT, C29, SHA3X, RXM)", algo)
	}
}
