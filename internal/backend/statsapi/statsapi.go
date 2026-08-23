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
//     Returns a difficulty*2^32/elapsed-time hashrate estimate (see
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

// hashesPerDifficultyUnit mirrors internal/leaflib.EstimateHashrateHz's
// exact constant/convention (2^32 hash attempts per expected accepted
// share at difficulty 1) so a miner sees the same hashrate figure
// whether it's read off a leaf's live per-session stats page or this
// backend's DB-query-based endpoint. Kept as an independent constant
// (rather than importing internal/leaflib, which is the miner-facing
// ingestion side's own package tree) to keep this package's
// dependency graph pointed only at internal/backend/*, matching every
// other backend subpackage's import discipline.
const hashesPerDifficultyUnit = 4294967296 // 2^32

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

// PoolSourceShareStatsRecord mirrors db.PoolSourceShareStats.
type PoolSourceShareStatsRecord struct {
	PoolID     int32
	SharesSum  int64
	ShareCount int64
}

// Repository is the narrow, read-only persistence surface this
// package's handlers depend on. *db.Repository satisfies this as-is
// (see internal/backend/db/stats.go); tests inject a fake.
type Repository interface {
	MinerBalances(ctx context.Context, paymentAddress, algo, network string, paymentID *string) ([]BalanceRecord, error)
	ShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (ShareStatsRecord, error)
	WorkerShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]WorkerShareStatsRecord, error)
	PoolSourceShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]PoolSourceShareStatsRecord, error)
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
}

// EstimateHashrateHS applies the standard difficulty*2^32/elapsed-time
// hashrate approximation to a difficulty-weighted share sum (see
// db.ShareStats.SharesSum's doc comment for why the `shares` column IS
// that difficulty-weighted sum) over a window of the given length.
// This is the exact same formula/constant as
// internal/leaflib.EstimateHashrateHz, just driven by a DB-queried
// window sum instead of a live in-memory per-session accumulator — see
// that function's doc comment for the real caveats (an
// industry-standard approximation, not a cryptographically exact hash
// count; genuinely algo-specific real per-attempt cost is not
// modeled). Returns 0 for a zero/negative window or a zero share sum,
// rather than dividing by (or reporting against) a meaningless
// denominator.
func EstimateHashrateHS(sharesSum int64, windowSeconds int64) float64 {
	if sharesSum <= 0 || windowSeconds <= 0 {
		return 0
	}
	return float64(sharesSum) * hashesPerDifficultyUnit / float64(windowSeconds)
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

func (h *Handler) handleHashrateWorkers(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	algo, network, paymentAddress, paymentID, windowSeconds, err := h.parseHashrateQuery(r)
	if err != nil {
		h.m.ObserveRequest("hashrate_workers", "rejected", time.Since(start))
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	since := time.Now().Add(-time.Duration(windowSeconds) * time.Second).Unix()
	rows, err := h.repo.WorkerShareStatsSince(r.Context(), algo, network, paymentAddress, paymentID, since)
	if err != nil {
		h.m.ObserveRequest("hashrate_workers", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]workerHashrateRow, 0, len(rows))
	for _, wr := range rows {
		out = append(out, workerHashrateRow{
			Identifier:          wr.Identifier,
			ShareCount:          wr.ShareCount,
			SharesSum:           wr.SharesSum,
			EstimatedHashrateHS: EstimateHashrateHS(wr.SharesSum, windowSeconds),
		})
	}

	h.m.ObserveRequest("hashrate_workers", "ok", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{
		"algo":            algo,
		"network":         network,
		"payment_address": paymentAddress,
		"payment_id":      paymentID,
		"window_seconds":  windowSeconds,
		"workers":         out,
	})
}

// poolSourceHashrateRow is one pool-server-source's entry in
// /api/v1/stats/hashrate/sources' response.
type poolSourceHashrateRow struct {
	PoolID              int32   `json:"pool_id"`
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
	rows, err := h.repo.PoolSourceShareStatsSince(r.Context(), algo, network, paymentAddress, paymentID, since)
	if err != nil {
		h.m.ObserveRequest("hashrate_sources", "error", time.Since(start))
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]poolSourceHashrateRow, 0, len(rows))
	for _, sr := range rows {
		out = append(out, poolSourceHashrateRow{
			PoolID:              sr.PoolID,
			ShareCount:          sr.ShareCount,
			SharesSum:           sr.SharesSum,
			EstimatedHashrateHS: EstimateHashrateHS(sr.SharesSum, windowSeconds),
		})
	}

	h.m.ObserveRequest("hashrate_sources", "ok", time.Since(start))
	writeJSON(w, http.StatusOK, map[string]any{
		"algo":            algo,
		"network":         network,
		"payment_address": paymentAddress,
		"payment_id":      paymentID,
		"window_seconds":  windowSeconds,
		"sources":         out,
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
