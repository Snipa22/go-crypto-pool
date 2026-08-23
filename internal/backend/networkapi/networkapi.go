// Package networkapi implements the backend's read-only, public
// POOL-WIDE network/topology HTTP API: GET endpoints exposing "what
// pools/ports does this backend run, and how is the pool overall
// doing" -- as opposed to internal/backend/statsapi, which is scoped
// to a single miner's own payment address. Like statsapi, this is a
// deliberately SEPARATE package/Handler from internal/backend/api
// (the leaf -> backend share/block ingestion trust boundary): a bug
// in this read-only aggregate-query path can never touch ingestion,
// and either surface can be deployed/rate-limited independently.
//
// Endpoints:
//
//   - GET /api/v1/network/pools[?algo=<ALGO>][&network=<NETWORK>]
//     Returns every configured `pools` row (each with its `ports`
//     rows), optionally narrowed by algo/network. algo/network are
//     optional filters here for the same reason they are on
//     statsapi's /stats/balance -- a multi-coin pool operator's
//     backend may have pools/ports configured for more than one
//     algo/network.
//
//   - GET /api/v1/network/stats?algo=<ALGO>&network=<NETWORK>[&window=<seconds>]
//     Returns a whole-pool (every miner, not just one payment
//     address) difficulty*2^32/elapsed-time hashrate estimate over
//     the trailing window (see EstimateHashrateHS, mirroring
//     statsapi's exact formula/convention), plus a lifetime blocks-
//     found count and the most recently found block's height/time
//     for that algo/network. algo and network are BOTH required here
//     (see this package's doc comment on why an unscoped cross-algo
//     hashrate sum is physically meaningless, mirroring statsapi's
//     /hashrate endpoint) -- this package does not carry a
//     Config.Network default-scoping story of its own since a public
//     pool-stats page reasonably wants to ask about any one of a
//     multi-network deployment's networks explicitly, not have one
//     silently assumed.
package networkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// hashesPerDifficultyUnit mirrors statsapi's own constant of the same
// name/purpose -- see that package's doc comment for why this is
// duplicated rather than imported (independent package dependency
// graphs, same underlying industry-standard approximation).
const hashesPerDifficultyUnit = 4294967296 // 2^32

// DefaultWindowSeconds/MaxWindowSeconds mirror statsapi's identically
// named constants -- same rationale, kept independent per this
// package's own dependency-graph discipline.
const (
	DefaultWindowSeconds = 600
	MaxWindowSeconds     = 7 * 24 * 3600
)

// PortRecord mirrors db.Port field-for-field.
type PortRecord struct {
	Port            int32
	Description     string
	MinDifficulty   int64
	MaxDifficulty   *int64
	StartDifficulty int64
	VariableDiff    bool
}

// PoolRecord mirrors db.Pool field-for-field (minus the internal
// numeric ID, which is a database implementation detail this public
// surface has no reason to expose).
type PoolRecord struct {
	Algo      string
	Network   string
	PoolType  string
	Name      string
	Enabled   bool
	CreatedAt time.Time
	Ports     []PortRecord
}

// NetworkStatsRecord mirrors db.NetworkStats.
type NetworkStatsRecord struct {
	SharesSum       int64
	ShareCount      int64
	BlocksFound     int64
	LastBlockAt     *time.Time
	LastBlockHeight *int64

	// NetworkHeight/NetworkDifficulty/NetworkEstimatedHashrateHS/
	// NetworkStateUpdatedAt mirror db.NetworkStats' identically named
	// fields -- the REAL, live upstream-chain state a poller
	// (internal/backend/networkpoller) has recorded, independent of
	// SharesSum/ShareCount's pool-local share-derived figures above.
	// All nil together if no poller has ever successfully recorded a
	// snapshot for this (algo, network) -- see handleStats' doc
	// comment on how that renders in the JSON response.
	NetworkHeight              *int64
	NetworkDifficulty          *float64
	NetworkEstimatedHashrateHS *float64
	NetworkStateUpdatedAt      *time.Time
}

// Repository is the narrow, read-only persistence surface this
// package's handlers depend on. *db.Repository satisfies this as-is
// (see internal/backend/db/network.go); tests inject a fake.
type Repository interface {
	ListPools(ctx context.Context, algo, network string) ([]PoolRecord, error)
	NetworkStatsSince(ctx context.Context, algo, network string, sinceUnix int64) (NetworkStatsRecord, error)
}

// Handler implements the backend's read-only pool-network endpoints.
type Handler struct {
	repo Repository
}

// NewHandler constructs a Handler backed by repo.
func NewHandler(repo Repository) *Handler {
	return &Handler{repo: repo}
}

// Mux builds a fresh *http.ServeMux with this Handler's routes
// registered. Most callers should use RegisterRoutes against a
// shared mux instead (see cmd/backend).
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// RegisterRoutes registers this Handler's routes onto mux. Safe to
// call on a mux that already has other, disjoint routes registered
// -- this package never registers anything outside /api/v1/network/.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/network/pools", h.handlePools)
	mux.HandleFunc("GET /api/v1/network/stats", h.handleStats)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

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

// EstimateHashrateHS mirrors statsapi.EstimateHashrateHS exactly --
// see that function's doc comment for the formula/caveats.
func EstimateHashrateHS(sharesSum int64, windowSeconds int64) float64 {
	if sharesSum <= 0 || windowSeconds <= 0 {
		return 0
	}
	return float64(sharesSum) * hashesPerDifficultyUnit / float64(windowSeconds)
}

// portResponseRow is the JSON shape one PortRecord serializes to.
type portResponseRow struct {
	Port            int32  `json:"port"`
	Description     string `json:"description"`
	MinDifficulty   int64  `json:"min_difficulty"`
	MaxDifficulty   *int64 `json:"max_difficulty,omitempty"`
	StartDifficulty int64  `json:"start_difficulty"`
	VariableDiff    bool   `json:"variable_diff"`
}

// poolResponseRow is the JSON shape one PoolRecord serializes to.
type poolResponseRow struct {
	Algo      string            `json:"algo"`
	Network   string            `json:"network"`
	PoolType  string            `json:"pool_type"`
	Name      string            `json:"name"`
	Enabled   bool              `json:"enabled"`
	CreatedAt string            `json:"created_at"`
	Ports     []portResponseRow `json:"ports"`
}

func (h *Handler) handlePools(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo, network := q.Get("algo"), q.Get("network")

	rows, err := h.repo.ListPools(r.Context(), algo, network)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]poolResponseRow, 0, len(rows))
	for _, p := range rows {
		ports := make([]portResponseRow, 0, len(p.Ports))
		for _, pt := range p.Ports {
			ports = append(ports, portResponseRow{
				Port:            pt.Port,
				Description:     pt.Description,
				MinDifficulty:   pt.MinDifficulty,
				MaxDifficulty:   pt.MaxDifficulty,
				StartDifficulty: pt.StartDifficulty,
				VariableDiff:    pt.VariableDiff,
			})
		}
		out = append(out, poolResponseRow{
			Algo:      p.Algo,
			Network:   p.Network,
			PoolType:  p.PoolType,
			Name:      p.Name,
			Enabled:   p.Enabled,
			CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339),
			Ports:     ports,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"pools": out})
}

// statsResponse is the JSON shape /api/v1/network/stats returns.
//
// EstimatedHashrateHS remains this POOL's own local, share-derived
// hashrate estimate (see EstimateHashrateHS) -- unchanged from before
// this field's real-network counterparts below were added, so
// existing consumers of this endpoint are not silently broken. The
// Network* fields are the NEW, separate, REAL chain-wide figures
// (subsystem gap audit items 2+4): what the actual upstream network
// this pool mines against is doing right now, as last observed by
// internal/backend/networkpoller's real, live RPC/GRPC poll loop --
// NOT derived from this backend's own `shares` table at all. All four
// are omitted from the response (rather than rendered as 0/null) when
// no poller has ever successfully recorded a snapshot for this
// (algo, network) -- e.g. neither GCPOOL_TARI_GRPC_ADDR nor
// GCPOOL_MONERO_RPC_ADDR is configured -- so a consumer can reliably
// tell "no real network data available yet" apart from "the real
// network genuinely has 0 hashrate".
type statsResponse struct {
	Algo                string  `json:"algo"`
	Network             string  `json:"network"`
	WindowSeconds       int64   `json:"window_seconds"`
	ShareCount          int64   `json:"share_count"`
	SharesSum           int64   `json:"shares_sum"`
	EstimatedHashrateHS float64 `json:"estimated_hashrate_hs"`
	BlocksFound         int64   `json:"blocks_found"`
	LastBlockHeight     *int64  `json:"last_block_height,omitempty"`
	LastBlockAt         *string `json:"last_block_at,omitempty"`

	NetworkHeight              *int64   `json:"network_height,omitempty"`
	NetworkDifficulty          *float64 `json:"network_difficulty,omitempty"`
	NetworkEstimatedHashrateHS *float64 `json:"network_estimated_hashrate_hs,omitempty"`
	NetworkStateUpdatedAt      *string  `json:"network_state_updated_at,omitempty"`
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := q.Get("algo")
	if algo == "" {
		writeJSONErr(w, http.StatusBadRequest, "algo is required")
		return
	}
	network := q.Get("network")
	if network == "" {
		writeJSONErr(w, http.StatusBadRequest, "network is required")
		return
	}
	windowSeconds, err := parseWindowSeconds(q.Get("window"))
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	since := time.Now().Add(-time.Duration(windowSeconds) * time.Second).Unix()
	stats, err := h.repo.NetworkStatsSince(r.Context(), algo, network, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	var lastBlockAt *string
	if stats.LastBlockAt != nil {
		s := stats.LastBlockAt.UTC().Format(time.RFC3339)
		lastBlockAt = &s
	}

	var networkStateUpdatedAt *string
	if stats.NetworkStateUpdatedAt != nil {
		s := stats.NetworkStateUpdatedAt.UTC().Format(time.RFC3339)
		networkStateUpdatedAt = &s
	}

	writeJSON(w, http.StatusOK, statsResponse{
		Algo:                algo,
		Network:             network,
		WindowSeconds:       windowSeconds,
		ShareCount:          stats.ShareCount,
		SharesSum:           stats.SharesSum,
		EstimatedHashrateHS: EstimateHashrateHS(stats.SharesSum, windowSeconds),
		BlocksFound:         stats.BlocksFound,
		LastBlockHeight:     stats.LastBlockHeight,
		LastBlockAt:         lastBlockAt,

		NetworkHeight:              stats.NetworkHeight,
		NetworkDifficulty:          stats.NetworkDifficulty,
		NetworkEstimatedHashrateHS: stats.NetworkEstimatedHashrateHS,
		NetworkStateUpdatedAt:      networkStateUpdatedAt,
	})
}
