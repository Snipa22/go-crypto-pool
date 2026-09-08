// Package legacyapi implements a thin, additive HTTP wrapper that
// reshapes this backend's real internal/backend/{statsapi,networkapi,
// addressmap} JSON responses (plus a small amount of new read-only
// db.Repository plumbing — see internal/backend/db/legacyapi_reads.go)
// into the exact field-name/casing/nesting shape the legacy Node.js
// nodejs-pool-sxmr stack's lib/api.js served, for any existing
// SXMR-legacy-shaped frontend/tooling that still expects those routes
// and field names verbatim.
//
// This is NOT a rewrite of anything: every handler in this package
// calls into an existing package's exported Repository interface
// (networkapi.Repository, statsapi.Repository, addressmap.Repository)
// or a small number of genuinely new, additive, read-only
// db.Repository methods added alongside this package (ListBlocks/
// ListPayouts/MinerIdentifiersSince — see that file's doc comment for
// exactly why each was needed and what it does NOT duplicate). No
// existing /api/v1/* route, handler, or response shape is touched.
//
// # Algo/network defaulting
//
// Every route below that scopes a query by algo defaults to RXM (this
// repo's Monero-family algo string — see db.ValidAlgos) when the
// caller's request carries no algo hint, mirroring legacy's own
// single-algo (Monero/SXMR) assumption; an explicit ?algo=<ALGO>
// query parameter, when present, overrides the default and is passed
// straight through to the underlying Repository call (which performs
// its own real validation — an unrecognized algo surfaces as a 500
// from the underlying query, not a bespoke validator grown here).
// Network works the same way: an omitted ?network= defaults to this
// backend's own Config.Network (mirroring statsapi.Config.Network's
// identical role), with an explicit override passed straight through.
//
// # Real, explicitly flagged gaps
//
// A handful of legacy fields have no genuine backing query anywhere
// in this repo as of this package's construction. Rather than
// fabricate plausible-looking numbers, every one of these renders a
// well-defined placeholder (0, an empty array, or an omitted key) —
// see each handler's own doc comment for the specific field and why:
//
//   - /pool/stats, /pool/stats/:pool_type: "miners" (no distinct-
//     active-miner-count query exists), "totalMinersPaid", and
//     "totalPayments" (no existing aggregate counts real payouts) all
//     render 0. "roundHashes" (legacy's since-last-block-found share
//     sum) also renders 0 -- no existing aggregate is scoped to a
//     round boundary, only to a fixed trailing time window.
//   - /pool/chart/hashrate/:pool_type, /pool/chart/miners/:pool_type:
//     the only backing aggregate (networkapi.Repository.NetworkStatsSince)
//     is NOT pool_type-scoped -- these two routes validate the
//     pool_type path segment (400 on garbage, matching legacy) but
//     the single data point returned is this ALGO+NETWORK's whole
//     figure, not actually narrowed to that one pool_type. Adding a
//     new pool_type-scoped aggregate query was judged out of scope
//     for a wrapper-only PR (unlike blocks/payments below, nothing in
//     the dispatch brief explicitly carved out a new-query exception
//     for this specific gap).
//   - /pool/chart/hashrate, /network/chart/difficulty, /pool/chart/miners
//     and their per-worker/per-pool_type variants: this backend has
//     no Redis-rolling-history-list equivalent, so every chart
//     endpoint returns a SINGLE-POINT array computed from the real
//     current window query, not fabricated retained history.
//   - /pool/payments[/:pool_type], /miner/:address/payments: legacy's
//     mixins/payees Monero-RPC concepts have no equivalent column in
//     this schema's `payouts` table; mixins always renders 0
//     (documented placeholder), while payees is real, backed data
//     (len(balance_ids) -- how many balance rows/destinations this
//     one real Transfer batch actually covered). pool_type is omitted
//     entirely from the response (not even a null/0 key) -- payouts
//     are not pool_type-scoped in this schema (one real Transfer can
//     span balance rows from more than one pool_type), so
//     /pool/payments/:pool_type's path segment is accepted but has no
//     column to filter against and is silently ignored.
//   - /miner/:address/stats[/allWorkers|/:identifier]: "invalidShares"
//     always renders 0 -- this schema's `shares` table only ever
//     stores ACCEPTED shares (see internal/backend/db's package doc
//     comment); a rejected/invalid share is never persisted anywhere,
//     so there is no possible query to source a real invalid count
//     from.
package legacyapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/addressmap"
	"github.com/Snipa22/go-crypto-pool/internal/backend/networkapi"
	"github.com/Snipa22/go-crypto-pool/internal/backend/statsapi"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// DefaultAlgo is the algo every algo-scoped route in this package
// defaults to when the caller's request carries no ?algo= query
// parameter — see this package's doc comment.
const DefaultAlgo = "RXM"

// defaultWindowSeconds mirrors statsapi/networkapi's own
// DefaultWindowSeconds — this package has no query parameter of its
// own for tuning it (legacy's routes never exposed one either), so it
// is simply a private constant instead of a re-exported one.
const defaultWindowSeconds = statsapi.DefaultWindowSeconds

// defaultLegacyLimit/defaultLegacyPage mirror legacy's own
// GET /pool/blocks and GET /pool/payments pagination defaults
// (limit=25, page=0).
const (
	defaultLegacyLimit = 25
	defaultLegacyPage  = 0
	maxLegacyLimit     = 1000
)

// identifiersAllTimeSince is passed to BlocksRepository/
// IdentifiersRepository.MinerIdentifiersSince's sinceUnix parameter
// wherever this package wants "every worker this address has ever
// registered, regardless of recency" (the allWorkers stats/chart
// shapes) as opposed to GET /miner/:address/identifiers' own real
// 10-minute freshness window.
const identifiersAllTimeSince int64 = 0

// identifiersFreshWindowSeconds is the real freshness window legacy's
// GET /miner/:address/identifiers used ("workers seen in the last 10
// minutes") — see that handler's own doc comment.
const identifiersFreshWindowSeconds = 10 * 60

// BlockRecord is one `blocks` row as needed by this package's
// GET /pool/blocks[/:pool_type] handler — mirrors db.Block field-for-
// field, kept as this package's own type for the same dependency-
// direction reason every other backend subpackage's own XxxRecord
// type exists (see e.g. statsapi.BalanceRecord's doc comment).
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
}

// BlocksRepository is the narrow, additive read surface
// GET /pool/blocks[/:pool_type] depends on. *db.Repository satisfies
// this via ListBlocks (see internal/backend/db/legacyapi_reads.go);
// tests inject a fake.
type BlocksRepository interface {
	ListBlocks(ctx context.Context, algo, network, poolType string, limit, offset int) ([]BlockRecord, error)
}

// PayoutRecord is one `payouts` row as needed by this package's
// GET /pool/payments[/:pool_type] and GET /miner/:address/payments
// handlers — mirrors db.Payout field-for-field.
type PayoutRecord struct {
	ID          int64
	Status      string
	BalanceIDs  []int64
	Amount      int64
	Fee         *int64
	TxHash      *string
	CompletedAt *time.Time
}

// PayoutsRepository is the narrow, additive read surface the payments
// handlers depend on. *db.Repository satisfies this via ListPayouts
// (see internal/backend/db/legacyapi_reads.go); tests inject a fake.
type PayoutsRepository interface {
	ListPayouts(ctx context.Context, algo, network string, paymentAddress *string, limit, offset int) ([]PayoutRecord, int64, error)
}

// IdentifierRecord is one `miner_identifiers` row as needed by this
// package's worker-identifier-sourcing endpoints — mirrors
// db.MinerIdentifier field-for-field.
type IdentifierRecord struct {
	WorkerName string
	LastShare  *time.Time
}

// IdentifiersRepository is the narrow, additive read surface
// GET /miner/:address/identifiers and the allWorkers stats/chart
// shapes depend on. *db.Repository satisfies this via
// MinerIdentifiersSince (see internal/backend/db/legacyapi_reads.go);
// tests inject a fake.
type IdentifiersRepository interface {
	MinerIdentifiersSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]IdentifierRecord, error)
}

// Config configures a Handler.
type Config struct {
	// Network is this backend's own configured network — see this
	// package's doc comment for how it drives the optional ?network=
	// override mechanism, mirroring statsapi.Config.Network's
	// identical role.
	Network poolpb.Network

	// PPSFeePercent/PPLNSFeePercent/SoloFeePercent are the same
	// operator-set fee percentages payout.Config already uses to
	// compute real payout fee deductions — surfaced here, verbatim
	// and read-only, purely to populate GET /pool/stats/:pool_type's
	// legacy "fee" field. This package does not recompute or
	// otherwise use these values for anything else; there is no
	// existing Repository/HTTP surface anywhere in this repo that
	// exposes an operator's configured fee percentage back out over
	// HTTP, so cmd/backend passes the same three cfg values it
	// already threads into payout.Config here too.
	PPSFeePercent   float64
	PPLNSFeePercent float64
	SoloFeePercent  float64
}

// Handler implements the SXMR-legacy-shaped wrapper routes described
// in this package's doc comment.
type Handler struct {
	network networkapi.Repository
	stats   statsapi.Repository
	addrMap addressmap.Repository
	blocks  BlocksRepository
	payouts PayoutsRepository
	idents  IdentifiersRepository
	cfg     Config
}

// NewHandler constructs a Handler. Every Repository parameter is the
// exact interface type its own owning package already exports
// (networkapi.Repository/statsapi.Repository/addressmap.Repository)
// plus this package's own three small additive interfaces above —
// see cmd/backend's wiring for how *db.Repository satisfies all six
// at once.
func NewHandler(network networkapi.Repository, stats statsapi.Repository, addrMap addressmap.Repository, blocks BlocksRepository, payouts PayoutsRepository, idents IdentifiersRepository, cfg Config) *Handler {
	return &Handler{
		network: network,
		stats:   stats,
		addrMap: addrMap,
		blocks:  blocks,
		payouts: payouts,
		idents:  idents,
		cfg:     cfg,
	}
}

// Mux builds a fresh *http.ServeMux with this Handler's routes
// registered. Most callers should use RegisterRoutes against a
// shared mux instead (see cmd/backend) — this exists mainly for this
// package's own tests.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// RegisterRoutes registers every SXMR-legacy-shaped route this
// package implements onto mux. Safe to call on a mux that already has
// other, disjoint routes registered (e.g. every existing /api/v1/*
// handler) — every route this package registers lives at legacy's own
// bare (non-/api/v1-prefixed) paths, so there is no possible overlap
// with anything internal/backend/api/statsapi/networkapi/addressmap/
// leafflagsapi already serve.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /pool/stats", h.handlePoolStats)
	mux.HandleFunc("GET /pool/stats/{pool_type}", h.handlePoolStatsByType)

	mux.HandleFunc("GET /pool/chart/hashrate", h.handlePoolHashrateChart)
	mux.HandleFunc("GET /pool/chart/hashrate/{pool_type}", h.handlePoolHashrateChartByType)
	mux.HandleFunc("GET /network/chart/difficulty", h.handleNetworkDifficultyChart)
	mux.HandleFunc("GET /pool/chart/miners", h.handlePoolMinersChart)
	mux.HandleFunc("GET /pool/chart/miners/{pool_type}", h.handlePoolMinersChartByType)

	mux.HandleFunc("GET /miner/{address}/chart/hashrate", h.handleMinerHashrateChart)
	mux.HandleFunc("GET /miner/{address}/chart/hashrate/allWorkers", h.handleMinerHashrateChartAllWorkers)
	mux.HandleFunc("GET /miner/{address}/chart/hashrate/{identifier}", h.handleMinerHashrateChartWorker)

	mux.HandleFunc("GET /pool/blocks", h.handlePoolBlocks)
	mux.HandleFunc("GET /pool/blocks/{pool_type}", h.handlePoolBlocksByType)

	mux.HandleFunc("GET /pool/payments", h.handlePoolPayments)
	mux.HandleFunc("GET /pool/payments/{pool_type}", h.handlePoolPaymentsByType)
	mux.HandleFunc("GET /miner/{address}/payments", h.handleMinerPayments)

	mux.HandleFunc("GET /miner/{address}/identifiers", h.handleMinerIdentifiers)

	mux.HandleFunc("GET /miner/{address}/stats", h.handleMinerStats)
	mux.HandleFunc("GET /miner/{address}/stats/allWorkers", h.handleMinerStatsAllWorkers)
	mux.HandleFunc("GET /miner/{address}/stats/{identifier}", h.handleMinerStatsWorker)

	mux.HandleFunc("POST /user/updateTariAddress", h.handleUpdateTariAddress)
	mux.HandleFunc("GET /user/tariAddress/{address}", h.handleGetTariAddress)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// invalidPoolType writes legacy's own exact {'error': 'Invalid pool
// type'} shape (note the capital I — this is a literal, deliberate
// match of legacy's own string, not this repo's usual lowercase error
// message convention).
func invalidPoolType(w http.ResponseWriter) {
	writeJSONErr(w, http.StatusBadRequest, "Invalid pool type")
}

// resolveAlgo implements this package's doc-comment-documented algo-
// defaulting rule: an omitted query value defaults to DefaultAlgo; an
// explicit one passes straight through (real validation happens
// inside whichever Repository method ends up called with it).
func resolveAlgo(raw string) string {
	if raw == "" {
		return DefaultAlgo
	}
	return raw
}

// networkDBString mirrors statsapi/networkapi/cmd/backend's own
// identically named private helper — poolpb.Network to this schema's
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
// network-defaulting rule: an omitted query value defaults to this
// Handler's own Config.Network; an explicit one passes straight
// through.
func (h *Handler) resolveNetwork(raw string) string {
	if raw != "" {
		return raw
	}
	return networkDBString(h.cfg.Network)
}

// legacyPoolTypeStrict maps a legacy lowercase pool_type path segment
// (pplns/pps/solo — legacy's own exact, fixed set) to this schema's
// real uppercase pool_type enum value. ok is false for anything else,
// which every STRICT caller (GET /pool/stats/:pool_type,
// GET /pool/chart/{hashrate,miners}/:pool_type) turns into legacy's
// exact 400 {"error": "Invalid pool type"} response.
func legacyPoolTypeStrict(raw string) (string, bool) {
	switch raw {
	case "pplns":
		return "PPLNS", true
	case "pps":
		return "PPS", true
	case "solo":
		return "SOLO", true
	default:
		return "", false
	}
}

// legacyPoolTypeLoose maps a pool_type path segment the same way
// legacyPoolTypeStrict does when it recognizes one of legacy's own
// three values, but — unlike legacyPoolTypeStrict — never rejects an
// unrecognized value with a 400. Instead it upper-cases raw verbatim
// and returns it as-is, to be passed straight through as a plain
// equality filter. Used by GET /pool/blocks/:pool_type, where this
// schema's pool_type is a genuinely different (string-enum, not
// legacy's int) shape than legacy's own path parameter — see this
// package's doc comment for why forcing a fake int mapping here would
// be worse than just passing the raw value through and letting an
// unrecognized one simply match zero rows.
func legacyPoolTypeLoose(raw string) string {
	if mapped, ok := legacyPoolTypeStrict(raw); ok {
		return mapped
	}
	return strings.ToUpper(raw)
}

// errInvalidLimit/errInvalidPage are parseLegacyLimitPage's own
// sentinel errors — every caller translates either into a 400 with
// the error's own message as the body (see e.g. handlePoolBlocks).
var (
	errInvalidLimit = errors.New("limit must be a positive integer")
	errInvalidPage  = errors.New("page must be a non-negative integer")
)

// parseLegacyLimitPage parses the optional ?limit=&page= query
// parameters GET /pool/blocks and GET /pool/payments both accept,
// defaulting to 25/0 (matching legacy exactly) and returning
// (limit, offset). limit is capped at maxLegacyLimit to bound a
// single crafted query string's worst-case scan/response size; page
// has no upper bound (an out-of-range page legitimately just returns
// zero rows).
func parseLegacyLimitPage(q url.Values) (limit, offset int, err error) {
	limit = defaultLegacyLimit
	if raw := q.Get("limit"); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil || v <= 0 {
			return 0, 0, errInvalidLimit
		}
		if v > maxLegacyLimit {
			v = maxLegacyLimit
		}
		limit = v
	}

	page := defaultLegacyPage
	if raw := q.Get("page"); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil || v < 0 {
			return 0, 0, errInvalidPage
		}
		page = v
	}

	return limit, page * limit, nil
}

// splitLegacyAddress replicates legacy's own address.split('.')
// payment-id convention (see e.g. GET /miner/:address/identifiers'
// doc comment): everything before the first '.' is the real payment
// address; everything after (if any) is the payment_id. An address
// with no '.' has a nil payment_id (matches every payment_id variant
// of that address, mirroring every other Repository method's own nil-
// means-any convention), not an empty-string one (which would instead
// mean "match only rows with no payment_id at all").
func splitLegacyAddress(raw string) (address string, paymentID *string) {
	if idx := strings.IndexByte(raw, '.'); idx >= 0 {
		id := raw[idx+1:]
		return raw[:idx], &id
	}
	return raw, nil
}

// nowUnix is a seam so tests can pin "now" if ever needed; production
// code always calls time.Now().Unix() through it.
var nowUnix = func() int64 { return time.Now().Unix() }
