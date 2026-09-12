// Package addressmap implements the backend's HTTP endpoints for the
// SXMR merge-mining system's XMR-to-Tari address mapping. A miner
// mining SXMR submits shares under a single Monero (XMR) payment
// address (see internal/backend/api's share-ingestion path), but any
// Tari-side payout needs a real Tari wallet address to send funds to.
// This package lets a miner register/update that mapping and lets the
// Tari-side payout path (or the miner themselves, for confirmation)
// look it up.
//
// This is a genuinely separate package/Handler from both
// internal/backend/api (the leaf -> backend share/block ingestion
// trust boundary) and internal/backend/statsapi (the read-only
// per-miner balance/hashrate surface) for the same reason those two
// are kept apart from each other: a bug in address-mapping writes
// must never be able to touch share/block ingestion or stats
// queries, and this surface can be deployed/rate-limited
// independently of either.
//
// Endpoints:
//
//   - POST /api/v1/address-map
//     Body: {"xmr_address": "...", "tari_address": "..."}
//     Upserts the mapping for xmr_address (see
//     Repository.UpsertAddressMap's doc comment on the upsert
//     semantics: one XMR address maps to exactly one live Tari
//     address at a time; re-POSTing the same xmr_address with a new
//     tari_address simply replaces the destination). Returns 201 on
//     success.
//
//   - GET /api/v1/address-map?xmr_address=<addr>
//     Returns the current mapping for xmr_address, or 404 if none
//     exists.
//
// Neither endpoint performs authentication -- like statsapi, this is
// a public-ish surface keyed only by information the miner already
// has (their own XMR address), not a privileged admin API. Callers
// fronting this backend with a reverse proxy that wants stricter
// controls (e.g. requiring the request be signed by the XMR address's
// private key) can layer that in front; this package does not
// invent a signature scheme that isn't backed by real verification
// code anywhere else in this repo.
package addressmap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	tariaddress "github.com/Snipa22/go-tari-lib/address"
	xmraddress "github.com/Snipa22/go-xmr-lib/support"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
)

// maxBodyBytes bounds how much of a POST body we will read. The
// mapping payload is two short address strings; there is no
// legitimate reason for it to approach this size.
const maxBodyBytes = 1 << 16 // 64 KiB

// maxAddressLen is a generous upper bound on a well-formed Monero or
// Tari address's length, used only as a cheap pre-check to reject
// absurdly long input before it reaches the real, coin-specific
// byte-exact decoders (validateXMRAddress/validateTariAddress below)
// -- those functions do the actual address-format verification via
// github.com/Snipa22/go-xmr-lib and github.com/Snipa22/go-tari-lib
// respectively; this constant is not itself a format validator.
const maxAddressLen = 512

// Record mirrors db.AddressMap field-for-field (see that package's
// doc comment) -- kept as this package's own type for the same
// dependency-direction reason api.ShareRecord/statsapi.BalanceRecord
// mirror their own db types instead of importing internal/backend/db
// directly.
type Record struct {
	XMRAddress  string
	TariAddress string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ErrNotFound is the sentinel a Repository implementation must return
// from Get when xmrAddress has no mapping. Handler translates this
// (and only this) error into a 404; any other error is a 500.
var ErrNotFound = errors.New("addressmap: no mapping for that xmr_address")

// Repository is the narrow persistence surface this package's
// handlers depend on. *db.Repository satisfies this via the adapter
// wired up in cmd/backend (see db/addressmap.go for the underlying
// UpsertAddressMap/GetAddressMap methods); tests inject a fake.
type Repository interface {
	Upsert(ctx context.Context, xmrAddress, tariAddress string) error
	Get(ctx context.Context, xmrAddress string) (Record, error)
}

// Handler implements the backend's address-mapping HTTP endpoints.
type Handler struct {
	repo Repository
	cfg  Config
}

// Config configures a Handler.
type Config struct {
	// Metrics, if non-nil, is the metrics.Metrics instance
	// handleUpsert increments (address_map_writes_total). If nil,
	// metrics are simply not recorded. See
	// PROD_HARDENING_REVIEW.md finding #19: per the audit, every
	// address-map write is "the single most alert-worthy event" this
	// backend can emit -- either a legitimate first-time mapping OR
	// evidence someone tried (and, per the set-once upsert
	// behavior, may have succeeded in overwriting) an existing
	// XMR->Tari mapping.
	Metrics *metrics.Metrics
}

// NewHandler constructs a Handler backed by repo, using cfg for
// optional metrics wiring. Existing callers that only need the
// pre-existing behavior can pass Config{}.
func NewHandler(repo Repository, cfg Config) *Handler {
	return &Handler{repo: repo, cfg: cfg}
}

// Mux builds a fresh *http.ServeMux with this Handler's routes
// registered. Most callers should use RegisterRoutes against a
// shared mux instead (see cmd/backend) -- this exists mainly for this
// package's own tests and any caller that genuinely wants this
// Handler stand-alone.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// RegisterRoutes registers this Handler's routes onto mux. Safe to
// call on a mux that already has other, disjoint routes registered
// -- this package never registers anything outside
// /api/v1/address-map.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/address-map", h.handleUpsert)
	mux.HandleFunc("GET /api/v1/address-map", h.handleGet)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// validateAddress rejects the obviously-malformed cases (empty,
// whitespace-only, or absurdly long) common to both coins, ahead of
// the coin-specific byte-exact decoding done by validateXMRAddress/
// validateTariAddress below.
func validateAddress(field, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return errors.New(field + " is required")
	}
	if len(addr) > maxAddressLen {
		return errors.New(field + " is too long")
	}
	return nil
}

// validateTariAddress performs real, byte-exact Tari address
// validation via github.com/Snipa22/go-tari-lib's address package --
// a byte-exact Go port of the real Tari Base Layer tari_address
// implementation (see that package's doc comment). address.Parse
// tries emoji, then base58, then hex encodings (mirroring Rust's
// `impl FromStr for TariAddress`) and, along the way, verifies the
// DammSum checksum, the network byte against the real, current set
// of Tari network wire-byte values, the features byte, and --
// critically -- that the embedded public key(s) decode to a
// canonical compressed Ristretto255 point (RFC 9496), not just that
// the string is the right length.
//
// This deliberately supersedes the previous length-only placeholder
// (see git history on this function): that check was a permissive
// stand-in adopted specifically because this package had no real,
// network-aware validator; it explicitly called out a byte-exact
// prefix table "sourced from Tari's own address-encoding source" as
// the legitimate future tightening, which is exactly what
// go-tari-lib's address package is. It naturally accepts the same
// real Esmeralda testnet address
// (f2GYDtVpj6yx8ZRPez2fsaU3VBAfVzcYycb3boUqMz1C9cZdJ7CrAkhhYoqRRNJPjwRSKqfd2caRe9jv8ZKwAwDGbvD)
// that motivated the permissive length-only check, because Esmeralda
// is one of the real network bytes address.NetworkFromByte accepts --
// but it now also rejects addresses with a right-length but wrong/
// corrupted checksum, network byte, features byte, or non-canonical
// public key, none of which the length check could ever catch.
func validateTariAddress(addr string) error {
	if err := validateAddress("tari_address", addr); err != nil {
		return err
	}
	if _, err := tariaddress.Parse(addr); err != nil {
		return errors.New("tari_address is not a valid Tari address: " + err.Error())
	}
	return nil
}

// validateXMRAddress performs real, checksum-verified Monero address
// validation via github.com/Snipa22/go-xmr-lib's support package
// (already a dependency of this repo's wallet-transfer engine, see
// internal/backend/disburse). support.IsValidMainnet/IsValidTestnet
// base58-decode the address and verify its trailing 4-byte Keccak
// checksum against the address's own payload -- a real structural
// check, not a length heuristic -- then confirm the leading network-
// tag byte is one of Monero's real mainnet (0x12 standard, 0x2a
// integrated, 0x13 subaddress, 0x11 -- legacy) or testnet (0x35
// standard/subaddress, 0x3f integrated) tag bytes. Both are checked
// (rather than picking one based on some pool-network hint) because
// this package's xmr_address field is not itself scoped to a single
// pool/network row -- see this package's own doc comment on why
// address-mapping is a genuinely separate, network-agnostic surface
// from api/statsapi/networkapi's per-(algo,network) scoping.
func validateXMRAddress(addr string) error {
	if err := validateAddress("xmr_address", addr); err != nil {
		return err
	}
	validMain, err := xmraddress.IsValidMainnet(addr)
	if err != nil {
		return errors.New("xmr_address is not a valid Monero address: " + err.Error())
	}
	if validMain {
		return nil
	}
	validTest, err := xmraddress.IsValidTestnet(addr)
	if err != nil {
		return errors.New("xmr_address is not a valid Monero address: " + err.Error())
	}
	if validTest {
		return nil
	}
	return errors.New("xmr_address is not a valid Monero address (bad checksum or unrecognized network byte)")
}

// ValidateXMRAddress is validateXMRAddress's exported form — added
// purely so internal/backend/legacyapi's SXMR-legacy-shaped
// POST /user/updateTariAddress wrapper can reuse this package's real,
// byte-exact Monero address validation without re-deriving it (see
// that package's own doc comment: legacyapi's whole point is response/
// request SHAPE translation, never re-implementing validation logic
// that already exists here). Purely additive — every existing
// internal call site keeps calling the lowercase validateXMRAddress
// directly; this is just a thin, exported alias for external reuse.
func ValidateXMRAddress(addr string) error {
	return validateXMRAddress(addr)
}

// ValidateTariAddress is validateTariAddress's exported form —
// mirrors ValidateXMRAddress's exact rationale/role above, for the
// Tari side.
func ValidateTariAddress(addr string) error {
	return validateTariAddress(addr)
}

// upsertRequest is the JSON body POST /api/v1/address-map expects.
type upsertRequest struct {
	XMRAddress  string `json:"xmr_address"`
	TariAddress string `json:"tari_address"`
}

func (h *Handler) handleUpsert(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req upsertRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "malformed JSON body")
		return
	}

	if err := validateXMRAddress(req.XMRAddress); err != nil {
		h.observeWrite(metrics.ResultRejected)
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateTariAddress(req.TariAddress); err != nil {
		h.observeWrite(metrics.ResultRejected)
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.repo.Upsert(r.Context(), req.XMRAddress, req.TariAddress); err != nil {
		h.observeWrite(metrics.ResultError)
		writeJSONErr(w, http.StatusInternalServerError, "upsert failed")
		return
	}
	h.observeWrite(metrics.ResultAccepted)

	writeJSON(w, http.StatusCreated, map[string]string{
		"xmr_address":  req.XMRAddress,
		"tari_address": req.TariAddress,
	})
}

// observeWrite increments Config.Metrics.AddressMapWritesTotal for
// one POST /api/v1/address-map attempt, a no-op if no Metrics is
// configured. See Config.Metrics' doc comment for why every write
// here is worth counting regardless of outcome.
func (h *Handler) observeWrite(result string) {
	if h.cfg.Metrics == nil {
		return
	}
	h.cfg.Metrics.AddressMapWritesTotal.WithLabelValues(result).Inc()
}

// getResponse is the JSON shape GET /api/v1/address-map returns.
type getResponse struct {
	XMRAddress  string `json:"xmr_address"`
	TariAddress string `json:"tari_address"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	xmrAddress := r.URL.Query().Get("xmr_address")
	if err := validateXMRAddress(xmrAddress); err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	rec, err := h.repo.Get(r.Context(), xmrAddress)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeJSONErr(w, http.StatusNotFound, "no mapping for that xmr_address")
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, getResponse{
		XMRAddress:  rec.XMRAddress,
		TariAddress: rec.TariAddress,
		CreatedAt:   rec.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   rec.UpdatedAt.UTC().Format(time.RFC3339),
	})
}
