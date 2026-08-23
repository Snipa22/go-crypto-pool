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
)

// maxBodyBytes bounds how much of a POST body we will read. The
// mapping payload is two short address strings; there is no
// legitimate reason for it to approach this size.
const maxBodyBytes = 1 << 16 // 64 KiB

// maxAddressLen is a generous upper bound on a well-formed Monero or
// Tari address's length, used only to reject obviously-malformed
// input before it reaches the database -- NOT a real address-format
// validator (this package does not decode/verify Monero base58 or
// Tari's own address encoding; that would require importing coin-
// specific address-parsing logic this repo does not currently have
// for either coin on the backend side).
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
}

// NewHandler constructs a Handler backed by repo.
func NewHandler(repo Repository) *Handler {
	return &Handler{repo: repo}
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
// whitespace-only, or absurdly long) without attempting real
// coin-specific address decoding -- see this package's doc comment
// on maxAddressLen for why that's a deliberate scope limit, not an
// oversight.
func validateAddress(field, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return errors.New(field + " is required")
	}
	if len(addr) > maxAddressLen {
		return errors.New(field + " is too long")
	}
	return nil
}

// validateTariAddress additionally checks a real, cheap structural
// invariant: length. nodejs-pool-sxmr's own /user/updateTariAddress
// route (lib/api.js) also checked a "12"/"14" prefix, but that check
// is MAINNET-specific -- a real Esmeralda testnet address (e.g. the
// one already in this project's own Vault test fixtures,
// f2GYDtVpj6yx8ZRPez2fsaU3VBAfVzcYycb3boUqMz1C9cZdJ7CrAkhhYoqRRNJPjwRSKqfd2caRe9jv8ZKwAwDGbvD,
// 91 chars, starts "f2") uses a genuinely different real network-byte
// prefix and would be wrongly rejected by that check. Since this
// backend explicitly supports both MAINNET and TESTNET (see
// ValidateNetwork), and this package does not have a verified,
// network-aware table of every real Tari network-byte prefix, only
// the length invariant (Tari addresses are consistently 90-91 base58
// chars across networks) is enforced here -- deliberately more
// permissive than the legacy mainnet-only reference, not a stricter
// invention. A real, byte-exact prefix table sourced from Tari's own
// address-encoding source (not guessed) would be a legitimate future
// tightening, but shipping a wrong restrictive check that silently
// blocks real testnet addresses is a worse failure mode than this
// permissive one.
func validateTariAddress(addr string) error {
	if err := validateAddress("tari_address", addr); err != nil {
		return err
	}
	if len(addr) < 90 || len(addr) > 200 {
		return errors.New("tari_address does not look like a valid Tari address (expected roughly 90+ base58 chars)")
	}
	return nil
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

	if err := validateAddress("xmr_address", req.XMRAddress); err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateTariAddress(req.TariAddress); err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.repo.Upsert(r.Context(), req.XMRAddress, req.TariAddress); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "upsert failed")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"xmr_address":  req.XMRAddress,
		"tari_address": req.TariAddress,
	})
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
	if err := validateAddress("xmr_address", xmrAddress); err != nil {
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
