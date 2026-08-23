// Package leafflagsapi implements the backend's read-only endpoint
// leaves poll to learn about manually-flagged (banned / forced-
// minimum-difficulty) payment addresses:
//
//	GET /api/v1/leaf/address-flags
//
// This is the OTHER real half of the manual ban/forced-difficulty
// system from internal/backend/db/addressflags.go's storage/CLI: that
// package is how an operator RECORDS a ban/floor decision (durable,
// audited, Postgres-backed); this package is how a leaf (leaf-direct
// — see internal/leaflib/addressflags.HTTPSource) LEARNS about it, so
// enforcement can happen at the correct layer (login rejection /
// difficulty floor on the leaf itself — see that package's doc
// comment for the full rationale of why this moved off the backend's
// share-ingestion path).
//
// Deliberately a SEPARATE package/Handler from internal/backend/api
// (share/block ingestion) and internal/backend/db/addressflags.go's
// own doc comment ("there is no HTTP endpoint for either" — written
// before this pass): that comment described the write side
// accurately (still CLI-only, still human-in-the-loop, still -yes-
// gated) but this is a READ-only, unauthenticated-by-default surface
// serving already-decided operator state, not a way to set it. A bug
// here can only ever leak which addresses are currently flagged (not
// exactly sensitive — these are payment addresses an operator already
// took public-ish action against) and can never write anything.
//
// Response is deliberately narrow: PaymentAddress/Banned/
// ForcedMinDifficulty only — no ban reason, no operator identifier, no
// timestamps. Those audit fields are real and valuable for a human
// operator reviewing `backend address list`, but a leaf's enforcement
// logic (internal/leaflib/addressflags.Cache) has no use for them and
// there is no reason to give every connected leaf process a copy of an
// audit trail it will never consult.
package leafflagsapi

import (
	"context"
	"encoding/json"
	"net/http"
)

// Flag is one actively-flagged address's real ban/forced-minimum-
// difficulty state, mirroring db.AddressFlag's two enforcement-
// relevant fields only (see this package's doc comment for why the
// audit fields are deliberately excluded here).
type Flag struct {
	PaymentAddress      string
	Banned              bool
	ForcedMinDifficulty *int64 // nil when no floor is set
}

// Repository is the narrow, read-only persistence surface this
// package's handler depends on. *db.Repository satisfies this as-is
// via its own ListAddressFlags (see internal/backend/db/
// addressflags.go); tests inject a fake.
type Repository interface {
	ListActiveAddressFlags(ctx context.Context) ([]Flag, error)
}

// Handler implements GET /api/v1/leaf/address-flags.
type Handler struct {
	repo Repository
}

// NewHandler constructs a Handler backed by repo.
func NewHandler(repo Repository) *Handler {
	return &Handler{repo: repo}
}

// Mux builds a fresh *http.ServeMux with this Handler's route
// registered. Most callers should use RegisterRoutes against a
// shared mux instead (see cmd/backend).
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// RegisterRoutes registers this Handler's route onto mux. Safe to
// call on a mux that already has other, disjoint routes registered —
// this package registers exactly one route, GET /api/v1/leaf/address-flags.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/leaf/address-flags", h.handleList)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// flagRow is the JSON shape one Flag serializes to — field names/
// shape are the exact contract internal/leaflib/addressflags.HTTPSource
// parses against; changing either side requires changing both.
type flagRow struct {
	PaymentAddress      string `json:"payment_address"`
	Banned              bool   `json:"banned"`
	ForcedMinDifficulty int64  `json:"forced_min_difficulty,omitempty"`
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.repo.ListActiveAddressFlags(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	out := make([]flagRow, 0, len(rows))
	for _, f := range rows {
		var floor int64
		if f.ForcedMinDifficulty != nil {
			floor = *f.ForcedMinDifficulty
		}
		out = append(out, flagRow{
			PaymentAddress:      f.PaymentAddress,
			Banned:              f.Banned,
			ForcedMinDifficulty: floor,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"flags": out})
}
