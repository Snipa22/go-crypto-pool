// tari.go implements the SXMR merge-mining system's legacy-shaped
// Tari-address endpoints, thin-wrapping internal/backend/addressmap's
// existing set/get logic (addressmap.Repository) — see this
// package's doc comment for why this wrapper reshapes both the
// request AND response bodies (legacy's camelCase xmrAddress/
// tariAddress keys, not addressmap's own snake_case xmr_address/
// tari_address wire shape) rather than re-deriving any address
// validation of its own.
package legacyapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Snipa22/go-crypto-pool/internal/backend/addressmap"
)

// maxTariBodyBytes bounds how much of a POST body handleUpdateTariAddress
// will read — mirrors addressmap's own maxBodyBytes constant/rationale
// exactly (two short address strings; no legitimate reason to be large).
const maxTariBodyBytes = 1 << 16 // 64 KiB

// updateTariAddressRequest is the JSON body
// POST /user/updateTariAddress expects — legacy's own exact camelCase
// field names (deliberately NOT addressmap's own upsertRequest shape,
// which uses xmr_address/tari_address — see this file's doc comment).
type updateTariAddressRequest struct {
	XMRAddress  string `json:"xmrAddress"`
	TariAddress string `json:"tariAddress"`
}

// handleUpdateTariAddress implements POST /user/updateTariAddress.
// Validation is delegated entirely to addressmap's own real,
// byte-exact Monero/Tari address validators (exported as
// addressmap.ValidateXMRAddress/ValidateTariAddress specifically for
// this reuse — see that package's doc comment on those two
// functions) rather than re-derived here; this handler's only job is
// picking which of legacy's two distinct failure messages to render
// depending on which side failed, and translating a successful Set
// into legacy's own {"msg": "<tariAddress>"} success shape.
//
// Set is set-once/no-overwrite (see addressmap.Repository.Set /
// FIX_BRIEF.md): a second call for an already-mapped xmr_address
// returns addressmap.ErrAlreadyMapped, which this handler
// deliberately folds into the SAME "Unable to insert address" 400
// legacy already sends on any Set error, rather than inventing a new
// response shape -- this keeps behavior identical to a legacy caller
// (a 400, not a 200 overwrite), matching legacy's own plain INSERT
// (no ON CONFLICT clause) failing/erroring on a duplicate
// xmr_address (see lib/api.js:869/872).
func (h *Handler) handleUpdateTariAddress(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTariBodyBytes)

	var req updateTariAddressRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "malformed JSON body"})
		return
	}

	if err := addressmap.ValidateXMRAddress(req.XMRAddress); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "Unable to validate XMR address"})
		return
	}
	if err := addressmap.ValidateTariAddress(req.TariAddress); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "Unable to validate Tari address"})
		return
	}

	if err := h.addrMap.Set(r.Context(), req.XMRAddress, req.TariAddress); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "Unable to insert address"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"msg": req.TariAddress})
}

// handleGetTariAddress implements GET /user/tariAddress/:address.
// Per legacy's own contract, a not-found xmr_address is NOT a 404
// here (unlike addressmap's own GET /api/v1/address-map) — it is a
// 200 with an empty-string msg, matching legacy's exact "no mapping
// yet" convention for this specific legacy-shaped route.
func (h *Handler) handleGetTariAddress(w http.ResponseWriter, r *http.Request) {
	xmrAddress := r.PathValue("address")

	rec, err := h.addrMap.Get(r.Context(), xmrAddress)
	if err != nil {
		if errors.Is(err, addressmap.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]string{"msg": ""})
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"msg": rec.TariAddress})
}
