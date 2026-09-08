// Package legacyconfig implements the SXMR-legacy backend's small,
// cheap, mostly-static/standalone HTTP endpoints ported from the
// legacy Node.js nodejs-pool-upgrade `lib/api.js` (see brief-auth.md
// for the exact ground-truth field names/behavior this mirrors):
// GET /config (a static pool-fee/config echo), GET /pool/motd
// (message of the day), GET /pool/ports (a flat pool+port listing),
// and GET /pool/address_type/{address} (a Tari/Monero address-type
// sniff).
//
// Kept as its own package/Handler, separate from
// internal/backend/authapi, per this repo's per-surface trust-
// boundary convention (see that package's own doc comment): none of
// these routes require authentication, and none of them touch the
// users/balance tables authapi writes to -- this is a genuinely
// distinct, read-only-except-for-nothing surface.
package legacyconfig

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	tariaddress "github.com/Snipa22/go-tari-lib/address"
	xmraddress "github.com/Snipa22/go-xmr-lib/support"

	"github.com/Snipa22/go-crypto-pool/internal/backend/networkapi"
)

// MotdRecord mirrors db.Motd field-for-field (see that package's doc
// comment) -- kept as this package's own type for the same
// dependency-direction reason every other internal/backend/*
// package's Record type mirrors its own db type instead of importing
// internal/backend/db directly.
type MotdRecord struct {
	Created time.Time
	Subject string
	Body    string
	Type    string
	Active  bool
}

// ErrMotdNotFound is the sentinel a Repository implementation must
// return from LatestMotd when the underlying table has no rows at
// all. Handler translates this (and an explicitly inactive row) into
// the same `200 {}` response.
var ErrMotdNotFound = errors.New("legacyconfig: no motd rows")

// Repository is the narrow, read-only persistence surface this
// package's handleMotd depends on. *db.Repository satisfies this via
// the adapter wired up in cmd/backend; tests inject a fake.
type Repository interface {
	LatestMotd(ctx context.Context) (MotdRecord, error)
}

// PoolPortsSource is the narrow surface handlePorts depends on to
// serve GET /pool/ports without this package duplicating
// networkapi's own ListPools query -- see
// networkapi.Handler.ListFlatPorts's doc comment for the small,
// additive, non-breaking method that satisfies this interface.
// *networkapi.Handler satisfies this as-is.
type PoolPortsSource interface {
	ListFlatPorts(ctx context.Context, algo, network string) ([]networkapi.FlatPort, error)
}

// Config configures a Handler's static GET /config response. Every
// field here mirrors a real cmd/backend GCPOOL_PAYOUT_*/
// GCPOOL_DISBURSE_*/GCPOOL_UNLOCKER_* env var where a real equivalent
// exists; fields with NO real backend equivalent are hardcoded
// placeholders documented individually at their call site in
// handleConfig (never fabricated non-zero data), per brief-auth.md's
// explicit instruction.
type Config struct {
	// PPSFeePercent/SoloFeePercent mirror
	// GCPOOL_PAYOUT_PPS_FEE_PERCENT/GCPOOL_PAYOUT_SOLO_FEE_PERCENT --
	// real values.
	PPSFeePercent  float64
	SoloFeePercent float64

	// DevDonationPercent/PoolDevDonationPercent mirror
	// GCPOOL_PAYOUT_DEV_DONATION_PERCENT/
	// GCPOOL_PAYOUT_POOL_DEV_DONATION_PERCENT -- real values.
	DevDonationPercent     float64
	PoolDevDonationPercent float64

	// MinWalletPayoutAtomic mirrors GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC
	// -- a real value (the same minimum this backend's own
	// disbursement engine enforces).
	MinWalletPayoutAtomic int64

	// MaturityDepth mirrors whichever of
	// GCPOOL_UNLOCKER_TARI_MATURITY/GCPOOL_UNLOCKER_MONERO_MATURITY
	// the caller of NewHandler chose to pass in -- this package is
	// coin-agnostic and has no opinion on which one "the" maturity
	// depth is for a multi-coin deployment; see cmd/backend's wiring
	// for the actual choice made there.
	MaturityDepth int64
}

// Handler implements this package's read-only HTTP endpoints.
type Handler struct {
	repo  Repository
	ports PoolPortsSource
	cfg   Config
}

// NewHandler constructs a Handler backed by repo/ports, using cfg for
// GET /config's static response fields.
func NewHandler(repo Repository, ports PoolPortsSource, cfg Config) *Handler {
	return &Handler{repo: repo, ports: ports, cfg: cfg}
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
// -- this package never registers anything outside /config,
// /pool/motd, /pool/ports, and /pool/address_type/.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /config", h.handleConfig)
	mux.HandleFunc("GET /pool/motd", h.handleMotd)
	mux.HandleFunc("GET /pool/ports", h.handlePorts)
	mux.HandleFunc("GET /pool/address_type/{address}", h.handleAddressType)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// configResponse is the JSON shape GET /config returns -- field
// names/casing mirror legacy's exact keys (see brief-auth.md).
type configResponse struct {
	// PPLNSFee is hardcoded to 0.6, matching legacy's own hardcoded
	// value exactly -- this backend has no GCPOOL_PAYOUT_PPLNS_FEE_*
	// env var equivalent (only PPS/Solo have one; see
	// cmd/backend/main.go), so this is a literal port of legacy's
	// constant, not a placeholder standing in for missing data.
	PPLNSFee float64 `json:"pplns_fee"`

	// PPSFee/SoloFee: real values (see Config.PPSFeePercent/
	// Config.SoloFeePercent).
	PPSFee  float64 `json:"pps_fee"`
	SoloFee float64 `json:"solo_fee"`

	// BTCFee: PLACEHOLDER. This backend has no Bitcoin-side fee
	// concept/env var at all.
	BTCFee float64 `json:"btc_fee"`

	// MinWalletPayout: real value (see Config.MinWalletPayoutAtomic).
	MinWalletPayout int64 `json:"min_wallet_payout"`

	// MinBTCPayout: PLACEHOLDER, no Bitcoin equivalent exists.
	MinBTCPayout int64 `json:"min_btc_payout"`

	// ManualWallet/ManualPaymentID: PLACEHOLDER. Legacy's manual-
	// payout-destination config has no equivalent env var in this
	// backend.
	ManualWallet    string `json:"manual_wallet"`
	ManualPaymentID string `json:"manual_payment_id"`

	// MinExchangePayout: PLACEHOLDER, no equivalent env var/concept
	// exists in this backend yet.
	MinExchangePayout int64 `json:"min_exchange_payout"`

	// DevDonation/PoolDevDonation: real values (see
	// Config.DevDonationPercent/Config.PoolDevDonationPercent).
	DevDonation     float64 `json:"dev_donation"`
	PoolDevDonation float64 `json:"pool_dev_donation"`

	// MaturityDepth: real value (see Config.MaturityDepth).
	MaturityDepth int64 `json:"maturity_depth"`

	// MinDenom: PLACEHOLDER, no equivalent env var/concept exists in
	// this backend yet.
	MinDenom int64 `json:"min_denom"`
}

func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, configResponse{
		PPLNSFee:          0.6,
		PPSFee:            h.cfg.PPSFeePercent,
		SoloFee:           h.cfg.SoloFeePercent,
		BTCFee:            0,
		MinWalletPayout:   h.cfg.MinWalletPayoutAtomic,
		MinBTCPayout:      0,
		ManualWallet:      "",
		ManualPaymentID:   "",
		MinExchangePayout: 0,
		DevDonation:       h.cfg.DevDonationPercent,
		PoolDevDonation:   h.cfg.PoolDevDonationPercent,
		MaturityDepth:     h.cfg.MaturityDepth,
		MinDenom:          0,
	})
}

// motdResponse is the JSON shape GET /pool/motd returns when an
// active motd row exists. Created is Unix seconds -- legacy's own
// `Math.floor(row.created/1000)` int-truncation of a millisecond
// timestamp, mirrored here via time.Time.Unix() (already
// whole-second resolution, so no separate truncation is needed).
type motdResponse struct {
	Created int64  `json:"created"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Type    string `json:"type"`
}

func (h *Handler) handleMotd(w http.ResponseWriter, r *http.Request) {
	m, err := h.repo.LatestMotd(r.Context())
	if err != nil {
		if errors.Is(err, ErrMotdNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{})
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if !m.Active {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, motdResponse{
		Created: m.Created.UTC().Unix(),
		Subject: m.Subject,
		Body:    m.Body,
		Type:    m.Type,
	})
}

// portResponseRow is one flattened pool+port entry in GET
// /pool/ports' response array. Field names are this package's own,
// best-effort reshaping of networkapi.FlatPort -- brief-auth.md's
// ground-truth transcription describes legacy's poolPorts cache only
// as "a flat array of port objects with pool type context", without
// enumerating its exact legacy JSON key names (unlike every other
// route in this dispatch, whose exact field names/casing were
// explicitly transcribed). These names were chosen for internal
// consistency with this backend's own networkapi/statsapi JSON
// conventions rather than a verified legacy field-for-field match;
// flagged explicitly here and in the dispatch summary.
type portResponseRow struct {
	Algo            string `json:"algo"`
	Network         string `json:"network"`
	PoolType        string `json:"pool_type"`
	Port            int32  `json:"port"`
	Description     string `json:"description"`
	MinDifficulty   int64  `json:"min_difficulty"`
	MaxDifficulty   *int64 `json:"max_difficulty,omitempty"`
	StartDifficulty int64  `json:"start_difficulty"`
	VariableDiff    bool   `json:"variable_diff"`
}

func (h *Handler) handlePorts(w http.ResponseWriter, r *http.Request) {
	ports, err := h.ports.ListFlatPorts(r.Context(), "", "")
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]portResponseRow, 0, len(ports))
	for _, p := range ports {
		out = append(out, portResponseRow{
			Algo:            p.Algo,
			Network:         p.Network,
			PoolType:        p.PoolType,
			Port:            p.Port,
			Description:     p.Description,
			MinDifficulty:   p.MinDifficulty,
			MaxDifficulty:   p.MaxDifficulty,
			StartDifficulty: p.StartDifficulty,
			VariableDiff:    p.VariableDiff,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// isValidXMRAddress performs the same real, checksum-verified Monero
// address validation internal/backend/addressmap.validateXMRAddress
// uses (github.com/Snipa22/go-xmr-lib/support.IsValidMainnet/
// IsValidTestnet) -- reused here rather than duplicated/reinvented,
// per brief-auth.md's explicit instruction to reuse this repo's
// existing address decoders.
func isValidXMRAddress(addr string) bool {
	if ok, err := xmraddress.IsValidMainnet(addr); err == nil && ok {
		return true
	}
	if ok, err := xmraddress.IsValidTestnet(addr); err == nil && ok {
		return true
	}
	return false
}

// addressTypeResponse is the JSON shape GET
// /pool/address_type/{address} returns.
type addressTypeResponse struct {
	Valid       bool   `json:"valid"`
	AddressType string `json:"address_type,omitempty"`
}

// handleAddressType implements GET /pool/address_type/{address}:
// legacy's genuinely new Tari-native address-type sniff (see
// brief-auth.md). Reuses the exact same real, byte-exact decoders
// internal/backend/addressmap already imports
// (github.com/Snipa22/go-xmr-lib/support,
// github.com/Snipa22/go-tari-lib/address) rather than writing new
// base58/decode logic. Legacy's second case was "BTC"; this stack
// validates neither Bitcoin addresses nor any BTC-specific decoder
// exists anywhere in this repo, so "TARI" is used instead per
// brief-auth.md's explicit instruction -- stated here and in the
// dispatch summary as a deliberate, non-equivalent substitution, not
// an oversight.
func (h *Handler) handleAddressType(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		writeJSON(w, http.StatusOK, addressTypeResponse{Valid: false})
		return
	}

	if isValidXMRAddress(address) {
		writeJSON(w, http.StatusOK, addressTypeResponse{Valid: true, AddressType: "XMR"})
		return
	}
	if _, err := tariaddress.Parse(address); err == nil {
		writeJSON(w, http.StatusOK, addressTypeResponse{Valid: true, AddressType: "TARI"})
		return
	}
	writeJSON(w, http.StatusOK, addressTypeResponse{Valid: false})
}
