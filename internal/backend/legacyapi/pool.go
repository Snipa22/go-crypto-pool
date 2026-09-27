package legacyapi

import (
	"net/http"

	"github.com/Snipa22/go-crypto-pool/internal/backend/networkapi"
)

// poolStatistics mirrors legacy's exact bare pool_statistics numeric
// field set (i.e. GET /pool/stats' shape, with no "fee" key) — see
// this package's doc comment for which of these render 0 (a genuine,
// flagged gap) versus a real, DB-backed value.
type poolStatistics struct {
	HashRate           float64 `json:"hashRate"`
	Miners             int64   `json:"miners"`
	TotalHashes        int64   `json:"totalHashes"`
	LastBlockFoundTime int64   `json:"lastBlockFoundTime"`
	LastBlockFound     int64   `json:"lastBlockFound"`
	TotalBlocksFound   int64   `json:"totalBlocksFound"`
	TotalMinersPaid    int64   `json:"totalMinersPaid"`
	TotalPayments      int64   `json:"totalPayments"`
	RoundHashes        int64   `json:"roundHashes"`
}

// poolStatisticsWithFee is GET /pool/stats/:pool_type's shape: the
// same fields as poolStatistics, plus the one additional "fee" key
// legacy's per-pool-type variant always carries (see this package's
// Config.PPSFeePercent/etc. doc comment for where the real value
// comes from) — a distinct type (rather than an omitempty field on
// poolStatistics itself) so a genuine, operator-configured 0% fee
// still renders "fee":0 here instead of being dropped by omitempty,
// while bare GET /pool/stats never emits a "fee" key at all.
type poolStatisticsWithFee struct {
	poolStatistics
	Fee float64 `json:"fee"`
}

// buildPoolStatistics computes poolStatistics for (algo, network)
// from the real networkapi.Repository.NetworkStatsSince aggregate —
// see this package's doc comment for exactly which fields that
// backs and which render a documented 0 placeholder instead.
func (h *Handler) buildPoolStatistics(r *http.Request, algo, network string) (poolStatistics, error) {
	since := nowUnix() - defaultWindowSeconds
	stats, err := h.network.NetworkStatsSince(r.Context(), algo, network, since)
	if err != nil {
		return poolStatistics{}, err
	}

	var lastBlockFoundTime int64
	if stats.LastBlockAt != nil {
		lastBlockFoundTime = stats.LastBlockAt.Unix()
	}
	var lastBlockFound int64
	if stats.LastBlockHeight != nil {
		lastBlockFound = *stats.LastBlockHeight
	}

	return poolStatistics{
		HashRate:           networkapi.EstimateHashrateHS(stats.SharesSum, defaultWindowSeconds),
		Miners:             0, // gap: no distinct-active-miner-count query exists anywhere in this repo
		TotalHashes:        stats.SharesSum,
		LastBlockFoundTime: lastBlockFoundTime,
		LastBlockFound:     lastBlockFound,
		TotalBlocksFound:   stats.BlocksFound,
		TotalMinersPaid:    0, // gap: no existing aggregate counts real paid-out miners
		TotalPayments:      0, // gap: no existing aggregate counts real payouts
		RoundHashes:        0, // gap: no existing aggregate is scoped to a round (since-last-block) boundary
	}, nil
}

// legacyPoolList is GET /pool/stats' own "pool_list" field: the
// static list of enabled pool types for this backend, derived from
// the real networkapi.Repository.ListPools data (filtered to
// Enabled=true, mapped to legacy's own three lowercase names, in
// legacy's own canonical pplns/pps/solo order) when that query
// returns at least one recognized, enabled pool_type; otherwise it
// falls back to the hardcoded single-element ["pplns"] list (this
// backend's original, pre-multi-pool-type default), since a genuinely
// empty ListPools result (e.g. an as-yet-unconfigured `pools` table in
// a fresh deployment) should not render an empty pool_list.
func (h *Handler) legacyPoolList(r *http.Request, algo, network string) []string {
	pools, err := h.network.ListPools(r.Context(), algo, network)
	if err != nil {
		return []string{"pplns"}
	}

	enabled := map[string]bool{}
	for _, p := range pools {
		if p.Enabled {
			enabled[p.PoolType] = true
		}
	}

	var out []string
	for _, pair := range []struct {
		legacy string
		schema string
	}{
		{"pplns", "PPLNS"},
		{"pps", "PPS"},
		{"solo", "SOLO"},
	} {
		if enabled[pair.schema] {
			out = append(out, pair.legacy)
		}
	}
	if len(out) == 0 {
		return []string{"pplns"}
	}
	return out
}

// lastPayment builds GET /pool/stats' "last_payment" field: the most
// recent real, SENT payouts row for (algo, network) (via the
// additive PayoutsRepository.ListPayouts, sourced identically to
// GET /pool/payments below), reshaped down to a small object, or the
// bare integer 0 when no payout has ever been sent — matching
// legacy's own "0-or-object" contract exactly.
func (h *Handler) lastPayment(r *http.Request, algo, network string) any {
	rows, _, err := h.payouts.ListPayouts(r.Context(), algo, network, nil, 1, 0)
	if err != nil || len(rows) == 0 {
		return 0
	}
	return legacyPaymentRow(rows[0])
}

// handlePoolStats implements GET /pool/stats.
func (h *Handler) handlePoolStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))

	stats, err := h.buildPoolStatistics(r, algo, network)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"pool_list":       h.legacyPoolList(r, algo, network),
		"pool_statistics": stats,
		"last_payment":    h.lastPayment(r, algo, network),
	})
}

// handlePoolStatsByType implements GET /pool/stats/:pool_type.
func (h *Handler) handlePoolStatsByType(w http.ResponseWriter, r *http.Request) {
	schemaPoolType, ok := legacyPoolTypeStrict(r.PathValue("pool_type"))
	if !ok {
		invalidPoolType(w)
		return
	}

	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))

	stats, err := h.buildPoolStatistics(r, algo, network)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	withFee := poolStatisticsWithFee{poolStatistics: stats, Fee: h.feePercentFor(schemaPoolType)}

	writeJSON(w, http.StatusOK, map[string]any{
		"pool_statistics": withFee,
	})
}

// feePercentFor returns this Handler's Config-supplied operator fee
// percentage for schemaPoolType (PPLNS/PPS/SOLO) — see Config's doc
// comment for why these three values are surfaced here at all.
func (h *Handler) feePercentFor(schemaPoolType string) float64 {
	switch schemaPoolType {
	case "PPLNS":
		return h.cfg.PPLNSFeePercent
	case "PPS":
		return h.cfg.PPSFeePercent
	case "SOLO":
		return h.cfg.SoloFeePercent
	default:
		return 0
	}
}

// blockResponseRow is one GET /pool/blocks[/:pool_type] row, using
// db.Block's own real field names (lowercased) as JSON keys per the
// dispatch brief's explicit instruction — see this package's doc
// comment for the pool_type int-vs-string-enum shape difference this
// deliberately does NOT paper over.
type blockResponseRow struct {
	Height     int64  `json:"height"`
	Hash       string `json:"hash"`
	Difficulty int64  `json:"difficulty"`
	Shares     int64  `json:"shares"`
	Timestamp  int64  `json:"timestamp"`
	Valid      bool   `json:"valid"`
	Unlocked   bool   `json:"unlocked"`
	Value      *int64 `json:"value"`
	PoolType   string `json:"pool_type"`
}

func legacyBlockRow(b BlockRecord) blockResponseRow {
	return blockResponseRow{
		Height:     b.Height,
		Hash:       b.Hash,
		Difficulty: b.Difficulty,
		Shares:     b.Shares,
		Timestamp:  b.Timestamp,
		Valid:      b.Valid,
		Unlocked:   b.Unlocked,
		Value:      b.Value,
		PoolType:   b.PoolType,
	}
}

func (h *Handler) listBlocksResponse(w http.ResponseWriter, r *http.Request, poolType string) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))

	limit, offset, err := parseLegacyLimitPage(q)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	rows, err := h.blocks.ListBlocks(r.Context(), algo, network, poolType, limit, offset)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]blockResponseRow, 0, len(rows))
	for _, b := range rows {
		out = append(out, legacyBlockRow(b))
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePoolBlocks implements GET /pool/blocks.
func (h *Handler) handlePoolBlocks(w http.ResponseWriter, r *http.Request) {
	h.listBlocksResponse(w, r, "")
}

// handlePoolBlocksByType implements GET /pool/blocks/:pool_type. Per
// this package's doc comment, an unrecognized pool_type is not
// rejected with a 400 here (unlike /pool/stats/:pool_type) — it is
// upper-cased and passed straight through as a plain equality filter,
// which simply matches zero rows for a genuinely bogus value.
func (h *Handler) handlePoolBlocksByType(w http.ResponseWriter, r *http.Request) {
	h.listBlocksResponse(w, r, legacyPoolTypeLoose(r.PathValue("pool_type")))
}

// paymentResponseRow is one GET /pool/payments[/:pool_type] or
// GET /miner/:address/payments row — see this package's doc comment
// for the mixins/payees/pool_type gaps this deliberately documents
// rather than papers over.
type paymentResponseRow struct {
	ID     int64  `json:"id"`
	Hash   string `json:"hash"`
	Mixins int    `json:"mixins"`
	Payees int    `json:"payees"`
	Fee    int64  `json:"fee"`
	Value  int64  `json:"value"`
	TS     int64  `json:"ts"`
}

func legacyPaymentRow(p PayoutRecord) paymentResponseRow {
	var hash string
	if p.TxHash != nil {
		hash = *p.TxHash
	}
	var fee int64
	if p.Fee != nil {
		fee = *p.Fee
	}
	var ts int64
	if p.CompletedAt != nil {
		ts = p.CompletedAt.Unix()
	}
	return paymentResponseRow{
		ID:     p.ID,
		Hash:   hash,
		Mixins: 0, // gap: no ring-size/mixin column exists in this schema's payouts table
		Payees: len(p.BalanceIDs),
		Fee:    fee,
		Value:  p.Amount,
		TS:     ts,
	}
}

func (h *Handler) listPaymentsResponse(w http.ResponseWriter, r *http.Request, paymentAddress *string) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))

	limit, offset, err := parseLegacyLimitPage(q)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, err.Error())
		return
	}

	rows, _, err := h.payouts.ListPayouts(r.Context(), algo, network, paymentAddress, limit, offset)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]paymentResponseRow, 0, len(rows))
	for _, p := range rows {
		out = append(out, legacyPaymentRow(p))
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePoolPayments implements GET /pool/payments.
func (h *Handler) handlePoolPayments(w http.ResponseWriter, r *http.Request) {
	h.listPaymentsResponse(w, r, nil)
}

// handlePoolPaymentsByType implements GET /pool/payments/:pool_type.
// The pool_type path segment is accepted (so legacy clients that
// always pass one don't get a 404) but silently ignored — see this
// package's doc comment: `payouts` has no pool_type column to filter
// against in this schema.
func (h *Handler) handlePoolPaymentsByType(w http.ResponseWriter, r *http.Request) {
	h.listPaymentsResponse(w, r, nil)
}

// handleMinerPayments implements GET /miner/:address/payments.
func (h *Handler) handleMinerPayments(w http.ResponseWriter, r *http.Request) {
	address, _ := splitLegacyAddress(r.PathValue("address"))
	h.listPaymentsResponse(w, r, &address)
}
