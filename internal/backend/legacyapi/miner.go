// miner.go implements every SXMR-legacy-shaped, single-miner-scoped
// endpoint: GET /miner/:address/identifiers and the
// GET /miner/:address/stats[/allWorkers|/:identifier] family.
package legacyapi

import (
	"net/http"
)

// handleMinerIdentifiers implements GET /miner/:address/identifiers:
// a flat JSON array of worker-name strings, using the real, additive
// IdentifiersRepository.MinerIdentifiersSince query with the exact
// same 10-minute freshness window legacy's own handler used (workers
// that haven't submitted a share in the last 10 minutes are not
// considered "currently seen", matching legacy's own semantics — see
// migrations' miner_identifiers.last_share column comment).
func (h *Handler) handleMinerIdentifiers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))
	address, paymentID := splitLegacyAddress(r.PathValue("address"))

	since := nowUnix() - identifiersFreshWindowSeconds
	rows, err := h.idents.MinerIdentifiersSince(r.Context(), algo, network, address, paymentID, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	out := make([]string, 0, len(rows))
	for _, ident := range rows {
		out = append(out, ident.WorkerName)
	}
	writeJSON(w, http.StatusOK, out)
}

// minerStatRow is legacy's exact per-worker shape — note "identifer"
// is legacy's own real misspelling (kept verbatim, not corrected, per
// the dispatch brief's explicit instruction). "invalidShares" always
// renders 0 — see this package's doc comment (this schema's `shares`
// table only ever stores accepted shares; there is no possible query
// to source a real invalid/rejected count from).
type minerStatRow struct {
	LTS           int64   `json:"lts"`
	Identifer     string  `json:"identifer"`
	Hash          float64 `json:"hash"`
	TotalHash     int64   `json:"totalHash"`
	ValidShares   int64   `json:"validShares"`
	InvalidShares int64   `json:"invalidShares"`
}

// minerStatRowWithBalance is the bare GET /miner/:address/stats
// shape: minerStatRow's fields (aggregated across every worker, with
// an empty Identifer — this is a whole-address aggregate, not any one
// worker's own row) plus the paid/unpaid/payment-count fields legacy
// only ever attached to the bare, non-worker-scoped request.
type minerStatRowWithBalance struct {
	minerStatRow
	AmtPaid  int64 `json:"amtPaid"`
	AmtDue   int64 `json:"amtDue"`
	TxnCount int64 `json:"txnCount"`
}

// lastSeenUnix returns the most recent LastShare across rows, or 0 if
// rows is empty or every row's LastShare is nil.
func lastSeenUnix(rows []IdentifierRecord) int64 {
	var max int64
	for _, r := range rows {
		if r.LastShare == nil {
			continue
		}
		if u := r.LastShare.Unix(); u > max {
			max = u
		}
	}
	return max
}

// buildMinerStatRow assembles a minerStatRow from an already-computed
// share aggregate (sharesSum/shareCount — either the whole-address
// aggregate or one worker's own aggregate) plus that row's LTS and
// identifer. This is the one, shared place the lts/hash/totalHash/
// validShares/invalidShares computation lives, so
// handleMinerStats (identifer="") and handleMinerStatsAllWorkers
// (identifer="global" for its address-wide aggregate row, and each
// worker's own identifier for its per-worker rows) never duplicate it.
func buildMinerStatRow(lts, sharesSum, shareCount int64, identifer string) minerStatRow {
	return minerStatRow{
		LTS:           lts,
		Identifer:     identifer,
		Hash:          estimateHashrateHS(sharesSum, defaultWindowSeconds),
		TotalHash:     sharesSum,
		ValidShares:   shareCount,
		InvalidShares: 0,
	}
}

// handleMinerStats implements GET /miner/:address/stats: the
// whole-address aggregate (ShareStatsSince, summed across every
// worker) plus the real amtPaid/amtDue (summed pending/paid balance
// via statsapi.Repository.MinerBalances) and txnCount (the real
// number of SENT payouts for this address, via the additive
// PayoutsRepository.ListPayouts — capped at a generous limit rather
// than a dedicated COUNT query, since ListPayouts already returns an
// exact total alongside its page of rows).
func (h *Handler) handleMinerStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))
	address, paymentID := splitLegacyAddress(r.PathValue("address"))

	since := nowUnix() - defaultWindowSeconds
	shareStats, err := h.stats.ShareStatsSince(r.Context(), algo, network, address, paymentID, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	idents, err := h.idents.MinerIdentifiersSince(r.Context(), algo, network, address, paymentID, identifiersAllTimeSince)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	balances, err := h.stats.MinerBalances(r.Context(), address, algo, network, paymentID)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	var amtPaid, amtDue int64
	for _, b := range balances {
		amtPaid += b.PaidBalance
		amtDue += b.PendingBalance
	}

	_, txnCount, err := h.payouts.ListPayouts(r.Context(), algo, network, &address, 1, 0)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, minerStatRowWithBalance{
		minerStatRow: buildMinerStatRow(lastSeenUnix(idents), shareStats.SharesSum, shareStats.ShareCount, ""),
		AmtPaid:      amtPaid,
		AmtDue:       amtDue,
		TxnCount:     txnCount,
	})
}

// handleMinerStatsAllWorkers implements
// GET /miner/:address/stats/allWorkers, matching legacy's own
// getAllWorkerStats shape: a JSON OBJECT keyed by worker identifier,
// PLUS a "global" key holding the same address-wide aggregate
// handleMinerStats computes for its own bare, non-worker-scoped
// response (built via the same shared buildMinerStatRow helper, with
// Identifer forced to the literal string "global" rather than
// handleMinerStats's own empty string). The worker-identifier KEY SET
// is sourced the same way handleMinerHashrateChartAllWorkers sources
// its own key set (every worker this address has ever registered —
// see that handler's doc comment), not merely from whichever workers
// happen to have a nonzero share sum in this window.
func (h *Handler) handleMinerStatsAllWorkers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))
	address, paymentID := splitLegacyAddress(r.PathValue("address"))

	since := nowUnix() - defaultWindowSeconds
	globalStats, err := h.stats.ShareStatsSince(r.Context(), algo, network, address, paymentID, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	workerStats, err := h.stats.WorkerShareStatsSince(r.Context(), algo, network, address, paymentID, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	idents, err := h.idents.MinerIdentifiersSince(r.Context(), algo, network, address, paymentID, identifiersAllTimeSince)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	type workerAgg struct {
		sharesSum  int64
		shareCount int64
	}
	byWorker := make(map[string]workerAgg, len(workerStats.Rows))
	for _, ws := range workerStats.Rows {
		byWorker[ws.Identifier] = workerAgg{sharesSum: ws.SharesSum, shareCount: ws.ShareCount}
	}

	out := make(map[string]minerStatRow, len(idents)+1)
	out["global"] = buildMinerStatRow(lastSeenUnix(idents), globalStats.SharesSum, globalStats.ShareCount, "global")
	for _, ident := range idents {
		agg := byWorker[ident.WorkerName]
		var lts int64
		if ident.LastShare != nil {
			lts = ident.LastShare.Unix()
		}
		out[ident.WorkerName] = buildMinerStatRow(lts, agg.sharesSum, agg.shareCount, ident.WorkerName)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleMinerStatsWorker implements
// GET /miner/:address/stats/:identifier: the single-worker analogue
// of handleMinerStatsAllWorkers, filtered down to the one matching
// identifier (a zero-valued row if that identifier has never been
// registered for this address).
func (h *Handler) handleMinerStatsWorker(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))
	address, paymentID := splitLegacyAddress(r.PathValue("address"))
	identifier := r.PathValue("identifier")

	since := nowUnix() - defaultWindowSeconds
	workerStats, err := h.stats.WorkerShareStatsSince(r.Context(), algo, network, address, paymentID, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	idents, err := h.idents.MinerIdentifiersSince(r.Context(), algo, network, address, paymentID, identifiersAllTimeSince)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	var sharesSum, shareCount int64
	for _, ws := range workerStats.Rows {
		if ws.Identifier == identifier {
			sharesSum, shareCount = ws.SharesSum, ws.ShareCount
			break
		}
	}
	var lts int64
	for _, ident := range idents {
		if ident.WorkerName == identifier && ident.LastShare != nil {
			lts = ident.LastShare.Unix()
			break
		}
	}

	writeJSON(w, http.StatusOK, minerStatRow{
		LTS:           lts,
		Identifer:     identifier,
		Hash:          estimateHashrateHS(sharesSum, defaultWindowSeconds),
		TotalHash:     sharesSum,
		ValidShares:   shareCount,
		InvalidShares: 0,
	})
}
