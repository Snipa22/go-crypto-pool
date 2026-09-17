// charts.go implements every SXMR-legacy-shaped chart endpoint. Legacy
// sourced these from a Redis rolling-history list this backend has no
// equivalent of — see this package's doc comment for the "real,
// flagged gap" this deliberately does not paper over: every endpoint
// here returns a SINGLE-POINT array (`[{ts: <now>, ...: <value>}]`)
// computed from the real current window query, not fabricated
// retained history.
package legacyapi

import (
	"net/http"
)

// hashratePoint is one entry in every hashrate-shaped chart array
// below.
type hashratePoint struct {
	TS   int64   `json:"ts"`
	Hash float64 `json:"hash"`
}

// difficultyPoint is one entry in GET /network/chart/difficulty's
// array.
type difficultyPoint struct {
	TS   int64   `json:"ts"`
	Diff float64 `json:"diff"`
}

// minersPoint is one entry in GET /pool/chart/miners[/:pool_type]'s
// array. Always renders Miners: 0 — see this package's doc comment
// (no distinct-active-miner-count query exists anywhere in this
// repo).
type minersPoint struct {
	TS     int64 `json:"ts"`
	Miners int64 `json:"miners"`
}

// handlePoolHashrateChart implements GET /pool/chart/hashrate.
func (h *Handler) handlePoolHashrateChart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))

	since := nowUnix() - defaultWindowSeconds
	stats, err := h.network.NetworkStatsSince(r.Context(), algo, network, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, []hashratePoint{{
		TS:   nowUnix(),
		Hash: estimateHashrateHS(stats.SharesSum, defaultWindowSeconds),
	}})
}

// handlePoolHashrateChartByType implements
// GET /pool/chart/hashrate/:pool_type. See this package's doc comment:
// the backing NetworkStatsSince aggregate is not pool_type-scoped, so
// the pool_type path segment is validated (400 on garbage, matching
// legacy) but the single returned value is this algo/network's whole
// figure, not narrowed to just that pool_type.
func (h *Handler) handlePoolHashrateChartByType(w http.ResponseWriter, r *http.Request) {
	if _, ok := legacyPoolTypeStrict(r.PathValue("pool_type")); !ok {
		invalidPoolType(w)
		return
	}
	h.handlePoolHashrateChart(w, r)
}

// handleNetworkDifficultyChart implements
// GET /network/chart/difficulty — sourced from the real, live chain
// difficulty internal/backend/networkpoller records (networkapi's own
// NetworkStatsRecord.NetworkDifficulty), which is nil (rendered here
// as 0) whenever no poller has ever recorded a snapshot for this
// (algo, network) — see networkapi.NetworkStatsRecord's own doc
// comment.
func (h *Handler) handleNetworkDifficultyChart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))

	since := nowUnix() - defaultWindowSeconds
	stats, err := h.network.NetworkStatsSince(r.Context(), algo, network, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	var diff float64
	if stats.NetworkDifficulty != nil {
		diff = *stats.NetworkDifficulty
	}

	writeJSON(w, http.StatusOK, []difficultyPoint{{TS: nowUnix(), Diff: diff}})
}

// handlePoolMinersChart implements GET /pool/chart/miners.
func (h *Handler) handlePoolMinersChart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []minersPoint{{TS: nowUnix(), Miners: 0}})
}

// handlePoolMinersChartByType implements
// GET /pool/chart/miners/:pool_type.
func (h *Handler) handlePoolMinersChartByType(w http.ResponseWriter, r *http.Request) {
	if _, ok := legacyPoolTypeStrict(r.PathValue("pool_type")); !ok {
		invalidPoolType(w)
		return
	}
	writeJSON(w, http.StatusOK, []minersPoint{{TS: nowUnix(), Miners: 0}})
}

// handleMinerHashrateChart implements
// GET /miner/:address/chart/hashrate.
func (h *Handler) handleMinerHashrateChart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	algo := resolveAlgo(q.Get("algo"))
	network := h.resolveNetwork(q.Get("network"))
	address, paymentID := splitLegacyAddress(r.PathValue("address"))

	since := nowUnix() - defaultWindowSeconds
	stats, err := h.stats.ShareStatsSince(r.Context(), algo, network, address, paymentID, since)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, []hashratePoint{{
		TS:   nowUnix(),
		Hash: estimateHashrateHS(stats.SharesSum, defaultWindowSeconds),
	}})
}

// handleMinerHashrateChartAllWorkers implements
// GET /miner/:address/chart/hashrate/allWorkers, matching legacy's
// own getAllWorkerHashCharts shape: {"global": [...], "<identifier>":
// [...], ...} — one single-point array per key. The worker-identifier
// KEY SET is sourced from the real, additive
// IdentifiersRepository.MinerIdentifiersSince query (every worker this
// address has ever registered — see that method's doc comment on
// sinceUnix=identifiersAllTimeSince), not merely from whichever
// workers happen to have a nonzero share sum in this window, so a
// worker with zero recent activity still gets its own (zero-valued)
// entry instead of silently vanishing from the response.
func (h *Handler) handleMinerHashrateChartAllWorkers(w http.ResponseWriter, r *http.Request) {
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

	sums := make(map[string]int64, len(workerStats.Rows))
	for _, ws := range workerStats.Rows {
		sums[ws.Identifier] = ws.SharesSum
	}

	now := nowUnix()
	out := map[string]any{
		"global": []hashratePoint{{TS: now, Hash: estimateHashrateHS(globalStats.SharesSum, defaultWindowSeconds)}},
	}
	for _, ident := range idents {
		out[ident.WorkerName] = []hashratePoint{{
			TS:   now,
			Hash: estimateHashrateHS(sums[ident.WorkerName], defaultWindowSeconds),
		}}
	}

	writeJSON(w, http.StatusOK, out)
}

// handleMinerHashrateChartWorker implements
// GET /miner/:address/chart/hashrate/:identifier — the single-worker
// analogue of handleMinerHashrateChartAllWorkers, sourced from the
// same WorkerShareStatsSince aggregate filtered down to the one
// matching identifier (0 if that identifier has no activity in the
// current window).
func (h *Handler) handleMinerHashrateChartWorker(w http.ResponseWriter, r *http.Request) {
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

	var sharesSum int64
	for _, ws := range workerStats.Rows {
		if ws.Identifier == identifier {
			sharesSum = ws.SharesSum
			break
		}
	}

	writeJSON(w, http.StatusOK, []hashratePoint{{
		TS:   nowUnix(),
		Hash: estimateHashrateHS(sharesSum, defaultWindowSeconds),
	}})
}

// estimateHashrateHS mirrors statsapi.EstimateHashrateHS/
// networkapi.EstimateHashrateHS exactly (see either's doc comment for
// the formula/caveats) — this package calls into both statsapi's and
// networkapi's own Repository interfaces depending on the endpoint, so
// rather than pick one package's copy to import by name for every
// call site, this is its own trivial, identical copy.
func estimateHashrateHS(sharesSum int64, windowSeconds int64) float64 {
	if sharesSum <= 0 || windowSeconds <= 0 {
		return 0
	}
	return float64(sharesSum) * 4294967296 / float64(windowSeconds)
}
