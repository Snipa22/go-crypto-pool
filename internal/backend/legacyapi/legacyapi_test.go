package legacyapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/addressmap"
	"github.com/Snipa22/go-crypto-pool/internal/backend/networkapi"
	"github.com/Snipa22/go-crypto-pool/internal/backend/statsapi"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

var errTest = errors.New("test: injected failure")

// --- fakes -----------------------------------------------------------

type fakeNetworkRepo struct {
	pools []networkapi.PoolRecord
	stats networkapi.NetworkStatsRecord
	err   error

	gotAlgo, gotNetwork string
}

func (f *fakeNetworkRepo) ListPools(_ context.Context, algo, network string) ([]networkapi.PoolRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork = algo, network
	return f.pools, nil
}

func (f *fakeNetworkRepo) NetworkStatsSince(_ context.Context, algo, network string, _ int64) (networkapi.NetworkStatsRecord, error) {
	if f.err != nil {
		return networkapi.NetworkStatsRecord{}, f.err
	}
	f.gotAlgo, f.gotNetwork = algo, network
	return f.stats, nil
}

type fakeStatsRepo struct {
	balances    []statsapi.BalanceRecord
	shareStats  statsapi.ShareStatsRecord
	workerStats []statsapi.WorkerShareStatsRecord
	err         error

	gotAlgo, gotNetwork, gotAddr string
	gotPaymentID                 *string
}

func (f *fakeStatsRepo) MinerBalances(_ context.Context, paymentAddress, algo, network string, paymentID *string) ([]statsapi.BalanceRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAddr, f.gotAlgo, f.gotNetwork, f.gotPaymentID = paymentAddress, algo, network, paymentID
	return f.balances, nil
}

func (f *fakeStatsRepo) ShareStatsSince(_ context.Context, algo, network, paymentAddress string, paymentID *string, _ int64) (statsapi.ShareStatsRecord, error) {
	if f.err != nil {
		return statsapi.ShareStatsRecord{}, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID = algo, network, paymentAddress, paymentID
	return f.shareStats, nil
}

func (f *fakeStatsRepo) WorkerShareStatsSince(_ context.Context, algo, network, paymentAddress string, paymentID *string, _ int64) ([]statsapi.WorkerShareStatsRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID = algo, network, paymentAddress, paymentID
	return f.workerStats, nil
}

func (f *fakeStatsRepo) PoolSourceShareStatsSince(_ context.Context, _, _, _ string, _ *string, _ int64) ([]statsapi.PoolSourceShareStatsRecord, error) {
	return nil, nil
}

type fakeAddrMapRepo struct {
	rec addressmap.Record
	err error

	gotXMR, gotTari string
}

func (f *fakeAddrMapRepo) Upsert(_ context.Context, xmrAddress, tariAddress string) error {
	if f.err != nil {
		return f.err
	}
	f.gotXMR, f.gotTari = xmrAddress, tariAddress
	return nil
}

func (f *fakeAddrMapRepo) Get(_ context.Context, xmrAddress string) (addressmap.Record, error) {
	f.gotXMR = xmrAddress
	if f.err != nil {
		return addressmap.Record{}, f.err
	}
	return f.rec, nil
}

type fakeBlocksRepo struct {
	rows []BlockRecord
	err  error

	gotAlgo, gotNetwork, gotPoolType string
	gotLimit, gotOffset              int
}

func (f *fakeBlocksRepo) ListBlocks(_ context.Context, algo, network, poolType string, limit, offset int) ([]BlockRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotPoolType, f.gotLimit, f.gotOffset = algo, network, poolType, limit, offset
	return f.rows, nil
}

type fakePayoutsRepo struct {
	rows  []PayoutRecord
	total int64
	err   error

	gotAlgo, gotNetwork string
	gotAddr             *string
	gotLimit, gotOffset int
}

func (f *fakePayoutsRepo) ListPayouts(_ context.Context, algo, network string, paymentAddress *string, limit, offset int) ([]PayoutRecord, int64, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotLimit, f.gotOffset = algo, network, paymentAddress, limit, offset
	return f.rows, f.total, nil
}

type fakeIdentsRepo struct {
	rows []IdentifierRecord
	err  error

	gotAlgo, gotNetwork, gotAddr string
	gotPaymentID                 *string
	gotSince                     int64
}

func (f *fakeIdentsRepo) MinerIdentifiersSince(_ context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]IdentifierRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID, f.gotSince = algo, network, paymentAddress, paymentID, sinceUnix
	return f.rows, nil
}

// --- helpers ----------------------------------------------------------

type testDeps struct {
	network *fakeNetworkRepo
	stats   *fakeStatsRepo
	addrMap *fakeAddrMapRepo
	blocks  *fakeBlocksRepo
	payouts *fakePayoutsRepo
	idents  *fakeIdentsRepo
}

func newTestHandler(cfg Config) (*Handler, *testDeps) {
	d := &testDeps{
		network: &fakeNetworkRepo{},
		stats:   &fakeStatsRepo{},
		addrMap: &fakeAddrMapRepo{},
		blocks:  &fakeBlocksRepo{},
		payouts: &fakePayoutsRepo{},
		idents:  &fakeIdentsRepo{},
	}
	h := NewHandler(d.network, d.stats, d.addrMap, d.blocks, d.payouts, d.idents, cfg)
	return h, d
}

func doGet(t *testing.T, mux *http.ServeMux, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func doPost(t *testing.T, mux *http.ServeMux, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// --- /pool/stats --------------------------------------------------------

func TestHandlePoolStats_OK(t *testing.T) {
	h, d := newTestHandler(Config{Network: poolpb.Network_NETWORK_TESTNET})
	height := int64(555)
	d.network.stats = networkapi.NetworkStatsRecord{SharesSum: 1000, ShareCount: 4, BlocksFound: 2, LastBlockHeight: &height}
	d.network.pools = []networkapi.PoolRecord{{PoolType: "PPLNS", Enabled: true}, {PoolType: "SOLO", Enabled: false}}

	rr := doGet(t, h.Mux(), "/pool/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if d.network.gotAlgo != DefaultAlgo {
		t.Errorf("gotAlgo = %q, want %q", d.network.gotAlgo, DefaultAlgo)
	}
	if d.network.gotNetwork != "TESTNET" {
		t.Errorf("gotNetwork = %q, want TESTNET (defaulted from Config.Network)", d.network.gotNetwork)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	poolList, ok := body["pool_list"].([]any)
	if !ok || len(poolList) != 1 || poolList[0] != "pplns" {
		t.Fatalf("pool_list = %v, want [\"pplns\"] (SOLO disabled)", body["pool_list"])
	}
	stats, ok := body["pool_statistics"].(map[string]any)
	if !ok {
		t.Fatalf("pool_statistics missing or wrong type: %v", body["pool_statistics"])
	}
	if _, hasFee := stats["fee"]; hasFee {
		t.Errorf("bare /pool/stats must not include a fee key, got %v", stats["fee"])
	}
	if stats["totalHashes"].(float64) != 1000 {
		t.Errorf("totalHashes = %v, want 1000", stats["totalHashes"])
	}
	if stats["totalBlocksFound"].(float64) != 2 {
		t.Errorf("totalBlocksFound = %v, want 2", stats["totalBlocksFound"])
	}
	if stats["lastBlockFound"].(float64) != 555 {
		t.Errorf("lastBlockFound = %v, want 555", stats["lastBlockFound"])
	}
	// Documented gaps must render exactly 0.
	for _, k := range []string{"miners", "totalMinersPaid", "totalPayments", "roundHashes"} {
		if stats[k].(float64) != 0 {
			t.Errorf("%s = %v, want 0 (documented gap)", k, stats[k])
		}
	}
	if body["last_payment"].(float64) != 0 {
		t.Errorf("last_payment = %v, want 0 (no payouts)", body["last_payment"])
	}
}

func TestHandlePoolStats_PoolListFallback(t *testing.T) {
	h, d := newTestHandler(Config{Network: poolpb.Network_NETWORK_TESTNET})
	d.network.pools = nil // nothing configured

	rr := doGet(t, h.Mux(), "/pool/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	poolList := body["pool_list"].([]any)
	if len(poolList) != 1 || poolList[0] != "pplns" {
		t.Fatalf("pool_list = %v, want fallback [\"pplns\"]", poolList)
	}
}

func TestHandlePoolStats_LastPayment(t *testing.T) {
	h, d := newTestHandler(Config{Network: poolpb.Network_NETWORK_TESTNET})
	fee := int64(10)
	txHash := "abc123"
	completedAt := time.Unix(5000, 0)
	d.payouts.rows = []PayoutRecord{{ID: 7, Status: "SENT", BalanceIDs: []int64{1, 2}, Amount: 900, Fee: &fee, TxHash: &txHash, CompletedAt: &completedAt}}

	rr := doGet(t, h.Mux(), "/pool/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	lp, ok := body["last_payment"].(map[string]any)
	if !ok {
		t.Fatalf("last_payment = %v, want object", body["last_payment"])
	}
	if lp["id"].(float64) != 7 || lp["hash"] != "abc123" || lp["payees"].(float64) != 2 || lp["value"].(float64) != 900 {
		t.Errorf("unexpected last_payment: %+v", lp)
	}
}

// --- /pool/stats/:pool_type ---------------------------------------------

func TestHandlePoolStatsByType_OK(t *testing.T) {
	h, d := newTestHandler(Config{Network: poolpb.Network_NETWORK_TESTNET, PPLNSFeePercent: 1.5})
	d.network.stats = networkapi.NetworkStatsRecord{SharesSum: 500}

	rr := doGet(t, h.Mux(), "/pool/stats/pplns")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	stats := body["pool_statistics"].(map[string]any)
	if stats["fee"].(float64) != 1.5 {
		t.Errorf("fee = %v, want 1.5", stats["fee"])
	}
}

func TestHandlePoolStatsByType_InvalidPoolType(t *testing.T) {
	h, _ := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/pool/stats/bogus")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] != "Invalid pool type" {
		t.Errorf("error = %q, want exact legacy message", body["error"])
	}
}

// --- /pool/ports ---------------------------------------------------------

func TestHandlePoolPorts_OK(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.network.pools = []networkapi.PoolRecord{
		{Algo: "RXM", Network: "TESTNET", PoolType: "PPLNS", Enabled: true, Ports: []networkapi.PortRecord{
			{Port: 3333, Description: "low", StartDifficulty: 100},
		}},
		{Algo: "RXM", Network: "TESTNET", PoolType: "SOLO", Enabled: false, Ports: []networkapi.PortRecord{
			{Port: 4444, Description: "disabled-pool"},
		}},
	}

	rr := doGet(t, h.Mux(), "/pool/ports")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var rows []legacyPortRow
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rows) != 1 || rows[0].Port != 3333 || rows[0].Difficulty != 100 {
		t.Fatalf("unexpected ports: %+v", rows)
	}
}

// --- charts ---------------------------------------------------------------

func TestHandlePoolHashrateChart_SinglePoint(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.network.stats = networkapi.NetworkStatsRecord{SharesSum: 4294967296} // exactly one "hash" worth

	rr := doGet(t, h.Mux(), "/pool/chart/hashrate")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var points []hashratePoint
	if err := json.Unmarshal(rr.Body.Bytes(), &points); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1 (single-point, not fabricated history)", len(points))
	}
	want := estimateHashrateHS(4294967296, defaultWindowSeconds)
	if points[0].Hash != want {
		t.Errorf("hash = %v, want %v", points[0].Hash, want)
	}
}

func TestHandlePoolHashrateChartByType_InvalidPoolType(t *testing.T) {
	h, _ := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/pool/chart/hashrate/bogus")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandlePoolMinersChart_AlwaysZero(t *testing.T) {
	h, _ := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/pool/chart/miners")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var points []minersPoint
	_ = json.Unmarshal(rr.Body.Bytes(), &points)
	if len(points) != 1 || points[0].Miners != 0 {
		t.Fatalf("unexpected points: %+v", points)
	}
}

func TestHandleNetworkDifficultyChart_NilRendersZero(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.network.stats = networkapi.NetworkStatsRecord{NetworkDifficulty: nil}
	rr := doGet(t, h.Mux(), "/network/chart/difficulty")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var points []difficultyPoint
	_ = json.Unmarshal(rr.Body.Bytes(), &points)
	if len(points) != 1 || points[0].Diff != 0 {
		t.Fatalf("unexpected points: %+v", points)
	}
}

func TestHandleMinerHashrateChartAllWorkers_Shape(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.stats.shareStats = statsapi.ShareStatsRecord{SharesSum: 100}
	d.stats.workerStats = []statsapi.WorkerShareStatsRecord{{Identifier: "rig1", SharesSum: 60}}
	d.idents.rows = []IdentifierRecord{{WorkerName: "rig1"}, {WorkerName: "rig2"}}

	rr := doGet(t, h.Mux(), "/miner/addr-1/chart/hashrate/allWorkers")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body map[string][]hashratePoint
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := body["global"]; !ok {
		t.Fatalf("missing global key: %+v", body)
	}
	if _, ok := body["rig1"]; !ok {
		t.Fatalf("missing rig1 key (has activity): %+v", body)
	}
	if _, ok := body["rig2"]; !ok {
		t.Fatalf("missing rig2 key (registered but zero activity, must still appear): %+v", body)
	}
	if body["rig2"][0].Hash != 0 {
		t.Errorf("rig2 hash = %v, want 0 (no activity in window)", body["rig2"][0].Hash)
	}
}

func TestHandleMinerHashrateChartWorker_UnknownIdentifierIsZero(t *testing.T) {
	h, _ := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/miner/addr-1/chart/hashrate/nosuchrig")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var points []hashratePoint
	_ = json.Unmarshal(rr.Body.Bytes(), &points)
	if len(points) != 1 || points[0].Hash != 0 {
		t.Fatalf("unexpected points: %+v", points)
	}
}

// --- /pool/blocks ---------------------------------------------------------

func TestHandlePoolBlocks_Defaults(t *testing.T) {
	h, d := newTestHandler(Config{Network: poolpb.Network_NETWORK_TESTNET})
	val := int64(12345)
	d.blocks.rows = []BlockRecord{{Height: 100, Hash: "h1", Difficulty: 200, Shares: 300, Timestamp: 400, Valid: true, Unlocked: true, Value: &val, PoolType: "PPLNS"}}

	rr := doGet(t, h.Mux(), "/pool/blocks")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if d.blocks.gotLimit != defaultLegacyLimit || d.blocks.gotOffset != 0 {
		t.Errorf("limit/offset = %d/%d, want %d/0", d.blocks.gotLimit, d.blocks.gotOffset, defaultLegacyLimit)
	}
	if d.blocks.gotPoolType != "" {
		t.Errorf("gotPoolType = %q, want empty (bare /pool/blocks)", d.blocks.gotPoolType)
	}
	if d.blocks.gotAlgo != DefaultAlgo {
		t.Errorf("gotAlgo = %q, want %q", d.blocks.gotAlgo, DefaultAlgo)
	}

	var rows []blockResponseRow
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rows) != 1 || rows[0].Hash != "h1" || rows[0].PoolType != "PPLNS" || *rows[0].Value != 12345 {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestHandlePoolBlocks_LimitPage(t *testing.T) {
	h, d := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/pool/blocks?limit=10&page=2")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if d.blocks.gotLimit != 10 || d.blocks.gotOffset != 20 {
		t.Errorf("limit/offset = %d/%d, want 10/20", d.blocks.gotLimit, d.blocks.gotOffset)
	}
}

func TestHandlePoolBlocks_InvalidLimit(t *testing.T) {
	h, _ := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/pool/blocks?limit=abc")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandlePoolBlocksByType_LoosePassthrough(t *testing.T) {
	h, d := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/pool/blocks/pplns")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if d.blocks.gotPoolType != "PPLNS" {
		t.Errorf("gotPoolType = %q, want PPLNS", d.blocks.gotPoolType)
	}

	// A garbage pool_type is NOT rejected with 400 here (unlike
	// /pool/stats/:pool_type) -- it is passed straight through
	// upper-cased.
	rr2 := doGet(t, h.Mux(), "/pool/blocks/garbage")
	if rr2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (loose passthrough)", rr2.Code)
	}
	if d.blocks.gotPoolType != "GARBAGE" {
		t.Errorf("gotPoolType = %q, want GARBAGE", d.blocks.gotPoolType)
	}
}

// --- /pool/payments, /miner/:address/payments -----------------------------

func TestHandlePoolPayments_Shape(t *testing.T) {
	h, d := newTestHandler(Config{})
	fee := int64(5)
	hash := "deadbeef"
	completedAt := time.Unix(1000, 0)
	d.payouts.rows = []PayoutRecord{{ID: 1, BalanceIDs: []int64{10, 11, 12}, Amount: 900, Fee: &fee, TxHash: &hash, CompletedAt: &completedAt}}

	rr := doGet(t, h.Mux(), "/pool/payments")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var rows []paymentResponseRow
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Mixins != 0 {
		t.Errorf("mixins = %d, want 0 (documented placeholder)", r.Mixins)
	}
	if r.Payees != 3 {
		t.Errorf("payees = %d, want 3 (len(balance_ids))", r.Payees)
	}
	if r.Fee != 5 || r.Value != 900 || r.TS != 1000 || r.Hash != "deadbeef" {
		t.Errorf("unexpected row: %+v", r)
	}
}

func TestHandleMinerPayments_ScopesByAddress(t *testing.T) {
	h, d := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/miner/my-addr.paymentid123/payments")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if d.payouts.gotAddr == nil || *d.payouts.gotAddr != "my-addr" {
		t.Errorf("gotAddr = %v, want my-addr (payment id split off)", d.payouts.gotAddr)
	}
}

func TestHandlePoolPaymentsByType_IgnoresPoolType(t *testing.T) {
	h, _ := newTestHandler(Config{})
	rr := doGet(t, h.Mux(), "/pool/payments/pplns")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (pool_type accepted but ignored)", rr.Code)
	}
}

// --- /miner/:address/identifiers ------------------------------------------

func TestHandleMinerIdentifiers_FlatArray(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.idents.rows = []IdentifierRecord{{WorkerName: "rig1"}, {WorkerName: "rig2"}}

	rr := doGet(t, h.Mux(), "/miner/addr-1/identifiers")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var names []string
	if err := json.Unmarshal(rr.Body.Bytes(), &names); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(names) != 2 || names[0] != "rig1" || names[1] != "rig2" {
		t.Fatalf("unexpected names: %v", names)
	}
	wantSince := nowUnix() - identifiersFreshWindowSeconds
	if d.idents.gotSince < wantSince-2 || d.idents.gotSince > wantSince+2 {
		t.Errorf("gotSince = %d, want ~%d (10-minute freshness window)", d.idents.gotSince, wantSince)
	}
}

func TestHandleMinerIdentifiers_AddressPaymentIDSplit(t *testing.T) {
	h, d := newTestHandler(Config{})
	doGet(t, h.Mux(), "/miner/addr-1.payid/identifiers")
	if d.idents.gotAddr != "addr-1" {
		t.Errorf("gotAddr = %q, want addr-1", d.idents.gotAddr)
	}
	if d.idents.gotPaymentID == nil || *d.idents.gotPaymentID != "payid" {
		t.Errorf("gotPaymentID = %v, want payid", d.idents.gotPaymentID)
	}
}

// --- /miner/:address/stats -------------------------------------------------

func TestHandleMinerStats_Bare(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.stats.shareStats = statsapi.ShareStatsRecord{SharesSum: 4294967296, ShareCount: 10}
	d.stats.balances = []statsapi.BalanceRecord{
		{PaymentAddress: "addr-1", PendingBalance: 50, PaidBalance: 200},
	}
	lastShare := time.Unix(9999, 0)
	d.idents.rows = []IdentifierRecord{{WorkerName: "rig1", LastShare: &lastShare}}
	d.payouts.total = 3

	rr := doGet(t, h.Mux(), "/miner/addr-1/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var row minerStatRowWithBalance
	if err := json.Unmarshal(rr.Body.Bytes(), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if row.AmtPaid != 200 || row.AmtDue != 50 {
		t.Errorf("amtPaid/amtDue = %d/%d, want 200/50", row.AmtPaid, row.AmtDue)
	}
	if row.TxnCount != 3 {
		t.Errorf("txnCount = %d, want 3", row.TxnCount)
	}
	if row.LTS != 9999 {
		t.Errorf("lts = %d, want 9999", row.LTS)
	}
	if row.InvalidShares != 0 {
		t.Errorf("invalidShares = %d, want 0 (documented gap)", row.InvalidShares)
	}
	if row.ValidShares != 10 {
		t.Errorf("validShares = %d, want 10", row.ValidShares)
	}
}

func TestHandleMinerStatsAllWorkers_IncludesInactiveWorkers(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.stats.workerStats = []statsapi.WorkerShareStatsRecord{{Identifier: "rig1", SharesSum: 10, ShareCount: 1}}
	d.idents.rows = []IdentifierRecord{{WorkerName: "rig1"}, {WorkerName: "rig2"}}

	rr := doGet(t, h.Mux(), "/miner/addr-1/stats/allWorkers")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var rows []minerStatRow
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	byName := map[string]minerStatRow{}
	for _, r := range rows {
		byName[r.Identifer] = r
	}
	if byName["rig1"].ValidShares != 1 {
		t.Errorf("rig1 validShares = %d, want 1", byName["rig1"].ValidShares)
	}
	if byName["rig2"].ValidShares != 0 || byName["rig2"].TotalHash != 0 {
		t.Errorf("rig2 = %+v, want zero-valued (no recent activity)", byName["rig2"])
	}
}

func TestHandleMinerStatsWorker_Specific(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.stats.workerStats = []statsapi.WorkerShareStatsRecord{{Identifier: "rig1", SharesSum: 4294967296, ShareCount: 5}}

	rr := doGet(t, h.Mux(), "/miner/addr-1/stats/rig1")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var row minerStatRow
	if err := json.Unmarshal(rr.Body.Bytes(), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if row.Identifer != "rig1" || row.ValidShares != 5 || row.TotalHash != 4294967296 {
		t.Fatalf("unexpected row: %+v", row)
	}
}

// --- tari address wrapper --------------------------------------------------

const testTariAddress = "f2GYDtVpj6yx8ZRPez2fsaU3VBAfVzcYycb3boUqMz1C9cZdJ7CrAkhhYoqRRNJPjwRSKqfd2caRe9jv8ZKwAwDGbvD"
const testXMRAddress = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"

func TestHandleUpdateTariAddress_Success(t *testing.T) {
	h, d := newTestHandler(Config{})
	body := `{"xmrAddress":"` + testXMRAddress + `","tariAddress":"` + testTariAddress + `"}`
	rr := doPost(t, h.Mux(), "/user/updateTariAddress", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg"] != testTariAddress {
		t.Errorf("msg = %q, want tari address echoed back", resp["msg"])
	}
	if d.addrMap.gotXMR != testXMRAddress || d.addrMap.gotTari != testTariAddress {
		t.Errorf("unexpected upsert args: %q / %q", d.addrMap.gotXMR, d.addrMap.gotTari)
	}
}

func TestHandleUpdateTariAddress_InvalidXMR(t *testing.T) {
	h, _ := newTestHandler(Config{})
	body := `{"xmrAddress":"not-a-real-address","tariAddress":"` + testTariAddress + `"}`
	rr := doPost(t, h.Mux(), "/user/updateTariAddress", body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg"] != "Unable to validate XMR address" || resp["success"] != false {
		t.Errorf("unexpected body: %+v", resp)
	}
}

func TestHandleUpdateTariAddress_InvalidTari(t *testing.T) {
	h, _ := newTestHandler(Config{})
	body := `{"xmrAddress":"` + testXMRAddress + `","tariAddress":"not-a-real-address"}`
	rr := doPost(t, h.Mux(), "/user/updateTariAddress", body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg"] != "Unable to validate Tari address" || resp["success"] != false {
		t.Errorf("unexpected body: %+v", resp)
	}
}

func TestHandleUpdateTariAddress_UpsertFailure(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.addrMap.err = errTest
	body := `{"xmrAddress":"` + testXMRAddress + `","tariAddress":"` + testTariAddress + `"}`
	rr := doPost(t, h.Mux(), "/user/updateTariAddress", body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg"] != "Unable to insert address" {
		t.Errorf("unexpected body: %+v", resp)
	}
}

func TestHandleGetTariAddress_Found(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.addrMap.rec = addressmap.Record{XMRAddress: testXMRAddress, TariAddress: testTariAddress}
	rr := doGet(t, h.Mux(), "/user/tariAddress/"+testXMRAddress)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg"] != testTariAddress {
		t.Errorf("msg = %q, want %q", resp["msg"], testTariAddress)
	}
}

func TestHandleGetTariAddress_NotFound(t *testing.T) {
	h, d := newTestHandler(Config{})
	d.addrMap.err = addressmap.ErrNotFound
	rr := doGet(t, h.Mux(), "/user/tariAddress/"+testXMRAddress)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (legacy: not-found is still 200 with empty msg)", rr.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg"] != "" {
		t.Errorf("msg = %q, want empty string", resp["msg"])
	}
}
