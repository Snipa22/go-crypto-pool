package statsapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// fakeRepo is an in-memory Repository test double.
type fakeRepo struct {
	balances          []BalanceRecord
	shareStats        ShareStatsRecord
	workerStats       WorkerShareStatsResultRecord
	poolSources       PoolSourceShareStatsResultRecord
	hashSamples       []HashSampleRecord
	difficultySamples []DifficultySampleRecord
	err               error

	gotAlgo, gotNetwork, gotAddr string
	gotPaymentID                 *string
	gotSince                     int64
	gotWorker                    *string
	gotPoolType                  string
}

func (f *fakeRepo) MinerBalances(_ context.Context, paymentAddress, algo, network string, paymentID *string) ([]BalanceRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAddr, f.gotAlgo, f.gotNetwork, f.gotPaymentID = paymentAddress, algo, network, paymentID
	return f.balances, nil
}

func (f *fakeRepo) ShareStatsSince(_ context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (ShareStatsRecord, error) {
	if f.err != nil {
		return ShareStatsRecord{}, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID, f.gotSince = algo, network, paymentAddress, paymentID, sinceUnix
	return f.shareStats, nil
}

func (f *fakeRepo) WorkerShareStatsSince(_ context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (WorkerShareStatsResultRecord, error) {
	if f.err != nil {
		return WorkerShareStatsResultRecord{}, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID, f.gotSince = algo, network, paymentAddress, paymentID, sinceUnix
	return f.workerStats, nil
}

func (f *fakeRepo) PoolSourceShareStatsSince(_ context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (PoolSourceShareStatsResultRecord, error) {
	if f.err != nil {
		return PoolSourceShareStatsResultRecord{}, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID, f.gotSince = algo, network, paymentAddress, paymentID, sinceUnix
	return f.poolSources, nil
}

func (f *fakeRepo) PoolTypeHashHistory(_ context.Context, algo, network, poolType string, sinceUnix int64) ([]HashSampleRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotPoolType, f.gotSince = algo, network, poolType, sinceUnix
	return f.hashSamples, nil
}

func (f *fakeRepo) MinerHashHistory(_ context.Context, algo, network, paymentAddress string, paymentID, worker *string, sinceUnix int64) ([]HashSampleRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID, f.gotWorker, f.gotSince = algo, network, paymentAddress, paymentID, worker, sinceUnix
	return f.hashSamples, nil
}

func (f *fakeRepo) NetworkDifficultyHistory(_ context.Context, algo, network string, sinceUnix int64) ([]DifficultySampleRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotSince = algo, network, sinceUnix
	return f.difficultySamples, nil
}

func doGet(t *testing.T, mux *http.ServeMux, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestHandleBalance_OK(t *testing.T) {
	repo := &fakeRepo{balances: []BalanceRecord{
		{Algo: "RXT", Network: "TESTNET", PaymentAddress: "addr-1", PendingBalance: 100, PaidBalance: 50, UpdatedAt: time.Unix(0, 0)},
	}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if repo.gotAddr != "addr-1" {
		t.Errorf("got addr %q, want addr-1", repo.gotAddr)
	}
	var resp struct {
		Balances []balanceResponseRow `json:"balances"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Balances) != 1 || resp.Balances[0].PendingBalance != 100 || resp.Balances[0].PaidBalance != 50 {
		t.Errorf("unexpected balances: %+v", resp.Balances)
	}
}

func TestHandleBalance_MissingAddress(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/balance")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleBalance_InvalidAlgo(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1&algo=BOGUS")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleBalance_NetworkMismatchRejected(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{Network: poolpb.Network_NETWORK_MAINNET})
	rr := doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1&network=TESTNET")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleBalance_NetworkDefaultsToConfigured(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{Network: poolpb.Network_NETWORK_TESTNET})
	rr := doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if repo.gotNetwork != "TESTNET" {
		t.Errorf("network = %q, want TESTNET (defaulted from config)", repo.gotNetwork)
	}
}

func TestHandleBalance_PaymentIDPresenceVsAbsence(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})

	doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1")
	if repo.gotPaymentID != nil {
		t.Errorf("expected nil payment_id when omitted, got %v", repo.gotPaymentID)
	}

	doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1&payment_id=")
	if repo.gotPaymentID == nil || *repo.gotPaymentID != "" {
		t.Errorf("expected non-nil empty payment_id when present-but-empty, got %v", repo.gotPaymentID)
	}

	doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1&payment_id=pid-1")
	if repo.gotPaymentID == nil || *repo.gotPaymentID != "pid-1" {
		t.Errorf("expected payment_id=pid-1, got %v", repo.gotPaymentID)
	}
}

func TestHandleHashrate_OK(t *testing.T) {
	repo := &fakeRepo{shareStats: ShareStatsRecord{SharesSum: 1000, ShareCount: 10}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate?payment_address=addr-1&algo=RXT&network=TESTNET&window=100")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp hashrateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantHS := float64(1000) / 100
	if resp.EstimatedHashrateHS != wantHS {
		t.Errorf("estimated hashrate = %v, want %v", resp.EstimatedHashrateHS, wantHS)
	}
	if resp.WindowSeconds != 100 || resp.ShareCount != 10 || resp.SharesSum != 1000 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestHandleHashrate_DefaultWindow(t *testing.T) {
	repo := &fakeRepo{shareStats: ShareStatsRecord{SharesSum: 1}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate?payment_address=addr-1&algo=RXT&network=TESTNET")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp hashrateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.WindowSeconds != DefaultWindowSeconds {
		t.Errorf("window = %d, want default %d", resp.WindowSeconds, DefaultWindowSeconds)
	}
}

func TestHandleHashrate_MissingAlgo(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate?payment_address=addr-1&network=TESTNET")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleHashrate_MissingNetworkNoConfigRejected(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate?payment_address=addr-1&algo=RXT")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (network required with no configured default)", rr.Code)
	}
}

func TestHandleHashrate_WindowTooLarge(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate?payment_address=addr-1&algo=RXT&network=TESTNET&window=99999999")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleHashrateWorkers_OK(t *testing.T) {
	repo := &fakeRepo{workerStats: WorkerShareStatsResultRecord{Rows: []WorkerShareStatsRecord{
		{Identifier: "rig-1", SharesSum: 500, ShareCount: 5},
		{Identifier: "rig-2", SharesSum: 200, ShareCount: 2},
	}}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/workers?payment_address=addr-1&algo=RXT&network=TESTNET&window=100")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Workers []workerHashrateRow `json:"workers"`
		Other   *otherWorkersBucket `json:"other"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Workers) != 2 {
		t.Fatalf("expected 2 workers, got %d", len(resp.Workers))
	}
	if resp.Workers[0].Identifier != "rig-1" || resp.Workers[0].SharesSum != 500 {
		t.Errorf("unexpected worker[0]: %+v", resp.Workers[0])
	}
	if resp.Other != nil {
		t.Errorf("expected no other bucket when repo returned none, got %+v", resp.Other)
	}
}

// TestHandleHashrateWorkers_OtherBucket proves the collapsed
// cardinality-cap "other" bucket (Finding 2's fix) round-trips
// through the JSON response as a distinct, unambiguous field.
func TestHandleHashrateWorkers_OtherBucket(t *testing.T) {
	repo := &fakeRepo{workerStats: WorkerShareStatsResultRecord{
		Rows: []WorkerShareStatsRecord{
			{Identifier: "rig-1", SharesSum: 500, ShareCount: 5},
		},
		Other: &WorkerShareStatsOtherRecord{SharesSum: 300, ShareCount: 30, IdentifierCount: 150},
	}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/workers?payment_address=addr-1&algo=RXT&network=TESTNET&window=100")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Workers []workerHashrateRow `json:"workers"`
		Other   *otherWorkersBucket `json:"other"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Workers) != 1 {
		t.Fatalf("expected 1 kept worker, got %d", len(resp.Workers))
	}
	if resp.Other == nil {
		t.Fatal("expected a non-nil other bucket")
	}
	if !resp.Other.IsOther {
		t.Error("other bucket IsOther = false, want true")
	}
	if resp.Other.IdentifierCount != 150 {
		t.Errorf("other.IdentifierCount = %d, want 150", resp.Other.IdentifierCount)
	}
	if resp.Other.SharesSum != 300 || resp.Other.ShareCount != 30 {
		t.Errorf("other = %+v, want SharesSum=300 ShareCount=30", resp.Other)
	}
}

func TestHandleHashrateSources_OK(t *testing.T) {
	repo := &fakeRepo{poolSources: PoolSourceShareStatsResultRecord{Rows: []PoolSourceShareStatsRecord{
		{PoolID: 1, SharesSum: 700, ShareCount: 7},
		{PoolID: 2, SharesSum: 300, ShareCount: 3},
	}}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/sources?payment_address=addr-1&algo=RXT&network=TESTNET&window=100")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Sources []poolSourceHashrateRow `json:"sources"`
		Other   *otherSourcesBucket     `json:"other"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(resp.Sources))
	}
	if resp.Sources[0].PoolID != 1 || resp.Sources[0].SharesSum != 700 {
		t.Errorf("unexpected source[0]: %+v", resp.Sources[0])
	}
	wantHS := float64(700) / 100
	if resp.Sources[0].EstimatedHashrateHS != wantHS {
		t.Errorf("estimated hashrate = %v, want %v", resp.Sources[0].EstimatedHashrateHS, wantHS)
	}
	if resp.Other != nil {
		t.Errorf("expected no other bucket when repo returned none, got %+v", resp.Other)
	}
}

// TestHandleHashrateSources_OtherBucket is
// TestHandleHashrateWorkers_OtherBucket's pool_id analogue.
func TestHandleHashrateSources_OtherBucket(t *testing.T) {
	repo := &fakeRepo{poolSources: PoolSourceShareStatsResultRecord{
		Rows:  []PoolSourceShareStatsRecord{{PoolID: 1, SharesSum: 700, ShareCount: 7}},
		Other: &PoolSourceShareStatsOtherRecord{SharesSum: 400, ShareCount: 40, PoolIDCount: 60},
	}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/sources?payment_address=addr-1&algo=RXT&network=TESTNET&window=100")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Sources []poolSourceHashrateRow `json:"sources"`
		Other   *otherSourcesBucket     `json:"other"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Sources) != 1 {
		t.Fatalf("expected 1 kept source, got %d", len(resp.Sources))
	}
	if resp.Other == nil {
		t.Fatal("expected a non-nil other bucket")
	}
	if !resp.Other.IsOther {
		t.Error("other bucket IsOther = false, want true")
	}
	if resp.Other.PoolIDCount != 60 {
		t.Errorf("other.PoolIDCount = %d, want 60", resp.Other.PoolIDCount)
	}
	if resp.Other.SharesSum != 400 || resp.Other.ShareCount != 40 {
		t.Errorf("other = %+v, want SharesSum=400 ShareCount=40", resp.Other)
	}
}

func TestHandleHashrateSources_MissingAlgo(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/sources?payment_address=addr-1&network=TESTNET")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestEstimateHashrateHS(t *testing.T) {
	if got := EstimateHashrateHS(0, 100); got != 0 {
		t.Errorf("zero shares should give 0 hashrate, got %v", got)
	}
	if got := EstimateHashrateHS(100, 0); got != 0 {
		t.Errorf("zero window should give 0 hashrate, got %v", got)
	}
	if got := EstimateHashrateHS(-5, 100); got != 0 {
		t.Errorf("negative shares should give 0 hashrate, got %v", got)
	}
	want := float64(100) / 10
	if got := EstimateHashrateHS(100, 10); got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRepositoryErrorMapsToInternalServerError(t *testing.T) {
	repo := &fakeRepo{err: context.DeadlineExceeded}
	h := NewHandler(repo, Config{})

	if rr := doGet(t, h.Mux(), "/api/v1/stats/balance?payment_address=addr-1"); rr.Code != http.StatusInternalServerError {
		t.Errorf("balance: status = %d, want 500", rr.Code)
	}
	if rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate?payment_address=addr-1&algo=RXT&network=TESTNET"); rr.Code != http.StatusInternalServerError {
		t.Errorf("hashrate: status = %d, want 500", rr.Code)
	}
}

// --- /hashrate/history ---

func TestHandleHashrateHistory_OK(t *testing.T) {
	repo := &fakeRepo{hashSamples: []HashSampleRecord{
		{HashrateHS: 1.5, SampleTime: time.Unix(1000, 0)},
		{HashrateHS: 2.5, SampleTime: time.Unix(1060, 0)},
	}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=RXT&network=TESTNET")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if repo.gotWorker != nil {
		t.Errorf("expected nil worker (miner-level) when omitted, got %v", repo.gotWorker)
	}
	var resp struct {
		Samples []hashHistorySampleRow `json:"samples"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Samples) != 2 || resp.Samples[0].HashrateHS != 1.5 || resp.Samples[1].HashrateHS != 2.5 {
		t.Errorf("unexpected samples: %+v", resp.Samples)
	}
}

func TestHandleHashrateHistory_EmptyWhenNoHistoryYet(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=RXT&network=TESTNET")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Samples []hashHistorySampleRow `json:"samples"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Samples == nil || len(resp.Samples) != 0 {
		t.Errorf("expected an empty (non-nil) samples array, got %+v", resp.Samples)
	}
}

func TestHandleHashrateHistory_WorkerScoped(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})
	doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=RXT&network=TESTNET&worker=rig-1")
	if repo.gotWorker == nil || *repo.gotWorker != "rig-1" {
		t.Errorf("expected worker=rig-1, got %v", repo.gotWorker)
	}
}

func TestHandleHashrateHistory_MissingAddress(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?algo=RXT&network=TESTNET")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleHashrateHistory_InvalidAlgo(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=BOGUS&network=TESTNET")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleHashrateHistory_InvalidNetwork(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=RXT")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (network required with no configured default)", rr.Code)
	}
}

func TestHandleHashrateHistory_WindowHoursCappedByRetention(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{HashHistoryRetention: 2 * time.Hour})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=RXT&network=TESTNET&window_hours=100")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (clamped, not rejected); body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		WindowHours float64 `json:"window_hours"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.WindowHours != 2 {
		t.Errorf("window_hours = %v, want 2 (clamped to configured retention)", resp.WindowHours)
	}
}

func TestHandleHashrateHistory_InvalidWindowHours(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=RXT&network=TESTNET&window_hours=-1")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

// --- /pool/history ---

func TestHandlePoolHistory_DefaultsToGlobal(t *testing.T) {
	repo := &fakeRepo{hashSamples: []HashSampleRecord{{HashrateHS: 42, SampleTime: time.Unix(1000, 0)}}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/pool/history?algo=RXT&network=TESTNET")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if repo.gotPoolType != "GLOBAL" {
		t.Errorf("pool_type = %q, want GLOBAL (default)", repo.gotPoolType)
	}
	var resp struct {
		PoolType string                 `json:"pool_type"`
		Samples  []hashHistorySampleRow `json:"samples"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.PoolType != "GLOBAL" || len(resp.Samples) != 1 || resp.Samples[0].HashrateHS != 42 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestHandlePoolHistory_ExplicitPoolType(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})
	doGet(t, h.Mux(), "/api/v1/stats/pool/history?algo=RXT&network=TESTNET&pool_type=PPLNS")
	if repo.gotPoolType != "PPLNS" {
		t.Errorf("pool_type = %q, want PPLNS", repo.gotPoolType)
	}
}

func TestHandlePoolHistory_InvalidPoolType(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/pool/history?algo=RXT&network=TESTNET&pool_type=BOGUS")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandlePoolHistory_MissingAlgo(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/pool/history?network=TESTNET")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

// --- /network/history ---

func TestHandleNetworkHistory_OK(t *testing.T) {
	repo := &fakeRepo{difficultySamples: []DifficultySampleRecord{
		{Difficulty: 123.5, SampleTime: time.Unix(1000, 0)},
	}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/network/history?algo=RXT&network=TESTNET")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Samples []difficultyHistorySampleRow `json:"samples"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Samples) != 1 || resp.Samples[0].Difficulty != 123.5 {
		t.Errorf("unexpected samples: %+v", resp.Samples)
	}
}

func TestHandleNetworkHistory_EmptyWhenNoHistoryYet(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/network/history?algo=RXT&network=TESTNET")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Samples []difficultyHistorySampleRow `json:"samples"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Samples == nil || len(resp.Samples) != 0 {
		t.Errorf("expected an empty (non-nil) samples array, got %+v", resp.Samples)
	}
}

func TestHandleNetworkHistory_InvalidAlgo(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/network/history?algo=BOGUS&network=TESTNET")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleNetworkHistory_MissingNetworkNoConfigRejected(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/network/history?algo=RXT")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (network required with no configured default)", rr.Code)
	}
}

func TestHistoryEndpoints_RepositoryErrorMapsToInternalServerError(t *testing.T) {
	repo := &fakeRepo{err: context.DeadlineExceeded}
	h := NewHandler(repo, Config{})

	if rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/history?payment_address=addr-1&algo=RXT&network=TESTNET"); rr.Code != http.StatusInternalServerError {
		t.Errorf("hashrate/history: status = %d, want 500", rr.Code)
	}
	if rr := doGet(t, h.Mux(), "/api/v1/stats/pool/history?algo=RXT&network=TESTNET"); rr.Code != http.StatusInternalServerError {
		t.Errorf("pool/history: status = %d, want 500", rr.Code)
	}
	if rr := doGet(t, h.Mux(), "/api/v1/stats/network/history?algo=RXT&network=TESTNET"); rr.Code != http.StatusInternalServerError {
		t.Errorf("network/history: status = %d, want 500", rr.Code)
	}
}
