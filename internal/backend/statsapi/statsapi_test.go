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
	balances    []BalanceRecord
	shareStats  ShareStatsRecord
	workerStats []WorkerShareStatsRecord
	err         error

	gotAlgo, gotNetwork, gotAddr string
	gotPaymentID                 *string
	gotSince                     int64
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

func (f *fakeRepo) WorkerShareStatsSince(_ context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]WorkerShareStatsRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotAddr, f.gotPaymentID, f.gotSince = algo, network, paymentAddress, paymentID, sinceUnix
	return f.workerStats, nil
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
	wantHS := float64(1000) * hashesPerDifficultyUnit / 100
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
	repo := &fakeRepo{workerStats: []WorkerShareStatsRecord{
		{Identifier: "rig-1", SharesSum: 500, ShareCount: 5},
		{Identifier: "rig-2", SharesSum: 200, ShareCount: 2},
	}}
	h := NewHandler(repo, Config{})
	rr := doGet(t, h.Mux(), "/api/v1/stats/hashrate/workers?payment_address=addr-1&algo=RXT&network=TESTNET&window=100")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Workers []workerHashrateRow `json:"workers"`
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
	want := float64(100) * hashesPerDifficultyUnit / 10
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
