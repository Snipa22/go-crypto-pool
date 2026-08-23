package networkapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeRepo struct {
	pools []PoolRecord
	stats NetworkStatsRecord
	err   error

	gotAlgo, gotNetwork string
	gotSince            int64
}

func (f *fakeRepo) ListPools(_ context.Context, algo, network string) ([]PoolRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork = algo, network
	return f.pools, nil
}

func (f *fakeRepo) NetworkStatsSince(_ context.Context, algo, network string, sinceUnix int64) (NetworkStatsRecord, error) {
	if f.err != nil {
		return NetworkStatsRecord{}, f.err
	}
	f.gotAlgo, f.gotNetwork, f.gotSince = algo, network, sinceUnix
	return f.stats, nil
}

func doGet(t *testing.T, mux *http.ServeMux, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestHandlePools_OK(t *testing.T) {
	repo := &fakeRepo{pools: []PoolRecord{
		{
			Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", Name: "main",
			Enabled: true, CreatedAt: time.Unix(0, 0),
			Ports: []PortRecord{{Port: 3333, Description: "low-diff", MinDifficulty: 1, StartDifficulty: 100, VariableDiff: true}},
		},
	}}
	mux := NewHandler(repo).Mux()

	rr := doGet(t, mux, "/api/v1/network/pools?algo=RXT&network=TESTNET")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if repo.gotAlgo != "RXT" || repo.gotNetwork != "TESTNET" {
		t.Fatalf("repo got unexpected filters: %q %q", repo.gotAlgo, repo.gotNetwork)
	}

	var body map[string][]poolResponseRow
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pools := body["pools"]
	if len(pools) != 1 || pools[0].Name != "main" || len(pools[0].Ports) != 1 || pools[0].Ports[0].Port != 3333 {
		t.Fatalf("unexpected pools response: %+v", pools)
	}
}

func TestHandlePools_Error(t *testing.T) {
	mux := NewHandler(&fakeRepo{err: context.DeadlineExceeded}).Mux()
	rr := doGet(t, mux, "/api/v1/network/pools")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestHandleStats_OK(t *testing.T) {
	height := int64(12345)
	repo := &fakeRepo{stats: NetworkStatsRecord{
		SharesSum: 1000, ShareCount: 5, BlocksFound: 2, LastBlockHeight: &height,
	}}
	mux := NewHandler(repo).Mux()

	rr := doGet(t, mux, "/api/v1/network/stats?algo=RXT&network=TESTNET&window=100")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if repo.gotAlgo != "RXT" || repo.gotNetwork != "TESTNET" {
		t.Fatalf("unexpected filters: %q %q", repo.gotAlgo, repo.gotNetwork)
	}

	var resp statsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.WindowSeconds != 100 {
		t.Fatalf("window_seconds = %d, want 100", resp.WindowSeconds)
	}
	wantHashrate := EstimateHashrateHS(1000, 100)
	if resp.EstimatedHashrateHS != wantHashrate {
		t.Fatalf("estimated_hashrate_hs = %v, want %v", resp.EstimatedHashrateHS, wantHashrate)
	}
	if resp.BlocksFound != 2 || resp.LastBlockHeight == nil || *resp.LastBlockHeight != 12345 {
		t.Fatalf("unexpected block fields: %+v", resp)
	}
}

func TestHandleStats_MissingParams(t *testing.T) {
	mux := NewHandler(&fakeRepo{}).Mux()

	cases := []string{
		"/api/v1/network/stats",
		"/api/v1/network/stats?algo=RXT",
		"/api/v1/network/stats?network=TESTNET",
		"/api/v1/network/stats?algo=RXT&network=TESTNET&window=-5",
		"/api/v1/network/stats?algo=RXT&network=TESTNET&window=abc",
	}
	for _, target := range cases {
		rr := doGet(t, mux, target)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("target %q: status = %d, want 400", target, rr.Code)
		}
	}
}

func TestHandleStats_DefaultWindow(t *testing.T) {
	repo := &fakeRepo{}
	mux := NewHandler(repo).Mux()
	rr := doGet(t, mux, "/api/v1/network/stats?algo=RXT&network=TESTNET")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp statsResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.WindowSeconds != DefaultWindowSeconds {
		t.Fatalf("window_seconds = %d, want default %d", resp.WindowSeconds, DefaultWindowSeconds)
	}
}
