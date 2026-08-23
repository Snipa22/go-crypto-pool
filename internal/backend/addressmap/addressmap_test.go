package addressmap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeRepo is an in-memory Repository test double.
type fakeRepo struct {
	rows map[string]Record
	err  error

	gotXMR, gotTari string
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: map[string]Record{}}
}

func (f *fakeRepo) Upsert(_ context.Context, xmrAddress, tariAddress string) error {
	if f.err != nil {
		return f.err
	}
	f.gotXMR, f.gotTari = xmrAddress, tariAddress
	now := time.Unix(1000, 0)
	rec, existed := f.rows[xmrAddress]
	if !existed {
		rec.CreatedAt = now
	}
	rec.XMRAddress = xmrAddress
	rec.TariAddress = tariAddress
	rec.UpdatedAt = now
	f.rows[xmrAddress] = rec
	return nil
}

func (f *fakeRepo) Get(_ context.Context, xmrAddress string) (Record, error) {
	if f.err != nil {
		return Record{}, f.err
	}
	rec, ok := f.rows[xmrAddress]
	if !ok {
		return Record{}, ErrNotFound
	}
	return rec, nil
}

func doPost(t *testing.T, mux *http.ServeMux, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func doGet(t *testing.T, mux *http.ServeMux, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestUpsertThenGet_OK(t *testing.T) {
	repo := newFakeRepo()
	mux := NewHandler(repo).Mux()

	rr := doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"4Axmr...","tari_address":"12tari..."}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("upsert status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if repo.gotXMR != "4Axmr..." || repo.gotTari != "12tari..." {
		t.Fatalf("repo got unexpected args: %q %q", repo.gotXMR, repo.gotTari)
	}

	rr = doGet(t, mux, "/api/v1/address-map?xmr_address=4Axmr...")
	if rr.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp getResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.XMRAddress != "4Axmr..." || resp.TariAddress != "12tari..." {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestUpsert_ReplacesExistingMapping(t *testing.T) {
	repo := newFakeRepo()
	mux := NewHandler(repo).Mux()

	doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"addr","tari_address":"tari-1"}`)
	rr := doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"addr","tari_address":"tari-2"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("second upsert status = %d", rr.Code)
	}

	rr = doGet(t, mux, "/api/v1/address-map?xmr_address=addr")
	var resp getResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.TariAddress != "tari-2" {
		t.Fatalf("expected replaced tari_address = tari-2, got %q", resp.TariAddress)
	}
}

func TestUpsert_MissingFields(t *testing.T) {
	mux := NewHandler(newFakeRepo()).Mux()

	cases := []string{
		`{"tari_address":"tari-1"}`,
		`{"xmr_address":"addr"}`,
		`{"xmr_address":"","tari_address":""}`,
		`not json`,
	}
	for _, body := range cases {
		rr := doPost(t, mux, "/api/v1/address-map", body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rr.Code)
		}
	}
}

func TestGet_MissingParam(t *testing.T) {
	mux := NewHandler(newFakeRepo()).Mux()
	rr := doGet(t, mux, "/api/v1/address-map")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestGet_NotFound(t *testing.T) {
	mux := NewHandler(newFakeRepo()).Mux()
	rr := doGet(t, mux, "/api/v1/address-map?xmr_address=unknown")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rr.Code, rr.Body.String())
	}
}

func TestGet_RepositoryError(t *testing.T) {
	repo := newFakeRepo()
	repo.err = context.DeadlineExceeded
	mux := NewHandler(repo).Mux()
	rr := doGet(t, mux, "/api/v1/address-map?xmr_address=addr")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}
