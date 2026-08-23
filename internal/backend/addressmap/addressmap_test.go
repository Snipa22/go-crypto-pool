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

	rr := doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"4Axmr...","tari_address":"12aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("upsert status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if repo.gotXMR != "4Axmr..." || repo.gotTari != "12aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
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
	if resp.XMRAddress != "4Axmr..." || resp.TariAddress != "12aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestUpsert_ReplacesExistingMapping(t *testing.T) {
	repo := newFakeRepo()
	mux := NewHandler(repo).Mux()

	doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"addr","tari_address":"12aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	rr := doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"addr","tari_address":"14bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("second upsert status = %d", rr.Code)
	}

	rr = doGet(t, mux, "/api/v1/address-map?xmr_address=addr")
	var resp getResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.TariAddress != "14bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("expected replaced tari_address, got %q", resp.TariAddress)
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

// TestValidateTariAddress_RealShapes is the real regression test for
// validateTariAddress's ported-from-legacy structural check: every
// case here mirrors an actual scenario nodejs-pool-sxmr's own
// /user/updateTariAddress route (lib/api.js) would accept or reject.
func TestValidateTariAddress_RealShapes(t *testing.T) {
	valid90With12 := "12" + strings.Repeat("a", 88) // 90 chars
	valid91With14 := "14" + strings.Repeat("b", 89) // 91 chars
	realEsmeraldaTestnetAddr := "f2GYDtVpj6yx8ZRPez2fsaU3VBAfVzcYycb3boUqMz1C9cZdJ7CrAkhhYoqRRNJPjwRSKqfd2caRe9jv8ZKwAwDGbvD" // real, live-used address this session -- confirmed 91 chars, "f2" prefix (testnet's real network byte, NOT mainnet's 12/14) -- the exact regression case that motivated only checking length, not a mainnet-specific prefix
	tooShort := "12" + strings.Repeat("d", 10)

	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"90-char-mainnet-shaped", valid90With12, false},
		{"91-char-mainnet-shaped", valid91With14, false},
		{"real-esmeralda-testnet-address", realEsmeraldaTestnetAddr, false},
		{"too-short", tooShort, true},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTariAddress(tc.addr)
			if tc.wantErr && err == nil {
				t.Fatalf("validateTariAddress(%q): expected an error, got nil", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateTariAddress(%q): unexpected error: %v", tc.addr, err)
			}
		})
	}
}
