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

// Real, checksum/byte-verified fixture addresses used throughout this
// file -- NOT placeholders. Each one round-trips through the real
// validator this package now uses (see validateXMRAddress/
// validateTariAddress in addressmap.go), so these tests exercise the
// actual byte-exact decode path, not just a length heuristic.
const (
	// realXMRMainnetAddr is the real, well-known Monero project
	// donation address -- a genuine mainnet standard address whose
	// base58/checksum has been independently verified for years by
	// the Monero ecosystem, not fabricated for this test.
	realXMRMainnetAddr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
	// realXMRTestnetAddr is a synthetic-but-real testnet standard
	// address: real random payload bytes with a correctly computed
	// Keccak-256 checksum and the real testnet tag byte (0x35),
	// generated the exact same way go-xmr-lib's own ValidateAddress
	// verifies it (base58-decode, split payload/checksum, recompute
	// Keccak, compare) -- it is not a real chain-observed address,
	// but it is byte-exact-valid per the real checksum algorithm.
	realXMRTestnetAddr = "9zvJVvqdNTbJsFNUijxqj42FofbRdUv36er2LQUvGZw2DpWdHBAA6wLSLLR9hgNTwSQGYewyAmZ9cW1FbTNNoNF84KaMHGC"

	// realTariEsmeraldaAddr and realTariMainnetAddr are real Tari
	// single addresses generated via go-tari-lib/address's own
	// NewSingleInteractiveOnly (a real canonical Ristretto255 public
	// key, real network byte, real features byte, real DammSum
	// checksum) -- they round-trip through address.Parse exactly like
	// a real wallet-generated address would.
	realTariEsmeraldaAddr = "f35v735NW63VX6wohQM4wQYjd56NewMgvbhNMtibbYQdqW9"
	realTariMainnetAddr   = "13rvPKhft3guQqmZ5kxW14DAzb2d8k8Gaw6scp5zDP8xkfE"

	// realTariEsmeraldaTestnetFixture is the exact real Esmeralda
	// testnet address this project's own git history (see
	// validateTariAddress's doc comment / commit b3b01d7) used to
	// catch the old mainnet-only-prefix bug. It is real, live-used,
	// 91-char base58 -- kept here as the regression case that
	// motivated this package's validation to be network-aware, and
	// it must still validate under the new byte-exact library.
	realTariEsmeraldaTestnetFixture = "f2GYDtVpj6yx8ZRPez2fsaU3VBAfVzcYycb3boUqMz1C9cZdJ7CrAkhhYoqRRNJPjwRSKqfd2caRe9jv8ZKwAwDGbvD"
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

	rr := doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"`+realXMRMainnetAddr+`","tari_address":"`+realTariEsmeraldaAddr+`"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("upsert status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if repo.gotXMR != realXMRMainnetAddr || repo.gotTari != realTariEsmeraldaAddr {
		t.Fatalf("repo got unexpected args: %q %q", repo.gotXMR, repo.gotTari)
	}

	rr = doGet(t, mux, "/api/v1/address-map?xmr_address="+realXMRMainnetAddr)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp getResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.XMRAddress != realXMRMainnetAddr || resp.TariAddress != realTariEsmeraldaAddr {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestUpsert_ReplacesExistingMapping(t *testing.T) {
	repo := newFakeRepo()
	mux := NewHandler(repo).Mux()

	doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"`+realXMRMainnetAddr+`","tari_address":"`+realTariEsmeraldaAddr+`"}`)
	rr := doPost(t, mux, "/api/v1/address-map", `{"xmr_address":"`+realXMRMainnetAddr+`","tari_address":"`+realTariMainnetAddr+`"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("second upsert status = %d, body = %s", rr.Code, rr.Body.String())
	}

	rr = doGet(t, mux, "/api/v1/address-map?xmr_address="+realXMRMainnetAddr)
	var resp getResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.TariAddress != realTariMainnetAddr {
		t.Fatalf("expected replaced tari_address, got %q", resp.TariAddress)
	}
}

func TestUpsert_MissingFields(t *testing.T) {
	mux := NewHandler(newFakeRepo()).Mux()

	cases := []string{
		`{"tari_address":"` + realTariEsmeraldaAddr + `"}`,
		`{"xmr_address":"` + realXMRMainnetAddr + `"}`,
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
	rr := doGet(t, mux, "/api/v1/address-map?xmr_address="+realXMRTestnetAddr)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rr.Code, rr.Body.String())
	}
}

func TestGet_RepositoryError(t *testing.T) {
	repo := newFakeRepo()
	repo.err = context.DeadlineExceeded
	mux := NewHandler(repo).Mux()
	rr := doGet(t, mux, "/api/v1/address-map?xmr_address="+realXMRMainnetAddr)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

// TestValidateTariAddress_RealShapes is the real regression test for
// validateTariAddress's byte-exact validator: every case here is a
// real, decodable-or-not Tari address shape, not a length heuristic
// probe.
func TestValidateTariAddress_RealShapes(t *testing.T) {
	tooShort := "12" + strings.Repeat("d", 10)
	// A structurally-plausible-length string that is not real
	// base58/emoji/hex-decodable Tari address data at all.
	garbage := strings.Repeat("z", 91)
	// Same as realTariEsmeraldaAddr but with the last character
	// flipped, which must break the DammSum checksum.
	tamperedChecksum := realTariEsmeraldaAddr[:len(realTariEsmeraldaAddr)-1] + flipLastChar(realTariEsmeraldaAddr)

	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"real-esmeralda-single-address", realTariEsmeraldaAddr, false},
		{"real-mainnet-single-address", realTariMainnetAddr, false},
		{"real-esmeralda-testnet-fixture-from-project-history", realTariEsmeraldaTestnetFixture, false},
		{"too-short", tooShort, true},
		{"empty", "", true},
		{"not-a-real-address-just-right-length-garbage", garbage, true},
		{"tampered-checksum", tamperedChecksum, true},
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

// flipLastChar returns a single character guaranteed to differ from
// the input string's last character (a small, boring alphabet-cycle
// helper used only to build the tamperedChecksum fixture above).
func flipLastChar(s string) string {
	last := s[len(s)-1]
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] != last {
			return string(alphabet[i])
		}
	}
	return "9"
}

// TestValidateXMRAddress_RealShapes is the real regression test for
// validateXMRAddress's checksum-verified validator.
func TestValidateXMRAddress_RealShapes(t *testing.T) {
	tamperedChecksum := realXMRMainnetAddr[:len(realXMRMainnetAddr)-1] + flipLastChar(realXMRMainnetAddr)

	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"real-mainnet-address", realXMRMainnetAddr, false},
		{"real-testnet-address", realXMRTestnetAddr, false},
		{"empty", "", true},
		{"not-base58check-at-all", "not-a-monero-address", true},
		{"tampered-checksum", tamperedChecksum, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateXMRAddress(tc.addr)
			if tc.wantErr && err == nil {
				t.Fatalf("validateXMRAddress(%q): expected an error, got nil", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateXMRAddress(%q): unexpected error: %v", tc.addr, err)
			}
		})
	}
}
