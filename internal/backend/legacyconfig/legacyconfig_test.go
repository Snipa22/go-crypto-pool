package legacyconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/networkapi"
)

// Real, checksum/byte-verified fixture addresses -- mirrors
// internal/backend/addressmap_test.go's own fixtures exactly (same
// real, well-known/verified addresses), since this package reuses the
// exact same underlying decoders.
const (
	realXMRMainnetAddr    = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
	realTariEsmeraldaAddr = "f35v735NW63VX6wohQM4wQYjd56NewMgvbhNMtibbYQdqW9"
	notAnAddress          = "not-a-real-address-at-all"
)

type fakeMotdRepo struct {
	motd MotdRecord
	err  error
}

func (f *fakeMotdRepo) LatestMotd(context.Context) (MotdRecord, error) {
	if f.err != nil {
		return MotdRecord{}, f.err
	}
	return f.motd, nil
}

type fakePoolPortsSource struct {
	ports []networkapi.FlatPort
	err   error

	gotAlgo, gotNetwork string
}

func (f *fakePoolPortsSource) ListFlatPorts(_ context.Context, algo, network string) ([]networkapi.FlatPort, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.gotAlgo, f.gotNetwork = algo, network
	return f.ports, nil
}

func doGet(t *testing.T, mux *http.ServeMux, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestHandleConfig(t *testing.T) {
	cfg := Config{
		PPSFeePercent:          1.5,
		SoloFeePercent:         2.5,
		DevDonationPercent:     0.5,
		PoolDevDonationPercent: 0.25,
		MinWalletPayoutAtomic:  1000000,
		MaturityDepth:          60,
	}
	h := NewHandler(&fakeMotdRepo{}, &fakePoolPortsSource{}, cfg)
	rr := doGet(t, h.Mux(), "/config")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp configResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.PPLNSFee != 0.6 {
		t.Errorf("pplns_fee = %v, want hardcoded 0.6", resp.PPLNSFee)
	}
	if resp.PPSFee != 1.5 || resp.SoloFee != 2.5 {
		t.Errorf("pps_fee/solo_fee = %v/%v, want 1.5/2.5", resp.PPSFee, resp.SoloFee)
	}
	if resp.DevDonation != 0.5 || resp.PoolDevDonation != 0.25 {
		t.Errorf("dev_donation/pool_dev_donation = %v/%v, want 0.5/0.25", resp.DevDonation, resp.PoolDevDonation)
	}
	if resp.MinWalletPayout != 1000000 {
		t.Errorf("min_wallet_payout = %v, want 1000000", resp.MinWalletPayout)
	}
	if resp.MaturityDepth != 60 {
		t.Errorf("maturity_depth = %v, want 60", resp.MaturityDepth)
	}
	// Placeholders must be the stated zero-values, never fabricated
	// non-zero data.
	if resp.BTCFee != 0 || resp.MinBTCPayout != 0 || resp.MinExchangePayout != 0 || resp.MinDenom != 0 {
		t.Errorf("expected placeholder fields to be zero, got %+v", resp)
	}
	if resp.ManualWallet != "" || resp.ManualPaymentID != "" {
		t.Errorf("expected placeholder string fields to be empty, got %+v", resp)
	}
}

func TestHandleMotd_ActiveRow(t *testing.T) {
	created := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	repo := &fakeMotdRepo{motd: MotdRecord{Created: created, Subject: "hello", Body: "world", Type: "info", Active: true}}
	h := NewHandler(repo, &fakePoolPortsSource{}, Config{})

	rr := doGet(t, h.Mux(), "/pool/motd")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp motdResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Created != created.Unix() || resp.Subject != "hello" || resp.Body != "world" || resp.Type != "info" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHandleMotd_InactiveRow_ReturnsEmptyObject(t *testing.T) {
	repo := &fakeMotdRepo{motd: MotdRecord{Subject: "hidden", Active: false}}
	h := NewHandler(repo, &fakePoolPortsSource{}, Config{})

	rr := doGet(t, h.Mux(), "/pool/motd")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if rr.Body.String() != "{}\n" {
		t.Fatalf("expected empty JSON object, got %q", rr.Body.String())
	}
}

func TestHandleMotd_NoRows_ReturnsEmptyObject(t *testing.T) {
	repo := &fakeMotdRepo{err: ErrMotdNotFound}
	h := NewHandler(repo, &fakePoolPortsSource{}, Config{})

	rr := doGet(t, h.Mux(), "/pool/motd")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if rr.Body.String() != "{}\n" {
		t.Fatalf("expected empty JSON object, got %q", rr.Body.String())
	}
}

func TestHandleMotd_RepositoryError(t *testing.T) {
	repo := &fakeMotdRepo{err: context.DeadlineExceeded}
	h := NewHandler(repo, &fakePoolPortsSource{}, Config{})

	rr := doGet(t, h.Mux(), "/pool/motd")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestHandlePorts(t *testing.T) {
	maxDiff := int64(50000)
	ports := &fakePoolPortsSource{ports: []networkapi.FlatPort{
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", Port: 3333, Description: "low", MinDifficulty: 1, MaxDifficulty: &maxDiff, StartDifficulty: 100, VariableDiff: true},
	}}
	h := NewHandler(&fakeMotdRepo{}, ports, Config{})

	rr := doGet(t, h.Mux(), "/pool/ports")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp []portResponseRow
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 || resp[0].Port != 3333 || resp[0].Algo != "RXT" || resp[0].PoolType != "PPLNS" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp[0].MaxDifficulty == nil || *resp[0].MaxDifficulty != maxDiff {
		t.Fatalf("unexpected max_difficulty: %+v", resp[0])
	}
}

func TestHandlePorts_Empty(t *testing.T) {
	h := NewHandler(&fakeMotdRepo{}, &fakePoolPortsSource{}, Config{})
	rr := doGet(t, h.Mux(), "/pool/ports")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if rr.Body.String() != "[]\n" {
		t.Fatalf("expected empty JSON array, got %q", rr.Body.String())
	}
}

func TestHandlePorts_Error(t *testing.T) {
	ports := &fakePoolPortsSource{err: context.DeadlineExceeded}
	h := NewHandler(&fakeMotdRepo{}, ports, Config{})
	rr := doGet(t, h.Mux(), "/pool/ports")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestHandleAddressType(t *testing.T) {
	h := NewHandler(&fakeMotdRepo{}, &fakePoolPortsSource{}, Config{})
	mux := h.Mux()

	cases := []struct {
		name      string
		address   string
		wantValid bool
		wantType  string
	}{
		{"real xmr mainnet address", realXMRMainnetAddr, true, "XMR"},
		{"real tari address", realTariEsmeraldaAddr, true, "TARI"},
		{"garbage", notAnAddress, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := doGet(t, mux, "/pool/address_type/"+tc.address)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			var resp addressTypeResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Valid != tc.wantValid {
				t.Errorf("valid = %v, want %v (body=%s)", resp.Valid, tc.wantValid, rr.Body.String())
			}
			if resp.AddressType != tc.wantType {
				t.Errorf("address_type = %q, want %q", resp.AddressType, tc.wantType)
			}
		})
	}
}
