package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
	"google.golang.org/protobuf/proto"
)

// fakeRepo is an in-memory ShareBlockRepository test double.
type fakeRepo struct {
	shares     []ShareRecord
	blocks     []BlockRecord
	shareErr   error
	blockErr   error
	lastBucket int64
}

func (f *fakeRepo) InsertShare(_ context.Context, s ShareRecord, bucketSize int64) error {
	if f.shareErr != nil {
		return f.shareErr
	}
	f.shares = append(f.shares, s)
	f.lastBucket = bucketSize
	return nil
}

func (f *fakeRepo) InsertBlock(_ context.Context, b BlockRecord) error {
	if f.blockErr != nil {
		return f.blockErr
	}
	f.blocks = append(f.blocks, b)
	return nil
}

func validShare() *poolpb.Share {
	return &poolpb.Share{
		Algo:           poolpb.Algo_ALGO_RXT,
		Network:        poolpb.Network_NETWORK_TESTNET,
		PoolType:       poolpb.PoolType_POOL_TYPE_PPLNS,
		Shares:         100,
		PaymentAddress: "addr-1",
		Identifier:     "worker-1",
		BlockHeight:    12345,
	}
}

func validBlock() *poolpb.Block {
	return &poolpb.Block{
		Algo:     poolpb.Algo_ALGO_C29,
		Network:  poolpb.Network_NETWORK_MAINNET,
		PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
		Hash:     "0xdeadbeef",
		Height:   999,
	}
}

func postProto(t *testing.T, mux *http.ServeMux, path string, msg proto.Message, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/x-protobuf")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestHandleShare_ValidRoundTrip(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)

	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("status = %d, want 2xx; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 1 {
		t.Fatalf("expected 1 share inserted, got %d", len(repo.shares))
	}
	got := repo.shares[0]
	if got.Algo != "RXT" || got.Network != "TESTNET" || got.PoolType != "PPLNS" {
		t.Errorf("unexpected mapped record: %+v", got)
	}
	if got.PaymentAddress != "addr-1" || got.Identifier != "worker-1" || got.BlockHeight != 12345 {
		t.Errorf("unexpected mapped record: %+v", got)
	}
	if repo.lastBucket != HeightPartitionBucketSize {
		t.Errorf("bucket size = %d, want %d", repo.lastBucket, HeightPartitionBucketSize)
	}
}

func TestHandleBlock_ValidRoundTrip(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})
	rr := postProto(t, h.Mux(), "/api/v1/block", validBlock(), nil)

	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("status = %d, want 2xx; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.blocks) != 1 {
		t.Fatalf("expected 1 block inserted, got %d", len(repo.blocks))
	}
	got := repo.blocks[0]
	if got.Algo != "C29" || got.Network != "MAINNET" || got.PoolType != "SOLO" {
		t.Errorf("unexpected mapped record: %+v", got)
	}
	if got.Hash != "0xdeadbeef" || got.Height != 999 {
		t.Errorf("unexpected mapped record: %+v", got)
	}
}

func TestHandleShare_MalformedProtobuf(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/share", bytes.NewReader([]byte{0xff, 0x01, 0x02, 0xff, 0xff}))
	req.Header.Set("Content-Type", "application/x-protobuf")
	rr := httptest.NewRecorder()
	h.Mux().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 0 {
		t.Errorf("expected no insert on malformed body, got %d", len(repo.shares))
	}
}

func TestHandleBlock_MalformedProtobuf(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/block", bytes.NewReader([]byte{0xff, 0x01, 0x02, 0xff, 0xff}))
	req.Header.Set("Content-Type", "application/x-protobuf")
	rr := httptest.NewRecorder()
	h.Mux().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleShare_MissingRequiredField(t *testing.T) {
	cases := map[string]*poolpb.Share{
		"unspecified algo": func() *poolpb.Share {
			s := validShare()
			s.Algo = poolpb.Algo_ALGO_UNSPECIFIED
			return s
		}(),
		"empty payment address": func() *poolpb.Share {
			s := validShare()
			s.PaymentAddress = ""
			return s
		}(),
		"negative block height": func() *poolpb.Share {
			s := validShare()
			s.BlockHeight = -1
			return s
		}(),
	}

	for name, share := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &fakeRepo{}
			h := NewHandler(repo, Config{})
			rr := postProto(t, h.Mux(), "/api/v1/share", share, nil)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
			}
			if len(repo.shares) != 0 {
				t.Errorf("expected no insert, got %d", len(repo.shares))
			}
		})
	}
}

func TestHandleBlock_MissingRequiredField(t *testing.T) {
	cases := map[string]*poolpb.Block{
		"unspecified algo": func() *poolpb.Block {
			b := validBlock()
			b.Algo = poolpb.Algo_ALGO_UNSPECIFIED
			return b
		}(),
		"empty hash": func() *poolpb.Block {
			b := validBlock()
			b.Hash = ""
			return b
		}(),
		"negative height": func() *poolpb.Block {
			b := validBlock()
			b.Height = -1
			return b
		}(),
	}

	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &fakeRepo{}
			h := NewHandler(repo, Config{})
			rr := postProto(t, h.Mux(), "/api/v1/block", block, nil)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
			}
			if len(repo.blocks) != 0 {
				t.Errorf("expected no insert, got %d", len(repo.blocks))
			}
		})
	}
}

func TestHandleShare_AuthWrongValue(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer good-token"})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), map[string]string{"Authorization": "Bearer wrong-token"})

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 0 {
		t.Errorf("expected no insert, got %d", len(repo.shares))
	}
}

func TestHandleShare_AuthHeaderMissing(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer good-token"})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 0 {
		t.Errorf("expected no insert, got %d", len(repo.shares))
	}
}

func TestHandleShare_AuthNotConfiguredMeansNoCheck(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)

	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("status = %d, want 2xx; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 1 {
		t.Errorf("expected 1 insert, got %d", len(repo.shares))
	}
}

func TestHandleShare_AuthConfiguredCorrectValueSucceeds(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{AuthHeaderName: "X-Pool-Auth", AuthHeaderValue: "secret"})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), map[string]string{"X-Pool-Auth": "secret"})

	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("status = %d, want 2xx; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 1 {
		t.Errorf("expected 1 insert, got %d", len(repo.shares))
	}
}

func TestHandleShare_DBErrorReturns500WithoutLeakingDetail(t *testing.T) {
	repo := &fakeRepo{shareErr: errors.New("pq: connection reset by peer at 10.0.0.5:5432 (internal detail)")}
	h := NewHandler(repo, Config{})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("10.0.0.5")) {
		t.Errorf("response body leaked internal error detail: %s", rr.Body.String())
	}
}

func TestHandleBlock_DBErrorReturns500(t *testing.T) {
	repo := &fakeRepo{blockErr: errors.New("db exploded")}
	h := NewHandler(repo, Config{})
	rr := postProto(t, h.Mux(), "/api/v1/block", validBlock(), nil)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}

func TestNewHandler(t *testing.T) {
	if h := NewHandler(&fakeRepo{}, Config{}); h == nil {
		t.Fatal("NewHandler returned nil")
	}
}

func TestHandleShare_NetworkMatchesConfigured_Accepted(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{Network: poolpb.Network_NETWORK_TESTNET})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)

	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("status = %d, want 2xx; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 1 {
		t.Fatalf("expected 1 share inserted, got %d", len(repo.shares))
	}
}

func TestHandleShare_NetworkMismatch_Rejected(t *testing.T) {
	// Backend configured for mainnet; share submitted is testnet
	// (validShare's default). This must be a hard rejection — a
	// testnet leaf must not be able to write into a mainnet backend.
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{Network: poolpb.Network_NETWORK_MAINNET})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 0 {
		t.Errorf("expected no insert on network mismatch, got %d", len(repo.shares))
	}
}

func TestHandleBlock_NetworkMatchesConfigured_Accepted(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{Network: poolpb.Network_NETWORK_MAINNET})
	rr := postProto(t, h.Mux(), "/api/v1/block", validBlock(), nil)

	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("status = %d, want 2xx; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.blocks) != 1 {
		t.Fatalf("expected 1 block inserted, got %d", len(repo.blocks))
	}
}

func TestHandleBlock_NetworkMismatch_Rejected(t *testing.T) {
	// Backend configured for testnet; block submitted is mainnet
	// (validBlock's default). Must be rejected, not silently accepted.
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{Network: poolpb.Network_NETWORK_TESTNET})
	rr := postProto(t, h.Mux(), "/api/v1/block", validBlock(), nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.blocks) != 0 {
		t.Errorf("expected no insert on network mismatch, got %d", len(repo.blocks))
	}
}

func TestHandleShare_NetworkNotConfiguredMeansNoCheck(t *testing.T) {
	// Config{} (Network unspecified) must keep behaving exactly like
	// before this change — no network enforcement — so existing/other
	// callers/tests that don't set Network aren't broken by this
	// additive check.
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{})
	rr := postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)

	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("status = %d, want 2xx; body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.shares) != 1 {
		t.Errorf("expected 1 insert, got %d", len(repo.shares))
	}
}
