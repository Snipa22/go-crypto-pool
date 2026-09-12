package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// scrapeMetrics starts a real httptest.Server around h.Mux(), GETs
// /metrics through it, and returns the real rendered Prometheus text
// body. This exercises the genuine promhttp handler end to end, not a
// mock of the Prometheus client library.
func scrapeMetrics(t *testing.T, h *Handler) string {
	t.Helper()
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}

	buf := make([]byte, 16384)
	n, _ := resp.Body.Read(buf)
	if n == 0 {
		t.Fatal("expected non-empty /metrics body")
	}
	return string(buf[:n])
}

// TestMetrics_SmokeTest is the basic "does /metrics respond and look
// like valid Prometheus exposition format" check via a real
// httptest.Server sitting in front of the actual Handler.Mux(),
// scraping the real promhttp-rendered output.
func TestMetrics_SmokeTest(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	body := scrapeMetrics(t, h)
	if !strings.Contains(body, "backend_build_info") {
		t.Errorf("expected backend_build_info in /metrics output, got:\n%s", body)
	}
}

// TestMetrics_ShareOutcomes_RecordedWithRealLabels drives real
// requests through the real handler across every branch point
// (accepted, rejected-bad-network, rejected-bad-auth, DB-error), then
// scrapes /metrics and asserts on the actual rendered counter lines —
// not a mocked metrics interface.
func TestMetrics_ShareOutcomes_RecordedWithRealLabels(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{
		AuthHeaderName:  "X-Pool-Auth",
		AuthHeaderValue: "secret",
		Network:         poolpb.Network_NETWORK_TESTNET,
	})
	mux := h.Mux()

	// accepted
	rr := postProto(t, mux, "/api/v1/share", validShare(), map[string]string{"X-Pool-Auth": "secret"})
	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("accepted share: status = %d, body=%s", rr.Code, rr.Body.String())
	}

	// rejected: bad auth (wrong header value)
	rr = postProto(t, mux, "/api/v1/share", validShare(), map[string]string{"X-Pool-Auth": "wrong"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad-auth share: status = %d, want 401", rr.Code)
	}

	// rejected: network mismatch (validShare() is TESTNET; submit as-is
	// but with the header, then check against a MAINNET-configured
	// handler for this one call by building a second handler)
	mismatchRepo := &fakeRepo{}
	hMismatch := NewHandler(mismatchRepo, Config{Network: poolpb.Network_NETWORK_MAINNET})
	rrMismatch := postProto(t, hMismatch.Mux(), "/api/v1/share", validShare(), nil)
	if rrMismatch.Code != http.StatusBadRequest {
		t.Fatalf("network-mismatch share: status = %d, want 400", rrMismatch.Code)
	}

	// error: DB insert fails
	errRepo := &fakeRepo{shareErr: errors.New("db exploded")}
	hErr := NewHandler(errRepo, Config{})
	rrErr := postProto(t, hErr.Mux(), "/api/v1/share", validShare(), nil)
	if rrErr.Code != http.StatusInternalServerError {
		t.Fatalf("db-error share: status = %d, want 500", rrErr.Code)
	}

	body := scrapeMetrics(t, h)
	wantAccepted := `shares_total{algo="RXT",network="TESTNET",pool_type="PPLNS",result="accepted"} 1`
	if !strings.Contains(body, wantAccepted) {
		t.Errorf("expected %q in %s's /metrics output, got:\n%s", wantAccepted, "h", body)
	}
	wantUnauthorized := `shares_total{algo="unknown",network="unknown",pool_type="unknown",result="unauthorized"} 1`
	if !strings.Contains(body, wantUnauthorized) {
		t.Errorf("expected %q (bad-auth rejection) in /metrics output, got:\n%s", wantUnauthorized, body)
	}

	mismatchBody := scrapeMetrics(t, hMismatch)
	wantMismatch := `shares_total{algo="RXT",network="TESTNET",pool_type="PPLNS",result="rejected"} 1`
	if !strings.Contains(mismatchBody, wantMismatch) {
		t.Errorf("expected %q (network-mismatch rejection) in /metrics output, got:\n%s", wantMismatch, mismatchBody)
	}

	errBody := scrapeMetrics(t, hErr)
	wantError := `shares_total{algo="RXT",network="TESTNET",pool_type="PPLNS",result="error"} 1`
	if !strings.Contains(errBody, wantError) {
		t.Errorf("expected %q (DB error) in /metrics output, got:\n%s", wantError, errBody)
	}
}

// TestMetrics_BlockOutcomes_RecordedWithRealLabels mirrors the share
// test above for /api/v1/block.
func TestMetrics_BlockOutcomes_RecordedWithRealLabels(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, Config{Network: poolpb.Network_NETWORK_MAINNET})

	rr := postProto(t, h.Mux(), "/api/v1/block", validBlock(), nil)
	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("accepted block: status = %d, body=%s", rr.Code, rr.Body.String())
	}

	errRepo := &fakeRepo{blockErr: errors.New("db exploded")}
	hErr := NewHandler(errRepo, Config{})
	rrErr := postProto(t, hErr.Mux(), "/api/v1/block", validBlock(), nil)
	if rrErr.Code != http.StatusInternalServerError {
		t.Fatalf("db-error block: status = %d, want 500", rrErr.Code)
	}

	body := scrapeMetrics(t, h)
	wantAccepted := `blocks_total{algo="C29",network="MAINNET",result="accepted"} 1`
	if !strings.Contains(body, wantAccepted) {
		t.Errorf("expected %q in /metrics output, got:\n%s", wantAccepted, body)
	}

	errBody := scrapeMetrics(t, hErr)
	wantError := `blocks_total{algo="C29",network="MAINNET",result="error"} 1`
	if !strings.Contains(errBody, wantError) {
		t.Errorf("expected %q in /metrics output, got:\n%s", wantError, errBody)
	}
}

// TestMetrics_AuthRejections_CountedAsUnauthorized proves the
// rejected-for-auth-specifically outcome on both /api/v1/share and
// /api/v1/block is recorded with the distinct result="unauthorized"
// label (metrics.ResultUnauthorized) on the existing shares_total/
// blocks_total counters — not folded into the generic "rejected"
// bucket, and not a brand new, parallel metric family.
func TestMetrics_AuthRejections_CountedAsUnauthorized(t *testing.T) {
	shareRepo := &fakeRepo{}
	hShare := NewHandler(shareRepo, Config{AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer good-token"})
	rr := postProto(t, hShare.Mux(), "/api/v1/share", validShare(), nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("share: status = %d, want 401", rr.Code)
	}

	blockRepo := &fakeRepo{}
	hBlock := NewHandler(blockRepo, Config{AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer good-token"})
	rrBlock := postProto(t, hBlock.Mux(), "/api/v1/block", validBlock(), map[string]string{"Authorization": "Bearer wrong-token"})
	if rrBlock.Code != http.StatusUnauthorized {
		t.Fatalf("block: status = %d, want 401", rrBlock.Code)
	}

	shareBody := scrapeMetrics(t, hShare)
	wantShare := `shares_total{algo="unknown",network="unknown",pool_type="unknown",result="unauthorized"} 1`
	if !strings.Contains(shareBody, wantShare) {
		t.Errorf("expected %q in /metrics output, got:\n%s", wantShare, shareBody)
	}
	if strings.Contains(shareBody, `shares_total{algo="unknown",network="unknown",pool_type="unknown",result="rejected"}`) {
		t.Errorf("auth rejection must not also be counted as a generic \"rejected\" result:\n%s", shareBody)
	}

	blockBody := scrapeMetrics(t, hBlock)
	wantBlock := `blocks_total{algo="unknown",network="unknown",result="unauthorized"} 1`
	if !strings.Contains(blockBody, wantBlock) {
		t.Errorf("expected %q in /metrics output, got:\n%s", wantBlock, blockBody)
	}
}

// TestMetrics_UnknownLabelsOnPreDecodeRejections confirms that
// rejections which happen before a share/block is decoded (malformed
// protobuf body) are recorded with the fixed "unknown" label values,
// not left unrecorded or guessed at.
func TestMetrics_UnknownLabelsOnPreDecodeRejections(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/share", bytes.NewReader([]byte{0xff, 0x01, 0x02, 0xff, 0xff}))
	req.Header.Set("Content-Type", "application/x-protobuf")
	rr := httptest.NewRecorder()
	h.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}

	body := scrapeMetrics(t, h)
	want := `shares_total{algo="unknown",network="unknown",pool_type="unknown",result="rejected"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("expected %q in /metrics output, got:\n%s", want, body)
	}
}

// TestMetrics_InsertDurationHistograms_ObserveRealTiming confirms the
// share/block insert histograms actually receive an observation for
// every attempted (post-validation) insert.
func TestMetrics_InsertDurationHistograms_ObserveRealTiming(t *testing.T) {
	h := NewHandler(&fakeRepo{}, Config{})
	postProto(t, h.Mux(), "/api/v1/share", validShare(), nil)
	postProto(t, h.Mux(), "/api/v1/block", validBlock(), nil)

	body := scrapeMetrics(t, h)
	for _, want := range []string{"share_insert_duration_seconds_count 1", "block_insert_duration_seconds_count 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in /metrics output, got:\n%s", want, body)
		}
	}
}
