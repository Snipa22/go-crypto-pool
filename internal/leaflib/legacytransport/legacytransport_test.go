// Copyright and license: see repository LICENSE (MIT).
package legacytransport

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	legacypb "github.com/Snipa22/go-crypto-pool/internal/legacyproto"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
	"google.golang.org/protobuf/proto"
)

// --- field-mapping / overflow-guard tests (buildLegacyShare/buildLegacyBlock) ---

func TestBuildLegacyShare_HappyPath(t *testing.T) {
	share := &poolpb.Share{
		Algo:           poolpb.Algo_ALGO_RXT,           // dropped, no legacy equivalent
		Network:        poolpb.Network_NETWORK_TESTNET, // dropped
		Shares:         100,
		PaymentAddress: "addr-1",
		FoundBlock:     true,
		PaymentId:      proto.String("pid-1"),
		PoolType:       poolpb.PoolType_POOL_TYPE_PPLNS,
		PoolId:         999, // must NOT be used -- own legacyPoolID used instead
		BlockDiff:      12345,
		BlockHeight:    500000,
		Timestamp:      1700000000,
		Identifier:     "worker-1",
		TrustedShare:   true,
	}

	legacyShare, err := buildLegacyShare(share, legacypb.POOLTYPE_PPLNS, 42)
	if err != nil {
		t.Fatalf("buildLegacyShare: %v", err)
	}

	if legacyShare.GetShares() != 100 {
		t.Errorf("Shares = %d, want 100", legacyShare.GetShares())
	}
	if legacyShare.GetPaymentAddress() != "addr-1" {
		t.Errorf("PaymentAddress = %q, want %q", legacyShare.GetPaymentAddress(), "addr-1")
	}
	if !legacyShare.GetFoundBlock() {
		t.Errorf("FoundBlock = false, want true")
	}
	if legacyShare.GetPaymentID() != "pid-1" {
		t.Errorf("PaymentID = %q, want %q", legacyShare.GetPaymentID(), "pid-1")
	}
	if !legacyShare.GetTrustedShare() {
		t.Errorf("TrustedShare = false, want true")
	}
	if legacyShare.GetPoolType() != legacypb.POOLTYPE_PPLNS {
		t.Errorf("PoolType = %v, want PPLNS", legacyShare.GetPoolType())
	}
	// The transport's OWN configured legacy pool ID (42) must be used,
	// NOT the incoming share's own PoolId (999).
	if legacyShare.GetPoolID() != 42 {
		t.Errorf("PoolID = %d, want 42 (the transport's own configured legacy pool ID, not the incoming share's pool_id=999)", legacyShare.GetPoolID())
	}
	if legacyShare.GetBlockDiff() != 12345 {
		t.Errorf("BlockDiff = %d, want 12345", legacyShare.GetBlockDiff())
	}
	if legacyShare.GetBitcoin() != false {
		t.Errorf("Bitcoin = %v, want false always", legacyShare.GetBitcoin())
	}
	if legacyShare.GetBlockHeight() != 500000 {
		t.Errorf("BlockHeight = %d, want 500000", legacyShare.GetBlockHeight())
	}
	if legacyShare.GetTimestamp() != 1700000000 {
		t.Errorf("Timestamp = %d, want 1700000000", legacyShare.GetTimestamp())
	}
	if legacyShare.GetIdentifier() != "worker-1" {
		t.Errorf("Identifier = %q, want %q", legacyShare.GetIdentifier(), "worker-1")
	}

	// Must genuinely marshal (all required proto2 fields populated).
	if _, err := proto.Marshal(legacyShare); err != nil {
		t.Fatalf("Marshal built legacy share: %v", err)
	}
}

func TestBuildLegacyShare_PaymentIDUnsetWhenNilOnInput(t *testing.T) {
	share := &poolpb.Share{
		Shares:         1,
		PaymentAddress: "addr",
		PoolType:       poolpb.PoolType_POOL_TYPE_SOLO,
		Identifier:     "worker",
		// PaymentId left nil.
	}

	legacyShare, err := buildLegacyShare(share, legacypb.POOLTYPE_SOLO, 1)
	if err != nil {
		t.Fatalf("buildLegacyShare: %v", err)
	}
	if legacyShare.PaymentID != nil {
		t.Errorf("PaymentID = %v, want nil (unset) when input PaymentId is nil", legacyShare.PaymentID)
	}
}

func TestBuildLegacyShare_BitcoinAlwaysFalse(t *testing.T) {
	// There is no "bitcoin" field on poolpb.Share at all -- this test
	// exists to make the invariant explicit and regression-proof: no
	// matter what, the built legacy Share always has Bitcoin=false.
	share := &poolpb.Share{
		Shares:         1,
		PaymentAddress: "addr",
		PoolType:       poolpb.PoolType_POOL_TYPE_PPS,
		Identifier:     "worker",
	}
	legacyShare, err := buildLegacyShare(share, legacypb.POOLTYPE_PPS, 1)
	if err != nil {
		t.Fatalf("buildLegacyShare: %v", err)
	}
	if legacyShare.GetBitcoin() != false {
		t.Errorf("Bitcoin = %v, want false", legacyShare.GetBitcoin())
	}
}

func TestBuildLegacyShare_SharesOverflowsInt32_ReturnsError(t *testing.T) {
	share := &poolpb.Share{
		Shares:         math.MaxInt32 + 1,
		PaymentAddress: "addr",
		PoolType:       poolpb.PoolType_POOL_TYPE_PPLNS,
		Identifier:     "worker",
	}
	_, err := buildLegacyShare(share, legacypb.POOLTYPE_PPLNS, 1)
	if err == nil {
		t.Fatal("expected error for shares overflowing int32, got nil")
	}
}

func TestBuildLegacyShare_BlockHeightOverflowsInt32_ReturnsError(t *testing.T) {
	share := &poolpb.Share{
		Shares:         1,
		PaymentAddress: "addr",
		PoolType:       poolpb.PoolType_POOL_TYPE_PPLNS,
		Identifier:     "worker",
		BlockHeight:    math.MaxInt32 + 1,
	}
	_, err := buildLegacyShare(share, legacypb.POOLTYPE_PPLNS, 1)
	if err == nil {
		t.Fatal("expected error for block_height overflowing int32, got nil")
	}
}

func TestBuildLegacyShare_UnspecifiedPoolType_ReturnsError(t *testing.T) {
	share := &poolpb.Share{
		Shares:         1,
		PaymentAddress: "addr",
		PoolType:       poolpb.PoolType_POOL_TYPE_UNSPECIFIED,
		Identifier:     "worker",
	}
	_, err := buildLegacyShare(share, legacypb.POOLTYPE_PPLNS, 1)
	if err == nil {
		t.Fatal("expected error for POOL_TYPE_UNSPECIFIED, got nil")
	}
}

func TestBuildLegacyShare_NegativeSharesOverflow_ReturnsError(t *testing.T) {
	share := &poolpb.Share{
		Shares:         math.MinInt32 - 1,
		PaymentAddress: "addr",
		PoolType:       poolpb.PoolType_POOL_TYPE_PPLNS,
		Identifier:     "worker",
	}
	_, err := buildLegacyShare(share, legacypb.POOLTYPE_PPLNS, 1)
	if err == nil {
		t.Fatal("expected error for shares underflowing int32, got nil")
	}
}

func TestBuildLegacyBlock_HappyPath(t *testing.T) {
	block := &poolpb.Block{
		Algo:       poolpb.Algo_ALGO_C29,           // dropped
		Network:    poolpb.Network_NETWORK_MAINNET, // dropped
		Hash:       "0xdeadbeef",
		Difficulty: 5000000,
		Shares:     100,
		Timestamp:  1700000001,
		PoolType:   poolpb.PoolType_POOL_TYPE_PROP,
		Unlocked:   true,
		Valid:      true,
		Value:      proto.Int64(987654321),
		Height:     123456,
		PoolId:     7, // dropped -- no legacy Block destination
	}

	legacyBlock, height32, err := buildLegacyBlock(block, legacypb.POOLTYPE_PROP)
	if err != nil {
		t.Fatalf("buildLegacyBlock: %v", err)
	}

	if height32 != 123456 {
		t.Errorf("height32 = %d, want 123456", height32)
	}
	if legacyBlock.GetHash() != "0xdeadbeef" {
		t.Errorf("Hash = %q, want %q", legacyBlock.GetHash(), "0xdeadbeef")
	}
	if legacyBlock.GetDifficulty() != 5000000 {
		t.Errorf("Difficulty = %d, want 5000000", legacyBlock.GetDifficulty())
	}
	if legacyBlock.GetShares() != 100 {
		t.Errorf("Shares = %d, want 100", legacyBlock.GetShares())
	}
	if legacyBlock.GetTimestamp() != 1700000001 {
		t.Errorf("Timestamp = %d, want 1700000001", legacyBlock.GetTimestamp())
	}
	if legacyBlock.GetPoolType() != legacypb.POOLTYPE_PROP {
		t.Errorf("PoolType = %v, want PROP", legacyBlock.GetPoolType())
	}
	if !legacyBlock.GetUnlocked() {
		t.Errorf("Unlocked = false, want true")
	}
	if !legacyBlock.GetValid() {
		t.Errorf("Valid = false, want true")
	}
	if legacyBlock.GetValue() != 987654321 {
		t.Errorf("Value = %d, want 987654321", legacyBlock.GetValue())
	}

	if _, err := proto.Marshal(legacyBlock); err != nil {
		t.Fatalf("Marshal built legacy block: %v", err)
	}
}

func TestBuildLegacyBlock_ValueUnsetWhenNilOnInput(t *testing.T) {
	block := &poolpb.Block{
		Hash:     "0xhash",
		PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
		// Value left nil.
	}
	legacyBlock, _, err := buildLegacyBlock(block, legacypb.POOLTYPE_SOLO)
	if err != nil {
		t.Fatalf("buildLegacyBlock: %v", err)
	}
	if legacyBlock.Value != nil {
		t.Errorf("Value = %v, want nil (unset)", legacyBlock.Value)
	}
}

func TestBuildLegacyBlock_HeightOverflowsInt32_ReturnsError(t *testing.T) {
	block := &poolpb.Block{
		Hash:     "0xhash",
		PoolType: poolpb.PoolType_POOL_TYPE_PPLNS,
		Height:   math.MaxInt32 + 1,
	}
	_, _, err := buildLegacyBlock(block, legacypb.POOLTYPE_PPLNS)
	if err == nil {
		t.Fatal("expected error for height overflowing int32, got nil")
	}
}

func TestBuildLegacyBlock_UnspecifiedPoolType_ReturnsError(t *testing.T) {
	block := &poolpb.Block{
		Hash:     "0xhash",
		PoolType: poolpb.PoolType_POOL_TYPE_UNSPECIFIED,
	}
	_, _, err := buildLegacyBlock(block, legacypb.POOLTYPE_PPLNS)
	if err == nil {
		t.Fatal("expected error for POOL_TYPE_UNSPECIFIED, got nil")
	}
}

// --- SubmitShare/SubmitBlock overflow-guard tests (through the full public API) ---

func TestSubmitShare_ShareOverflowsInt32_ReturnsErrorWithoutNetworkCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := New(Config{BackendBaseURL: srv.URL, AuthKey: "key", LegacyPoolType: legacypb.POOLTYPE_PPLNS, LegacyPoolID: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	share := &poolpb.Share{
		Shares:         math.MaxInt32 + 1,
		PaymentAddress: "addr",
		PoolType:       poolpb.PoolType_POOL_TYPE_PPLNS,
		Identifier:     "worker",
	}
	if err := tr.SubmitShare(context.Background(), share); err == nil {
		t.Fatal("expected error for overflowing shares, got nil")
	}
	if called {
		t.Error("expected no HTTP call to be made for an invalid share, but the server was hit")
	}
}

func TestSubmitBlock_HeightOverflowsInt32_ReturnsErrorWithoutNetworkCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := New(Config{BackendBaseURL: srv.URL, AuthKey: "key", LegacyPoolType: legacypb.POOLTYPE_PPLNS, LegacyPoolID: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	block := &poolpb.Block{
		Hash:     "0xhash",
		PoolType: poolpb.PoolType_POOL_TYPE_PPLNS,
		Height:   math.MaxInt32 + 1,
	}
	if err := tr.SubmitBlock(context.Background(), block); err == nil {
		t.Fatal("expected error for overflowing height, got nil")
	}
	if called {
		t.Error("expected no HTTP call to be made for an invalid block, but the server was hit")
	}
}

// --- HTTP-transport-level tests ---

func TestSubmitShare_SendsRawProtobufWithKeyInBodyNotHeader(t *testing.T) {
	var (
		gotPath           string
		gotBody           []byte
		gotAuthHeaderKey  string
		gotAuthHeaderAuth string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		// The real legacy server has no HTTP-header-based auth at all --
		// confirm the auth key never leaks into any header.
		gotAuthHeaderKey = r.Header.Get("key")
		gotAuthHeaderAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	tr, err := New(Config{
		BackendBaseURL: srv.URL,
		AuthKey:        "the-real-secret",
		LegacyPoolType: legacypb.POOLTYPE_PPLNS,
		LegacyPoolID:   5,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	share := &poolpb.Share{
		Shares:         10,
		PaymentAddress: "addr-x",
		FoundBlock:     true,
		PoolType:       poolpb.PoolType_POOL_TYPE_PPLNS,
		BlockDiff:      99,
		BlockHeight:    12345,
		Timestamp:      1700000005,
		Identifier:     "worker-x",
		TrustedShare:   true,
	}

	if err := tr.SubmitShare(context.Background(), share); err != nil {
		t.Fatalf("SubmitShare: %v", err)
	}

	if gotPath != "/leafApi" {
		t.Errorf("path = %q, want %q", gotPath, "/leafApi")
	}
	if gotAuthHeaderKey != "" {
		t.Errorf("auth key leaked into a 'key' HTTP header: %q -- must be carried only in decoded WSData.key", gotAuthHeaderKey)
	}
	if gotAuthHeaderAuth != "" {
		t.Errorf("auth key leaked into an Authorization HTTP header: %q -- must be carried only in decoded WSData.key", gotAuthHeaderAuth)
	}

	// Raw protobuf body, no JSON wrapper.
	decoded := &legacypb.WSData{}
	if err := proto.Unmarshal(gotBody, decoded); err != nil {
		t.Fatalf("server received invalid protobuf WSData: %v", err)
	}
	if decoded.GetMsgType() != legacypb.MESSAGETYPE_SHARE {
		t.Errorf("MsgType = %v, want SHARE", decoded.GetMsgType())
	}
	if decoded.GetKey() != "the-real-secret" {
		t.Errorf("WSData.Key = %q, want %q", decoded.GetKey(), "the-real-secret")
	}
	// exInt is unused/irrelevant for SHARE.
	if decoded.GetExInt() != 0 {
		t.Errorf("ExInt = %d, want 0 for a SHARE message", decoded.GetExInt())
	}

	decodedShare := &legacypb.Share{}
	if err := proto.Unmarshal(decoded.GetMsg(), decodedShare); err != nil {
		t.Fatalf("server received invalid protobuf Share in WSData.Msg: %v", err)
	}
	if decodedShare.GetPaymentAddress() != "addr-x" {
		t.Errorf("decoded Share.PaymentAddress = %q, want %q", decodedShare.GetPaymentAddress(), "addr-x")
	}
	if decodedShare.GetPoolID() != 5 {
		t.Errorf("decoded Share.PoolID = %d, want 5 (the transport's configured legacy pool ID)", decodedShare.GetPoolID())
	}
}

func TestSubmitBlock_SendsRawProtobufWithHeightAsExInt(t *testing.T) {
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	tr, err := New(Config{
		BackendBaseURL: srv.URL,
		AuthKey:        "secret-2",
		LegacyPoolType: legacypb.POOLTYPE_SOLO,
		LegacyPoolID:   9,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	block := &poolpb.Block{
		Hash:     "0xblockhash",
		PoolType: poolpb.PoolType_POOL_TYPE_SOLO,
		Valid:    true,
		Height:   777777,
	}

	if err := tr.SubmitBlock(context.Background(), block); err != nil {
		t.Fatalf("SubmitBlock: %v", err)
	}

	decoded := &legacypb.WSData{}
	if err := proto.Unmarshal(gotBody, decoded); err != nil {
		t.Fatalf("server received invalid protobuf WSData: %v", err)
	}
	if decoded.GetMsgType() != legacypb.MESSAGETYPE_BLOCK {
		t.Errorf("MsgType = %v, want BLOCK", decoded.GetMsgType())
	}
	if decoded.GetKey() != "secret-2" {
		t.Errorf("WSData.Key = %q, want %q", decoded.GetKey(), "secret-2")
	}
	if decoded.GetExInt() != 777777 {
		t.Errorf("ExInt = %d, want 777777 (the real block height)", decoded.GetExInt())
	}

	decodedBlock := &legacypb.Block{}
	if err := proto.Unmarshal(decoded.GetMsg(), decodedBlock); err != nil {
		t.Fatalf("server received invalid protobuf Block in WSData.Msg: %v", err)
	}
	if decodedBlock.GetHash() != "0xblockhash" {
		t.Errorf("decoded Block.Hash = %q, want %q", decodedBlock.GetHash(), "0xblockhash")
	}
}

func TestSubmitShare_403Response_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	tr, err := New(Config{BackendBaseURL: srv.URL, AuthKey: "wrong-key", LegacyPoolType: legacypb.POOLTYPE_PPLNS, LegacyPoolID: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	share := &poolpb.Share{
		Shares: 1, PaymentAddress: "addr", PoolType: poolpb.PoolType_POOL_TYPE_PPLNS, Identifier: "w",
	}
	if err := tr.SubmitShare(context.Background(), share); err == nil {
		t.Fatal("expected error for 403 response, got nil")
	}
}

func TestSubmitBlock_400Response_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	tr, err := New(Config{BackendBaseURL: srv.URL, AuthKey: "key", LegacyPoolType: legacypb.POOLTYPE_PPLNS, LegacyPoolID: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	block := &poolpb.Block{Hash: "0xh", PoolType: poolpb.PoolType_POOL_TYPE_PPLNS}
	if err := tr.SubmitBlock(context.Background(), block); err == nil {
		t.Fatal("expected error for 400 response, got nil")
	}
}

// TestSubmitShare_200SuccessTrue_NoError proves the transport-level
// contract works for the real legacy "unconditional success" SHARE
// semantics. NOTE (per this test's own comment, and the package doc
// comment): a 200 {"success":true} here does NOT prove the inner Share
// payload was actually accepted/processed server-side -- the real
// nodejs-pool remoteShare.js silently swallows inner-Share decode
// failures in a try/catch and responds 200 regardless. This test only
// proves the outer WSData envelope was delivered and the HTTP-level
// contract is satisfied.
func TestSubmitShare_200SuccessTrue_NoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	tr, err := New(Config{BackendBaseURL: srv.URL, AuthKey: "key", LegacyPoolType: legacypb.POOLTYPE_PPLNS, LegacyPoolID: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	share := &poolpb.Share{
		Shares: 1, PaymentAddress: "addr", PoolType: poolpb.PoolType_POOL_TYPE_PPLNS, Identifier: "w",
	}
	if err := tr.SubmitShare(context.Background(), share); err != nil {
		t.Fatalf("SubmitShare: unexpected error: %v", err)
	}
}

func TestSubmitShare_TimesOutOnSlowServer(t *testing.T) {
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock
	}))
	defer func() {
		close(unblock)
		srv.Close()
	}()

	tr, err := New(Config{
		BackendBaseURL: srv.URL, AuthKey: "key", LegacyPoolType: legacypb.POOLTYPE_PPLNS, LegacyPoolID: 1,
		ShareTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tr.Close()

	share := &poolpb.Share{
		Shares: 1, PaymentAddress: "addr", PoolType: poolpb.PoolType_POOL_TYPE_PPLNS, Identifier: "w",
	}

	start := time.Now()
	err = tr.SubmitShare(context.Background(), share)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("SubmitShare took %v to time out, want well under 2s given a 100ms configured timeout", elapsed)
	}
}

func TestNew_RequiresBackendBaseURL(t *testing.T) {
	if _, err := New(Config{AuthKey: "key"}); err == nil {
		t.Fatal("expected error for empty BackendBaseURL, got nil")
	}
}

func TestNew_RequiresAuthKey(t *testing.T) {
	if _, err := New(Config{BackendBaseURL: "https://example.com"}); err == nil {
		t.Fatal("expected error for empty AuthKey, got nil")
	}
}
