package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
	"google.golang.org/protobuf/proto"
)

func TestSubmitShare_EncodesAndHitsCorrectPath(t *testing.T) {
	var (
		gotPath        string
		gotContentType string
		gotAuthHeader  string
		gotBody        []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotAuthHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tr, err := NewHTTPProtobufTransport(HTTPProtobufTransportConfig{
		BaseURL:         srv.URL,
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer test-token",
	})
	if err != nil {
		t.Fatalf("NewHTTPProtobufTransport: %v", err)
	}
	defer tr.Close()

	share := &poolpb.Share{
		Algo:           poolpb.Algo_ALGO_RXT,
		Network:        poolpb.Network_NETWORK_TESTNET,
		PaymentAddress: "addr",
		Identifier:     "worker-1",
	}

	if err := tr.SubmitShare(context.Background(), share); err != nil {
		t.Fatalf("SubmitShare: %v", err)
	}

	if gotPath != defaultSharePath {
		t.Errorf("path = %q, want %q", gotPath, defaultSharePath)
	}
	if gotContentType != protobufContentType {
		t.Errorf("Content-Type = %q, want %q", gotContentType, protobufContentType)
	}
	if gotAuthHeader != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer test-token")
	}

	decoded := &poolpb.Share{}
	if err := proto.Unmarshal(gotBody, decoded); err != nil {
		t.Fatalf("server received invalid protobuf: %v", err)
	}
	if !proto.Equal(decoded, share) {
		t.Fatalf("decoded share mismatch: got %v, want %v", decoded, share)
	}
}

func TestSubmitBlock_EncodesAndHitsCorrectPath(t *testing.T) {
	var gotPath string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := NewHTTPProtobufTransport(HTTPProtobufTransportConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPProtobufTransport: %v", err)
	}
	defer tr.Close()

	block := &poolpb.Block{
		Algo:    poolpb.Algo_ALGO_C29,
		Network: poolpb.Network_NETWORK_MAINNET,
		Hash:    "0xdeadbeef",
		Valid:   true,
	}

	if err := tr.SubmitBlock(context.Background(), block); err != nil {
		t.Fatalf("SubmitBlock: %v", err)
	}

	if gotPath != defaultBlockPath {
		t.Errorf("path = %q, want %q", gotPath, defaultBlockPath)
	}

	decoded := &poolpb.Block{}
	if err := proto.Unmarshal(gotBody, decoded); err != nil {
		t.Fatalf("server received invalid protobuf: %v", err)
	}
	if !proto.Equal(decoded, block) {
		t.Fatalf("decoded block mismatch: got %v, want %v", decoded, block)
	}
}

func TestSubmitShare_NonSuccessStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	tr, err := NewHTTPProtobufTransport(HTTPProtobufTransportConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPProtobufTransport: %v", err)
	}
	defer tr.Close()

	err = tr.SubmitShare(context.Background(), &poolpb.Share{Algo: poolpb.Algo_ALGO_RXM})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

// TestSubmitShare_TimesOutOnSlowServer is the key regression guard for
// the "no timeouts anywhere" bug class found in the legacy stratum
// servers: a backend that hangs forever must not hang the leaf forever.
func TestSubmitShare_TimesOutOnSlowServer(t *testing.T) {
	unblock := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock
	}))
	defer func() {
		close(unblock)
		srv.Close()
	}()

	tr, err := NewHTTPProtobufTransport(HTTPProtobufTransportConfig{
		BaseURL:      srv.URL,
		ShareTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewHTTPProtobufTransport: %v", err)
	}
	defer tr.Close()

	start := time.Now()
	err = tr.SubmitShare(context.Background(), &poolpb.Share{Algo: poolpb.Algo_ALGO_SHA3X})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("SubmitShare took %v to time out, want well under 2s given a 100ms configured timeout", elapsed)
	}
}

func TestNewHTTPProtobufTransport_RequiresBaseURL(t *testing.T) {
	if _, err := NewHTTPProtobufTransport(HTTPProtobufTransportConfig{}); err == nil {
		t.Fatal("expected error for empty BaseURL, got nil")
	}
}
